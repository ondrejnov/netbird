//go:build privileged && linux

package server

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/netbirdio/netbird/client/internal/hostcoord"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/internal/statemanager"
	"github.com/netbirdio/netbird/client/internal/updater"
	"github.com/netbirdio/netbird/client/proto"
	nbssh "github.com/netbirdio/netbird/client/ssh"
)

const (
	reportRouterSSHKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJMWh6h2QGJRHCxTWbwMo6nDf3kMKl0wHCRCnFEUbfwH router"
	slotOneSSHFile     = "99-netbird-1.conf"
)

// reportFixture is two networks whose routing peer has an SSH key, on real engines.
type reportFixture struct {
	*sessionsFixture
	workKey profilemanager.SessionKey
	homeKey profilemanager.SessionKey
}

func newReportFixture(t *testing.T) *reportFixture {
	t.Helper()
	t.Setenv("TMPDIR", t.TempDir())
	f := newSessionsFixture(t)

	// The same profiles, now registered with a Management whose routing peer has an SSH key.
	work, home := networkWork, networkHome
	work.routerSSHKey, home.routerSSHKey = reportRouterSSHKey, reportRouterSSHKey
	startNetwork(t, f.ctx, profilemanager.DefaultConfigPathDir, f.work, f.signalAddr, work)
	startNetwork(t, f.ctx, profilemanager.DefaultConfigPathDir, f.home, f.signalAddr, home)

	return &reportFixture{
		sessionsFixture: f,
		workKey:         sessionKeyOf(profilemanager.ID(f.work), f.username),
		homeKey:         sessionKeyOf(profilemanager.ID(f.home), f.username),
	}
}

func (f *reportFixture) selector(profile string) *proto.SessionSelector {
	return &proto.SessionSelector{Profile: profile, Username: f.username}
}

func (f *reportFixture) upAndAwait(t *testing.T, profile string) *session {
	t.Helper()
	upProfile(t, f.ctx, f.s, profile, f.username)
	ss := f.session(t, profile)
	awaitConnected(t, ss, profile)
	return ss
}

func sshConfigPath(name string) string {
	return filepath.Join(nbssh.UnixSSHConfigDir, name)
}

// metricsPeerID returns the peer a metrics.txt of a bundle says it is about.
func metricsPeerID(t *testing.T, metrics string) string {
	t.Helper()
	match := regexp.MustCompile(`peer_id=([^, ]+)`).FindStringSubmatch(metrics)
	require.Len(t, match, 2, "metrics.txt should name its peer: %q", metrics)
	return match[1]
}

func awaitFile(t *testing.T, path string) string {
	t.Helper()
	var content []byte
	require.Eventuallyf(t, func() bool {
		var err error
		content, err = os.ReadFile(path)
		return err == nil
	}, 60*time.Second, 100*time.Millisecond, "%s should appear", path)
	return string(content)
}

// Metrics, the debug bundle and the SSH config on real engines: each answers for its own session,
// and stopping one leaves what belongs to the other.
func TestReportsOfEachSessionOnRealEngines(t *testing.T) {
	f := newReportFixture(t)
	t.Cleanup(func() {
		_ = os.Remove(sshConfigPath(nbssh.NetBirdSSHConfigFile))
		_ = os.Remove(sshConfigPath(slotOneSSHFile))
	})

	addr := freeLoopbackAddr(t)
	enableLocalMetrics(t, f.s, f.ctx, f.workKey, addr, true)
	enableLocalMetrics(t, f.s, f.ctx, f.homeKey, addr, true)

	// Two MTUs, which a daemon with one value for the process could not have.
	const homeMTU = 1400
	mtu := int64(homeMTU)
	_, err := f.s.SetConfig(f.ctx, &proto.SetConfigRequest{ProfileName: f.home, Username: f.username, Mtu: &mtu})
	require.NoError(t, err)

	work := f.upAndAwait(t, f.work)
	home := f.upAndAwait(t, f.home)
	require.Same(t, work, f.s.focusedSession(), "the first network is focused")
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = f.s.StopSessions(ctx)
	})

	t.Run("metrics", func(t *testing.T) {
		for _, profile := range []string{f.work, f.home} {
			body := awaitMetrics(t, addr, fmt.Sprintf(`netbird_management_connected{profile="%s"} 1`, profile))
			assert.Contains(t, body, fmt.Sprintf(`netbird_signal_connected{profile="%s"} 1`, profile))
		}
		for _, profile := range []string{f.work, f.home} {
			awaitMetrics(t, addr, fmt.Sprintf(`netbird_peers{profile="%s"} 1`, profile))
			// This one comes from the client metrics of the engine, not from the recorder.
			awaitMetrics(t, addr, fmt.Sprintf(`netbird_login_duration_seconds_count{profile="%s",success="true"} 1`, profile))
		}
	})

	t.Run("interface MTU", func(t *testing.T) {
		wt0, err := netlink.LinkByName("wt0")
		require.NoError(t, err)
		wt1, err := netlink.LinkByName("wt1")
		require.NoError(t, err)
		assert.Equal(t, 1280, wt0.Attrs().MTU, "the default of the first session")
		assert.Equal(t, homeMTU, wt1.Attrs().MTU, "the config of the second session")
		assert.EqualValues(t, homeMTU, home.client().Engine().InterfaceMTU(), "the resolver of the session reads this")
		assert.EqualValues(t, 1280, work.client().Engine().InterfaceMTU(), "the resolver of the session reads this")
	})

	t.Run("debug bundle", func(t *testing.T) {
		bundle := func(selector *proto.SessionSelector) map[string]string {
			t.Helper()
			resp, err := f.s.DebugBundle(f.ctx, &proto.DebugBundleRequest{Session: selector})
			require.NoError(t, err)
			t.Cleanup(func() { _ = os.Remove(resp.GetPath()) })
			return bundleEntries(t, resp.GetPath())
		}

		entries := bundle(nil)
		homeDir := "sessions/" + f.home + "/"
		assert.Contains(t, entries["status.txt"], "Profile: "+f.work, "the top is about the focused session")
		assert.Contains(t, entries["status.txt"], localOverlayAddr(t, work).String(), "with the address of its network")
		assert.Contains(t, entries[homeDir+"status.txt"], "Profile: "+f.home, "status.txt names the profile of its session")
		assert.Contains(t, entries[homeDir+"status.txt"], localOverlayAddr(t, home).String(), "with the address of its network")
		assert.NotContains(t, entries[homeDir+"status.txt"], localOverlayAddr(t, work).String(), "and not the other")
		assert.NotContains(t, entries["status.txt"], localOverlayAddr(t, home).String(), "and not the other")
		assert.Contains(t, entries[homeDir+"state.json"], `"name":"wt1"`, "the state is that of its session")
		assert.NotContains(t, entries[homeDir+"state.json"], `"name":"wt0"`, "the state is that of its session")
		assert.Contains(t, entries["state.json"], `"name":"wt0"`, "the state is that of its session")
		assert.NotContains(t, entries["state.json"], `"name":"wt1"`, "the state is that of its session")
		homeURL := home.connectionConfig().ManagementURL.String()
		workURL := work.connectionConfig().ManagementURL.String()
		assert.Contains(t, entries[homeDir+"config.txt"], homeURL, "the config is that of its session")
		assert.NotContains(t, entries[homeDir+"config.txt"], workURL, "the config is that of its session")
		assert.Contains(t, entries["config.txt"], workURL, "the config is that of its session")
		assert.Contains(t, entries, homeDir+"wgshow.txt", "the interface stats are those of its session")
		workPeer, homePeer := metricsPeerID(t, entries["metrics.txt"]), metricsPeerID(t, entries[homeDir+"metrics.txt"])
		assert.NotEqual(t, workPeer, homePeer, "metrics.txt should come from the engine of its session")

		only := bundle(f.selector(f.home))
		assert.Contains(t, only["status.txt"], "Profile: "+f.home, "a selector puts its session on top")
		assert.Contains(t, only["status.txt"], localOverlayAddr(t, home).String())
		assert.Equal(t, homePeer, metricsPeerID(t, only["metrics.txt"]), "a selector brings the metrics of its session")
		for name := range only {
			assert.False(t, strings.HasPrefix(name, "sessions/"), "%s should not be in the bundle of one session", name)
		}
	})

	t.Run("ssh config", func(t *testing.T) {
		first := awaitFile(t, sshConfigPath(nbssh.NetBirdSSHConfigFile))
		second := awaitFile(t, sshConfigPath(slotOneSSHFile))
		assert.Contains(t, first, networkWork.router.String(), "the file of slot 0 has the peers of its session")
		assert.NotContains(t, first, networkHome.router.String(), "the file of slot 0 has the peers of no other")
		assert.Contains(t, second, networkHome.router.String(), "the file of slot 1 has the peers of its session")
		assert.NotContains(t, second, networkWork.router.String(), "the file of slot 1 has the peers of no other")

		state := func(key profilemanager.SessionKey) string {
			t.Helper()
			raw, err := os.ReadFile(f.s.profileManager.GetStatePathFor(key))
			require.NoError(t, err)
			return string(raw)
		}
		require.Eventually(t, func() bool {
			return strings.Contains(state(f.homeKey), slotOneSSHFile) && strings.Contains(state(f.workKey), nbssh.NetBirdSSHConfigFile)
		}, 30*time.Second, 100*time.Millisecond, "each state file should record the file of its session")

		// The stop of one session takes its file and leaves the file of the other.
		f.down(t, home)
		assert.NoFileExists(t, sshConfigPath(slotOneSSHFile), "the stop should remove the file of the session")
		after, err := os.ReadFile(sshConfigPath(nbssh.NetBirdSSHConfigFile))
		require.NoError(t, err, "the file of the other session must stay")
		assert.Equal(t, first, string(after), "the file of the other session must stay as it was")
		assert.NotContains(t, state(f.homeKey), slotOneSSHFile, "the state of a clean stop should not read as a residue")

		// A session that stopped cleanly comes back next to the other, residue check and all.
		home = f.upAndAwait(t, f.home)
		awaitFile(t, sshConfigPath(slotOneSSHFile))

		f.down(t, work)
		assert.NoFileExists(t, sshConfigPath(nbssh.NetBirdSSHConfigFile), "the stop should remove the file of slot 0")
		assert.FileExists(t, sshConfigPath(slotOneSSHFile), "the file of the other session must stay")

		work = f.upAndAwait(t, f.work)
		awaitFile(t, sshConfigPath(nbssh.NetBirdSSHConfigFile))
	})

	t.Run("metrics after a stop", func(t *testing.T) {
		f.down(t, home)
		require.Eventually(t, func() bool {
			return !strings.Contains(scrapeMetrics(addr), fmt.Sprintf(`profile="%s"`, f.home))
		}, 10*time.Second, 50*time.Millisecond, "a session that stopped should leave the report")
		awaitMetrics(t, addr, fmt.Sprintf(`netbird_management_connected{profile="%s"} 1`, f.work))
	})
}

// The updater acts on the whole machine, so at most one session drives it: the focused one when its
// run starts. A move of the focus does not move it, and the next focus gets it only once it is free.
func TestUpdatesFollowTheFocusAtTheStartOfARun(t *testing.T) {
	f := newReportFixture(t)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = f.s.StopSessions(ctx)
	})

	work := f.upAndAwait(t, f.work)
	home := f.upAndAwait(t, f.home)
	require.Same(t, work, f.s.focusedSession())

	drives := func(ss *session) bool {
		t.Helper()
		var engineReady bool
		require.Eventually(t, func() bool {
			engineReady = ss.client() != nil && ss.client().Engine() != nil
			return engineReady
		}, 30*time.Second, 50*time.Millisecond, "the session should have an engine")
		return ss.client().Engine().DrivesUpdates()
	}

	assert.True(t, drives(work), "the focused session should drive the updater")
	assert.False(t, drives(home), "another session must not drive the updater")
	assert.True(t, work.client().Engine().WaitsForCertificateSlot(), "a session waits for the certificate store")

	// No move while running.
	_, err := f.s.SwitchProfile(f.ctx, &proto.SwitchProfileRequest{ProfileName: &f.home, Username: &f.username})
	require.NoError(t, err)
	assert.True(t, drives(work), "a move of the focus leaves a running session as it is")
	assert.False(t, drives(home), "a move of the focus leaves a running session as it is")

	// The new focus starts while the old holder still runs: there is one updater and one holder.
	f.down(t, home)
	home = f.upAndAwait(t, f.home)
	assert.False(t, drives(home), "the updater must not have two drivers")

	// Once it is free, the next run of the focus takes it.
	f.down(t, work)
	f.down(t, home)
	home = f.upAndAwait(t, f.home)
	assert.True(t, drives(home), "the focused session should take the free updater")
	work = f.upAndAwait(t, f.work)
	assert.False(t, drives(work), "a session without the focus must not take the updater")
}

// A session without the focus does not start the updater for a UI that subscribes to it.
func TestUpdaterStartsOnlyForTheFocusedSession(t *testing.T) {
	f := newGateFixture(t)
	require.NotNil(t, f.s.updateManager, "the start should create the update manager")
	require.False(t, f.s.updateManager.Started(), "nothing started it yet")

	subscribe := func(selector *proto.SessionSelector) {
		t.Helper()
		ctx, cancel := context.WithCancel(f.ctx)
		stream := &capturingEventStream{fakeServerStream: fakeServerStream[proto.SystemEvent]{ctx: ctx}}
		done := make(chan error, 1)
		go func() { done <- f.s.SubscribeEvents(&proto.SubscribeRequest{Session: selector}, stream) }()
		require.Eventually(t, func() bool { return stream.count() > 0 }, 5*time.Second, 10*time.Millisecond, "the subscription should come up")
		cancel()
		<-done
	}

	require.NoError(t, f.up(f.second))
	// The updater starts on this context, and its version fetcher does not get along with being
	// stopped right after the start (version.Update.StopWatch reads what StartFetcher writes).
	f.s.mutex.Lock()
	f.s.rootCtx = context.Background()
	f.s.mutex.Unlock()
	subscribe(&proto.SessionSelector{Profile: string(f.second.Profile), Username: f.second.Username})
	assert.False(t, f.s.updateManager.Started(), "a session without the focus must not start the updater")

	subscribe(nil)
	assert.True(t, f.s.updateManager.Started(), "the focused session starts the updater")
}

// A daemon without the gate starts the updater for any subscriber, as it always did.
func TestUpdaterStartsForAnySubscriberWithoutTheGate(t *testing.T) {
	s, ctx, _, _, _ := setupServerWithProfile(t)
	ss := s.focusedSession()
	s.updateManager = updater.NewManager(ctx, ss.statusRecorder, statemanager.New(filepath.Join(t.TempDir(), "state.json")))

	streamCtx, cancelStream := context.WithCancel(ctx)
	stream := &capturingEventStream{fakeServerStream: fakeServerStream[proto.SystemEvent]{ctx: streamCtx}}
	done := make(chan error, 1)
	go func() { done <- s.SubscribeEvents(&proto.SubscribeRequest{}, stream) }()
	require.Eventually(t, func() bool { return stream.count() > 0 }, 5*time.Second, 10*time.Millisecond)
	cancelStream()
	<-done
	assert.True(t, s.updateManager.Started())
}

// The state of a session names the file of its slot, and cleaning up after a crash takes just that
// file. Files with the same name in other places, and files of a state that is not there, stay.
func TestResidualStateRemovesTheSSHConfigOfItsSlot(t *testing.T) {
	f := prepareGateFixture(t)
	dir := t.TempDir()

	write := func(name string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, []byte("# netbird"), 0o600))
		return path
	}
	firstFile := write(nbssh.NetBirdSSHConfigFile)
	secondFile := write(slotOneSSHFile)
	strayFile := write("99-netbird-2.conf")

	state := func(key profilemanager.SessionKey, file string) {
		t.Helper()
		raw := fmt.Sprintf(`{"ssh_config_state":{"SSHConfigDir":%s,"SSHConfigFile":%s}}`, strconv.Quote(dir), strconv.Quote(file))
		path := f.s.profileManager.GetStatePathFor(key)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
		require.NoError(t, os.WriteFile(path, []byte(raw), 0o600))
	}
	state(f.first, nbssh.NetBirdSSHConfigFile)
	state(f.second, slotOneSSHFile)

	writeDesiredSessions(t, map[profilemanager.SessionKey]hostcoord.DesiredState{
		f.first:  hostcoord.DesiredDown,
		f.second: hostcoord.DesiredDown,
	})
	require.NoError(t, f.s.Start())

	assert.NoFileExists(t, firstFile, "the state of the first session should take its file")
	assert.NoFileExists(t, secondFile, "the state of the second session should take its file")
	assert.FileExists(t, strayFile, "a file no state names must stay")
}

// fakeFirewalld puts a firewall-cmd on the PATH that answers as a running firewalld and records what
// it was asked. The harness has no system bus, so the daemon goes through the command.
func fakeFirewalld(t *testing.T) func() string {
	t.Helper()
	dir := t.TempDir()
	calls := filepath.Join(dir, "calls")
	script := "#!/bin/sh\n[ \"$1\" = \"--state\" ] && exit 0\necho \"$2\" >> " + calls + "\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "firewall-cmd"), []byte(script), 0o755))
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return func() string {
		raw, err := os.ReadFile(calls)
		if os.IsNotExist(err) {
			return ""
		}
		require.NoError(t, err)
		return string(raw)
	}
}

// Each session trusts its own interface in firewalld, with both backends, and the end of one touches
// only what it trusted.
func TestEachSessionTrustsItsInterfaceInFirewalld(t *testing.T) {
	for _, backend := range hostBackends {
		t.Run(backend.name, func(t *testing.T) {
			backend.setup(t)
			calls := fakeFirewalld(t)
			f := newSessionsFixture(t)
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				_ = f.s.StopSessions(ctx)
			})

			upProfile(t, f.ctx, f.s, f.work, f.username)
			work := f.session(t, f.work)
			awaitConnected(t, work, f.work)
			upProfile(t, f.ctx, f.s, f.home, f.username)
			home := f.session(t, f.home)
			awaitConnected(t, home, f.home)

			assert.Contains(t, calls(), "--change-interface=wt0", "the first session should trust its interface")
			assert.Contains(t, calls(), "--change-interface=wt1", "the second session should trust its interface")

			f.down(t, work)
			assert.Contains(t, calls(), "--remove-interface=wt0", "the session that ended should take its interface out")
			assert.NotContains(t, calls(), "--remove-interface=wt1", "the session that stays must keep its interface")
		})
	}
}
