//go:build !android && !ios

package server

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/debug"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
)

func freeLoopbackAddr(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.Addr().String()
	require.NoError(t, listener.Close())
	return addr
}

// scrapeMetrics returns what the endpoint answers, "" when it does not.
func scrapeMetrics(addr string) string {
	client := http.Client{Timeout: time.Second}
	resp, err := client.Get(fmt.Sprintf("http://%s/metrics", addr))
	if err != nil {
		return ""
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusOK {
		return ""
	}
	return string(body)
}

func awaitMetrics(t *testing.T, addr, want string) string {
	t.Helper()
	var body string
	require.Eventuallyf(t, func() bool {
		body = scrapeMetrics(addr)
		return strings.Contains(body, want)
	}, 10*time.Second, 50*time.Millisecond, "the endpoint should report %s", want)
	return body
}

func enableLocalMetrics(t *testing.T, s *Server, ctx context.Context, key profilemanager.SessionKey, addr string, enabled bool) {
	t.Helper()
	_, err := s.SetConfig(ctx, &proto.SetConfigRequest{
		ProfileName:         string(key.Profile),
		Username:            key.Username,
		EnableLocalMetrics:  &enabled,
		LocalMetricsAddress: &addr,
	})
	require.NoError(t, err)
}

func metricLine(key profilemanager.SessionKey) string {
	return fmt.Sprintf(`netbird_peers{profile="%s"} 0`, key.Profile)
}

// The endpoint follows the focused session, as it did the one session, and reports the sessions
// that run. A profile is on it only when its own config says so: the endpoint takes no credentials,
// and the session of another user must not show up because the focused one enabled it.
func TestLocalMetrics_ReportEachSessionThatAskedForIt(t *testing.T) {
	f := newGateFixture(t)
	addr := freeLoopbackAddr(t)

	enableLocalMetrics(t, f.s, f.ctx, f.first, addr, true)
	enableLocalMetrics(t, f.s, f.ctx, f.second, addr, true)
	require.NoError(t, f.up(f.first))

	body := awaitMetrics(t, addr, metricLine(f.first))
	assert.NotContains(t, body, metricLine(f.second), "a session that does not run has nothing to report")

	require.NoError(t, f.up(f.second))
	require.NoError(t, f.up(f.third))
	body = awaitMetrics(t, addr, metricLine(f.second))
	assert.Contains(t, body, metricLine(f.first), "the session that was there stays")
	assert.NotContains(t, body, metricLine(f.third), "a profile that did not enable metrics must not be reported")
	assert.NotContains(t, body, "netbird_peers 0", "with the gate every series says which profile it is about")

	_, err := f.s.Down(f.ctx, &proto.DownRequest{Session: &proto.SessionSelector{Profile: string(f.second.Profile), Username: f.second.Username}})
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		return !strings.Contains(scrapeMetrics(addr), metricLine(f.second))
	}, 10*time.Second, 50*time.Millisecond, "a session that went down should go from the report")

	// A running profile turning its metrics off leaves right away, no restart needed.
	require.NoError(t, f.up(f.second))
	awaitMetrics(t, addr, metricLine(f.second))
	enableLocalMetrics(t, f.s, f.ctx, f.second, addr, false)
	body = awaitMetrics(t, addr, metricLine(f.first))
	assert.NotContains(t, body, metricLine(f.second), "a profile that turned its metrics off must not be reported")

	// The focus on a profile without metrics takes the endpoint down, what it did for one session.
	f.focus(t, f.third)
	require.Eventually(t, func() bool { return scrapeMetrics(addr) == "" }, 10*time.Second, 50*time.Millisecond,
		"the endpoint should follow the focused session")
}

// Without the gate the endpoint is what it has always been: the same series, without a label.
func TestLocalMetrics_WithoutTheGateHaveNoLabel(t *testing.T) {
	s, _, _, _, _ := setupServerWithProfile(t)
	addr := freeLoopbackAddr(t)
	s.localMetrics.Reconcile(true, addr)
	t.Cleanup(s.localMetrics.Stop)

	body := awaitMetrics(t, addr, "netbird_peers 0")
	assert.NotContains(t, body, "profile=", "without the gate there is one session and no label")
}

func TestSessionLabels_StayApartAcrossUsers(t *testing.T) {
	sessionOf := func(id, username string) *session {
		ss := newSession()
		ss.bindKey(profilemanager.SessionKey{Profile: profilemanager.ID(id), Username: username})
		return ss
	}
	unique := sessionOf("aaaa", "alice")
	shared := sessionOf("default", "")
	alice := sessionOf("work", "alice")
	bob := sessionOf("work", "bob")
	odd := sessionOf("work", "../odd name")

	labels := sessionLabels([]*session{unique, shared, alice, bob, odd})

	assert.Equal(t, "aaaa", labels[unique], "a profile ID is enough when only one session has it")
	assert.Equal(t, "default", labels[shared])
	assert.Equal(t, "work@alice", labels[alice], "legacy IDs come from names, so two users can share one")
	assert.Equal(t, "work@bob", labels[bob])
	assert.Equal(t, "work@___odd_name", labels[odd], "the label names a directory in the bundle")
}

// The bundle of a caller covers each session the caller may read, apart, and only those.
func TestDebugBundle_CoversTheSessionsOfTheCaller(t *testing.T) {
	f := newAccessFixture(t)
	require.NoError(t, f.up(f.alice))
	require.NoError(t, f.up(f.bob))
	require.NoError(t, f.up(f.shared))
	f.focus(t, f.alice)

	logFile := filepath.Join(t.TempDir(), "client.log")
	require.NoError(t, os.WriteFile(logFile, []byte("a line about the session of bob\n"), 0o600))
	f.s.logFile = logFile

	bundle := func(ctx context.Context, selector *proto.SessionSelector) map[string]string {
		t.Helper()
		resp, err := f.s.DebugBundle(ctx, &proto.DebugBundleRequest{Session: selector})
		require.NoError(t, err)
		t.Cleanup(func() { _ = os.Remove(resp.GetPath()) })
		return bundleEntries(t, resp.GetPath())
	}
	sessionDir := func(key profilemanager.SessionKey) string {
		return "sessions/" + string(key.Profile) + "/"
	}

	t.Run("a caller without a selector", func(t *testing.T) {
		entries := bundle(aliceCtx(), nil)
		assert.Contains(t, entries["status.txt"], "Profile: "+string(f.alice.Profile), "the top is about the focused session")
		assert.Contains(t, entries, sessionDir(f.shared)+"status.txt", "the shared session may be read by anyone")
		assert.NotContains(t, entries, sessionDir(f.bob)+"status.txt", "the session of another user must stay out")
		assert.NotContains(t, entries, "client.log", "the log of the daemon also speaks of the session of bob")
	})

	t.Run("root without a selector", func(t *testing.T) {
		entries := bundle(f.ctx, nil)
		assert.Contains(t, entries["status.txt"], "Profile: "+string(f.alice.Profile), "the top is about the focused session")
		assert.Contains(t, entries[sessionDir(f.bob)+"status.txt"], "Profile: "+string(f.bob.Profile), "status.txt names its own profile")
		assert.Contains(t, entries[sessionDir(f.shared)+"status.txt"], "Profile: "+string(f.shared.Profile))
		assert.NotContains(t, entries, sessionDir(f.alice)+"status.txt", "the session at the top appears once")
		assert.Contains(t, entries, "client.log", "root may read everything")
	})

	t.Run("a selector names one session", func(t *testing.T) {
		entries := bundle(f.ctx, &proto.SessionSelector{Profile: string(f.bob.Profile), Username: f.bob.Username})
		assert.Contains(t, entries["status.txt"], "Profile: "+string(f.bob.Profile), "the top is about the named session")
		for name := range entries {
			assert.False(t, strings.HasPrefix(name, "sessions/"), "%s should not be in the bundle of one session", name)
		}
	})
}

// The bundle reads files and runs probes for long. The other sessions must not wait for that.
func TestDebugBundle_DoesNotHoldTheServerMutex(t *testing.T) {
	f := newGateFixture(t)
	require.NoError(t, f.up(f.first))
	require.NoError(t, f.up(f.second))

	uiLog := filepath.Join(t.TempDir(), uiLogFileName)
	require.NoError(t, os.WriteFile(uiLog, []byte("ui"), 0o600))
	f.s.mutex.Lock()
	f.s.uiLogPath = uiLog
	f.s.mutex.Unlock()

	reached := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	var opener debug.LogOpener = func(path string) (*os.File, error) {
		once.Do(func() { close(reached) })
		<-release
		return os.Open(path)
	}

	done := make(chan error, 1)
	go func() {
		path, _, err := f.s.generateDebugBundle(f.session(f.first), &proto.DebugBundleRequest{}, opener, bundleScope{})
		if err == nil {
			_ = os.Remove(path)
		}
		done <- err
	}()

	<-reached
	free := f.s.mutex.TryLock()
	if free {
		f.s.mutex.Unlock()
	}
	assert.True(t, free, "s.mutex must be free while the bundle is written")

	status := make(chan error, 1)
	go func() {
		_, err := f.s.Status(f.ctx, &proto.StatusRequest{Session: &proto.SessionSelector{Profile: string(f.second.Profile), Username: f.second.Username}})
		status <- err
	}()
	select {
	case err := <-status:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		assert.Fail(t, "another session should get an answer while the bundle is written")
	}

	close(release)
	require.NoError(t, <-done)
}

// Two bundles at once: the capture goes to one of them, and its file stays until that one is done.
func TestDebugBundle_ACaptureGoesToOneBundle(t *testing.T) {
	f := newGateFixture(t)
	ss := f.session(f.first)

	bc := newTestBundleCapture(t)
	_, err := bc.file.WriteString("pcap of the session")
	require.NoError(t, err)
	captureFile := bc.file.Name()
	f.s.mutex.Lock()
	ss.bundleCapture = bc
	f.s.mutex.Unlock()

	const bundles = 4
	withCapture := make(chan bool, bundles)
	var wg sync.WaitGroup
	for range bundles {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := f.s.DebugBundle(f.ctx, &proto.DebugBundleRequest{})
			if !assert.NoError(t, err) {
				return
			}
			defer func() { _ = os.Remove(resp.GetPath()) }()
			entry, found := bundleEntries(t, resp.GetPath())["capture.pcap"]
			if found {
				assert.Contains(t, entry, "pcap of the session", "the capture should be complete")
			}
			withCapture <- found
		}()
	}
	wg.Wait()
	close(withCapture)

	var carriers int
	for found := range withCapture {
		if found {
			carriers++
		}
	}
	assert.Equal(t, 1, carriers, "exactly one bundle should carry the capture")
	assert.NoFileExists(t, captureFile, "the file of the capture should go with the bundle that took it")
}

// A CPU profile goes to the one bundle that takes it, as before.
func TestDebugBundle_ACPUProfileGoesToOneBundle(t *testing.T) {
	f := newGateFixture(t)
	f.s.mutex.Lock()
	f.s.cpuProfileBuf = bytes.NewBufferString("cpu of the daemon")
	f.s.mutex.Unlock()

	first, err := f.s.DebugBundle(f.ctx, &proto.DebugBundleRequest{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.Remove(first.GetPath()) })
	second, err := f.s.DebugBundle(f.ctx, &proto.DebugBundleRequest{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.Remove(second.GetPath()) })

	assert.Contains(t, bundleEntries(t, first.GetPath()), "cpu.prof")
	assert.NotContains(t, bundleEntries(t, second.GetPath()), "cpu.prof")
}

// A probe of one session says nothing about the relays and signal of another, so it must not
// count against that session's throttle.
func TestProbeThrottle_IsThatOfTheSession(t *testing.T) {
	first, second := newSession(), newSession()
	var firstRuns, secondRuns int
	firstProber := fakeProber{onProbe: func() bool { firstRuns++; return true }}
	secondProber := fakeProber{onProbe: func() bool { secondRuns++; return true }}

	first.probeThrottle.Run(context.Background(), firstProber, firstProber, false)
	second.probeThrottle.Run(context.Background(), secondProber, secondProber, false)
	assert.Equal(t, 1, firstRuns, "the first session should probe")
	assert.Equal(t, 1, secondRuns, "a probe of the first session must not stand in for the second")

	first.probeThrottle.Run(context.Background(), firstProber, firstProber, false)
	assert.Equal(t, 1, firstRuns, "a session keeps its own throttle")
}

// The log of the daemon goes back further than what runs now. A session of another user that is
// down, or only on record, has left its lines there all the same.
func TestDebugBundle_ALogSpeaksOfSessionsThatEnded(t *testing.T) {
	logFile := filepath.Join(t.TempDir(), "client.log")
	require.NoError(t, os.WriteFile(logFile, []byte("a line about the session of bob\n"), 0o600))

	bundle := func(t *testing.T, f *accessFixture) map[string]string {
		t.Helper()
		f.s.logFile = logFile
		f.focus(t, f.alice)
		resp, err := f.s.DebugBundle(aliceCtx(), &proto.DebugBundleRequest{})
		require.NoError(t, err)
		t.Cleanup(func() { _ = os.Remove(resp.GetPath()) })
		return bundleEntries(t, resp.GetPath())
	}

	t.Run("a session of another user that went down", func(t *testing.T) {
		f := newAccessFixture(t)
		require.NoError(t, f.up(f.bob))
		_, err := f.s.Down(f.ctx, &proto.DownRequest{Session: selectorOf(f.bob)})
		require.NoError(t, err)
		awaitRunEndOf(t, f.session(f.bob))

		assert.NotContains(t, bundle(t, f), "client.log")
	})

	t.Run("a session of another user only on record", func(t *testing.T) {
		f := newAccessFixture(t)
		_, err := f.s.slots.Ensure(f.bob)
		require.NoError(t, err)

		assert.NotContains(t, bundle(t, f), "client.log")
	})
}
