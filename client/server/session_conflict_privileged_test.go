//go:build privileged && linux

package server

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"go.uber.org/mock/gomock"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

// The rows of section 6 on real engines. The session limit lives in TestGate_RefusedSessionLeavesEverythingAlone,
// the IPv6 overlay in TestAttachDropsOverlappingIPv6, and a domain on two links in
// TestResolved_SharedDomainWarnsBothSessions, because the harness has no resolved.

var defaultV4Route = netip.MustParsePrefix("0.0.0.0/0")

func (f *sessionsFixture) statusEntry(t *testing.T, ss *session) *proto.SessionStatus {
	t.Helper()
	resp, err := f.s.Status(f.ctx, &proto.StatusRequest{})
	require.NoError(t, err)
	for _, entry := range resp.GetSessions() {
		if entry.GetProfileId() == string(ss.key.Profile) {
			return entry
		}
	}
	return nil
}

func (f *sessionsFixture) selector(ss *session) *proto.SessionSelector {
	return &proto.SessionSelector{Profile: string(ss.key.Profile), Username: ss.key.Username}
}

func (f *sessionsFixture) interfaceOf(t *testing.T, ss *session) string {
	t.Helper()
	resources, running := f.s.slots.Running(ss.key)
	require.Truef(t, running, "session %s should hold its resources", ss.key.Profile)
	return resources.Interface
}

// startProfile brings up a further network for the test and connects it.
func (f *sessionsFixture) startProfile(t *testing.T, profile string, network hostNetwork) *session {
	t.Helper()
	startNetwork(t, f.ctx, profilemanager.DefaultConfigPathDir, profile, f.signalAddr, network)
	upProfile(t, f.ctx, f.s, profile, f.username)
	ss := f.session(t, profile)
	awaitConnected(t, ss, profile)
	keepRouterConnected(t, ss.statusRecorder)
	return ss
}

func awaitSessionEvent(t *testing.T, ss *session, kind string) *proto.SystemEvent {
	t.Helper()
	var found *proto.SystemEvent
	require.Eventuallyf(t, func() bool {
		events := eventsOfKind(ss, kind)
		if len(events) == 0 {
			return false
		}
		found = events[0]
		return true
	}, 30*time.Second, 50*time.Millisecond, "session %s should get the event %s", ss.key.Profile, kind)
	assert.Equal(t, string(ss.key.Profile), found.GetProfileId(), "event %s should name its profile", kind)
	return found
}

// The Up that waits hears why, the status keeps it, and no second attempt follows.
func TestOverlappingOverlayExplainsItself(t *testing.T) {
	f := newSessionsFixture(t)

	upProfile(t, f.ctx, f.s, f.work, f.username)
	work := f.session(t, f.work)
	awaitConnected(t, work, f.work)

	const clash = "clash"
	startNetwork(t, f.ctx, profilemanager.DefaultConfigPathDir, clash, f.signalAddr, networkWork)
	username := f.username
	name := clash
	_, err := f.s.Up(f.ctx, &proto.UpRequest{ProfileName: &name, Username: &username})

	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, gstatus.Code(err), "the Up should say the session is refused: %v", err)
	assert.Contains(t, gstatus.Convert(err).Message(), "overlaps", "the Up should name the reason")

	refused := f.session(t, clash)
	entry := f.statusEntry(t, refused)
	require.NotNil(t, entry)
	assert.Equal(t, "overlay", entry.GetConflict())
	assert.Equal(t, string(internal.StatusIdle), entry.GetStatus(), "the retries are over")
	awaitSessionEvent(t, refused, "session_refused")

	f.down(t, work)
	upProfile(t, f.ctx, f.s, clash, f.username)
	awaitConnected(t, refused, clash)
	assert.Nil(t, f.statusEntry(t, refused).Conflict, "the conflict went with the other session")
	f.down(t, refused)
}

// The check runs again when Management moves the running session onto the overlay of another one.
func TestOverlayChangeFromManagementRefusesTheSession(t *testing.T) {
	f := newSessionsFixture(t)

	upProfile(t, f.ctx, f.s, f.work, f.username)
	work := f.session(t, f.work)
	awaitConnected(t, work, f.work)

	const moved = "moved"
	logins := 0
	server, mgmtAddr, accounts, err := startManagementWithAccounts(t, f.signalAddr, writeNetworkStore(t, networkHome), &logins)
	require.NoError(t, err)
	t.Cleanup(server.Stop)
	config, err := profilemanager.UpdateOrCreateConfig(profilemanager.ConfigInput{
		ConfigPath:    filepath.Join(profilemanager.DefaultConfigPathDir, moved+".json"),
		ManagementURL: "http://" + mgmtAddr,
	})
	require.NoError(t, err)
	registerPeer(t, f.ctx, config)

	upProfile(t, f.ctx, f.s, moved, f.username)
	session := f.session(t, moved)
	awaitConnected(t, session, moved)
	requireInterfaceAddress(t, f.interfaceOf(t, session), networkHome.overlay, session)
	// The first network map has arrived, so the change reaches the session as an update.
	awaitSessionEvent(t, session, "host_dns_held")
	_, giveUp := session.runChans()

	ctx := context.Background()
	const ownerID = "a23efe53-63fb-11ec-90d6-0242ac120003"
	services := service.NewMockManager(gomock.NewController(t))
	services.EXPECT().ReloadAllServicesForAccount(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	accounts.SetServiceManager(services)
	settings, err := accounts.Store.GetAccountSettings(ctx, store.LockingStrengthNone, fixtureAccount)
	require.NoError(t, err)
	changed := settings.Copy()
	changed.NetworkRange = networkWork.overlay
	if changed.Extra == nil {
		changed.Extra = &types.ExtraSettings{}
	}
	_, err = accounts.UpdateAccountSettings(ctx, fixtureAccount, ownerID, changed)
	require.NoError(t, err)

	select {
	case <-giveUp:
	case <-time.After(60 * time.Second):
		t.Fatal("the session should stop retrying once its new overlay overlaps the other one")
	}
	assert.Equal(t, "overlay", f.statusEntry(t, session).GetConflict())
	assert.Equal(t, internal.StatusConnected, work.state.CurrentStatus(), "the other session should not notice")
	assert.NoError(t, f.s.host.Isolation().Verify())
}

// The same prefix in two networks: a warning for the one in line, another when it takes over.
func TestSharedRouteWarnsAndHandsOver(t *testing.T) {
	f := newSessionsFixture(t)

	upProfile(t, f.ctx, f.s, f.work, f.username)
	work := f.session(t, f.work)
	awaitConnected(t, work, f.work)
	keepRouterConnected(t, work.statusRecorder)
	workDev := f.interfaceOf(t, work)
	awaitRoute(t, networkWork.shared, workDev)

	upProfile(t, f.ctx, f.s, f.home, f.username)
	home := f.session(t, f.home)
	awaitConnected(t, home, f.home)
	keepRouterConnected(t, home.statusRecorder)
	homeDev := f.interfaceOf(t, home)
	awaitRoute(t, networkHome.route, homeDev)

	shadowed := awaitSessionEvent(t, home, "route_shadowed")
	assert.Equal(t, proto.SystemEvent_WARNING, shadowed.GetSeverity())
	assert.Equal(t, proto.SystemEvent_NETWORK, shadowed.GetCategory())
	assert.Equal(t, networkHome.shared.String(), shadowed.GetMetadata()["prefix"], "the warning should name the route")
	assert.Empty(t, eventsOfKind(work, "route_shadowed"), "the owner has nothing to be warned about")

	f.down(t, work)
	awaitRoute(t, networkHome.shared, homeDev)
	acquired := awaitSessionEvent(t, home, "route_acquired")
	assert.Equal(t, proto.SystemEvent_WARNING, acquired.GetSeverity())
	assert.Equal(t, networkHome.shared.String(), acquired.GetMetadata()["prefix"])
	f.down(t, home)
}

// A route over the overlay of another session stays out of the table, and the session hears of it.
func TestRouteOverAnotherOverlayIsRefusedWithAWarning(t *testing.T) {
	f := newSessionsFixture(t)

	upProfile(t, f.ctx, f.s, f.work, f.username)
	work := f.session(t, f.work)
	awaitConnected(t, work, f.work)

	covering := networkHome
	covering.extraRoutes = []netip.Prefix{netip.MustParsePrefix("100.71.0.0/24")}
	cover := f.startProfile(t, "cover", covering)
	dev := f.interfaceOf(t, cover)
	awaitRoute(t, networkHome.route, dev)

	event := awaitSessionEvent(t, cover, "route_overlay_refused")
	assert.Equal(t, proto.SystemEvent_WARNING, event.GetSeverity())
	assert.Equal(t, "100.71.0.0/24", event.GetMetadata()["prefix"])
	assert.Empty(t, linesWith(snapshotRoutes(t), "dst=100.71.0.0/24"), "the route must not reach the table")
	assert.Len(t, eventsOfKind(cover, "route_overlay_refused"), 1, "one warning per route is enough")
	f.down(t, cover)
}

// One exit node for the host, the first wins. An automatic one in the next session is skipped with a
// warning, a manual one is refused, and nothing is handed over when the owner leaves (R4).
func TestExitNodeFirstWins(t *testing.T) {
	f := newSessionsFixture(t)

	firstNetwork := networkWork
	firstNetwork.extraRoutes = []netip.Prefix{defaultV4Route}
	first := f.startProfile(t, "exit-first", firstNetwork)
	firstDev := f.interfaceOf(t, first)
	defaultThrough := func(dev string) []string {
		return linesWith(snapshotRoutes(t), "table=7120 dst=0.0.0.0/0 dev="+dev, "table=7120 dst=default dev="+dev)
	}
	require.Eventually(t, func() bool { return len(defaultThrough(firstDev)) > 0 }, 30*time.Second, 100*time.Millisecond,
		"the first session should own the exit node")

	secondNetwork := networkHome
	secondNetwork.extraRoutes = []netip.Prefix{defaultV4Route}
	second := f.startProfile(t, "exit-second", secondNetwork)
	secondDev := f.interfaceOf(t, second)

	// Auto-apply is skipped with a warning.
	held := awaitSessionEvent(t, second, "exit_node_held")
	assert.Equal(t, proto.SystemEvent_WARNING, held.GetSeverity())
	assert.Empty(t, defaultThrough(secondDev), "the second session must not get a default route")
	assert.NotEmpty(t, defaultThrough(firstDev), "the first session keeps the exit node")
	assert.Equal(t, "exit_node", f.statusEntry(t, second).GetConflict())
	assert.Nil(t, f.statusEntry(t, first).Conflict, "the owner has no conflict")

	// A manual selection is refused and changes nothing.
	exitID := extraRouteID(0)
	_, err := f.s.DeselectNetworks(f.ctx, &proto.SelectNetworksRequest{NetworkIDs: []string{exitID}, Session: f.selector(second)})
	require.NoError(t, err)
	// The first session owns the host DNS as well, which is what the status says from here on.
	require.Eventually(t, func() bool { return f.statusEntry(t, second).GetConflict() == "dns" }, 30*time.Second, 50*time.Millisecond,
		"a session that gave up its exit node has no such conflict left")

	_, err = f.s.SelectNetworks(f.ctx, &proto.SelectNetworksRequest{NetworkIDs: []string{exitID}, Append: true, Session: f.selector(second)})
	require.Error(t, err, "a manual exit node next to the owner must be refused")
	assert.Equal(t, codes.FailedPrecondition, gstatus.Code(err))
	routeSelector := second.client().Engine().GetRouteManager().GetRouteSelector()
	assert.False(t, routeSelector.IsSelected("extra-0"), "a refused selection must change nothing")

	// The owner itself may select what it has.
	_, err = f.s.SelectNetworks(f.ctx, &proto.SelectNetworksRequest{NetworkIDs: []string{exitID}, Append: true, Session: f.selector(first)})
	assert.NoError(t, err, "the owner is not in conflict with itself")

	// Back in line, then the owner leaves: no handover, a warning, the physical default.
	_, err = f.s.SelectNetworks(f.ctx, &proto.SelectNetworksRequest{All: true, Session: f.selector(second)})
	require.NoError(t, err, "selecting everything is not a manual exit node")
	require.Eventually(t, func() bool { return len(eventsOfKind(second, "exit_node_held")) > 1 }, 30*time.Second, 50*time.Millisecond,
		"auto-apply should be skipped again")

	f.down(t, first)
	released := awaitSessionEvent(t, second, "exit_node_released")
	assert.Equal(t, proto.SystemEvent_WARNING, released.GetSeverity())
	assert.Empty(t, defaultThrough(firstDev), "the route of the owner should be gone")
	assert.Empty(t, defaultThrough(secondDev), "the exit node must not be handed over")
	assert.Equal(t, "dns", f.statusEntry(t, second).GetConflict(), "with the owner gone the exit node is in no conflict")

	// The request was dropped, and making it again works.
	_, err = f.s.DeselectNetworks(f.ctx, &proto.SelectNetworksRequest{NetworkIDs: []string{exitID}, Session: f.selector(second)})
	require.NoError(t, err)
	_, err = f.s.SelectNetworks(f.ctx, &proto.SelectNetworksRequest{NetworkIDs: []string{exitID}, Append: true, Session: f.selector(second)})
	require.NoError(t, err, "the exit node is free")
	require.Eventually(t, func() bool { return len(defaultThrough(secondDev)) > 0 }, 30*time.Second, 100*time.Millisecond,
		"a new request should get the exit node")
	f.down(t, second)
}

// The host DNS of a backend with one configuration: the second session works by IP and hears of it.
func TestHostDNSHeldWarnsWithItsConflict(t *testing.T) {
	f := newSessionsFixture(t)

	upProfile(t, f.ctx, f.s, f.work, f.username)
	work := f.session(t, f.work)
	awaitConnected(t, work, f.work)
	require.Eventually(t, func() bool {
		owner, held := f.s.host.Coordinator().DNSOwners().HostDNSOwner()
		return held && owner == work.key
	}, 30*time.Second, 100*time.Millisecond, "the first session should own the host DNS")

	upProfile(t, f.ctx, f.s, f.home, f.username)
	home := f.session(t, f.home)
	awaitConnected(t, home, f.home)

	event := awaitSessionEvent(t, home, "host_dns_held")
	assert.Equal(t, proto.SystemEvent_WARNING, event.GetSeverity())
	assert.Equal(t, proto.SystemEvent_DNS, event.GetCategory())
	assert.Equal(t, "dns", f.statusEntry(t, home).GetConflict())
	assert.Nil(t, f.statusEntry(t, work).Conflict, "the owner has no conflict")

	f.down(t, home)
	assert.Nil(t, f.statusEntry(t, home), "a session taken down has nothing left to report")
	upProfile(t, f.ctx, f.s, f.home, f.username)
	awaitConnected(t, home, f.home)
	f.down(t, home)
	f.down(t, work)
}

// Bringing a session up deletes whatever has the name of its interface. A profile that names an
// interface other than the one of its slot could aim that at any link of the host, and whoever owns
// a profile can write that name without any privilege. A session does not get that far, and the
// session that runs stays as it is.
func TestExplicitInterfaceIsRefused(t *testing.T) {
	f := newSessionsFixture(t)

	upProfile(t, f.ctx, f.s, f.work, f.username)
	work := f.session(t, f.work)
	awaitConnected(t, work, f.work)

	const victim = "nbvictim0"
	require.NoError(t, netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: victim}}))
	t.Cleanup(func() {
		if link, err := netlink.LinkByName(victim); err == nil {
			_ = netlink.LinkDel(link)
		}
	})
	before, err := netlink.LinkByName(victim)
	require.NoError(t, err)

	// The name of the slot of another session is as explicit as any other.
	for _, explicit := range []string{victim, "wt7"} {
		t.Run(explicit, func(t *testing.T) {
			name := explicit
			_, err := profilemanager.UpdateOrCreateConfig(profilemanager.ConfigInput{
				ConfigPath:    filepath.Join(profilemanager.DefaultConfigPathDir, f.home+".json"),
				InterfaceName: &name,
			})
			require.NoError(t, err)

			profile, username := f.home, f.username
			_, err = f.s.Up(f.ctx, &proto.UpRequest{ProfileName: &profile, Username: &username})
			require.Error(t, err)
			assert.Equal(t, codes.FailedPrecondition, gstatus.Code(err), "the Up should say the session is refused: %v", err)
			assert.Contains(t, gstatus.Convert(err).Message(), "interface")

			home := f.session(t, f.home)
			assert.Equal(t, "interface", f.statusEntry(t, home).GetConflict())

			after, err := netlink.LinkByName(victim)
			require.NoError(t, err, "the link must not be deleted")
			assert.Equal(t, before.Attrs().Index, after.Attrs().Index, "the link must be the same one")
			assert.Equal(t, internal.StatusConnected, work.state.CurrentStatus(), "the running session should not notice")
		})
	}
}

// The name of a slot is free for anything else on the host until a session wants it. A link that a
// session would not have created stays, and the session does not run.
func TestForeignLinkOnTheNameOfASlotIsRefused(t *testing.T) {
	f := newSessionsFixture(t)

	const slotName = "wt0"
	require.NoError(t, netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: slotName}}))
	t.Cleanup(func() {
		if link, err := netlink.LinkByName(slotName); err == nil {
			_ = netlink.LinkDel(link)
		}
	})
	before, err := netlink.LinkByName(slotName)
	require.NoError(t, err)

	profile, username := f.work, f.username
	_, err = f.s.Up(f.ctx, &proto.UpRequest{ProfileName: &profile, Username: &username})
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, gstatus.Code(err), "the Up should say the session is refused: %v", err)
	assert.Equal(t, "interface", f.statusEntry(t, f.session(t, f.work)).GetConflict())

	after, err := netlink.LinkByName(slotName)
	require.NoError(t, err, "the link must not be deleted")
	assert.Equal(t, before.Attrs().Index, after.Attrs().Index, "the link must be the same one")
	assert.Equal(t, "dummy", after.Type())
}

// tunModes are the ways a session can use the name of its slot. A kernel session deletes whatever has
// the name when it comes up, so what is refused there has to be refused before that.
var tunModes = []struct {
	name  string
	setup func(t *testing.T)
}{
	{name: "kernel", setup: requireKernelInterface},
	{name: "userspace", setup: func(t *testing.T) { t.Setenv("NB_WG_KERNEL_DISABLED", "true") }},
}

// A TUN nobody closes is not the one of a previous attempt, whichever mode comes next. It stays.
func TestForeignTunOnTheNameOfASlotIsRefused(t *testing.T) {
	for _, mode := range tunModes {
		t.Run(mode.name, func(t *testing.T) {
			mode.setup(t)
			f := newSessionsFixture(t)

			const slotName = "wt0"
			require.NoError(t, netlink.LinkAdd(&netlink.Tuntap{
				LinkAttrs: netlink.LinkAttrs{Name: slotName},
				Mode:      netlink.TUNTAP_MODE_TUN,
				Flags:     netlink.TUNTAP_DEFAULTS | netlink.TUNTAP_NO_PI,
			}))
			t.Cleanup(func() {
				if link, err := netlink.LinkByName(slotName); err == nil {
					_ = netlink.LinkDel(link)
				}
			})
			before, err := netlink.LinkByName(slotName)
			require.NoError(t, err)

			profile, username := f.work, f.username
			_, err = f.s.Up(f.ctx, &proto.UpRequest{ProfileName: &profile, Username: &username})
			require.Error(t, err)
			assert.Equal(t, codes.FailedPrecondition, gstatus.Code(err), "the Up should say the session is refused: %v", err)
			assert.Equal(t, "interface", f.statusEntry(t, f.session(t, f.work)).GetConflict())

			after, err := netlink.LinkByName(slotName)
			require.NoError(t, err, "the TUN must not be deleted")
			assert.Equal(t, before.Attrs().Index, after.Attrs().Index, "the TUN must be the same one")
			assert.Equal(t, "tuntap", after.Type())
		})
	}
}

// The TUN of a previous attempt can be there for a moment when the next attempt starts. The session
// waits it out instead of stopping for good.
func TestClosingTunOnTheNameOfASlotDoesNotStopTheSession(t *testing.T) {
	for _, mode := range tunModes {
		t.Run(mode.name, func(t *testing.T) {
			mode.setup(t)
			f := newSessionsFixture(t)

			tun := &netlink.Tuntap{
				LinkAttrs:  netlink.LinkAttrs{Name: "wt0"},
				Mode:       netlink.TUNTAP_MODE_TUN,
				Flags:      netlink.TUNTAP_DEFAULTS | netlink.TUNTAP_NO_PI,
				NonPersist: true,
				Queues:     1,
			}
			require.NoError(t, netlink.LinkAdd(tun))
			timer := time.AfterFunc(500*time.Millisecond, func() {
				for _, fd := range tun.Fds {
					assert.NoError(t, fd.Close())
				}
			})
			t.Cleanup(func() { timer.Stop() })

			upProfile(t, f.ctx, f.s, f.work, f.username)
			awaitConnected(t, f.session(t, f.work), f.work)
		})
	}
}

// Q24 with real resources: a refused Up reaches neither the state file nor the running session.
func TestResidualBesideARunningSessionLeavesItAlone(t *testing.T) {
	f := newSessionsFixture(t)

	upProfile(t, f.ctx, f.s, f.work, f.username)
	work := f.session(t, f.work)
	awaitConnected(t, work, f.work)
	keepRouterConnected(t, work.statusRecorder)
	dev := f.interfaceOf(t, work)
	awaitRoute(t, networkWork.route, dev)
	awaitRoute(t, networkWork.shared, dev)

	homeKey := sessionKeyOf(profilemanager.ID(f.home), f.username)
	statePath := f.s.profileManager.GetStatePathFor(homeKey)
	require.NoError(t, os.WriteFile(statePath, []byte(residualStateJSON), 0o600))

	before := takeHostSnapshot(t, identityLine)
	name, username := f.home, f.username
	_, err := f.s.Up(f.ctx, &proto.UpRequest{ProfileName: &name, Username: &username})

	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, gstatus.Code(err), "the Up should be refused: %v", err)
	content, readErr := os.ReadFile(statePath)
	require.NoError(t, readErr)
	assert.Equal(t, residualStateJSON, string(content), "the state must stay")
	assert.Equal(t, before, takeHostSnapshot(t, identityLine), "the host must stay as the running session needs it")
	assert.Equal(t, internal.StatusConnected, work.state.CurrentStatus())
}

// A warning runs on the goroutine of the session that caused it, here the one giving up a route, and
// reaches the other session whatever the rest of the daemon is holding.
func TestRouteWarningDoesNotWaitForAnySession(t *testing.T) {
	f := newSessionsFixture(t)

	upProfile(t, f.ctx, f.s, f.work, f.username)
	work := f.session(t, f.work)
	awaitConnected(t, work, f.work)
	keepRouterConnected(t, work.statusRecorder)
	awaitRoute(t, networkWork.shared, f.interfaceOf(t, work))

	upProfile(t, f.ctx, f.s, f.home, f.username)
	home := f.session(t, f.home)
	awaitConnected(t, home, f.home)
	keepRouterConnected(t, home.statusRecorder)
	awaitSessionEvent(t, home, "route_shadowed")

	require.NoError(t, work.lockLifecycle(f.ctx))
	require.NoError(t, home.lockLifecycle(f.ctx))
	f.s.mutex.Lock()
	work.mu.Lock()
	home.mu.Lock()

	var unlock sync.Once
	release := func() {
		unlock.Do(func() {
			home.mu.Unlock()
			work.mu.Unlock()
			f.s.mutex.Unlock()
			home.unlockLifecycle()
			work.unlockLifecycle()
		})
	}
	t.Cleanup(release)

	done := make(chan error, 1)
	go func() {
		done <- f.s.host.Coordinator().Routes().Remove(work.key, networkWork.shared)
	}()

	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("the warning must not wait for a lock of the daemon or of a session")
	}
	assert.Len(t, eventsOfKind(home, "route_acquired"), 1, "the warning should be there before anyone lets go of anything")
	release()

	f.down(t, home)
	f.down(t, work)
}
