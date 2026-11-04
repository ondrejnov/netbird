//go:build linux && !android && privileged

package systemops

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/hostcoord"
	"github.com/netbirdio/netbird/client/internal/routemanager/vars"
)

var (
	testKeyA = hostcoord.SessionKey{Profile: "a", Username: "alice"}
	testKeyB = hostcoord.SessionKey{Profile: "b", Username: "alice"}

	testV4Default = netip.MustParsePrefix("0.0.0.0/0")
	testV6Default = netip.MustParsePrefix("::/0")
)

// overlayIface is a session's interface address without the rest of the device.
type overlayIface struct {
	name string
	addr wgaddr.Address
}

func (i overlayIface) Address() wgaddr.Address { return i.addr }
func (i overlayIface) Name() string            { return i.name }

// eventRecorder collects the warnings a session would publish as SystemEvent.
type eventRecorder struct {
	mu     sync.Mutex
	events []hostcoord.RouteEvent
}

func (r *eventRecorder) record(event hostcoord.RouteEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, event)
}

func (r *eventRecorder) kinds() []hostcoord.RouteEventKind {
	r.mu.Lock()
	defer r.mu.Unlock()
	kinds := make([]hostcoord.RouteEventKind, 0, len(r.events))
	for _, event := range r.events {
		kinds = append(kinds, event.Kind)
	}
	return kinds
}

// sharedSession is one session with its own interface in a shared table.
type sharedSession struct {
	ops    *SysOps
	intf   *net.Interface
	events *eventRecorder
}

// newSharedSessions starts two sessions that share one coordinator and one route
// registry, the way a daemon runs them. The final cleanup removes the routing base.
func newSharedSessions(t *testing.T, ifaceA, ifaceB wgIface) (a, b sharedSession) {
	t.Helper()
	requireAdvancedRouting(t)

	coordinator := hostcoord.New()
	routes := hostcoord.NewRoutes()
	a = newSharedSession(t, coordinator, routes, testKeyA, ifaceA, "nbshareda0", "198.18.40.1/24")
	b = newSharedSession(t, coordinator, routes, testKeyB, ifaceB, "nbsharedb0", "198.18.50.1/24")

	require.NoError(t, a.ops.SetupRouting(nil, nil, true))
	require.NoError(t, b.ops.SetupRouting(nil, nil, true))
	t.Cleanup(func() {
		assert.NoError(t, a.ops.CleanupRouting(nil, true))
		assert.NoError(t, b.ops.CleanupRouting(nil, true))
	})
	return a, b
}

func newSharedSession(
	t *testing.T,
	coordinator *hostcoord.Coordinator,
	routes *hostcoord.Routes,
	key hostcoord.SessionKey,
	overlay wgIface,
	ifaceName, cidr string,
) sharedSession {
	t.Helper()
	createAndSetupDummyInterface(t, ifaceName, cidr)
	enableInterfaceIPv6(t, ifaceName)
	intf, err := net.InterfaceByName(ifaceName)
	require.NoError(t, err)

	events := &eventRecorder{}
	return sharedSession{
		ops:    NewShared(overlay, nil, coordinator, key, WithSharedRoutes(routes, events.record)),
		intf:   intf,
		events: events,
	}
}

// enableInterfaceIPv6 undoes the disable_ipv6 default of the test container for the
// session's interface only, otherwise the kernel refuses v6 routes through it.
func enableInterfaceIPv6(t *testing.T, ifaceName string) {
	t.Helper()
	path := fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/disable_ipv6", ifaceName)
	if err := os.WriteFile(path, []byte("0"), 0o644); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Logf("enable IPv6 on %s: %v", ifaceName, err)
	}
}

// tableEntry is one route of the shared table as the kernel reports it.
type tableEntry struct {
	linkIndex int
	kind      int
}

// tableEntries returns the routes of the shared table for prefix.
func tableEntries(t *testing.T, prefix netip.Prefix) []tableEntry {
	t.Helper()
	entries, err := listTableEntries(prefix)
	require.NoError(t, err)
	return entries
}

func listTableEntries(prefix netip.Prefix) ([]tableEntry, error) {
	family := netlink.FAMILY_V4
	if prefix.Addr().Is6() {
		family = netlink.FAMILY_V6
	}
	routes, err := netlink.RouteListFiltered(family, &netlink.Route{Table: NetbirdVPNTableID}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return nil, err
	}

	var entries []tableEntry
	for _, route := range routes {
		if routeDestination(route, family) == prefix {
			entries = append(entries, tableEntry{linkIndex: route.LinkIndex, kind: route.Type})
		}
	}
	return entries, nil
}

// routeDestination handles the default route, which the kernel reports without Dst.
func routeDestination(route netlink.Route, family int) netip.Prefix {
	if route.Dst == nil {
		if family == netlink.FAMILY_V4 {
			return testV4Default
		}
		return testV6Default
	}
	addr, ok := netip.AddrFromSlice(route.Dst.IP)
	if !ok {
		return netip.Prefix{}
	}
	ones, _ := route.Dst.Mask.Size()
	return netip.PrefixFrom(addr.Unmap(), ones)
}

func requireRouteVia(t *testing.T, prefix netip.Prefix, intf *net.Interface, msg string) {
	t.Helper()
	entries := tableEntries(t, prefix)
	require.Lenf(t, entries, 1, "%s: exactly one route should exist for the prefix", msg)
	require.Equalf(t, intf.Index, entries[0].linkIndex, "%s: the route should use the device of %s", msg, intf.Name)
	require.Equalf(t, syscall.RTN_UNICAST, entries[0].kind, "%s: the route should be unicast", msg)
}

func requireNoRoute(t *testing.T, prefix netip.Prefix, msg string) {
	t.Helper()
	require.Emptyf(t, tableEntries(t, prefix), "%s: no route should exist for the prefix", msg)
}

func requireUnreachableV6Default(t *testing.T, msg string) {
	t.Helper()
	entries := tableEntries(t, testV6Default)
	require.Lenf(t, entries, 1, "%s: the v6 blackhole should exist", msg)
	require.Equalf(t, syscall.RTN_UNREACHABLE, entries[0].kind, "%s: the v6 default should be unreachable", msg)
}

// The same prefix from two sessions lands once, on the owner's device. The release
// moves it to the next session through that session's device, with no call from it.
func TestSharedRouteHandover(t *testing.T) {
	prefixes := map[string]netip.Prefix{
		"v4": netip.MustParsePrefix("198.51.100.0/24"),
		"v6": netip.MustParsePrefix("2001:db8:40::/64"),
	}
	for name, prefix := range prefixes {
		t.Run(name, func(t *testing.T) {
			a, b := newSharedSessions(t, nil, nil)

			require.NoError(t, a.ops.AddVPNRoute(prefix, a.intf))
			requireRouteVia(t, prefix, a.intf, "first add")

			require.NoError(t, b.ops.AddVPNRoute(prefix, b.intf))
			requireRouteVia(t, prefix, a.intf, "second add")
			assert.Equal(t, []hostcoord.RouteEventKind{hostcoord.RouteEventShadowed}, b.events.kinds(), "the waiting session should get a warning")

			require.NoError(t, a.ops.RemoveVPNRoute(prefix, a.intf))
			requireRouteVia(t, prefix, b.intf, "owner removed")
			assert.Equal(t,
				[]hostcoord.RouteEventKind{hostcoord.RouteEventShadowed, hostcoord.RouteEventAcquired},
				b.events.kinds(), "the next owner should get a warning")

			require.NoError(t, b.ops.RemoveVPNRoute(prefix, b.intf))
			requireNoRoute(t, prefix, "last owner removed")
			assert.True(t, hasRoutingRules(t), "rules should stay while sessions hold the base")

			require.NoError(t, a.ops.CleanupRouting(nil, true))
			require.NoError(t, b.ops.CleanupRouting(nil, true))
		})
	}
}

// A waiting session that leaves must not disturb the owner or the kernel table.
func TestSharedRouteWaiterRemoveKeepsOwner(t *testing.T) {
	a, b := newSharedSessions(t, nil, nil)
	prefix := netip.MustParsePrefix("198.51.100.0/24")

	require.NoError(t, a.ops.AddVPNRoute(prefix, a.intf))
	require.NoError(t, b.ops.AddVPNRoute(prefix, b.intf))

	require.NoError(t, b.ops.RemoveVPNRoute(prefix, b.intf))
	requireRouteVia(t, prefix, a.intf, "waiter removed")

	require.NoError(t, a.ops.RemoveVPNRoute(prefix, a.intf))
	requireNoRoute(t, prefix, "owner removed")
}

// The kernel drops the routes of a deleted interface, which happens when a session
// goes down hard. The release must still move the prefix to the next session.
func TestSharedRouteHandoverAfterOwnerInterfaceIsGone(t *testing.T) {
	a, b := newSharedSessions(t, nil, nil)
	prefix := netip.MustParsePrefix("198.51.100.0/24")

	require.NoError(t, a.ops.AddVPNRoute(prefix, a.intf))
	require.NoError(t, b.ops.AddVPNRoute(prefix, b.intf))

	link, err := netlink.LinkByIndex(a.intf.Index)
	require.NoError(t, err)
	require.NoError(t, netlink.LinkSetDown(link))
	requireNoRoute(t, prefix, "owner interface down")

	require.NoError(t, a.ops.RemoveVPNRoute(prefix, a.intf))
	requireRouteVia(t, prefix, b.intf, "owner released after its interface went down")

	// The last owner has nobody to hand over to, its delete finds no route left.
	link, err = netlink.LinkByIndex(b.intf.Index)
	require.NoError(t, err)
	require.NoError(t, netlink.LinkSetDown(link))
	require.NoError(t, b.ops.RemoveVPNRoute(prefix, b.intf))
	requireNoRoute(t, prefix, "last owner released after its interface went down")
}

// Concurrent add and remove from both sessions on many prefixes. Each goroutine ends
// in a known state, so the end state of the table is known whatever the interleaving.
func TestSharedRouteConcurrentAddRemove(t *testing.T) {
	const (
		rounds   = 20
		toggles  = 15
		prefixes = 8
	)
	a, b := newSharedSessions(t, nil, nil)

	testPrefixes := make([]netip.Prefix, 0, prefixes)
	for i := range prefixes {
		testPrefixes = append(testPrefixes, netip.PrefixFrom(netip.AddrFrom4([4]byte{198, 51, byte(i), 0}), 24))
	}

	toggle := func(session sharedSession, prefix netip.Prefix, endAdded bool) {
		for range toggles {
			assert.NoError(t, session.ops.AddVPNRoute(prefix, session.intf))
			assert.NoError(t, session.ops.RemoveVPNRoute(prefix, session.intf))
		}
		if endAdded {
			assert.NoError(t, session.ops.AddVPNRoute(prefix, session.intf))
		}
	}

	for round := range rounds {
		// The session that stays alternates, so both directions of the race run.
		stays, leaves := a, b
		if round%2 == 1 {
			stays, leaves = b, a
		}

		var wg sync.WaitGroup
		for _, prefix := range testPrefixes {
			wg.Add(2)
			go func(prefix netip.Prefix) {
				defer wg.Done()
				toggle(stays, prefix, true)
			}(prefix)
			go func(prefix netip.Prefix) {
				defer wg.Done()
				toggle(leaves, prefix, false)
			}(prefix)
		}
		wg.Wait()

		for _, prefix := range testPrefixes {
			requireRouteVia(t, prefix, stays.intf, fmt.Sprintf("round %d", round))
		}

		// Both sessions claim again, whichever got there first owns the route, and
		// the concurrent release of the owner has to hand it to the other session.
		for _, prefix := range testPrefixes {
			wg.Add(1)
			go func(prefix netip.Prefix) {
				defer wg.Done()
				assert.NoError(t, leaves.ops.AddVPNRoute(prefix, leaves.intf))
				assert.NoError(t, stays.ops.RemoveVPNRoute(prefix, stays.intf))
			}(prefix)
		}
		wg.Wait()
		for _, prefix := range testPrefixes {
			requireRouteVia(t, prefix, leaves.intf, fmt.Sprintf("round %d after release", round))
		}

		for _, prefix := range testPrefixes {
			require.NoError(t, leaves.ops.RemoveVPNRoute(prefix, leaves.intf))
			requireNoRoute(t, prefix, fmt.Sprintf("round %d all released", round))
		}
	}
}

// A delete followed by an add would leave a moment where the prefix falls through
// to the physical default. The kernel table must show a route throughout a handover.
func TestSharedRouteHandoverKeepsRouteInTable(t *testing.T) {
	const handovers = 300
	a, b := newSharedSessions(t, nil, nil)
	prefix := netip.MustParsePrefix("198.51.100.0/24")

	require.NoError(t, a.ops.AddVPNRoute(prefix, a.intf))
	require.NoError(t, b.ops.AddVPNRoute(prefix, b.intf))

	var missing, samples atomic.Int64
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			samples.Add(1)
			entries, err := listTableEntries(prefix)
			if !assert.NoError(t, err) {
				return
			}
			if len(entries) != 1 {
				missing.Add(1)
			}
		}
	}()

	// Each round the owner leaves and queues up again, so the route moves every time.
	owner, next := a, b
	for range handovers {
		require.NoError(t, owner.ops.RemoveVPNRoute(prefix, owner.intf))
		require.NoError(t, owner.ops.AddVPNRoute(prefix, owner.intf))
		owner, next = next, owner
	}
	close(stop)
	<-done

	require.Positive(t, samples.Load(), "the sampler should have run")
	assert.Zero(t, missing.Load(), "the prefix must have exactly one route during every handover")
	requireRouteVia(t, prefix, owner.intf, "after the handovers")
	assert.NotEqual(t, owner.intf.Index, next.intf.Index, "the sessions should use their own interfaces")
}

// R4: the default prefixes are not handed over, and the owner's blackhole goes with it.
func TestSharedDefaultRouteIsNotHandedOver(t *testing.T) {
	a, b := newSharedSessions(t, nil, nil)

	require.NoError(t, a.ops.AddVPNRoute(testV4Default, a.intf))
	requireRouteVia(t, testV4Default, a.intf, "exit node added")
	requireUnreachableV6Default(t, "exit node added")

	require.NoError(t, b.ops.AddVPNRoute(testV4Default, b.intf))
	requireRouteVia(t, testV4Default, a.intf, "second session asked for the exit node")
	requireUnreachableV6Default(t, "second session asked for the exit node")
	assert.Equal(t, []hostcoord.RouteEventKind{hostcoord.RouteEventExitNodeHeld}, b.events.kinds(), "the second session should get a warning")

	require.NoError(t, a.ops.RemoveVPNRoute(testV4Default, a.intf))
	requireNoRoute(t, testV4Default, "owner left")
	requireNoRoute(t, testV6Default, "owner left")
	assert.Equal(t,
		[]hostcoord.RouteEventKind{hostcoord.RouteEventExitNodeHeld, hostcoord.RouteEventExitNodeReleased},
		b.events.kinds(), "the waiting session should learn the exit node is gone")

	// The waiter's own removal must not disturb a table it never wrote to.
	require.NoError(t, b.ops.RemoveVPNRoute(testV4Default, b.intf))
	requireNoRoute(t, testV4Default, "waiter removed")

	// With the exit node free the next request wins, and owns the blackhole.
	require.NoError(t, b.ops.AddVPNRoute(testV4Default, b.intf))
	requireRouteVia(t, testV4Default, b.intf, "new owner")
	requireUnreachableV6Default(t, "new owner")

	require.NoError(t, b.ops.RemoveVPNRoute(testV4Default, b.intf))
	requireNoRoute(t, testV4Default, "new owner left")
	requireNoRoute(t, testV6Default, "new owner left")
}

// The blackhole belongs to the exit node owner, so another session cannot install a
// v6 default next to it, and the owner's stop removes it with the rest of its routes.
func TestSharedExitNodeOwnerStopRemovesBlackhole(t *testing.T) {
	v6Overlay := overlayIface{name: "nbsharedb0", addr: wgaddr.Address{
		IP:      netip.MustParseAddr("198.18.50.1"),
		Network: netip.MustParsePrefix("198.18.50.0/24"),
		IPv6:    netip.MustParseAddr("fd00:50::1"),
		IPv6Net: netip.MustParsePrefix("fd00:50::/64"),
	}}
	a, b := newSharedSessions(t, nil, v6Overlay)

	require.NoError(t, a.ops.AddVPNRoute(testV4Default, a.intf))
	require.NoError(t, b.ops.AddVPNRoute(testV6Default, b.intf))
	requireUnreachableV6Default(t, "v6 default of another session")

	require.NoError(t, a.ops.CleanupRouting(nil, true))

	requireNoRoute(t, testV4Default, "owner stopped")
	requireNoRoute(t, testV6Default, "owner stopped")
	assert.True(t, hasRoutingRules(t), "the other session still holds the routing base")
	assert.Equal(t,
		[]hostcoord.RouteEventKind{hostcoord.RouteEventExitNodeHeld, hostcoord.RouteEventExitNodeReleased},
		b.events.kinds(), "the waiting session should learn the exit node is gone")
}

// While v4 stays in the tunnel the blackhole is what stops v6 from leaking, so a failed
// route delete must leave it, and the repeated uninstall must finish the job. The invalid
// prefix makes the delete fail without touching the table, like a refusal of the kernel.
func TestUninstallSharedRouteKeepsBlackholeWhenRouteStays(t *testing.T) {
	a, _ := newSharedSessions(t, nil, nil)
	nexthop := Nexthop{Intf: a.intf}
	require.NoError(t, installSharedRoute(testV4Default, nexthop, true))

	require.Error(t, uninstallSharedRoute(netip.Prefix{}, nexthop, true))
	requireRouteVia(t, testV4Default, a.intf, "failed uninstall")
	requireUnreachableV6Default(t, "failed uninstall")

	require.NoError(t, uninstallSharedRoute(testV4Default, nexthop, true))
	requireNoRoute(t, testV4Default, "repeated uninstall")
	requireNoRoute(t, testV6Default, "repeated uninstall")
}

// A session that went down hard has no interface left, and its route went with it. That
// must not count as a failed delete, or the blackhole would never be removed.
func TestUninstallSharedRouteAfterInterfaceIsDeleted(t *testing.T) {
	newSharedSessions(t, nil, nil)

	// Not the helper for dummy interfaces, whose cleanup expects the link to still exist.
	dummy := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "nbsharedgone0"}}
	require.NoError(t, netlink.LinkAdd(dummy))
	t.Cleanup(func() {
		if err := netlink.LinkDel(dummy); err != nil {
			t.Logf("delete dummy interface: %v", err)
		}
	})
	require.NoError(t, netlink.LinkSetUp(dummy))
	intf, err := net.InterfaceByName(dummy.Name)
	require.NoError(t, err)

	nexthop := Nexthop{Intf: intf}
	require.NoError(t, installSharedRoute(testV4Default, nexthop, true))
	requireRouteVia(t, testV4Default, intf, "installed")

	require.NoError(t, netlink.LinkDel(dummy))
	requireNoRoute(t, testV4Default, "interface deleted")
	requireUnreachableV6Default(t, "the blackhole has no device and stays")

	require.NoError(t, uninstallSharedRoute(testV4Default, nexthop, true))
	requireNoRoute(t, testV6Default, "uninstall after the interface went away")
}

// A session with a v6 overlay gets no blackhole: management sends ::/0 as its own route.
func TestSharedExitNodeOwnerWithV6Overlay(t *testing.T) {
	v6Overlay := overlayIface{name: "nbshareda0", addr: wgaddr.Address{
		IP:      netip.MustParseAddr("198.18.40.1"),
		Network: netip.MustParsePrefix("198.18.40.0/24"),
		IPv6:    netip.MustParseAddr("fd00:40::1"),
		IPv6Net: netip.MustParsePrefix("fd00:40::/64"),
	}}
	a, _ := newSharedSessions(t, v6Overlay, nil)

	require.NoError(t, a.ops.AddVPNRoute(testV4Default, a.intf))
	requireNoRoute(t, testV6Default, "a v6 overlay needs no blackhole")

	require.NoError(t, a.ops.AddVPNRoute(testV6Default, a.intf))
	requireRouteVia(t, testV6Default, a.intf, "the owner's own v6 default")

	require.NoError(t, a.ops.CleanupRouting(nil, true))
	requireNoRoute(t, testV4Default, "owner stopped")
	requireNoRoute(t, testV6Default, "owner stopped")
}

// A stop removes the session's own routes and hands over the shared ones, without a
// flush. The foreign route stands for state only a flush of the whole table would
// remove. The last stop still empties the table.
func TestSharedRoutesStopWithoutTableFlush(t *testing.T) {
	a, b := newSharedSessions(t, nil, nil)
	own := netip.MustParsePrefix("198.51.100.0/25")
	shared := netip.MustParsePrefix("198.51.100.128/25")
	other := netip.MustParsePrefix("203.0.113.0/25")
	foreign := netip.MustParsePrefix("203.0.113.128/25")

	require.NoError(t, addRoute(foreign, Nexthop{Intf: b.intf}, NetbirdVPNTableID))
	require.NoError(t, a.ops.AddVPNRoute(own, a.intf))
	require.NoError(t, a.ops.AddVPNRoute(shared, a.intf))
	require.NoError(t, b.ops.AddVPNRoute(shared, b.intf))
	require.NoError(t, b.ops.AddVPNRoute(other, b.intf))

	require.NoError(t, a.ops.CleanupRouting(nil, true))

	requireNoRoute(t, own, "session A stopped")
	requireRouteVia(t, shared, b.intf, "session A stopped")
	requireRouteVia(t, other, b.intf, "session A stopped")
	requireRouteVia(t, foreign, b.intf, "session A stopped")
	assert.True(t, hasRoutingRules(t), "session B still holds rules 105 and 110")

	require.NoError(t, b.ops.CleanupRouting(nil, true))

	assert.Empty(t, tableRoutes(t), "the last stop should flush the shared table")
	assert.False(t, hasRoutingRules(t), "the last stop should remove rules 105 and 110")
}

// A starting engine cleans up before its setup. That must not touch another session.
func TestSharedRoutesCleanupBeforeSetupKeepsOtherRoutes(t *testing.T) {
	a, b := newSharedSessions(t, nil, nil)
	prefix := netip.MustParsePrefix("198.51.100.0/24")
	require.NoError(t, a.ops.AddVPNRoute(prefix, a.intf))

	require.NoError(t, b.ops.CleanupRouting(nil, true))

	requireRouteVia(t, prefix, a.intf, "cleanup of the other session")
	assert.True(t, hasRoutingRules(t), "session A still holds rules 105 and 110")
}

// Without the option the kernel keeps refusing a second route, as it does today.
func TestSysOpsWithoutSharedRoutesKeepExclusiveAdd(t *testing.T) {
	requireAdvancedRouting(t)
	prefix := netip.MustParsePrefix("198.51.100.0/24")

	constructors := map[string]func(*hostcoord.Coordinator, hostcoord.SessionKey) *SysOps{
		"New": func(*hostcoord.Coordinator, hostcoord.SessionKey) *SysOps {
			return New(nil, nil)
		},
		"NewShared": func(coordinator *hostcoord.Coordinator, key hostcoord.SessionKey) *SysOps {
			return NewShared(nil, nil, coordinator, key)
		},
	}
	for name, newOps := range constructors {
		t.Run(name, func(t *testing.T) {
			coordinator := hostcoord.New()
			first, second := newOps(coordinator, testKeyA), newOps(coordinator, testKeyB)
			require.NoError(t, first.SetupRouting(nil, nil, true))
			require.NoError(t, second.SetupRouting(nil, nil, true))
			t.Cleanup(func() {
				assert.NoError(t, second.CleanupRouting(nil, true))
				assert.NoError(t, first.CleanupRouting(nil, true))
			})

			createAndSetupDummyInterface(t, "nbexcla0", "198.18.60.1/24")
			createAndSetupDummyInterface(t, "nbexclb0", "198.18.70.1/24")
			intfA, err := net.InterfaceByName("nbexcla0")
			require.NoError(t, err)
			intfB, err := net.InterfaceByName("nbexclb0")
			require.NoError(t, err)

			require.NoError(t, first.AddVPNRoute(prefix, intfA))
			require.ErrorIs(t, second.AddVPNRoute(prefix, intfB), syscall.EEXIST)
			requireRouteVia(t, prefix, intfA, "second add refused")
		})
	}
}

// Without the option the host-wide behavior stays, including the blackhole bookkeeping.
func TestSysOpsWithoutSharedRoutesDefaultRoute(t *testing.T) {
	requireAdvancedRouting(t)
	r := New(nil, nil)
	require.NoError(t, r.SetupRouting(nil, nil, true))
	t.Cleanup(func() {
		assert.NoError(t, r.CleanupRouting(nil, true))
	})

	createAndSetupDummyInterface(t, "nbexcla0", "198.18.60.1/24")
	intf, err := net.InterfaceByName("nbexcla0")
	require.NoError(t, err)

	require.NoError(t, r.AddVPNRoute(testV4Default, intf))
	requireRouteVia(t, testV4Default, intf, "exit node added")
	requireUnreachableV6Default(t, "exit node added")

	require.NoError(t, r.RemoveVPNRoute(testV4Default, intf))
	requireNoRoute(t, testV4Default, "exit node removed")
	requireNoRoute(t, testV6Default, "exit node removed")
}

// A repeated install can fail while the earlier one is still in the table. The v4 traffic
// stays in the tunnel, so the v6 blackhole has to stay as well.
func TestInstallSharedRouteFailureKeepsBlackholeOfInstalledRoute(t *testing.T) {
	coordinator := hostcoord.New()
	session := NewShared(nil, nil, coordinator, hostcoord.SessionKey{Profile: "exit"})
	require.NoError(t, session.SetupRouting(nil, nil, true))
	t.Cleanup(func() {
		assert.NoError(t, session.CleanupRouting(nil, true))
	})

	createAndSetupDummyInterface(t, "nbrollb0", "198.18.40.1/24")
	intf, err := net.InterfaceByName("nbrollb0")
	require.NoError(t, err)
	require.NoError(t, installSharedRoute(vars.Defaultv4, Nexthop{Intf: intf}, true))

	missing := &net.Interface{Index: 999999, Name: "nbmissing"}
	require.ErrorContains(t, installSharedRoute(vars.Defaultv4, Nexthop{Intf: missing}, true), "add route")

	requireUnreachableV6Default(t, "failed repeated install")
}
