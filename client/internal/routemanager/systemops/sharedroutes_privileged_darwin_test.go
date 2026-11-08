//go:build privileged && darwin && !ios

package systemops

import (
	"net"
	"net/netip"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/route"
	"golang.org/x/sys/unix"

	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/iface/wgbackend"
	"github.com/netbirdio/netbird/client/internal/hostcoord"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/internal/routemanager/notifier"
	nbnet "github.com/netbirdio/netbird/client/net"
)

type sessionTestIface struct {
	name string
	addr wgaddr.Address
}

func (i sessionTestIface) Name() string            { return i.name }
func (i sessionTestIface) Address() wgaddr.Address { return i.addr }

type testSession struct {
	key  hostcoord.SessionKey
	intf *net.Interface
	ops  *SysOps
}

// createSessionUtun brings up a utun with the address of a session. It goes away with the test.
func createSessionUtun(t *testing.T, name, overlay string) *net.Interface {
	t.Helper()
	dev, err := wgbackend.CreateTUN(name, 1280)
	require.NoError(t, err, "create %s", name)
	t.Cleanup(func() { _ = dev.Close() })

	prefix := netip.MustParsePrefix(overlay)
	mask := net.CIDRMask(prefix.Bits(), 32)
	out, err := exec.Command("ifconfig", name, "inet", prefix.Addr().String(), prefix.Addr().String(),
		"netmask", net.IP(mask).String(), "up").CombinedOutput()
	require.NoError(t, err, "configure %s: %s", name, out)

	var intf *net.Interface
	require.Eventually(t, func() bool {
		intf, err = net.InterfaceByName(name)
		return err == nil && intf.Flags&net.FlagUp != 0
	}, 10*time.Second, 100*time.Millisecond, "%s comes up", name)
	return intf
}

func newTestSession(t *testing.T, coordinator *hostcoord.Coordinator, profile, name, overlay string) *testSession {
	t.Helper()
	intf := createSessionUtun(t, name, overlay)

	prefix := netip.MustParsePrefix(overlay)
	key := hostcoord.SessionKey{Profile: profilemanager.ID(profile)}
	require.NoError(t, coordinator.Sessions().Set(key, name, prefix.Masked()))
	t.Cleanup(func() { coordinator.Sessions().Remove(key) })

	ops := NewShared(sessionTestIface{name: name, addr: wgaddr.MustParseWGAddress(overlay)}, notifier.NewNotifier(), coordinator, key,
		WithSharedRoutes(coordinator.Routes(), nil),
		WithOverlayPrefixes(coordinator.Sessions()),
	)
	return &testSession{key: key, intf: intf, ops: ops}
}

// carrier returns the interface index of the unscoped route for prefix, 0 when there is none.
func carrier(t *testing.T, prefix netip.Prefix) int {
	t.Helper()
	current, found, err := unscopedRoute(prefix)
	require.NoError(t, err)
	if !found {
		return 0
	}
	return current.index
}

// scopedDefaultsOn counts the scoped default routes NetBird marked on the interface with index.
func scopedDefaultsOn(t *testing.T, index int) int {
	t.Helper()
	rib, err := retryFetchRIB()
	require.NoError(t, err)
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	require.NoError(t, err)

	count := 0
	for _, msg := range msgs {
		rtMsg, ok := msg.(*route.RouteMessage)
		if !ok || rtMsg.Index != index || rtMsg.Flags&routeProtoFlag == 0 || rtMsg.Flags&unix.RTF_IFSCOPE == 0 {
			continue
		}
		info, err := MsgToRoute(rtMsg)
		if err == nil && info.Dst.Bits() == 0 {
			count++
		}
	}
	return count
}

func boundName(af int) string {
	if intf := nbnet.BoundInterface(af); intf != nil {
		return intf.Name
	}
	return ""
}

// TEST-NET-3 stands in for a network route both sessions get from their Management, so the host
// keeps its connectivity while the test runs.
func TestSharedRoutes_OneOwnerAndHandoverOnMacOS(t *testing.T) {
	routed := netip.MustParsePrefix("203.0.113.0/24")
	coordinator := hostcoord.New()
	a := newTestSession(t, coordinator, "work", "utun166", "100.93.0.1/16")
	b := newTestSession(t, coordinator, "home", "utun167", "100.94.0.1/16")
	t.Cleanup(func() {
		_ = a.ops.CleanupRouting(nil, true)
		_ = b.ops.CleanupRouting(nil, true)
	})

	require.NoError(t, a.ops.AddVPNRoute(routed, a.intf))
	require.NoError(t, b.ops.AddVPNRoute(routed, b.intf), "the second session waits instead of failing")
	assert.Equal(t, a.intf.Index, carrier(t, routed), "the first session carries the prefix")

	require.NoError(t, a.ops.RemoveVPNRoute(routed, a.intf))
	assert.Equal(t, b.intf.Index, carrier(t, routed), "the prefix moves to the waiting session")

	// The route manager recalculating while B owns the prefix changes nothing.
	require.NoError(t, b.ops.AddVPNRoute(routed, b.intf))
	assert.Equal(t, b.intf.Index, carrier(t, routed))

	// A late remove by the previous owner must not delete the route of the new one: a delete on
	// macOS names the prefix only.
	require.NoError(t, a.ops.removeRouteIfPresent(routed, Nexthop{Intf: a.intf}))
	assert.Equal(t, b.intf.Index, carrier(t, routed), "the route of the owner stays")

	require.NoError(t, b.ops.CleanupRouting(nil, true))
	assert.Zero(t, carrier(t, routed), "the stop of the last session removes the route")
}

func TestSharedRoutes_StopOfTheOwnerHandsOverOnMacOS(t *testing.T) {
	routed := netip.MustParsePrefix("203.0.113.0/24")
	coordinator := hostcoord.New()
	a := newTestSession(t, coordinator, "work", "utun166", "100.93.0.1/16")
	b := newTestSession(t, coordinator, "home", "utun167", "100.94.0.1/16")
	t.Cleanup(func() {
		_ = a.ops.CleanupRouting(nil, true)
		_ = b.ops.CleanupRouting(nil, true)
	})

	require.NoError(t, a.ops.AddVPNRoute(routed, a.intf))
	require.NoError(t, b.ops.AddVPNRoute(routed, b.intf))
	require.Equal(t, a.intf.Index, carrier(t, routed))

	require.NoError(t, a.ops.CleanupRouting(nil, true))
	assert.Equal(t, b.intf.Index, carrier(t, routed), "the stop of the owner hands the prefix to the other session")
}

// A route for the prefix that no session put there is not taken over.
func TestSharedRoutes_ForeignRouteStaysOnMacOS(t *testing.T) {
	routed := netip.MustParsePrefix("203.0.113.0/24")
	out, err := exec.Command("route", "-n", "add", "-net", routed.String(), "-interface", "lo0").CombinedOutput()
	require.NoError(t, err, "add a foreign route: %s", out)
	t.Cleanup(func() { _ = exec.Command("route", "-n", "delete", "-net", routed.String()).Run() })
	lo, err := net.InterfaceByName("lo0")
	require.NoError(t, err)

	coordinator := hostcoord.New()
	a := newTestSession(t, coordinator, "work", "utun166", "100.93.0.1/16")
	t.Cleanup(func() { _ = a.ops.CleanupRouting(nil, true) })

	assert.Error(t, a.ops.AddVPNRoute(routed, a.intf), "the add fails on a route of something else")
	assert.Equal(t, lo.Index, carrier(t, routed), "the foreign route stays")
}

func TestSharedRoutes_RefuseTheOverlayOfAnotherSessionOnMacOS(t *testing.T) {
	coordinator := hostcoord.New()
	a := newTestSession(t, coordinator, "work", "utun166", "100.93.0.1/16")
	newTestSession(t, coordinator, "home", "utun167", "100.94.0.1/16")
	t.Cleanup(func() { _ = a.ops.CleanupRouting(nil, true) })

	inOther := netip.MustParsePrefix("100.94.5.0/24")
	assert.Error(t, a.ops.AddVPNRoute(inOther, a.intf), "a route into the overlay of another session is refused")
	assert.Zero(t, carrier(t, inOther), "and never reaches the table")
}

// The scoped defaults and the bound interface serve the sockets of every session, so they stay
// until the last session stops. Scoped routes leave the unscoped table alone, so the host keeps
// its connectivity.
func TestSharedScopedDefaults_LastSessionRemovesThemOnMacOS(t *testing.T) {
	physical, err := GetNextHop(netip.IPv4Unspecified())
	require.NoError(t, err, "the host needs a default route for this test")
	require.NotNil(t, physical.Intf)
	nbnet.Init()
	require.True(t, nbnet.AdvancedRouting(), "the test needs advanced routing")

	coordinator := hostcoord.New()
	a := newTestSession(t, coordinator, "work", "utun166", "100.93.0.1/16")
	b := newTestSession(t, coordinator, "home", "utun167", "100.94.0.1/16")
	t.Cleanup(func() {
		_ = a.ops.CleanupRouting(nil, true)
		_ = b.ops.CleanupRouting(nil, true)
	})

	require.NoError(t, a.ops.SetupRouting(nil, nil, true))
	require.NoError(t, b.ops.SetupRouting(nil, nil, true), "the second session installs the defaults again")
	assert.GreaterOrEqual(t, scopedDefaultsOn(t, physical.Intf.Index), 1, "a scoped default is on the physical interface")
	assert.Equal(t, physical.Intf.Name, boundName(unix.AF_INET), "sockets bind to the physical interface")

	require.NoError(t, a.ops.CleanupRouting(nil, true))
	assert.GreaterOrEqual(t, scopedDefaultsOn(t, physical.Intf.Index), 1, "the stop of one session keeps the defaults of the other")
	assert.Equal(t, physical.Intf.Name, boundName(unix.AF_INET), "and its bound interface")

	require.NoError(t, b.ops.CleanupRouting(nil, true))
	assert.Zero(t, scopedDefaultsOn(t, physical.Intf.Index), "the last session removes the defaults")
	assert.Empty(t, boundName(unix.AF_INET), "and the bound interface")
}
