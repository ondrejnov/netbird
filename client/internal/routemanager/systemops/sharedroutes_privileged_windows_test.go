//go:build privileged && windows

package systemops

import (
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/hostcoord"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/internal/routemanager/notifier"
)

type sessionTestIface struct {
	name string
	addr wgaddr.Address
}

func (i sessionTestIface) Name() string            { return i.name }
func (i sessionTestIface) Address() wgaddr.Address { return i.addr }

type testSession struct {
	key   hostcoord.SessionKey
	intf  *net.Interface
	ops   *SysOps
	nexth Nexthop
}

func newTestSession(t *testing.T, coordinator *hostcoord.Coordinator, profile, name string, slot uint32, overlay string) *testSession {
	t.Helper()
	prefix := netip.MustParsePrefix(overlay)
	createSessionAdapter(t, name, slot, prefix)
	intf, err := net.InterfaceByName(name)
	require.NoError(t, err)

	key := hostcoord.SessionKey{Profile: profilemanager.ID(profile)}
	require.NoError(t, coordinator.Sessions().Set(key, name, prefix.Masked()))
	t.Cleanup(func() { coordinator.Sessions().Remove(key) })

	addr := wgaddr.MustParseWGAddress(overlay)
	ops := NewShared(sessionTestIface{name: name, addr: addr}, notifier.NewNotifier(), coordinator, key,
		WithSharedRoutes(coordinator.Routes(), nil),
		WithOverlayPrefixes(coordinator.Sessions()),
	)
	return &testSession{key: key, intf: intf, ops: ops, nexth: Nexthop{Intf: intf}}
}

func (s *testSession) has(prefix netip.Prefix) bool {
	return routePresent(prefix, s.nexth)
}

// TEST-NET-3 stands in for a network route both sessions get from their Management, so the host
// keeps its connectivity while the test runs.
func TestSharedRoutes_OneOwnerAndHandoverOnWindows(t *testing.T) {
	routed := netip.MustParsePrefix("203.0.113.0/24")
	coordinator := hostcoord.New()
	a := newTestSession(t, coordinator, "work", "wt66", 66, "100.93.0.1/16")
	b := newTestSession(t, coordinator, "home", "wt67", 67, "100.94.0.1/16")
	t.Cleanup(func() {
		_ = a.ops.CleanupRouting(nil, true)
		_ = b.ops.CleanupRouting(nil, true)
	})

	require.NoError(t, a.ops.AddVPNRoute(routed, a.intf))
	require.NoError(t, b.ops.AddVPNRoute(routed, b.intf))
	assert.True(t, a.has(routed), "the first session carries the prefix")
	assert.False(t, b.has(routed), "the second one waits instead of adding a route that would race the first")

	require.NoError(t, a.ops.RemoveVPNRoute(routed, a.intf))
	assert.True(t, b.has(routed), "the prefix moves to the waiting session")
	assert.False(t, a.has(routed), "the previous route goes, it would win over the new owner at equal metric")

	// Adding again while it owns the prefix is the route manager recalculating; nothing breaks.
	require.NoError(t, b.ops.AddVPNRoute(routed, b.intf))
	assert.True(t, b.has(routed))

	require.NoError(t, b.ops.CleanupRouting(nil, true))
	assert.False(t, b.has(routed), "the stop of a session releases its routes")
}

func TestSharedRoutes_RefuseTheOverlayOfAnotherSessionOnWindows(t *testing.T) {
	coordinator := hostcoord.New()
	a := newTestSession(t, coordinator, "work", "wt66", 66, "100.93.0.1/16")
	newTestSession(t, coordinator, "home", "wt67", 67, "100.94.0.1/16")
	t.Cleanup(func() { _ = a.ops.CleanupRouting(nil, true) })

	inOther := netip.MustParsePrefix("100.94.5.0/24")
	assert.Error(t, a.ops.AddVPNRoute(inOther, a.intf), "a route into the overlay of another session is refused")
	assert.False(t, a.has(inOther), "and never reaches the table")
}
