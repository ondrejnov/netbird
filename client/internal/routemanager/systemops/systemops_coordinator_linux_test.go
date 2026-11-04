//go:build linux && !android && privileged

package systemops

import (
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/netbirdio/netbird/client/internal/hostcoord"
	nbnet "github.com/netbirdio/netbird/client/net"
)

const testRPFilterPath = "/proc/sys/net/ipv4/conf/all/rp_filter"

// requireAdvancedRouting makes AddVPNRoute use the shared table, as a running daemon does.
func requireAdvancedRouting(t *testing.T) {
	t.Helper()
	nbnet.Init()
	require.True(t, nbnet.AdvancedRouting(), "these tests need advanced routing")
}

func tableRoutes(t *testing.T) []netlink.Route {
	t.Helper()
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Table: NetbirdVPNTableID}, netlink.RT_FILTER_TABLE)
	require.NoError(t, err)
	return routes
}

func hasRouteVia(routes []netlink.Route, linkIndex int) bool {
	for _, route := range routes {
		if route.LinkIndex == linkIndex {
			return true
		}
	}
	return false
}

func hasRoutingRules(t *testing.T) bool {
	t.Helper()
	rules, err := netlink.RuleList(netlink.FAMILY_V4)
	require.NoError(t, err)

	var found105, found110 bool
	for _, rule := range rules {
		found105 = found105 || rule.Priority == 105
		found110 = found110 || rule.Priority == 110
	}
	return found105 && found110
}

func readRPFilter(t *testing.T) string {
	t.Helper()
	value, err := os.ReadFile(testRPFilterPath)
	require.NoError(t, err)
	return strings.TrimSpace(string(value))
}

// setStrictRPFilter makes the base change a visible sysctl, so the test can tell
// the original value from the one the first session installed.
func setStrictRPFilter(t *testing.T) {
	t.Helper()
	original, err := os.ReadFile(testRPFilterPath)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(testRPFilterPath, []byte("1"), 0o644))
	t.Cleanup(func() {
		assert.NoError(t, os.WriteFile(testRPFilterPath, original, 0o644))
	})
}

// addSessionRoute installs a route the way an engine does and returns the index of
// the session's interface.
func addSessionRoute(t *testing.T, r *SysOps, ifaceName, cidr, dst string) int {
	t.Helper()
	createAndSetupDummyInterface(t, ifaceName, cidr)
	intf, err := net.InterfaceByName(ifaceName)
	require.NoError(t, err)
	require.NoError(t, r.AddVPNRoute(netip.MustParsePrefix(dst), intf))
	return intf.Index
}

// Two sessions share the rules, the table and the sysctls. The first session's stop
// must leave the second one routable, and the last stop must restore the host,
// including the sysctl values only the first session saw.
func TestSharedRoutingBaseSurvivesFirstSessionStop(t *testing.T) {
	requireAdvancedRouting(t)
	setStrictRPFilter(t)

	coordinator := hostcoord.New()
	sessionA := NewShared(nil, nil, coordinator, hostcoord.SessionKey{Profile: "a"})
	sessionB := NewShared(nil, nil, coordinator, hostcoord.SessionKey{Profile: "b"})

	require.NoError(t, sessionA.SetupRouting(nil, nil, true))
	require.NoError(t, sessionB.SetupRouting(nil, nil, true))
	t.Cleanup(func() {
		assert.NoError(t, New(nil, nil).CleanupRouting(nil, true))
	})

	indexA := addSessionRoute(t, sessionA, "nbcoorda0", "198.18.10.1/24", "198.51.100.0/25")
	indexB := addSessionRoute(t, sessionB, "nbcoordb0", "198.18.20.1/24", "198.51.100.128/25")
	require.True(t, hasRouteVia(tableRoutes(t), indexA), "route of session A should be installed")
	require.True(t, hasRouteVia(tableRoutes(t), indexB), "route of session B should be installed")
	require.Equal(t, "2", readRPFilter(t), "the base should set rp_filter to loose")

	require.NoError(t, sessionA.CleanupRouting(nil, true))

	assert.True(t, hasRouteVia(tableRoutes(t), indexB), "stopping session A must keep the route of session B")
	assert.True(t, hasRoutingRules(t), "stopping session A must keep rules 105 and 110")
	assert.Equal(t, "2", readRPFilter(t), "stopping session A must keep the sysctls of the running base")

	require.NoError(t, sessionB.CleanupRouting(nil, true))

	assert.Empty(t, tableRoutes(t), "the last stop should flush the shared table")
	assert.False(t, hasRoutingRules(t), "the last stop should remove rules 105 and 110")
	assert.Equal(t, "1", readRPFilter(t), "the last stop should restore the original sysctl value")
}

// A starting engine cleans up before its own setup. With another session running,
// that cleanup must not reach the live table.
func TestSharedRoutingBaseCleanupBeforeSetupKeepsRunningSession(t *testing.T) {
	requireAdvancedRouting(t)
	coordinator := hostcoord.New()
	running := NewShared(nil, nil, coordinator, hostcoord.SessionKey{Profile: "running"})
	starting := NewShared(nil, nil, coordinator, hostcoord.SessionKey{Profile: "starting"})

	require.NoError(t, running.SetupRouting(nil, nil, true))
	t.Cleanup(func() {
		assert.NoError(t, running.CleanupRouting(nil, true))
	})
	index := addSessionRoute(t, running, "nbcoordr0", "198.18.30.1/24", "198.51.100.0/24")

	require.NoError(t, starting.CleanupRouting(nil, true))

	assert.True(t, hasRouteVia(tableRoutes(t), index), "the cleanup of a starting session must keep live routes")
	assert.True(t, hasRoutingRules(t), "the cleanup of a starting session must keep rules 105 and 110")
}

// Without a coordinator the stop stays host-wide, as a single session expects.
func TestRoutingWithoutCoordinatorRestoresSysctlPerInstance(t *testing.T) {
	setStrictRPFilter(t)

	r := New(nil, nil)
	require.NoError(t, r.SetupRouting(nil, nil, true))
	assert.Equal(t, "2", readRPFilter(t), "setup should set rp_filter to loose")

	require.NoError(t, r.CleanupRouting(nil, true))
	assert.Equal(t, "1", readRPFilter(t), "cleanup should restore the original sysctl value")
	assert.False(t, hasRoutingRules(t), "cleanup should remove rules 105 and 110")
}
