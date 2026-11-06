//go:build linux && !android && privileged

package systemops

import (
	"net"
	"net/netip"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func addDummyLink(t *testing.T, name, address string) netlink.Link {
	t.Helper()
	link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}
	require.NoError(t, netlink.LinkAdd(link))
	addr, err := netlink.ParseAddr(address)
	require.NoError(t, err)
	require.NoError(t, netlink.AddrAdd(link, addr))
	require.NoError(t, netlink.LinkSetUp(link))
	return link
}

// I8: an exit node of any session puts a default route through its interface in the shared table. A
// monitor that watches that next hop misses the physical default going away, and a restart of the
// session that added it would look like a network change to the others.
func TestGetDefaultNextHopExcludingFindsThePhysicalDefault(t *testing.T) {
	runtime.LockOSThread()
	require.NoError(t, unix.Unshare(unix.CLONE_NEWNET), "enter a network namespace")

	physical := addDummyLink(t, "phys0", "192.0.2.2/24")
	session := addDummyLink(t, "wtx", "100.64.0.1/16")

	gateway := net.ParseIP("192.0.2.1")
	require.NoError(t, netlink.RouteAdd(&netlink.Route{LinkIndex: physical.Attrs().Index, Gw: gateway, Priority: 100}))
	require.NoError(t, netlink.RouteAdd(&netlink.Route{
		LinkIndex: session.Attrs().Index,
		Dst:       &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
		Table:     NetbirdVPNTableID,
	}))
	rule := netlink.NewRule()
	rule.Priority = 110
	rule.Table = NetbirdVPNTableID
	rule.Family = netlink.FAMILY_V4
	require.NoError(t, netlink.RuleAdd(rule))

	unspecified := netip.IPv4Unspecified()

	nexthop, err := GetDefaultNextHopExcluding(unspecified, []string{"wtx"})
	require.NoError(t, err)
	require.NotNil(t, nexthop.Intf)
	assert.Equal(t, "phys0", nexthop.Intf.Name, "the interface of the session must not count as the next hop")
	assert.Equal(t, netip.MustParseAddr("192.0.2.1"), nexthop.IP)

	require.NoError(t, netlink.RouteDel(&netlink.Route{LinkIndex: physical.Attrs().Index, Gw: gateway, Priority: 100}))
	_, err = GetDefaultNextHopExcluding(unspecified, []string{"wtx"})
	assert.Error(t, err, "with only the interface of a session left there is no next hop")

	other, err := GetDefaultNextHopExcluding(unspecified, nil)
	require.NoError(t, err)
	require.NotNil(t, other.Intf)
	assert.Equal(t, "wtx", other.Intf.Name, "without an exclusion the lookup itself finds the session")
}
