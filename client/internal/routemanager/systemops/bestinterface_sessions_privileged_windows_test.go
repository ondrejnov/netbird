//go:build privileged && windows

package systemops

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/wgbackend"
)

func createSessionAdapter(t *testing.T, name string, slot uint32, prefix netip.Prefix) winipcfg.LUID {
	t.Helper()
	guid, err := device.SlotGUID(slot)
	require.NoError(t, err)
	dev, err := wgbackend.CreateTUNWithRequestedGUID(name, &guid, 1280)
	require.NoError(t, err, "create adapter %s", name)
	nt := dev.(*wgbackend.NativeTUN)
	t.Cleanup(func() { _ = nt.Close() })
	luid := winipcfg.LUID(nt.LUID())
	require.NoError(t, luid.SetIPAddresses([]netip.Prefix{prefix}))
	require.Eventually(t, func() bool {
		ifc, err := net.InterfaceByName(name)
		return err == nil && ifc.Flags&net.FlagUp != 0
	}, 10*time.Second, 100*time.Millisecond, "adapter %s comes up", name)
	return luid
}

// Session A carries a route that is more specific than the default route of the host, as its exit
// node or a network route would be. The sockets of session B must not be bound to A's adapter.
// TEST-NET-2 stands in for the internet, so the host keeps its connectivity while the test runs.
func TestGetBestInterface_SkipsTheInterfacesOfAllSessions(t *testing.T) {
	dest := netip.MustParseAddr("198.51.100.7")
	routed := netip.MustParsePrefix("198.51.100.0/24")

	before, err := GetBestInterface(dest)
	require.NoError(t, err, "the host needs a default route for this test")

	luidA := createSessionAdapter(t, "wt64", 64, netip.MustParsePrefix("100.91.0.1/16"))
	createSessionAdapter(t, "wt65", 65, netip.MustParsePrefix("100.92.0.1/16"))
	require.NoError(t, luidA.AddRoute(routed, netip.IPv4Unspecified(), 0))
	t.Cleanup(func() { _ = luidA.DeleteRoute(routed, netip.IPv4Unspecified()) })

	onlyOwn, err := GetBestInterface(dest, "wt65")
	require.NoError(t, err)
	assert.Equal(t, "wt64", onlyOwn.Name, "skipping only its own interface hands session B the route of session A")

	all, err := GetBestInterface(dest, "wt65", "wt64")
	require.NoError(t, err)
	assert.Equal(t, before.Name, all.Name, "skipping every session's interface leaves the host's own route")

	missing, err := GetBestInterface(dest, "wt65", "wt64", "wt99")
	require.NoError(t, err, "an interface that does not exist is no reason to fail")
	assert.Equal(t, before.Name, missing.Name)
}
