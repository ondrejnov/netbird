//go:build privileged && windows

package firewall

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/iface/wgbackend"
)

// A high slot, so the test never meets the adapter of a session that runs on the host.
const isolationTestSlot = 63

func createSlotAdapter(t *testing.T, slot uint32) winipcfg.LUID {
	t.Helper()
	guid, err := device.SlotGUID(slot)
	require.NoError(t, err)
	dev, err := wgbackend.CreateTUNWithRequestedGUID("wt63", &guid, 1280)
	require.NoError(t, err, "create the adapter of slot %d", slot)
	nt := dev.(*wgbackend.NativeTUN)
	t.Cleanup(func() { _ = nt.Close() })
	return winipcfg.LUID(nt.LUID())
}

func setIPv4Row(t *testing.T, luid winipcfg.LUID, change func(*winipcfg.MibIPInterfaceRow)) {
	t.Helper()
	row, err := luid.IPInterface(windows.AF_INET)
	require.NoError(t, err)
	change(row)
	row.SitePrefixLength = 0
	require.NoError(t, row.Set())
}

func TestSessionIsolation_AdapterFlags(t *testing.T) {
	luid := createSlotAdapter(t, isolationTestSlot)
	// Start from the worst case: the flags I3 and I4 rely on are on, as ICS would leave them.
	setIPv4Row(t, luid, func(r *winipcfg.MibIPInterfaceRow) {
		r.ForwardingEnabled = true
		r.WeakHostReceive = true
		r.WeakHostSend = true
	})

	iso := NewSessionIsolation()
	_, err := iso.Add("wt63", wgaddr.MustParseWGAddress("100.81.0.1/16"))
	require.NoError(t, err)
	require.NoError(t, iso.attach("wt63", isolationTestSlot), "attaching sets the flags")

	for _, family := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		row, err := luid.IPInterface(family)
		if err != nil {
			continue
		}
		assert.False(t, row.ForwardingEnabled, "family %d: forwarding is off", family)
		assert.False(t, row.WeakHostReceive, "family %d: weak host receive is off", family)
		assert.False(t, row.WeakHostSend, "family %d: weak host send is off", family)
	}
	require.NoError(t, iso.Verify())

	setIPv4Row(t, luid, func(r *winipcfg.MibIPInterfaceRow) { r.ForwardingEnabled = true })
	assert.Error(t, iso.Verify(), "forwarding turned on behind the daemon's back is a lost isolation")

	require.NoError(t, iso.Restore())
	assert.NoError(t, iso.Verify(), "Restore turns it off again")
	row, err := luid.IPInterface(windows.AF_INET)
	require.NoError(t, err)
	assert.False(t, row.ForwardingEnabled, "and the adapter really has it off")
}
