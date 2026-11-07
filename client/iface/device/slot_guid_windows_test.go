//go:build windows

package device

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func setCustomGUID(t *testing.T, guid string) {
	t.Helper()
	previous := CustomWindowsGUIDString
	CustomWindowsGUIDString = guid
	t.Cleanup(func() { CustomWindowsGUIDString = previous })
}

func TestSlotGUID_SlotZeroKeepsTheAdapterOfToday(t *testing.T) {
	setCustomGUID(t, "")

	got, err := SlotGUID(0)
	require.NoError(t, err)
	want, err := windows.GUIDFromString(defaultWindowsGUIDSTring)
	require.NoError(t, err)
	assert.Equal(t, want, got, "slot 0 must keep the GUID a client without sessions uses")
}

func TestSlotGUID_EverySlotHasItsOwnStableAdapter(t *testing.T) {
	setCustomGUID(t, "")

	// The value is fixed so that a change of the derivation, which would leave the adapters of
	// the previous version behind under GUIDs nobody looks for, fails here. It is RFC 9562
	// UUIDv5 of "slot-1" in the namespace of the default GUID, computed outside Go.
	want := map[uint32]string{
		1: "{FF576BB7-1075-5F97-9CAB-CE8F9FD52AC8}",
	}
	seen := map[windows.GUID]uint32{}
	for slot := uint32(0); slot < 32; slot++ {
		got, err := SlotGUID(slot)
		require.NoError(t, err)
		other, taken := seen[got]
		assert.False(t, taken, "slot %d has the GUID of slot %d", slot, other)
		seen[got] = slot

		again, err := SlotGUID(slot)
		require.NoError(t, err)
		assert.Equal(t, got, again, "slot %d gets the same adapter on every start", slot)

		if w, ok := want[slot]; ok {
			assert.Equal(t, w, got.String(), "GUID of slot %d", slot)
		}
	}
}

func TestSlotGUID_FollowsACustomBase(t *testing.T) {
	setCustomGUID(t, "")
	defaultSlot1, err := SlotGUID(1)
	require.NoError(t, err)

	const custom = "{0b9c8e1e-5c2a-4b8e-9d55-3f2b1a7c6d01}"
	setCustomGUID(t, custom)

	zero, err := SlotGUID(0)
	require.NoError(t, err)
	want, err := windows.GUIDFromString(custom)
	require.NoError(t, err)
	assert.Equal(t, want, zero, "slot 0 uses the custom GUID as it is")

	one, err := SlotGUID(1)
	require.NoError(t, err)
	assert.NotEqual(t, defaultSlot1, one, "the slots of a custom base do not collide with the default ones")
	assert.NotEqual(t, zero, one, "slot 1 is not the adapter of slot 0")
}

func TestSlotGUID_InvalidCustomBaseIsAnError(t *testing.T) {
	setCustomGUID(t, "not-a-guid")

	_, err := SlotGUID(0)
	assert.Error(t, err, "slot 0 refuses an unparsable GUID")
	_, err = SlotGUID(1)
	assert.Error(t, err, "and so does every other slot")
}
