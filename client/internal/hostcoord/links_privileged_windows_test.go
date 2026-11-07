//go:build privileged && windows

package hostcoord

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"

	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/wgbackend"
)

// High slots, so the tests never meet the adapter of a session that runs on the host.
const (
	testSlot      Slot = 61
	testSlotName       = "wt61"
	testOtherSlot Slot = 62
)

func createTestAdapter(t *testing.T, name string, guid windows.GUID) *wgbackend.NativeTUN {
	t.Helper()
	dev, err := wgbackend.CreateTUNWithRequestedGUID(name, &guid, 1280)
	require.NoError(t, err, "create adapter %s", name)
	nt := dev.(*wgbackend.NativeTUN)
	t.Cleanup(func() { _ = nt.Close() })
	return nt
}

func slotGUID(t *testing.T, slot Slot) windows.GUID {
	t.Helper()
	guid, err := device.SlotGUID(uint32(slot))
	require.NoError(t, err)
	return guid
}

func adapterName(t *testing.T, guid windows.GUID) string {
	t.Helper()
	adapters, err := listPresentAdapters()
	require.NoError(t, err)
	for _, a := range adapters {
		if a.guid == guid {
			return a.name
		}
	}
	return ""
}

func TestRefuseForeignLink_FreeName(t *testing.T) {
	assert.NoError(t, RefuseForeignLink(t.Context(), testSlotName, testSlot))
}

func TestRefuseForeignLink_ForeignAdapterWithTheName(t *testing.T) {
	foreign := slotGUID(t, testOtherSlot)
	createTestAdapter(t, testSlotName, foreign)

	start := time.Now()
	err := RefuseForeignLink(t.Context(), testSlotName, testSlot)
	assert.ErrorIs(t, err, ErrForeignLink, "creating the slot's adapter would rename the foreign one")
	assert.Less(t, time.Since(start), closingAdapterWait, "a foreign adapter is refused at once, not waited for")
	assert.Equal(t, testSlotName, adapterName(t, foreign), "the foreign adapter keeps its name")
}

func TestRefuseForeignLink_WaitsForTheAdapterOfAPreviousAttempt(t *testing.T) {
	previous := createTestAdapter(t, testSlotName, slotGUID(t, testSlot))
	go func() {
		time.Sleep(time.Second)
		_ = previous.Close()
	}()

	start := time.Now()
	require.NoError(t, RefuseForeignLink(t.Context(), testSlotName, testSlot),
		"the adapter of a previous attempt goes away, which is what the wait is for")
	assert.GreaterOrEqual(t, time.Since(start), time.Second, "the check waited for the adapter to go")

	// The point of the wait: the slot's adapter can be created again right after it.
	createTestAdapter(t, testSlotName, slotGUID(t, testSlot))
}

func TestRefuseForeignLink_AdapterOfTheSlotThatStays(t *testing.T) {
	createTestAdapter(t, testSlotName, slotGUID(t, testSlot))

	start := time.Now()
	err := RefuseForeignLink(t.Context(), testSlotName, testSlot)
	assert.ErrorIs(t, err, ErrForeignLink, "no adapter can be created on a GUID that is taken")
	assert.GreaterOrEqual(t, time.Since(start), closingAdapterWait, "the adapter got its time to go away")
}

func TestRefuseForeignLink_StopsWaitingWithItsContext(t *testing.T) {
	createTestAdapter(t, testSlotName, slotGUID(t, testSlot))

	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	err := RefuseForeignLink(ctx, testSlotName, testSlot)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.NotErrorIs(t, err, ErrForeignLink, "a cancelled wait says nothing about the adapter")
}

func TestListPresentAdapters_DropsAClosedAdapter(t *testing.T) {
	guid := slotGUID(t, testSlot)
	nt := createTestAdapter(t, testSlotName, guid)
	require.Equal(t, testSlotName, adapterName(t, guid), "a live adapter is listed")

	require.NoError(t, nt.Close())
	assert.Eventually(t, func() bool { return adapterName(t, guid) == "" }, closingAdapterWait, 50*time.Millisecond,
		"a closed adapter leaves the listing")
	_, err := net.InterfaceByName(testSlotName)
	assert.Error(t, err, "and the name is free again")
}
