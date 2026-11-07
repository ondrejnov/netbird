//go:build windows

package hostcoord

import (
	"context"
	"fmt"
	"net"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"github.com/netbirdio/netbird/client/iface/device"
)

const (
	// closingAdapterWait is how long the adapter of a previous attempt gets to go away. Wintun
	// removes it a couple of seconds after its handle closes, also when the process was killed,
	// and until then no adapter can be created with its GUID.
	closingAdapterWait = 5 * time.Second
	closingAdapterPoll = 50 * time.Millisecond
)

// RemoveSessionLinks does nothing: Wintun removes the adapter of a session when the daemon exits,
// also when it crashes, so none outlives it.
func RemoveSessionLinks([]SlotRecord) error {
	return nil
}

// VerifyNoSessionLinks finds nothing, for the same reason.
func VerifyNoSessionLinks([]SlotRecord) error {
	return nil
}

// presentAdapter is an adapter Windows lists as present, with what tells whose it is.
type presentAdapter struct {
	name string
	guid windows.GUID
}

type linkVerdict int

const (
	linkFree linkVerdict = iota
	// linkClosing means the adapter of the slot is still there, the one of a previous attempt.
	linkClosing
	// linkForeign means another adapter has the name of the slot. Creating the adapter of the
	// slot would rename that one, and lookups by name would find the wrong adapter.
	linkForeign
)

// judgeAdapters decides what the present adapters mean for the adapter of a slot called name
// with slotGUID.
func judgeAdapters(adapters []presentAdapter, name string, slotGUID windows.GUID) (linkVerdict, string) {
	verdict := linkFree
	detail := ""
	for _, a := range adapters {
		switch {
		case a.name == name && a.guid != slotGUID:
			return linkForeign, fmt.Sprintf("%s is an adapter with GUID %s, the slot has %s", name, a.guid, slotGUID)
		case a.guid == slotGUID:
			verdict = linkClosing
			detail = fmt.Sprintf("the adapter %q with the GUID of %s stays", a.name, name)
		}
	}
	return verdict, detail
}

// RefuseForeignLink refuses to bring the adapter of slot up as name where that cannot work: an
// adapter that is not the slot's has the name, or the slot's own adapter, left by a previous
// attempt, does not go away within closingAdapterWait. Any lookup failure counts as well, as
// nobody can tell what is there.
func RefuseForeignLink(ctx context.Context, name string, slot Slot) error {
	slotGUID, err := device.SlotGUID(uint32(slot))
	if err != nil {
		return fmt.Errorf("GUID of slot %d: %w", slot, err)
	}

	timeout := time.NewTimer(closingAdapterWait)
	defer timeout.Stop()
	poll := time.NewTicker(closingAdapterPoll)
	defer poll.Stop()

	for {
		adapters, err := listPresentAdapters()
		if err != nil {
			return fmt.Errorf("list adapters: %w", err)
		}
		verdict, detail := judgeAdapters(adapters, name, slotGUID)
		switch verdict {
		case linkFree:
			return nil
		case linkForeign:
			return fmt.Errorf("%w: %s", ErrForeignLink, detail)
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for the adapter of %s to go away: %w", name, ctx.Err())
		case <-timeout.C:
			return fmt.Errorf("%w: %s", ErrForeignLink, detail)
		case <-poll.C:
		}
	}
}

// listPresentAdapters lists the adapters net.Interfaces sees. The interface table also keeps rows
// of adapters that are gone, and their GUIDs still resolve for a while, so it cannot tell.
func listPresentAdapters() ([]presentAdapter, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	adapters := make([]presentAdapter, 0, len(ifaces))
	for _, ifc := range ifaces {
		guid, err := adapterGUID(ifc.Index)
		if err != nil {
			if _, gone := net.InterfaceByIndex(ifc.Index); gone != nil {
				// It went away since the listing, as a closing adapter does.
				continue
			}
			return nil, fmt.Errorf("GUID of %s: %w", ifc.Name, err)
		}
		adapters = append(adapters, presentAdapter{name: ifc.Name, guid: guid})
	}
	return adapters, nil
}

func adapterGUID(index int) (windows.GUID, error) {
	luid, err := winipcfg.LUIDFromIndex(uint32(index))
	if err != nil {
		return windows.GUID{}, err
	}
	guid, err := luid.GUID()
	if err != nil {
		return windows.GUID{}, err
	}
	return *guid, nil
}
