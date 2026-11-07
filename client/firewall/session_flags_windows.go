//go:build windows

package firewall

import (
	"errors"
	"fmt"
	"net"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"github.com/netbirdio/netbird/client/iface/device"
)

// windowsAdapterFlags works on the IP interfaces of the adapter of a slot, found by the GUID of
// the slot. Another program can rename the adapter, its GUID stays.
type windowsAdapterFlags struct{}

var errAdapterAbsent = errors.New("adapter not present")

// slotLUID returns the LUID of the adapter of slot, or errAdapterAbsent. A GUID keeps resolving
// for a while after its adapter is gone, so presence is checked in the interface list as well.
func slotLUID(slot uint32) (winipcfg.LUID, error) {
	guid, err := device.SlotGUID(slot)
	if err != nil {
		return 0, err
	}
	luid, err := winipcfg.LUIDFromGUID(&guid)
	if err != nil {
		return 0, errAdapterAbsent
	}
	row, err := luid.Interface()
	if err != nil {
		return 0, errAdapterAbsent
	}
	if _, err := net.InterfaceByIndex(int(row.InterfaceIndex)); err != nil {
		return 0, errAdapterAbsent
	}
	return luid, nil
}

var families = []struct {
	name   string
	family winipcfg.AddressFamily
}{
	{"IPv4", windows.AF_INET},
	{"IPv6", windows.AF_INET6},
}

// isolate turns forwarding and the weak host model off on the adapter of slot. A family the
// adapter has no IP interface for is skipped; IPv4 has to be there.
func (windowsAdapterFlags) isolate(slot uint32) error {
	luid, err := slotLUID(slot)
	if err != nil {
		return err
	}
	for _, f := range families {
		row, err := luid.IPInterface(f.family)
		if err != nil {
			if f.family == windows.AF_INET {
				return fmt.Errorf("read %s interface: %w", f.name, err)
			}
			continue
		}
		row.ForwardingEnabled = false
		row.WeakHostSend = false
		row.WeakHostReceive = false
		if f.family == windows.AF_INET {
			// SetIpInterfaceEntry refuses an IPv4 row with a site prefix length.
			row.SitePrefixLength = 0
		}
		if err := row.Set(); err != nil {
			return fmt.Errorf("set %s interface: %w", f.name, err)
		}
	}
	return nil
}

// check reports a flag that would let a packet cross to another adapter. An adapter that is gone
// delivers nothing and passes.
func (windowsAdapterFlags) check(slot uint32) error {
	luid, err := slotLUID(slot)
	if errors.Is(err, errAdapterAbsent) {
		return nil
	}
	if err != nil {
		return err
	}
	var errs []error
	for _, f := range families {
		row, err := luid.IPInterface(f.family)
		if err != nil {
			continue
		}
		if row.ForwardingEnabled {
			errs = append(errs, fmt.Errorf("%s forwarding is on", f.name))
		}
		if row.WeakHostReceive {
			errs = append(errs, fmt.Errorf("%s weak host receive is on", f.name))
		}
		if row.WeakHostSend {
			errs = append(errs, fmt.Errorf("%s weak host send is on", f.name))
		}
	}
	return errors.Join(errs...)
}
