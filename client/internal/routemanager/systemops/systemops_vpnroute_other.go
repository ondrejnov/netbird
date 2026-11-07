//go:build !linux && !ios && !js && !windows

package systemops

import (
	"net"
	"net/netip"
)

func (r *SysOps) AddVPNRoute(prefix netip.Prefix, intf *net.Interface) error {
	if err := r.validateRoute(prefix); err != nil {
		return err
	}
	return r.genericAddVPNRoute(prefix, intf)
}

func (r *SysOps) RemoveVPNRoute(prefix netip.Prefix, intf *net.Interface) error {
	if err := r.validateRoute(prefix); err != nil {
		return err
	}
	return r.genericRemoveVPNRoute(prefix, intf)
}
