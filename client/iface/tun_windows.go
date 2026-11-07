//go:build windows

package iface

import (
	"github.com/netbirdio/netbird/client/iface/bind"
	"github.com/netbirdio/netbird/client/iface/device"
)

func newTunDevice(opts WGIFaceOpts, iceBind *bind.ICEBind) WGTunDevice {
	return device.NewSlotTunDevice(opts.IFaceName, opts.Slot, opts.Address, opts.WGPort, opts.WGPrivKey, opts.MTU, iceBind)
}
