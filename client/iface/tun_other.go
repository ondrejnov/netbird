//go:build !linux && !ios && !android && !js && !windows

package iface

import (
	"github.com/netbirdio/netbird/client/iface/bind"
	"github.com/netbirdio/netbird/client/iface/device"
)

func newTunDevice(opts WGIFaceOpts, iceBind *bind.ICEBind) WGTunDevice {
	return device.NewTunDevice(opts.IFaceName, opts.Address, opts.WGPort, opts.WGPrivKey, opts.MTU, iceBind)
}
