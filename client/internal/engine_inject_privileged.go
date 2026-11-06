//go:build privileged

package internal

import "errors"

// injectOffset leaves the room a TUN write needs in front of the packet.
const injectOffset = 16

// InjectFromPeer hands a raw IP packet to the interface as if a peer had sent it through the tunnel.
// It exists for the privileged tests and needs a userspace interface.
func (e *Engine) InjectFromPeer(packet []byte) error {
	device := e.wgInterface.GetDevice()
	if device == nil {
		return errors.New("the interface has no userspace device")
	}
	buf := make([]byte, injectOffset+len(packet))
	copy(buf[injectOffset:], packet)
	_, err := device.Write([][]byte{buf}, injectOffset)
	return err
}

// DrivesUpdates reports whether Management drives the updater through this engine. It exists for
// the privileged tests.
func (e *Engine) DrivesUpdates() bool {
	return e.updateManager != nil
}

// WaitsForCertificateSlot reports whether a certificate collection of this engine waits for a
// slot another one holds. It exists for the privileged tests.
func (e *Engine) WaitsForCertificateSlot() bool {
	return e.certProofs.WaitForSlot
}

// InterfaceMTU returns the MTU of the interface of this engine, which the DNS server of the engine
// reads. It exists for the privileged tests.
func (e *Engine) InterfaceMTU() uint16 {
	return e.wgInterface.MTU()
}
