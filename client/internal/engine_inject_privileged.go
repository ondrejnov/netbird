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
