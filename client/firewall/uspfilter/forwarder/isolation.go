package forwarder

import (
	"net"
	"net/netip"

	"github.com/netbirdio/netbird/client/firewall/uspfilter/common"
	nblog "github.com/netbirdio/netbird/client/firewall/uspfilter/log"
)

// isolationHolder lets an interface value sit in an atomic pointer.
type isolationHolder struct {
	src common.IsolationSource
}

// SetIsolation sets where the forwarder learns about the other sessions of the daemon. A nil
// source is the behavior of a host with a single session.
func (f *Forwarder) SetIsolation(src common.IsolationSource) {
	if src == nil {
		f.isolation.Store(nil)
		return
	}
	f.isolation.Store(&isolationHolder{src: src})
}

func (f *Forwarder) isolationSource() common.IsolationSource {
	holder := f.isolation.Load()
	if holder == nil {
		return nil
	}
	return holder.src
}

// isolationRefuses reports whether a flow to dst must be refused because dst lies in the
// overlay of another session. A source that fails refuses too (I6).
func (f *Forwarder) isolationRefuses(dst netip.Addr) bool {
	denied, err := common.DeniesAddr(f.isolationSource(), dst)
	if denied && f.logger.Enabled(nblog.LevelTrace) {
		f.logger.Trace2("forwarder: refusing destination in another session (state error: %v): %v", err, dst)
	}
	return denied
}

// isOtherSessionAddr reports whether the local address the host picked for a connected
// socket belongs to another session, which means the flow would leave through that
// session's interface. An address that cannot be read refuses.
func (f *Forwarder) isOtherSessionAddr(local net.Addr) bool {
	udpAddr, ok := local.(*net.UDPAddr)
	if !ok {
		return f.isolationSource() != nil
	}
	return f.isolationRefuses(udpAddr.AddrPort().Addr())
}
