package uspfilter

import (
	"net/netip"

	"github.com/netbirdio/netbird/client/firewall/uspfilter/common"
	nblog "github.com/netbirdio/netbird/client/firewall/uspfilter/log"
)

// dropIsolated reports whether a packet addressed to dstIP must be dropped because dstIP
// belongs to another session. It covers local delivery to that session's address (I4) and
// routing into its network (I3): both reach the host through this interface, and the
// route ACLs of this network cannot grant access to a network they do not manage.
// Without a source it never drops. A source that fails drops, never passes (I6).
func (m *Manager) dropIsolated(srcIP, dstIP netip.Addr) bool {
	denied, err := common.DeniesAddr(m.isolation, dstIP)
	if !denied {
		return false
	}

	if m.logger.Enabled(nblog.LevelTrace) {
		if err != nil {
			m.logger.Trace3("Dropping packet (session isolation unknown): src=%s dst=%s: %v", srcIP, dstIP, err)
		} else {
			m.logger.Trace2("Dropping packet (other session): src=%s dst=%s", srcIP, dstIP)
		}
	}
	return true
}
