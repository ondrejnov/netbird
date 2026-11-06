//go:build linux && !android

package conntrack

import "net/netip"

// WithSessionFlows makes the instance report only the flows of its session, for a daemon with
// several of them. Conntrack events cover the whole host and the marks are shared between sessions,
// so a mark says nothing about the session (R1). otherOverlays returns the prefixes of the others.
func WithSessionFlows(otherOverlays func() []netip.Prefix) Option {
	return func(c *ConnTrack) {
		c.otherOverlays = otherOverlays
	}
}

// sessionFlow reports whether a flow carries an overlay address of this session and none of another
// one. A flow with the addresses of two networks would tell each about the other (I5).
func (c *ConnTrack) sessionFlow(srcIP, dstIP netip.Addr) bool {
	addr := c.iface.Address()
	inOverlay := func(ip netip.Addr) bool {
		return addr.Network.Contains(ip) || (addr.IPv6Net.IsValid() && addr.IPv6Net.Contains(ip))
	}
	if !inOverlay(srcIP) && !inOverlay(dstIP) {
		return false
	}
	for _, other := range c.otherOverlays() {
		if other.Contains(srcIP) || other.Contains(dstIP) {
			return false
		}
	}
	return true
}
