//go:build !linux && !android && !ios

package systemops

import "net/netip"

// GetDefaultNextHopExcluding is GetNextHop on this platform, which runs one session.
func GetDefaultNextHopExcluding(ip netip.Addr, _ []string) (Nexthop, error) {
	return GetNextHop(ip)
}
