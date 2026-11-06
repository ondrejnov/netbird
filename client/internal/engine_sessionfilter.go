package internal

import (
	"net/netip"
	"slices"

	"github.com/netbirdio/netbird/client/internal/hostcoord"
	"github.com/netbirdio/netbird/client/system"
)

// excludeSessionAddresses keeps the addresses of all sessions out of what goes to
// Management (I5).
func (e *Engine) excludeSessionAddresses(info *system.Info) {
	if e.config.Sessions == nil {
		return
	}
	excludeAddressesOf(e.config.Sessions, info)
}

// excludeAddressesOf drops every address inside an overlay prefix of any session
// from the reported network addresses. It builds a new slice because the info
// source may share the gathered one between calls.
func excludeAddressesOf(sessions hostcoord.SessionSource, info *system.Info) {
	prefixes := sessions.OverlayPrefixes()
	if len(prefixes) == 0 {
		return
	}
	kept := make([]system.NetworkAddress, 0, len(info.NetworkAddresses))
	for _, addr := range info.NetworkAddresses {
		ip := addr.NetIP.Addr().Unmap()
		if slices.ContainsFunc(prefixes, func(p netip.Prefix) bool { return p.Contains(ip) }) {
			continue
		}
		kept = append(kept, addr)
	}
	info.NetworkAddresses = kept
}

// iceBlackList returns the interface blacklist for ICE candidate gathering with
// the interfaces of all sessions added. The filter matches by prefix, so a short
// session name also covers longer ones, which errs on the side of exclusion.
func (e *Engine) iceBlackList() []string {
	if e.config.Sessions == nil {
		return e.config.IFaceBlackList
	}
	out := slices.Clone(e.config.IFaceBlackList)
	for _, name := range e.config.Sessions.SessionInterfaces() {
		if !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	return out
}
