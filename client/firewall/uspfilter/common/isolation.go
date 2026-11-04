package common

import (
	"fmt"
	"net/netip"
)

// IsolationSnapshot is what the other sessions of one daemon own. It is immutable once
// returned, so a reader can keep it for the duration of a packet without a lock.
type IsolationSnapshot struct {
	// Interfaces are the overlay interface names of the other sessions.
	Interfaces []string
	// Overlays are the overlay prefixes of the other sessions, IPv4 and IPv6.
	Overlays []netip.Prefix
}

// IsolationSource reports what the other sessions of this daemon own, so the userspace
// filter and the forwarder can keep a peer of one network out of another network.
//
// The method runs for every inbound packet, so an implementation returns a shared
// snapshot and does not allocate. A nil source means a host with one session.
type IsolationSource interface {
	// OtherSessions returns the interfaces and overlay prefixes of every session except
	// the caller's own. An error means the state is unknown and the caller must refuse.
	OtherSessions() (IsolationSnapshot, error)
}

// Validate rejects a snapshot the filter cannot trust, so a half-filled snapshot
// denies traffic instead of letting it through.
func (s IsolationSnapshot) Validate() error {
	for _, name := range s.Interfaces {
		if name == "" {
			return fmt.Errorf("empty interface name")
		}
	}
	for _, prefix := range s.Overlays {
		if !prefix.IsValid() || prefix.Addr().Is4In6() {
			return fmt.Errorf("invalid overlay prefix %v", prefix)
		}
	}
	return nil
}

// Covers reports whether addr lies in an overlay of another session.
func (s IsolationSnapshot) Covers(addr netip.Addr) bool {
	// A zone makes Prefix.Contains report false, which would let the address through.
	addr = addr.Unmap().WithZone("")
	for _, prefix := range s.Overlays {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// DeniesAddr reports whether traffic to or from addr must be refused because it belongs to
// another session. A nil source never denies. A source that fails or returns a snapshot that
// does not validate always denies, and the error says why.
func DeniesAddr(src IsolationSource, addr netip.Addr) (bool, error) {
	if src == nil {
		return false, nil
	}
	if !addr.IsValid() {
		return true, fmt.Errorf("invalid address")
	}
	snapshot, err := src.OtherSessions()
	if err != nil {
		return true, fmt.Errorf("read other sessions: %w", err)
	}
	if err := snapshot.Validate(); err != nil {
		return true, err
	}
	return snapshot.Covers(addr), nil
}
