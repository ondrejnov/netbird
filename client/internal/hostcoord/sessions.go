package hostcoord

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
)

// SessionSource reports what the sessions of one daemon own, so an engine can keep
// the interfaces and addresses of the other sessions out of what it exposes.
type SessionSource interface {
	// SessionInterfaces returns the interface names of all sessions.
	SessionInterfaces() []string
	// OverlayPrefixes returns the overlay prefixes of all sessions.
	OverlayPrefixes() []netip.Prefix
}

type sessionEntry struct {
	iface    string
	prefixes []netip.Prefix
}

// Sessions records the interface and overlay prefixes of every running session.
type Sessions struct {
	mu      sync.Mutex
	entries map[SessionKey]sessionEntry
}

// NewSessions returns an empty Sessions.
func NewSessions() *Sessions {
	return &Sessions{entries: make(map[SessionKey]sessionEntry)}
}

// Set records the interface and overlay prefixes of key, replacing an earlier
// record. A name that does not fit the kernel limits is rejected, never truncated.
func (s *Sessions) Set(key SessionKey, iface string, prefixes ...netip.Prefix) error {
	if err := validateInterfaceName(iface); err != nil {
		return err
	}
	masked := make([]netip.Prefix, 0, len(prefixes))
	for _, p := range prefixes {
		if !p.IsValid() {
			return fmt.Errorf("invalid overlay prefix %v", p)
		}
		masked = append(masked, p.Masked())
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[key] = sessionEntry{iface: iface, prefixes: masked}
	return nil
}

// Remove drops the record of key.
func (s *Sessions) Remove(key SessionKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, key)
}

// SessionInterfaces returns the interface names of all sessions.
func (s *Sessions) SessionInterfaces() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	names := make([]string, 0, len(s.entries))
	for _, e := range s.entries {
		names = append(names, e.iface)
	}
	return names
}

// OverlayPrefixes returns the overlay prefixes of all sessions.
func (s *Sessions) OverlayPrefixes() []netip.Prefix {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []netip.Prefix
	for _, e := range s.entries {
		out = append(out, e.prefixes...)
	}
	return slices.Clone(out)
}

func validateInterfaceName(name string) error {
	if name == "" {
		return fmt.Errorf("empty interface name")
	}
	if len(name) > maxInterfaceNameLen {
		return fmt.Errorf("interface name %q is longer than %d bytes", name, maxInterfaceNameLen)
	}
	if strings.ContainsAny(name, "/ \t\n\r\x00") {
		return fmt.Errorf("interface name %q contains a forbidden character", name)
	}
	return nil
}
