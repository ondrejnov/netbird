package hostcoord

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/netbirdio/netbird/client/firewall/uspfilter/common"
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
	// views is what the userspace filter reads for every packet, replaced on every change.
	views atomic.Pointer[isolationViews]
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
	s.rebuildViewsLocked()
	return nil
}

// Remove drops the record of key.
func (s *Sessions) Remove(key SessionKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, key)
	s.rebuildViewsLocked()
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

// OverlayPrefixesExcept returns the overlay prefixes of all sessions other than key.
func (s *Sessions) OverlayPrefixesExcept(key SessionKey) []netip.Prefix {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []netip.Prefix
	for other, e := range s.entries {
		if other != key {
			out = append(out, e.prefixes...)
		}
	}
	return out
}

// IsolationSource returns what the userspace filter of the session key reads to keep its peers out
// of the other sessions.
func (s *Sessions) IsolationSource(key SessionKey) common.IsolationSource {
	return sessionIsolationSource{sessions: s, key: key}
}

// isolationViews holds an immutable snapshot for each session, and one with all sessions for a
// session that has no record yet.
type isolationViews struct {
	all    common.IsolationSnapshot
	except map[SessionKey]common.IsolationSnapshot
}

func (s *Sessions) rebuildViewsLocked() {
	views := &isolationViews{except: make(map[SessionKey]common.IsolationSnapshot, len(s.entries))}
	for _, entry := range s.entries {
		views.all.Interfaces = append(views.all.Interfaces, entry.iface)
		views.all.Overlays = append(views.all.Overlays, entry.prefixes...)
	}
	for key := range s.entries {
		var snapshot common.IsolationSnapshot
		for other, entry := range s.entries {
			if other != key {
				snapshot.Interfaces = append(snapshot.Interfaces, entry.iface)
				snapshot.Overlays = append(snapshot.Overlays, entry.prefixes...)
			}
		}
		views.except[key] = snapshot
	}
	s.views.Store(views)
}

type sessionIsolationSource struct {
	sessions *Sessions
	key      SessionKey
}

// OtherSessions returns the interfaces and overlay prefixes of the other sessions.
func (v sessionIsolationSource) OtherSessions() (common.IsolationSnapshot, error) {
	views := v.sessions.views.Load()
	if views == nil {
		return common.IsolationSnapshot{}, nil
	}
	if snapshot, ok := views.except[v.key]; ok {
		return snapshot, nil
	}
	return views.all, nil
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
