//go:build !android && !ios && !freebsd && !js

package preferences

import (
	"fmt"
	"slices"
)

// SetStartupProfile adds or removes a profile ID from StartupProfiles, then
// persists and broadcasts. No-op if unchanged.
func (s *Store) SetStartupProfile(profileID string, enabled bool) error {
	if profileID == "" {
		return fmt.Errorf("empty profile ID")
	}

	s.mu.Lock()
	if slices.Contains(s.current.StartupProfiles, profileID) == enabled {
		s.mu.Unlock()
		return nil
	}
	next := s.current
	if enabled {
		next.StartupProfiles = append(slices.Clone(s.current.StartupProfiles), profileID)
	} else {
		next.StartupProfiles = slices.DeleteFunc(slices.Clone(s.current.StartupProfiles), func(id string) bool {
			return id == profileID
		})
	}
	if err := s.persistLocked(next); err != nil {
		s.mu.Unlock()
		return fmt.Errorf("persist preferences: %w", err)
	}
	s.current = next
	s.mu.Unlock()

	s.broadcast(next)
	return nil
}
