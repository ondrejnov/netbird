//go:build !ios

package dns

import (
	"fmt"
)

type ShutdownState struct {
	CreatedKeys []string
	// Slot is the slot of the session that created the keys. Without recorded keys the cleanup
	// looks for the keys of this slot only, so it cannot take those of another session.
	Slot uint32 `json:",omitempty"`
}

func (s *ShutdownState) Name() string {
	return "dns_state"
}

func (s *ShutdownState) Cleanup() error {
	manager := newSlotHostManager(s.Slot)
	for _, key := range s.CreatedKeys {
		manager.createdKeys[key] = struct{}{}
	}

	if err := manager.restoreUncleanShutdownDNS(); err != nil {
		return fmt.Errorf("restore unclean shutdown dns: %w", err)
	}

	return nil
}
