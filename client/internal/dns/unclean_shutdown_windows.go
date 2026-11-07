package dns

import (
	"fmt"
)

type ShutdownState struct {
	Guid string
	GPO  bool
	// Slot names the rule keys to remove. State from before slots holds 0, the names it used.
	Slot uint32 `json:",omitempty"`
}

func (s *ShutdownState) Name() string {
	return "dns_state"
}

func (s *ShutdownState) Cleanup() error {
	manager := &registryConfigurator{
		guid: s.Guid,
		gpo:  s.GPO,
		slot: s.Slot,
	}

	if err := manager.restoreUncleanShutdownDNS(); err != nil {
		return fmt.Errorf("restore unclean shutdown dns: %w", err)
	}

	return nil
}
