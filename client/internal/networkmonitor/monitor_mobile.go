//go:build ios || android

package networkmonitor

import (
	"context"
	"fmt"
)

type NetworkMonitor struct {
}

// New creates a new network monitor.
// Option configures a NetworkMonitor, which this platform does not run.
type Option func(*NetworkMonitor)

// WithNetbirdInterfaces does nothing on this platform.
func WithNetbirdInterfaces(func() []string) Option {
	return func(*NetworkMonitor) {}
}

func New(_ ...Option) *NetworkMonitor {
	return &NetworkMonitor{}
}

func (nw *NetworkMonitor) Listen(_ context.Context) error {
	return fmt.Errorf("network monitor not supported on mobile platforms")
}

func (nw *NetworkMonitor) Stop() {
}
