// Package hostcoord coordinates host resources shared by concurrent sessions
// running in one daemon.
package hostcoord

import (
	"sync"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
)

// SessionKey identifies one session. The type lives in profilemanager, which state
// paths are derived in and which cannot import this package.
type SessionKey = profilemanager.SessionKey

// RoutingBase describes the routing state shared by all holders.
type RoutingBase struct {
	// SysctlFailed reports that the host sysctls could not be fully configured.
	SysctlFailed bool
}

// TeardownFunc undoes host state.
type TeardownFunc func() error

// SetupFunc installs the shared routing state. On error it leaves the installed
// state for the caller's cleanup, and the base stays unheld.
type SetupFunc func() (RoutingBase, TeardownFunc, error)

// Coordinator owns the host resources shared by sessions. It is passed as a
// dependency so tests and the foreground mode can use their own instance.
type Coordinator struct {
	mu       sync.Mutex
	holders  map[SessionKey]struct{}
	base     RoutingBase
	teardown TeardownFunc

	routes   *Routes
	dns      *DNSOwners
	sessions *Sessions
}

// New returns a Coordinator with no holders.
func New() *Coordinator {
	return &Coordinator{
		holders:  make(map[SessionKey]struct{}),
		routes:   NewRoutes(),
		dns:      NewDNSOwners(),
		sessions: NewSessions(),
	}
}

// Routes returns the owners of the prefixes in the shared routing table.
func (c *Coordinator) Routes() *Routes {
	return c.routes
}

// DNSOwners returns the owners of the host DNS and the catch-all.
func (c *Coordinator) DNSOwners() *DNSOwners {
	return c.dns
}

// Sessions returns the interfaces and overlay prefixes of the running sessions.
func (c *Coordinator) Sessions() *Sessions {
	return c.sessions
}

// AcquireRoutingBase adds key to the routing base holders. Only the first holder
// runs setup. Repeated calls with the same key hold one reference.
func (c *Coordinator) AcquireRoutingBase(key SessionKey, setup SetupFunc) (RoutingBase, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.holders) > 0 {
		c.holders[key] = struct{}{}
		return c.base, nil
	}

	base, teardown, err := setup()
	if err != nil {
		return RoutingBase{}, err
	}

	c.holders[key] = struct{}{}
	c.base = base
	c.teardown = teardown
	return base, nil
}

// ReleaseRoutingBase removes key from the routing base holders. The last holder
// runs the teardown returned by setup. When nobody holds the base, idleCleanup
// removes what a previous run may have left behind. While another session holds
// the base, nothing on the host changes.
func (c *Coordinator) ReleaseRoutingBase(key SessionKey, idleCleanup TeardownFunc) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.holders, key)
	if len(c.holders) > 0 {
		return nil
	}

	cleanup := idleCleanup
	if c.teardown != nil {
		cleanup = c.teardown
	}
	c.base = RoutingBase{}
	c.teardown = nil

	if cleanup == nil {
		return nil
	}
	return cleanup()
}
