//go:build darwin && !ios

package firewall

import (
	"context"
	"errors"
	"fmt"
	"sync"

	log "github.com/sirupsen/logrus"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/firewall/uspfilter"
	"github.com/netbirdio/netbird/client/firewall/uspfilter/common"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	nftypes "github.com/netbirdio/netbird/client/internal/netflow/types"
	"github.com/netbirdio/netbird/client/internal/statemanager"
)

// ErrSessionNotIsolated means the session cannot run: nothing would keep it from the other sessions.
var ErrSessionNotIsolated = errors.New("session would not be isolated")

// SessionAddResult is what a session has to honor after SessionIsolation.Add.
type SessionAddResult struct {
	// IPv6Disabled means the session is isolated without its IPv6 overlay and must run without it.
	IPv6Disabled bool
	// Kernel means the kernel enforces the isolation of the session. macOS has no per-interface
	// switch for forwarding or the weak host model, so it never does, and the userspace firewall
	// of the session has to exist.
	Kernel bool
}

// SessionIsolation keeps the sessions of one daemon from reaching each other's networks. On macOS
// every packet of a session passes its userspace firewall before the kernel sees it, and that
// firewall drops what is meant for the other sessions. The isolation only tracks the members.
type SessionIsolation struct {
	mu      sync.Mutex
	added   bool
	members map[string]struct{}
}

// NewSessionIsolation returns the isolation of one daemon. It touches nothing on the host.
func NewSessionIsolation() *SessionIsolation {
	return &SessionIsolation{members: make(map[string]struct{})}
}

// Add records the session on the interface name.
func (i *SessionIsolation) Add(name string, _ wgaddr.Address) (SessionAddResult, error) {
	i.mu.Lock()
	defer i.mu.Unlock()

	i.added = true
	i.members[name] = struct{}{}
	return SessionAddResult{}, nil
}

// Remove takes the session out of the isolation, which keeps holding for the others.
func (i *SessionIsolation) Remove(name string) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	delete(i.members, name)
	return nil
}

// Verify fails only when no session was added: the isolation has no host state that could drift.
func (i *SessionIsolation) Verify() error {
	i.mu.Lock()
	defer i.mu.Unlock()

	if !i.added {
		return errors.New("verify isolation: no session was added")
	}
	return nil
}

// Restore does nothing, as Verify never finds anything to restore.
func (*SessionIsolation) Restore() error {
	return nil
}

// RemoveAll drops all sessions.
func (i *SessionIsolation) RemoveAll() error {
	i.mu.Lock()
	defer i.mu.Unlock()
	clear(i.members)
	return nil
}

// RemoveResidualSessionIsolation does nothing: the isolation leaves nothing on the host.
func RemoveResidualSessionIsolation() error {
	return nil
}

// SessionConfig is what a firewall needs to be one session of several.
type SessionConfig struct {
	// Slot is the slot of the session, for the log.
	Slot uint32
	// Isolation is the isolation of the daemon. The session was added to it first.
	Isolation *SessionIsolation
	// Source tells the userspace firewall about the other sessions.
	Source common.IsolationSource
}

// NewSessionFirewall is NewFirewall for one session of several. It builds a userspace firewall that
// drops what is meant for the other sessions. It refuses a session with server routes disabled,
// which hands routed packets to a kernel that would forward them between sessions (Q10).
func NewSessionFirewall(ctx context.Context, iface IFaceMapper, _ *statemanager.Manager, flowLogger nftypes.FlowLogger, disableServerRoutes bool, mtu uint16, session SessionConfig) (firewall.Manager, error) {
	if err := checkSessionFirewall(iface, disableServerRoutes, session); err != nil {
		return nil, err
	}

	log.Infof("creating a userspace firewall for the session on slot %d", session.Slot)
	return uspfilter.Create(uspfilter.Config{
		IFace:               iface,
		DisableServerRoutes: disableServerRoutes,
		FlowLogger:          flowLogger,
		MTU:                 mtu,
		Isolation:           session.Source,
		TrustContext:        ctx,
	})
}

func checkSessionFirewall(iface IFaceMapper, disableServerRoutes bool, session SessionConfig) error {
	switch {
	case session.Isolation == nil:
		return fmt.Errorf("%w: no isolation", ErrSessionNotIsolated)
	case session.Source == nil:
		return fmt.Errorf("%w: no isolation source", ErrSessionNotIsolated)
	case !iface.IsUserspaceBind():
		return fmt.Errorf("%w: the interface has no userspace bind for the firewall", ErrSessionNotIsolated)
	case disableServerRoutes:
		return fmt.Errorf("%w: with server routes disabled routed packets go to the kernel, which has no native firewall to isolate them", ErrSessionNotIsolated)
	}

	session.Isolation.mu.Lock()
	defer session.Isolation.mu.Unlock()
	if _, known := session.Isolation.members[iface.Name()]; !known {
		return fmt.Errorf("%w: %s is not in the isolation", ErrSessionNotIsolated, iface.Name())
	}
	return nil
}
