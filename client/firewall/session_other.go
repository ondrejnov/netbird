//go:build (!linux && !windows && !(darwin && !ios)) || android

package firewall

import (
	"context"
	"errors"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/firewall/uspfilter/common"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	nftypes "github.com/netbirdio/netbird/client/internal/netflow/types"
	"github.com/netbirdio/netbird/client/internal/statemanager"
)

// ErrSessionNotIsolated means the session cannot run: nothing would keep it from the other sessions.
var ErrSessionNotIsolated = errors.New("concurrent sessions are not supported on this platform")

// SessionAddResult is what a session has to honor after SessionIsolation.Add.
type SessionAddResult struct {
	IPv6Disabled bool
	Kernel       bool
}

// SessionIsolation refuses everything on this platform, where the gate refuses to start.
type SessionIsolation struct{}

// NewSessionIsolation returns an isolation that refuses every session.
func NewSessionIsolation() *SessionIsolation {
	return &SessionIsolation{}
}

// Add refuses the session.
func (*SessionIsolation) Add(string, wgaddr.Address) (SessionAddResult, error) {
	return SessionAddResult{}, ErrSessionNotIsolated
}

// Remove does nothing, as no session was added.
func (*SessionIsolation) Remove(string) error {
	return nil
}

// Verify refuses the session.
func (*SessionIsolation) Verify() error {
	return ErrSessionNotIsolated
}

// Restore refuses the session.
func (*SessionIsolation) Restore() error {
	return ErrSessionNotIsolated
}

// RemoveAll does nothing, as no session was added.
func (*SessionIsolation) RemoveAll() error {
	return nil
}

// RemoveResidualSessionIsolation does nothing, as no isolation can exist on this platform.
func RemoveResidualSessionIsolation() error {
	return nil
}

// SessionConfig is what a firewall needs to be one session of several.
type SessionConfig struct {
	Slot      uint32
	Isolation *SessionIsolation
	Source    common.IsolationSource
}

// NewSessionFirewall refuses the session.
func NewSessionFirewall(context.Context, IFaceMapper, *statemanager.Manager, nftypes.FlowLogger, bool, uint16, SessionConfig) (firewall.Manager, error) {
	return nil, ErrSessionNotIsolated
}
