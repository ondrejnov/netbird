//go:build windows

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
	// Kernel means the kernel enforces the isolation of the session. On Windows it never does in
	// that sense: the adapter flags keep packets apart, but anything on the host can turn them on,
	// so the userspace firewall of the session has to exist as well.
	Kernel bool
}

// adapterFlags turns off and checks what lets Windows deliver a packet that came in on the adapter
// of a slot to another adapter's address, or forward it to another adapter (I3, I4).
type adapterFlags interface {
	isolate(slot uint32) error
	check(slot uint32) error
}

type isolationMember struct {
	slot uint32
	// attached means the adapter exists and its flags were set. Add runs before the adapter does.
	attached bool
}

// SessionIsolation keeps the sessions of one daemon from reaching each other's networks. On
// Windows it keeps forwarding and the weak host model off on the adapter of every session, and
// the userspace firewall of each session drops what is meant for the others.
type SessionIsolation struct {
	mu      sync.Mutex
	flags   adapterFlags
	added   bool
	members map[string]*isolationMember
}

// NewSessionIsolation returns the isolation of one daemon. It touches nothing until a session
// firewall attaches its adapter.
func NewSessionIsolation() *SessionIsolation {
	return newSessionIsolation(windowsAdapterFlags{})
}

func newSessionIsolation(flags adapterFlags) *SessionIsolation {
	return &SessionIsolation{flags: flags, members: make(map[string]*isolationMember)}
}

// Add records the session on the interface name. Its adapter does not exist yet; the session
// firewall attaches it before the session has peers.
func (i *SessionIsolation) Add(name string, _ wgaddr.Address) (SessionAddResult, error) {
	i.mu.Lock()
	defer i.mu.Unlock()

	i.added = true
	if _, known := i.members[name]; !known {
		i.members[name] = &isolationMember{}
	}
	return SessionAddResult{}, nil
}

// attach sets the flags of the adapter of slot, which the session on name has. A session must not
// run when it fails.
func (i *SessionIsolation) attach(name string, slot uint32) error {
	i.mu.Lock()
	defer i.mu.Unlock()

	member, known := i.members[name]
	if !known {
		return fmt.Errorf("%s is not in the isolation", name)
	}
	if err := i.flags.isolate(slot); err != nil {
		return fmt.Errorf("isolate the adapter of %s: %w", name, err)
	}
	member.slot = slot
	member.attached = true
	return nil
}

// Remove takes the session out of the isolation, which keeps holding for the others. The flags of
// its adapter stay off, the adapter goes away with the session.
func (i *SessionIsolation) Remove(name string) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	delete(i.members, name)
	return nil
}

// Verify checks the flags of every attached adapter. A session must not keep running when it
// fails.
func (i *SessionIsolation) Verify() error {
	i.mu.Lock()
	defer i.mu.Unlock()

	if !i.added {
		return errors.New("verify isolation: no session was added")
	}
	var errs []error
	for name, m := range i.members {
		if !m.attached {
			continue
		}
		if err := i.flags.check(m.slot); err != nil {
			errs = append(errs, fmt.Errorf("adapter of %s: %w", name, err))
		}
	}
	return errors.Join(errs...)
}

// Restore turns the flags of every attached adapter off again, after Verify found one on.
func (i *SessionIsolation) Restore() error {
	i.mu.Lock()
	defer i.mu.Unlock()

	var errs []error
	for name, m := range i.members {
		if !m.attached {
			continue
		}
		// An adapter that went away delivers nothing, and its session is leaving.
		if err := i.flags.isolate(m.slot); err != nil && !errors.Is(err, errAdapterAbsent) {
			errs = append(errs, fmt.Errorf("adapter of %s: %w", name, err))
		}
	}
	return errors.Join(errs...)
}

// RemoveAll drops all sessions.
func (i *SessionIsolation) RemoveAll() error {
	i.mu.Lock()
	defer i.mu.Unlock()
	clear(i.members)
	return nil
}

// RemoveResidualSessionIsolation does nothing: the flags live on adapters, which a crashed daemon
// does not leave behind.
func RemoveResidualSessionIsolation() error {
	return nil
}

// SessionConfig is what a firewall needs to be one session of several.
type SessionConfig struct {
	// Slot selects the adapter and the names of the Windows Firewall rules the session owns.
	Slot uint32
	// Isolation is the isolation of the daemon. The session was added to it first.
	Isolation *SessionIsolation
	// Source tells the userspace firewall about the other sessions.
	Source common.IsolationSource
}

// NewSessionFirewall is NewFirewall for one session of several. It sets the isolation flags of
// the session's adapter and builds a userspace firewall that drops what is meant for the other
// sessions. With server routes disabled the firewall drops routed packets itself rather than
// handing them to a kernel whose isolation does not count (Q10).
func NewSessionFirewall(ctx context.Context, iface IFaceMapper, _ *statemanager.Manager, flowLogger nftypes.FlowLogger, disableServerRoutes bool, mtu uint16, session SessionConfig) (firewall.Manager, error) {
	switch {
	case session.Isolation == nil:
		return nil, fmt.Errorf("%w: no isolation", ErrSessionNotIsolated)
	case session.Source == nil:
		return nil, fmt.Errorf("%w: no isolation source", ErrSessionNotIsolated)
	case !iface.IsUserspaceBind():
		return nil, fmt.Errorf("%w: the interface has no userspace bind for the firewall", ErrSessionNotIsolated)
	}

	if err := session.Isolation.attach(iface.Name(), session.Slot); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSessionNotIsolated, err)
	}

	log.Infof("creating a userspace firewall for the session on slot %d", session.Slot)
	return uspfilter.Create(uspfilter.Config{
		IFace:               iface,
		DisableServerRoutes: disableServerRoutes,
		DropRouted:          disableServerRoutes,
		FlowLogger:          flowLogger,
		MTU:                 mtu,
		InterfaceAllower:    uspfilter.NewWindowsInterfaceAllowerForSlot(iface, session.Slot),
		Isolation:           session.Source,
		TrustContext:        ctx,
	})
}
