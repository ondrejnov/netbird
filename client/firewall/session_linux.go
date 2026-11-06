//go:build !android

package firewall

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"

	nberrors "github.com/netbirdio/netbird/client/errors"
	nbiptables "github.com/netbirdio/netbird/client/firewall/iptables"
	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	nbnftables "github.com/netbirdio/netbird/client/firewall/nftables"
	"github.com/netbirdio/netbird/client/firewall/uspfilter"
	"github.com/netbirdio/netbird/client/firewall/uspfilter/common"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	nftypes "github.com/netbirdio/netbird/client/internal/netflow/types"
	"github.com/netbirdio/netbird/client/internal/routemanager/ipfwdstate"
	"github.com/netbirdio/netbird/client/internal/statemanager"
)

// ErrSessionNotIsolated means the session cannot run: nothing would keep it from the other sessions.
var ErrSessionNotIsolated = errors.New("session would not be isolated")

// SessionAddResult is what a session has to honor after SessionIsolation.Add.
type SessionAddResult struct {
	// IPv6Disabled means the session is isolated without its IPv6 overlay and must run without it.
	IPv6Disabled bool
	// Kernel means the kernel enforces the isolation of the session. Otherwise only the userspace
	// firewall of the session does, which then has to exist.
	Kernel bool
}

// SessionIsolation keeps the sessions of one daemon from reaching each other's networks. The kind
// of firewall decides what enforces it (Q9, Q10): a native backend is mandatory wherever one exists,
// also with a userspace bind, and the discovery runs once, as its answer depends on the tables the
// first session creates.
type SessionIsolation struct {
	mu      sync.Mutex
	detect  func() FWType
	decided bool
	backend FWType
	nft     *nbnftables.Isolation
	ipt     *nbiptables.Isolation
	members map[string]struct{}
	// forwarding is the IP forwarding state of the daemon. It lives here since the firewall
	// managers are its only users, and it exists only where they do.
	forwarding *ipfwdstate.HostState
}

// NewSessionIsolation returns the isolation of one daemon. It touches nothing until the first Add.
func NewSessionIsolation() *SessionIsolation {
	return &SessionIsolation{detect: check, members: make(map[string]struct{}), forwarding: ipfwdstate.NewHostState()}
}

func (i *SessionIsolation) resolveLocked() (FWType, error) {
	if i.decided {
		return i.backend, nil
	}

	backend := i.detect()
	switch backend {
	case NFTABLES:
		i.nft = nbnftables.NewIsolation()
	case IPTABLES:
		ipt, err := nbiptables.NewIsolation()
		if err != nil {
			return UNKNOWN, fmt.Errorf("create iptables isolation: %w", err)
		}
		i.ipt = ipt
	}
	i.backend = backend
	i.decided = true
	return backend, nil
}

// Add isolates the session on the interface name from the others, and only then may the session
// have peers. A session must not run when it fails.
func (i *SessionIsolation) Add(name string, addr wgaddr.Address) (SessionAddResult, error) {
	i.mu.Lock()
	defer i.mu.Unlock()

	backend, err := i.resolveLocked()
	if err != nil {
		return SessionAddResult{}, err
	}

	var v6Disabled bool
	switch backend {
	case NFTABLES:
		result, err := i.nft.Add(nbnftables.IfaceName(name), addr)
		if err != nil {
			return SessionAddResult{}, err
		}
		v6Disabled = result.IPv6Disabled
	case IPTABLES:
		result, err := i.ipt.Add(nbiptables.IfaceName(name), addr)
		if err != nil {
			return SessionAddResult{}, err
		}
		v6Disabled = result.IPv6Disabled
	default:
		return SessionAddResult{}, nil
	}
	i.members[name] = struct{}{}
	return SessionAddResult{IPv6Disabled: v6Disabled, Kernel: true}, nil
}

// Remove takes the session out of the isolation, which keeps holding for the others.
func (i *SessionIsolation) Remove(name string) error {
	i.mu.Lock()
	defer i.mu.Unlock()

	if _, known := i.members[name]; !known {
		return nil
	}

	var err error
	switch i.backend {
	case NFTABLES:
		err = i.nft.Remove(nbnftables.IfaceName(name))
	case IPTABLES:
		err = i.ipt.Remove(nbiptables.IfaceName(name))
	}
	if err != nil {
		return err
	}
	delete(i.members, name)
	return nil
}

// Verify compares the kernel state with what the isolation should be. A session must not keep
// running when it fails.
func (i *SessionIsolation) Verify() error {
	i.mu.Lock()
	defer i.mu.Unlock()

	switch {
	case !i.decided:
		return errors.New("verify isolation: no session was added")
	case i.backend == NFTABLES:
		return i.nft.Verify()
	case i.backend == IPTABLES:
		return i.ipt.Verify()
	}
	return nil
}

// Restore puts the isolation back as it should be, with all sessions, after Verify found it changed.
func (i *SessionIsolation) Restore() error {
	i.mu.Lock()
	defer i.mu.Unlock()

	switch i.backend {
	case NFTABLES:
		return i.nft.Restore()
	case IPTABLES:
		return i.ipt.Restore()
	}
	return nil
}

// RemoveAll drops all sessions and whatever is left of the isolation in the kernel. Sessions that
// failed to leave one by one, because the isolation was gone, would otherwise count forever.
func (i *SessionIsolation) RemoveAll() error {
	i.mu.Lock()
	defer i.mu.Unlock()

	var err error
	switch i.backend {
	case NFTABLES:
		err = i.nft.RemoveAll()
	case IPTABLES:
		err = i.ipt.RemoveAll()
	}
	if err != nil {
		return err
	}
	clear(i.members)
	return nil
}

// kernelEnforces reports whether the kernel isolates the interface name, and whether the host has
// a native backend that should.
func (i *SessionIsolation) kernelEnforces(name string) (enforced, native bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	_, enforced = i.members[name]
	return enforced, i.decided && i.backend != UNKNOWN
}

func (i *SessionIsolation) decidedBackend() (FWType, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.resolveLocked()
}

// RemoveResidualSessionIsolation removes the isolation a crashed daemon left, on both backends. The
// backend it ran on is not known here, and the discovery may answer differently now.
func RemoveResidualSessionIsolation() error {
	var merr *multierror.Error
	if err := nbnftables.NewIsolation().RemoveAll(); err != nil {
		merr = multierror.Append(merr, err)
	}

	ipt, err := nbiptables.NewIsolation()
	if err != nil {
		log.Debugf("no iptables isolation to remove: %v", err)
		return nberrors.FormatErrorOrNil(merr)
	}
	if err := ipt.RemoveAll(); err != nil {
		merr = multierror.Append(merr, err)
	}
	return nberrors.FormatErrorOrNil(merr)
}

// SessionConfig is what a firewall needs to be one session of several.
type SessionConfig struct {
	// Slot selects the names the firewall owns.
	Slot uint32
	// Isolation is the isolation of the daemon. The session was added to it first.
	Isolation *SessionIsolation
	// Source tells the userspace firewall about the other sessions.
	Source common.IsolationSource
}

// isolationSource returns the source for the userspace firewall, nil without a session.
func (c *SessionConfig) isolationSource() common.IsolationSource {
	if c == nil {
		return nil
	}
	return c.Source
}

func (c *SessionConfig) newNftablesAllower(iface IFaceMapper, mtu uint16) (*nbnftables.InterfaceAllower, error) {
	if c == nil {
		return nbnftables.NewInterfaceAllower(iface, mtu)
	}
	names, err := nbnftables.NamesForSlot(uint(c.Slot))
	if err != nil {
		return nil, err
	}
	return nbnftables.NewInterfaceAllowerForSession(iface, mtu, names)
}

func (c *SessionConfig) createNative(iface IFaceMapper, mtu uint16) (nativeManager, error) {
	backend, err := c.Isolation.decidedBackend()
	if err != nil {
		return nil, err
	}

	switch backend {
	case IPTABLES:
		log.Info("creating an iptables firewall manager for the session")
		return nbiptables.Create(iface, mtu, nbiptables.WithSlot(uint(c.Slot)), nbiptables.WithHostForwarding(c.Isolation.forwarding))
	case NFTABLES:
		log.Info("creating an nftables firewall manager for the session")
		names, err := nbnftables.NamesForSlot(uint(c.Slot))
		if err != nil {
			return nil, err
		}
		return nbnftables.CreateForSession(iface, mtu, names, nbnftables.WithHostForwarding(c.Isolation.forwarding))
	default:
		return nil, errNoFirewallManager
	}
}

// NewSessionFirewall is NewFirewall for one session of several. It refuses a firewall that would
// leave the session without isolation (I6): a native backend the session is not in, no isolation
// source for the userspace firewall, and a userspace firewall that would hand routed packets to a
// kernel that does not isolate them, which is what it does with server routes disabled (Q10).
// Cancelling ctx aborts the firewalld call of this session and of no other.
func NewSessionFirewall(ctx context.Context, iface IFaceMapper, stateManager *statemanager.Manager, flowLogger nftypes.FlowLogger, disableServerRoutes bool, mtu uint16, session SessionConfig) (firewall.Manager, error) {
	if session.Isolation == nil {
		return nil, fmt.Errorf("%w: no isolation", ErrSessionNotIsolated)
	}
	if session.Source == nil {
		return nil, fmt.Errorf("%w: no isolation source", ErrSessionNotIsolated)
	}

	enforced, native := session.Isolation.kernelEnforces(iface.Name())
	if native && !enforced {
		return nil, fmt.Errorf("%w: %s is not in the kernel isolation", ErrSessionNotIsolated, iface.Name())
	}

	fm, err := newFirewall(ctx, iface, stateManager, flowLogger, disableServerRoutes, mtu, &session)
	if errors.Is(err, errNoFirewallManager) {
		return nil, fmt.Errorf("%w: %w", ErrSessionNotIsolated, err)
	}
	if err != nil {
		return nil, err
	}

	if _, userspace := fm.(*uspfilter.Manager); userspace && !enforced && disableServerRoutes {
		if err := fm.Close(stateManager); err != nil {
			log.Warnf("failed to close the refused session firewall: %v", err)
		}
		return nil, fmt.Errorf("%w: with server routes disabled routed packets go to the kernel, which has no native firewall to isolate them", ErrSessionNotIsolated)
	}
	return fm, nil
}
