package internal

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/firewall"
	firewallManager "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/debug"
	"github.com/netbirdio/netbird/client/internal/dns"
	"github.com/netbirdio/netbird/client/internal/hostcoord"
	"github.com/netbirdio/netbird/client/internal/netflow/conntrack"
	"github.com/netbirdio/netbird/client/internal/networkmonitor"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/internal/routemanager/notifier"
	"github.com/netbirdio/netbird/client/internal/routemanager/systemops"
	cProto "github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/client/system"
)

// ErrSessionRefused means a session must not run on this host as things are: its resources are
// taken, its overlay overlaps another one, or it could not be isolated. Trying again would change
// nothing, and it says nothing about the other sessions.
var ErrSessionRefused = errors.New("session refused")

// ErrOverlayOverlap means the IPv4 overlay of a session overlaps the one of another session.
var ErrOverlayOverlap = errors.New("overlay overlaps another session")

// ErrExplicitInterface means the profile names its own interface, which a session cannot have: the
// name of the link is not on record, so the cleanup after a crash would leave the link with its peers
// outside the isolation, and bringing the session up deletes whatever has that name.
var ErrExplicitInterface = errors.New("a session cannot have an explicit interface name")

// ErrIsolationLost means the rules between the sessions changed while they ran and could not be put back.
var ErrIsolationLost = errors.New("the isolation between the sessions was lost")

// DaemonHost is what the sessions of one daemon share on the host. There is one per daemon, passed
// on as a dependency.
type DaemonHost struct {
	coordinator *hostcoord.Coordinator
	slots       *hostcoord.Slots
	isolation   *firewall.SessionIsolation
	accounting  *conntrack.Accounting

	// attachMu makes the check of the overlays and what follows from it one step. It covers no
	// network wait, only the allocator and the rule updates.
	attachMu sync.Mutex
	// watch checks the isolation while sessions run. Guarded by attachMu.
	watch isolationWatch
}

// NewDaemonHost returns the shared state of a daemon that stores its slots in slots.
func NewDaemonHost(slots *hostcoord.Slots) *DaemonHost {
	return &DaemonHost{
		coordinator: hostcoord.New(),
		slots:       slots,
		isolation:   firewall.NewSessionIsolation(),
		accounting:  conntrack.NewAccounting(),
		watch: isolationWatch{
			interval: isolationCheckInterval,
			sessions: make(map[*SessionHost]chan error),
			removals: make(map[string]struct{}),
		},
	}
}

// Coordinator returns the coordinator of the daemon.
func (d *DaemonHost) Coordinator() *hostcoord.Coordinator {
	return d.coordinator
}

// Isolation returns the isolation of the daemon.
func (d *DaemonHost) Isolation() *firewall.SessionIsolation {
	return d.isolation
}

// ExcludeSessionAddresses keeps the addresses of all sessions out of info, which is about to go to the
// Management of one of them (I5). A login needs it as much as a sync: it is the first thing a network
// hears from this host, and it runs before the session is on record itself.
func (d *DaemonHost) ExcludeSessionAddresses(info *system.Info) {
	excludeAddressesOf(d.coordinator.Sessions(), info)
}

// Session returns the view of one session. recorder receives the warnings for that session, and
// can be nil for a session nobody listens to.
func (d *DaemonHost) Session(key hostcoord.SessionKey, recorder *peer.Status) *SessionHost {
	return &SessionHost{daemon: d, key: key, recorder: recorder}
}

// SessionHost is one session's share of the host. A nil SessionHost means a client that owns the
// host alone, which is every client without the feature gate. Its methods accept that.
type SessionHost struct {
	daemon   *DaemonHost
	key      hostcoord.SessionKey
	recorder *peer.Status
	slot     hostcoord.Slot
	// lost is what the run of the current attempt hears on when the isolation fails. It belongs to
	// the goroutine of the run, the watch has its own reference.
	lost <-chan error
}

// attach gives an attempt of the session its resources and isolates it, before the engine exists,
// so no peer can reach the host outside the isolation (I6). The caller runs the returned func once
// the engine has stopped. The config stays as it is: a default in it means the slot decides, and
// the name of the slot is not written back. ctx ends the wait for the interface of a previous attempt.
func (h *SessionHost) attach(ctx context.Context, config *profilemanager.Config, engineConfig *EngineConfig) (func(), error) {
	d := h.daemon

	resources, err := h.reserve(config)
	if err != nil {
		return nil, err
	}
	// Outside attachMu, the other sessions have nothing to wait for here.
	if err := hostcoord.RefuseForeignLink(ctx, resources.Interface, resources.Slot); err != nil {
		d.slots.Release(resources.Lease)
		if ctx.Err() != nil {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %w", ErrSessionRefused, err)
	}

	d.attachMu.Lock()
	defer d.attachMu.Unlock()

	// The isolation can have been lost during the wait.
	if err := d.recoverIsolationLocked(); err != nil {
		d.slots.Release(resources.Lease)
		return nil, fmt.Errorf("%w: %w", ErrSessionRefused, err)
	}
	// A session that failed to leave must not refuse this one, on its overlay or its interface.
	d.repeatIsolationRemovalsLocked()

	addr, err := h.checkOverlays(engineConfig.WgAddr)
	if err != nil {
		d.slots.Release(resources.Lease)
		return nil, fmt.Errorf("%w: %w", ErrSessionRefused, err)
	}

	result, err := d.isolation.Add(resources.Interface, addr)
	if err != nil {
		d.slots.Release(resources.Lease)
		return nil, fmt.Errorf("%w: isolate session: %w", ErrSessionRefused, err)
	}
	delete(d.watch.removals, resources.Interface)

	if !result.Kernel && config.DisableFirewall {
		h.detachLocked(resources)
		return nil, fmt.Errorf("%w: the host has no native firewall and the session disables its own, nothing would isolate it", ErrSessionRefused)
	}
	if result.IPv6Disabled {
		addr.ClearIPv6()
	}

	prefixes := []netip.Prefix{addr.Network}
	if addr.HasIPv6() {
		prefixes = append(prefixes, addr.IPv6Net)
	}
	if err := d.coordinator.Sessions().Set(h.key, resources.Interface, prefixes...); err != nil {
		h.detachLocked(resources)
		return nil, fmt.Errorf("%w: record session: %w", ErrSessionRefused, err)
	}

	h.slot = resources.Slot
	engineConfig.WgIfaceName = resources.Interface
	engineConfig.WgSlot = resources.Slot
	engineConfig.WgPort = int(resources.Port)
	if engineConfig.WgAddr.HasIPv6() && !addr.HasIPv6() {
		log.Warnf("session on %s continues without its IPv6 overlay", resources.Interface)
		h.warn(cProto.SystemEvent_NETWORK, eventIPv6Skipped, "This session continues without its IPv6 overlay, the overlay overlaps another session or cannot be isolated", nil)
		// Management keeps sending the address, which must not read as a change every time.
		engineConfig.DisableIPv6 = true
	}
	engineConfig.WgAddr = addr
	engineConfig.Sessions = d.coordinator.Sessions()
	engineConfig.Session = h
	h.lost = d.watchSessionLocked(h)
	return func() { h.detach(resources) }, nil
}

// reserve gives the attempt its resources, once it is clear the session may run at all.
func (h *SessionHost) reserve(config *profilemanager.Config) (hostcoord.SessionResources, error) {
	d := h.daemon
	d.attachMu.Lock()
	defer d.attachMu.Unlock()

	if err := d.recoverIsolationLocked(); err != nil {
		return hostcoord.SessionResources{}, fmt.Errorf("%w: %w", ErrSessionRefused, err)
	}
	if config.WgIface != iface.WgInterfaceDefault {
		return hostcoord.SessionResources{}, fmt.Errorf("%w: %w", ErrSessionRefused, ErrExplicitInterface)
	}

	resources, err := d.slots.Reserve(h.key, hostcoord.ResourceRequest{WgIface: config.WgIface, WgPort: config.WgPort})
	if err != nil {
		return hostcoord.SessionResources{}, fmt.Errorf("%w: reserve resources: %w", ErrSessionRefused, err)
	}
	return resources, nil
}

func (h *SessionHost) excludeSessionAddresses(info *system.Info) {
	if h != nil {
		h.daemon.ExcludeSessionAddresses(info)
	}
}

// scopeRemoteBundle keeps a debug bundle the Management of this session asked for to this session: it
// goes to wherever that Management says (I5). The state file is the one of the session and not of the
// focused one, and what describes the host also describes the other sessions.
func (h *SessionHost) scopeRemoteBundle(deps *debug.GeneratorDependencies) {
	if h == nil {
		return
	}
	deps.StatePath = profilemanager.NewServiceManager("").GetStatePathFor(h.key)
	deps.ProfileName = h.key.Profile.String()
	deps.OmitHostWide = true
}

// checkOverlays refuses an IPv4 overlay that overlaps another session and drops an IPv6 one that
// does (section 6). The kernel isolation checks the same, but the userspace firewall has only this.
func (h *SessionHost) checkOverlays(addr wgaddr.Address) (wgaddr.Address, error) {
	for _, other := range h.daemon.coordinator.Sessions().OverlayPrefixesExcept(h.key) {
		if other.Overlaps(addr.Network) {
			return addr, ErrOverlayOverlap
		}
		if addr.HasIPv6() && other.Overlaps(addr.IPv6Net) {
			addr.ClearIPv6()
		}
	}
	return addr, nil
}

func (h *SessionHost) detach(resources hostcoord.SessionResources) {
	d := h.daemon
	d.attachMu.Lock()
	defer d.attachMu.Unlock()
	h.detachLocked(resources)
}

func (h *SessionHost) detachLocked(resources hostcoord.SessionResources) {
	d := h.daemon
	d.unwatchSessionLocked(h)

	// A newer attempt of the session took the resources over, and they keep it isolated.
	if !d.slots.Release(resources.Lease) {
		log.Warnf("session on %s was attached again before its previous attempt ended", resources.Interface)
		return
	}

	d.coordinator.Sessions().Remove(h.key)
	d.coordinator.DNSOwners().ForgetSession(h.key)
	if err := d.isolation.Remove(resources.Interface); err != nil {
		log.Errorf("failed to remove session on %s from the isolation, trying again: %v", resources.Interface, err)
		d.watch.removals[resources.Interface] = struct{}{}
	}
	d.resetLostIsolationLocked()
	d.syncIsolationCheckLocked()
}

// verifyIsolation runs once the engine has installed its rules, which is when a rule of another
// origin above the isolation would show (I6, Q14).
func (h *SessionHost) verifyIsolation() error {
	if h == nil {
		return nil
	}
	if err := h.daemon.isolation.Verify(); err != nil {
		return fmt.Errorf("%w: %w", ErrSessionRefused, err)
	}
	return nil
}

func (h *SessionHost) newFirewall(e *Engine) (firewallManager.Manager, error) {
	fm, err := firewall.NewSessionFirewall(e.ctx, e.wgInterface, e.stateManager, e.flowManager.GetLogger(), e.config.DisableServerRoutes, e.config.MTU, firewall.SessionConfig{
		Slot:      uint32(h.slot),
		Isolation: h.daemon.isolation,
		Source:    h.daemon.coordinator.Sessions().IsolationSource(h.key),
	})
	if errors.Is(err, firewall.ErrSessionNotIsolated) {
		return nil, fmt.Errorf("%w: %w", ErrSessionRefused, err)
	}
	return fm, err
}

// newSysOps returns how the route manager of the session builds its system operations, nil for a
// client that owns the host alone.
func (h *SessionHost) newSysOps(e *Engine) func(*notifier.Notifier) *systemops.SysOps {
	if h == nil {
		return nil
	}
	coordinator := h.daemon.coordinator
	return func(n *notifier.Notifier) *systemops.SysOps {
		return systemops.NewShared(e.wgInterface, n, coordinator, h.key,
			systemops.WithSharedRoutes(coordinator.Routes(), h.routeEvent),
			systemops.WithOverlayPrefixes(coordinator.Sessions()),
		)
	}
}

func (h *SessionHost) hostDNS() dns.HostDNSCoordinator {
	if h == nil {
		return nil
	}
	sessions := h.daemon.coordinator.Sessions()
	return h.daemon.coordinator.DNSOwners().Session(h.key, sessions.SessionInterfaces, h.dnsWarning)
}

func (h *SessionHost) conntrackOptions() []conntrack.Option {
	if h == nil {
		return nil
	}
	sessions := h.daemon.coordinator.Sessions()
	return []conntrack.Option{
		conntrack.WithAccounting(h.daemon.accounting),
		conntrack.WithSessionFlows(func() []netip.Prefix { return sessions.OverlayPrefixesExcept(h.key) }),
	}
}

func (h *SessionHost) networkMonitorOptions() []networkmonitor.Option {
	if h == nil {
		return nil
	}
	return []networkmonitor.Option{networkmonitor.WithNetbirdInterfaces(h.daemon.coordinator.Sessions().SessionInterfaces)}
}

// retryHandovers runs when the interface of the session is back: the routes a failed handover
// left without an owner can move now.
func (h *SessionHost) retryHandovers() {
	if h == nil {
		return
	}
	if err := h.daemon.coordinator.Routes().RetryHandovers(); err != nil {
		log.Warnf("failed to retry route handovers: %v", err)
	}
}
