//go:build (linux && !android) || freebsd

package dns

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/statemanager"
	nbdns "github.com/netbirdio/netbird/dns"
)

// hostInterfaceSet holds interface names to leave out when capturing the original
// nameservers. A nil set leaves out nothing.
type hostInterfaceSet map[string]struct{}

func newHostInterfaceSet(names []string) hostInterfaceSet {
	set := make(hostInterfaceSet, len(names))
	for _, name := range names {
		set[name] = struct{}{}
	}
	return set
}

func (s hostInterfaceSet) contains(name string) bool {
	_, ok := s[name]
	return ok
}

func newCoordinatedHostManager(wgInterface string, coordinator HostDNSCoordinator) (hostManager, error) {
	osManager, reason, err := getOSDNSManagerType()
	if err != nil {
		return nil, fmt.Errorf("get os dns manager type: %w", err)
	}

	log.Infof("System DNS manager discovered: %s (%s)", osManager, reason)
	return coordinatedManagerFromType(wgInterface, osManager, coordinator)
}

func coordinatedManagerFromType(wgInterface string, osManager osManagerType, coordinator HostDNSCoordinator) (hostManager, error) {
	switch osManager {
	case networkManager, systemdManager:
		netbirdIfaces := newHostInterfaceSet(coordinator.NetbirdInterfaces())
		manager, err := newHostManagerFromType(wgInterface, osManager, netbirdIfaces)
		if err != nil {
			return nil, fmt.Errorf("create host manager: %w", err)
		}
		return &perLinkHostManager{hostManager: manager, coordinator: coordinator}, nil
	default:
		return &exclusiveHostManager{
			coordinator: coordinator,
			osManager:   osManager,
			newManager: func() (hostManager, error) {
				return newHostManagerFromType(wgInterface, osManager, nil)
			},
		}, nil
	}
}

// perLinkHostManager shares a backend that keeps its configuration per link. Every
// session programs its own link, and only the catch-all is arbitrated.
type perLinkHostManager struct {
	hostManager
	coordinator HostDNSCoordinator
	holds       bool
	// refused means a refused claim limits the configuration. It stays set until a
	// configuration is applied without that limit.
	refused bool
	// dropPending means the link may still carry the catch-all this session stopped
	// asking for, so the claim stays and the next update tries again.
	dropPending bool
}

// strictHostManager is a backend that only logs some failures in applyDNSConfig. Giving
// up the catch-all needs to know about them, a session without a coordinator must not.
type strictHostManager interface {
	applyDNSConfigStrict(config HostDNSConfig, stateManager *statemanager.Manager) error
}

func (m *perLinkHostManager) applyDNSConfig(config HostDNSConfig, stateManager *statemanager.Manager) error {
	if err := m.applyArbitrated(config, stateManager); err != nil {
		return err
	}
	m.coordinator.ServeDomains(linkDomains(config))
	return nil
}

func (m *perLinkHostManager) applyArbitrated(config HostDNSConfig, stateManager *statemanager.Manager) error {
	if !requestsCatchAll(config) {
		return m.applyWithoutRequest(config, stateManager)
	}

	if err := m.coordinator.ClaimCatchAll(); err != nil {
		if !m.refused {
			log.Warnf("not routing all DNS through this session: %v", err)
			m.coordinator.WarnHostDNS(HostDNSWarning{Kind: HostDNSCatchAllHeld, Err: err})
			m.refused = true
		}
		return m.hostManager.applyDNSConfig(withoutCatchAll(config), stateManager)
	}

	if err := m.hostManager.applyDNSConfig(config, stateManager); err != nil {
		// A link that held the catch-all before may still have it, so it stays claimed.
		if !m.holds {
			m.coordinator.ReleaseCatchAll()
		}
		return err
	}
	m.holds = true
	m.refused = false
	m.dropPending = false
	return nil
}

// applyWithoutRequest releases only after the link dropped the catch-all, so another
// session cannot claim it while this link still carries it.
func (m *perLinkHostManager) applyWithoutRequest(config HostDNSConfig, stateManager *statemanager.Manager) error {
	if err := m.applyDroppingCatchAll(config, stateManager); err != nil {
		m.dropPending = m.holds
		return err
	}
	m.coordinator.ReleaseCatchAll()
	m.holds = false
	m.refused = false
	m.dropPending = false
	return nil
}

func (m *perLinkHostManager) applyDroppingCatchAll(config HostDNSConfig, stateManager *statemanager.Manager) error {
	if strict, ok := m.hostManager.(strictHostManager); ok && m.holds {
		return strict.applyDNSConfigStrict(config, stateManager)
	}
	return m.hostManager.applyDNSConfig(config, stateManager)
}

func (m *perLinkHostManager) hostClaimPending() bool {
	return m.refused || m.dropPending
}

func (m *perLinkHostManager) retryClaim() bool {
	return m.coordinator.ClaimCatchAll() == nil
}

func (m *perLinkHostManager) restoreHostDNS() error {
	err := m.hostManager.restoreHostDNS()
	m.coordinator.ReleaseCatchAll()
	m.coordinator.ServeDomains(nil)
	m.holds = false
	return err
}

// linkDomains returns the domains the link answers for, in one spelling. The root domain is the
// catch-all, which has its own claim.
func linkDomains(config HostDNSConfig) []string {
	var domains []string
	for _, d := range config.Domains {
		if d.Disabled || isRootDomain(d) {
			continue
		}
		name := strings.ToLower(strings.TrimSuffix(d.Domain, "."))
		if !slices.Contains(domains, name) {
			domains = append(domains, name)
		}
	}
	return domains
}

func requestsCatchAll(config HostDNSConfig) bool {
	return config.RouteAll || slices.ContainsFunc(config.Domains, func(d DomainConfig) bool {
		return !d.Disabled && isRootDomain(d)
	})
}

// withoutCatchAll also drops a root domain, which on a per-link backend routes all
// names the same way RouteAll does. It clones because the caller's config shares the slice.
func withoutCatchAll(config HostDNSConfig) HostDNSConfig {
	config.RouteAll = false
	config.Domains = slices.DeleteFunc(slices.Clone(config.Domains), isRootDomain)
	return config
}

func isRootDomain(d DomainConfig) bool {
	return d.Domain == nbdns.RootZone
}

// exclusiveHostManager shares a backend that holds one configuration for the whole
// host. The first session owns it, the others leave the backend alone and work by IP.
// The real manager exists only while this session is the owner, because its constructor
// would otherwise read the owner's nameserver from /etc/resolv.conf as an original one.
type exclusiveHostManager struct {
	coordinator HostDNSCoordinator
	osManager   osManagerType
	newManager  func() (hostManager, error)
	owner       hostManager
	// refused means another session owned the host DNS at the last attempt. It stays
	// set until this session becomes the owner.
	refused bool
}

func (m *exclusiveHostManager) applyDNSConfig(config HostDNSConfig, stateManager *statemanager.Manager) error {
	if m.owner != nil {
		return m.owner.applyDNSConfig(config, stateManager)
	}

	if err := m.coordinator.ClaimHostDNS(); err != nil {
		if !m.refused {
			log.Warnf("not configuring host DNS for this session, it works by IP only: %v", err)
			m.coordinator.WarnHostDNS(HostDNSWarning{Kind: HostDNSHeld, Err: err})
			m.refused = true
		}
		return nil
	}

	manager, err := m.newManager()
	if err != nil {
		m.coordinator.ReleaseHostDNS()
		return fmt.Errorf("create host manager: %w", err)
	}
	if err := manager.applyDNSConfig(config, stateManager); err != nil {
		m.coordinator.ReleaseHostDNS()
		return err
	}
	m.owner = manager
	m.refused = false
	return nil
}

func (m *exclusiveHostManager) hostClaimPending() bool {
	return m.refused
}

func (m *exclusiveHostManager) retryClaim() bool {
	return m.coordinator.ClaimHostDNS() == nil
}

func (m *exclusiveHostManager) restoreHostDNS() error {
	if m.owner == nil {
		return nil
	}
	err := m.owner.restoreHostDNS()
	m.owner = nil
	m.coordinator.ReleaseHostDNS()
	return err
}

func (m *exclusiveHostManager) supportCustomPort() bool {
	return false
}

func (m *exclusiveHostManager) string() string {
	if m.owner == nil {
		return m.osManager.String()
	}
	return m.owner.string()
}

func (m *exclusiveHostManager) getOriginalNameservers() []netip.Addr {
	if m.owner == nil {
		return nil
	}
	return m.owner.getOriginalNameservers()
}
