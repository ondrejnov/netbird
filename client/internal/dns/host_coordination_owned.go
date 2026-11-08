//go:build windows || (darwin && !ios)

package dns

import (
	"slices"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/statemanager"
)

// ownedDomainsHostManager shares a backend that keeps one resolver per domain for the whole host
// with the other sessions. On Windows a namespace resolves through the NRPT rule whose key comes
// first in name order, with no fallback to another rule. macOS picks one of the scutil resolvers
// for a domain as well. A domain two sessions both wrote would silently resolve through one of
// them only, so every domain and the catch-all have one owner, and only the owner writes them.
type ownedDomainsHostManager struct {
	// hostManager writes the rules, failing when it cannot remove the previous ones.
	hostManager
	coordinator HostDNSCoordinator
	// held lists the domains another session owned at the last attempt, as last warned.
	held []string
	// catchAllRefused means another session owned the catch-all at the last attempt.
	catchAllRefused bool
	// failed means the last apply failed, so the rules may still carry what this session claimed.
	failed bool
}

func (m *ownedDomainsHostManager) applyDNSConfig(config HostDNSConfig, stateManager *statemanager.Manager) error {
	wanted := linkDomains(config)
	held := m.coordinator.ClaimDomains(wanted)
	m.warnHeldDomains(held)
	config = withoutDomains(config, held)

	wantsCatchAll := requestsCatchAll(config)
	if wantsCatchAll && !m.claimCatchAll() {
		config = withoutCatchAll(config)
	}

	if err := m.hostManager.applyDNSConfig(config, stateManager); err != nil {
		// The rules of the previous apply may still be there, so nothing is given up.
		m.failed = true
		return err
	}

	// What is still wanted stays: owned it is in the rules, refused it is a conflict.
	m.coordinator.ReleaseDomains(wanted)
	if !wantsCatchAll {
		m.coordinator.ReleaseCatchAll()
		m.catchAllRefused = false
	}
	m.failed = false
	return nil
}

func (m *ownedDomainsHostManager) claimCatchAll() bool {
	err := m.coordinator.ClaimCatchAll()
	if err == nil {
		m.catchAllRefused = false
		return true
	}
	if !m.catchAllRefused {
		log.Warnf("not routing all DNS through this session: %v", err)
		m.coordinator.WarnHostDNS(HostDNSWarning{Kind: HostDNSCatchAllHeld, Err: err})
		m.catchAllRefused = true
	}
	return false
}

// warnHeldDomains warns about the domains another session owns that it was not warned about.
func (m *ownedDomainsHostManager) warnHeldDomains(held []string) {
	fresh := slices.DeleteFunc(slices.Clone(held), func(domain string) bool {
		return slices.Contains(m.held, domain)
	})
	m.held = held
	if len(fresh) == 0 {
		return
	}
	log.Warnf("not resolving %d DNS domains in this session, another session owns them", len(fresh))
	log.Debugf("DNS domains owned by another session: %v", fresh)
	m.coordinator.WarnHostDNS(HostDNSWarning{Kind: HostDNSDomainHeld, Domains: fresh})
}

func (m *ownedDomainsHostManager) hostClaimPending() bool {
	return len(m.held) > 0 || m.catchAllRefused || m.failed
}

// retryClaim reports whether anything refused before is free now. A claim it gets stays until
// the next apply keeps or releases it.
func (m *ownedDomainsHostManager) retryClaim() bool {
	if m.catchAllRefused && m.coordinator.ClaimCatchAll() == nil {
		return true
	}
	if len(m.held) == 0 {
		return false
	}
	return len(m.coordinator.ClaimDomains(m.held)) < len(m.held)
}

// restoreHostDNS gives up the claims even when a rule could not be removed: the session is
// leaving, and keeping them would keep the domains from every other session for good.
func (m *ownedDomainsHostManager) restoreHostDNS() error {
	err := m.hostManager.restoreHostDNS()
	m.coordinator.ReleaseCatchAll()
	m.coordinator.ReleaseDomains(nil)
	m.held = nil
	m.catchAllRefused = false
	m.failed = false
	return err
}

// withoutDomains drops the domains in drop, spelled as linkDomains spells them. It clones because
// the caller's config shares the slice.
func withoutDomains(config HostDNSConfig, drop []string) HostDNSConfig {
	if len(drop) == 0 {
		return config
	}
	config.Domains = slices.DeleteFunc(slices.Clone(config.Domains), func(d DomainConfig) bool {
		return !isRootDomain(d) && slices.Contains(drop, normalizeLinkDomain(d.Domain))
	})
	return config
}
