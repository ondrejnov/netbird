package dns

import (
	"slices"
	"strings"

	nbdns "github.com/netbirdio/netbird/dns"
)

// HostDNSWarningKind names a host DNS limit a session should warn its user about.
type HostDNSWarningKind string

const (
	// HostDNSCatchAllHeld means another session owns the catch-all route, so this
	// session keeps only its match and search domains.
	HostDNSCatchAllHeld HostDNSWarningKind = "dns_catch_all_held"
	// HostDNSHeld means another session owns the host DNS on a backend that holds one
	// configuration for the whole host. This session works by IP only.
	HostDNSHeld HostDNSWarningKind = "host_dns_held"
	// HostDNSDomainShared means another session serves the same domain on its link. A name
	// in the domain is answered by whichever link answers first, see section 5.3 of the spec.
	HostDNSDomainShared HostDNSWarningKind = "dns_domain_shared"
	// HostDNSDomainHeld means another session owns a domain on a backend that keeps one rule
	// per domain for the whole host. Names in it resolve through that session only.
	HostDNSDomainHeld HostDNSWarningKind = "dns_domain_held"
)

// HostDNSWarning is a warning for one session.
type HostDNSWarning struct {
	Kind HostDNSWarningKind
	Err  error
	// Domains lists the domains of HostDNSDomainShared and HostDNSDomainHeld.
	Domains []string
}

// HostDNSCoordinator connects a DNS server to the sessions sharing the host. A failed
// claim means another session owns the resource, and the DNS server claims again with
// every update. It calls the coordinator with its own lock held, so WarnHostDNS must not
// block on another session.
type HostDNSCoordinator interface {
	// NetbirdInterfaces returns the NetBird interfaces of all sessions. Their
	// nameservers are NetBird's own, never the host's original ones.
	NetbirdInterfaces() []string
	// ClaimCatchAll claims the catch-all route. The owner may claim repeatedly.
	ClaimCatchAll() error
	// ReleaseCatchAll releases the catch-all route if this session owns it.
	ReleaseCatchAll()
	// ClaimHostDNS claims the host DNS. The owner may claim repeatedly.
	ClaimHostDNS() error
	// ReleaseHostDNS releases the host DNS if this session owns it.
	ReleaseHostDNS()
	// ClaimDomains claims the domains on a backend that keeps one rule per domain for the
	// whole host, and returns those another session owns. The owner may claim repeatedly.
	ClaimDomains(domains []string) []string
	// ReleaseDomains releases the domains of this session that are not in keep.
	ReleaseDomains(keep []string)
	// ServeDomains records the domains this session serves on its link, replacing the earlier
	// ones. A domain shared with another session is reported through its warning.
	ServeDomains(domains []string)
	// WarnHostDNS reports a warning for this session.
	WarnHostDNS(HostDNSWarning)
}

// hostConfigNotApplied is the value of a config hash when no configuration counts as
// applied, so the next one is applied whatever its hash is.
const hostConfigNotApplied = ^uint64(0)

// claimingHostManager is a host manager that needs a claim for part of its configuration.
type claimingHostManager interface {
	// hostClaimPending reports that a refused claim limits the configuration, or that
	// a held claim could not be given up yet, so the next update must try again.
	hostClaimPending() bool
	// retryClaim claims again what was refused. After true this session holds the
	// claim, and applying the configuration either keeps or releases it.
	retryClaim() bool
}

func hostClaimPending(manager hostManager) bool {
	claiming, ok := manager.(claimingHostManager)
	return ok && claiming.hostClaimPending()
}

// linkDomains returns the domains the link answers for, in one spelling. The root domain is the
// catch-all, which has its own claim.
func linkDomains(config HostDNSConfig) []string {
	var domains []string
	for _, d := range config.Domains {
		if d.Disabled || isRootDomain(d) {
			continue
		}
		name := normalizeLinkDomain(d.Domain)
		if !slices.Contains(domains, name) {
			domains = append(domains, name)
		}
	}
	return domains
}

func normalizeLinkDomain(domain string) string {
	return strings.ToLower(strings.TrimSuffix(domain, "."))
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
