package dns

// HostDNSWarningKind names a host DNS limit a session should warn its user about.
type HostDNSWarningKind string

const (
	// HostDNSCatchAllHeld means another session owns the catch-all route, so this
	// session keeps only its match and search domains.
	HostDNSCatchAllHeld HostDNSWarningKind = "dns_catch_all_held"
	// HostDNSHeld means another session owns the host DNS on a backend that holds one
	// configuration for the whole host. This session works by IP only.
	HostDNSHeld HostDNSWarningKind = "host_dns_held"
)

// HostDNSWarning is a warning for one session.
type HostDNSWarning struct {
	Kind HostDNSWarningKind
	Err  error
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
