package hostcoord

import (
	"errors"
	"slices"
	"sync"

	"github.com/netbirdio/netbird/client/internal/dns"
)

// ErrDNSHeld reports that another session owns the host DNS resource.
var ErrDNSHeld = errors.New("host DNS resource held by another session")

// dnsClaim is one resource with one owner. refused lists the sessions that asked for it while
// another session held it, for as long as nothing has changed that.
type dnsClaim struct {
	owner   SessionKey
	held    bool
	refused map[SessionKey]struct{}
}

func (c *dnsClaim) claim(key SessionKey) error {
	if c.held && c.owner != key {
		if c.refused == nil {
			c.refused = make(map[SessionKey]struct{})
		}
		c.refused[key] = struct{}{}
		return ErrDNSHeld
	}
	delete(c.refused, key)
	c.owner = key
	c.held = true
	return nil
}

// release also ends the refusal of key, which is no longer asking for the resource.
func (c *dnsClaim) release(key SessionKey) {
	delete(c.refused, key)
	if c.held && c.owner == key {
		c.owner = SessionKey{}
		c.held = false
	}
}

func (c *dnsClaim) refusedTo(key SessionKey) bool {
	_, refused := c.refused[key]
	return refused
}

// sessionDomains is what one session serves on its link.
type sessionDomains struct {
	domains []string
	// warned holds the shared domains the session has been told about.
	warned []string
	warn   func(dns.HostDNSWarning)
}

// DNSOwners records which session owns the host DNS resources that only one session
// can hold. The first claim wins, and a claim stays until its owner releases it:
// nothing is handed over, the next session gets it with its next claim.
type DNSOwners struct {
	mu       sync.Mutex
	catchAll dnsClaim
	hostDNS  dnsClaim
	served   map[SessionKey]*sessionDomains
	// domains holds the domain claims of backends where one rule per domain serves the
	// whole host.
	domains map[string]*dnsClaim
}

// NewDNSOwners returns a DNSOwners with nothing claimed.
func NewDNSOwners() *DNSOwners {
	return &DNSOwners{
		served:  make(map[SessionKey]*sessionDomains),
		domains: make(map[string]*dnsClaim),
	}
}

// ClaimCatchAll makes key the owner of the catch-all DNS route on backends with
// per-link configuration. It returns ErrDNSHeld when another session owns it.
func (o *DNSOwners) ClaimCatchAll(key SessionKey) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.catchAll.claim(key)
}

// ReleaseCatchAll frees the catch-all if key owns it.
func (o *DNSOwners) ReleaseCatchAll(key SessionKey) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.catchAll.release(key)
}

// CatchAllOwner returns the owner of the catch-all, if there is one.
func (o *DNSOwners) CatchAllOwner() (SessionKey, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.catchAll.owner, o.catchAll.held
}

// ClaimHostDNS makes key the owner of the host DNS on backends that hold one
// configuration for the whole host. It returns ErrDNSHeld when another session owns it.
func (o *DNSOwners) ClaimHostDNS(key SessionKey) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.hostDNS.claim(key)
}

// ReleaseHostDNS frees the host DNS if key owns it.
func (o *DNSOwners) ReleaseHostDNS(key SessionKey) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.hostDNS.release(key)
}

// HostDNSOwner returns the owner of the host DNS, if there is one.
func (o *DNSOwners) HostDNSOwner() (SessionKey, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.hostDNS.owner, o.hostDNS.held
}

// ClaimDomains makes key the owner of every domain in domains no other session owns, on
// backends where one rule per domain serves the whole host. It returns the domains another
// session owns, sorted. A claim stays until ReleaseDomains leaves it out.
func (o *DNSOwners) ClaimDomains(key SessionKey, domains []string) []string {
	o.mu.Lock()
	defer o.mu.Unlock()

	var held []string
	for _, domain := range domains {
		claim := o.domains[domain]
		if claim == nil {
			claim = &dnsClaim{}
			o.domains[domain] = claim
		}
		if err := claim.claim(key); err != nil {
			held = append(held, domain)
		}
	}
	slices.Sort(held)
	return slices.Compact(held)
}

// ReleaseDomains frees every domain key owns or asked for, except those in keep.
func (o *DNSOwners) ReleaseDomains(key SessionKey, keep []string) {
	o.mu.Lock()
	defer o.mu.Unlock()

	for domain, claim := range o.domains {
		if slices.Contains(keep, domain) {
			continue
		}
		claim.release(key)
		o.dropIdleDomainLocked(domain, claim)
	}
}

// DomainOwner returns the owner of a domain, if there is one.
func (o *DNSOwners) DomainOwner(domain string) (SessionKey, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	claim := o.domains[domain]
	if claim == nil {
		return SessionKey{}, false
	}
	return claim.owner, claim.held
}

func (o *DNSOwners) dropIdleDomainLocked(domain string, claim *dnsClaim) {
	if !claim.held && len(claim.refused) == 0 {
		delete(o.domains, domain)
	}
}

func (o *DNSOwners) domainRefusedLocked(key SessionKey) bool {
	for _, claim := range o.domains {
		if claim.refusedTo(key) {
			return true
		}
	}
	return false
}

// ServeDomains records the domains key serves on its link and warns every session that shares one
// with another session and has not heard of it yet. A session sharing a domain stays warned about it
// until it stops serving it. The warnings run with the lock released.
func (o *DNSOwners) ServeDomains(key SessionKey, domains []string, warn func(dns.HostDNSWarning)) {
	notices := o.recordDomains(key, domains, warn)
	for _, notice := range notices {
		if notice.warn != nil {
			notice.warn(dns.HostDNSWarning{Kind: dns.HostDNSDomainShared, Domains: notice.domains})
		}
	}
}

type domainNotice struct {
	warn    func(dns.HostDNSWarning)
	domains []string
}

func (o *DNSOwners) recordDomains(key SessionKey, domains []string, warn func(dns.HostDNSWarning)) []domainNotice {
	o.mu.Lock()
	defer o.mu.Unlock()

	if len(domains) == 0 {
		delete(o.served, key)
	} else {
		entry := o.served[key]
		if entry == nil {
			entry = &sessionDomains{}
			o.served[key] = entry
		}
		entry.domains = slices.Clone(domains)
		entry.warn = warn
	}

	var notices []domainNotice
	for session, entry := range o.served {
		shared := o.sharedDomainsLocked(session)
		fresh := slices.DeleteFunc(slices.Clone(shared), func(domain string) bool {
			return slices.Contains(entry.warned, domain)
		})
		entry.warned = shared
		if len(fresh) > 0 {
			notices = append(notices, domainNotice{warn: entry.warn, domains: fresh})
		}
	}
	return notices
}

func (o *DNSOwners) sharedDomainsLocked(key SessionKey) []string {
	entry := o.served[key]
	if entry == nil {
		return nil
	}
	var shared []string
	for _, domain := range entry.domains {
		for other, otherEntry := range o.served {
			if other != key && slices.Contains(otherEntry.domains, domain) {
				shared = append(shared, domain)
				break
			}
		}
	}
	slices.Sort(shared)
	return shared
}

// InConflict reports whether the DNS of key is limited by another session at the moment: a resource
// it asked for is held, or it serves a domain another session serves too.
func (o *DNSOwners) InConflict(key SessionKey) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.catchAll.refusedTo(key) || o.hostDNS.refusedTo(key) || o.domainRefusedLocked(key) ||
		len(o.sharedDomainsLocked(key)) > 0
}

// ForgetSession drops what a stopped session asked for. A claim it still holds stays: only the
// DNS manager that programmed the host knows when that is undone.
func (o *DNSOwners) ForgetSession(key SessionKey) {
	o.mu.Lock()
	defer o.mu.Unlock()
	delete(o.catchAll.refused, key)
	delete(o.hostDNS.refused, key)
	delete(o.served, key)
	for domain, claim := range o.domains {
		delete(claim.refused, key)
		o.dropIdleDomainLocked(domain, claim)
	}
}

// Session returns the view of o for one session, to be passed as
// dns.DefaultServerConfig.HostDNS. interfaces lists the NetBird interfaces of all
// sessions, warn receives what the session should report to its user. Either may be
// nil.
func (o *DNSOwners) Session(key SessionKey, interfaces func() []string, warn func(dns.HostDNSWarning)) *DNSSession {
	return &DNSSession{owners: o, key: key, interfaces: interfaces, warn: warn}
}

// DNSSession is DNSOwners bound to one session.
type DNSSession struct {
	owners     *DNSOwners
	key        SessionKey
	interfaces func() []string
	warn       func(dns.HostDNSWarning)
}

var _ dns.HostDNSCoordinator = (*DNSSession)(nil)

// NetbirdInterfaces returns the NetBird interfaces of all sessions.
func (s *DNSSession) NetbirdInterfaces() []string {
	if s.interfaces == nil {
		return nil
	}
	return s.interfaces()
}

// ClaimCatchAll claims the catch-all for this session.
func (s *DNSSession) ClaimCatchAll() error {
	return s.owners.ClaimCatchAll(s.key)
}

// ReleaseCatchAll releases the catch-all if this session owns it.
func (s *DNSSession) ReleaseCatchAll() {
	s.owners.ReleaseCatchAll(s.key)
}

// ClaimHostDNS claims the host DNS for this session.
func (s *DNSSession) ClaimHostDNS() error {
	return s.owners.ClaimHostDNS(s.key)
}

// ReleaseHostDNS releases the host DNS if this session owns it.
func (s *DNSSession) ReleaseHostDNS() {
	s.owners.ReleaseHostDNS(s.key)
}

// ClaimDomains claims the domains for this session and returns those another session owns.
func (s *DNSSession) ClaimDomains(domains []string) []string {
	return s.owners.ClaimDomains(s.key, domains)
}

// ReleaseDomains frees the domains of this session that are not in keep.
func (s *DNSSession) ReleaseDomains(keep []string) {
	s.owners.ReleaseDomains(s.key, keep)
}

// ServeDomains records the domains this session serves on its link.
func (s *DNSSession) ServeDomains(domains []string) {
	s.owners.ServeDomains(s.key, domains, s.warn)
}

// WarnHostDNS passes a warning to the session's callback.
func (s *DNSSession) WarnHostDNS(warning dns.HostDNSWarning) {
	if s.warn != nil {
		s.warn(warning)
	}
}
