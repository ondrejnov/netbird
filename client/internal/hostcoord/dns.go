package hostcoord

import (
	"errors"
	"sync"

	"github.com/netbirdio/netbird/client/internal/dns"
)

// ErrDNSHeld reports that another session owns the host DNS resource.
var ErrDNSHeld = errors.New("host DNS resource held by another session")

type dnsClaim struct {
	owner SessionKey
	held  bool
}

func (c *dnsClaim) claim(key SessionKey) error {
	if c.held && c.owner != key {
		return ErrDNSHeld
	}
	c.owner = key
	c.held = true
	return nil
}

func (c *dnsClaim) release(key SessionKey) {
	if c.held && c.owner == key {
		*c = dnsClaim{}
	}
}

// DNSOwners records which session owns the host DNS resources that only one session
// can hold. The first claim wins, and a claim stays until its owner releases it:
// nothing is handed over, the next session gets it with its next claim.
type DNSOwners struct {
	mu       sync.Mutex
	catchAll dnsClaim
	hostDNS  dnsClaim
}

// NewDNSOwners returns a DNSOwners with nothing claimed.
func NewDNSOwners() *DNSOwners {
	return &DNSOwners{}
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

// WarnHostDNS passes a warning to the session's callback.
func (s *DNSSession) WarnHostDNS(warning dns.HostDNSWarning) {
	if s.warn != nil {
		s.warn(warning)
	}
}
