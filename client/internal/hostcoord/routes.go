package hostcoord

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"

	nberrors "github.com/netbirdio/netbird/client/errors"
)

// maxInterfaceNameLen is the Linux limit, IFNAMSIZ without the terminating NUL.
const maxInterfaceNameLen = 15

// ErrInvalidRouteDev reports a device name the kernel would refuse.
var ErrInvalidRouteDev = errors.New("invalid route device name")

var defaultPrefixes = [...]netip.Prefix{
	netip.PrefixFrom(netip.IPv4Unspecified(), 0),
	netip.PrefixFrom(netip.IPv6Unspecified(), 0),
}

// RouteEventKind names a change a session should warn its user about.
type RouteEventKind string

const (
	// RouteEventShadowed means another session owns the prefix and this one waits in line.
	RouteEventShadowed RouteEventKind = "route_shadowed"
	// RouteEventAcquired means the previous owner left and this session carries the prefix now.
	RouteEventAcquired RouteEventKind = "route_acquired"
	// RouteEventHandoverFailed means this session could not take over and stays in line.
	// RetryHandovers tries again.
	RouteEventHandoverFailed RouteEventKind = "route_handover_failed"
	// RouteEventExitNodeHeld means another session owns the exit node, which is not handed over.
	RouteEventExitNodeHeld RouteEventKind = "exit_node_held"
	// RouteEventExitNodeReleased means the exit node owner left and traffic takes the
	// physical default. The session's request is dropped and has to be made again.
	RouteEventExitNodeReleased RouteEventKind = "exit_node_released"
	// RouteEventOverlayRefused means the route overlaps the overlay of another session and
	// stays out of the table.
	RouteEventOverlayRefused RouteEventKind = "route_overlay_refused"
)

// RouteEvent is a warning for one session.
type RouteEvent struct {
	Kind RouteEventKind
	// Session is the session the warning is for.
	Session SessionKey
	Prefix  netip.Prefix
	// Owner is the session owning the prefix, when there is one.
	Owner SessionKey
	// Err is set for RouteEventHandoverFailed.
	Err error
}

// RouteEventFunc receives warnings. It runs on the goroutine of whichever session
// caused the change, possibly while that session holds its own locks, so it must not
// block on another session. It may call back into Routes.
type RouteEventFunc func(RouteEvent)

// RouteClaim is what one session needs to carry a prefix.
type RouteClaim struct {
	// Dev is the session's interface name.
	Dev string
	// Install makes Dev carry the prefix. It must atomically replace a route the
	// prefix already has, so a handover leaves no moment where the prefix falls
	// through to the physical default.
	Install func() error
	// Remove deletes the route through Dev. A route that is already gone is a success.
	// Routes may call it again after the session stopped, so it must not need the session.
	Remove func() error
	// Notify receives the warnings for this claim. It may be nil.
	Notify RouteEventFunc
}

// RouteResult reports where a prefix went after Add.
type RouteResult struct {
	// Installed reports that the calling session carries the prefix.
	Installed bool
	// Owner is the session carrying the prefix.
	Owner SessionKey
	// OwnerDev is the interface of Owner.
	OwnerDev string
}

// Routes tracks which session carries each prefix of the shared routing table. One
// session owns a prefix and the others wait in order of arrival. A released prefix
// moves to the next session, which a reference counter cannot do because it only
// adds on the transition from zero.
//
// The default prefixes form one exit node for the whole host and are not handed over.
type Routes struct {
	// mu also covers the kernel calls: a claim changing between the decision and the
	// kernel call would leave the table disagreeing with the owner recorded here.
	mu       sync.Mutex
	prefixes map[netip.Prefix]*prefixClaims
	// leftovers are default routes whose owner stopped before their delete worked.
	leftovers map[exitNodeLeftover]*routeClaim
}

type exitNodeLeftover struct {
	key    SessionKey
	prefix netip.Prefix
}

// NewRoutes returns a Routes with no claims.
func NewRoutes() *Routes {
	return &Routes{
		prefixes:  make(map[netip.Prefix]*prefixClaims),
		leftovers: make(map[exitNodeLeftover]*routeClaim),
	}
}

type routeClaim struct {
	RouteClaim
	key SessionKey
}

// prefixClaims holds the claims of one prefix. owner is nil when nobody could install
// the route, the waiters are then retried by RetryHandovers and by the next Add or
// Remove on the prefix.
type prefixClaims struct {
	owner   *routeClaim
	waiters []*routeClaim
}

func (c *prefixClaims) empty() bool {
	return c.owner == nil && len(c.waiters) == 0
}

// enqueue adds a waiter. A session already in line keeps its place.
func (c *prefixClaims) enqueue(claim *routeClaim) {
	for i, waiter := range c.waiters {
		if waiter.key == claim.key {
			c.waiters[i] = claim
			return
		}
	}
	c.waiters = append(c.waiters, claim)
}

func (c *prefixClaims) dropWaiter(key SessionKey) {
	c.waiters = slices.DeleteFunc(c.waiters, func(waiter *routeClaim) bool {
		return waiter.key == key
	})
}

// notice is a warning waiting to be delivered once the lock is released.
type notice struct {
	notify RouteEventFunc
	event  RouteEvent
}

func newNotice(claim *routeClaim, kind RouteEventKind, prefix netip.Prefix, owner SessionKey) notice {
	return notice{
		notify: claim.Notify,
		event:  RouteEvent{Kind: kind, Session: claim.key, Prefix: prefix, Owner: owner},
	}
}

func deliver(notices []notice) {
	for _, n := range notices {
		if n.notify != nil {
			n.notify(n.event)
		}
	}
}

// Add claims prefix for the session. It returns without an error when another session
// owns the prefix: the claim then waits in line, or for a default prefix is only
// recorded so the session can be told when the exit node goes away. On an error the
// session holds no new claim.
func (r *Routes) Add(key SessionKey, prefix netip.Prefix, claim RouteClaim) (RouteResult, error) {
	prefix, err := normalizePrefix(prefix)
	if err != nil {
		return RouteResult{}, err
	}
	if err := validateClaim(claim); err != nil {
		return RouteResult{}, err
	}

	r.mu.Lock()
	result, notices, err := r.add(prefix, &routeClaim{RouteClaim: claim, key: key})
	r.mu.Unlock()

	deliver(notices)
	return result, err
}

func (r *Routes) add(prefix netip.Prefix, claim *routeClaim) (RouteResult, []notice, error) {
	claims := r.prefixes[prefix]
	if claims == nil {
		claims = &prefixClaims{}
		r.prefixes[prefix] = claims
	}
	defer r.forgetIfEmpty(prefix)

	if isDefaultPrefix(prefix) {
		return r.addDefault(prefix, claims, claim)
	}
	return addShared(prefix, claims, claim)
}

func (r *Routes) addDefault(prefix netip.Prefix, claims *prefixClaims, claim *routeClaim) (RouteResult, []notice, error) {
	if holder := r.exitNodeOwner(); holder != nil && holder.key != claim.key {
		claims.enqueue(claim)
		notices := []notice{newNotice(claim, RouteEventExitNodeHeld, prefix, holder.key)}
		return resultFor(claim, holder), notices, nil
	}

	// A leftover that still cannot go must not cost the session its exit node. It waits
	// until the exit node is free again.
	r.settleExitNodeLeftovers()

	if err := claim.Install(); err != nil {
		return RouteResult{}, nil, err
	}
	claims.owner = claim
	return resultFor(claim, claim), nil, nil
}

func addShared(prefix netip.Prefix, claims *prefixClaims, claim *routeClaim) (RouteResult, []notice, error) {
	if owner := claims.owner; owner != nil && owner.key == claim.key {
		if err := claim.Install(); err != nil {
			return RouteResult{}, nil, err
		}
		claims.owner = claim
		return resultFor(claim, claim), nil, nil
	}

	claims.enqueue(claim)
	if claims.owner != nil {
		notices := []notice{newNotice(claim, RouteEventShadowed, prefix, claims.owner.key)}
		return resultFor(claim, claims.owner), notices, nil
	}

	notices, selfErr := promote(prefix, claims, claim)
	if selfErr != nil {
		claims.dropWaiter(claim.key)
		return RouteResult{}, notices, selfErr
	}
	if claims.owner != claim {
		notices = append(notices, newNotice(claim, RouteEventShadowed, prefix, claims.owner.key))
	}
	return resultFor(claim, claims.owner), notices, nil
}

// promote installs the first waiter that can carry the route. A failure of self is
// returned instead of reported, because the caller is still there to get the error.
func promote(prefix netip.Prefix, claims *prefixClaims, self *routeClaim) ([]notice, error) {
	var notices []notice
	for _, waiter := range claims.waiters {
		err := waiter.Install()
		if err == nil {
			claims.owner = waiter
			claims.dropWaiter(waiter.key)
			if waiter != self {
				notices = append(notices, newNotice(waiter, RouteEventAcquired, prefix, waiter.key))
			}
			return notices, nil
		}

		if waiter == self {
			return notices, err
		}
		log.Debugf("route handover of %s to %s: %v", prefix, waiter.Dev, err)
		failed := newNotice(waiter, RouteEventHandoverFailed, prefix, SessionKey{})
		failed.event.Err = err
		notices = append(notices, failed)
	}
	return notices, nil
}

// Remove releases the session's claim on prefix. If the session owned the prefix, it
// moves to the next session in line. A session without a claim changes nothing. When
// the kernel refuses the delete the claim stays and Remove can be called again.
func (r *Routes) Remove(key SessionKey, prefix netip.Prefix) error {
	prefix, err := normalizePrefix(prefix)
	if err != nil {
		return err
	}

	r.mu.Lock()
	notices, err := r.release(key, prefix, true)
	if isDefaultPrefix(prefix) {
		r.settleExitNodeLeftovers()
	}
	r.mu.Unlock()

	deliver(notices)
	return err
}

// ReleaseSession releases every claim of the session and touches nothing of the
// others. A stopped session never retries, so a claim whose delete failed is dropped
// anyway: keeping it would block the prefix. A route through the session's interface
// goes with the interface or is replaced by an Install. An exit node route may hold a
// blackhole that has no device, so Routes keeps deleting that one itself.
func (r *Routes) ReleaseSession(key SessionKey) error {
	r.mu.Lock()
	var (
		merr    *multierror.Error
		notices []notice
	)
	for _, prefix := range r.claimedBy(key) {
		released, err := r.release(key, prefix, false)
		notices = append(notices, released...)
		if err != nil {
			log.Debugf("release route %s: %v", prefix, err)
			merr = multierror.Append(merr, fmt.Errorf("release route claim: %w", err))
		}
	}
	r.settleExitNodeLeftovers()
	r.mu.Unlock()

	deliver(notices)
	return nberrors.FormatErrorOrNil(merr)
}

// RetryHandovers installs the prefixes a failed handover left without a route, in the
// order of their lines, and deletes what a stopped exit node owner left behind. It is
// for a session whose interface recovered or that got RouteEventHandoverFailed. The
// sessions were told already, so a failure is only returned: an event would make a
// handler that calls this method loop.
func (r *Routes) RetryHandovers() error {
	r.mu.Lock()
	var (
		merr    *multierror.Error
		notices []notice
	)
	for prefix, claims := range r.prefixes {
		if !handoverPending(prefix, claims) {
			continue
		}
		acquired, err := retryHandover(prefix, claims)
		notices = append(notices, acquired...)
		if err != nil {
			merr = multierror.Append(merr, fmt.Errorf("hand over route %s: %w", prefix, err))
		}
	}
	if err := r.retryExitNodeLeftovers(); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("delete exit node leftovers: %w", err))
	}
	r.mu.Unlock()

	deliver(notices)
	return nberrors.FormatErrorOrNil(merr)
}

// handoverPending excludes the default prefixes, which are not handed over (R4). They
// also have waiters and no owner while the owner holds only the other family.
func handoverPending(prefix netip.Prefix, claims *prefixClaims) bool {
	return claims.owner == nil && !isDefaultPrefix(prefix)
}

// retryHandover returns the notices of the new owner, and the errors of the waiters only
// when none of them could take the prefix.
func retryHandover(prefix netip.Prefix, claims *prefixClaims) ([]notice, error) {
	promoted, _ := promote(prefix, claims, nil)

	var (
		merr    *multierror.Error
		notices []notice
	)
	for _, n := range promoted {
		if n.event.Kind == RouteEventHandoverFailed {
			merr = multierror.Append(merr, n.event.Err)
			continue
		}
		notices = append(notices, n)
	}
	if claims.owner != nil {
		return notices, nil
	}
	return notices, nberrors.FormatErrorOrNil(merr)
}

func (r *Routes) claimedBy(key SessionKey) []netip.Prefix {
	var prefixes []netip.Prefix
	for prefix, claims := range r.prefixes {
		isOwner := claims.owner != nil && claims.owner.key == key
		isWaiter := slices.ContainsFunc(claims.waiters, func(waiter *routeClaim) bool {
			return waiter.key == key
		})
		if isOwner || isWaiter {
			prefixes = append(prefixes, prefix)
		}
	}
	return prefixes
}

func (r *Routes) release(key SessionKey, prefix netip.Prefix, keepOnFailure bool) ([]notice, error) {
	claims := r.prefixes[prefix]
	if claims == nil {
		return nil, nil
	}
	defer r.forgetIfEmpty(prefix)

	if claims.owner == nil || claims.owner.key != key {
		claims.dropWaiter(key)
		if !handoverPending(prefix, claims) {
			return nil, nil
		}
		notices, _ := promote(prefix, claims, nil)
		return notices, nil
	}

	if isDefaultPrefix(prefix) {
		return r.releaseExitNode(prefix, claims, keepOnFailure)
	}
	return releaseOwner(prefix, claims, keepOnFailure)
}

func releaseOwner(prefix netip.Prefix, claims *prefixClaims, keepOnFailure bool) ([]notice, error) {
	previous := claims.owner
	claims.owner = nil

	notices, _ := promote(prefix, claims, nil)
	if claims.owner != nil {
		return notices, nil
	}

	if err := previous.Remove(); err != nil {
		if keepOnFailure {
			claims.owner = previous
		}
		return notices, err
	}
	return notices, nil
}

// releaseExitNode removes the route without a handover (R4). The exit node stays held
// until its owner has dropped both families.
func (r *Routes) releaseExitNode(prefix netip.Prefix, claims *prefixClaims, keepOnFailure bool) ([]notice, error) {
	owner := claims.owner
	err := owner.Remove()
	if err != nil && keepOnFailure {
		return nil, err
	}

	claims.owner = nil
	if err != nil {
		r.leftovers[exitNodeLeftover{key: owner.key, prefix: prefix}] = owner
	}
	if r.exitNodeOwner() != nil {
		return nil, err
	}
	return r.dropExitNodeWaiters(), err
}

// retryExitNodeLeftovers runs only while nobody owns the exit node: the delete of a
// blackhole cannot tell whose it is, so it would take the one of a new owner, and a new
// owner's Install has replaced the leftover anyway. A leftover already gone is a success.
func (r *Routes) retryExitNodeLeftovers() error {
	if r.exitNodeOwner() != nil {
		return nil
	}

	var merr *multierror.Error
	for id, leftover := range r.leftovers {
		if err := leftover.Remove(); err != nil {
			merr = multierror.Append(merr, err)
			continue
		}
		delete(r.leftovers, id)
	}
	return nberrors.FormatErrorOrNil(merr)
}

// settleExitNodeLeftovers is the attempt made along another operation, whose session
// has nothing to do with a failure of the leftover.
func (r *Routes) settleExitNodeLeftovers() {
	if err := r.retryExitNodeLeftovers(); err != nil {
		log.Debugf("delete exit node leftovers: %v", err)
	}
}

func (r *Routes) dropExitNodeWaiters() []notice {
	var notices []notice
	for _, prefix := range defaultPrefixes {
		claims := r.prefixes[prefix]
		if claims == nil {
			continue
		}
		for _, waiter := range claims.waiters {
			notices = append(notices, newNotice(waiter, RouteEventExitNodeReleased, prefix, SessionKey{}))
		}
		claims.waiters = nil
		r.forgetIfEmpty(prefix)
	}
	return notices
}

func (r *Routes) exitNodeOwner() *routeClaim {
	for _, prefix := range defaultPrefixes {
		if claims := r.prefixes[prefix]; claims != nil && claims.owner != nil {
			return claims.owner
		}
	}
	return nil
}

// ExitNodeOwner returns the session holding the exit node of the host, if there is one. A route
// that only waits for its peer has claimed nothing yet.
func (r *Routes) ExitNodeOwner() (SessionKey, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	owner := r.exitNodeOwner()
	if owner == nil {
		return SessionKey{}, false
	}
	return owner.key, true
}

// WaitsForExitNode reports whether the session asked for an exit node another session holds.
func (r *Routes) WaitsForExitNode(key SessionKey) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, prefix := range defaultPrefixes {
		claims := r.prefixes[prefix]
		if claims == nil {
			continue
		}
		if slices.ContainsFunc(claims.waiters, func(waiter *routeClaim) bool { return waiter.key == key }) {
			return true
		}
	}
	return false
}

func (r *Routes) forgetIfEmpty(prefix netip.Prefix) {
	if claims := r.prefixes[prefix]; claims != nil && claims.empty() {
		delete(r.prefixes, prefix)
	}
}

func resultFor(claim, owner *routeClaim) RouteResult {
	return RouteResult{Installed: claim == owner, Owner: owner.key, OwnerDev: owner.Dev}
}

func isDefaultPrefix(prefix netip.Prefix) bool {
	return prefix.Bits() == 0
}

// normalizePrefix returns the identity the kernel gives a route, so an unmasked or a
// v4-mapped prefix cannot look like a second route.
func normalizePrefix(prefix netip.Prefix) (netip.Prefix, error) {
	if !prefix.IsValid() {
		return netip.Prefix{}, fmt.Errorf("invalid route prefix %q", prefix)
	}

	addr, bits := prefix.Addr(), prefix.Bits()
	if addr.Is4In6() {
		if bits < 96 {
			return netip.Prefix{}, fmt.Errorf("invalid v4-mapped route prefix %q", prefix)
		}
		addr, bits = addr.Unmap(), bits-96
	}
	return netip.PrefixFrom(addr, bits).Masked(), nil
}

func validateClaim(claim RouteClaim) error {
	if err := validateDevName(claim.Dev); err != nil {
		return err
	}
	if claim.Install == nil || claim.Remove == nil {
		return errors.New("route claim without install or remove")
	}
	return nil
}

// validateDevName applies the checks of the kernel's dev_valid_name. A longer name is
// refused rather than cut, because a cut name could be the interface of another session.
func validateDevName(name string) error {
	if name == "" || name == "." || name == ".." || len(name) > maxInterfaceNameLen {
		return fmt.Errorf("%w: %q", ErrInvalidRouteDev, name)
	}
	if strings.ContainsFunc(name, func(c rune) bool {
		return c == '/' || c == ':' || c == ' ' || (c >= '\t' && c <= '\r')
	}) {
		return fmt.Errorf("%w: %q", ErrInvalidRouteDev, name)
	}
	return nil
}
