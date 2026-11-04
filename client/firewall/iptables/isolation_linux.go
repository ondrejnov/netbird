//go:build !android

package iptables

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"

	"github.com/coreos/go-iptables/iptables"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/netbirdio/netbird/client/iface/wgaddr"
)

// ErrOverlayOverlap reports that the IPv4 overlay of a session overlaps another session's.
var ErrOverlayOverlap = errors.New("overlay overlaps another session")

// IfaceName is the name of the overlay interface of a session.
type IfaceName string

// validate rejects what the kernel would never accept as an interface name, and "+", which
// iptables reads as a wildcard and would widen a rule to other interfaces.
func (n IfaceName) validate() error {
	if n == "" || len(n) >= unix.IFNAMSIZ || n == "." || n == ".." {
		return fmt.Errorf("invalid interface name %q", string(n))
	}
	if strings.ContainsAny(string(n), "/:+\x00") || strings.ContainsFunc(string(n), func(r rune) bool { return r <= ' ' || r == 0x7f }) {
		return fmt.Errorf("invalid interface name %q", string(n))
	}
	return nil
}

// AddResult is what a session has to honor after a successful Add.
type AddResult struct {
	// IPv6Disabled means the session is isolated without the IPv6 overlay it asked for: it
	// overlaps the one of another session, or the host cannot isolate IPv6. The session must not
	// put the IPv6 address on its interface: the rules go by address, so a peer of the other
	// session would reach it there.
	IPv6Disabled bool
}

// isolationMember holds the overlay prefixes of a session. An invalid overlay6 means the
// session has no IPv6 overlay on this host. stale and stale6 are prefixes of a failed update
// the rollback could not take out of the kernel: they count as occupied, and leave with the
// next update or Remove. no6 means the session is not in the IPv6 plane because the host has none
// or cannot install it: it is the one thing a repeated Add with the same overlays does not
// compare. A plane that is installed but refuses the session fails Add instead.
type isolationMember struct {
	overlay  netip.Prefix
	overlay6 netip.Prefix
	stale    netip.Prefix
	stale6   netip.Prefix
	no6      bool
}

// withoutPlane6 is the member as it stands when the IPv6 plane could not take it.
func (m isolationMember) withoutPlane6() isolationMember {
	m.overlay6 = netip.Prefix{}
	m.no6 = true
	return m
}

func newIsolationMember(addr wgaddr.Address) (isolationMember, error) {
	overlay := addr.Network
	if !overlay.IsValid() || !overlay.Addr().Unmap().Is4() || overlay.Bits() < 1 || overlay.Bits() > 32 {
		return isolationMember{}, errors.New("session has no valid IPv4 overlay")
	}
	member := isolationMember{overlay: netip.PrefixFrom(overlay.Addr().Unmap(), overlay.Bits()).Masked()}

	overlay6 := addr.IPv6Net
	if addr.HasIPv6() && overlay6.IsValid() && overlay6.Addr().Is6() && overlay6.Bits() > 0 {
		member.overlay6 = overlay6.Masked()
	}
	return member, nil
}

// Isolation keeps sessions from reaching each other's networks through this host, with one
// chain per hook and ipsets instead of rules for pairs. The chains hang off the top of the
// built-in chains of mangle: an accept in filter never gets to decide about these packets,
// whichever table or manager was set up first. One daemon has one Isolation.
type Isolation struct {
	mu      sync.Mutex
	members map[IfaceName]isolationMember
	plane4  *isolationPlane
	// plane6 is nil when the host has no ip6tables.
	plane6 *isolationPlane
}

// NewIsolation returns an Isolation without sessions. It installs nothing until the first Add,
// and fails when the host has no iptables to isolate sessions with.
func NewIsolation() (*Isolation, error) {
	client4, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return nil, fmt.Errorf("init iptables: %w", err)
	}
	i := &Isolation{
		members: make(map[IfaceName]isolationMember),
		plane4:  newIsolationPlane(client4, false),
	}

	client6, err := iptables.NewWithProtocol(iptables.ProtocolIPv6)
	if err != nil {
		log.Debugf("no ip6tables for the session isolation: %v", err)
		return i, nil
	}
	i.plane6 = newIsolationPlane(client6, true)
	return i, nil
}

// Add isolates the session on the given interface from all others, or updates its overlays
// when it is already known. A session must not run when Add fails. An overlapping IPv4 overlay
// fails with ErrOverlayOverlap. An overlapping IPv6 overlay, and a host that cannot install the
// IPv6 plane, make the session continue without v6, which the result reports. An installed plane
// that cannot take the session fails Add, since a session outside its forward rules would pass v6
// between interfaces. A failed update leaves the session on its previous overlays.
func (i *Isolation) Add(name IfaceName, addr wgaddr.Address) (AddResult, error) {
	if err := name.validate(); err != nil {
		return AddResult{}, err
	}
	requested, err := newIsolationMember(addr)
	if err != nil {
		return AddResult{}, fmt.Errorf("add %s to isolation: %w", name, err)
	}

	i.mu.Lock()
	defer i.mu.Unlock()

	member, err := i.resolveOverlaps(name, requested)
	if err != nil {
		return AddResult{}, fmt.Errorf("add %s to isolation: %w", name, err)
	}

	if previous, known := i.members[name]; known {
		stored := previous
		if !sameOverlays(previous, member) {
			stored, err = i.updateMember(name, previous, member)
			if err != nil {
				return AddResult{}, fmt.Errorf("update %s in isolation: %w", name, err)
			}
		}
		return ipv6Result(requested, stored), nil
	}

	stored, err := i.addMember(name, member)
	if err != nil {
		if len(i.members) == 0 {
			if terr := i.teardown(); terr != nil {
				return AddResult{}, fmt.Errorf("add %s to isolation: %w; rollback: %v", name, err, terr)
			}
		}
		return AddResult{}, fmt.Errorf("add %s to isolation: %w", name, err)
	}
	i.members[name] = stored
	return ipv6Result(requested, stored), nil
}

func ipv6Result(requested, stored isolationMember) AddResult {
	return AddResult{IPv6Disabled: requested.overlay6.IsValid() && stored.overlay6 != requested.overlay6}
}

// sameOverlays tells whether Add would change nothing in the kernel for a known session.
func sameOverlays(previous, member isolationMember) bool {
	previous.no6 = false
	return previous == member
}

func (i *Isolation) resolveOverlaps(name IfaceName, member isolationMember) (isolationMember, error) {
	for other, existing := range i.members {
		if other == name {
			continue
		}
		if existing.overlay.Overlaps(member.overlay) || existing.stale.Overlaps(member.overlay) {
			return isolationMember{}, fmt.Errorf("%w %s", ErrOverlayOverlap, other)
		}
		if existing.overlay6.Overlaps(member.overlay6) || existing.stale6.Overlaps(member.overlay6) {
			log.Warnf("IPv6 overlay of %s overlaps session %s, isolating it without IPv6", name, other)
			member.overlay6 = netip.Prefix{}
		}
	}
	return member, nil
}

// addMember puts a new session into the IPv4 plane and then into the IPv6 plane. Both stop the
// session when they fail, and the IPv4 half is taken out again. It returns the member as the
// kernel holds it.
func (i *Isolation) addMember(name IfaceName, member isolationMember) (isolationMember, error) {
	if !i.plane4.installed {
		if err := i.plane4.install(); err != nil {
			return member, err
		}
	}
	if err := i.plane4.addMember(name, member.overlay); err != nil {
		return member, err
	}
	stored, err := i.applyPlane6(name, isolationMember{}, false, member)
	if err != nil {
		if rerr := i.plane4.removeMember(name, member.overlay); rerr != nil {
			return member, fmt.Errorf("%w; rollback: %v", err, rerr)
		}
		return member, err
	}
	return stored, nil
}

// ensurePlane6 installs the v6 half when it can. A plane installed late also needs the sessions
// already running, except skip: traffic must not cross to them over v6 either.
func (i *Isolation) ensurePlane6(skip IfaceName) error {
	if i.plane6 == nil {
		return errors.New("host has no ip6tables")
	}
	if i.plane6.installed {
		return nil
	}
	if err := i.plane6.install(); err != nil {
		return err
	}

	joined := make([]IfaceName, 0, len(i.members))
	for existing := range i.members {
		if existing == skip {
			continue
		}
		if err := i.plane6.addMember(existing, netip.Prefix{}); err != nil {
			err = fmt.Errorf("add running session %s: %w", existing, err)
			// A half filled plane would pass as installed on the next Add. One that cannot be
			// taken down is not installed either: the next install starts from nothing.
			if terr := i.plane6.teardown(); terr != nil {
				i.plane6.installed, i.plane6.ifaceSets = false, nil
				return fmt.Errorf("%w; rollback: %v", err, terr)
			}
			return err
		}
		joined = append(joined, existing)
	}
	for _, existing := range joined {
		member := i.members[existing]
		member.no6 = false
		i.members[existing] = member
	}
	return nil
}

// applyPlane6 puts the session into the v6 plane with the wanted overlay and returns the member as
// the kernel holds it. A host without the plane takes the v6 from the session. A plane that is
// installed and cannot take the session fails: the forward rules of the others only match sessions
// that are in it. A known session whose v6 update fails keeps its previous overlay, which the
// kernel still has, so members keeps matching it.
func (i *Isolation) applyPlane6(name IfaceName, previous isolationMember, known bool, member isolationMember) (isolationMember, error) {
	want := member.overlay6
	if err := i.ensurePlane6(name); err != nil {
		if want.IsValid() {
			log.Debugf("session %s continues without IPv6 isolation: %v", name, err)
		}
		return carryStale6(member.withoutPlane6(), previous), nil
	}

	if known && !previous.no6 {
		return i.replaceOverlay6(name, previous, member), nil
	}
	if err := i.plane6.addMember(name, want); err != nil {
		return isolationMember{}, fmt.Errorf("join IPv6 isolation: %w", err)
	}
	member.no6 = false
	return carryStale6(member, previous), nil
}

// carryStale6 keeps the stale prefix of the previous member, which stays in the kernel until it is
// taken out. One that became the overlay is in use, and a later cleanup would take it from the
// session.
func carryStale6(member, previous isolationMember) isolationMember {
	if previous.stale6 != member.overlay6 {
		member.stale6 = previous.stale6
	}
	return member
}

// replaceOverlay6 moves a session that is in the plane to a new v6 overlay. Only one prefix can be
// recorded as stale, so a new overlay waits while an earlier one is still out of the kernel.
func (i *Isolation) replaceOverlay6(name IfaceName, previous, member isolationMember) isolationMember {
	want := member.overlay6
	if previous.stale6.IsValid() && previous.stale6 != want && previous.overlay6 != want {
		log.Warnf("session %s keeps its IPv6 overlay until the stale %s is out of the kernel", name, previous.stale6)
		member.overlay6 = previous.overlay6
		return carryStale6(member, previous)
	}

	err := i.plane6.replaceOverlay(name, previous.overlay6, want)
	if err == nil {
		return carryStale6(member, previous)
	}

	log.Warnf("session %s continues without its new IPv6 overlay: %v", name, err)
	member.overlay6 = previous.overlay6
	if rerr := i.plane6.restoreOverlay(name, previous.overlay6, want); rerr != nil {
		member.stale6 = want
		log.Debugf("restore IPv6 overlay of %s: %v", name, rerr)
		return member
	}
	return carryStale6(member, previous)
}

// updateMember moves a session to new overlays. Ipsets have no batch, so a failed step is undone
// by hand: members has to keep matching the kernel, or Verify fails for all other sessions. The
// IPv4 plane goes first. A failure of either plane fails the update, and the IPv4 overlay goes back.
func (i *Isolation) updateMember(name IfaceName, previous, member isolationMember) (isolationMember, error) {
	previous, err := i.removeStale(name, previous)
	i.members[name] = previous
	if err != nil {
		return previous, err
	}

	if err := i.plane4.replaceOverlay(name, previous.overlay, member.overlay); err != nil {
		if rerr := i.plane4.restoreOverlay(name, previous.overlay, member.overlay); rerr != nil {
			previous.stale = member.overlay
			i.members[name] = previous
			return previous, fmt.Errorf("%w; rollback: %v", err, rerr)
		}
		return previous, err
	}

	stored, err := i.applyPlane6(name, previous, true, member)
	if err != nil {
		if rerr := i.plane4.restoreOverlay(name, previous.overlay, member.overlay); rerr != nil {
			previous.stale = member.overlay
			i.members[name] = previous
			return previous, fmt.Errorf("%w; rollback: %v", err, rerr)
		}
		return previous, err
	}
	i.members[name] = stored
	return stored, nil
}

// removeStale takes the leftovers of a failed update out of the kernel. Only the IPv4 ones can
// fail the update, an IPv6 one stays recorded for the next try.
func (i *Isolation) removeStale(name IfaceName, member isolationMember) (isolationMember, error) {
	if err := i.plane4.removeOverlay(name, member.stale); err != nil {
		return member, err
	}
	member.stale = netip.Prefix{}

	if i.plane6 == nil || !i.plane6.installed {
		member.stale6 = netip.Prefix{}
		return member, nil
	}
	if err := i.plane6.removeOverlay(name, member.stale6); err != nil {
		log.Debugf("remove stale IPv6 overlay of %s: %v", name, err)
		return member, nil
	}
	member.stale6 = netip.Prefix{}
	return member, nil
}

func (i *Isolation) removeAllStale(name IfaceName, member isolationMember) error {
	err := i.plane4.removeOverlay(name, member.stale)
	if i.plane6 != nil && i.plane6.installed {
		err = errors.Join(err, i.plane6.removeOverlay(name, member.stale6))
	}
	return err
}

// Remove takes the session out of the isolation, which keeps holding for all others. The
// last session removes all chains and sets. Removing an unknown session does nothing, and a
// failed Remove can be repeated.
func (i *Isolation) Remove(name IfaceName) error {
	i.mu.Lock()
	defer i.mu.Unlock()

	member, known := i.members[name]
	if !known {
		return nil
	}

	if len(i.members) == 1 {
		if err := i.teardown(); err != nil {
			return fmt.Errorf("remove %s from isolation: %w", name, err)
		}
		delete(i.members, name)
		return nil
	}

	if err := i.plane4.removeMember(name, member.overlay); err != nil {
		return fmt.Errorf("remove %s from isolation: %w", name, err)
	}
	// Whatever a failed attempt to join the plane left behind is not in members, so the plane is
	// asked even for a session marked no6. Objects that are not there are no error.
	if i.plane6 != nil && i.plane6.installed {
		if err := i.plane6.removeMember(name, member.overlay6); err != nil {
			return fmt.Errorf("remove %s from isolation: %w", name, err)
		}
	}
	if err := i.removeAllStale(name, member); err != nil {
		return fmt.Errorf("remove %s from isolation: %w", name, err)
	}
	delete(i.members, name)
	return nil
}

// RemoveAll drops all sessions, the chains and the sets, including what a crashed daemon left.
func (i *Isolation) RemoveAll() error {
	i.mu.Lock()
	defer i.mu.Unlock()

	if err := i.teardown(); err != nil {
		return fmt.Errorf("remove isolation: %w", err)
	}
	clear(i.members)
	return nil
}

func (i *Isolation) teardown() error {
	err := i.plane4.teardown()
	if i.plane6 != nil {
		err = errors.Join(err, i.plane6.teardown())
	}
	return err
}

// Verify compares the kernel state with what the isolation should be and reports any
// difference, including additions and rules moved above the chains. Sessions must not keep
// running when it fails.
func (i *Isolation) Verify() error {
	i.mu.Lock()
	defer i.mu.Unlock()

	if len(i.members) == 0 {
		if err := i.verifyNothingInstalled(); err != nil {
			return fmt.Errorf("verify isolation: %w", err)
		}
		return nil
	}

	overlays := make(map[IfaceName]netip.Prefix, len(i.members))
	overlays6 := make(map[IfaceName]netip.Prefix, len(i.members))
	for name, member := range i.members {
		overlays[name] = member.overlay
		if !member.no6 {
			overlays6[name] = member.overlay6
		}
	}
	if err := i.plane4.verify(overlays); err != nil {
		return fmt.Errorf("verify isolation: %w", err)
	}
	if i.plane6 != nil && i.plane6.installed {
		if err := i.plane6.verify(overlays6); err != nil {
			return fmt.Errorf("verify isolation: %w", err)
		}
	}
	return nil
}

func (i *Isolation) verifyNothingInstalled() error {
	if err := i.plane4.verifyAbsent(); err != nil {
		return err
	}
	if i.plane6 != nil {
		return i.plane6.verifyAbsent()
	}
	return nil
}
