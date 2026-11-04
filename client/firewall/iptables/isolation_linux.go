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
	// IPv6Disabled means the IPv6 overlay overlaps the one of another session and the session
	// is isolated without it. The session must not put the IPv6 address on its interface: the
	// rules go by address, so a peer of the other session would reach it there.
	IPv6Disabled bool
}

// isolationMember holds the overlay prefixes of a session. An invalid overlay6 means the
// session has no IPv6 overlay on this host. stale and stale6 are prefixes of a failed update
// the rollback could not take out of the kernel: they count as occupied, and leave with the
// next update or Remove.
type isolationMember struct {
	overlay  netip.Prefix
	overlay6 netip.Prefix
	stale    netip.Prefix
	stale6   netip.Prefix
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
// fails with ErrOverlayOverlap, an overlapping IPv6 overlay makes it continue without v6, which
// the result reports. A failed update leaves the session on its previous overlays.
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
	result := AddResult{IPv6Disabled: requested.overlay6.IsValid() && !member.overlay6.IsValid()}

	if previous, known := i.members[name]; known {
		if previous == member {
			return result, nil
		}
		if err := i.updateMember(name, previous, member); err != nil {
			return AddResult{}, fmt.Errorf("update %s in isolation: %w", name, err)
		}
		return result, nil
	}

	if err := i.addMember(name, member); err != nil {
		if len(i.members) == 0 {
			if terr := i.teardown(); terr != nil {
				return AddResult{}, fmt.Errorf("add %s to isolation: %w; rollback: %v", name, err, terr)
			}
		}
		return AddResult{}, fmt.Errorf("add %s to isolation: %w", name, err)
	}
	i.members[name] = member
	return result, nil
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

func (i *Isolation) addMember(name IfaceName, member isolationMember) error {
	if !i.plane4.installed {
		if err := i.plane4.install(); err != nil {
			return err
		}
	}
	if err := i.ensurePlane6(member); err != nil {
		return err
	}

	if err := i.plane4.addMember(name, member.overlay); err != nil {
		return err
	}
	if i.plane6 == nil || !i.plane6.installed {
		return nil
	}
	if err := i.plane6.addMember(name, member.overlay6); err != nil {
		if rerr := i.plane4.removeMember(name, member.overlay); rerr != nil {
			return fmt.Errorf("%w; rollback: %v", err, rerr)
		}
		return err
	}
	return nil
}

// ensurePlane6 installs the v6 half when it can. Sessions without v6 run fine when it cannot,
// a session with v6 cannot be isolated then and must not start. A plane installed late also
// needs the sessions already running: traffic must not cross to them over v6 either.
func (i *Isolation) ensurePlane6(member isolationMember) error {
	hasV6 := member.overlay6.IsValid()
	if i.plane6 == nil {
		if hasV6 {
			return errors.New("session has an IPv6 overlay but the host has no ip6tables")
		}
		return nil
	}
	if i.plane6.installed {
		return nil
	}
	if err := i.plane6.install(); err != nil {
		if hasV6 {
			return err
		}
		log.Debugf("skip IPv6 session isolation: %v", err)
		return nil
	}
	for existing := range i.members {
		if err := i.plane6.addMember(existing, netip.Prefix{}); err != nil {
			// A half filled plane would pass as installed on the next Add.
			if terr := i.plane6.teardown(); terr != nil {
				return fmt.Errorf("add running session %s: %w; rollback: %v", existing, err, terr)
			}
			return fmt.Errorf("add running session %s: %w", existing, err)
		}
	}
	return nil
}

// updateMember moves a session to new overlays. Ipsets have no batch, so a failed step is undone
// by hand: members has to keep matching the kernel, or Verify fails for all other sessions.
func (i *Isolation) updateMember(name IfaceName, previous, member isolationMember) error {
	if err := i.removeStale(name, previous); err != nil {
		return err
	}
	previous.stale, previous.stale6 = netip.Prefix{}, netip.Prefix{}
	i.members[name] = previous

	if err := i.ensurePlane6(member); err != nil {
		return err
	}
	if err := i.replaceOverlays(name, previous, member); err != nil {
		if rerr := i.restoreOverlays(name, previous, member); rerr != nil {
			return fmt.Errorf("%w; rollback: %v", err, rerr)
		}
		return err
	}
	i.members[name] = member
	return nil
}

func (i *Isolation) replaceOverlays(name IfaceName, previous, member isolationMember) error {
	if err := i.plane4.replaceOverlay(name, previous.overlay, member.overlay); err != nil {
		return err
	}
	if i.plane6 != nil && i.plane6.installed {
		return i.plane6.replaceOverlay(name, previous.overlay6, member.overlay6)
	}
	return nil
}

// restoreOverlays puts both planes back on the previous overlays, and keeps track of what a plane
// could not undo.
func (i *Isolation) restoreOverlays(name IfaceName, previous, failed isolationMember) error {
	err := i.plane4.restoreOverlay(name, previous.overlay, failed.overlay)
	if err != nil {
		previous.stale = failed.overlay
	}
	if i.plane6 != nil && i.plane6.installed {
		if err6 := i.plane6.restoreOverlay(name, previous.overlay6, failed.overlay6); err6 != nil {
			previous.stale6 = failed.overlay6
			err = errors.Join(err, err6)
		}
	}
	i.members[name] = previous
	return err
}

func (i *Isolation) removeStale(name IfaceName, member isolationMember) error {
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
	if i.plane6 != nil && i.plane6.installed {
		if err := i.plane6.removeMember(name, member.overlay6); err != nil {
			return fmt.Errorf("remove %s from isolation: %w", name, err)
		}
	}
	if err := i.removeStale(name, member); err != nil {
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
		overlays6[name] = member.overlay6
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
