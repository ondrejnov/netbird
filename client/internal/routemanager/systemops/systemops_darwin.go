//go:build darwin && !ios

package systemops

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/route"
	"golang.org/x/sys/unix"

	nberrors "github.com/netbirdio/netbird/client/errors"
	"github.com/netbirdio/netbird/client/internal/hostcoord"
	"github.com/netbirdio/netbird/client/internal/routemanager/vars"
	nbnet "github.com/netbirdio/netbird/client/net"
)

// scopedRouteBudget bounds retries for the scoped default route. Installing or
// deleting it matters enough that we're willing to spend longer waiting for the
// kernel reply than for per-prefix exclusion routes.
const scopedRouteBudget = 5 * time.Second

// setupAdvancedRouting installs an RTF_IFSCOPE default route per address family
// pinned to the current physical egress, so IP_BOUND_IF scoped lookups can
// resolve gateway'd destinations while the VPN's split default owns the
// unscoped table.
//
// Timing note: this runs during routeManager.Init, which happens before the
// VPN interface is created and before any peer routes propagate. The initial
// mgmt / signal / relay TCP dials always fire before this runs, so those
// sockets miss the IP_BOUND_IF binding and rely on the kernel's normal route
// lookup, which at that point correctly picks the physical default. Those
// already-established TCP flows keep their originally-selected interface for
// their lifetime on Darwin because the kernel caches the egress route
// per-socket at connect time; adding the VPN's 0/1 + 128/1 split default
// afterwards does not migrate them since the original en0 default stays in
// the table. Any subsequent reconnect via nbnet.NewDialer picks up the
// populated bound-iface cache and gets IP_BOUND_IF set cleanly.
func (r *SysOps) setupAdvancedRouting() error {
	if r.coordinator != nil {
		return r.acquireSharedScopedDefaults()
	}
	return r.installScopedDefaults()
}

// acquireSharedScopedDefaults holds the scoped defaults together with the other sessions. Every
// session installs them again on its start, as a session restarts after a network change and the
// defaults of the session that started first would point at the previous network. The last
// session to leave removes them.
func (r *SysOps) acquireSharedScopedDefaults() error {
	if _, err := r.coordinator.AcquireRoutingBase(r.sessionKey, func() (hostcoord.RoutingBase, hostcoord.TeardownFunc, error) {
		return hostcoord.RoutingBase{}, nil, nil
	}); err != nil {
		return fmt.Errorf("acquire routing base: %w", err)
	}

	if err := r.installScopedDefaults(); err != nil {
		if releaseErr := r.releaseSharedScopedDefaults(); releaseErr != nil {
			log.Warnf("failed to release the routing base after a failed setup: %v", releaseErr)
		}
		return err
	}
	return nil
}

func (r *SysOps) releaseSharedScopedDefaults() error {
	return r.coordinator.ReleaseRoutingBase(r.sessionKey, func() error {
		scopedDefaultsMu.Lock()
		defer scopedDefaultsMu.Unlock()
		nbnet.ClearBoundInterfaces()
		return r.flushScopedDefaults()
	})
}

// scopedDefaultsMu serializes the flush and install of the scoped defaults, which the sessions of a
// daemon share.
var scopedDefaultsMu sync.Mutex

func (r *SysOps) installScopedDefaults() error {
	scopedDefaultsMu.Lock()
	defer scopedDefaultsMu.Unlock()

	// Drop any previously-cached egress interface before reinstalling. On a
	// refresh, a family that no longer resolves would otherwise keep the stale
	// binding, causing new sockets to scope to an interface without a matching
	// scoped default.
	nbnet.ClearBoundInterfaces()

	if err := r.flushScopedDefaults(); err != nil {
		log.Warnf("flush residual scoped defaults: %v", err)
	}

	var merr *multierror.Error
	installed := 0

	for _, unspec := range []netip.Addr{netip.IPv4Unspecified(), netip.IPv6Unspecified()} {
		ok, err := r.installScopedDefaultFor(unspec)
		if err != nil {
			merr = multierror.Append(merr, err)
			continue
		}
		if ok {
			installed++
		}
	}

	if installed == 0 && merr != nil {
		return nberrors.FormatErrorOrNil(merr)
	}
	if merr != nil {
		log.Warnf("advanced routing setup partially succeeded: %v", nberrors.FormatErrorOrNil(merr))
	}
	return nil
}

// installScopedDefaultFor resolves the physical default nexthop for the given
// address family, installs a scoped default via it, and caches the iface for
// subsequent IP_BOUND_IF / IPV6_BOUND_IF socket binds.
func (r *SysOps) installScopedDefaultFor(unspec netip.Addr) (bool, error) {
	nexthop, err := r.physicalDefaultNexthop(unspec)
	if err != nil {
		if errors.Is(err, vars.ErrRouteNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("get default nexthop for %s: %w", unspec, err)
	}
	if nexthop.Intf == nil {
		return false, fmt.Errorf("unusable default nexthop for %s (no interface)", unspec)
	}

	reused := false
	if err := r.addScopedDefault(unspec, nexthop); err != nil {
		if !errors.Is(err, unix.EEXIST) {
			return false, fmt.Errorf("add scoped default on %s: %w", nexthop.Intf.Name, err)
		}
		// macOS installs its own RTF_IFSCOPE defaults for primary service
		// selection on multi-NIC setups, so a route on this ifindex can
		// already exist before we try. Binding to it via IP[V6]_BOUND_IF
		// still produces the scoped lookup we need.
		reused = true
	}

	af := unix.AF_INET
	if unspec.Is6() {
		af = unix.AF_INET6
	}
	nbnet.SetBoundInterface(af, nexthop.Intf)
	via := "point-to-point"
	if nexthop.IP.IsValid() {
		via = nexthop.IP.String()
	}
	verb := "installed"
	if reused {
		verb = "reused existing"
	}
	log.Infof("%s scoped default route via %s on %s for %s", verb, via, nexthop.Intf.Name, afOf(unspec))
	return true, nil
}

// cleanupAdvancedRouting releases the routes of a session before the scoped defaults, so its
// prefixes move on to the other sessions while their sockets still find the physical egress.
func (r *SysOps) cleanupAdvancedRouting() error {
	if r.coordinator == nil {
		nbnet.ClearBoundInterfaces()
		return r.flushScopedDefaults()
	}

	var merr *multierror.Error
	if r.sharedRoutes != nil {
		if err := r.releaseSharedRoutes(); err != nil {
			merr = multierror.Append(merr, err)
		}
	}
	if err := r.releaseSharedScopedDefaults(); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("release routing base: %w", err))
	}
	return nberrors.FormatErrorOrNil(merr)
}

// flushPlatformExtras runs darwin-specific residual cleanup hooked into the
// generic FlushMarkedRoutes path, so a crashed daemon's scoped defaults get
// removed on the next boot regardless of whether a profile is brought up.
func (r *SysOps) flushPlatformExtras() error {
	return r.flushScopedDefaults()
}

// flushScopedDefaults removes any scoped default routes tagged with routeProtoFlag.
// Safe to call at startup to clear residual entries from a prior session.
func (r *SysOps) flushScopedDefaults() error {
	rib, err := retryFetchRIB()
	if err != nil {
		return fmt.Errorf("fetch routing table: %w", err)
	}

	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return fmt.Errorf("parse routing table: %w", err)
	}

	var merr *multierror.Error
	removed := 0

	for _, msg := range msgs {
		rtMsg, ok := msg.(*route.RouteMessage)
		if !ok {
			continue
		}
		if rtMsg.Flags&routeProtoFlag == 0 {
			continue
		}
		if rtMsg.Flags&unix.RTF_IFSCOPE == 0 {
			continue
		}

		info, err := MsgToRoute(rtMsg)
		if err != nil {
			log.Debugf("skip scoped flush: %v", err)
			continue
		}
		if !info.Dst.IsValid() || info.Dst.Bits() != 0 {
			continue
		}

		if err := r.deleteScopedRoute(rtMsg); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("delete scoped default %s on index %d: %w",
				info.Dst, rtMsg.Index, err))
			continue
		}
		removed++
		log.Debugf("flushed residual scoped default %s on index %d", info.Dst, rtMsg.Index)
	}

	if removed > 0 {
		log.Infof("flushed %d residual scoped default route(s)", removed)
	}
	return nberrors.FormatErrorOrNil(merr)
}

func (r *SysOps) addScopedDefault(unspec netip.Addr, nexthop Nexthop) error {
	return r.scopedRouteSocket(unix.RTM_ADD, unspec, nexthop)
}

func (r *SysOps) deleteScopedRoute(rtMsg *route.RouteMessage) error {
	// Preserve identifying flags from the stored route (including RTF_GATEWAY
	// only if present); kernel-set bits like RTF_DONE don't belong on RTM_DELETE.
	keep := unix.RTF_UP | unix.RTF_STATIC | unix.RTF_GATEWAY | unix.RTF_IFSCOPE | routeProtoFlag
	del := &route.RouteMessage{
		Type:    unix.RTM_DELETE,
		Flags:   rtMsg.Flags & keep,
		Version: unix.RTM_VERSION,
		Seq:     r.getSeq(),
		Index:   rtMsg.Index,
		Addrs:   rtMsg.Addrs,
	}
	return r.writeRouteMessage(del, scopedRouteBudget)
}

func (r *SysOps) scopedRouteSocket(action int, unspec netip.Addr, nexthop Nexthop) error {
	flags := unix.RTF_UP | unix.RTF_STATIC | unix.RTF_IFSCOPE | routeProtoFlag

	msg := &route.RouteMessage{
		Type:    action,
		Flags:   flags,
		Version: unix.RTM_VERSION,
		ID:      uintptr(os.Getpid()),
		Seq:     r.getSeq(),
		Index:   nexthop.Intf.Index,
	}

	const numAddrs = unix.RTAX_NETMASK + 1
	addrs := make([]route.Addr, numAddrs)

	dst, err := addrToRouteAddr(unspec)
	if err != nil {
		return fmt.Errorf("build destination: %w", err)
	}
	mask, err := prefixToRouteNetmask(netip.PrefixFrom(unspec, 0))
	if err != nil {
		return fmt.Errorf("build netmask: %w", err)
	}
	addrs[unix.RTAX_DST] = dst
	addrs[unix.RTAX_NETMASK] = mask

	if nexthop.IP.IsValid() {
		msg.Flags |= unix.RTF_GATEWAY
		gw, err := addrToRouteAddr(nexthop.IP.Unmap())
		if err != nil {
			return fmt.Errorf("build gateway: %w", err)
		}
		addrs[unix.RTAX_GATEWAY] = gw
	} else {
		addrs[unix.RTAX_GATEWAY] = &route.LinkAddr{
			Index: nexthop.Intf.Index,
			Name:  nexthop.Intf.Name,
		}
	}
	msg.Addrs = addrs

	return r.writeRouteMessage(msg, scopedRouteBudget)
}

func afOf(a netip.Addr) string {
	if a.Is4() {
		return "IPv4"
	}
	return "IPv6"
}

// physicalDefaultNexthop returns the default nexthop of the physical network for the family of
// unspec. A lookup of the unspecified address matches the split default of an exit node, which with
// concurrent sessions may be up on the interface of another session already. The unscoped default
// route stays in the table under the split halves, so it is used then.
func (r *SysOps) physicalDefaultNexthop(unspec netip.Addr) (Nexthop, error) {
	nexthop, err := GetNextHop(unspec)
	if err != nil || r.coordinator == nil || nexthop.Intf == nil || !r.isSessionInterface(nexthop.Intf.Name) {
		return nexthop, err
	}

	current, found, err := unscopedRoute(netip.PrefixFrom(unspec, 0))
	if err != nil {
		return Nexthop{}, err
	}
	if !found || current.nexthop.Intf == nil || r.isSessionInterface(current.nexthop.Intf.Name) {
		return Nexthop{}, vars.ErrRouteNotFound
	}
	current.nexthop.IP = embeddedZoneToZone(current.nexthop.IP, current.nexthop.Intf)
	return current.nexthop, nil
}

// isSessionInterface reports whether name is the interface of this or another session.
func (r *SysOps) isSessionInterface(name string) bool {
	if r.wgInterface != nil && r.wgInterface.Name() == name {
		return true
	}
	return slices.Contains(r.coordinator.Sessions().SessionInterfaces(), name)
}

// embeddedZoneToZone moves the scope of a link-local gateway into the zone. The routing socket of
// macOS reports it in the second 16-bit word of the address instead (the KAME convention).
func embeddedZoneToZone(addr netip.Addr, intf *net.Interface) netip.Addr {
	if !addr.Is6() || !addr.IsLinkLocalUnicast() || addr.Zone() != "" {
		return addr
	}
	raw := addr.As16()
	raw[2], raw[3] = 0, 0
	return netip.AddrFrom16(raw).WithZone(intf.Name)
}
