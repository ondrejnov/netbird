package systemops

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/hostcoord"
	"github.com/netbirdio/netbird/client/internal/routemanager/notifier"
	"github.com/netbirdio/netbird/client/internal/routemanager/refcounter"
	"github.com/netbirdio/netbird/client/internal/routemanager/vars"
)

type Nexthop struct {
	IP   netip.Addr
	Intf *net.Interface
}

// Route represents a basic network route with core routing information
type Route struct {
	Dst       netip.Prefix
	Gw        netip.Addr
	Interface *net.Interface
}

// DetailedRoute extends Route with additional metadata for display and debugging
type DetailedRoute struct {
	Route
	Metric          int
	InterfaceMetric int
	InterfaceIndex  int
	Protocol        string
	Scope           string
	Type            string
	Table           string
	Flags           string
}

// Equal checks if two nexthops are equal.
func (n Nexthop) Equal(other Nexthop) bool {
	return n.IP == other.IP && (n.Intf == nil && other.Intf == nil ||
		n.Intf != nil && other.Intf != nil && n.Intf.Index == other.Intf.Index)
}

// String returns a string representation of the nexthop.
func (n Nexthop) String() string {
	if n.Intf == nil {
		return n.IP.String()
	}
	if n.IP.IsValid() {
		return fmt.Sprintf("%s @ %d (%s)", n.IP.String(), n.Intf.Index, n.Intf.Name)
	}
	return fmt.Sprintf("no-ip @ %d (%s)", n.Intf.Index, n.Intf.Name)
}

type wgIface interface {
	Address() wgaddr.Address
	Name() string
}

type ExclusionCounter = refcounter.Counter[netip.Prefix, struct{}, Nexthop]

type SysOps struct {
	refCounter  *ExclusionCounter
	wgInterface wgIface
	// prefixes is tracking all the current added prefixes im memory
	// (this is used in iOS as all route updates require a full table update)
	//nolint
	prefixes map[netip.Prefix]struct{}
	//nolint
	mu sync.Mutex
	// notifier is used to notify the system of route changes (also used on mobile)
	notifier *notifier.Notifier
	// seq is an atomic counter for generating unique sequence numbers for route messages
	//nolint:unused // only used on BSD systems
	seq atomic.Uint32

	localSubnetsCache     []*net.IPNet
	localSubnetsCacheMu   sync.RWMutex
	localSubnetsCacheTime time.Time

	// coordinator shares the routing base between sessions. When nil, this instance
	// owns the base alone. Only Linux uses it.
	//nolint:unused // only used on Linux
	coordinator *hostcoord.Coordinator
	sessionKey  hostcoord.SessionKey
	// sharedRoutes decides which session carries a prefix of the shared table. When
	// nil, routes go straight to the kernel. Only Linux and Windows use it.
	//nolint:unused // only used on Linux and Windows
	sharedRoutes *hostcoord.Routes
	//nolint:unused // only used on Linux and Windows
	sharedRouteEvents hostcoord.RouteEventFunc
	// otherOverlays lists the overlay prefixes of the other sessions. When nil, only the
	// own overlay is refused.
	otherOverlays overlayPrefixSource
	// overlayRefusals holds the routes the session was warned about, see warnOverlayRouteRefused.
	//nolint:unused // only used on Linux and Windows
	overlayRefusals sync.Map
	// originalSysctl stores the sysctl values from before this instance changed them.
	//nolint:unused // only used on Linux
	originalSysctl map[string]int
	// sysctlFailed is used as an indicator to emit a warning when default routes are configured.
	//nolint:unused // only used on Linux
	sysctlFailed atomic.Bool
}

func New(wgInterface wgIface, notifier *notifier.Notifier) *SysOps {
	return &SysOps{
		wgInterface: wgInterface,
		notifier:    notifier,
	}
}

// NewShared returns a SysOps that shares the routing base with the other sessions
// of coordinator instead of owning it. Linux honors the coordinator and the options,
// Windows the shared routes and the overlay prefixes, as it has no routing base.
func NewShared(wgInterface wgIface, notifier *notifier.Notifier, coordinator *hostcoord.Coordinator, key hostcoord.SessionKey, opts ...SharedOption) *SysOps {
	r := New(wgInterface, notifier)
	r.coordinator = coordinator
	r.sessionKey = key
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// overlayPrefixSource reports the overlay prefixes of the sessions of the daemon other
// than key. hostcoord.Sessions implements it.
type overlayPrefixSource interface {
	OverlayPrefixesExcept(key hostcoord.SessionKey) []netip.Prefix
}

// SharedOption configures a SysOps returned by NewShared.
type SharedOption func(*SysOps)

// WithSharedRoutes makes the session claim its overlay routes in routes, so a prefix
// shared with another session has one owner and moves on when that owner leaves. Its
// stop then removes only the routes of this session. onEvent receives the warnings for
// this session and may be nil. Nil routes leave the routes unshared.
func WithSharedRoutes(routes *hostcoord.Routes, onEvent hostcoord.RouteEventFunc) SharedOption {
	return func(r *SysOps) {
		r.sharedRoutes = routes
		r.sharedRouteEvents = onEvent
	}
}

// WithOverlayPrefixes makes the session refuse every route that covers or overlaps an
// overlay prefix src reports for another session. The default routes 0.0.0.0/0 and ::/0 stay allowed,
// since the traffic to an overlay still follows the rules of the host. A nil src keeps
// the check on the own overlay only.
func WithOverlayPrefixes(src overlayPrefixSource) SharedOption {
	return func(r *SysOps) {
		r.otherOverlays = src
	}
}

//nolint:unused // only used on BSD systems
func (r *SysOps) getSeq() int {
	return int(r.seq.Add(1))
}

func (r *SysOps) validateRoute(prefix netip.Prefix) error {
	addr := prefix.Addr()

	switch {
	case
		!addr.IsValid(),
		addr.IsLoopback(),
		addr.IsLinkLocalUnicast(),
		addr.IsLinkLocalMulticast(),
		addr.IsInterfaceLocalMulticast(),
		addr.IsMulticast(),
		addr.IsUnspecified() && prefix.Bits() != 0,
		r.isOwnAddress(addr),
		r.overlapsOtherOverlay(prefix):
		return vars.ErrRouteNotAllowed
	}
	return nil
}

func (r *SysOps) overlapsOtherOverlay(prefix netip.Prefix) bool {
	if r.otherOverlays == nil || prefix.Bits() == 0 {
		return false
	}
	// A 4in6 prefix would never overlap a v4 prefix, so compare the v4 form.
	if addr := prefix.Addr(); addr.Is4In6() && prefix.Bits() >= 96 {
		prefix = netip.PrefixFrom(addr.Unmap(), prefix.Bits()-96)
	}
	for _, overlay := range r.otherOverlays.OverlayPrefixesExcept(r.sessionKey) {
		if prefix.Overlaps(overlay) {
			return true
		}
	}
	return false
}

func (r *SysOps) isOwnAddress(addr netip.Addr) bool {
	if r.wgInterface == nil {
		return false
	}
	wgAddr := r.wgInterface.Address()
	return wgAddr.Network.Contains(addr) || (wgAddr.IPv6Net.IsValid() && wgAddr.IPv6Net.Contains(addr))
}
