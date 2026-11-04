//go:build !android

package systemops

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"syscall"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	nberrors "github.com/netbirdio/netbird/client/errors"
	"github.com/netbirdio/netbird/client/internal/hostcoord"
	"github.com/netbirdio/netbird/client/internal/routemanager/vars"
)

func (r *SysOps) addSharedVPNRoute(prefix netip.Prefix, intf *net.Interface) error {
	if intf == nil {
		return errors.New("shared route without an interface")
	}

	nexthop := Nexthop{netip.Addr{}, intf}
	// Decided once, so the claim removes exactly what it installed. A change of the
	// v6 overlay restarts the engine, which releases the claim first.
	withBlackhole := prefix == vars.Defaultv4 && (r.wgInterface == nil || !r.wgInterface.Address().HasIPv6())

	_, err := r.sharedRoutes.Add(r.sessionKey, prefix, hostcoord.RouteClaim{
		Dev: intf.Name,
		Install: func() error {
			return installSharedRoute(prefix, nexthop, withBlackhole)
		},
		Remove: func() error {
			return uninstallSharedRoute(prefix, nexthop, withBlackhole)
		},
		Notify: r.sharedRouteEvents,
	})
	if err != nil {
		return fmt.Errorf("claim route: %w", err)
	}
	return nil
}

func (r *SysOps) removeSharedVPNRoute(prefix netip.Prefix) error {
	if err := r.sharedRoutes.Remove(r.sessionKey, prefix); err != nil {
		return fmt.Errorf("release route: %w", err)
	}
	return nil
}

// cleanupSharedRouting releases the routes of this session before the routing base,
// because the last release of the base flushes the whole table.
func (r *SysOps) cleanupSharedRouting() error {
	var result *multierror.Error
	if err := r.sharedRoutes.ReleaseSession(r.sessionKey); err != nil {
		result = multierror.Append(result, fmt.Errorf("release session routes: %w", err))
	}
	if err := r.releaseRoutingBase(); err != nil {
		result = multierror.Append(result, fmt.Errorf("release routing base: %w", err))
	}
	return nberrors.FormatErrorOrNil(result)
}

// installSharedRoute installs the blackhole first, so v6 cannot leak once v4 is in
// the tunnel. Replacing keeps the route present during a handover between sessions.
func installSharedRoute(prefix netip.Prefix, nexthop Nexthop, withBlackhole bool) error {
	if withBlackhole {
		if err := replaceUnreachableRoute(vars.Defaultv6, NetbirdVPNTableID); err != nil {
			return fmt.Errorf("add v6 blackhole: %w", err)
		}
	}
	if err := replaceRoute(prefix, nexthop, NetbirdVPNTableID); err != nil {
		if withBlackhole {
			rollBackBlackhole(prefix)
		}
		return fmt.Errorf("add route: %w", err)
	}
	return nil
}

// rollBackBlackhole keeps the blackhole when a previous install of the route is still in
// the table, or when that cannot be determined, so v6 cannot leak while v4 is in the tunnel.
func rollBackBlackhole(prefix netip.Prefix) {
	routes, err := netlink.RouteListFiltered(getAddressFamily(prefix), &netlink.Route{Table: NetbirdVPNTableID}, netlink.RT_FILTER_TABLE)
	if err != nil {
		log.Debugf("keep v6 blackhole, list routes: %v", err)
		return
	}
	if slices.ContainsFunc(routes, func(route netlink.Route) bool {
		return route.Dst == nil || route.Dst.IP.IsUnspecified() && isZeroMask(route.Dst.Mask)
	}) {
		return
	}
	if err := removeUnreachableRoute(vars.Defaultv6, NetbirdVPNTableID); err != nil {
		log.Debugf("roll back v6 blackhole: %v", err)
	}
}

func isZeroMask(mask net.IPMask) bool {
	ones, _ := mask.Size()
	return ones == 0
}

// uninstallSharedRoute removes the route before the blackhole, the reverse of the
// install, and keeps the blackhole when the route stays, so v6 cannot leak while v4 is
// still in the tunnel. Both deletes accept a route already gone, so it can be repeated.
func uninstallSharedRoute(prefix netip.Prefix, nexthop Nexthop, withBlackhole bool) error {
	if err := removeRoute(prefix, nexthop, NetbirdVPNTableID); err != nil {
		return fmt.Errorf("remove route: %w", err)
	}
	if !withBlackhole {
		return nil
	}
	if err := removeUnreachableRoute(vars.Defaultv6, NetbirdVPNTableID); err != nil {
		return fmt.Errorf("remove v6 blackhole: %w", err)
	}
	return nil
}

func replaceRoute(prefix netip.Prefix, nexthop Nexthop, tableID int) error {
	_, ipNet, err := net.ParseCIDR(prefix.String())
	if err != nil {
		return fmt.Errorf(errParsePrefixMsg, prefix, err)
	}

	route := &netlink.Route{
		Scope:  netlink.SCOPE_UNIVERSE,
		Table:  tableID,
		Family: getAddressFamily(prefix),
		Dst:    ipNet,
	}
	if err := addNextHop(nexthop, route); err != nil {
		return fmt.Errorf("add gateway and device: %w", err)
	}

	if err := netlink.RouteReplace(route); err != nil && !isOpErr(err) {
		return fmt.Errorf("netlink replace route: %w", err)
	}
	return nil
}

func replaceUnreachableRoute(prefix netip.Prefix, tableID int) error {
	_, ipNet, err := net.ParseCIDR(prefix.String())
	if err != nil {
		return fmt.Errorf(errParsePrefixMsg, prefix, err)
	}

	route := &netlink.Route{
		Type:   syscall.RTN_UNREACHABLE,
		Table:  tableID,
		Family: getAddressFamily(prefix),
		Dst:    ipNet,
	}
	if err := netlink.RouteReplace(route); err != nil && !isOpErr(err) {
		return fmt.Errorf("netlink replace unreachable route: %w", err)
	}
	return nil
}
