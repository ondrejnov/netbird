package systemops

import (
	"fmt"
	"net/netip"
)

// routeHandoverRemoves is true because every Windows interface holds routes of its own: the next
// owner adds its route next to the previous one, which is removed afterwards.
const routeHandoverRemoves = true

// ensureRoute adds the route unless the interface has it already, and reports which it was.
func (r *SysOps) ensureRoute(prefix netip.Prefix, nexthop Nexthop) (existed bool, err error) {
	if routePresent(prefix, nexthop) {
		return true, nil
	}
	if err := addRoute(prefix, nexthop); err != nil {
		return false, fmt.Errorf("add route %s: %w", prefix, err)
	}
	return false, nil
}

func (r *SysOps) removeRouteIfPresent(prefix netip.Prefix, nexthop Nexthop) error {
	if !routePresent(prefix, nexthop) {
		return nil
	}
	return deleteRoute(prefix, nexthop)
}

// routePresent reports whether the interface of nexthop has a route for prefix. An interface
// that is gone has no routes.
func routePresent(prefix netip.Prefix, nexthop Nexthop) bool {
	route, err := setupRouteEntry(prefix, nexthop)
	if err != nil {
		return false
	}
	return getIPForwardEntry2(route) == nil
}
