//go:build windows || (darwin && !ios)

package systemops

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/hostcoord"
	"github.com/netbirdio/netbird/client/internal/routemanager/vars"
)

// AddVPNRoute adds a route through the NetBird interface. With concurrent sessions the prefix is
// claimed instead, so only one session carries it.
func (r *SysOps) AddVPNRoute(prefix netip.Prefix, intf *net.Interface) error {
	if err := r.validateRoute(prefix); err != nil {
		r.warnOverlayRouteRefused(prefix)
		return err
	}
	if r.sharedRoutes != nil {
		return r.addSharedVPNRoute(prefix, intf)
	}
	return r.genericAddVPNRoute(prefix, intf)
}

// RemoveVPNRoute removes a route added by AddVPNRoute.
func (r *SysOps) RemoveVPNRoute(prefix netip.Prefix, intf *net.Interface) error {
	if err := r.validateRoute(prefix); err != nil {
		return err
	}
	if r.sharedRoutes != nil {
		return r.removeSharedVPNRoute(prefix)
	}
	return r.genericRemoveVPNRoute(prefix, intf)
}

// routeParts are the routes a session holds for one prefix. The default prefixes are split in
// halves, and a v4 exit node without v6 adds the v6 halves as a best-effort blackhole, the same
// as genericAddVPNRoute.
type routeParts struct {
	required []netip.Prefix
	optional []netip.Prefix
}

func (r *SysOps) sharedRouteParts(prefix netip.Prefix) routeParts {
	switch prefix {
	case vars.Defaultv4:
		parts := routeParts{required: []netip.Prefix{splitDefaultv4_1, splitDefaultv4_2}}
		if r.wgInterface == nil || !r.wgInterface.Address().HasIPv6() {
			parts.optional = []netip.Prefix{splitDefaultv6_1, splitDefaultv6_2}
		}
		return parts
	case vars.Defaultv6:
		return routeParts{required: []netip.Prefix{splitDefaultv6_1, splitDefaultv6_2}}
	default:
		return routeParts{required: []netip.Prefix{prefix}}
	}
}

func (r *SysOps) addSharedVPNRoute(prefix netip.Prefix, intf *net.Interface) error {
	if intf == nil {
		return errors.New("shared route without an interface")
	}
	nexthop := Nexthop{netip.Addr{}, intf}
	// Decided once, so the claim removes exactly what it installed.
	parts := r.sharedRouteParts(prefix)

	_, err := r.sharedRoutes.Add(r.sessionKey, prefix, hostcoord.RouteClaim{
		Dev:              intf.Name,
		Install:          func() error { return r.installRouteParts(parts, nexthop) },
		Remove:           func() error { return r.removeRouteParts(parts, nexthop) },
		RemoveOnHandover: routeHandoverRemoves,
		Notify:           r.sharedRouteEvents,
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

// releaseSharedRoutes releases every claim of the session, so its prefixes move on to the
// sessions waiting for them.
func (r *SysOps) releaseSharedRoutes() error {
	if err := r.sharedRoutes.ReleaseSession(r.sessionKey); err != nil {
		return fmt.Errorf("release session routes: %w", err)
	}
	return nil
}

// installRouteParts adds the routes of a claim. A route already on the interface comes from an
// earlier install by the same session and counts as added.
func (r *SysOps) installRouteParts(parts routeParts, nexthop Nexthop) error {
	var added []netip.Prefix
	for _, p := range parts.required {
		existed, err := r.ensureRoute(p, nexthop)
		if err != nil {
			r.rollBackRoutes(added, nexthop)
			return err
		}
		if !existed {
			added = append(added, p)
		}
	}
	for _, p := range parts.optional {
		if _, err := r.ensureRoute(p, nexthop); err != nil {
			log.Warnf("failed to add v6 split-default blackhole %s: %v", p, err)
		}
	}
	return nil
}

func (r *SysOps) rollBackRoutes(added []netip.Prefix, nexthop Nexthop) {
	for _, p := range added {
		if err := r.removeRouteIfPresent(p, nexthop); err != nil {
			log.Warnf("failed to roll back route %s: %v", p, err)
		}
	}
}

// removeRouteParts removes the routes of a claim. A route already gone is a success, so the
// removal can repeat after the session stopped.
func (r *SysOps) removeRouteParts(parts routeParts, nexthop Nexthop) error {
	var errs []error
	for _, list := range [][]netip.Prefix{parts.required, parts.optional} {
		for _, p := range list {
			if err := r.removeRouteIfPresent(p, nexthop); err != nil {
				errs = append(errs, fmt.Errorf("remove %s: %w", p, err))
			}
		}
	}
	return errors.Join(errs...)
}
