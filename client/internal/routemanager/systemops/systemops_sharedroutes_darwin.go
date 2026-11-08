//go:build !ios

package systemops

import (
	"fmt"
	"net"
	"net/netip"
	"slices"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// routeHandoverRemoves is false because the macOS table holds one unscoped route per prefix: the
// next owner replaces the route of the previous one, so there is nothing left to remove after it.
const routeHandoverRemoves = false

// tableRoute is an unscoped route of the table for one prefix.
type tableRoute struct {
	index   int
	nexthop Nexthop
}

// ensureRoute adds the route unless the interface has it already, and reports which it was. A
// route of another session for the prefix is the one a handover takes over, so it is replaced. A
// route of anything else stays, and the add fails on it as it does without sessions.
func (r *SysOps) ensureRoute(prefix netip.Prefix, nexthop Nexthop) (existed bool, err error) {
	if nexthop.Intf == nil {
		return false, fmt.Errorf("route %s without an interface", prefix)
	}
	current, found, err := unscopedRoute(prefix)
	if err != nil {
		return false, err
	}
	if found && current.index == nexthop.Intf.Index {
		return true, nil
	}
	if found && r.isOtherSessionInterface(current.index) {
		if err := r.removeFromRouteTable(prefix, current.nexthop); err != nil {
			return false, fmt.Errorf("take over route %s: %w", prefix, err)
		}
	}
	if err := r.addToRouteTable(prefix, nexthop); err != nil {
		return false, fmt.Errorf("add route %s: %w", prefix, err)
	}
	return false, nil
}

// removeRouteIfPresent removes the route only while it goes through the interface of nexthop. A
// delete names the prefix, not the interface, so without the check it would take the route of the
// session that owns the prefix now.
func (r *SysOps) removeRouteIfPresent(prefix netip.Prefix, nexthop Nexthop) error {
	if nexthop.Intf == nil {
		return fmt.Errorf("route %s without an interface", prefix)
	}
	current, found, err := unscopedRoute(prefix)
	if err != nil {
		return err
	}
	if !found || current.index != nexthop.Intf.Index {
		return nil
	}
	return r.removeFromRouteTable(prefix, nexthop)
}

// isOtherSessionInterface reports whether the interface with index belongs to another session of
// the daemon. An interface that is gone cannot be told apart, so it does not count.
func (r *SysOps) isOtherSessionInterface(index int) bool {
	if r.coordinator == nil {
		return false
	}
	intf, err := net.InterfaceByIndex(index)
	if err != nil {
		log.Debugf("interface %d of a route is gone: %v", index, err)
		return false
	}
	if r.wgInterface != nil && intf.Name == r.wgInterface.Name() {
		return false
	}
	return slices.Contains(r.coordinator.Sessions().SessionInterfaces(), intf.Name)
}

// unscopedRoute returns the unscoped route of the table for exactly prefix, and whether there is one.
// Scoped routes are per interface and leave the unscoped lookup alone.
func unscopedRoute(prefix netip.Prefix) (tableRoute, bool, error) {
	rib, err := retryFetchRIB()
	if err != nil {
		return tableRoute{}, false, fmt.Errorf("fetch routing table: %w", err)
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return tableRoute{}, false, fmt.Errorf("parse routing table: %w", err)
	}

	prefix = prefix.Masked()
	for _, msg := range msgs {
		rtMsg, ok := msg.(*route.RouteMessage)
		if !ok || rtMsg.Flags&unix.RTF_IFSCOPE != 0 {
			continue
		}
		info, err := MsgToRoute(rtMsg)
		if err != nil {
			continue
		}
		if info.Dst.Masked() != prefix {
			continue
		}
		nexthop := Nexthop{IP: info.Gw, Intf: info.Interface}
		if nexthop.Intf == nil {
			if intf, err := net.InterfaceByIndex(rtMsg.Index); err == nil {
				nexthop.Intf = intf
			}
		}
		return tableRoute{index: rtMsg.Index, nexthop: nexthop}, true, nil
	}
	return tableRoute{}, false, nil
}
