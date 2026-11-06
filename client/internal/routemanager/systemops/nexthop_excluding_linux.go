//go:build !android

package systemops

import (
	"fmt"
	"net"
	"net/netip"
	"slices"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/netbirdio/netbird/client/internal/routemanager/vars"
)

// GetDefaultNextHopExcluding returns the next hop of the default route ip, 0.0.0.0 or ::, stands
// for, ignoring the interfaces named excluded. The lookup follows the routing rules of the host, so
// it finds the exit node of whichever session has one. The main table then has the physical default.
func GetDefaultNextHopExcluding(ip netip.Addr, excluded []string) (Nexthop, error) {
	nexthop, err := GetNextHop(ip)
	if err != nil {
		return Nexthop{}, err
	}
	if nexthop.Intf == nil || !slices.Contains(excluded, nexthop.Intf.Name) {
		return nexthop, nil
	}

	log.Debugf("default route goes through %s of a session, using the main table", nexthop.Intf.Name)
	family := netlink.FAMILY_V4
	if ip.Is6() {
		family = netlink.FAMILY_V6
	}
	return mainTableDefault(family, excluded)
}

func mainTableDefault(family int, excluded []string) (Nexthop, error) {
	routes, err := netlink.RouteListFiltered(family, &netlink.Route{Table: unix.RT_TABLE_MAIN}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return Nexthop{}, fmt.Errorf("list main table routes: %w", err)
	}

	var best *netlink.Route
	var bestIntf *net.Interface
	for i := range routes {
		route := &routes[i]
		if !isDefaultDst(route.Dst) || (best != nil && route.Priority >= best.Priority) {
			continue
		}
		intf, err := net.InterfaceByIndex(route.LinkIndex)
		if err != nil {
			log.Debugf("failed to find interface %d of a default route: %v", route.LinkIndex, err)
			continue
		}
		if !slices.Contains(excluded, intf.Name) {
			best, bestIntf = route, intf
		}
	}
	if best == nil {
		return Nexthop{}, vars.ErrRouteNotFound
	}
	if best.Gw == nil {
		return Nexthop{Intf: bestIntf}, nil
	}

	addr, err := ipToAddr(best.Gw, bestIntf)
	if err != nil {
		return Nexthop{}, fmt.Errorf("convert gateway to address: %w", err)
	}
	return Nexthop{IP: addr, Intf: bestIntf}, nil
}

// isDefaultDst reports whether dst is a default route. netlink v1.3 reports the default as 0.0.0.0/0
// or ::/0, older versions as a nil Dst.
func isDefaultDst(dst *net.IPNet) bool {
	if dst == nil {
		return true
	}
	ones, _ := dst.Mask.Size()
	return ones == 0
}
