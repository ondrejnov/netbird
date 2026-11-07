//go:build (linux && !android) || windows

package systemops

import (
	"net/netip"

	"github.com/netbirdio/netbird/client/internal/hostcoord"
)

// warnOverlayRouteRefused tells the session once per route that the overlay of another session keeps
// it out of the table. The route manager asks again with every recalculation.
func (r *SysOps) warnOverlayRouteRefused(prefix netip.Prefix) {
	if r.sharedRouteEvents == nil || !r.overlapsOtherOverlay(prefix) {
		return
	}
	if _, warned := r.overlayRefusals.LoadOrStore(prefix, struct{}{}); warned {
		return
	}
	r.sharedRouteEvents(hostcoord.RouteEvent{
		Kind:    hostcoord.RouteEventOverlayRefused,
		Session: r.sessionKey,
		Prefix:  prefix,
	})
}
