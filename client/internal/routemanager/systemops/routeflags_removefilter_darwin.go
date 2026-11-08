//go:build darwin && !ios

package systemops

import "golang.org/x/sys/unix"

// IgnoreRemovedDefaultRoute reports whether an RTM_DELETE default route with the given flags should
// be ignored by the network monitor. A scoped default NetBird marked is one of its own: with
// concurrent sessions another session reinstalls them on its start, which is no network change.
func IgnoreRemovedDefaultRoute(flags int) bool {
	return flags&unix.RTF_IFSCOPE != 0 && flags&routeProtoFlag != 0
}
