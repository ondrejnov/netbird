//go:build dragonfly || freebsd || netbsd || openbsd

package systemops

// IgnoreAddedDefaultRoute reports whether an RTM_ADD default route with the
// given flags should be ignored by the network monitor.
func IgnoreAddedDefaultRoute(flags int) bool {
	return filterRoutesByFlags(flags)
}

// IgnoreRemovedDefaultRoute reports whether an RTM_DELETE default route with the given flags should
// be ignored by the network monitor. These platforms do not run concurrent sessions.
func IgnoreRemovedDefaultRoute(int) bool {
	return false
}
