//go:build ios

package systemops

// IgnoreRemovedDefaultRoute reports whether an RTM_DELETE default route with the given flags should
// be ignored by the network monitor. iOS installs no scoped defaults of NetBird.
func IgnoreRemovedDefaultRoute(int) bool {
	return false
}
