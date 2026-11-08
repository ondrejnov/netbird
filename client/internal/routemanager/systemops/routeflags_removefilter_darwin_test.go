//go:build darwin && !ios

package systemops

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func TestIgnoreRemovedDefaultRoute(t *testing.T) {
	up := unix.RTF_UP | unix.RTF_GATEWAY | unix.RTF_STATIC
	assert.True(t, IgnoreRemovedDefaultRoute(up|unix.RTF_IFSCOPE|routeProtoFlag), "a scoped default of NetBird is no network change")
	assert.False(t, IgnoreRemovedDefaultRoute(up), "the unscoped default going away is a network change")
	assert.False(t, IgnoreRemovedDefaultRoute(up|unix.RTF_IFSCOPE), "a scoped default of macOS still counts as before")
	assert.False(t, IgnoreRemovedDefaultRoute(up|routeProtoFlag), "an unscoped default with the mark still counts")
}
