//go:build linux && !android

package dns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// A session whose host DNS revert failed leaves a dns_state naming its interface. Once the interface
// is gone, systemd-resolved has dropped the link configuration with it, so the cleanup has nothing to
// undo. Failing instead leaves the state on disk for good and blocks the profile from running next to
// another session.
func TestShutdownStateCleanupSystemdGoneInterface(t *testing.T) {
	state := &ShutdownState{ManagerType: systemdManager, WgIface: "nbgone-test0"}

	assert.NoError(t, state.Cleanup(), "a gone interface leaves no systemd-resolved link config to revert")
}
