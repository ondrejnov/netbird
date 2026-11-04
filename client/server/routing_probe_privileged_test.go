//go:build privileged

package server

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
	nbnet "github.com/netbirdio/netbird/client/net"
)

// The daemon has to know its routing mode before the first session, not when that
// session happens to start. With auto connect off, Start brings up no session at all,
// so the probe can only have come from Start itself.
func TestStart_ProbesRoutingWithoutASession(t *testing.T) {
	s, ctx, _, _, cfgPath := setupServerWithProfile(t)
	ctx, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	s.rootCtx = ctx

	disableAutoConnect := true
	_, err := profilemanager.UpdateOrCreateConfig(profilemanager.ConfigInput{
		ConfigPath:         cfgPath,
		DisableAutoConnect: &disableAutoConnect,
	})
	require.NoError(t, err)

	t.Cleanup(nbnet.Init)
	t.Setenv("NB_USE_LEGACY_ROUTING", "true")
	nbnet.Init()
	require.False(t, nbnet.AdvancedRouting(), "the test starts from a process that has not probed this host")
	t.Setenv("NB_USE_LEGACY_ROUTING", "")

	require.NoError(t, s.Start())

	assert.False(t, s.session.isClientRunning(), "auto connect is off, so no session may run")
	assert.True(t, nbnet.AdvancedRouting(), "Start must probe routing before the first session")
}
