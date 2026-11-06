//go:build privileged

package internal

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	nbnet "github.com/netbirdio/netbird/client/net"
)

// runUntilPrivateKeyCheck goes through the start of Run, where the routing probe sits,
// and stops at the private key check that follows, without touching the network.
func runUntilPrivateKeyCheck(t *testing.T, dir string, opts ...ConnectClientOption) {
	t.Helper()

	config, err := profilemanager.UpdateOrCreateConfig(profilemanager.ConfigInput{
		ConfigPath:    filepath.Join(dir, "work.json"),
		ManagementURL: "http://127.0.0.1:1",
	})
	require.NoError(t, err)
	config.PrivateKey = "not a key"

	client := NewConnectClient(CtxInitState(context.Background()), config, peer.NewRecorder(""), opts...)
	require.Error(t, client.Run(nil, ""), "the unusable private key must stop the run")
}

// The daemon probes once when it starts, so a session must not probe again. The
// environment is changed behind its back to tell a repeated probe from a kept result,
// and a client without a session key shows that the same change is visible to a probe.
func TestRun_OnlyClientsWithoutDaemonProbeRouting(t *testing.T) {
	switch runtime.GOOS {
	case "linux", "darwin", "windows":
	default:
		// Elsewhere there is no probe: advanced routing is never supported, so there is no
		// result for a session to keep and no change for a probe to see.
		t.Skipf("%s does not probe the routing support", runtime.GOOS)
	}
	dir := connectIdentityTestDir(t)

	t.Cleanup(nbnet.Init)
	nbnet.Init()
	require.True(t, nbnet.AdvancedRouting(), "the test needs a host with advanced routing")

	t.Setenv("NB_USE_LEGACY_ROUTING", "true")

	runUntilPrivateKeyCheck(t, dir, WithSessionKey(profilemanager.SessionKey{Profile: "work", Username: "alice"}))
	assert.True(t, nbnet.AdvancedRouting(), "a daemon session must keep the result of the daemon's probe")

	runUntilPrivateKeyCheck(t, dir, WithStatePath(filepath.Join(dir, "state.json")))
	assert.False(t, nbnet.AdvancedRouting(), "a foreground or embedded client must probe on every run")
}
