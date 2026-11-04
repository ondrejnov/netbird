//go:build privileged

package internal

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
)

// A disk-backed client with no state file must refuse to run instead of looking the file
// up through the active profile. Privileged because Run probes the routing setup first.
func TestRunWithoutStatePathFails(t *testing.T) {
	dir := connectIdentityTestDir(t)
	config, err := profilemanager.UpdateOrCreateConfig(profilemanager.ConfigInput{
		ConfigPath:    filepath.Join(dir, "work.json"),
		ManagementURL: "http://127.0.0.1:1",
	})
	require.NoError(t, err)

	ctx := CtxInitState(context.Background())
	client := NewConnectClient(ctx, config, peer.NewRecorder(""))

	assert.ErrorIs(t, client.Run(nil, ""), errNoStatePath)
}
