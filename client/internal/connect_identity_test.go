package internal

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
)

func connectIdentityTestDir(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	origDir, origActive, origOverride := profilemanager.DefaultConfigPathDir, profilemanager.ActiveProfileStatePath, profilemanager.ConfigDirOverride
	profilemanager.DefaultConfigPathDir = dir
	profilemanager.ActiveProfileStatePath = filepath.Join(dir, "active_profile.json")
	profilemanager.ConfigDirOverride = dir
	t.Cleanup(func() {
		profilemanager.DefaultConfigPathDir = origDir
		profilemanager.ActiveProfileStatePath = origActive
		profilemanager.ConfigDirOverride = origOverride
	})

	t.Setenv("NB_DNS_STATE_FILE", "")
	return dir
}

// The active profile names someone else, as it does after a switch: the client still
// takes the state file and the certificate store owner from the key it was given.
func TestWithSessionKey_IdentityComesFromKeyNotActiveProfile(t *testing.T) {
	dir := connectIdentityTestDir(t)
	sm := profilemanager.NewServiceManager("")
	require.NoError(t, sm.SetActiveProfileState(&profilemanager.ActiveProfileState{ID: "other", Username: "bob"}))

	client := NewConnectClient(context.Background(), nil, nil,
		WithSessionKey(profilemanager.SessionKey{Profile: "work", Username: "alice"}))

	assert.Equal(t, filepath.Join(dir, "work.state.json"), client.statePath, "state file of the key")
	assert.Equal(t, "alice", client.profileOwner, "certificate store owner of the key")
	assert.False(t, client.profileOwnerUnknown, "the owner is known")
}

func TestWithSessionKey_DefaultProfileHasKnownOwner(t *testing.T) {
	dir := connectIdentityTestDir(t)

	client := NewConnectClient(context.Background(), nil, nil,
		WithSessionKey(profilemanager.SessionKey{Profile: profilemanager.DefaultProfileName}))

	assert.Equal(t, filepath.Join(dir, "state.json"), client.statePath, "state file of the default profile")
	assert.Empty(t, client.profileOwner, "the default profile belongs to no user")
	assert.False(t, client.profileOwnerUnknown, "an empty owner of the default profile is still known")
}

// A client without an identity must not answer certificate posture checks from a
// user's store.
func TestWithSessionKey_EmptyKeyLeavesOwnerUnknown(t *testing.T) {
	connectIdentityTestDir(t)

	client := NewConnectClient(context.Background(), nil, nil, WithSessionKey(profilemanager.SessionKey{}))

	assert.True(t, client.profileOwnerUnknown, "no user's store may answer for an unknown owner")
}
