package internal

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/configs"
	"github.com/netbirdio/netbird/client/internal/debug"
	"github.com/netbirdio/netbird/client/internal/hostcoord"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
)

func bundleContents(t *testing.T, path string) map[string]string {
	t.Helper()
	reader, err := zip.OpenReader(path)
	require.NoError(t, err)
	defer func() { require.NoError(t, reader.Close()) }()

	contents := make(map[string]string, len(reader.File))
	for _, file := range reader.File {
		opened, err := file.Open()
		require.NoError(t, err)
		raw, err := io.ReadAll(opened)
		require.NoError(t, err)
		require.NoError(t, opened.Close())
		contents[file.Name] = string(raw)
	}
	return contents
}

// The Management of a session can ask for a debug bundle and name where it goes. With the focus on
// another session that destination must get neither the state of the focused session, which is what
// a bundle without a state path carries, nor the log of the daemon or the host information, which
// describe all sessions (I5).
func TestRemoteBundleStaysWithItsSession(t *testing.T) {
	const (
		focusedState = "state-of-the-focused-session"
		ownState     = "state-of-the-session-asked"
		daemonLog    = "line-about-every-session"
	)

	dir := t.TempDir()
	origDir, origState, origDefault := profilemanager.DefaultConfigPathDir, profilemanager.ActiveProfileStatePath, profilemanager.DefaultConfigPath
	profilemanager.DefaultConfigPathDir = dir
	profilemanager.ActiveProfileStatePath = filepath.Join(dir, "active_profile.json")
	profilemanager.DefaultConfigPath = filepath.Join(dir, "default.json")
	t.Cleanup(func() {
		profilemanager.DefaultConfigPathDir = origDir
		profilemanager.ActiveProfileStatePath = origState
		profilemanager.DefaultConfigPath = origDefault
	})

	const otherManagement = "mgmt.other.example"
	origStateDir := configs.StateDir
	configs.StateDir = dir
	t.Cleanup(func() { configs.StateDir = origStateDir })
	require.NoError(t, os.WriteFile(filepath.Join(dir, "service.json"), []byte(`{"management_url":"https://`+otherManagement+`:443"}`), 0o600))

	own := hostcoord.SessionKey{Profile: "work", Username: "alice"}
	focused := profilemanager.ActiveProfileState{ID: "home", Username: "bob"}
	manager := profilemanager.NewServiceManager("")
	require.NoError(t, manager.SetActiveProfileState(&focused))
	require.NoError(t, os.WriteFile(manager.GetStatePath(), []byte(`{"marker":"`+focusedState+`"}`), 0o600))
	require.NoError(t, os.WriteFile(manager.GetStatePathFor(own), []byte(`{"marker":"`+ownState+`"}`), 0o600))

	logPath := filepath.Join(dir, "netbird.log")
	require.NoError(t, os.WriteFile(logPath, []byte(daemonLog+"\n"), 0o600))

	slots, err := hostcoord.NewSlots(dir)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, slots.Close()) })

	e := &Engine{
		statusRecorder: peer.NewRecorder(""),
		config: &EngineConfig{
			ProfileConfig: &profilemanager.Config{},
			LogPath:       logPath,
			TempDir:       dir,
			Session:       NewDaemonHost(slots).Session(own, nil),
		},
	}
	deps := e.remoteBundleDependencies(nil)
	deps.RefreshStatus = nil

	path, err := debug.NewBundleGenerator(deps, debug.BundleConfig{IncludeSystemInfo: true}).Generate()
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.Remove(path) })

	contents := bundleContents(t, path)
	assert.Contains(t, contents["state.json"], ownState, "the bundle should carry the state of the session it is about")
	for name, content := range contents {
		assert.NotContains(t, content, focusedState, "%s must not carry the state of the focused session", name)
		assert.NotContains(t, content, daemonLog, "%s must not carry the log of the daemon", name)
		assert.NotContains(t, content, otherManagement, "%s must not name the Management of another network", name)
	}
	assert.NotContains(t, contents, "routes.txt", "the routes of the host describe all sessions")
}

// Without the gate a remote bundle stays what it is (I1).
func TestRemoteBundleWithoutTheGateIsUnchanged(t *testing.T) {
	e := &Engine{statusRecorder: peer.NewRecorder(""), config: &EngineConfig{ProfileConfig: &profilemanager.Config{}, LogPath: "the-log"}}
	deps := e.remoteBundleDependencies(nil)

	assert.Empty(t, deps.StatePath, "the state file stays the one of the active profile")
	assert.Empty(t, deps.ProfileName)
	assert.False(t, deps.OmitHostWide)
	assert.Equal(t, "the-log", deps.LogPath)
}
