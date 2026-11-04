package profilemanager

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// statePathTestDir points the profile paths at a temp dir and unsets the state file
// override, so the result depends only on the key under test.
func statePathTestDir(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	origDir, origActive, origOverride := DefaultConfigPathDir, ActiveProfileStatePath, ConfigDirOverride
	DefaultConfigPathDir = dir
	ActiveProfileStatePath = filepath.Join(dir, "active_profile.json")
	ConfigDirOverride = dir
	t.Cleanup(func() {
		DefaultConfigPathDir, ActiveProfileStatePath, ConfigDirOverride = origDir, origActive, origOverride
	})

	t.Setenv(envStateFile, "")
	return dir
}

func TestGetStatePathFor(t *testing.T) {
	dir := statePathTestDir(t)
	sm := NewServiceManager("")

	tests := []struct {
		name string
		key  SessionKey
		want string
	}{
		{"default profile", SessionKey{Profile: DefaultProfileName}, filepath.Join(dir, "state.json")},
		{"default profile ignores user", SessionKey{Profile: DefaultProfileName, Username: "alice"}, filepath.Join(dir, "state.json")},
		{"named profile", SessionKey{Profile: "work", Username: "alice"}, filepath.Join(dir, "work.state.json")},
		{"traversal falls back to default", SessionKey{Profile: "../evil", Username: "alice"}, filepath.Join(dir, "state.json")},
		{"empty key falls back to default", SessionKey{}, filepath.Join(dir, "state.json")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, sm.GetStatePathFor(tt.key), "state path of the key")
		})
	}
}

func TestGetStatePathFor_SeparatesUsersWithoutOverride(t *testing.T) {
	dir := statePathTestDir(t)
	ConfigDirOverride = ""
	sm := NewServiceManager("")

	alice := sm.GetStatePathFor(SessionKey{Profile: "work", Username: "alice"})
	bob := sm.GetStatePathFor(SessionKey{Profile: "work", Username: "bob"})

	assert.Equal(t, filepath.Join(dir, "alice", "work.state.json"), alice, "state path of the first user")
	assert.Equal(t, filepath.Join(dir, "bob", "work.state.json"), bob, "state path of the second user")
}

func TestGetStatePathFor_HonoursStateFileOverride(t *testing.T) {
	statePathTestDir(t)
	override := filepath.Join(t.TempDir(), "override.json")
	t.Setenv(envStateFile, override)
	sm := NewServiceManager("")

	assert.Equal(t, override, sm.GetStatePathFor(SessionKey{Profile: "work", Username: "alice"}), "override wins for GetStatePathFor")
	assert.Equal(t, override, sm.GetStatePath(), "override wins for GetStatePath")
}

// The key decides, whatever profile is active, and the active profile is not consulted
// at all: reading it would provision active_profile.json as a side effect.
func TestGetStatePathFor_DoesNotReadActiveProfile(t *testing.T) {
	dir := statePathTestDir(t)
	sm := NewServiceManager("")
	key := SessionKey{Profile: "work", Username: "alice"}
	want := filepath.Join(dir, "work.state.json")

	assert.Equal(t, want, sm.GetStatePathFor(key), "state path without any active profile")
	_, err := os.Stat(ActiveProfileStatePath)
	assert.ErrorIs(t, err, os.ErrNotExist, "GetStatePathFor must not provision the active profile state")

	require.NoError(t, sm.SetActiveProfileState(&ActiveProfileState{ID: "other", Username: "alice"}))
	assert.Equal(t, want, sm.GetStatePathFor(key), "state path while another profile is active")
}

// A session of the active profile and the daemon's own lookups must agree on the file.
func TestGetStatePath_MatchesKeyOfActiveProfile(t *testing.T) {
	dir := statePathTestDir(t)
	origDefault := DefaultConfigPath
	DefaultConfigPath = filepath.Join(dir, "default.json")
	t.Cleanup(func() { DefaultConfigPath = origDefault })
	sm := NewServiceManager("")

	assert.Equal(t, filepath.Join(dir, "state.json"), sm.GetStatePath(), "default profile is active at first")

	active := &ActiveProfileState{ID: "work", Username: "alice"}
	require.NoError(t, sm.SetActiveProfileState(active))

	assert.Equal(t, filepath.Join(dir, "work.state.json"), sm.GetStatePath(), "state path of the active profile")
	assert.Equal(t, sm.GetStatePathFor(active.SessionKey()), sm.GetStatePath(), "both lookups must name one file")
}

func TestStateFileProfiles(t *testing.T) {
	dir := statePathTestDir(t)
	ConfigDirOverride = ""
	sm := NewServiceManager("")

	write := func(parts ...string) string {
		path := filepath.Join(append([]string{dir}, parts...)...)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
		require.NoError(t, os.WriteFile(path, []byte("{}"), 0o600))
		return path
	}

	keys, err := sm.StateFileProfiles()
	require.NoError(t, err)
	assert.Empty(t, keys, "an empty directory holds no state file")

	write("state.json")
	work := write("alice", "work.state.json")
	write("bob", "work.state.json")
	write("bob", "work.json")
	write("bob", "work.prefs.json")
	write("bob", "work.state.json.corrupted.1")
	write("bob", "not.a.stem.state.json")
	write("not.a.user", "home.state.json")
	require.NoError(t, os.Mkdir(filepath.Join(dir, "bob", "dir.state.json"), 0o700))
	require.NoError(t, os.Symlink(work, filepath.Join(dir, "bob", "link.state.json")))

	keys, err = sm.StateFileProfiles()
	require.NoError(t, err)
	assert.Equal(t, []SessionKey{
		{Profile: defaultProfileName},
		{Profile: "work", Username: "alice"},
		{Profile: "work", Username: "bob"},
	}, keys, "only the regular state files of profiles should be found")

	assert.Equal(t, work, sm.GetStatePathFor(keys[1]), "a found key should lead back to its file")
	assert.NoDirExists(t, filepath.Join(dir, "notauser"), "looking must not create a directory")
}

func TestStateFileProfiles_OverrideHoldsAllUsers(t *testing.T) {
	dir := statePathTestDir(t)
	sm := NewServiceManager("")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "work.state.json"), []byte("{}"), 0o600))

	keys, err := sm.StateFileProfiles()
	require.NoError(t, err)
	assert.Equal(t, []SessionKey{{Profile: "work"}}, keys, "the state file should be found in the override directory")
}

// A failure in one place must leave what was found elsewhere usable.
func TestStateFileProfiles_ReportsWhatItCouldNotRead(t *testing.T) {
	dir := statePathTestDir(t)
	blocker := filepath.Join(dir, "file")
	require.NoError(t, os.WriteFile(blocker, nil, 0o600))
	ConfigDirOverride = ""
	DefaultConfigPathDir = blocker

	keys, err := NewServiceManager("").StateFileProfiles()
	assert.Error(t, err, "an unreadable directory must not read as having no state files")
	assert.Empty(t, keys, "nothing could be found")
}
