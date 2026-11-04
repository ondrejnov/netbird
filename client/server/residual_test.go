package server

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/hostcoord"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/internal/routemanager/systemops"
	"github.com/netbirdio/netbird/client/internal/statemanager"
	"github.com/netbirdio/netbird/client/proto"
)

// An empty route state has nothing to undo on the host, and it is a registered state, so the
// cleanup runs for real and takes it out of the file.
const residualStateJSON = `{"route_state":{"refCountMap":{},"idMap":{}}}`

// residualFixture is a daemon whose active profile and one more profile left state files
// behind, as they do after a crash.
type residualFixture struct {
	s       *Server
	ctx     context.Context
	active  profilemanager.SessionKey
	other   profilemanager.SessionKey
	flushes int
}

func newResidualFixture(t *testing.T) *residualFixture {
	t.Helper()
	t.Setenv("NB_DNS_STATE_FILE", "")

	s, ctx, profName, username, cfgPath := setupServerWithProfile(t)
	f := &residualFixture{
		s:      s,
		ctx:    ctx,
		active: profilemanager.SessionKey{Profile: profilemanager.ID(profName), Username: username},
		other:  profilemanager.SessionKey{Profile: "other-profile", Username: username},
	}
	s.flushRoutesFn = func() error {
		f.flushes++
		return nil
	}

	// Nothing may leave the test host, whichever profile a test ends up connecting.
	for _, path := range []string{cfgPath, filepath.Join(filepath.Dir(cfgPath), "other-profile.json")} {
		_, err := profilemanager.UpdateOrCreateConfig(profilemanager.ConfigInput{
			ConfigPath:    path,
			ManagementURL: "http://127.0.0.1:1",
		})
		require.NoError(t, err)
	}

	f.writeState(t, f.active)
	f.writeState(t, f.other)
	return f
}

func (f *residualFixture) statePath(key profilemanager.SessionKey) string {
	return f.s.profileManager.GetStatePathFor(key)
}

func (f *residualFixture) writeState(t *testing.T, key profilemanager.SessionKey) {
	t.Helper()
	require.NoError(t, os.WriteFile(f.statePath(key), []byte(residualStateJSON), 0o600))
}

func (f *residualFixture) residual(t *testing.T, key profilemanager.SessionKey) bool {
	t.Helper()
	names, err := statemanager.New(f.statePath(key)).GetSavedStateNames()
	require.NoError(t, err)
	return len(names) > 0
}

func writeStoredSessions(t *testing.T, keys ...profilemanager.SessionKey) {
	t.Helper()
	entries := make([]string, 0, len(keys))
	for slot, key := range keys {
		entries = append(entries, fmt.Sprintf(`{"profile":%q,"username":%q,"slot":%d,"desired":"down"}`, key.Profile, key.Username, slot))
	}
	content := `{"version":1,"sessions":[` + strings.Join(entries, ",") + `]}`
	path := filepath.Join(profilemanager.DefaultConfigPathDir, "sessions.json")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
}

// A crash leaves the state of every session that ran. All of it has to be undone by the time
// the daemon starts its first session, not only what the active profile recorded. What runs
// is known only in memory, so a profile is not left out for missing from the sessions file.
func TestRestoreResidualAtStart_CleansEveryProfile(t *testing.T) {
	f := newResidualFixture(t)
	unlisted := profilemanager.SessionKey{Profile: "unlisted", Username: f.active.Username}
	f.writeState(t, unlisted)
	writeStoredSessions(t, f.other)

	require.NoError(t, f.s.restoreResidualAtStart(f.ctx))

	assert.False(t, f.residual(t, f.other), "a stored session should be cleaned")
	assert.False(t, f.residual(t, f.active), "the active profile should be cleaned even when it is not stored")
	assert.False(t, f.residual(t, unlisted), "a profile that is not stored should be cleaned too")
	assert.Equal(t, 1, f.flushes, "the marked routes should be flushed once")
}

// The scenario of a run on another profile than the active one: default ran, work got selected
// without a Down, and the daemon crashed. Only state.json holds what default did to the host,
// and nothing on disk says it ran. The layout is the one of an installation, with a directory
// per user.
func TestRestoreResidualAtStart_CleansProfileDirectoriesOfAllUsers(t *testing.T) {
	f := newResidualFixture(t)
	profilemanager.ConfigDirOverride = ""

	dir := profilemanager.DefaultConfigPathDir
	stateFile := func(parts ...string) string {
		path := filepath.Join(append([]string{dir}, parts...)...)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
		require.NoError(t, os.WriteFile(path, []byte(residualStateJSON), 0o600))
		return path
	}
	hasResidual := func(path string) bool {
		names, err := statemanager.New(path).GetSavedStateNames()
		require.NoError(t, err)
		return len(names) > 0
	}

	cleaned := []string{
		stateFile("state.json"),
		stateFile("alice", "work.state.json"),
		stateFile("bob", "home.state.json"),
	}

	// None of these is the state file of a profile.
	outside := filepath.Join(t.TempDir(), "outside.json")
	require.NoError(t, os.WriteFile(outside, []byte(residualStateJSON), 0o600))
	require.NoError(t, os.Symlink(outside, filepath.Join(dir, "alice", "link.state.json")))
	backup := stateFile("alice", "work.state.json.corrupted.1")
	invalid := stateFile("alice", "not.a.stem.state.json")

	require.NoError(t, f.s.restoreResidualAtStart(f.ctx))

	for _, path := range cleaned {
		assert.False(t, hasResidual(path), "%s should be cleaned", path)
	}
	assert.True(t, hasResidual(outside), "a symlink should not be followed")
	assert.True(t, hasResidual(backup), "a backup of a corrupted file should stay")
	assert.True(t, hasResidual(invalid), "a name that is no profile should stay")
	assert.Equal(t, 1, f.flushes, "the marked routes should be flushed once")

	_, err := os.Stat(filepath.Join(dir, "sessions.json"))
	assert.ErrorIs(t, err, os.ErrNotExist, "the cleanup must not create a sessions file")
}

// One session with the gate off may only end up with a cleaner host (I1): a state file with
// nothing to undo keeps its bytes and its modification time.
func TestRestoreResidualAtStart_LeavesFileWithoutResidualUntouched(t *testing.T) {
	f := newResidualFixture(t)

	contents := map[string]string{
		"empty":        `{}`,
		"cleaned":      `{"route_state":null,"dns_state":null}`,
		"unregistered": `{"some_future_state":{"a": 1}}`,
	}
	past := time.Now().Add(-time.Hour).Truncate(time.Second)
	for name, content := range contents {
		path := f.statePath(profilemanager.SessionKey{Profile: profilemanager.ID(name), Username: f.active.Username})
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
		require.NoError(t, os.Chtimes(path, past, past))
	}

	require.NoError(t, f.s.restoreResidualAtStart(f.ctx))

	for name, content := range contents {
		path := f.statePath(profilemanager.SessionKey{Profile: profilemanager.ID(name), Username: f.active.Username})
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, content, string(data), "%s should keep its content", name)
		info, err := os.Stat(path)
		require.NoError(t, err)
		assert.True(t, info.ModTime().Equal(past), "%s should not be written", name)
	}
}

// The installation of someone who never enabled concurrent profiles: nothing new on disk.
func TestRestoreResidualAtStart_WithoutSessionsFileLeavesNoTrace(t *testing.T) {
	f := newResidualFixture(t)

	require.NoError(t, f.s.restoreResidualAtStart(f.ctx))

	assert.False(t, f.residual(t, f.active), "the active profile should be cleaned")
	assert.False(t, f.residual(t, f.other), "a profile found on disk should be cleaned without a sessions file")
	assert.Equal(t, 1, f.flushes, "the marked routes should be flushed as before")

	for _, name := range []string{"sessions.json", "sessions.lock"} {
		_, err := os.Stat(filepath.Join(profilemanager.DefaultConfigPathDir, name))
		assert.ErrorIs(t, err, os.ErrNotExist, "%s must not be created", name)
	}
}

// A file the daemon cannot read must not stop the cleanup it can still do.
func TestRestoreResidualAtStart_CorruptSessionsFileStillCleansActive(t *testing.T) {
	f := newResidualFixture(t)
	path := filepath.Join(profilemanager.DefaultConfigPathDir, "sessions.json")
	require.NoError(t, os.WriteFile(path, []byte("{"), 0o600))

	err := f.s.restoreResidualAtStart(f.ctx)
	assert.ErrorIs(t, err, hostcoord.ErrCorruptSessions)

	assert.False(t, f.residual(t, f.active), "the active profile should still be cleaned")
	assert.Equal(t, 1, f.flushes, "the marked routes should still be flushed")

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "{", string(data), "a corrupt file should stay for whoever can repair it")
}

// A failure in one session's file is that session's problem, the next one still gets cleaned.
func TestRestoreResidualAtStart_FailureDoesNotStopOthers(t *testing.T) {
	f := newResidualFixture(t)
	broken := profilemanager.SessionKey{Profile: "broken", Username: f.active.Username}
	// A directory in place of the file cannot be read.
	require.NoError(t, os.Mkdir(f.statePath(broken), 0o700))
	writeStoredSessions(t, broken, f.other)

	assert.Error(t, f.s.restoreResidualAtStart(f.ctx), "the failure should be reported")

	assert.False(t, f.residual(t, f.other), "a session after the failed one should be cleaned")
	assert.False(t, f.residual(t, f.active), "the active profile should be cleaned")
	assert.Equal(t, 1, f.flushes, "the marked routes should be flushed")
}

func TestResidualStatePaths_SharedFileOnce(t *testing.T) {
	f := newResidualFixture(t)
	shared := filepath.Join(t.TempDir(), "shared.json")
	t.Setenv("NB_DNS_STATE_FILE", shared)

	records := []hostcoord.SlotRecord{{Key: f.other}, {Key: f.active, Slot: 1}}
	assert.Equal(t, []string{shared}, f.s.residualStatePaths(records, []profilemanager.SessionKey{f.other}), "one file should be cleaned once")
}

// The whole of Start: everything is clean before the first session gets to run.
func TestStart_CleansStoredSessionsBeforeTheFirstRun(t *testing.T) {
	f := newResidualFixture(t)
	writeStoredSessions(t, f.other)

	rootCtx, cancel := context.WithCancel(f.ctx)
	f.s.rootCtx = rootCtx
	stopRunAtCleanup(t, f.s, cancel)

	var runningAtFlush, otherCleanAtFlush bool
	f.s.flushRoutesFn = func() error {
		runningAtFlush = f.s.session.isClientRunning() || f.s.session.hasActCancel()
		otherCleanAtFlush = !f.residual(t, f.other)
		return nil
	}

	require.NoError(t, f.s.Start())

	assert.False(t, runningAtFlush, "the cleanup should finish before a session starts")
	assert.True(t, otherCleanAtFlush, "the state files should be clean before the flush")
	assert.False(t, f.residual(t, f.active), "the active profile should be clean")
	assert.True(t, f.s.session.isClientRunning(), "the session should start afterwards")
}

// Up with a profile runs the session of that profile, so its file is the one to clean. The
// file of the profile that was active until now could belong to a running session.
func TestUp_CleansOnlyTheStateFileOfItsProfile(t *testing.T) {
	f := newResidualFixture(t)
	f.s.session.setConfig(f.active, &profilemanager.Config{})
	rootCtx, cancel := context.WithCancel(f.ctx)
	f.s.rootCtx = rootCtx
	stopRunAtCleanup(t, f.s, cancel)

	name, username := f.other.Profile.String(), f.other.Username
	_, err := f.s.Up(f.ctx, &proto.UpRequest{ProfileName: &name, Username: &username, Async: true})
	require.NoError(t, err)

	assert.False(t, f.residual(t, f.other), "the profile being started should be cleaned")
	assert.True(t, f.residual(t, f.active), "the previously active profile is not this session's to clean")
	assert.Equal(t, 1, f.flushes, "no other session runs, so the flush should stay")
}

func TestLogin_CleansOnlyTheStateFileOfItsProfile(t *testing.T) {
	f := newResidualFixture(t)

	active, err := f.s.profileManager.GetActiveProfileState()
	require.NoError(t, err)

	name, username := f.other.Profile.String(), f.other.Username
	_, resolved, switched, err := f.s.authorizeAndPrepareLogin(f.ctx, &proto.LoginRequest{ProfileName: &name, Username: &username}, active)
	require.NoError(t, err)
	require.True(t, switched, "the login should have switched the profile")
	require.Equal(t, f.other, resolved.SessionKey(), "the login should target the other profile")

	assert.False(t, f.residual(t, f.other), "the profile logging in should be cleaned")
	assert.True(t, f.residual(t, f.active), "the previously active profile is not this login's to clean")
	assert.Equal(t, 1, f.flushes, "no other session runs, so the flush should stay")
}

func (f *residualFixture) login(t *testing.T) {
	t.Helper()
	active, err := f.s.profileManager.GetActiveProfileState()
	require.NoError(t, err)
	_, _, _, err = f.s.authorizeAndPrepareLogin(f.ctx, &proto.LoginRequest{}, active)
	require.NoError(t, err)
}

// The check of what runs and the cleanup are one step only under the mutex Up and the MDM
// restart hold when they start a run.
func TestLogin_CleansUnderTheServerMutex(t *testing.T) {
	f := newResidualFixture(t)

	var mutexHeld bool
	f.s.flushRoutesFn = func() error {
		mutexHeld = !f.s.mutex.TryLock()
		if !mutexHeld {
			f.s.mutex.Unlock()
		}
		return nil
	}

	f.login(t)

	assert.True(t, mutexHeld, "the cleanup should run under the server mutex")
}

// Login gives up the mutex after cancelling the current attempt, and a run can start in that
// gap. The cancel below stands in for it, since it runs right where the mutex is given up.
func TestLogin_RunStartedAfterTheCancel(t *testing.T) {
	tests := []struct {
		name      string
		newRun    func(f *residualFixture) profilemanager.SessionKey
		wantClean bool
		wantFlush int
	}{
		{
			name:      "new run of the same profile owns the state file and the routes",
			newRun:    func(f *residualFixture) profilemanager.SessionKey { return f.active },
			wantClean: false,
			wantFlush: 0,
		},
		{
			name:      "new run of another profile owns only the routes",
			newRun:    func(f *residualFixture) profilemanager.SessionKey { return f.other },
			wantClean: true,
			wantFlush: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newResidualFixture(t)
			f.s.session.beginRun(f.active, nil)
			f.s.session.setActCancel(func() { f.s.session.beginRun(tt.newRun(f), nil) })

			f.login(t)

			assert.Equal(t, tt.wantClean, !f.residual(t, f.active), "whether the state file of the profile got cleaned")
			assert.Equal(t, tt.wantFlush, f.flushes, "number of flushes")
		})
	}
}

// The run Login itself cancelled may still be on its way out. That is no new run: what it
// leaves in the file is what Login is there to clean.
func TestLogin_CleansAfterItsOwnCancelledRun(t *testing.T) {
	f := newResidualFixture(t)
	f.s.session.beginRun(f.active, nil)
	f.s.session.setActCancel(func() {})

	f.login(t)

	assert.False(t, f.residual(t, f.active), "the state file of the cancelled run should be cleaned")
	assert.Equal(t, 1, f.flushes, "no other session runs, so the flush should stay")
}

// A policy change must not bring back a profile that is gone: it would get a new identity and
// the default Management URL, and start connecting there. Only the run has to end.
func TestMDMRestart_RunningProfileWithoutConfigEndsTheRun(t *testing.T) {
	f := newResidualFixture(t)
	removed := profilemanager.SessionKey{Profile: "removed-profile", Username: f.active.Username}
	cfgPath, err := (&profilemanager.ActiveProfileState{ID: removed.Profile, Username: removed.Username}).FilePath()
	require.NoError(t, err)

	// Should a run start anyway, it ends before it reaches any network.
	rootCtx, cancel := context.WithCancel(f.ctx)
	cancel()
	f.s.rootCtx = rootCtx
	stopRunAtCleanup(t, f.s, cancel)

	_, giveUp := f.s.session.beginRun(removed, nil)
	f.s.session.setActCancel(func() { close(giveUp) })

	assert.Error(t, f.s.onMDMPolicyChange(nil, nil), "the restart should be refused")

	assert.NoFileExists(t, cfgPath, "the removed profile should not get a new config")
	assert.False(t, f.s.session.isClientRunning(), "the run should count as ended")
	_, running := f.s.session.runningKey()
	assert.False(t, running, "nothing should run")
}

func TestRestoreOwnResidual_Flush(t *testing.T) {
	tests := []struct {
		name  string
		setup func(f *residualFixture)
		want  int
	}{
		{
			name:  "no session runs",
			setup: func(*residualFixture) {},
			want:  1,
		},
		{
			name: "own session is the one running",
			setup: func(f *residualFixture) {
				f.s.session.beginRun(f.active, nil)
			},
			want: 1,
		},
		{
			name: "another session runs",
			setup: func(f *residualFixture) {
				f.s.session.beginRun(f.other, nil)
			},
			want: 0,
		},
		{
			name: "another session wants to run but its goroutine is gone",
			setup: func(f *residualFixture) {
				_, giveUp := f.s.session.beginRun(f.other, nil)
				close(giveUp)
			},
			want: 1,
		},
		{
			name: "another session was brought down",
			setup: func(f *residualFixture) {
				f.s.session.beginRun(f.other, nil)
				f.s.session.markClientDown()
			},
			want: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newResidualFixture(t)
			tt.setup(f)

			require.NoError(t, f.s.restoreOwnResidual(f.ctx, f.active))

			assert.False(t, f.residual(t, f.active), "the own state file should be cleaned")
			assert.True(t, f.residual(t, f.other), "the state file of another profile should stay")
			assert.Equal(t, tt.want, f.flushes, "number of flushes")
		})
	}
}

func (f *residualFixture) removeState(t *testing.T, keys ...profilemanager.SessionKey) {
	t.Helper()
	for _, key := range keys {
		require.NoError(t, os.Remove(f.statePath(key)))
	}
}

func (f *residualFixture) writeDefaultState(t *testing.T) {
	t.Helper()
	path := filepath.Join(profilemanager.DefaultConfigPathDir, "state.json")
	require.NoError(t, os.WriteFile(path, []byte(residualStateJSON), 0o600))
}

// slotZeroOwner opens the slots and returns what got stored for slot 0.
func (f *residualFixture) slotZeroOwner(t *testing.T) hostcoord.SlotRecord {
	t.Helper()
	base := profilemanager.DefaultConfigPathDir
	slots, err := f.s.openSlots(base, f.active)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, slots.Close()) })

	records, err := hostcoord.StoredRecords(base)
	require.NoError(t, err)
	require.Len(t, records, 1, "the owner should reach the disk right away")
	assert.Equal(t, hostcoord.Slot(0), records[0].Slot, "the owner should hold slot 0")
	assert.Equal(t, hostcoord.DesiredDown, records[0].Desired, "migration is no request to connect")
	return records[0]
}

// A state file with no sessions file comes from before slots, and the interface and firewall
// names it records are those of slot 0. Its owner has to keep that slot.
func TestOpenSlots_ActiveStateFileMakesActiveProfileOwner(t *testing.T) {
	f := newResidualFixture(t)
	f.removeState(t, f.other)

	assert.Equal(t, f.active, f.slotZeroOwner(t).Key, "the active profile should be the owner")

	// The next start cleans the file through the stored session.
	require.NoError(t, f.s.restoreResidualAtStart(f.ctx))
	assert.False(t, f.residual(t, f.active), "the owner's state file should be cleaned")
}

// The profile that left the only state file is the one using the names of slot 0, whichever
// profile happens to be selected.
func TestOpenSlots_OnlyStateFileOfAnotherProfileMakesItOwner(t *testing.T) {
	f := newResidualFixture(t)
	f.removeState(t, f.active)

	assert.Equal(t, f.other.Profile, f.slotZeroOwner(t).Key.Profile, "the profile with the state file should be the owner")
}

func TestOpenSlots_OnlyDefaultStateFileMakesDefaultOwner(t *testing.T) {
	f := newResidualFixture(t)
	f.removeState(t, f.active, f.other)
	f.writeDefaultState(t)

	owner := f.slotZeroOwner(t)
	assert.Equal(t, profilemanager.ID(profilemanager.DefaultProfileName), owner.Key.Profile, "default should be the owner")
}

// The default profile is shared by every user, so the active state can carry a username the
// state file does not.
func TestOpenSlots_ActiveDefaultProfileKeepsItsKey(t *testing.T) {
	f := newResidualFixture(t)
	f.removeState(t, f.active, f.other)
	f.writeDefaultState(t)
	f.active = profilemanager.SessionKey{Profile: profilemanager.DefaultProfileName, Username: f.active.Username}

	assert.Equal(t, f.active, f.slotZeroOwner(t).Key, "the key of the active profile should be stored")
}

func TestOpenSlots_SeveralStateFilesMakeActiveProfileOwner(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, f *residualFixture)
	}{
		{
			name:  "the active profile has one of them",
			setup: func(*testing.T, *residualFixture) {},
		},
		{
			name: "the active profile has none",
			setup: func(t *testing.T, f *residualFixture) {
				f.removeState(t, f.active)
				f.writeDefaultState(t)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newResidualFixture(t)
			tt.setup(t, f)

			assert.Equal(t, f.active, f.slotZeroOwner(t).Key, "the active profile should be the owner")
		})
	}
}

// The start cleans what the files record and keeps the files, so the owner stays the same
// whether the slots open before or after the cleanup.
func TestOpenSlots_OwnerDoesNotDependOnTheCleanup(t *testing.T) {
	f := newResidualFixture(t)
	f.removeState(t, f.active)

	require.NoError(t, f.s.restoreResidualAtStart(f.ctx))

	assert.Equal(t, f.other.Profile, f.slotZeroOwner(t).Key.Profile, "the cleaned file should still name the owner")
}

func TestOpenSlots_NoStateFileNamesNoOwner(t *testing.T) {
	f := newResidualFixture(t)
	f.removeState(t, f.active, f.other)
	base := profilemanager.DefaultConfigPathDir

	slots, err := f.s.openSlots(base, f.active)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, slots.Close()) })

	assert.Empty(t, slots.Records(), "without a state file nothing holds slot 0")
	_, err = os.Stat(filepath.Join(base, "sessions.json"))
	assert.ErrorIs(t, err, os.ErrNotExist, "there is nothing to store yet")
}

func TestOpenSlots_StoredSessionsWinOverStateFile(t *testing.T) {
	f := newResidualFixture(t)
	writeStoredSessions(t, f.other)

	slots, err := f.s.openSlots(profilemanager.DefaultConfigPathDir, f.active)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, slots.Close()) })

	records := slots.Records()
	require.Len(t, records, 1, "the stored file should stay as it is")
	assert.Equal(t, f.other, records[0].Key, "slot 0 should stay with its stored owner")
}

// Whether a state file exists decides who owns slot 0. An answer the daemon did not get must
// not be read as "no": the slot could go to a profile whose names differ from those recorded.
func TestOpenSlots_UnknownStateFileRefuses(t *testing.T) {
	f := newResidualFixture(t)
	blocker := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(blocker, nil, 0o600))
	profilemanager.DefaultConfigPathDir = blocker
	base := t.TempDir()

	_, err := f.s.openSlots(base, f.active)
	assert.Error(t, err)

	_, err = os.Stat(filepath.Join(base, "sessions.json"))
	assert.ErrorIs(t, err, os.ErrNotExist, "a refused migration must store nothing")
}

// A real state of the route manager goes through the same path as the fixture's raw JSON.
func TestCleanStateFile_RemovesRegisteredState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	mgr := statemanager.New(path)
	mgr.RegisterState(&systemops.ShutdownState{})
	require.NoError(t, mgr.UpdateState(&systemops.ShutdownState{}))
	require.NoError(t, mgr.PersistState(context.Background()))

	require.NoError(t, cleanStateFile(context.Background(), path))

	names, err := statemanager.New(path).GetSavedStateNames()
	require.NoError(t, err)
	assert.Empty(t, names, "the state should be gone from the file")
}
