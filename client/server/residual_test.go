package server

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
// the daemon starts its first session, not only what the active profile recorded.
func TestRestoreResidualAtStart_CleansEveryStoredSession(t *testing.T) {
	f := newResidualFixture(t)
	unlisted := profilemanager.SessionKey{Profile: "unlisted", Username: f.active.Username}
	f.writeState(t, unlisted)
	writeStoredSessions(t, f.other)

	require.NoError(t, f.s.restoreResidualAtStart(f.ctx))

	assert.False(t, f.residual(t, f.other), "a stored session should be cleaned")
	assert.False(t, f.residual(t, f.active), "the active profile should be cleaned even when it is not stored")
	assert.True(t, f.residual(t, unlisted), "a profile that is not stored should stay as it is")
	assert.Equal(t, 1, f.flushes, "the marked routes should be flushed once")
}

// The installation of someone who never enabled concurrent profiles: the same cleanup as
// always, and nothing new on disk.
func TestRestoreResidualAtStart_WithoutSessionsFileLeavesNoTrace(t *testing.T) {
	f := newResidualFixture(t)

	require.NoError(t, f.s.restoreResidualAtStart(f.ctx))

	assert.False(t, f.residual(t, f.active), "the active profile should be cleaned")
	assert.True(t, f.residual(t, f.other), "without a sessions file no other profile is known")
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
	assert.Equal(t, []string{shared}, f.s.residualStatePaths(records), "one file should be cleaned once")
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
				f.s.session.beginRun(f.active)
			},
			want: 1,
		},
		{
			name: "another session runs",
			setup: func(f *residualFixture) {
				f.s.session.beginRun(f.other)
			},
			want: 0,
		},
		{
			name: "another session wants to run but its goroutine is gone",
			setup: func(f *residualFixture) {
				_, giveUp := f.s.session.beginRun(f.other)
				close(giveUp)
			},
			want: 1,
		},
		{
			name: "another session was brought down",
			setup: func(f *residualFixture) {
				f.s.session.beginRun(f.other)
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

// A state file with no sessions file comes from before slots, and the interface and firewall
// names it records are those of slot 0. Its owner has to keep that slot.
func TestOpenSlots_ExistingStateFileMakesActiveProfileOwnerOfSlotZero(t *testing.T) {
	f := newResidualFixture(t)
	base := profilemanager.DefaultConfigPathDir

	slots, err := openSlots(base, f.active, f.statePath(f.active))
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, slots.Close()) })

	records, err := hostcoord.StoredRecords(base)
	require.NoError(t, err)
	require.Len(t, records, 1, "the owner should reach the disk right away")
	assert.Equal(t, f.active, records[0].Key, "the active profile should be the owner")
	assert.Equal(t, hostcoord.Slot(0), records[0].Slot, "the owner should hold slot 0")
	assert.Equal(t, hostcoord.DesiredDown, records[0].Desired, "migration is no request to connect")

	// The next start cleans the file through the stored session.
	require.NoError(t, f.s.restoreResidualAtStart(f.ctx))
	assert.False(t, f.residual(t, f.active), "the owner's state file should be cleaned")
	assert.True(t, f.residual(t, f.other), "a profile that is not stored should stay as it is")
}

func TestOpenSlots_NoStateFileNamesNoOwner(t *testing.T) {
	f := newResidualFixture(t)
	require.NoError(t, os.Remove(f.statePath(f.active)))
	base := profilemanager.DefaultConfigPathDir

	slots, err := openSlots(base, f.active, f.statePath(f.active))
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, slots.Close()) })

	assert.Empty(t, slots.Records(), "without a state file nothing holds slot 0")
	_, err = os.Stat(filepath.Join(base, "sessions.json"))
	assert.ErrorIs(t, err, os.ErrNotExist, "there is nothing to store yet")
}

func TestOpenSlots_StoredSessionsWinOverStateFile(t *testing.T) {
	f := newResidualFixture(t)
	writeStoredSessions(t, f.other)

	slots, err := openSlots(profilemanager.DefaultConfigPathDir, f.active, f.statePath(f.active))
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, slots.Close()) })

	records := slots.Records()
	require.Len(t, records, 1, "the stored file should stay as it is")
	assert.Equal(t, f.other, records[0].Key, "slot 0 should stay with its stored owner")
}

// Whether the state file exists decides who owns slot 0. An answer the daemon did not get must
// not be read as "no": the slot could go to a profile whose names differ from those recorded.
func TestOpenSlots_UnknownStateFileRefuses(t *testing.T) {
	f := newResidualFixture(t)
	blocker := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(blocker, nil, 0o600))
	base := t.TempDir()

	_, err := openSlots(base, f.active, filepath.Join(blocker, "state.json"))
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
