package server

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/hostcoord"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
)

func refusedBecause(cause error) error {
	return fmt.Errorf("%w: %w", internal.ErrSessionRefused, cause)
}

// statusEntry returns what the status says about key, nil when it says nothing.
func (f *gateFixture) statusEntry(t *testing.T, key profilemanager.SessionKey) *proto.SessionStatus {
	t.Helper()
	resp, err := f.s.Status(f.ctx, &proto.StatusRequest{})
	require.NoError(t, err)
	for _, entry := range resp.GetSessions() {
		if entry.GetProfileId() == string(key.Profile) {
			return entry
		}
	}
	return nil
}

func eventsOfKind(ss *session, kind string) []*proto.SystemEvent {
	var events []*proto.SystemEvent
	for _, event := range ss.statusRecorder.GetEventHistory() {
		if event.GetMetadata()[proto.MetadataKindKey] == kind {
			events = append(events, event)
		}
	}
	return events
}

// Section 6: a session that must not run ends its retries at the first refusal, the Up that waited
// for it hears why, and the status keeps saying so until the session gets another chance.
func TestRefusedSessionTellsWhy(t *testing.T) {
	for _, tc := range []struct {
		name     string
		cause    error
		conflict string
		message  string
	}{
		{name: "overlay", cause: internal.ErrOverlayOverlap, conflict: "overlay", message: "overlaps"},
		{name: "interface", cause: hostcoord.ErrInterfaceConflict, conflict: "interface", message: "interface"},
		{name: "port", cause: hostcoord.ErrPortConflict, conflict: "interface", message: "port"},
		{name: "isolation", cause: errors.New("no isolation rules"), message: "no isolation rules"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newGateFixture(t)
			require.NoError(t, f.up(f.first))
			firstClient := f.session(f.first).client()

			f.failRuns[f.second] = refusedBecause(tc.cause)
			err := f.up(f.second)

			requireCode(t, codes.FailedPrecondition, err)
			assert.Contains(t, gstatus.Convert(err).Message(), tc.message, "the Up should say what is wrong")
			second := f.session(f.second)
			awaitRunEndOf(t, second)
			assert.Equal(t, 1, f.runCount(f.second), "a refused session must not be retried")

			entry := f.statusEntry(t, f.second)
			require.NotNil(t, entry, "the status should report the refused session")
			assert.Equal(t, string(internal.StatusIdle), entry.GetStatus(), "a refused session is not trying to connect")
			if tc.conflict == "" {
				assert.Nil(t, entry.Conflict, "a refusal that is no conflict with a session names none")
			} else {
				assert.Equal(t, tc.conflict, entry.GetConflict())
			}
			assert.Same(t, firstClient, f.session(f.first).client(), "the running session must not notice")
			assert.Nil(t, f.statusEntry(t, f.first).Conflict, "the running session has no conflict")

			refused := eventsOfKind(second, "session_refused")
			require.Len(t, refused, 1, "the refusal should be reported once")
			assert.Equal(t, string(f.second.Profile), refused[0].GetProfileId(), "the event should name its profile")
			assert.Equal(t, proto.SystemEvent_ERROR, refused[0].GetSeverity())
			assert.Contains(t, refused[0].GetUserMessage(), tc.message)

			delete(f.failRuns, f.second)
			require.NoError(t, f.up(f.second), "with the conflict gone the session starts")
			assert.Nil(t, f.statusEntry(t, f.second).Conflict, "a new run starts without the old conflict")
		})
	}
}

// Without a waiting Up the status and the event are all there is, and a Down ends the matter.
func TestAsyncUpOfARefusedSessionShowsInTheStatus(t *testing.T) {
	f := newGateFixture(t)
	require.NoError(t, f.up(f.first))

	f.failRuns[f.second] = refusedBecause(internal.ErrOverlayOverlap)
	name, username := string(f.second.Profile), f.second.Username
	_, err := f.s.Up(f.ctx, &proto.UpRequest{ProfileName: &name, Username: &username, Async: true})
	require.NoError(t, err)

	second := f.session(f.second)
	awaitRunEndOf(t, second)
	require.Eventually(t, func() bool {
		return f.statusEntry(t, f.second).GetConflict() == "overlay"
	}, 5*time.Second, 10*time.Millisecond, "the status should show the conflict")

	selector := &proto.SessionSelector{Profile: name, Username: username}
	_, err = f.s.Down(f.ctx, &proto.DownRequest{Session: selector})
	require.NoError(t, err)
	assert.Nil(t, f.statusEntry(t, f.second), "a session taken down has nothing left to report")
}

// A profile that does not connect on its own runs without the retry loop and gets the same answer.
func TestRefusalWithoutAutoConnect(t *testing.T) {
	f := newGateFixture(t)
	require.NoError(t, f.up(f.first))

	disabled := true
	_, err := profilemanager.UpdateOrCreateConfig(profilemanager.ConfigInput{
		ConfigPath:         filepath.Join(profilemanager.DefaultConfigPathDir, string(f.second.Profile)+".json"),
		DisableAutoConnect: &disabled,
	})
	require.NoError(t, err)

	f.failRuns[f.second] = refusedBecause(internal.ErrOverlayOverlap)
	requireCode(t, codes.FailedPrecondition, f.up(f.second))
	assert.Equal(t, "overlay", f.statusEntry(t, f.second).GetConflict())
}

// Q24: what a failed cleanup left in the state file can name the host resources of a running session,
// and a new run would overwrite the record of it. The Up is refused and nothing is touched.
func TestResidualBesideARunningSessionRefusesTheUp(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
	}{
		{name: "residual", content: residualStateJSON},
		{name: "unreadable", content: "{not json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newGateFixture(t)
			require.NoError(t, f.up(f.first))
			firstClient := f.session(f.first).client()

			statePath := f.s.profileManager.GetStatePathFor(f.second)
			require.NoError(t, os.WriteFile(statePath, []byte(tc.content), 0o600))

			flushes := 0
			f.s.flushRoutesFn = func() error {
				flushes++
				return nil
			}

			err := f.up(f.second)

			requireCode(t, codes.FailedPrecondition, err)
			assert.Contains(t, gstatus.Convert(err).Message(), "state", "the Up should name what is in the way")
			assert.Zero(t, f.runCount(f.second), "the session must not run")
			assert.NotContains(t, f.stored(t), f.second, "a refused session must not come back after a restart")
			assert.Zero(t, flushes, "the marked routes may belong to the running session")
			content, readErr := os.ReadFile(statePath)
			require.NoError(t, readErr)
			assert.Equal(t, tc.content, string(content), "the state must stay as it is")
			assert.Same(t, firstClient, f.session(f.first).client(), "the running session must not notice")
			assert.Equal(t, 1, f.runCount(f.first))

			_, err = f.s.Down(f.ctx, &proto.DownRequest{})
			require.NoError(t, err)
			assert.NoError(t, f.up(f.second), "alone on the host the session cleans what it left and starts")
		})
	}
}

// A state file a clean stop left has nothing to undo, and must not stand in the way.
func TestCleanStateFileBesideARunningSessionIsNoObstacle(t *testing.T) {
	f := newGateFixture(t)
	require.NoError(t, f.up(f.first))

	statePath := f.s.profileManager.GetStatePathFor(f.second)
	require.NoError(t, os.WriteFile(statePath, []byte(`{"route_state":null}`), 0o600))

	assert.NoError(t, f.up(f.second))
}

// I1: without the gate an event stays what it was, and the Up the same message.
func TestNoConflictSurfaceWithoutTheGate(t *testing.T) {
	ss := newSession()
	ss.statusRecorder.PublishEvent(proto.SystemEvent_INFO, proto.SystemEvent_SYSTEM, "message", "", nil)
	history := ss.statusRecorder.GetEventHistory()
	require.Len(t, history, 1)
	assert.Empty(t, history[0].GetProfileId(), "an event without the gate names no profile")

	running, giveUp := ss.beginRun(profilemanager.SessionKey{}, nil)
	close(giveUp)
	_ = running
	s := &Server{}
	_, err := s.waitForUp(t.Context(), ss)
	require.Error(t, err)
	assert.Equal(t, "client gave up to connect", err.Error())
}

func awaitRunEndOf(t *testing.T, ss *session) {
	t.Helper()
	_, giveUp := ss.runChans()
	select {
	case <-giveUp:
	case <-time.After(30 * time.Second):
		t.Fatal("the run should end")
	}
}
