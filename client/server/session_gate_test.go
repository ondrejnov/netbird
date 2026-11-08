package server

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/iface/netstack"
	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/hostcoord"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/internal/statemanager"
	"github.com/netbirdio/netbird/client/proto"
)

// gateFixture is a daemon with the feature gate on and three profiles. A run is a stand-in that
// connects at once and ends with its context, so the tests see what the daemon decides about
// its sessions without real engines.
type gateFixture struct {
	s        *Server
	ctx      context.Context
	first    profilemanager.SessionKey
	second   profilemanager.SessionKey
	third    profilemanager.SessionKey
	mu       sync.Mutex
	runs     map[profilemanager.SessionKey]int
	failRuns map[profilemanager.SessionKey]error
}

type gateOption func(*gateFixture)

func newGateFixture(t *testing.T, opts ...gateOption) *gateFixture {
	t.Helper()
	f := prepareGateFixture(t, opts...)
	// A stored session that wants to stay down, so that the first start with the gate does not
	// connect the active profile on its own.
	writeDesiredSessions(t, map[profilemanager.SessionKey]hostcoord.DesiredState{f.first: hostcoord.DesiredDown})
	require.NoError(t, f.s.Start())
	return f
}

// prepareGateFixture stops short of the start, for a test that lays out the disk first.
func prepareGateFixture(t *testing.T, opts ...gateOption) *gateFixture {
	t.Helper()
	if !slices.Contains(concurrentProfilesOSes, runtime.GOOS) {
		// The gate refuses to start elsewhere (5.5), so nothing below it can run there.
		// TestGate_StartIsRefusedOnUnsupportedOS checks the refusal on those platforms.
		t.Skipf("concurrent profiles run only on %v", concurrentProfilesOSes)
	}
	return prepareGateServer(t, opts...)
}

// prepareGateServer is prepareGateFixture on any platform.
func prepareGateServer(t *testing.T, opts ...gateOption) *gateFixture {
	t.Helper()
	t.Setenv("NB_DNS_STATE_FILE", "")
	t.Setenv(netstack.EnvUseNetstackMode, "false")

	s, ctx, profName, username, cfgPath := setupServerWithProfile(t)
	rootCtx, cancelRoot := context.WithCancel(ctx)
	s.rootCtx = rootCtx
	s.sessionSet = newSessionSet(true)
	s.localMetrics = s.newLocalMetrics(rootCtx)

	f := &gateFixture{
		s:        s,
		ctx:      ctx,
		first:    profilemanager.SessionKey{Profile: profilemanager.ID(profName), Username: username},
		second:   profilemanager.SessionKey{Profile: "second-profile", Username: username},
		third:    profilemanager.SessionKey{Profile: "third-profile", Username: username},
		runs:     make(map[profilemanager.SessionKey]int),
		failRuns: make(map[profilemanager.SessionKey]error),
	}
	s.flushRoutesFn = func() error { return nil }
	// These tests run without a harness, next to whatever interfaces the host has.
	s.removeLinksFn = func([]hostcoord.SlotRecord) error { return nil }
	s.verifyLinksFn = func([]hostcoord.SlotRecord) error { return nil }
	s.advancedRoutingFn = func() bool { return true }
	s.connectFn = f.connect

	dir := filepath.Dir(cfgPath)
	for _, path := range []string{cfgPath, filepath.Join(dir, "second-profile.json"), filepath.Join(dir, "third-profile.json")} {
		_, err := profilemanager.UpdateOrCreateConfig(profilemanager.ConfigInput{
			ConfigPath:    path,
			ManagementURL: "http://127.0.0.1:1",
		})
		require.NoError(t, err)
	}

	for _, opt := range opts {
		opt(f)
	}

	t.Cleanup(func() {
		cancelRoot()
		f.awaitRunsEnded(t)
	})
	return f
}

func (f *gateFixture) connect(ctx context.Context, ss *session, key profilemanager.SessionKey, _ *profilemanager.Config, runningChan chan struct{}) error {
	f.mu.Lock()
	f.runs[key]++
	failure := f.failRuns[key]
	f.mu.Unlock()
	if failure != nil {
		return failure
	}

	ss.setClient(newDummyConnectClient(ctx))
	ss.state.Set(internal.StatusConnected)
	close(runningChan)
	<-ctx.Done()
	return nil
}

func (f *gateFixture) awaitRunsEnded(t *testing.T) {
	t.Helper()
	sessions := []*session{}
	f.s.mutex.Lock()
	for _, ss := range f.s.sessions {
		sessions = append(sessions, ss)
	}
	f.s.mutex.Unlock()
	for _, ss := range sessions {
		_, giveUp := ss.runChans()
		if giveUp == nil {
			continue
		}
		select {
		case <-giveUp:
		case <-time.After(30 * time.Second):
			t.Error("a run did not end with the root context")
		}
	}
}

func (f *gateFixture) runCount(key profilemanager.SessionKey) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.runs[key]
}

func (f *gateFixture) session(key profilemanager.SessionKey) *session {
	f.s.mutex.Lock()
	defer f.s.mutex.Unlock()
	return f.s.sessions[key]
}

func (f *gateFixture) up(key profilemanager.SessionKey) error {
	name, username := string(key.Profile), key.Username
	_, err := f.s.Up(f.ctx, &proto.UpRequest{ProfileName: &name, Username: &username})
	return err
}

func (f *gateFixture) focus(t *testing.T, key profilemanager.SessionKey) {
	t.Helper()
	name, username := string(key.Profile), key.Username
	_, err := f.s.SwitchProfile(f.ctx, &proto.SwitchProfileRequest{ProfileName: &name, Username: &username})
	require.NoError(t, err)
}

func (f *gateFixture) stored(t *testing.T) map[profilemanager.SessionKey]hostcoord.DesiredState {
	t.Helper()
	records, err := hostcoord.StoredRecords(profilemanager.DefaultConfigPathDir)
	require.NoError(t, err)
	desired := make(map[profilemanager.SessionKey]hostcoord.DesiredState, len(records))
	for _, record := range records {
		desired[record.Key] = record.Desired
	}
	return desired
}

func writeDesiredSessions(t *testing.T, sessions map[profilemanager.SessionKey]hostcoord.DesiredState) {
	t.Helper()
	slots, err := hostcoord.NewSlots(profilemanager.DefaultConfigPathDir)
	require.NoError(t, err)
	for key, desired := range sessions {
		_, err := slots.Ensure(key)
		require.NoError(t, err)
		require.NoError(t, slots.SetDesired(key, desired))
	}
	require.NoError(t, slots.Close())
}

func requireCode(t *testing.T, want codes.Code, err error) {
	t.Helper()
	require.Error(t, err)
	require.Equal(t, want, gstatus.Code(err), "unexpected status: %v", err)
}

func TestConcurrentProfilesPlatform(t *testing.T) {
	assert.NoError(t, checkConcurrentProfilesPlatform("linux"))
	assert.NoError(t, checkConcurrentProfilesPlatform("windows"))
	assert.NoError(t, checkConcurrentProfilesPlatform("darwin"))

	for _, goos := range []string{"freebsd", "android", "ios"} {
		err := checkConcurrentProfilesPlatform(goos)
		require.Error(t, err, "the gate must refuse %s", goos)
		assert.Contains(t, err.Error(), "only on Linux, Windows and macOS", "the operator should be told why")
		assert.Contains(t, err.Error(), goos)
		assert.Contains(t, err.Error(), "--enable-concurrent-profiles", "the operator should be told what to change")
	}
}

// Off Linux, Windows and macOS the service with the gate does not start, and the refusal leaves the disk and the host
// as they were: no sessions file, no slots, no session.
func TestGate_StartIsRefusedOnUnsupportedOS(t *testing.T) {
	if slices.Contains(concurrentProfilesOSes, runtime.GOOS) {
		t.Skip("here the gate starts, which every other gate test covers")
	}
	f := prepareGateServer(t)
	dir := profilemanager.DefaultConfigPathDir

	err := f.s.Start()
	require.Error(t, err, "the gate must refuse %s", runtime.GOOS)
	assert.Contains(t, err.Error(), "only on Linux, Windows and macOS", "the operator should be told why")
	assert.Contains(t, err.Error(), "--enable-concurrent-profiles", "the operator should be told what to change")

	_, statErr := os.Stat(filepath.Join(dir, "sessions.json"))
	assert.ErrorIs(t, statErr, os.ErrNotExist, "a refused start must store no sessions")
	f.s.mutex.Lock()
	defer f.s.mutex.Unlock()
	assert.Nil(t, f.s.slots, "a refused start must open no slots")
	assert.Empty(t, f.s.sessions, "a refused start must start no session")
	assert.Zero(t, f.runCount(f.first), "a refused start must connect nothing")
}

func TestGetFeatures_ReportsTheGateAndTheLimit(t *testing.T) {
	f := newGateFixture(t)
	features, err := f.s.GetFeatures(f.ctx, &proto.GetFeaturesRequest{})
	require.NoError(t, err)
	assert.True(t, features.GetConcurrentProfilesEnabled())
	assert.Equal(t, defaultMaxSessions, features.GetMaxSessions())

	off := New(f.ctx, "console", "", false, false, false, false, false)
	features, err = off.GetFeatures(f.ctx, &proto.GetFeaturesRequest{})
	require.NoError(t, err)
	assert.False(t, features.GetConcurrentProfilesEnabled())

	limited := New(f.ctx, "console", "", false, false, false, false, true, WithMaxSessions(0))
	features, err = limited.GetFeatures(f.ctx, &proto.GetFeaturesRequest{})
	require.NoError(t, err)
	assert.Zero(t, features.GetMaxSessions(), "a limit of 0 means no limit")
}

// The scenario the gate exists for: an Up of another profile adds a session, and the session
// that ran stays exactly as it was.
func TestGate_UpStartsAnotherSessionAndLeavesTheOthers(t *testing.T) {
	f := newGateFixture(t)
	require.NoError(t, f.up(f.first))
	firstClient := f.session(f.first).client()
	_, firstGiveUp := f.session(f.first).runChans()
	require.NotNil(t, firstClient)

	require.NoError(t, f.up(f.second))

	assert.Equal(t, 1, f.runCount(f.first), "the first session must not be restarted")
	assert.Equal(t, 1, f.runCount(f.second))
	assert.Same(t, firstClient, f.session(f.first).client(), "the first session must keep its client")
	select {
	case <-firstGiveUp:
		t.Fatal("the run of the first session ended")
	default:
	}
	assert.Equal(t, internal.StatusConnected, f.session(f.first).state.CurrentStatus())
	assert.Equal(t, internal.StatusConnected, f.session(f.second).state.CurrentStatus())
	assert.Equal(t, f.first, f.s.focusedSession().key, "an Up does not move the focus")

	active, err := f.s.profileManager.GetActiveProfileState()
	require.NoError(t, err)
	assert.Equal(t, f.first, active.SessionKey(), "an Up does not change the active profile")

	assert.Equal(t, hostcoord.DesiredUp, f.stored(t)[f.first])
	assert.Equal(t, hostcoord.DesiredUp, f.stored(t)[f.second])

	// An Up without a profile is for the focused session, and joins its run.
	_, err = f.s.Up(f.ctx, &proto.UpRequest{})
	require.NoError(t, err)
	assert.Equal(t, 1, f.runCount(f.first), "an Up of a running session joins its run")
}

// A session the limit refuses has nothing done on its behalf.
func TestGate_RefusedSessionLeavesEverythingAlone(t *testing.T) {
	f := newGateFixture(t, func(f *gateFixture) { f.s.maxSessions = 1 })
	require.NoError(t, f.up(f.first))
	firstClient := f.session(f.first).client()

	flushes := 0
	f.s.flushRoutesFn = func() error {
		flushes++
		return nil
	}
	statePath := f.s.profileManager.GetStatePathFor(f.second)
	require.NoError(t, os.WriteFile(statePath, []byte(residualStateJSON), 0o600))

	err := f.up(f.second)

	requireCode(t, codes.ResourceExhausted, err)
	assert.Zero(t, f.runCount(f.second), "the second session must not run")
	assert.NotContains(t, f.stored(t), f.second, "a refused session must not come back after a restart")
	assert.Zero(t, flushes, "a refused session must not touch the host")
	content, err := os.ReadFile(statePath)
	require.NoError(t, err)
	assert.Equal(t, residualStateJSON, string(content), "the state of the refused session must stay")

	assert.Same(t, firstClient, f.session(f.first).client(), "the running session must not notice")
	assert.Equal(t, 1, f.runCount(f.first))

	_, err = f.s.Down(f.ctx, &proto.DownRequest{})
	require.NoError(t, err)
	assert.NoError(t, f.up(f.second), "with nothing running the session is the only one")
}

// Management can drive the updater, which acts on the whole machine, only through the focused session.
func TestGate_OnlyTheFocusedSessionControlsUpdates(t *testing.T) {
	f := newGateFixture(t)
	require.NoError(t, f.up(f.first))
	require.NoError(t, f.up(f.second))

	assert.True(t, f.s.controlsUpdates(f.session(f.first)), "the focused session controls the updates")
	assert.False(t, f.s.controlsUpdates(f.session(f.second)), "another session gets no update manager")

	f.focus(t, f.second)
	assert.True(t, f.s.controlsUpdates(f.session(f.second)), "the next run of the new focus controls them")
	assert.False(t, f.s.controlsUpdates(f.session(f.first)))

	f.s.sessionSet = newSessionSet(false)
	assert.True(t, f.s.controlsUpdates(f.s.focusedSession()), "without the gate nothing changes")
}

func TestGate_SessionLimit(t *testing.T) {
	t.Run("the limit refuses the next session", func(t *testing.T) {
		f := newGateFixture(t, func(f *gateFixture) { f.s.maxSessions = 2 })
		require.NoError(t, f.up(f.first))
		require.NoError(t, f.up(f.second))

		requireCode(t, codes.ResourceExhausted, f.up(f.third))
		assert.Zero(t, f.runCount(f.third))

		_, err := f.s.Down(f.ctx, &proto.DownRequest{})
		require.NoError(t, err)
		assert.NoError(t, f.up(f.third), "a session that went down frees its place")
	})

	t.Run("the limit comes before the wiring", func(t *testing.T) {
		f := newGateFixture(t, func(f *gateFixture) { f.s.maxSessions = 1 })
		require.NoError(t, f.up(f.first))
		requireCode(t, codes.ResourceExhausted, f.up(f.second))
	})

	t.Run("a limit of 0 means no limit", func(t *testing.T) {
		f := newGateFixture(t, func(f *gateFixture) { f.s.maxSessions = 0 })
		require.NoError(t, f.up(f.first))
		require.NoError(t, f.up(f.second))
		require.NoError(t, f.up(f.third))
		assert.Equal(t, 1, f.runCount(f.third))
	})
}

// A session in teardown still has its interface and rules on the host. It has to count, or the
// next session would come up on the same names.
func TestGate_SessionInTeardownStillHoldsTheHost(t *testing.T) {
	f := newGateFixture(t, func(f *gateFixture) { f.s.maxSessions = 1 })
	require.NoError(t, f.up(f.first))

	ss := f.session(f.first)
	_, giveUp := ss.beginRun(f.first, nil)
	assert.True(t, ss.holdsHost())
	ss.markClientDown()
	assert.True(t, ss.holdsHost(), "the goroutine is alive, whatever the intent says")
	requireCode(t, codes.ResourceExhausted, f.up(f.second))

	close(giveUp)
	assert.False(t, ss.holdsHost(), "with the goroutine gone nothing is left")
}

// The real client path with the gate on: the run reaches a client of its session, and the Down
// ends it. Nothing listens on the Management address, so no engine comes up.
func TestGate_RealClientRunStopsWithDown(t *testing.T) {
	f := newGateFixture(t)
	f.s.connectFn = nil

	name, username := string(f.first.Profile), f.first.Username
	_, err := f.s.Up(f.ctx, &proto.UpRequest{ProfileName: &name, Username: &username, Async: true})
	require.NoError(t, err)

	ss := f.session(f.first)
	require.Eventually(t, func() bool { return ss.client() != nil }, 5*time.Second, 10*time.Millisecond,
		"the run should publish its client on its own session")

	_, err = f.s.Down(f.ctx, &proto.DownRequest{})
	require.NoError(t, err)
	assert.Nil(t, ss.client())
	assert.False(t, ss.holdsHost(), "the run should be over")
	assert.Equal(t, internal.StatusIdle, ss.state.CurrentStatus())
}

func TestGate_SwitchProfileMovesOnlyTheFocus(t *testing.T) {
	f := newGateFixture(t)
	require.NoError(t, f.up(f.first))
	first := f.session(f.first)
	firstClient := first.client()
	_, giveUp := first.runChans()
	flow := &stubOAuthFlow{}
	first.swapOAuthFlow(oauthAuthFlow{flow: flow})

	f.focus(t, f.second)

	assert.Equal(t, f.second, f.s.focusedSession().key)
	active, err := f.s.profileManager.GetActiveProfileState()
	require.NoError(t, err)
	assert.Equal(t, f.second, active.SessionKey(), "the focus follows the active profile file")

	assert.Same(t, firstClient, first.client(), "the run must go on")
	assert.True(t, first.isClientRunning())
	select {
	case <-giveUp:
		t.Fatal("the run of the session that lost the focus ended")
	default:
	}
	assert.Same(t, flow, first.oauthFlow().flow, "a pending login of another session must survive")

	status, err := f.s.Status(f.ctx, &proto.StatusRequest{})
	require.NoError(t, err)
	assert.Equal(t, string(internal.StatusIdle), status.GetStatus(), "the top level fields describe the focused session")

	f.focus(t, f.first)
	assert.Same(t, first, f.s.focusedSession(), "a profile keeps its session")
	status, err = f.s.Status(f.ctx, &proto.StatusRequest{})
	require.NoError(t, err)
	assert.Equal(t, string(internal.StatusConnected), status.GetStatus())
}

func TestGate_SwitchProfileHonoursTheKillSwitch(t *testing.T) {
	f := newGateFixture(t)
	f.s.profilesDisabled = true

	name, username := string(f.second.Profile), f.second.Username
	_, err := f.s.SwitchProfile(f.ctx, &proto.SwitchProfileRequest{ProfileName: &name, Username: &username})
	requireCode(t, codes.Unavailable, err)
	assert.Equal(t, f.first, f.s.focusedSession().key)

	requireCode(t, codes.Unavailable, f.up(f.second))
	assert.Zero(t, f.runCount(f.second))
}

func TestGate_DownTargetsTheFocusedSession(t *testing.T) {
	f := newGateFixture(t)
	require.NoError(t, f.up(f.first))
	require.NoError(t, f.up(f.second))
	second := f.session(f.second)
	secondClient := second.client()

	_, err := f.s.Down(f.ctx, &proto.DownRequest{})
	require.NoError(t, err)

	assert.Equal(t, internal.StatusIdle, f.session(f.first).state.CurrentStatus())
	assert.False(t, f.session(f.first).isClientRunning())
	assert.Nil(t, f.session(f.first).client())
	assert.Equal(t, hostcoord.DesiredDown, f.stored(t)[f.first])

	assert.Same(t, secondClient, second.client(), "the other session must keep running")
	assert.Equal(t, internal.StatusConnected, second.state.CurrentStatus())
	assert.Equal(t, hostcoord.DesiredUp, f.stored(t)[f.second])
}

func TestGate_DownAllTakesEverySessionDown(t *testing.T) {
	f := newGateFixture(t)
	require.NoError(t, f.up(f.first))
	require.NoError(t, f.up(f.second))

	_, err := f.s.Down(f.ctx, &proto.DownRequest{All: true})
	require.NoError(t, err)

	for _, key := range []profilemanager.SessionKey{f.first, f.second} {
		ss := f.session(key)
		assert.Equal(t, internal.StatusIdle, ss.state.CurrentStatus())
		assert.Nil(t, ss.client())
		assert.False(t, ss.holdsHost())
		assert.Equal(t, hostcoord.DesiredDown, f.stored(t)[key])
	}

	_, err = f.s.Down(f.ctx, &proto.DownRequest{All: true})
	assert.NoError(t, err, "a session that ran once has nothing left to take down, as a repeated Down without the gate")
}

func TestDown_RefusesASelectorWithAll(t *testing.T) {
	f := newGateFixture(t)
	_, err := f.s.Down(f.ctx, &proto.DownRequest{
		All:     true,
		Session: &proto.SessionSelector{Profile: string(f.first.Profile), Username: f.first.Username},
	})
	requireCode(t, codes.InvalidArgument, err)
}

// A service stop is no request to stay down: the sessions come back with the service.
func TestGate_StopSessionsKeepsTheDesiredState(t *testing.T) {
	f := newGateFixture(t)
	require.NoError(t, f.up(f.first))
	require.NoError(t, f.up(f.second))

	require.NoError(t, f.s.StopSessions(f.ctx))

	for _, key := range []profilemanager.SessionKey{f.first, f.second} {
		assert.False(t, f.session(key).holdsHost(), "the service stop must end every run")
		assert.Equal(t, hostcoord.DesiredUp, f.stored(t)[key])
	}
}

func TestGate_StatusListsTheSessions(t *testing.T) {
	f := newGateFixture(t)
	require.NoError(t, f.up(f.first))
	require.NoError(t, f.up(f.second))
	f.focus(t, f.third)

	status, err := f.s.Status(f.ctx, &proto.StatusRequest{GetFullPeerStatus: true})
	require.NoError(t, err)
	assert.Equal(t, string(internal.StatusIdle), status.GetStatus(), "the top level fields describe the focused session")

	byID := make(map[string]*proto.SessionStatus)
	for _, entry := range status.GetSessions() {
		byID[entry.GetProfileId()] = entry
	}
	require.Len(t, byID, 3, "both runs and the focused session should be listed")

	assert.Equal(t, string(internal.StatusConnected), byID[string(f.first.Profile)].GetStatus())
	assert.False(t, byID[string(f.first.Profile)].GetFocused())
	assert.Equal(t, string(internal.StatusConnected), byID[string(f.second.Profile)].GetStatus())
	assert.NotNil(t, byID[string(f.second.Profile)].GetFullStatus(), "full status was asked for")
	assert.True(t, byID[string(f.third.Profile)].GetFocused())
	assert.Equal(t, string(internal.StatusIdle), byID[string(f.third.Profile)].GetStatus())

	brief, err := f.s.Status(f.ctx, &proto.StatusRequest{})
	require.NoError(t, err)
	for _, entry := range brief.GetSessions() {
		assert.Nil(t, entry.GetFullStatus(), "full status was not asked for")
	}
}

// fakeServerStream carries the context of a caller into a streaming handler and takes what it sends.
type fakeServerStream[T any] struct {
	grpc.ServerStream
	ctx context.Context
}

func (f fakeServerStream[T]) Context() context.Context { return f.ctx }

func (f fakeServerStream[T]) Send(*T) error { return nil }

// Every RPC with a selector. A handler that forgets the check would answer about the wrong session
// without saying so.
func selectorRPCs(s *Server, ctx context.Context, selector *proto.SessionSelector) map[string]func() error {
	return map[string]func() error{
		"Status": func() error {
			_, err := s.Status(ctx, &proto.StatusRequest{Session: selector})
			return err
		},
		"SubscribeStatus": func() error {
			return s.SubscribeStatus(&proto.StatusRequest{Session: selector}, fakeServerStream[proto.StatusResponse]{ctx: ctx})
		},
		"SubscribeEvents": func() error {
			return s.SubscribeEvents(&proto.SubscribeRequest{Session: selector}, fakeServerStream[proto.SystemEvent]{ctx: ctx})
		},
		"Down": func() error {
			_, err := s.Down(ctx, &proto.DownRequest{Session: selector})
			return err
		},
		"WaitSSOLogin": func() error {
			_, err := s.WaitSSOLogin(ctx, &proto.WaitSSOLoginRequest{Session: selector})
			return err
		},
		"ListNetworks": func() error {
			_, err := s.ListNetworks(ctx, &proto.ListNetworksRequest{Session: selector})
			return err
		},
		"SelectNetworks": func() error {
			_, err := s.SelectNetworks(ctx, &proto.SelectNetworksRequest{Session: selector})
			return err
		},
		"DeselectNetworks": func() error {
			_, err := s.DeselectNetworks(ctx, &proto.SelectNetworksRequest{Session: selector})
			return err
		},
		"TracePacket": func() error {
			_, err := s.TracePacket(ctx, &proto.TracePacketRequest{Session: selector})
			return err
		},
		"StartCapture": func() error {
			return s.StartCapture(&proto.StartCaptureRequest{Session: selector}, fakeServerStream[proto.CapturePacket]{ctx: ctx})
		},
		"GetPeerSSHHostKey": func() error {
			_, err := s.GetPeerSSHHostKey(ctx, &proto.GetPeerSSHHostKeyRequest{Session: selector})
			return err
		},
		"RequestJWTAuth": func() error {
			_, err := s.RequestJWTAuth(ctx, &proto.RequestJWTAuthRequest{Session: selector})
			return err
		},
		"WaitJWTToken": func() error {
			_, err := s.WaitJWTToken(ctx, &proto.WaitJWTTokenRequest{Session: selector})
			return err
		},
		"RequestExtendAuthSession": func() error {
			_, err := s.RequestExtendAuthSession(ctx, &proto.RequestExtendAuthSessionRequest{Session: selector})
			return err
		},
		"WaitExtendAuthSession": func() error {
			_, err := s.WaitExtendAuthSession(ctx, &proto.WaitExtendAuthSessionRequest{Session: selector})
			return err
		},
		"DismissSessionWarning": func() error {
			_, err := s.DismissSessionWarning(ctx, &proto.DismissSessionWarningRequest{Session: selector})
			return err
		},
		"ExposeService": func() error {
			return s.ExposeService(&proto.ExposeServiceRequest{Session: selector}, fakeServerStream[proto.ExposeServiceEvent]{ctx: ctx})
		},
		"ListStates": func() error {
			_, err := s.ListStates(ctx, &proto.ListStatesRequest{Session: selector})
			return err
		},
		"CleanState": func() error {
			_, err := s.CleanState(ctx, &proto.CleanStateRequest{Session: selector})
			return err
		},
		"DeleteState": func() error {
			_, err := s.DeleteState(ctx, &proto.DeleteStateRequest{Session: selector})
			return err
		},
		"DebugBundle": func() error {
			_, err := s.DebugBundle(ctx, &proto.DebugBundleRequest{Session: selector})
			return err
		},
		"SetSyncResponsePersistence": func() error {
			_, err := s.SetSyncResponsePersistence(ctx, &proto.SetSyncResponsePersistenceRequest{Session: selector})
			return err
		},
		"StartBundleCapture": func() error {
			_, err := s.StartBundleCapture(ctx, &proto.StartBundleCaptureRequest{Session: selector})
			return err
		},
		"StopBundleCapture": func() error {
			_, err := s.StopBundleCapture(ctx, &proto.StopBundleCaptureRequest{Session: selector})
			return err
		},
	}
}

// Without the gate there is one session, and a selector can only name what it runs.
func TestSessionSelector_OtherThanFocusedIsRefusedWithoutTheGate(t *testing.T) {
	f := newResidualFixture(t)

	selectors := map[string]*proto.SessionSelector{
		"a profile that does not exist": {Profile: "no-such-profile", Username: f.active.Username},
		"an empty selector":             {},
		"a profile that is not focused": {Profile: "default", Username: f.active.Username},
	}
	for selectorName, selector := range selectors {
		calls := selectorRPCs(f.s, f.ctx, selector)
		require.Len(t, calls, selectorRPCCount)
		for rpc, call := range calls {
			err := call()
			requireCode(t, codes.FailedPrecondition, err)
			assert.Contains(t, err.Error(), errSelectorNotFocused, "%s of %s: every failure gets one answer", rpc, selectorName)
		}
	}
}

// The gate must not change who may do what without it: nothing asks for the identity.
func TestSessionSelector_WithoutTheGateIgnoresTheIdentity(t *testing.T) {
	f := newResidualFixture(t)
	selector := &proto.SessionSelector{Profile: string(f.active.Profile), Username: f.active.Username}

	for name, ctx := range map[string]context.Context{"another user": userCtx(), "an unknown caller": context.Background()} {
		for _, session := range []*proto.SessionSelector{nil, selector} {
			_, err := f.s.Status(ctx, &proto.StatusRequest{Session: session})
			assert.NoError(t, err, name)
			_, err = f.s.ListStates(ctx, &proto.ListStatesRequest{Session: session})
			assert.NoError(t, err, name)
		}
	}
}

func TestGate_UpIsRefusedInAnUnsupportedRuntime(t *testing.T) {
	t.Run("netstack", func(t *testing.T) {
		f := newGateFixture(t)
		t.Setenv(netstack.EnvUseNetstackMode, "true")
		err := f.up(f.first)
		requireCode(t, codes.FailedPrecondition, err)
		assert.Contains(t, err.Error(), "netstack")
		assert.Zero(t, f.runCount(f.first))
	})

	t.Run("legacy routing", func(t *testing.T) {
		f := newGateFixture(t)
		f.s.advancedRoutingFn = func() bool { return false }
		err := f.up(f.first)
		requireCode(t, codes.FailedPrecondition, err)
		assert.Contains(t, err.Error(), "legacy routing")
		assert.Zero(t, f.runCount(f.first))
	})

	t.Run("a shared state file", func(t *testing.T) {
		f := newGateFixture(t)
		t.Setenv("NB_DNS_STATE_FILE", filepath.Join(t.TempDir(), "state.json"))
		err := f.up(f.first)
		requireCode(t, codes.FailedPrecondition, err)
		assert.Contains(t, err.Error(), "NB_DNS_STATE_FILE")
		assert.Zero(t, f.runCount(f.first))
	})
}

func TestGate_LoginTouchesOnlyTheFocusedSession(t *testing.T) {
	f := newGateFixture(t)
	require.NoError(t, f.up(f.first))
	firstClient := f.session(f.first).client()
	f.s.isLoginRequiredFn = func(context.Context, *profilemanager.Config) (bool, error) { return false, nil }

	f.focus(t, f.second)
	name, username := string(f.second.Profile), f.second.Username
	_, err := f.s.Login(f.ctx, &proto.LoginRequest{ProfileName: &name, Username: &username})
	require.NoError(t, err)

	assert.Same(t, firstClient, f.session(f.first).client(), "a login of another session must not end this one")
	assert.Equal(t, internal.StatusConnected, f.session(f.first).state.CurrentStatus())
	assert.Equal(t, 1, f.runCount(f.first))
}

// The state of a profile can record the names of another slot, from a run before the slots. Cleaning
// it next to a running session could take the interface or the rules of that session.
func TestGate_ResidualStaysWhileAnotherSessionRuns(t *testing.T) {
	f := newGateFixture(t)
	f.s.isLoginRequiredFn = func(context.Context, *profilemanager.Config) (bool, error) { return false, nil }
	statePath := f.s.profileManager.GetStatePathFor(f.second)
	residual := func() bool {
		names, err := statemanager.New(statePath).GetSavedStateNames()
		require.NoError(t, err)
		return len(names) > 0
	}
	require.NoError(t, os.WriteFile(statePath, []byte(residualStateJSON), 0o600))

	require.NoError(t, f.up(f.first))
	flushes := 0
	f.s.flushRoutesFn = func() error {
		flushes++
		return nil
	}

	f.focus(t, f.second)
	name, username := string(f.second.Profile), f.second.Username
	_, err := f.s.Login(f.ctx, &proto.LoginRequest{ProfileName: &name, Username: &username})
	require.NoError(t, err)
	assert.True(t, residual(), "a login next to a running session must leave the state")

	requireCode(t, codes.FailedPrecondition, f.up(f.second))
	assert.True(t, residual(), "an Up next to a running session must leave the state")

	_, err = f.s.CleanState(f.ctx, &proto.CleanStateRequest{All: true})
	requireCode(t, codes.FailedPrecondition, err)
	assert.True(t, residual(), "a state cleanup next to a running session must be refused")
	assert.Zero(t, flushes, "the marked routes may belong to the running session")

	f.focus(t, f.first)
	_, err = f.s.Down(f.ctx, &proto.DownRequest{})
	require.NoError(t, err)
	f.focus(t, f.second)
	_, err = f.s.Login(f.ctx, &proto.LoginRequest{ProfileName: &name, Username: &username})
	require.NoError(t, err)
	assert.False(t, residual(), "alone on the host the session cleans what it left")
	assert.Equal(t, 1, flushes)
}

func TestGate_LogoutOfARunningSessionIsRefused(t *testing.T) {
	f := newGateFixture(t)
	require.NoError(t, f.up(f.first))

	_, err := f.s.Logout(f.ctx, &proto.LogoutRequest{})
	requireCode(t, codes.FailedPrecondition, err)
	assert.Equal(t, internal.StatusConnected, f.session(f.first).state.CurrentStatus())

	name, username := string(f.first.Profile), f.first.Username
	_, err = f.s.Logout(f.ctx, &proto.LogoutRequest{ProfileName: &name, Username: &username})
	requireCode(t, codes.FailedPrecondition, err)
	assert.Equal(t, hostcoord.DesiredUp, f.stored(t)[f.first])
}

func TestGate_RemoveProfile(t *testing.T) {
	f := newGateFixture(t)
	require.NoError(t, f.up(f.first))
	require.NoError(t, f.up(f.second))

	name, username := string(f.second.Profile), f.second.Username
	_, err := f.s.RemoveProfile(f.ctx, &proto.RemoveProfileRequest{ProfileName: name, Username: username})
	requireCode(t, codes.FailedPrecondition, err)
	assert.Contains(t, f.stored(t), f.second)

	second := f.session(f.second)
	f.focus(t, f.second)
	_, err = f.s.Down(f.ctx, &proto.DownRequest{})
	require.NoError(t, err)
	f.focus(t, f.first)
	require.False(t, second.holdsHost())

	// The deregistration cannot reach a Management here and the removal goes on without it.
	removeCtx, cancelRemove := context.WithTimeout(f.ctx, time.Second)
	defer cancelRemove()
	_, err = f.s.RemoveProfile(removeCtx, &proto.RemoveProfileRequest{ProfileName: name, Username: username})
	require.NoError(t, err)
	assert.NotContains(t, f.stored(t), f.second, "the removal frees the slot")
	assert.Nil(t, f.session(f.second), "the removal drops the session")

	// An Up that resolved the profile before the removal must not bring it back.
	err = f.s.lockedLaunch(f.ctx, second, sessionLaunch{
		resolve: func() (*profilemanager.Config, error) {
			t.Error("the config of a removed profile must not be read: it would provision it again")
			return nil, errors.New("removed")
		},
		source: proto.MetadataSourceUpRPC,
	})
	assert.Error(t, err)
}

// One session failing is that session's business.
func TestGate_ErrorOfASessionLeavesTheOthers(t *testing.T) {
	f := newGateFixture(t)
	require.NoError(t, f.up(f.first))
	firstClient := f.session(f.first).client()

	f.mu.Lock()
	f.failRuns[f.second] = gstatus.Error(codes.PermissionDenied, "needs a login")
	f.mu.Unlock()

	err := f.up(f.second)
	require.Error(t, err, "the second session should report its own failure")

	assert.Same(t, firstClient, f.session(f.first).client())
	assert.Equal(t, internal.StatusConnected, f.session(f.first).state.CurrentStatus())
	assert.False(t, f.session(f.second).holdsHost(), "a run that ended holds nothing")
	assert.NoError(t, f.up(f.third), "a run that ended does not count against the next one")
}

func TestGate_SleepCoversEverySession(t *testing.T) {
	f := newGateFixture(t)
	require.NoError(t, f.up(f.first))
	require.NoError(t, f.up(f.second))
	agent := &serverAgent{s: f.s}

	status, err := agent.Status()
	require.NoError(t, err)
	assert.Equal(t, internal.StatusConnected, status)

	f.focus(t, f.third)

	status, err = agent.Status()
	require.NoError(t, err)
	assert.Equal(t, internal.StatusConnected, status, "a session that is not focused counts too")

	require.NoError(t, agent.Down(f.ctx))
	for _, key := range []profilemanager.SessionKey{f.first, f.second} {
		assert.Equal(t, internal.StatusIdle, f.session(key).state.CurrentStatus())
		assert.Equal(t, hostcoord.DesiredUp, f.stored(t)[key], "a sleep is no request to stay down")
	}
	assert.Zero(t, f.runCount(f.third), "a session that was down stays down")

	status, err = agent.Status()
	require.NoError(t, err)
	assert.Equal(t, internal.StatusIdle, status)

	require.NoError(t, agent.Up(f.ctx))
	assert.Equal(t, 2, f.runCount(f.first))
	assert.Equal(t, 2, f.runCount(f.second))
	assert.Zero(t, f.runCount(f.third), "the wake up brings back only what the sleep took down")
}

func TestGate_MDMRestartCoversEverySession(t *testing.T) {
	f := newGateFixture(t)
	require.NoError(t, f.up(f.first))
	require.NoError(t, f.up(f.second))
	f.focus(t, f.third)

	require.NoError(t, f.s.onMDMPolicyChange(nil, nil))

	require.Eventually(t, func() bool {
		return f.runCount(f.first) == 2 && f.runCount(f.second) == 2
	}, 5*time.Second, 10*time.Millisecond, "each running session should be restarted")
	assert.Zero(t, f.runCount(f.third), "a session with no run must not be started")
	assert.Equal(t, f.third, f.s.focusedSession().key, "the restart must not move the focus")
}

// A run that gave up does not hold the host, so another session can be in its place by the time
// a policy changes. Bringing the old run back would put the two side by side with no isolation.
func TestGate_MDMRestartDoesNotReviveARunPastTheLimit(t *testing.T) {
	f := newGateFixture(t, func(f *gateFixture) { f.s.maxSessions = 1 })
	require.NoError(t, f.up(f.first))
	first := f.session(f.first)
	first.cancelAct()
	_, giveUp := first.runChans()
	select {
	case <-giveUp:
	case <-time.After(5 * time.Second):
		t.Fatal("the run did not end")
	}
	first.state.Set(internal.StatusIdle)
	require.True(t, first.isClientRunning(), "the intent outlives the run that gave up")
	require.False(t, first.holdsHost())

	require.NoError(t, f.up(f.second))

	err := f.s.onMDMPolicyChange(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "limit", "the refusal should reach the caller")
	assert.Equal(t, 1, f.runCount(f.first), "the run that gave up must stay ended")
	assert.False(t, first.isClientRunning())
}

func TestGate_RestartBringsBackTheDesiredSessions(t *testing.T) {
	t.Run("every session that was up", func(t *testing.T) {
		f := prepareGateFixture(t)
		writeDesiredSessions(t, map[profilemanager.SessionKey]hostcoord.DesiredState{
			f.first:  hostcoord.DesiredUp,
			f.second: hostcoord.DesiredUp,
			f.third:  hostcoord.DesiredDown,
		})

		require.NoError(t, f.s.Start())

		require.Eventually(t, func() bool {
			return f.runCount(f.first) == 1 && f.runCount(f.second) == 1
		}, 5*time.Second, 10*time.Millisecond, "both sessions should come back")
		assert.Zero(t, f.runCount(f.third), "a session that was down stays down")
		assert.Equal(t, f.first, f.s.focusedSession().key)
	})

	t.Run("the focused session that was down stays down", func(t *testing.T) {
		f := prepareGateFixture(t)
		writeDesiredSessions(t, map[profilemanager.SessionKey]hostcoord.DesiredState{
			f.first:  hostcoord.DesiredDown,
			f.second: hostcoord.DesiredUp,
		})

		require.NoError(t, f.s.Start())

		require.Eventually(t, func() bool { return f.runCount(f.second) == 1 }, 5*time.Second, 10*time.Millisecond)
		assert.Zero(t, f.runCount(f.first))
		assert.Equal(t, internal.StatusIdle, f.session(f.first).state.CurrentStatus())
	})

	t.Run("the first start with the gate connects the active profile", func(t *testing.T) {
		f := prepareGateFixture(t)

		require.NoError(t, f.s.Start())

		require.Eventually(t, func() bool { return f.runCount(f.first) == 1 }, 5*time.Second, 10*time.Millisecond)
		assert.Equal(t, hostcoord.DesiredUp, f.stored(t)[f.first])
	})

	t.Run("past the limit a session stays down and keeps wanting to come back", func(t *testing.T) {
		f := prepareGateFixture(t, func(f *gateFixture) { f.s.maxSessions = 1 })
		writeDesiredSessions(t, map[profilemanager.SessionKey]hostcoord.DesiredState{
			f.first:  hostcoord.DesiredUp,
			f.second: hostcoord.DesiredUp,
		})

		require.NoError(t, f.s.Start())

		require.Eventually(t, func() bool { return f.runCount(f.first) == 1 }, 5*time.Second, 10*time.Millisecond)
		assert.Zero(t, f.runCount(f.second))
		assert.Equal(t, hostcoord.DesiredUp, f.stored(t)[f.second])
	})

	t.Run("a profile that is gone does not come back", func(t *testing.T) {
		f := prepareGateFixture(t)
		gone := profilemanager.SessionKey{Profile: "gone-profile", Username: f.first.Username}
		writeDesiredSessions(t, map[profilemanager.SessionKey]hostcoord.DesiredState{
			f.first: hostcoord.DesiredUp,
			gone:    hostcoord.DesiredUp,
		})

		require.NoError(t, f.s.Start())

		require.Eventually(t, func() bool { return f.runCount(f.first) == 1 }, 5*time.Second, 10*time.Millisecond)
		assert.Zero(t, f.runCount(gone))
		_, err := os.Stat(filepath.Join(profilemanager.DefaultConfigPathDir, "gone-profile.json"))
		assert.True(t, os.IsNotExist(err), "the restore must not provision a removed profile")
	})
}

// Turning the gate off is a return to one session: the active profile connects, and the sessions
// file is only read, for the residual cleanup.
func TestGateOff_ConnectsOnlyTheFocusedAndLeavesTheSessionsFile(t *testing.T) {
	f := prepareGateFixture(t)
	f.s.sessionSet = newSessionSet(false)
	f.s.connectFn = f.connect
	f.s.advancedRoutingFn = func() bool { return true }
	writeDesiredSessions(t, map[profilemanager.SessionKey]hostcoord.DesiredState{
		f.first:  hostcoord.DesiredDown,
		f.second: hostcoord.DesiredUp,
	})
	path := filepath.Join(profilemanager.DefaultConfigPathDir, "sessions.json")
	before, err := os.ReadFile(path)
	require.NoError(t, err)

	require.NoError(t, f.s.Start())
	t.Cleanup(func() {
		_, giveUp := f.s.focusedSession().runChans()
		if giveUp != nil {
			f.s.focusedSession().cancelAct()
			<-giveUp
		}
	})

	require.Eventually(t, func() bool { return f.runCount(f.first) == 1 }, 5*time.Second, 10*time.Millisecond,
		"without the gate the active profile connects, whatever the file says")
	assert.Zero(t, f.runCount(f.second))

	after, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, string(before), string(after), "without the gate the file is not written")
}

// I1: nothing about the gate reaches a daemon without it.
func TestGateOff_LeavesNoTrace(t *testing.T) {
	f := newResidualFixture(t)
	s := f.s
	assert.Nil(t, s.sessions)
	assert.Nil(t, s.slots)

	resp, err := s.GetFeatures(f.ctx, &proto.GetFeaturesRequest{})
	require.NoError(t, err)
	assert.False(t, resp.GetConcurrentProfilesEnabled())

	name, username := string(f.other.Profile), f.other.Username
	_, err = s.SwitchProfile(f.ctx, &proto.SwitchProfileRequest{ProfileName: &name, Username: &username})
	require.NoError(t, err)
	assert.Equal(t, f.other, func() profilemanager.SessionKey {
		key, _ := s.focusedSession().selectedConfig()
		return key
	}(), "without the gate the one session follows the active profile")

	status, err := s.Status(f.ctx, &proto.StatusRequest{})
	require.NoError(t, err)
	assert.Empty(t, status.GetSessions(), "the sessions list belongs to the gate")

	_, err = os.Stat(filepath.Join(profilemanager.DefaultConfigPathDir, "sessions.json"))
	assert.True(t, os.IsNotExist(err), "without the gate there is no sessions file")
}

func TestGate_StartIsIdempotent(t *testing.T) {
	f := prepareGateFixture(t)
	require.NoError(t, f.s.Start())
	require.Eventually(t, func() bool { return f.runCount(f.first) == 1 }, 5*time.Second, 10*time.Millisecond)
	require.NoError(t, f.s.Start())
	assert.Equal(t, 1, f.runCount(f.first))
}

func TestGate_StartRefusesACorruptSessionsFile(t *testing.T) {
	f := prepareGateFixture(t)
	path := filepath.Join(profilemanager.DefaultConfigPathDir, "sessions.json")
	require.NoError(t, os.WriteFile(path, []byte(`not json`), 0o600))

	require.Error(t, f.s.Start())
	assert.Zero(t, f.runCount(f.first))

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "not json", string(content), "a corrupt file stays for the operator")
}

// A Down gives up on the end of a run after 5 s, and the run can take much longer: stopping an engine
// has its own timeouts. The next Up must not start a second run next to it, as the end of the first
// takes the isolation of the session along.
func TestGate_UpDoesNotOverlapARunStillStopping(t *testing.T) {
	f := newGateFixture(t)

	stopped := make(chan struct{})
	release := sync.OnceFunc(func() { close(stopped) })
	t.Cleanup(release)
	var active, overlapped atomic.Int32
	connect := f.s.connectFn
	f.s.connectFn = func(ctx context.Context, ss *session, key profilemanager.SessionKey, config *profilemanager.Config, runningChan chan struct{}) error {
		if active.Add(1) > 1 {
			overlapped.Add(1)
		}
		defer active.Add(-1)
		err := connect(ctx, ss, key, config, runningChan)
		<-stopped
		return err
	}

	require.NoError(t, f.up(f.first))
	_, err := f.s.Down(f.ctx, &proto.DownRequest{})
	require.NoError(t, err, "a Down gives up waiting for the run")

	name, username := string(f.first.Profile), f.first.Username
	ctx, cancel := context.WithTimeout(f.ctx, 200*time.Millisecond)
	defer cancel()
	_, err = f.s.Up(ctx, &proto.UpRequest{ProfileName: &name, Username: &username})
	assert.Equal(t, codes.FailedPrecondition, gstatus.Code(err), "the Up should not start next to the stopping run: %v", err)
	assert.Zero(t, overlapped.Load(), "two runs of one session must not overlap")
	assert.Equal(t, 1, f.runCount(f.first), "the second run should not have started")

	release()
	require.NoError(t, f.up(f.first), "once the run has ended the Up goes through")
	assert.Zero(t, overlapped.Load(), "two runs of one session must not overlap")
	assert.Equal(t, 2, f.runCount(f.first), "the second run should start after the first ended")
}
