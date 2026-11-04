package server

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/auth"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/util/capture"
)

// hammerWithReaders runs read in several goroutines while write repeats. Each reader
// reads at least once before it can see the stop, so even a writer that finishes before
// the readers are scheduled leaves accesses for -race to compare.
func hammerWithReaders(read, write func()) {
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				read()
				select {
				case <-stop:
					return
				default:
				}
			}
		}()
	}

	for i := 0; i < 500; i++ {
		write()
		runtime.Gosched()
	}
	close(stop)
	wg.Wait()
}

// Status reads the lifecycle fields with no outer lock while Up, Down and the MDM
// restart write them under Server.mutex, so only session.mu orders the two. Run with
// -race, this fails if any accessor reads or writes a field outside it.
func TestSessionLifecycle_ConcurrentAccess(t *testing.T) {
	ss := newSession()
	client := newDummyConnectClient(internal.CtxInitState(context.Background()))

	hammerWithReaders(func() {
		ss.isClientRunning()
		ss.connectionGoroutineRunning()
		ss.runChans()
		ss.hasActCancel()
		ss.cancelAct()
		ss.clientConnectingOrConnected()
		ss.runningKey()
		ss.restarting()
		ss.restartStillWanted(runRestart{})
		ss.configBelongsTo(profilemanager.SessionKey{})
		ss.configBelongsToRun()
	}, func() {
		ss.setActCancel(func() {})
		ss.setClient(client)
		_, giveUp := ss.beginRun(profilemanager.SessionKey{})
		ss.beginRestart()
		ss.endRestart()
		close(giveUp)
		ss.markClientDown()
		ss.setClient(nil)
	})

	assert.False(t, ss.isClientRunning(), "the last writer marked the client down")
	assert.False(t, ss.connectionGoroutineRunning(), "the last run's giveUp channel is closed")
}

// An MDM restart replaces the run channels while a Status with WaitForReady is parked
// on them. The wait has to follow the new run, not finish its 1s tick and go back to
// channels nobody will ever close.
func TestStatusWaitForReady_FollowsRestartedRun(t *testing.T) {
	s := newTestServer()
	s.rootCtx = context.Background()
	mgmtURL, err := url.Parse("https://management.example:443")
	require.NoError(t, err)
	s.session.setConfig(profilemanager.SessionKey{}, &profilemanager.Config{ManagementURL: mgmtURL})

	s.session.beginRun(profilemanager.SessionKey{})

	waitForReady := true
	done := make(chan error, 1)
	go func() {
		_, err := s.Status(context.Background(), &proto.StatusRequest{WaitForReady: &waitForReady})
		done <- err
	}()

	// Long enough for Status to park on the first run's channels.
	time.Sleep(100 * time.Millisecond)

	restarted, _ := s.session.beginRun(profilemanager.SessionKey{})
	close(restarted)

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Status kept waiting on the channels of the run that was replaced")
	}
}

// Status and the policy checks read the config with no Server.mutex, while SwitchProfile,
// Login and Up replace it. Run with -race, this fails if a read skips session.mu.
func TestConfigSwap_DoesNotRaceWithItsReaders(t *testing.T) {
	s := newTestServer()
	s.rootCtx = context.Background()
	mgmtURL, err := url.Parse("https://management.example:443")
	require.NoError(t, err)
	first := &profilemanager.Config{ManagementURL: mgmtURL}
	second := &profilemanager.Config{ManagementURL: mgmtURL}
	s.session.setConfig(profilemanager.SessionKey{}, first)

	hammerWithReaders(func() {
		_, err := s.Status(context.Background(), &proto.StatusRequest{})
		assert.NoError(t, err)
		s.checkUpdateSettingsDisabled()
	}, func() {
		s.mutex.Lock()
		s.session.setConfig(profilemanager.SessionKey{}, second)
		s.session.setConfig(profilemanager.SessionKey{}, first)
		s.mutex.Unlock()
	})

	assert.Same(t, first, s.session.currentConfig(), "the last write should be the one a reader sees")
}

// WaitSSOLogin and WaitJWTToken read the flow record while Login and RequestJWTAuth
// replace it. The mutators are called without Server.mutex here on purpose: run with
// -race, this fails if any of them touches the record outside session.mu.
func TestOAuthFlowRecord_ConcurrentAccess(t *testing.T) {
	ss := newSession()
	flow := &stubOAuthFlow{}
	next := oauthAuthFlow{flow: flow, info: auth.AuthFlowInfo{UserCode: "code"}}

	hammerWithReaders(func() {
		ss.oauthFlow()
		ss.expireOAuthFlow(flow)
		ss.claimOAuthWait(flow, func() {})
		ss.clearOAuthFlowIf(flow)
		ss.currentCapture()
	}, func() {
		ss.swapOAuthFlow(next)
		ss.setCapture(nil)
		ss.clearOAuthFlow()
	})

	assert.Nil(t, ss.oauthFlow().flow, "the last writer cleared the record")
}

// swapOAuthFlow hands the displaced wait to exactly one caller, which is what cancels it.
// With a separate read and write, the two racing callers could both inherit one wait and
// lose the other, leaving it orphaned on its device-code window.
func TestSwapOAuthFlow_HandsTheDisplacedWaitToOneCaller(t *testing.T) {
	ss := newSession()
	ss.oauthAuthFlow.waitCancel = func() {}

	var wg sync.WaitGroup
	var mu sync.Mutex
	inherited := 0
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			displaced := ss.swapOAuthFlow(oauthAuthFlow{})
			if displaced == nil {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			inherited++
		}()
	}
	wg.Wait()

	assert.Equal(t, 1, inherited, "exactly one caller should inherit the displaced wait")
}

func TestClaimOAuthWait_RefusesAReplacedFlow(t *testing.T) {
	ss := newSession()
	current := &stubOAuthFlow{}
	ss.oauthAuthFlow = oauthAuthFlow{flow: current}

	_, claimed := ss.claimOAuthWait(&stubOAuthFlow{}, func() {})
	assert.False(t, claimed, "a flow that is no longer pending must not take over the wait")
	assert.Nil(t, ss.oauthFlow().waitCancel, "a refused claim must leave the record alone")

	_, claimed = ss.claimOAuthWait(current, func() {})
	assert.True(t, claimed, "the pending flow should claim the wait")
	assert.NotNil(t, ss.oauthFlow().waitCancel, "the claim should record the wait's cancel")
}

// I9: a token or a login flow belongs to one session. There is one session today, but
// the session map only keeps this true if the state is per session from the start.
func TestSessions_DoNotShareAuthState(t *testing.T) {
	first, second := newSession(), newSession()
	owner := unprivilegedIdentity()

	require.True(t, first.jwtCache.store("token", owner, testTTL, first.jwtCache.currentGeneration()))
	first.oauthAuthFlow = oauthAuthFlow{flow: &stubOAuthFlow{}}
	first.extendAuthSessionFlow.Set(&stubOAuthFlow{}, auth.AuthFlowInfo{DeviceCode: "device"})
	first.setCapture(&capture.Session{})

	_, found := second.jwtCache.get(owner)
	assert.False(t, found, "a JWT cached by one session was served by another")
	assert.Nil(t, second.oauthFlow().flow, "an SSO flow of one session showed up on another")
	_, _, pending := second.extendAuthSessionFlow.Get()
	assert.False(t, pending, "an extend-session flow of one session showed up on another")
	assert.Nil(t, second.currentCapture(), "a capture of one session showed up on another")
}

// The key names what runs, so it has to stop answering as soon as nothing does, and it
// must follow a restart.
func TestRunningKey_FollowsTheRun(t *testing.T) {
	first := profilemanager.SessionKey{Profile: "first", Username: "alice"}
	second := profilemanager.SessionKey{Profile: "second", Username: "alice"}
	ss := newSession()

	_, running := ss.runningKey()
	assert.False(t, running, "no run was ever started")

	_, giveUp := ss.beginRun(first)
	key, running := ss.runningKey()
	assert.True(t, running, "the goroutine of the run is alive")
	assert.Equal(t, first, key, "the key must be the one the run started with")

	close(giveUp)
	_, running = ss.runningKey()
	assert.False(t, running, "the goroutine gave up, nothing runs")

	ss.beginRun(second)
	key, running = ss.runningKey()
	assert.True(t, running, "the restarted goroutine is alive")
	assert.Equal(t, second, key, "the key must follow the restart")

	ss.markClientDown()
	_, running = ss.runningKey()
	assert.False(t, running, "the daemon no longer wants to be connected")
}

func TestSameSessionProfile(t *testing.T) {
	alice := "alice"
	tests := []struct {
		name string
		a, b profilemanager.SessionKey
		want bool
	}{
		{"same profile and user", profilemanager.SessionKey{Profile: "work", Username: alice}, profilemanager.SessionKey{Profile: "work", Username: alice}, true},
		{"legacy namesake of another user", profilemanager.SessionKey{Profile: "work", Username: alice}, profilemanager.SessionKey{Profile: "work", Username: "bob"}, false},
		{"other profile", profilemanager.SessionKey{Profile: "work", Username: alice}, profilemanager.SessionKey{Profile: "home", Username: alice}, false},
		// Switching to default drops the username the active state held, and a single
		// session must not read that as a config of another profile.
		{"default is shared by every user", profilemanager.SessionKey{Profile: profilemanager.DefaultProfileName, Username: alice}, profilemanager.SessionKey{Profile: profilemanager.DefaultProfileName}, true},
		{"nothing resolved against a run", profilemanager.SessionKey{}, profilemanager.SessionKey{Profile: "work", Username: alice}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, sameSessionProfile(tt.a, tt.b), "keys %+v and %+v", tt.a, tt.b)
		})
	}
}

// The hint of a session extend is the account of the profile the token will go to, so it
// has to come from the running profile however the local active profile moved.
func TestExtendSessionLoginHint_FollowsRunningProfile(t *testing.T) {
	s, _, _, username, _ := setupServerWithProfile(t)
	dir := profilemanager.DefaultConfigPathDir

	writeState := func(id, email string) {
		require.NoError(t, os.WriteFile(filepath.Join(dir, id+".state.json"), []byte(`{"email":"`+email+`"}`), 0o600))
	}
	writeState(profilemanager.DefaultProfileName, "default@example.com")
	writeState("work", "work@example.com")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "active_profile.txt"), []byte("work"), 0o600))

	assert.Equal(t, "work@example.com", s.extendSessionLoginHint(), "with nothing running the hint stays the local active profile's")

	_, giveUp := s.session.beginRun(profilemanager.SessionKey{Profile: profilemanager.DefaultProfileName})
	assert.Equal(t, "default@example.com", s.extendSessionLoginHint(), "the hint must be the running profile's")

	close(giveUp)
	assert.Equal(t, "work@example.com", s.extendSessionLoginHint(), "a finished run must not decide the hint")

	s.session.beginRun(profilemanager.SessionKey{Profile: "gone", Username: username})
	assert.Empty(t, s.extendSessionLoginHint(), "a running profile with no recorded account has no hint")
}

// The daemon's root context carries no connection state: it belongs to the session. Every
// handler that reports or changes the status has to find it there.
func TestServerHandlers_WorkWithoutStateInRootContext(t *testing.T) {
	s := New(context.Background(), "console", "", false, false, false, false)
	managementURL, err := url.Parse("https://management.example.com")
	require.NoError(t, err)
	s.session.setConfig(profilemanager.SessionKey{}, &profilemanager.Config{ManagementURL: managementURL})

	require.NotPanics(t, func() {
		resp, err := s.Status(context.Background(), &proto.StatusRequest{})
		require.NoError(t, err)
		assert.Equal(t, string(internal.StatusIdle), resp.GetStatus(), "a new session should report idle")
	}, "the status must not depend on the root context")

	agent := &serverAgent{s}
	require.NotPanics(t, func() {
		status, err := agent.Status()
		require.NoError(t, err)
		assert.Equal(t, internal.StatusIdle, status, "the sleep handler should read the session status")
	}, "the sleep handler must not depend on the root context")
}

// Each session has its own status: a login that fails in one must not show up in another.
// The connect client and the engine read the status from their context, so the context of
// a run has to lead to the state of the session that started it.
func TestSessionState_BelongsToOneSession(t *testing.T) {
	first, second := newSession(), newSession()

	ctx, cancel := first.runContext(context.Background())
	defer cancel()
	assert.Same(t, first.state, internal.CtxGetState(ctx), "a run should resolve the state of its session")

	client := newDummyConnectClient(ctx)
	first.state.Set(internal.StatusConnected)
	assert.Equal(t, internal.StatusConnected, client.Status(), "the client should report the state of its session")
	assert.False(t, first.clientConnectingOrConnected(), "no client is published on the session yet")

	first.setClient(client)
	assert.True(t, first.clientConnectingOrConnected(), "the session should see its own client connected")

	_ = internal.CtxGetState(ctx).Wrap(internal.ErrResetConnection)
	_, err := second.state.Status()
	assert.NoError(t, err, "an error of one session must not reach another")
	assert.Equal(t, internal.StatusIdle, second.state.CurrentStatus(), "the other session should stay idle")
}

// The context of a run ends with the parent: the daemon's shutdown stops every run.
func TestSessionRunContext_FollowsParent(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	ctx, cancel := newSession().runContext(parent)
	defer cancel()

	cancelParent()
	assert.ErrorIs(t, ctx.Err(), context.Canceled, "the run should end with its parent")
}
