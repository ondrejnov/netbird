package server

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/client/testutil/mgmtmeta"
)

// The daemon takes guardedConfigMu before s.mutex. authorizeAndPrepareLogin
// takes s.mutex while holding guardedConfigMu, so a SetConfig that grabbed
// s.mutex first and then waited for guardedConfigMu would deadlock the daemon
// against a concurrent login: two unprivileged IPC calls are enough.
//
// The held guardedConfigMu below stands in for that login. While SetConfig waits
// for it, s.mutex must stay free, otherwise the login waiting for s.mutex could
// never release guardedConfigMu.
func TestSetConfig_TakesGuardedConfigMuBeforeServerMutex(t *testing.T) {
	s, ctx, profName, username, _ := setupServerWithProfile(t)

	s.guardedConfigMu.Lock()

	done := make(chan error, 1)
	go func() {
		_, err := s.SetConfig(ctx, &proto.SetConfigRequest{
			ProfileName: profName,
			Username:    username,
		})
		done <- err
	}()

	require.Never(t, func() bool {
		if !s.mutex.TryLock() {
			return true
		}
		s.mutex.Unlock()
		return false
	}, 500*time.Millisecond, 10*time.Millisecond,
		"SetConfig held s.mutex while waiting for guardedConfigMu, which deadlocks against a concurrent login")

	s.guardedConfigMu.Unlock()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("SetConfig did not finish after guardedConfigMu was released")
	}
}

// requireWaitsOnSessionMu runs rpc with session.mu held and requires it to park there
// with every lock in held still taken. An RPC that parks holding them took them first,
// which is the documented order. If it took session.mu first, then held, a concurrent
// RPC holding held and waiting for session.mu would deadlock the daemon.
func requireWaitsOnSessionMu(t *testing.T, s *Server, rpc func() error, held ...*sync.Mutex) {
	t.Helper()

	s.focusedSession().mu.Lock()
	unlocked := false
	unlock := func() {
		if !unlocked {
			unlocked = true
			s.focusedSession().mu.Unlock()
		}
	}
	defer unlock()

	done := make(chan error, 1)
	go func() {
		done <- rpc()
	}()

	holdsOuterLocks := func() bool {
		for _, mu := range held {
			if mu.TryLock() {
				mu.Unlock()
				return false
			}
		}
		return true
	}

	deadline := time.After(2 * time.Second)
	for !holdsOuterLocks() {
		select {
		case err := <-done:
			t.Fatalf("the RPC finished while session.mu was held (err: %v), so session.mu does not guard what it read", err)
		case <-deadline:
			t.Fatal("the RPC did not take the outer locks before session.mu")
		case <-time.After(time.Millisecond):
		}
	}

	select {
	case err := <-done:
		t.Fatalf("the RPC finished while session.mu was held (err: %v), so session.mu does not guard what it read", err)
	case <-time.After(100 * time.Millisecond):
	}
	require.True(t, holdsOuterLocks(), "the RPC released an outer lock while waiting for session.mu")

	unlock()

	select {
	case err := <-done:
		t.Logf("the RPC returned after session.mu was released: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("the RPC did not finish after session.mu was released")
	}
}

func TestDown_TakesServerMutexBeforeSessionMu(t *testing.T) {
	s := newTestServer()
	s.rootCtx = context.Background()
	_, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s.focusedSession().actCancel = cancel

	requireWaitsOnSessionMu(t, s, func() error {
		_, err := s.Down(context.Background(), &proto.DownRequest{})
		return err
	}, &s.mutex)
}

// SetConfig is where the whole chain is taken: the update-settings gate reads the
// session's config with guardedConfigMu and Server.mutex already held.
func TestSetConfig_TakesOuterLocksBeforeSessionMu(t *testing.T) {
	s, ctx, profName, username, _ := setupServerWithProfile(t)

	requireWaitsOnSessionMu(t, s, func() error {
		_, err := s.SetConfig(ctx, &proto.SetConfigRequest{
			ProfileName: profName,
			Username:    username,
		})
		return err
	}, &s.guardedConfigMu, &s.mutex)
}

func TestWaitJWTToken_TakesServerMutexBeforeSessionMu(t *testing.T) {
	s := newTestServer()

	requireWaitsOnSessionMu(t, s, func() error {
		_, err := s.WaitJWTToken(context.Background(), &proto.WaitJWTTokenRequest{DeviceCode: "device-code"})
		return err
	}, &s.mutex)
}

func TestStartBundleCapture_TakesServerMutexBeforeSessionMu(t *testing.T) {
	s := newTestServer()

	requireWaitsOnSessionMu(t, s, func() error {
		_, err := s.StartBundleCapture(context.Background(), &proto.StartBundleCaptureRequest{})
		return err
	}, &s.mutex)
}

// The other half of the order: nothing that holds session.mu may wait for an outer
// lock. RPCs hold Server.mutex across slow work such as stopping an engine, so a session
// method waiting for it would freeze every reader of the session, including the ones
// that take no outer lock.
func TestSessionMethods_DoNotWaitForOuterLocks(t *testing.T) {
	s := newTestServer()

	s.guardedConfigMu.Lock()
	defer s.guardedConfigMu.Unlock()
	s.mutex.Lock()
	defer s.mutex.Unlock()

	done := make(chan struct{})
	go func() {
		defer close(done)
		ss := s.focusedSession()

		ss.setActCancel(func() {})
		ss.hasActCancel()
		ss.cancelAct()
		ss.beginRun(profilemanager.SessionKey{}, nil)
		ss.runChans()
		ss.isClientRunning()
		ss.connectionGoroutineRunning()
		ss.markClientDown()
		ss.setClient(newDummyConnectClient(internal.CtxInitState(context.Background())))
		ss.client()
		ss.clientConnectingOrConnected()
		ss.setConfig(profilemanager.SessionKey{}, &profilemanager.Config{})
		ss.currentConfig()
		ss.selectedConfig()
		ss.connectionConfig()
		ss.otherProfileRunKey()
		ss.configOfFlow(oauthAuthFlow{})
		ss.runningKey()
		ss.beginRestart()
		ss.restartStillWanted(runRestart{})
		ss.restarting()
		ss.endRestart()
		_ = ss.awaitRestart(context.Background())
		ss.configBelongsTo(profilemanager.SessionKey{})
		ss.configBelongsToRun()
		ss.oauthFlow()
		ss.swapOAuthFlow(oauthAuthFlow{})
		ss.clearOAuthFlow()
		ss.clearOAuthFlowIf(nil)
		ss.expireOAuthFlow(nil)
		ss.claimOAuthWait(nil, func() {})
		ss.setCapture(nil)
		ss.currentCapture()
		ss.setHostClaim(true)
		ss.holdsHost()
		ss.setHostClaim(false)
		ss.armAccountPrompt()
		ss.takeAccountPrompt()
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a session method waited for an outer lock")
	}
}

// dropPendingAuthFlows cancels a parked WaitSSOLogin, which reads the flow record on the
// way out, so the cancel has to run outside the critical section that took it.
func TestDropPendingAuthFlows_CancelsOutsideSessionMu(t *testing.T) {
	s := newTestServer()
	s.focusedSession().oauthAuthFlow = oauthAuthFlow{
		flow:       &stubOAuthFlow{},
		waitCancel: func() { s.focusedSession().oauthFlow() },
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.mutex.Lock()
		defer s.mutex.Unlock()
		s.dropPendingAuthFlows(s.focusedSession())
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("dropPendingAuthFlows held session.mu across the cancel")
	}
}

// A cancel starts teardown, and whatever it wakes reads the session as it unwinds, so
// running it under session.mu would deadlock on the first such read.
func TestCancelAct_RunsOutsideSessionMu(t *testing.T) {
	ss := newSession()
	ss.setActCancel(func() { ss.isClientRunning() })

	done := make(chan struct{})
	go func() {
		defer close(done)
		ss.cancelAct()
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("cancelAct held session.mu across the cancel")
	}
}

// requireWaitsOnLifecycle runs rpc with the lifecycle of the focused session held and requires
// it to park there with s.mutex free. Stopping a session holds its lifecycle for as long as the
// teardown takes, so an RPC parked on it with s.mutex taken would stop the daemon for all of it.
func requireWaitsOnLifecycle(t *testing.T, s *Server, rpc func() error) {
	t.Helper()

	ss := s.focusedSession()
	require.NoError(t, ss.lockLifecycle(context.Background()))
	unlocked := false
	unlock := func() {
		if !unlocked {
			unlocked = true
			ss.unlockLifecycle()
		}
	}
	defer unlock()

	done := make(chan error, 1)
	go func() {
		done <- rpc()
	}()

	require.Never(t, func() bool {
		select {
		case err := <-done:
			done <- err
			return true
		default:
		}
		if !s.mutex.TryLock() {
			return true
		}
		s.mutex.Unlock()
		return false
	}, 300*time.Millisecond, 5*time.Millisecond, "the RPC did not park on the lifecycle with s.mutex free")

	unlock()

	select {
	case err := <-done:
		t.Logf("the RPC returned after the lifecycle was released: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("the RPC did not finish after the lifecycle was released")
	}
}

func TestDown_WaitsForTheLifecycleWithoutServerMutex(t *testing.T) {
	s := newTestServer()
	requireWaitsOnLifecycle(t, s, func() error {
		_, err := s.Down(context.Background(), &proto.DownRequest{})
		return err
	})
}

func TestUp_WaitsForTheLifecycleWithoutServerMutex(t *testing.T) {
	s, ctx, _, _, _ := setupServerWithProfile(t)
	requireWaitsOnLifecycle(t, s, func() error {
		_, err := s.Up(ctx, &proto.UpRequest{})
		return err
	})
}

func TestLogout_WaitsForTheLifecycleWithoutServerMutex(t *testing.T) {
	s, ctx, _, _, cfgPath := setupServerWithProfile(t)
	// The deregistration goes to a Management of the test, not to a host that needs a network.
	management := mgmtmeta.Start(t)
	_, err := profilemanager.UpdateOrCreateConfig(profilemanager.ConfigInput{
		ConfigPath:    cfgPath,
		ManagementURL: management.URL(),
	})
	require.NoError(t, err)
	requireWaitsOnLifecycle(t, s, func() error {
		_, err := s.Logout(ctx, &proto.LogoutRequest{})
		return err
	})
}

// The lifecycle waits with the context of the RPC, so that a client that goes away does not
// leave a handler parked behind a slow teardown.
func TestLockLifecycle_GivesUpWithTheContext(t *testing.T) {
	ss := newSession()
	require.NoError(t, ss.lockLifecycle(context.Background()))
	defer ss.unlockLifecycle()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	assert.ErrorIs(t, ss.lockLifecycle(ctx), context.Canceled)
}

// Stopping an engine can take seconds. Under s.mutex it would stop every RPC of every session,
// so the daemon has to stay responsive for the whole stop, and the client stays published until
// the stop is over, because a state cleanup must not pull the host out from under it.
func TestCleanupConnection_StopsTheEngineWithoutServerMutex(t *testing.T) {
	s := newTestServer()
	ss := s.focusedSession()
	ss.setActCancel(func() {})
	client := newDummyConnectClient(internal.CtxInitState(context.Background()))
	ss.setClient(client)

	stopping := make(chan struct{})
	release := make(chan struct{})
	s.stopEngineFn = func(*internal.Engine) error {
		close(stopping)
		<-release
		return nil
	}

	done := make(chan error, 1)
	go func() { done <- s.cleanupConnection(ss) }()

	select {
	case <-stopping:
	case <-time.After(5 * time.Second):
		t.Fatal("the engine stop did not start")
	}

	require.True(t, s.mutex.TryLock(), "s.mutex was held across the engine stop")
	s.mutex.Unlock()
	assert.Same(t, client, ss.client(), "the client has to stay published during the stop")
	assert.False(t, ss.isClientRunning(), "the intent flips before the stop")

	close(release)
	require.NoError(t, <-done)
	assert.Nil(t, ss.client())
}

// The whole point of the rule above: a session stuck in its teardown leaves the others alone.
func TestGate_ASlowTeardownDoesNotBlockTheOtherSessions(t *testing.T) {
	f := newGateFixture(t)
	require.NoError(t, f.up(f.first))
	require.NoError(t, f.up(f.second))

	stopping := make(chan struct{})
	release := make(chan struct{})
	var first atomic.Bool
	f.s.stopEngineFn = func(*internal.Engine) error {
		if first.CompareAndSwap(false, true) {
			close(stopping)
			<-release
		}
		return nil
	}

	downDone := make(chan error, 1)
	go func() {
		_, err := f.s.Down(f.ctx, &proto.DownRequest{})
		downDone <- err
	}()
	select {
	case <-stopping:
	case <-time.After(5 * time.Second):
		t.Fatal("the engine stop did not start")
	}

	answers := func(name string, rpc func() error) {
		t.Helper()
		done := make(chan error, 1)
		go func() { done <- rpc() }()
		select {
		case err := <-done:
			assert.NoError(t, err, name)
		case <-time.After(3 * time.Second):
			close(release)
			t.Fatalf("%s stayed blocked behind the teardown of another session", name)
		}
	}

	answers("Status", func() error {
		_, err := f.s.Status(f.ctx, &proto.StatusRequest{})
		return err
	})
	answers("GetFeatures", func() error {
		_, err := f.s.GetFeatures(f.ctx, &proto.GetFeaturesRequest{})
		return err
	})
	answers("SwitchProfile", func() error {
		f.focus(t, f.second)
		return nil
	})
	answers("Down of the other session", func() error {
		_, err := f.s.Down(f.ctx, &proto.DownRequest{})
		return err
	})
	answers("Up of a third session", func() error {
		return f.up(f.third)
	})

	close(release)
	require.NoError(t, <-downDone)
}
