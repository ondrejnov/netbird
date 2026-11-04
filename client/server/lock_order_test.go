package server

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
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

	s.session.mu.Lock()
	unlocked := false
	unlock := func() {
		if !unlocked {
			unlocked = true
			s.session.mu.Unlock()
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
	s.rootCtx = internal.CtxInitState(context.Background())
	_, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s.session.actCancel = cancel

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
		ss := s.session

		ss.setActCancel(func() {})
		ss.hasActCancel()
		ss.cancelAct()
		ss.beginRun(profilemanager.SessionKey{})
		ss.runChans()
		ss.isClientRunning()
		ss.connectionGoroutineRunning()
		ss.markClientDown()
		ss.setClient(newDummyConnectClient(internal.CtxInitState(context.Background())))
		ss.client()
		ss.clientConnectingOrConnected()
		ss.setConfig(profilemanager.SessionKey{}, &profilemanager.Config{})
		ss.currentConfig()
		ss.runningKey()
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
	s.session.oauthAuthFlow = oauthAuthFlow{
		flow:       &stubOAuthFlow{},
		waitCancel: func() { s.session.oauthFlow() },
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.mutex.Lock()
		defer s.mutex.Unlock()
		s.dropPendingAuthFlows()
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
