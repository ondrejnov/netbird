package server

import (
	"context"
	"net/url"
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
	}, func() {
		ss.setActCancel(func() {})
		ss.setClient(client)
		_, giveUp := ss.beginRun()
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
	s.rootCtx = internal.CtxInitState(context.Background())
	mgmtURL, err := url.Parse("https://management.example:443")
	require.NoError(t, err)
	s.session.setConfig(&profilemanager.Config{ManagementURL: mgmtURL})

	s.session.beginRun()

	waitForReady := true
	done := make(chan error, 1)
	go func() {
		_, err := s.Status(context.Background(), &proto.StatusRequest{WaitForReady: &waitForReady})
		done <- err
	}()

	// Long enough for Status to park on the first run's channels.
	time.Sleep(100 * time.Millisecond)

	restarted, _ := s.session.beginRun()
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
	s.rootCtx = internal.CtxInitState(context.Background())
	mgmtURL, err := url.Parse("https://management.example:443")
	require.NoError(t, err)
	first := &profilemanager.Config{ManagementURL: mgmtURL}
	second := &profilemanager.Config{ManagementURL: mgmtURL}
	s.session.setConfig(first)

	hammerWithReaders(func() {
		_, err := s.Status(context.Background(), &proto.StatusRequest{})
		assert.NoError(t, err)
		s.checkUpdateSettingsDisabled()
	}, func() {
		s.mutex.Lock()
		s.session.setConfig(second)
		s.session.setConfig(first)
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
