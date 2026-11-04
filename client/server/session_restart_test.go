package server

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
)

// rpcDeadline is how long an RPC may take while a restart waits. The wait itself takes
// up to 10s, so an RPC parked behind it cannot pass as a slow one.
const rpcDeadline = 3 * time.Second

// parkedRestart is an MDM restart waiting for a run that is cancelled but has not ended,
// which is what a slow engine teardown looks like.
type parkedRestart struct {
	f         *residualFixture
	giveUp    chan struct{}
	endRun    func()
	restarted chan error
}

func startParkedRestart(t *testing.T) *parkedRestart {
	t.Helper()

	f := newResidualFixture(t)
	rootCtx, cancelRoot := context.WithCancel(f.ctx)
	f.s.rootCtx = rootCtx
	stopRunAtCleanup(t, f.s, cancelRoot)

	config, err := f.s.storedRunningConfig(f.active)
	require.NoError(t, err)
	f.s.session.setConfig(f.active, config)
	_, giveUp := f.s.session.beginRun(f.active)

	cancelled := make(chan struct{})
	f.s.session.setActCancel(sync.OnceFunc(func() { close(cancelled) }))

	p := &parkedRestart{
		f:         f,
		giveUp:    giveUp,
		endRun:    sync.OnceFunc(func() { close(giveUp) }),
		restarted: make(chan error, 1),
	}

	go func() { p.restarted <- f.s.onMDMPolicyChange(nil, nil) }()

	t.Cleanup(func() {
		p.endRun()
		select {
		case err := <-p.restarted:
			t.Logf("restart ended with: %v", err)
		case <-time.After(15 * time.Second):
			t.Error("the restart did not return after the run ended")
		}
	})

	select {
	case <-cancelled:
	case <-time.After(5 * time.Second):
		t.Fatal("the restart did not cancel the run")
	}
	return p
}

func (p *parkedRestart) waitRestarted(t *testing.T) error {
	t.Helper()
	select {
	case err := <-p.restarted:
		p.restarted <- err
		return err
	case <-time.After(15 * time.Second):
		t.Fatal("the restart did not return")
		return nil
	}
}

// answersInTime requires rpc to return while the restart is still waiting.
func answersInTime(t *testing.T, name string, rpc func() error) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- rpc() }()

	select {
	case err := <-done:
		assert.NoError(t, err, name)
	case <-time.After(rpcDeadline):
		t.Fatalf("%s stayed blocked while the MDM restart waited for the run to end", name)
	}
}

// The restart waits up to 10s for a teardown. The daemon has to keep answering meanwhile,
// and the restart still has to happen once the run is gone.
func TestMDMRestart_RPCsAnswerDuringTheWaitAndTheRunComesBack(t *testing.T) {
	p := startParkedRestart(t)
	s, ctx := p.f.s, p.f.ctx

	answersInTime(t, "Status", func() error {
		_, err := s.Status(ctx, &proto.StatusRequest{})
		return err
	})
	answersInTime(t, "GetFeatures", func() error {
		_, err := s.GetFeatures(ctx, &proto.GetFeaturesRequest{})
		return err
	})
	answersInTime(t, "GetActiveProfile", func() error {
		_, err := s.GetActiveProfile(ctx, &proto.GetActiveProfileRequest{})
		return err
	})

	select {
	case err := <-p.restarted:
		t.Fatalf("the restart returned before the run ended: %v", err)
	default:
	}

	p.endRun()
	require.NoError(t, p.waitRestarted(t))

	running, giveUp := s.session.runChans()
	assert.NotEqual(t, (<-chan struct{})(p.giveUp), giveUp, "the restart should have started a new run")
	assert.NotNil(t, running, "the new run should have its channels")
	key, alive := s.session.runningKey()
	assert.True(t, alive, "the new run should be alive")
	assert.Equal(t, p.f.active, key, "the restart should bring back the profile that ran")
}

// A Down during the wait is the user's decision and comes last, so the restart must not
// connect again behind it.
func TestMDMRestart_DownDuringTheWaitStaysDown(t *testing.T) {
	p := startParkedRestart(t)
	s := p.f.s

	down := make(chan error, 1)
	go func() {
		_, err := s.Down(context.Background(), &proto.DownRequest{})
		down <- err
	}()

	require.Eventually(t, func() bool { return !s.session.isClientRunning() }, rpcDeadline, 10*time.Millisecond,
		"Down stayed blocked while the MDM restart waited for the run to end")

	p.endRun()
	require.NoError(t, <-down)
	require.NoError(t, p.waitRestarted(t))

	_, giveUp := s.session.runChans()
	assert.Equal(t, (<-chan struct{})(p.giveUp), giveUp, "the restart must not start a run after a Down")
	assert.False(t, s.session.isClientRunning(), "the daemon should stay down")
}

// An Up during the wait joins the run the restart brings back. The run it finds is on its
// way out, and reporting that it gave up would fail a request nothing is wrong with.
func TestMDMRestart_UpDuringTheWaitJoinsTheNewRun(t *testing.T) {
	p := startParkedRestart(t)
	s := p.f.s

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	up := make(chan error, 1)
	go func() {
		_, err := s.Up(ctx, &proto.UpRequest{})
		up <- err
	}()

	// Long enough for an Up that would not wait to get to the run being cancelled.
	time.Sleep(200 * time.Millisecond)
	p.endRun()
	require.NoError(t, p.waitRestarted(t))

	// The Management of the fixture is unreachable, so the new run never gets ready.
	assert.ErrorIs(t, <-up, context.DeadlineExceeded, "Up should wait for the new run")

	_, giveUp := s.session.runChans()
	assert.NotEqual(t, (<-chan struct{})(p.giveUp), giveUp, "the restart should have started a new run")
}

// A Login during the wait takes the session over. A restart started now would run next to
// the login with its cancel overwritten, so that nothing could stop it.
func TestMDMRestart_LoginDuringTheWaitKeepsTheSession(t *testing.T) {
	p := startParkedRestart(t)
	s := p.f.s

	active, err := s.profileManager.GetActiveProfileState()
	require.NoError(t, err)
	answersInTime(t, "Login", func() error {
		_, _, _, err := s.authorizeAndPrepareLogin(p.f.ctx, &proto.LoginRequest{}, active)
		return err
	})

	p.endRun()
	require.NoError(t, p.waitRestarted(t))

	_, giveUp := s.session.runChans()
	assert.Equal(t, (<-chan struct{})(p.giveUp), giveUp, "the restart must not start a run after a Login")
	_, alive := s.session.runningKey()
	assert.False(t, alive, "nothing should run until the Up that follows the login")
}

// A run that outlasts the wait fails the restart as before, and a waiter must not stay
// parked behind it.
func TestMDMRestart_TimeoutReleasesWaiters(t *testing.T) {
	p := startParkedRestart(t)
	s := p.f.s

	require.Error(t, p.waitRestarted(t), "the restart should give up on a run that does not end")

	_, giveUp := s.session.runChans()
	assert.Equal(t, (<-chan struct{})(p.giveUp), giveUp, "the restart must not start a second run next to the old one")

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err := s.Up(ctx, &proto.UpRequest{})
	assert.ErrorIs(t, err, context.DeadlineExceeded, "Up should wait on the run that is still there")
}

// A Status that waits for the connection is asking about the run the restart brings back.
func TestMDMRestart_StatusWaitForReadyFollowsTheRestart(t *testing.T) {
	p := startParkedRestart(t)
	s := p.f.s

	wait := true
	status := make(chan error, 1)
	go func() {
		_, err := s.Status(context.Background(), &proto.StatusRequest{WaitForReady: &wait})
		status <- err
	}()

	select {
	case err := <-status:
		t.Fatalf("Status answered from the run on its way out: %v", err)
	case <-time.After(200 * time.Millisecond):
	}

	p.endRun()
	require.NoError(t, p.waitRestarted(t))

	select {
	case err := <-status:
		t.Fatalf("Status did not wait for the new run: %v", err)
	case <-time.After(200 * time.Millisecond):
	}

	// Stands in for the engine of the new run coming up.
	s.session.mu.Lock()
	close(s.session.clientRunningChan)
	s.session.mu.Unlock()

	select {
	case err := <-status:
		assert.NoError(t, err)
	case <-time.After(rpcDeadline):
		t.Fatal("Status did not follow the new run")
	}
}

// While the goroutine of the old run is gone and the new one has not started, the profile
// still counts as running: Logout and the residual cleanup decide on it.
func TestMDMRestart_RunCountsAsRunningAfterItsGoroutineEnded(t *testing.T) {
	ss := newSession()
	key := profilemanager.SessionKey{Profile: "work", Username: "user"}
	_, giveUp := ss.beginRun(key)

	restart, ok := ss.beginRestart()
	require.True(t, ok, "a running session should be restartable")
	assert.True(t, restart.running, "the run was alive when the restart began")
	assert.Equal(t, key, restart.key, "the restart should remember the profile")

	_, again := ss.beginRestart()
	assert.False(t, again, "a second restart must not start while one is in progress")

	close(giveUp)
	current, running := ss.runningKey()
	assert.True(t, running, "the run being replaced should count as running")
	assert.Equal(t, key, current, "the run being replaced should keep its profile")

	ss.endRestart()
	_, running = ss.runningKey()
	assert.False(t, running, "after a restart that started nothing, nothing should run")
	ss.endRestart()
}

// Each step that can replace what a restart is about ends it. A restart that misses one of
// them either brings back a run the user took down, or orphans the one that replaced it.
func TestRestartStillWanted(t *testing.T) {
	key := profilemanager.SessionKey{Profile: "work", Username: "user"}
	tests := []struct {
		name string
		step func(ss *session)
		want bool
	}{
		{name: "nothing happened", step: func(*session) {}, want: true},
		{name: "the attempt was cancelled", step: (*session).cancelAct, want: true},
		{name: "a client was published", step: func(ss *session) {
			ss.setClient(newDummyConnectClient(internal.CtxInitState(context.Background())))
		}, want: true},
		{name: "Down or Logout", step: (*session).markClientDown, want: false},
		{name: "Login or WaitSSOLogin", step: func(ss *session) { ss.setActCancel(func() {}) }, want: false},
		{name: "Up", step: func(ss *session) {
			ss.setActCancel(func() {})
			ss.beginRun(key)
		}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ss := newSession()
			ss.beginRun(key)
			ss.setActCancel(func() {})

			restart, ok := ss.beginRestart()
			require.True(t, ok)
			tt.step(ss)

			assert.Equal(t, tt.want, ss.restartStillWanted(restart), "whether the restart should go on")
			ss.endRestart()
		})
	}
}

// awaitRestart gives up with its context, so that a caller that went away does not stay
// parked behind a restart.
func TestAwaitRestart_EndsWithContextAndRestart(t *testing.T) {
	ss := newSession()
	require.NoError(t, ss.awaitRestart(context.Background()), "with no restart there is nothing to wait for")

	ss.beginRun(profilemanager.SessionKey{})
	_, ok := ss.beginRestart()
	require.True(t, ok)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	assert.ErrorIs(t, ss.awaitRestart(ctx), context.Canceled, "a cancelled caller should stop waiting")

	done := make(chan error, 1)
	go func() { done <- ss.awaitRestart(context.Background()) }()
	ss.endRestart()
	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(rpcDeadline):
		t.Fatal("awaitRestart did not end with the restart")
	}
}
