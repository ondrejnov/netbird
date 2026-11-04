package server

import (
	"context"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
)

// Status reads the lifecycle fields with no outer lock while Up, Down and the MDM
// restart write them under Server.mutex, so only session.mu orders the two. Run with
// -race, this fails if any accessor reads or writes a field outside it.
func TestSessionLifecycle_ConcurrentAccess(t *testing.T) {
	ss := newSession()

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				ss.isClientRunning()
				ss.connectionGoroutineRunning()
				ss.runChans()
				ss.hasActCancel()
				ss.cancelAct()
				ss.clientConnectingOrConnected()
			}
		}()
	}

	client := newDummyConnectClient(internal.CtxInitState(context.Background()))
	for i := 0; i < 500; i++ {
		ss.setActCancel(func() {})
		ss.setClient(client)
		_, giveUp := ss.beginRun()
		close(giveUp)
		ss.markClientDown()
		ss.setClient(nil)
	}
	close(stop)
	wg.Wait()

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

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_, err := s.Status(context.Background(), &proto.StatusRequest{})
				assert.NoError(t, err)
				s.checkUpdateSettingsDisabled()
			}
		}()
	}

	for i := 0; i < 500; i++ {
		s.mutex.Lock()
		s.session.setConfig(second)
		s.session.setConfig(first)
		s.mutex.Unlock()
	}
	close(stop)
	wg.Wait()

	assert.Same(t, first, s.session.currentConfig(), "the last write should be the one a reader sees")
}
