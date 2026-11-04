package server

import (
	"context"
	"sync"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/auth"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/util/capture"
)

// session is the state of one connection the daemon runs. The daemon still runs a
// single session, owned by Server for its whole lifetime.
//
// The lock order is guardedConfigMu, Server.mutex, session.mu. mu is a leaf: it guards
// single reads and writes of the fields below, is never held across a call out of this
// type, and session has no reference back to Server. It does not make a check followed
// by an act atomic: those sequences stay under Server.mutex, as they always were.
type session struct {
	mu sync.Mutex

	actCancel context.CancelFunc

	// clientRunning tracks "the daemon wants to be connected": set by Start and Up,
	// cleared by Down and Logout. It persists across retry loops, signal disconnects
	// and ErrResetConnection cycles, and the connectWithRetryRuns goroutine does not
	// change it when it exits. For whether that goroutine is still alive, see
	// connectionGoroutineRunning.
	clientRunning     bool
	clientRunningChan chan struct{}
	clientGiveUpChan  chan struct{} // closed when connectWithRetryRuns goroutine exits

	connectClient *internal.ConnectClient

	config *profilemanager.Config

	// statusRecorder is set by newSession and never replaced, so reading it takes no
	// lock. The recorder synchronizes itself.
	statusRecorder *peer.Status

	oauthAuthFlow oauthAuthFlow

	// extendAuthSessionFlow holds the pending PKCE flow created by
	// RequestExtendAuthSession until WaitExtendAuthSession resolves it. It is separate
	// from oauthAuthFlow, which is reserved for the SSH JWT path, so a concurrent SSH
	// auth does not clobber the session extend flow or vice versa. Set by newSession and
	// never replaced; the flow synchronizes itself.
	extendAuthSessionFlow *auth.PendingFlow

	// jwtCache is set by newSession and never replaced; the cache synchronizes itself.
	jwtCache *jwtCache

	// activeCapture is the packet capture currently installed on the engine.
	activeCapture *capture.Session
}

func newSession() *session {
	return &session{
		statusRecorder:        peer.NewRecorder(""),
		extendAuthSessionFlow: auth.NewPendingFlow(),
		jwtCache:              newJWTCache(),
	}
}

// cancelAct cancels the current attempt, if there is one. The cancel runs after the
// unlock because it can start arbitrary teardown.
func (ss *session) cancelAct() {
	ss.mu.Lock()
	cancel := ss.actCancel
	ss.mu.Unlock()

	if cancel != nil {
		cancel()
	}
}

func (ss *session) setActCancel(cancel context.CancelFunc) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.actCancel = cancel
}

func (ss *session) hasActCancel() bool {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return ss.actCancel != nil
}

func (ss *session) isClientRunning() bool {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return ss.clientRunning
}

// markClientDown records that the daemon no longer wants to be connected. The retry
// goroutine and its channels are left alone, they follow the cancellation.
func (ss *session) markClientDown() {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.clientRunning = false
}

// beginRun records the intent to be connected and returns the channels for the
// connectWithRetryRuns goroutine the caller is about to start.
func (ss *session) beginRun() (running, giveUp chan struct{}) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.clientRunning = true
	ss.clientRunningChan = make(chan struct{})
	ss.clientGiveUpChan = make(chan struct{})
	return ss.clientRunningChan, ss.clientGiveUpChan
}

// runChans returns the channels of the most recently started retry goroutine, for a
// waiter. A restart replaces them, so a waiter that outlives one has to read them again.
func (ss *session) runChans() (running, giveUp <-chan struct{}) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return ss.clientRunningChan, ss.clientGiveUpChan
}

// connectionGoroutineRunning reports whether the connectWithRetryRuns goroutine is
// still running. It returns false when no goroutine has ever been started and when the
// most recent one has already closed clientGiveUpChan on exit, whether due to ctx
// cancel, DisableAutoConnect single-shot completion, or backoff retry exhaustion.
func (ss *session) connectionGoroutineRunning() bool {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	if ss.clientGiveUpChan == nil {
		return false
	}
	select {
	case <-ss.clientGiveUpChan:
		return false
	default:
		return true
	}
}

func (ss *session) client() *internal.ConnectClient {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return ss.connectClient
}

func (ss *session) setClient(client *internal.ConnectClient) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.connectClient = client
}

// clientConnectingOrConnected reports whether the connect client is holding the host's
// state, which a state cleanup must not pull out from under it.
func (ss *session) clientConnectingOrConnected() bool {
	client := ss.client()
	if client == nil {
		return false
	}
	status := client.Status()
	return status == internal.StatusConnected || status == internal.StatusConnecting
}

// currentConfig returns the config the session runs with, nil until something resolved
// one. A caller that uses it more than once takes one snapshot, so a concurrent swap
// cannot mix the fields of two configs.
func (ss *session) currentConfig() *profilemanager.Config {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return ss.config
}

func (ss *session) setConfig(config *profilemanager.Config) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.config = config
}
