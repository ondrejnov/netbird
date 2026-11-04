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
	// actGeneration counts the replacements of actCancel, so that a restart can tell
	// whether someone took the session over while it waited with no lock held.
	actGeneration uint64

	// clientRunning tracks "the daemon wants to be connected": set by Start and Up,
	// cleared by Down and Logout. It persists across retry loops, signal disconnects
	// and ErrResetConnection cycles, and the connectWithRetryRuns goroutine does not
	// change it when it exits. For whether that goroutine is still alive, see
	// connectionGoroutineRunning.
	clientRunning     bool
	clientRunningChan chan struct{}
	clientGiveUpChan  chan struct{} // closed when connectWithRetryRuns goroutine exits

	// restart is the MDM restart in progress, nil when there is none. restartDone is closed
	// when it ends.
	restart     *runRestart
	restartDone chan struct{}

	connectClient *internal.ConnectClient

	// runKey is the profile the most recent run was started for. A profile switch does
	// not touch it, and it outlives the run, so it still names the owner of a client that
	// stays published after its goroutine gave up.
	runKey profilemanager.SessionKey

	config *profilemanager.Config
	// configKey is the profile config was resolved for.
	configKey profilemanager.SessionKey

	// statusRecorder is set by newSession and never replaced, so reading it takes no
	// lock. The recorder synchronizes itself.
	statusRecorder *peer.Status

	// state is the status of the connection. Set by newSession and never replaced; the
	// state synchronizes itself.
	state *internal.ContextState

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
		state:                 internal.NewContextState(),
		extendAuthSessionFlow: auth.NewPendingFlow(),
		jwtCache:              newJWTCache(),
	}
}

// runContext returns the context of one attempt of this session, cancelled along with
// parent. The connect client and the engine read the state of their session from it.
func (ss *session) runContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithCancel(internal.CtxWithState(parent, ss.state))
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
	ss.actGeneration++
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

// beginRun records the intent to be connected for the profile key and returns the
// channels for the connectWithRetryRuns goroutine the caller is about to start.
func (ss *session) beginRun(key profilemanager.SessionKey) (running, giveUp chan struct{}) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.runKey = key
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
	return ss.goroutineAliveLocked()
}

func (ss *session) goroutineAliveLocked() bool {
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

// runningKey returns the profile the session is running. It reports false when nothing
// runs: the daemon does not want to be connected, or the retry goroutine is gone, for
// instance because a Login cancelled it to take over. A run an MDM restart is replacing
// still counts, as its goroutine ends only on the way to the next one, unless someone took
// the session over meanwhile.
func (ss *session) runningKey() (profilemanager.SessionKey, bool) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if !ss.clientRunning || (!ss.goroutineAliveLocked() && !ss.restartKeepsRunLocked()) {
		return profilemanager.SessionKey{}, false
	}
	return ss.runKey, true
}

func (ss *session) restartKeepsRunLocked() bool {
	return ss.restart != nil && ss.restart.running && ss.restart.actGeneration == ss.actGeneration
}

// runRestart is what an MDM restart copied from the session before releasing the locks
// to wait for the run to end.
type runRestart struct {
	// key is the profile to bring back. running is false when no run was alive, and the
	// restart then starts the active profile.
	key     profilemanager.SessionKey
	running bool
	giveUp  <-chan struct{}

	actGeneration uint64
}

// beginRestart marks an MDM restart as in progress, for the waiters of awaitRestart, and
// reports false, changing nothing, when there is nothing to restart or one is in progress.
// A successful call has to be paired with endRestart.
func (ss *session) beginRestart() (runRestart, bool) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if !ss.clientRunning || ss.restart != nil {
		return runRestart{}, false
	}

	restart := runRestart{giveUp: ss.clientGiveUpChan, actGeneration: ss.actGeneration}
	if ss.goroutineAliveLocked() {
		restart.key, restart.running = ss.runKey, true
	}
	ss.restart = &restart
	ss.restartDone = make(chan struct{})
	return restart, true
}

func (ss *session) endRestart() {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if ss.restart != nil {
		close(ss.restartDone)
		ss.restart, ss.restartDone = nil, nil
	}
}

// restartStillWanted reports whether the session is as restart left it: a Down or a Logout
// asked to stay down, and an Up, a Login or a WaitSSOLogin replaced the attempt with its own.
func (ss *session) restartStillWanted(restart runRestart) bool {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return ss.clientRunning && ss.actGeneration == restart.actGeneration
}

func (ss *session) restarting() bool {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return ss.restart != nil
}

// awaitRestart waits until no MDM restart is in progress. The caller must not hold
// Server.mutex, which the restart needs in order to finish.
func (ss *session) awaitRestart(ctx context.Context) error {
	for {
		ss.mu.Lock()
		done := ss.restartDone
		ss.mu.Unlock()
		if done == nil {
			return nil
		}

		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
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

// currentConfig returns the config of the profile last selected on the daemon, nil until
// something resolved one. SwitchProfile and Login replace it without touching the running
// client, so it can belong to another profile than the client: see configBelongsTo and
// configBelongsToRun. A caller that uses it more than once takes one snapshot, so a
// concurrent swap cannot mix the fields of two configs.
func (ss *session) currentConfig() *profilemanager.Config {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return ss.config
}

// selectedConfig returns currentConfig along with the profile it was resolved for.
func (ss *session) selectedConfig() (profilemanager.SessionKey, *profilemanager.Config) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return ss.configKey, ss.config
}

func (ss *session) setConfig(key profilemanager.SessionKey, config *profilemanager.Config) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.configKey = key
	ss.config = config
}

// configBelongsTo reports whether the current config is the one of the profile key.
func (ss *session) configBelongsTo(key profilemanager.SessionKey) bool {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return sameSessionProfile(ss.configKey, key)
}

// configBelongsToRun reports whether the current config is the one of the profile the
// most recent run was started for, which is the profile the published client belongs to.
func (ss *session) configBelongsToRun() bool {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return sameSessionProfile(ss.configKey, ss.runKey)
}

// sameSessionProfile reports whether two keys name one profile. The default profile is
// shared by every user: switching to it drops the username the active state held.
func sameSessionProfile(a, b profilemanager.SessionKey) bool {
	if a.Profile != b.Profile {
		return false
	}
	return a.Profile == profilemanager.DefaultProfileName || a.Username == b.Username
}
