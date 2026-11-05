package server

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/auth"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/util/capture"
)

// session is the state of one connection the daemon runs. Without the feature gate the
// daemon has one, which follows the active profile, and with it one per profile.
//
// The lock order is guardedConfigMu, session.lifecycle, Server.mutex, session.mu. mu is a
// leaf: it guards single reads and writes of the fields below, is never held across a call
// out of this type, and session has no reference back to Server. It does not make a check
// followed by an act atomic: a sequence that starts or stops a run holds lifecycle, so that it
// can release Server.mutex around the slow steps without blocking the other sessions.
type session struct {
	mu sync.Mutex

	// key is the profile of the session when the feature gate is on, and the zero value
	// otherwise. It is set before the session can be reached and never changes.
	key profilemanager.SessionKey

	// lifecycle is held by a sequence that starts or stops a run. A channel, so that an RPC
	// can give up on it with its context. See lockLifecycle.
	lifecycle chan struct{}

	// hostClaim marks a run on its way up or a residual cleanup: nothing shows on the run
	// fields yet, but the session is working on the host. See holdsHost.
	hostClaim bool

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

	// runConfig is the config the most recent run was started with, set along with runKey.
	// It stays when another profile gets selected, see connectionConfig.
	runConfig *profilemanager.Config

	// config is the config of the profile selected on the daemon, see currentConfig.
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

	// forceAccountPrompt makes the next startSSOLogin build its flow with a
	// forced account prompt. Armed when a login came back for an account other
	// than the hinted one: that flow's browser is gone, so the correction has to
	// ride on the user's next connect. Deliberately not persisted: a lost flag only
	// costs one more mismatch round.
	forceAccountPrompt bool

	// isSessionActive records that the session reached the connected state, so that a
	// later NeedsLogin reads as an expiry. It synchronizes itself.
	isSessionActive atomic.Bool

	// sessionWatcher notifies about the expiry of this session. Written under Server.mutex.
	sessionWatcher *internal.SessionWatcher

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

	// bundleCapture is the capture destined for the debug bundle of this session. Guarded by
	// Server.mutex.
	bundleCapture *bundleCapture

	// persistSyncResponse makes the clients of this session keep the latest sync response.
	persistSyncResponse bool

	// refusal says why the most recent run was refused, until the session gets another chance or
	// is taken down.
	refusal *internal.SessionRefusal
}

func newSession() *session {
	return &session{
		lifecycle:             make(chan struct{}, 1),
		statusRecorder:        peer.NewRecorder(""),
		state:                 internal.NewContextState(),
		extendAuthSessionFlow: auth.NewPendingFlow(),
		jwtCache:              newJWTCache(),
		persistSyncResponse:   true,
	}
}

// lockLifecycle takes the right to start or stop a run of this session. The caller must not
// hold Server.mutex. It gives up with ctx.
func (ss *session) lockLifecycle(ctx context.Context) error {
	select {
	case ss.lifecycle <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (ss *session) unlockLifecycle() {
	<-ss.lifecycle
}

func (ss *session) syncResponsePersistence() bool {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return ss.persistSyncResponse
}

func (ss *session) setSyncResponsePersistence(enabled bool) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.persistSyncResponse = enabled
}

func (ss *session) setHostClaim(claim bool) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.hostClaim = claim
}

// holdsHost reports whether the session has or may still have something on the host, which
// outlives the intent: after a Down the run still holds it until its goroutine ends. It stays
// true across an MDM restart, for which the goroutine ends on the way to the next one.
func (ss *session) holdsHost() bool {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return ss.hostClaim || ss.goroutineAliveLocked() || ss.restartKeepsRunLocked()
}

// takeAccountPrompt returns the account prompt flag and clears it.
func (ss *session) takeAccountPrompt() bool {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	prompt := ss.forceAccountPrompt
	ss.forceAccountPrompt = false
	return prompt
}

func (ss *session) armAccountPrompt() {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.forceAccountPrompt = true
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
	ss.refusal = nil
}

// recordRefusal reports false when the daemon no longer wants the session up, and a Down has
// already said all there is to say about it.
func (ss *session) recordRefusal(refusal internal.SessionRefusal) bool {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if !ss.clientRunning {
		return false
	}
	ss.refusal = &refusal
	return true
}

func (ss *session) currentRefusal() *internal.SessionRefusal {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return ss.refusal
}

// beginRun records the intent to be connected for the profile key with config and returns
// the channels for the connectWithRetryRuns goroutine the caller is about to start.
func (ss *session) beginRun(key profilemanager.SessionKey, config *profilemanager.Config) (running, giveUp chan struct{}) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.runKey = key
	ss.runConfig = config
	ss.clientRunning = true
	ss.refusal = nil
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
// client, so it can belong to another profile than the client: an operation on the
// connection uses connectionConfig instead. A caller that uses it more than once takes one
// snapshot, so a concurrent swap cannot mix the fields of two configs.
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

// connectionConfig returns the config of what the status recorder and the published client
// describe: the run, when another profile than the selected one has one, and the selected
// config otherwise. Without a switch during a run it is always currentConfig.
func (ss *session) connectionConfig() *profilemanager.Config {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if ss.runConfig != nil && ss.otherProfileRunsLocked() {
		return ss.runConfig
	}
	return ss.config
}

// otherProfileRunKey returns the profile of a run or a published client, if that is another
// one than the selected profile. A flow from the selected config would then hand its token
// to the wrong engine.
func (ss *session) otherProfileRunKey() (profilemanager.SessionKey, bool) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return ss.runKey, ss.otherProfileRunsLocked()
}

func (ss *session) otherProfileRunsLocked() bool {
	if sameSessionProfile(ss.configKey, ss.runKey) {
		return false
	}
	// A client stays published after its goroutine gave up, until a Down clears it.
	return ss.connectClient != nil || (ss.clientRunning && (ss.goroutineAliveLocked() || ss.restartKeepsRunLocked()))
}

// configOfFlow returns the config a login with the token of flow belongs to: the flow's, if
// the selection moved away from its profile while the IdP was being polled.
func (ss *session) configOfFlow(flow oauthAuthFlow) *profilemanager.Config {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if sameSessionProfile(ss.configKey, flow.key) {
		return ss.config
	}
	return flow.config
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

// focusedSession returns the session an RPC without a selector acts on. A caller that uses
// it more than once takes one snapshot, so it cannot mix the state of two sessions.
func (s *Server) focusedSession() *session {
	return s.focused.Load()
}
