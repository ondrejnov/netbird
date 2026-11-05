package server

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/hostcoord"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
)

// ensureSessionWatcher starts the watcher of the session expiry of ss, once. The caller holds
// s.mutex.
func (s *Server) ensureSessionWatcher(ss *session) {
	if ss.sessionWatcher != nil {
		return
	}
	ss.sessionWatcher = internal.NewSessionWatcher(s.rootCtx, ss.statusRecorder)
	ss.sessionWatcher.SetOnExpireListener(func() { s.onSessionExpire(ss) })
}

// concurrentStart is what startConcurrent found about the focused session.
type concurrentStart struct {
	ss             *session
	config         *profilemanager.Config
	existingConfig bool
	// firstStart says there were no stored sessions, as on the first start with the gate. The
	// daemon connected the active profile until now, and keeps doing so that once.
	firstStart bool
}

// startConcurrent is Start with the gate.
func (s *Server) startConcurrent() error {
	if err := checkConcurrentProfilesPlatform(runtime.GOOS); err != nil {
		return err
	}

	s.mutex.Lock()
	if s.slots != nil {
		s.mutex.Unlock()
		return nil
	}
	start, err := s.prepareConcurrentStart()
	s.mutex.Unlock()
	if err != nil {
		return err
	}

	s.restoreSessions(start)
	return nil
}

// prepareConcurrentStart brings up the sessions file and the services of the daemon and makes
// the active profile the focused session. The caller holds s.mutex.
func (s *Server) prepareConcurrentStart() (concurrentStart, error) {
	if _, err := s.profileManager.CopyDefaultProfileIfNotExists(); err != nil && !errors.Is(err, profilemanager.ErrorOldDefaultConfigNotFound) {
		return concurrentStart{}, err
	}

	activeProf, err := s.profileManager.GetActiveProfileState()
	if err != nil {
		return concurrentStart{}, fmt.Errorf("failed to get active profile state: %w", err)
	}

	stored, err := hostcoord.StoredRecords(profilemanager.DefaultConfigPathDir)
	if err != nil {
		return concurrentStart{}, fmt.Errorf("read stored sessions: %w", err)
	}

	// Ahead of the residual cleanup: migrating to slots reads the state files as they are.
	slots, err := s.openSlots(profilemanager.DefaultConfigPathDir, activeProf.SessionKey())
	if err != nil {
		return concurrentStart{}, fmt.Errorf("open stored sessions: %w", err)
	}
	s.slots = slots
	s.host = internal.NewDaemonHost(slots)
	context.AfterFunc(s.rootCtx, func() {
		if err := slots.Close(); err != nil {
			log.Debugf("close stored sessions: %v", err)
		}
	})

	key := sessionKeyOf(activeProf.ID, activeProf.Username)
	ss := s.focusedSession()
	ss.key = key
	s.sessions[key] = ss

	s.startDaemonServices(ss)

	// A session interface the cleanup could not take away carries peers no session answers for (I6).
	if err := s.verifySessionLinks(slots.Records()); err != nil {
		s.slots = nil
		s.host = nil
		if closeErr := slots.Close(); closeErr != nil {
			log.Debugf("close stored sessions: %v", closeErr)
		}
		return concurrentStart{}, fmt.Errorf("residual session interface: %w", err)
	}

	state := profileStateOf(key)
	config, existingConfig, err := s.getConfig(state)
	if err != nil {
		log.Errorf("failed to get active profile config: %v", err)
		return concurrentStart{}, err
	}
	ss.setConfig(key, config)
	ss.statusRecorder.UpdateManagementAddress(config.ManagementURL.String())
	ss.statusRecorder.UpdateRosenpass(config.RosenpassEnabled, config.RosenpassPermissive)
	s.localMetrics.Reconcile(config.LocalMetricsEnabled, config.LocalMetricsAddress)
	s.ensureSessionWatcher(ss)

	return concurrentStart{ss: ss, config: config, existingConfig: existingConfig, firstStart: len(stored) == 0}, nil
}

// restoreSessions brings back the sessions that were up when the daemon went away, the focused
// one first. A session that cannot come back stays down and leaves the others alone.
func (s *Server) restoreSessions(start concurrentStart) {
	records := s.slots.Records()

	focusedWanted := start.firstStart
	for _, record := range records {
		if record.Key == start.ss.key {
			focusedWanted = focusedWanted || record.Desired == hostcoord.DesiredUp
		}
	}
	s.restoreFocusedSession(start, focusedWanted)

	for _, record := range records {
		if record.Key == start.ss.key || record.Desired != hostcoord.DesiredUp {
			continue
		}
		if err := s.restoreSession(record.Key); err != nil {
			log.Errorf("failed to restore the session of profile %s: %v", record.Key.Profile, err)
		}
	}
}

func (s *Server) restoreFocusedSession(start concurrentStart, wanted bool) {
	ss := start.ss
	switch {
	case start.config.DisableAutoConnect:
		ss.state.Set(internal.StatusIdle)
		return
	case !start.existingConfig:
		log.Warnf("not trying to connect when configuration was just created")
		ss.state.Set(internal.StatusNeedsLogin)
		return
	case !wanted:
		return
	}

	err := s.lockedLaunch(s.rootCtx, ss, sessionLaunch{
		resolve: func() (*profilemanager.Config, error) { return start.config, nil },
		source:  proto.MetadataSourceStartup,
	})
	if err != nil {
		log.Errorf("failed to restore the session of profile %s: %v", ss.key.Profile, err)
	}
}

// restoreSession brings back a session that is not focused. Its config is read as stored,
// without provisioning: the profile can be gone, and a new identity would bring it back.
func (s *Server) restoreSession(key profilemanager.SessionKey) error {
	config, err := s.storedRunningConfig(key)
	if err != nil {
		return err
	}
	if config.DisableAutoConnect {
		return nil
	}

	s.mutex.Lock()
	ss := s.sessionOfLocked(sessionKeyOf(key.Profile, key.Username))
	s.mutex.Unlock()

	return s.lockedLaunch(s.rootCtx, ss, sessionLaunch{
		resolve: func() (*profilemanager.Config, error) { return config, nil },
		source:  proto.MetadataSourceStartup,
	})
}

func (s *Server) lockedLaunch(ctx context.Context, ss *session, launch sessionLaunch) error {
	if err := ss.lockLifecycle(ctx); err != nil {
		return err
	}
	defer ss.unlockLifecycle()
	return s.launchSession(ctx, ss, launch)
}

// sessionLaunch describes a run launchSession starts.
type sessionLaunch struct {
	md      metadata.MD
	resolve func() (*profilemanager.Config, error)
	source  string
}

// launchSession starts a run of ss, next to whatever else runs. Only the steps that decide or
// publish hold s.mutex. Reading the config and cleaning the residual state run with the session
// claiming the host, so that an Up of another session counts it. The caller holds the lifecycle
// of ss and not s.mutex.
func (s *Server) launchSession(ctx context.Context, ss *session, launch sessionLaunch) error {
	if err := s.refuseUnsupportedRuntime(); err != nil {
		return err
	}

	s.mutex.Lock()
	if s.sessions[ss.key] != ss {
		s.mutex.Unlock()
		return fmt.Errorf("profile %s was removed", ss.key.Profile)
	}
	others, err := s.admitSessionLocked(ss)
	if err != nil {
		s.mutex.Unlock()
		return err
	}
	ss.setHostClaim(true)
	s.mutex.Unlock()
	defer ss.setHostClaim(false)

	config, err := launch.resolve()
	if err != nil {
		log.Errorf("failed to get profile config: %v", err)
		return fmt.Errorf("failed to get profile config: %w", err)
	}

	if err := s.storeDesiredUp(ss.key); err != nil {
		return err
	}

	s.restoreLaunchResidual(ctx, ss, others)

	s.mutex.Lock()
	defer s.mutex.Unlock()

	ss.setConfig(ss.key, config)
	ss.statusRecorder.UpdateManagementAddress(config.ManagementURL.String())
	ss.statusRecorder.UpdateRosenpass(config.RosenpassEnabled, config.RosenpassPermissive)
	if s.focusedSession() == ss {
		s.localMetrics.Reconcile(config.LocalMetricsEnabled, config.LocalMetricsAddress)
	}
	s.ensureSessionWatcher(ss)

	// A successful WaitSSOLogin leaves NeedsLogin behind, see the Up without the gate.
	if ss.state.CurrentStatus() == internal.StatusNeedsLogin {
		ss.state.Set(internal.StatusIdle)
	}

	// it should be nil here, but in case it isn't we cancel it.
	ss.cancelAct()
	runCtx, cancel := ss.runContext(s.rootCtx)
	if launch.md != nil {
		runCtx = metadata.NewOutgoingContext(runCtx, launch.md)
	}
	ss.setActCancel(cancel)

	runningChan, giveUpChan := ss.beginRun(ss.key, config)
	go s.connectWithRetryRuns(runCtx, ss, ss.key, config, runningChan, giveUpChan)
	s.publishConfigChangedEvent(ss, launch.source)
	return nil
}

// storeDesiredUp puts the session on record before it runs. A session the daemon would not
// bring back after a crash is refused: that is a promise the record exists to keep.
func (s *Server) storeDesiredUp(key profilemanager.SessionKey) error {
	if _, err := s.slots.Ensure(key); err != nil {
		return fmt.Errorf("store the slot of the session: %w", err)
	}
	if err := s.slots.SetDesired(key, hostcoord.DesiredUp); err != nil {
		return fmt.Errorf("store the desired state of the session: %w", err)
	}
	return nil
}

// restoreLaunchResidual cleans what the profile left on the host. Its state records host names
// another session can be using by now, so it is left in the file while one runs.
func (s *Server) restoreLaunchResidual(ctx context.Context, ss *session, others int) {
	if others > 0 {
		log.Debugf("leaving the residual state of profile %s, another session is running", ss.key.Profile)
		return
	}
	if err := s.restoreResidualAlone(ctx, ss.key); err != nil {
		log.Warnf(errRestoreResidualState, err)
	}
}

// restoreLoginResidualConcurrent is restoreLoginResidual with the gate, without s.mutex held
// across the cleanup. A session that is not alone leaves its state in the file, as a launch does.
func (s *Server) restoreLoginResidualConcurrent(ctx context.Context, ss *session, key profilemanager.SessionKey, cancelled <-chan struct{}) error {
	if err := ss.lockLifecycle(ctx); err != nil {
		return err
	}
	defer ss.unlockLifecycle()

	s.mutex.Lock()
	running, ok := ss.runningKey()
	_, giveUp := ss.runChans()
	if (ok && giveUp != cancelled && sameSessionProfile(running, key)) || s.otherHostHoldersLocked(ss) > 0 {
		s.mutex.Unlock()
		return nil
	}
	ss.setHostClaim(true)
	s.mutex.Unlock()
	defer ss.setHostClaim(false)

	return s.restoreResidualAlone(ctx, key)
}

// claimHostAlone keeps a cleanup of the state of ss away from any other session, whose host
// resources the state can name, until the returned func runs. Without the gate there is no other.
func (s *Server) claimHostAlone(ctx context.Context, ss *session) (func(), error) {
	if !s.concurrentProfiles {
		return func() {}, nil
	}
	if err := ss.lockLifecycle(ctx); err != nil {
		return nil, err
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.otherHostHoldersLocked(ss) > 0 {
		ss.unlockLifecycle()
		return nil, gstatus.Error(codes.FailedPrecondition, "cannot clean state while another session is running, bring it down first")
	}
	ss.setHostClaim(true)
	return func() {
		ss.setHostClaim(false)
		ss.unlockLifecycle()
	}, nil
}

// upTargetKey returns the profile an Up with the gate is for: the one it names, or the focused
// one. The profiles kill switch keeps guarding what a switch used to do.
func (s *Server) upTargetKey(msg *proto.UpRequest) (profilemanager.SessionKey, error) {
	focused := s.focusedSession().key
	if msg == nil || msg.ProfileName == nil {
		return focused, nil
	}

	resolved, username, err := s.resolveNamedProfile(*msg.ProfileName, msg.Username)
	if err != nil {
		return profilemanager.SessionKey{}, err
	}
	key := sessionKeyOf(resolved.ID, username)
	if key != focused && s.checkProfilesDisabled() {
		return profilemanager.SessionKey{}, profilesDisabledError()
	}
	return key, nil
}

// upConcurrent is Up with the gate: it starts the session of the requested profile, or joins the
// run it has, and touches neither the focus nor the other sessions.
func (s *Server) upConcurrent(callerCtx context.Context, msg *proto.UpRequest) (*proto.UpResponse, error) {
	key, err := s.upTargetKey(msg)
	if err != nil {
		return nil, err
	}

	s.mutex.Lock()
	ss := s.sessionOfLocked(key)
	s.mutex.Unlock()

	return s.upSession(callerCtx, ss, msg.GetAsync())
}

func (s *Server) upSession(callerCtx context.Context, ss *session, async bool) (*proto.UpResponse, error) {
	if err := s.lockForStart(callerCtx, ss); err != nil {
		return nil, err
	}
	wait, err := s.upSessionLocked(callerCtx, ss, async)
	ss.unlockLifecycle()
	if err != nil {
		return nil, err
	}
	if !wait {
		return &proto.UpResponse{}, nil
	}
	return s.waitForUp(callerCtx, ss)
}

// upSessionLocked is called with the lifecycle of ss and s.mutex held, and releases s.mutex.
// It reports whether the caller is to wait for the connection.
func (s *Server) upSessionLocked(callerCtx context.Context, ss *session, async bool) (bool, error) {
	status, err := ss.state.Status()
	if err != nil {
		s.mutex.Unlock()
		return false, err
	}

	if ss.isClientRunning() && ss.connectionGoroutineRunning() {
		if status == internal.StatusNeedsLogin {
			ss.cancelAct()
		}
		s.mutex.Unlock()
		return true, nil
	}
	s.mutex.Unlock()

	if status != internal.StatusIdle && status != internal.StatusNeedsLogin {
		return false, fmt.Errorf("up already in progress: current status %s", status)
	}

	md, _ := metadata.FromIncomingContext(callerCtx)
	err = s.launchSession(callerCtx, ss, sessionLaunch{
		md: md,
		resolve: func() (*profilemanager.Config, error) {
			config, _, err := s.getConfig(profileStateOf(ss.key))
			return config, err
		},
		source: proto.MetadataSourceUpRPC,
	})
	if err != nil {
		return false, err
	}
	return !async, nil
}

// downConcurrent is Down with the gate. The sessions it takes down stay down after a restart.
func (s *Server) downConcurrent(ctx context.Context, msg *proto.DownRequest) (*proto.DownResponse, error) {
	targets := []*session{s.focusedSession()}
	if msg.GetAll() {
		targets = s.allSessions()
	}

	for _, ss := range targets {
		s.markDesired(ss, hostcoord.DesiredDown)
	}
	if err := s.downSessions(ctx, targets); err != nil {
		return nil, err
	}
	return &proto.DownResponse{}, nil
}

// downSessions takes the sessions down side by side. It reports ErrServiceNotUp only when none
// of them was up.
func (s *Server) downSessions(ctx context.Context, targets []*session) error {
	var mu sync.Mutex
	var wasUp bool
	err := s.forEachSession(targets, func(ss *session) error {
		err := s.downSession(ctx, ss)
		if errors.Is(err, ErrServiceNotUp) {
			return nil
		}
		mu.Lock()
		wasUp = true
		mu.Unlock()
		return err
	})
	if err == nil && !wasUp {
		return ErrServiceNotUp
	}
	return err
}

// StopSessions ends the runs of all sessions for a service stop. Unlike a Down it leaves the
// desired states as they are, so that the sessions come back with the service.
func (s *Server) StopSessions(ctx context.Context) error {
	if !s.concurrentProfiles {
		_, err := s.Down(ctx, &proto.DownRequest{})
		return err
	}
	return s.downSessions(ctx, s.allSessions())
}

// sleepStatus reports whether any session is worth taking down for a system sleep.
func (s *Server) sleepStatus() internal.StatusType {
	for _, ss := range s.allSessions() {
		if status := ss.state.CurrentStatus(); status == internal.StatusConnected || status == internal.StatusConnecting {
			return status
		}
	}
	return internal.StatusIdle
}

// sleepSessions takes down the sessions that are connected or connecting, and returns those that
// went down. It fails only when none did, as the others still have to come back on wake up.
func (s *Server) sleepSessions(ctx context.Context) ([]*session, error) {
	var targets []*session
	for _, ss := range s.allSessions() {
		if status := ss.state.CurrentStatus(); status == internal.StatusConnected || status == internal.StatusConnecting {
			targets = append(targets, ss)
		}
	}

	var mu sync.Mutex
	var slept []*session
	err := s.forEachSession(targets, func(ss *session) error {
		if err := s.downSession(ctx, ss); err != nil && !errors.Is(err, ErrServiceNotUp) {
			return err
		}
		mu.Lock()
		slept = append(slept, ss)
		mu.Unlock()
		return nil
	})
	if err != nil && len(slept) > 0 {
		log.Errorf("failed to take all sessions down for sleep: %v", err)
		err = nil
	}
	return slept, err
}

// wakeSessions brings back what sleepSessions took down. A session that fails leaves the others.
func (s *Server) wakeSessions(ctx context.Context, sessions []*session) error {
	return s.forEachSession(sessions, func(ss *session) error {
		_, err := s.upSession(ctx, ss, false)
		return err
	})
}
