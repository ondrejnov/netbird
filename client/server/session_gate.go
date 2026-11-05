package server

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	nberrors "github.com/netbirdio/netbird/client/errors"
	"github.com/netbirdio/netbird/client/iface/netstack"
	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/auth"
	"github.com/netbirdio/netbird/client/internal/hostcoord"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/internal/updater"
	nbnet "github.com/netbirdio/netbird/client/net"
	"github.com/netbirdio/netbird/client/proto"
)

// defaultMaxSessions is the limit of sessions running at once, see WithMaxSessions.
const defaultMaxSessions uint32 = 4

const concurrentProfilesOS = "linux"

const errSelectorNotFocused = "the session selector does not name the focused session"

// Option changes how New builds a Server.
type Option func(*Server)

// WithMaxSessions sets the limit of sessions running at once, 0 means no limit.
func WithMaxSessions(limit uint32) Option {
	return func(s *Server) {
		s.maxSessions = limit
	}
}

// sessionSet is what the feature gate adds to Server. Without the gate sessions stays empty
// and the one session is the focused one.
type sessionSet struct {
	// concurrentProfiles is the feature gate. It is fixed for the life of the daemon.
	concurrentProfiles bool
	maxSessions        uint32

	// sessions holds the session of each profile seen since the start, by normalized key.
	// Guarded by Server.mutex. A session stays until its profile is removed.
	sessions map[profilemanager.SessionKey]*session

	// updateHolder is the session whose run drives the updater, nil when none does.
	updateHolder *atomic.Pointer[session]

	// slots stores the slots and the desired states. Set once by the start.
	slots *hostcoord.Slots

	// host is what the sessions share on the host. Set once by the start.
	host *internal.DaemonHost

	// connectFn stands in for a client run, stopEngineFn for stopping an engine,
	// advancedRoutingFn for the routing probe, and removeLinksFn and verifyLinksFn for the session
	// links of the host. Tests set them; production leaves them nil.
	connectFn         func(ctx context.Context, ss *session, key profilemanager.SessionKey, config *profilemanager.Config, runningChan chan struct{}) error
	stopEngineFn      func(engine *internal.Engine) error
	advancedRoutingFn func() bool
	removeLinksFn     func(records []hostcoord.SlotRecord) error
	verifyLinksFn     func(records []hostcoord.SlotRecord) error

	// lookupUIDFn stands in for the account database of the host. Tests set it; production
	// leaves it nil.
	lookupUIDFn func(username string) (uint32, error)
}

func newSessionSet(concurrentProfiles bool) sessionSet {
	set := sessionSet{concurrentProfiles: concurrentProfiles, maxSessions: defaultMaxSessions, updateHolder: &atomic.Pointer[session]{}}
	if concurrentProfiles {
		set.sessions = make(map[profilemanager.SessionKey]*session)
	}
	return set
}

// clientOptions binds a client to its profile and, with the gate, to its share of the host.
func (s *Server) clientOptions(ss *session, key profilemanager.SessionKey) []internal.ConnectClientOption {
	opts := []internal.ConnectClientOption{internal.WithSessionKey(key)}
	if s.concurrentProfiles {
		opts = append(opts, internal.WithSessionHost(s.host.Session(key, ss.statusRecorder)))
	}
	return opts
}

// newAuth returns the client of a login with the Management of config. With the gate the system info
// it sends leaves out the addresses of all sessions (I5).
func (s *Server) newAuth(ctx context.Context, config *profilemanager.Config) (*auth.Auth, error) {
	var opts []auth.Option
	if s.host != nil {
		opts = append(opts, auth.WithInfoFilter(s.host.ExcludeSessionAddresses))
	}
	return auth.NewAuth(ctx, config.PrivateKey, config.ManagementURL, config, opts...)
}

// controlsUpdates reports whether Management may drive the updater through this session. The
// updater acts on the whole machine, so only the focused session does (5.4).
func (s *Server) controlsUpdates(ss *session) bool {
	return !s.concurrentProfiles || s.focusedSession() == ss
}

// claimUpdates returns the update manager for a run of ss, nil when the run must not drive it, and
// what the run calls when it ends. The focus is read when the run starts and a run keeps what it
// got (5.4), so a run that lost the focus can still hold the updater. Until it ends nobody else gets
// it, as two networks would otherwise take turns telling one machine what to install.
func (s *Server) claimUpdates(ss *session) (*updater.Manager, func()) {
	if !s.concurrentProfiles {
		return s.updateManager, func() {
			// Nothing to release: the one session always drives the updater.
		}
	}
	if !s.controlsUpdates(ss) || !s.updateHolder.CompareAndSwap(nil, ss) {
		return nil, func() {
			// Nothing to release: this run got no updater.
		}
	}
	return s.updateManager, func() { s.updateHolder.CompareAndSwap(ss, nil) }
}

// checkConcurrentProfilesPlatform refuses the gate on a platform whose host resources do not
// know about sessions.
func checkConcurrentProfilesPlatform(goos string) error {
	if goos != concurrentProfilesOS {
		return fmt.Errorf("concurrent profiles are supported only on Linux, not on %s: reinstall the service without --enable-concurrent-profiles", goos)
	}
	return nil
}

// refuseUnsupportedRuntime refuses a session in a mode where the invariants of concurrent
// sessions cannot hold. It is decided at every start, for the first session as well: which
// sessions run next to it changes later without another check.
func (s *Server) refuseUnsupportedRuntime() error {
	if netstack.IsEnabled() {
		return gstatus.Errorf(codes.FailedPrecondition, "concurrent profiles do not support netstack mode (%s)", netstack.EnvUseNetstackMode)
	}
	if !s.advancedRouting() {
		return gstatus.Error(codes.FailedPrecondition, "concurrent profiles need advanced routing, and this host runs legacy routing")
	}
	if profilemanager.StateFileOverridden() {
		return gstatus.Error(codes.FailedPrecondition, "concurrent profiles do not support NB_DNS_STATE_FILE, which gives all sessions one state file")
	}
	return nil
}

func (s *Server) advancedRouting() bool {
	if s.advancedRoutingFn != nil {
		return s.advancedRoutingFn()
	}
	return nbnet.AdvancedRouting()
}

// stopEngine stops engine, which can be nil when the client did not get to create one.
func (s *Server) stopEngine(engine *internal.Engine) error {
	if s.stopEngineFn != nil {
		return s.stopEngineFn(engine)
	}
	if engine == nil {
		return nil
	}
	return engine.Stop()
}

// sessionKeyOf returns the map key of a profile. The default profile is shared by every user.
func sessionKeyOf(id profilemanager.ID, username string) profilemanager.SessionKey {
	if id == profilemanager.DefaultProfileName {
		username = ""
	}
	return profilemanager.SessionKey{Profile: id, Username: username}
}

// sessionOfLocked returns the session of key, creating it when the profile has none yet. The
// caller holds s.mutex.
func (s *Server) sessionOfLocked(key profilemanager.SessionKey) *session {
	if ss, ok := s.sessions[key]; ok {
		return ss
	}
	ss := newSession()
	ss.bindKey(key)
	ss.state.SetOnChange(ss.statusRecorder.NotifyStateChange)
	s.sessions[key] = ss
	return ss
}

// allSessions returns a snapshot of the sessions, in a stable order.
func (s *Server) allSessions() []*session {
	if !s.concurrentProfiles {
		return []*session{s.focusedSession()}
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()
	sessions := make([]*session, 0, len(s.sessions))
	for _, ss := range s.sessions {
		sessions = append(sessions, ss)
	}
	slices.SortFunc(sessions, func(a, b *session) int {
		if c := strings.Compare(a.key.Username, b.key.Username); c != 0 {
			return c
		}
		return strings.Compare(string(a.key.Profile), string(b.key.Profile))
	})
	return sessions
}

// forEachSession runs fn for each session side by side, so that a slow one does not hold up
// the others, and an error of one does not stop them.
func (s *Server) forEachSession(sessions []*session, fn func(ss *session) error) error {
	if len(sessions) == 1 {
		return fn(sessions[0])
	}

	var mu sync.Mutex
	var merr *multierror.Error
	var wg sync.WaitGroup
	for _, ss := range sessions {
		wg.Add(1)
		go func(ss *session) {
			defer wg.Done()
			if err := fn(ss); err != nil {
				mu.Lock()
				merr = multierror.Append(merr, err)
				mu.Unlock()
			}
		}(ss)
	}
	wg.Wait()
	return nberrors.FormatErrorOrNil(merr)
}

// otherHostHoldersLocked counts the sessions other than ss that have something on the host.
// The caller holds s.mutex.
func (s *Server) otherHostHoldersLocked(ss *session) int {
	var others int
	for _, other := range s.sessions {
		if other != ss && other.holdsHost() {
			others++
		}
	}
	return others
}

// admitSessionLocked is the only check of the session limit. It returns how many other sessions
// hold the host. The caller holds s.mutex.
func (s *Server) admitSessionLocked(ss *session) (int, error) {
	others := s.otherHostHoldersLocked(ss)
	if s.maxSessions > 0 && uint32(others) >= s.maxSessions {
		return others, gstatus.Errorf(codes.ResourceExhausted, "the limit of %d concurrent sessions is reached, bring a session down first", s.maxSessions)
	}
	return others, nil
}

// admitRestartLocked keeps an MDM restart from bringing back a run that gave up, when other
// sessions have taken its place up to the limit. Such a run stays ended.
func (s *Server) admitRestartLocked(ss *session) error {
	if !s.concurrentProfiles {
		return nil
	}
	if _, err := s.admitSessionLocked(ss); err != nil {
		ss.markClientDown()
		return err
	}
	return nil
}

// refreshIdleSessionConfig renews the config of a session an MDM change finds with no run. The
// kill switches read the policy from it, and with other sessions running the change is real.
func (s *Server) refreshIdleSessionConfig(ss *session) {
	if s.concurrentProfiles {
		s.refreshSelectedConfig(ss)
	}
}

// loginTarget returns the session a login is for: the one it names, or the focused one. It leaves
// the focus alone, and the profiles kill switch keeps guarding what a switch used to do.
func (s *Server) loginTarget(ctx context.Context, msg *proto.LoginRequest) (*session, error) {
	if !s.concurrentProfiles || msg.ProfileName == nil {
		return s.checkSessionSelector(ctx, nil)
	}

	ss, err := s.namedSession(s.callerOf(ctx), *msg.ProfileName, msg.GetUsername())
	if err != nil {
		return nil, err
	}
	if ss != s.focusedSession() && s.checkProfilesDisabled() {
		return nil, profilesDisabledError()
	}
	return ss, nil
}

// loginProfileState returns the profile a login is for.
func (s *Server) loginProfileState(ss *session) (*profilemanager.ActiveProfileState, error) {
	if s.concurrentProfiles {
		return profileStateOf(ss.key), nil
	}
	activeProf, err := s.profileManager.GetActiveProfileState()
	if err != nil {
		return nil, fmt.Errorf("failed to get active profile state: %w", err)
	}
	return activeProf, nil
}

// logoutTarget returns the session a logout decides about.
func (s *Server) logoutTarget(ctx context.Context, msg *proto.LogoutRequest) (*session, error) {
	if !s.concurrentProfiles {
		return s.focusedSession(), nil
	}
	if msg.ProfileName == nil || *msg.ProfileName == "" || msg.Username == nil || *msg.Username == "" {
		return s.checkSessionSelector(ctx, nil)
	}
	return s.namedSession(s.callerOf(ctx), *msg.ProfileName, msg.GetUsername())
}

// requireLogoutTarget refuses a logout whose handle no longer resolves to the session it was checked
// against: a profile added or renamed in between can move a handle. It would deregister one peer and
// clear the login of another session.
func (s *Server) requireLogoutTarget(target *session, id profilemanager.ID, username string) error {
	if s.concurrentProfiles && target.key != sessionKeyOf(id, username) {
		return gstatus.Error(codes.FailedPrecondition, "the profile changed during the logout, try again")
	}
	return nil
}

// clearLoggedOutSession leaves nothing of the login of ss behind, focused or not (I9). The flows go
// first: the connection cleanup clears the login flow without ending the wait on it.
func (s *Server) clearLoggedOutSession(ss *session) {
	s.mutex.Lock()
	s.dropPendingAuthFlows(ss)
	s.mutex.Unlock()

	if err := s.cleanupConnection(ss); err != nil && !errors.Is(err, ErrServiceNotUp) {
		log.Errorf("failed to cleanup connection: %v", err)
	}
	ss.isSessionActive.Store(false)
	ss.state.Set(internal.StatusNeedsLogin)
}

// refuseLogoutOfRunningSession keeps a deregistration from pulling the peer out from under a
// run, which has to be brought down first. The caller holds the lifecycle of ss.
func (s *Server) refuseLogoutOfRunningSession(ss *session) error {
	if s.concurrentProfiles && ss.holdsHost() {
		return gstatus.Error(codes.FailedPrecondition, "the session is running, bring it down first")
	}
	return nil
}

// markDesired stores whether the session comes back after a daemon restart. A failure costs
// only that, it does not undo what the user asked for.
func (s *Server) markDesired(ss *session, desired hostcoord.DesiredState) {
	if !s.concurrentProfiles {
		return
	}
	if err := s.slots.SetDesired(ss.key, desired); err != nil && !errors.Is(err, hostcoord.ErrUnknownSession) {
		log.Warnf("failed to store the desired state of profile %s: %v", ss.key.Profile, err)
	}
}

// removeProfileConcurrent is RemoveProfile with the gate: the deregistration is a network call,
// which runs under the lifecycle of the session and not under s.mutex.
func (s *Server) removeProfileConcurrent(ctx context.Context, msg *proto.RemoveProfileRequest) (*proto.RemoveProfileResponse, error) {
	if s.checkProfilesDisabled() {
		return nil, profilesDisabledError()
	}
	if msg.ProfileName == "" {
		return nil, gstatus.Errorf(codes.InvalidArgument, "profile name must be provided")
	}
	if err := s.authorizeNamedProfile(ctx, msg.ProfileName, msg.Username); err != nil {
		return nil, err
	}
	resolved, err := s.resolveProfileHandle(msg.ProfileName, msg.Username)
	if err != nil {
		return nil, err
	}

	key := sessionKeyOf(resolved.ID, msg.Username)
	s.mutex.Lock()
	ss := s.sessionOfLocked(key)
	s.mutex.Unlock()

	if err := ss.lockLifecycle(ctx); err != nil {
		return nil, err
	}
	defer ss.unlockLifecycle()

	// Ahead of the deregistration, which cannot be undone.
	if ss.holdsHost() {
		return nil, gstatus.Errorf(codes.FailedPrecondition, "profile %q is running, bring the connection down first", msg.ProfileName)
	}

	if err := s.logoutFromProfile(ctx, resolved, msg.Username); err != nil {
		log.Warnf("removing profile %s locally without deregistering it: %v", resolved.ID, err)
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	if err := s.profileManager.RemoveProfile(resolved.ID, msg.Username); err != nil {
		log.Errorf("failed to remove profile: %v", err)
		return nil, fmt.Errorf("failed to remove profile: %w", err)
	}
	delete(s.sessions, key)
	s.stopBundleCaptureLocked(ss)
	s.cleanupBundleCapture(ss)
	if err := s.slots.Remove(key); err != nil {
		log.Warnf("failed to free the slot of profile %s: %v", resolved.ID, err)
	}

	s.publishProfileListChanged(msg.ProfileName)

	return &proto.RemoveProfileResponse{Id: resolved.ID.String()}, nil
}

// switchFocus is SwitchProfile with the gate: it changes which session the RPCs without a
// selector act on, and leaves every session as it is. The focus follows the active profile file,
// which is why the file is written only once the new session has a config to answer with.
func (s *Server) switchFocus(ctx context.Context, msg *proto.SwitchProfileRequest) (*proto.SwitchProfileResponse, error) {
	if msg != nil && msg.ProfileName != nil {
		if err := s.authorizeNamedProfile(ctx, *msg.ProfileName, msg.GetUsername()); err != nil {
			return nil, err
		}
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	previous := s.focusedSession()
	key := previous.key

	if msg != nil && msg.ProfileName != nil {
		resolved, username, err := s.resolveNamedProfile(*msg.ProfileName, msg.Username)
		if err != nil {
			log.Errorf("failed to switch profile: %v", err)
			return nil, err
		}
		key = sessionKeyOf(resolved.ID, username)
		if key != previous.key && s.checkProfilesDisabled() {
			return nil, profilesDisabledError()
		}
	}

	target := profileStateOf(key)
	config, _, err := s.getConfig(target)
	if err != nil {
		log.Errorf("failed to get profile config: %v", err)
		return nil, fmt.Errorf("failed to get profile config: %w", err)
	}

	if key != previous.key {
		log.Infof("switching focus to profile %s for user %s", key.Profile, key.Username)
		if err := s.profileManager.SetActiveProfileState(target); err != nil {
			log.Errorf("failed to set active profile state: %v", err)
			return nil, fmt.Errorf("failed to set active profile state: %w", err)
		}
	}

	ss := s.sessionOfLocked(key)
	ss.setConfig(key, config)
	s.focused.Store(ss)
	s.localMetrics.Reconcile(config.LocalMetricsEnabled, config.LocalMetricsAddress)
	if ss != previous {
		// A status stream without a selector follows the focus, and hears of it from here.
		previous.statusRecorder.NotifyStateChange()
	}

	if msg != nil && msg.ProfileName != nil {
		// A subscriber hears it on the recorder of the previous focus before it moves on.
		s.publishProfileListChangedOn(previous, *msg.ProfileName)
		if ss != previous {
			s.publishProfileListChangedOn(ss, *msg.ProfileName)
		}
	}

	return &proto.SwitchProfileResponse{Id: key.Profile.String()}, nil
}

// sessionStatuses describes the sessions the caller may read that have something to report, along
// with the focused one and target, which the response is about. targetStatus is what the response
// already says about target.
func (s *Server) sessionStatuses(caller sessionCaller, target *session, targetStatus internal.StatusType, full bool) []*proto.SessionStatus {
	focused := s.focusedSession()

	var statuses []*proto.SessionStatus
	for _, ss := range s.allSessions() {
		if !caller.mayReach(ss.key) {
			continue
		}

		status := ss.state.CurrentStatus()
		holdsHost := ss.holdsHost()
		if ss == target {
			status = targetStatus
		} else if isQuietSession(ss, focused) {
			continue
		}

		entry := &proto.SessionStatus{
			ProfileId:   ss.key.Profile.String(),
			ProfileName: s.profileDisplayName(ss.key),
			Status:      string(status),
			Focused:     ss == focused,
			Conflict:    s.conflictOf(ss),
		}
		if holdsHost {
			if resources, running := s.slots.Running(ss.key); running {
				entry.InterfaceName = resources.Interface
			}
			entry.OverlayIp = ss.statusRecorder.GetLocalPeerState().IP
		}
		if full {
			entry.FullStatus = s.fullStatusOf(ss)
		}
		statuses = append(statuses, entry)
	}
	return statuses
}

// isQuietSession reports whether a session has nothing to report: it is not focused, holds nothing
// on the host and sits idle.
func isQuietSession(ss, focused *session) bool {
	return ss != focused && !ss.holdsHost() && !ss.isClientRunning() && ss.state.CurrentStatus() == internal.StatusIdle
}

// downTargets returns what a Down reaches: ss, or with all whatever the caller may reach. The others
// stay up, and it is not an error that they do.
func (s *Server) downTargets(ctx context.Context, ss *session, all bool) []*session {
	if !all {
		return []*session{ss}
	}

	caller := s.callerOf(ctx)
	var targets []*session
	for _, candidate := range s.allSessions() {
		if caller.mayReach(candidate.key) {
			targets = append(targets, candidate)
		}
	}
	return targets
}

func profilesDisabledError() error {
	return gstatus.Errorf(codes.Unavailable, errProfilesDisabled)
}
