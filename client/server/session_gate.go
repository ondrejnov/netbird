package server

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	nberrors "github.com/netbirdio/netbird/client/errors"
	"github.com/netbirdio/netbird/client/iface/netstack"
	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/hostcoord"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
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

	// slots stores the slots and the desired states. Set once by the start.
	slots *hostcoord.Slots

	// host is what the sessions share on the host. Set once by the start.
	host *internal.DaemonHost

	// connectFn stands in for a client run, stopEngineFn for stopping an engine and
	// advancedRoutingFn for the routing probe. Tests set them; production leaves them nil.
	connectFn         func(ctx context.Context, ss *session, key profilemanager.SessionKey, config *profilemanager.Config, runningChan chan struct{}) error
	stopEngineFn      func(engine *internal.Engine) error
	advancedRoutingFn func() bool
}

func newSessionSet(concurrentProfiles bool) sessionSet {
	set := sessionSet{concurrentProfiles: concurrentProfiles, maxSessions: defaultMaxSessions}
	if concurrentProfiles {
		set.sessions = make(map[profilemanager.SessionKey]*session)
	}
	return set
}

// clientOptions binds a client to its profile and, with the gate, to its share of the host.
func (s *Server) clientOptions(key profilemanager.SessionKey) []internal.ConnectClientOption {
	opts := []internal.ConnectClientOption{internal.WithSessionKey(key)}
	if s.concurrentProfiles {
		opts = append(opts, internal.WithSessionHost(s.host.Session(key)))
	}
	return opts
}

// controlsUpdates reports whether Management may drive the updater through this session. The
// updater acts on the whole machine, so only the focused session does (5.4).
func (s *Server) controlsUpdates(ss *session) bool {
	return !s.concurrentProfiles || s.focusedSession() == ss
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
	ss.key = key
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

// checkSessionSelector refuses a selector that names anything but the focused session, the only
// one the RPCs can reach so far. Every failure gets the same answer, so a selector does not tell
// a caller which profiles exist. No selector means the focused session.
func (s *Server) checkSessionSelector(selector *proto.SessionSelector) error {
	if selector == nil {
		return nil
	}

	refused := gstatus.Error(codes.FailedPrecondition, errSelectorNotFocused)

	focused, err := s.focusedKey()
	if err != nil {
		log.Warnf("failed to read the focused session for a session selector: %v", err)
		return refused
	}
	resolved, err := s.profileManager.ResolveProfile(selector.GetProfile(), selector.GetUsername())
	if err != nil {
		log.Debugf("failed to resolve a session selector: %v", err)
		return refused
	}
	if !isSessionProfile(focused, resolved.ID, selector.GetUsername()) {
		return refused
	}
	return nil
}

func (s *Server) focusedKey() (profilemanager.SessionKey, error) {
	if s.concurrentProfiles {
		return s.focusedSession().key, nil
	}
	active, err := s.profileManager.GetActiveProfileState()
	if err != nil {
		return profilemanager.SessionKey{}, err
	}
	return active.SessionKey(), nil
}

// loginProfileState returns the profile a login is for. With the gate a login cannot reach
// another session than the focused one: it would have to leave the focus alone, and the
// WaitSSOLogin that follows has no way to name another session yet.
func (s *Server) loginProfileState(ss *session, msg *proto.LoginRequest) (*profilemanager.ActiveProfileState, error) {
	if !s.concurrentProfiles {
		activeProf, err := s.profileManager.GetActiveProfileState()
		if err != nil {
			return nil, fmt.Errorf("failed to get active profile state: %w", err)
		}
		return activeProf, nil
	}

	if msg.ProfileName != nil {
		resolved, username, err := s.resolveNamedProfile(*msg.ProfileName, msg.Username)
		if err != nil {
			return nil, err
		}
		if !isSessionProfile(ss.key, resolved.ID, username) {
			return nil, gstatus.Errorf(codes.FailedPrecondition, "profile %q is not the focused one, select it before logging in", *msg.ProfileName)
		}
	}
	return profileStateOf(ss.key), nil
}

// logoutTarget returns the session a logout decides about.
func (s *Server) logoutTarget(msg *proto.LogoutRequest) (*session, error) {
	if !s.concurrentProfiles || msg.ProfileName == nil || *msg.ProfileName == "" || msg.Username == nil || *msg.Username == "" {
		return s.focusedSession(), nil
	}

	resolved, err := s.resolveProfileHandle(*msg.ProfileName, *msg.Username)
	if err != nil {
		return nil, err
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.sessionOfLocked(sessionKeyOf(resolved.ID, *msg.Username)), nil
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
	if err := s.slots.Remove(key); err != nil {
		log.Warnf("failed to free the slot of profile %s: %v", resolved.ID, err)
	}

	s.publishProfileListChanged(msg.ProfileName)

	return &proto.RemoveProfileResponse{Id: resolved.ID.String()}, nil
}

// switchFocus is SwitchProfile with the gate: it changes which session the RPCs without a
// selector act on, and leaves every session as it is. The focus follows the active profile file,
// which is why the file is written only once the new session has a config to answer with.
func (s *Server) switchFocus(msg *proto.SwitchProfileRequest) (*proto.SwitchProfileResponse, error) {
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

	if msg != nil && msg.ProfileName != nil {
		// A subscriber stays on the recorder it subscribed to, the one of the previous focus.
		s.publishProfileListChangedOn(previous, *msg.ProfileName)
		if ss != previous {
			s.publishProfileListChangedOn(ss, *msg.ProfileName)
		}
	}

	return &proto.SwitchProfileResponse{Id: key.Profile.String()}, nil
}

// sessionStatuses describes the sessions that have something to report, along with the focused
// one. focusedStatus is what the response already says about it.
func (s *Server) sessionStatuses(focused *session, focusedStatus internal.StatusType, full bool) []*proto.SessionStatus {
	var statuses []*proto.SessionStatus
	for _, ss := range s.allSessions() {
		status := ss.state.CurrentStatus()
		holdsHost := ss.holdsHost()
		if ss == focused {
			status = focusedStatus
		} else if !holdsHost && !ss.isClientRunning() && status == internal.StatusIdle {
			continue
		}

		entry := &proto.SessionStatus{
			ProfileId:   ss.key.Profile.String(),
			ProfileName: s.profileDisplayName(ss.key),
			Status:      string(status),
			Focused:     ss == focused,
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

func profilesDisabledError() error {
	return gstatus.Errorf(codes.Unavailable, errProfilesDisabled)
}
