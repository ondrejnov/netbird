package server

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal/ipcauth"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
)

const errSessionOfAnotherUser = "the session belongs to another user"

// sessionCaller is who an RPC answers to, as far as the sessions are concerned. The identity comes
// from the kernel through ipcauth.CallerIdentity, and never from a field of the request: a username
// in a request says nothing about who is asking.
type sessionCaller struct {
	id         ipcauth.Identity
	identified bool
	// profileOf reads the profile of a session off disk, owners included.
	profileOf func(key profilemanager.SessionKey) (*profilemanager.Profile, error)
}

func (s *Server) callerOf(ctx context.Context) sessionCaller {
	id, identified := ipcauth.CallerIdentity(ctx)
	return sessionCaller{
		id:         id,
		identified: identified,
		profileOf:  s.profileOfKey,
	}
}

// mayReach reports whether the caller may control and read the session of key: the session of a
// profile the caller owns, and any session for a privileged caller. A caller the daemon cannot
// identify reaches nothing, and a profile whose owner cannot be read is not the caller's (I6).
func (c sessionCaller) mayReach(key profilemanager.SessionKey) bool {
	if !c.identified {
		return false
	}
	if c.privileged() || ipcauth.ProfileOwnershipDisabled() {
		return true
	}
	profile, err := c.profileOf(key)
	if err != nil {
		log.Debugf("denying access to the session of profile %s: %v", key.Profile, err)
		return false
	}
	return profile.AccessibleBy(c.id)
}

// privileged reports whether the kernel vouches for a caller that may read everything.
func (c sessionCaller) privileged() bool {
	return c.identified && ipcauth.IsPrivilegedCaller(c.id)
}

func foreignSessionError(caller sessionCaller) error {
	if caller.identified {
		log.Warnf("denying access to the session of another user for caller %s", caller.id)
	} else {
		log.Warnf("denying access to the session of another user: the caller's identity cannot be verified on this control channel")
	}
	return gstatus.Error(codes.PermissionDenied, errSessionOfAnotherUser)
}

// sessionKeyFor returns the session key of a resolved profile. A profile in a legacy per-user
// directory keeps that directory in its key, as its ID can be a display name another user holds.
func sessionKeyFor(profile *profilemanager.Profile) profilemanager.SessionKey {
	return sessionKeyOf(profile.ID, legacyDirHint(profile))
}

// selectedProfile returns the profile a request names, as the authorization gate resolved it. The
// gate cannot read the request of a stream before the handler runs, so a stream's selector is
// resolved here, for the same identity and by the same rule. A profile the caller does not own is
// refused.
func (s *Server) selectedProfile(ctx context.Context, handle string) (*profilemanager.Profile, error) {
	if _, ok := ipcauth.TargetFromContext(ctx); ok {
		return s.targetProfile(ctx)
	}

	caller := s.callerOf(ctx)
	if !caller.identified {
		return nil, foreignSessionError(caller)
	}
	target, err := s.ResolveTarget(caller.id, handle)
	if err != nil {
		return nil, err
	}
	if !target.Owned {
		return nil, foreignSessionError(caller)
	}
	profile, err := s.profileManager.ProfileByPath(target.Path)
	if err != nil {
		return nil, fmt.Errorf("read profile %s: %w", handle, err)
	}
	return profile, nil
}

// namedSession returns the session of the profile a request names, for a caller that owns it.
func (s *Server) namedSession(ctx context.Context, handle string) (*session, error) {
	resolved, err := s.selectedProfile(ctx, handle)
	if err != nil {
		return nil, err
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.sessionOfLocked(s.keyOfProfileLocked(resolved)), nil
}

// keyOfProfileLocked returns the key of the session of profile, or a new key when it has none. A
// key made from the active profile state can carry the raw username where the profile is found by
// its sanitized directory, so an existing session is matched on the profile's file. The caller
// holds s.mutex.
func (s *Server) keyOfProfileLocked(profile *profilemanager.Profile) profilemanager.SessionKey {
	if focused := s.focusedSession(); focused != nil && s.isSessionProfile(focused.key, profile) {
		return focused.key
	}
	for key := range s.sessions {
		if key.Profile == profile.ID && s.isSessionProfile(key, profile) {
			return key
		}
	}
	return sessionKeyFor(profile)
}

// checkSessionSelector returns the session an RPC acts on, which is all the handler may look at: a
// second look at the focus could land on another session than the one checked. Without a selector
// it is the focused session. With the gate the caller has to be allowed to reach it, without it
// a selector can only name the one session there is.
func (s *Server) checkSessionSelector(ctx context.Context, selector *proto.SessionSelector) (*session, error) {
	if !s.concurrentProfiles {
		return s.checkFocusedSelector(ctx, selector)
	}

	if selector != nil {
		return s.sessionOfSelector(ctx, selector)
	}

	caller := s.callerOf(ctx)
	ss := s.focusedSession()
	if !caller.mayReach(ss.key) {
		return nil, foreignSessionError(caller)
	}
	return ss, nil
}

// checkOpenSelector is checkSessionSelector for Down and Status, which without a selector act on the
// focused session for whoever the authorization gate let through.
func (s *Server) checkOpenSelector(ctx context.Context, selector *proto.SessionSelector) (*session, error) {
	if selector == nil {
		return s.focusedSession(), nil
	}
	return s.checkSessionSelector(ctx, selector)
}

func (s *Server) sessionOfSelector(ctx context.Context, selector *proto.SessionSelector) (*session, error) {
	handle := selector.GetProfile()
	if handle == "" {
		return nil, gstatus.Error(codes.InvalidArgument, "the session selector names no profile")
	}
	return s.namedSession(ctx, handle)
}

// checkFocusedSelector refuses a selector that names anything but the one session. Every failure
// gets the same answer, so a selector does not tell a caller which profiles exist.
func (s *Server) checkFocusedSelector(ctx context.Context, selector *proto.SessionSelector) (*session, error) {
	ss := s.focusedSession()
	if selector == nil {
		return ss, nil
	}

	refused := gstatus.Error(codes.FailedPrecondition, errSelectorNotFocused)
	if selector.GetProfile() == "" {
		return nil, refused
	}

	active, err := s.profileManager.GetActiveProfileState()
	if err != nil {
		log.Warnf("failed to read the focused session for a session selector: %v", err)
		return nil, refused
	}
	resolved, err := s.selectedProfile(ctx, selector.GetProfile())
	if err != nil {
		log.Debugf("failed to resolve a session selector: %v", err)
		return nil, refused
	}
	if !s.isActiveProfile(active, resolved) {
		return nil, refused
	}
	return ss, nil
}

// focusMovedFrom reports whether a stream on ss has to move on: one without a selector describes the
// focused session. Without the gate the focus never moves.
func (s *Server) focusMovedFrom(ss *session, selector *proto.SessionSelector) bool {
	return selector == nil && s.focusedSession() != ss
}

// eventSessionAfter returns the session an event stream on ss goes on with, and refuses the stream
// when the focus moved on to a session the caller may not read.
func (s *Server) eventSessionAfter(ctx context.Context, ss *session, selector *proto.SessionSelector) (*session, error) {
	if !s.focusMovedFrom(ss, selector) {
		return ss, nil
	}
	next := s.focusedSession()
	caller := s.callerOf(ctx)
	if !caller.mayReach(next.key) {
		return nil, foreignSessionError(caller)
	}
	return next, nil
}

// statePathOf returns the state file of ss. Without the gate the one session follows the active
// profile and has no key of its own.
func (s *Server) statePathOf(ss *session) string {
	if s.concurrentProfiles {
		return s.profileManager.GetStatePathFor(ss.key)
	}
	return s.profileManager.GetStatePath()
}

// bundleStatePath returns the state file a debug bundle of ss carries. Empty means the generator
// reads the one of the active profile, which is right for the one session without the gate unless
// it runs another profile than the one selected.
func (s *Server) bundleStatePath(ss *session) string {
	if s.concurrentProfiles {
		return s.profileManager.GetStatePathFor(ss.key)
	}
	if key, otherRuns := ss.otherProfileRunKey(); otherRuns {
		return s.profileManager.GetStatePathFor(key)
	}
	return ""
}
