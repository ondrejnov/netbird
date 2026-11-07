package server

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal/ipcauth"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
)

const (
	errSessionOfAnotherUser = "the session belongs to another user"

	passwdPath = "/etc/passwd"
)

// sessionCaller is who an RPC answers to, as far as the sessions are concerned. The identity comes
// from the kernel through ipcauth.CallerIdentity, and never from a field of the request: a username
// in a request says which profile is meant, not who is asking.
type sessionCaller struct {
	id         ipcauth.Identity
	identified bool
	lookupUID  func(username string) (uint32, error)
	accounts   func() ([]hostAccount, error)
	// accountName and windowsAccounts are the account database of a Windows host.
	accountName     func(sid string) (string, error)
	windowsAccounts func() ([]windowsAccount, error)
}

// hostAccount is an account in the account database of the host.
type hostAccount struct {
	name string
	uid  uint32
}

func (s *Server) callerOf(ctx context.Context) sessionCaller {
	id, identified := ipcauth.CallerIdentity(ctx)
	lookup := s.lookupUIDFn
	if lookup == nil {
		lookup = accountUID
	}
	accounts := s.accountsFn
	if accounts == nil {
		accounts = localAccounts
	}
	accountName := s.accountNameFn
	if accountName == nil {
		accountName = windowsAccountName
	}
	windowsAccounts := s.windowsAccountsFn
	if windowsAccounts == nil {
		windowsAccounts = localWindowsAccounts
	}
	return sessionCaller{
		id:              id,
		identified:      identified,
		lookupUID:       lookup,
		accounts:        accounts,
		accountName:     accountName,
		windowsAccounts: windowsAccounts,
	}
}

// mayReach reports whether the caller may control and read the session of key: its own and the
// shared default session, and any session for a privileged caller. A caller the daemon cannot
// identify reaches nothing, and a failure to tell who owns a session means it is not the caller's (I6).
func (c sessionCaller) mayReach(key profilemanager.SessionKey) bool {
	if !c.identified {
		return false
	}
	if key.Profile == profilemanager.DefaultProfileName {
		return true
	}
	return c.mayReachUser(key.Username)
}

func (c sessionCaller) mayReachUser(username string) bool {
	if c.privileged() {
		return true
	}
	return c.identified && c.owns(username)
}

// privileged reports whether the kernel vouches for a caller that may read everything.
func (c sessionCaller) privileged() bool {
	return c.identified && ipcauth.IsPrivilegedCaller(c.id)
}

// owns reports whether the sessions of username belong to the caller: the account is the caller's,
// and its directory of profiles is its alone.
func (c sessionCaller) owns(username string) bool {
	return c.holdsAccount(username) && c.aloneInDirectory(username)
}

// holdsAccount reports whether username names the caller. A name that is no account counts as the
// numeric identity of a user without one, which is what the CLI sends for it.
func (c sessionCaller) holdsAccount(username string) bool {
	if username == "" {
		return false
	}
	if c.id.IsWindows() {
		return c.holdsWindowsAccount(username)
	}
	uid, err := c.lookupUID(username)
	if err == nil {
		return uid == c.id.UID
	}
	var unknown user.UnknownUserError
	if errors.As(err, &unknown) {
		return username == strconv.FormatUint(uint64(c.id.UID), 10)
	}
	log.Warnf("failed to look up the owner of a session: %v", err)
	return false
}

// aloneInDirectory reports whether the profiles of username can be only those of its account. The
// directory comes from the sanitized name while ownership goes by the account, so john.doe and johndoe
// would have different sessions on the same files, keys included. Only a privileged caller can reach
// such a directory. It runs on every read of a status, so the refusal stays at debug level.
func (c sessionCaller) aloneInDirectory(username string) bool {
	if c.id.IsWindows() {
		return c.aloneInWindowsDirectory(username)
	}
	if profilemanager.SanitizedUsername(username) != username {
		log.Debugf("denying access to the profiles of %s for an unprivileged caller: the name of their directory differs from the name of the account", username)
		return false
	}

	accounts, err := c.accounts()
	if err != nil {
		log.Warnf("failed to read the accounts of this host: %v", err)
		return false
	}
	for _, account := range accounts {
		if account.uid != c.id.UID && profilemanager.SanitizedUsername(account.name) == username {
			log.Debugf("denying access to the profiles of %s for an unprivileged caller: the account %s shares their directory", username, account.name)
			return false
		}
	}
	return true
}

// localAccounts reads the accounts of the host from its passwd file. No such file means no accounts,
// as in a container that runs on numeric identities. There is no way to list accounts through NSS.
func localAccounts() ([]hostAccount, error) {
	raw, err := os.ReadFile(passwdPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", passwdPath, err)
	}

	var accounts []hostAccount
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 3 {
			continue
		}
		uid, err := strconv.ParseUint(fields[2], 10, 32)
		if err != nil {
			continue
		}
		accounts = append(accounts, hostAccount{name: fields[0], uid: uint32(uid)})
	}
	return accounts, nil
}

// accountUID returns the UID of the account username on this host.
func accountUID(username string) (uint32, error) {
	account, err := user.Lookup(username)
	if err != nil {
		return 0, err
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("parse UID of %s: %w", username, err)
	}
	return uint32(uid), nil
}

func foreignSessionError(caller sessionCaller) error {
	if caller.identified {
		log.Warnf("denying access to the session of another user for caller %s", caller.id)
	} else {
		log.Warnf("denying access to the session of another user: the caller's identity cannot be verified on this control channel")
	}
	return gstatus.Error(codes.PermissionDenied, errSessionOfAnotherUser)
}

// requireProfileReachable refuses a handle naming a profile of another user. It runs ahead of the
// resolution, so that the answer does not say whether the profile exists.
func requireProfileReachable(caller sessionCaller, handle, username string) error {
	if (handle == profilemanager.DefaultProfileName && caller.identified) || caller.mayReachUser(username) {
		return nil
	}
	return foreignSessionError(caller)
}

// authorizeProfilesOf refuses a request about the profiles of another user: their names are metadata
// of that user, and a change writes into their directory. Without the feature gate a request goes on
// as it always did (I1).
func (s *Server) authorizeProfilesOf(ctx context.Context, username string) error {
	if !s.concurrentProfiles {
		return nil
	}
	caller := s.callerOf(ctx)
	if caller.mayReachUser(username) {
		return nil
	}
	return foreignSessionError(caller)
}

// authorizeActiveProfile refuses to name the focused session to a caller that may not read it.
func (s *Server) authorizeActiveProfile(ctx context.Context, active *profilemanager.ActiveProfileState) error {
	if !s.concurrentProfiles {
		return nil
	}
	caller := s.callerOf(ctx)
	if caller.mayReach(sessionKeyOf(active.ID, active.Username)) {
		return nil
	}
	return foreignSessionError(caller)
}

// authorizeNamedProfile refuses a request naming a profile of another user. Without the feature
// gate a request goes on as it always did (I1).
func (s *Server) authorizeNamedProfile(ctx context.Context, handle, username string) error {
	if !s.concurrentProfiles {
		return nil
	}
	return requireProfileReachable(s.callerOf(ctx), handle, username)
}

// namedSession returns the session of a profile the request names, for a caller that may reach it.
func (s *Server) namedSession(caller sessionCaller, handle, username string) (*session, error) {
	if err := requireProfileReachable(caller, handle, username); err != nil {
		return nil, err
	}
	resolved, name, err := s.resolveNamedProfile(handle, &username)
	if err != nil {
		return nil, err
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.sessionOfLocked(sessionKeyOf(resolved.ID, name)), nil
}

// checkSessionSelector returns the session an RPC acts on, which is all the handler may look at: a
// second look at the focus could land on another session than the one checked. Without a selector
// it is the focused session. With the gate the caller has to be allowed to reach it, without it
// a selector can only name the one session there is.
func (s *Server) checkSessionSelector(ctx context.Context, selector *proto.SessionSelector) (*session, error) {
	if !s.concurrentProfiles {
		return s.checkFocusedSelector(selector)
	}

	caller := s.callerOf(ctx)
	if selector != nil {
		return s.sessionOfSelector(caller, selector)
	}

	ss := s.focusedSession()
	if !caller.mayReach(ss.key) {
		return nil, foreignSessionError(caller)
	}
	return ss, nil
}

// checkOpenSelector is checkSessionSelector for Down and Status, which keep answering without a
// selector whoever asks, as they always did (5.6).
func (s *Server) checkOpenSelector(ctx context.Context, selector *proto.SessionSelector) (*session, error) {
	if selector == nil {
		return s.focusedSession(), nil
	}
	return s.checkSessionSelector(ctx, selector)
}

func (s *Server) sessionOfSelector(caller sessionCaller, selector *proto.SessionSelector) (*session, error) {
	handle, username := selector.GetProfile(), selector.GetUsername()
	if handle == "" {
		return nil, gstatus.Error(codes.InvalidArgument, "the session selector names no profile")
	}
	if handle != profilemanager.DefaultProfileName && username == "" {
		return nil, gstatus.Errorf(codes.InvalidArgument, "the session selector names profile %q without a username", handle)
	}
	return s.namedSession(caller, handle, username)
}

// checkFocusedSelector refuses a selector that names anything but the one session. Every failure
// gets the same answer, so a selector does not tell a caller which profiles exist.
func (s *Server) checkFocusedSelector(selector *proto.SessionSelector) (*session, error) {
	ss := s.focusedSession()
	if selector == nil {
		return ss, nil
	}

	refused := gstatus.Error(codes.FailedPrecondition, errSelectorNotFocused)

	active, err := s.profileManager.GetActiveProfileState()
	if err != nil {
		log.Warnf("failed to read the focused session for a session selector: %v", err)
		return nil, refused
	}
	resolved, err := s.profileManager.ResolveProfile(selector.GetProfile(), selector.GetUsername())
	if err != nil {
		log.Debugf("failed to resolve a session selector: %v", err)
		return nil, refused
	}
	if !isSessionProfile(active.SessionKey(), resolved.ID, selector.GetUsername()) {
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
