//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"

	nberrors "github.com/netbirdio/netbird/client/errors"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
)

// focusReturnTimeout bounds the switch that gives the focus back after a failed connect, which
// runs even when the caller's context is already done.
const focusReturnTimeout = 5 * time.Second

// SessionStatus is the state of the session of one profile on a daemon with concurrent profiles.
// The daemon leaves out the sessions that sit idle and are not focused.
type SessionStatus struct {
	ProfileID     string `json:"profileId"`
	ProfileName   string `json:"profileName"`
	Status        string `json:"status"`
	InterfaceName string `json:"interfaceName"`
	OverlayIP     string `json:"overlayIp"`
	Focused       bool   `json:"focused"`
	// Conflict names the resource that keeps the session from running: overlay, exit_node, dns
	// or interface. Empty when there is none.
	Conflict string `json:"conflict"`
}

// ConcurrentProfiles is the concurrent profiles feature gate of the daemon.
type ConcurrentProfiles struct {
	Enabled bool `json:"enabled"`
	// MaxSessions is the limit of sessions running at once, 0 means no limit.
	MaxSessions uint32 `json:"maxSessions"`
}

// SessionParams selects the session of a profile by handle: an exact ID, a unique ID prefix or a
// unique display name.
type SessionParams struct {
	ProfileName string `json:"profileName"`
	Username    string `json:"username"`
}

func sessionsFromProto(in []*proto.SessionStatus) []SessionStatus {
	if len(in) == 0 {
		return nil
	}
	out := make([]SessionStatus, 0, len(in))
	for _, s := range in {
		out = append(out, SessionStatus{
			ProfileID:     s.GetProfileId(),
			ProfileName:   s.GetProfileName(),
			Status:        s.GetStatus(),
			InterfaceName: s.GetInterfaceName(),
			OverlayIP:     s.GetOverlayIp(),
			Focused:       s.GetFocused(),
			Conflict:      s.GetConflict(),
		})
	}
	return out
}

// SessionOf returns the session of the profile with the given ID.
func (st Status) SessionOf(profileID string) (SessionStatus, bool) {
	for _, s := range st.Sessions {
		if s.ProfileID == profileID {
			return s, true
		}
	}
	return SessionStatus{}, false
}

func (st Status) focusedSession() (SessionStatus, bool) {
	for _, s := range st.Sessions {
		if s.Focused {
			return s, true
		}
	}
	return SessionStatus{}, false
}

// FocusedProfileID returns the profile ID of the focused session, empty without the concurrent
// profiles gate.
func (st Status) FocusedProfileID() string {
	focused, _ := st.focusedSession()
	return focused.ProfileID
}

// SessionsFingerprint changes whenever a session starts, stops, changes its status, its conflict
// or the focus.
func (st Status) SessionsFingerprint() string {
	var b strings.Builder
	for _, s := range st.Sessions {
		fmt.Fprintf(&b, "%s|%s|%t|%s;", s.ProfileID, s.Status, s.Focused, s.Conflict)
	}
	return b.String()
}

// sessionRuns reports whether the session of a profile is up or on its way up, so that a switch
// to it has nothing to connect.
func sessionRuns(s SessionStatus) bool {
	return strings.EqualFold(s.Status, StatusConnected) || strings.EqualFold(s.Status, StatusConnecting)
}

// ConcurrentProfiles reads the concurrent profiles feature gate. A daemon that predates it
// reports it disabled.
func (s *Profiles) ConcurrentProfiles(ctx context.Context) (ConcurrentProfiles, error) {
	cli, err := s.conn.Client()
	if err != nil {
		return ConcurrentProfiles{}, err
	}
	resp, err := cli.GetFeatures(ctx, &proto.GetFeaturesRequest{})
	if err != nil {
		return ConcurrentProfiles{}, err
	}
	return ConcurrentProfiles{
		Enabled:     resp.GetConcurrentProfilesEnabled(),
		MaxSessions: resp.GetMaxSessions(),
	}, nil
}

// DownSession disconnects the session of one profile and leaves the others running. It needs the
// concurrent profiles gate; without it the daemon refuses a selector.
func (s *Connection) DownSession(ctx context.Context, p SessionParams) error {
	if p.ProfileName == "" {
		// An empty selector would mean the focused session, which may be someone else's.
		return errors.New("a profile is required to disconnect its session")
	}
	cli, err := s.conn.Client()
	if err != nil {
		return err
	}
	req := &proto.DownRequest{Session: &proto.SessionSelector{Profile: p.ProfileName, Username: p.Username}}
	if _, err := cli.Down(ctx, req); err != nil {
		return s.classifyDaemonError(err)
	}
	return nil
}

// needsLogin reports whether a session waits for the user to log in, which only a selection of
// the profile starts.
func needsLogin(s SessionStatus) bool {
	return strings.EqualFold(s.Status, StatusNeedsLogin) ||
		strings.EqualFold(s.Status, StatusLoginFailed) ||
		strings.EqualFold(s.Status, StatusSessionExpired)
}

// ConnectStartupProfiles connects the profiles chosen to come up with the GUI. It acts only with
// the gate, where an Up that names a profile leaves the focus where it is. A profile that runs
// already or waits for a login is skipped, as is an ID no longer in the profile list. One profile
// failing, such as on the session limit or a conflict, does not keep the others down.
func ConnectStartupProfiles(ctx context.Context, profiles *Profiles, conn *Connection, feed *DaemonFeed, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	gate, err := profiles.ConcurrentProfiles(ctx)
	if err != nil {
		return fmt.Errorf("read the concurrent profiles gate: %w", err)
	}
	if !gate.Enabled {
		return nil
	}

	username, err := profiles.Username()
	if err != nil {
		return fmt.Errorf("get current user: %w", err)
	}
	list, err := profiles.List(ctx, username)
	if err != nil {
		return fmt.Errorf("list profiles: %w", err)
	}
	st, err := feed.Get(ctx)
	if err != nil {
		return fmt.Errorf("get status: %w", err)
	}

	known := make(map[string]bool, len(list))
	for _, p := range list {
		known[p.ID] = true
	}

	var merr *multierror.Error
	for _, id := range ids {
		if !known[id] {
			continue
		}
		if session, ok := st.SessionOf(id); ok && (sessionRuns(session) || needsLogin(session)) {
			log.Debugf("startup profiles: skipping profile %s in state %s", id, session.Status)
			continue
		}
		if err := conn.Up(ctx, UpParams{ProfileName: id, Username: username}); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("connect profile %s: %w", id, err))
		}
	}
	return nberrors.FormatErrorOrNil(merr)
}

// DisconnectOnQuit ends what quitting the UI ends. Without the gate that is the one connection.
// With it the UI shows every session, so it brings all of them down; the daemon limits that to the
// sessions the caller may reach and leaves those of other users running.
func DisconnectOnQuit(ctx context.Context, profiles *Profiles, conn *Connection) error {
	gate, err := profiles.ConcurrentProfiles(ctx)
	if err != nil {
		log.Warnf("read the concurrent profiles gate, disconnecting the focused session only: %v", err)
	}
	if !gate.Enabled {
		return conn.Down(ctx)
	}
	return conn.downAll(ctx)
}

func (s *Connection) downAll(ctx context.Context) error {
	cli, err := s.conn.Client()
	if err != nil {
		return err
	}
	if _, err := cli.Down(ctx, &proto.DownRequest{All: true}); err != nil {
		return s.classifyDaemonError(err)
	}
	return nil
}

// switchFocus is the switch on a daemon with concurrent profiles. SwitchProfile then moves only
// the focus and every session keeps running, so nothing is brought down. With connect the session
// of p is brought up unless it runs already, and when that fails the focus goes back to where it
// was, as `netbird up --profile` does.
func (s *ProfileSwitcher) switchFocus(ctx context.Context, p ProfileRef, prev Status, connect bool) error {
	previous, hadFocus := prev.focusedSession()
	target, known := prev.SessionOf(p.ProfileName)
	needsUp := connect && (!known || !sessionRuns(target))

	log.Infof("profileswitcher: focus profile=%q connect=%v needsUp=%v", p.ProfileName, connect, needsUp)

	if needsUp && s.feed != nil {
		s.feed.BeginProfileSwitch()
	}

	resolvedID, err := s.profiles.Switch(ctx, p)
	if err != nil {
		if needsUp && s.feed != nil {
			s.feed.CancelProfileSwitch()
		}
		return fmt.Errorf("switch profile %q: %w", p.ProfileName, err)
	}
	mirrorActiveProfile(resolvedID)

	if needsUp {
		if err := s.connection.Up(ctx, UpParams(p)); err != nil {
			if s.feed != nil {
				s.feed.CancelProfileSwitch()
			}
			if hadFocus && previous.ProfileID != resolvedID {
				s.giveFocusBack(ctx, previous.ProfileID, p.Username)
			}
			s.emitProfileChanged(p)
			return fmt.Errorf("connect %q: %w", p.ProfileName, err)
		}
	}

	s.emitProfileChanged(p)
	return nil
}

func (s *ProfileSwitcher) giveFocusBack(ctx context.Context, profileID, username string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), focusReturnTimeout)
	defer cancel()

	resolvedID, err := s.profiles.Switch(ctx, ProfileRef{ProfileName: profileID, Username: username})
	if err != nil {
		log.Warnf("profileswitcher: give the focus back to profile %s: %v", profileID, err)
		return
	}
	mirrorActiveProfile(resolvedID)
}

// mirrorActiveProfile writes the choice into the user-side ProfileManager state: the CLI's
// `netbird up` reads this file and sends the ID back in the Up RPC, so if it diverges the daemon
// reverts the UI switch on the next CLI `up`. Best-effort, the daemon is authoritative.
func mirrorActiveProfile(resolvedID string) {
	if err := profilemanager.NewProfileManager().SwitchProfile(profilemanager.ID(resolvedID)); err != nil {
		log.Warnf("profileswitcher: mirror to user-side ProfileManager failed: %v", err)
	}
}

// emitProfileChanged fans the switch out to the other surfaces. The daemon emits no profile
// event, so the React ProfileContext would otherwise stay on the old profile after a tray switch.
func (s *ProfileSwitcher) emitProfileChanged(p ProfileRef) {
	if s.feed != nil && s.feed.emitter != nil {
		s.feed.emitter.Emit(EventProfileChanged, p)
	}
}
