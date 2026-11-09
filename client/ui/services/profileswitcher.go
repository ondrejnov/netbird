//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"
	"strings"

	log "github.com/sirupsen/logrus"
)

// ProfileSwitcher holds the switch policy shared by the tray and React
// frontend so both flip profiles identically. SwitchActive (plain selection:
// header dropdown, tray submenu) always connects after the switch;
// SwitchActiveNoConnect (manage-profiles screen) never does, so the user can
// still adjust the management URL before connecting. prevStatus from
// DaemonFeed.Get at entry only decides the teardown:
//
//	Connected/Connecting/NeedsLogin/LoginFailed/SessionExpired → Down first.
//	Idle → no Down.
//
// On a daemon with concurrent profiles the switch only moves the focus and
// never brings a session down, see switchFocus.
type ProfileSwitcher struct {
	profiles   *Profiles
	connection *Connection
	feed       *DaemonFeed
}

func NewProfileSwitcher(profiles *Profiles, connection *Connection, feed *DaemonFeed) *ProfileSwitcher {
	return &ProfileSwitcher{profiles: profiles, connection: connection, feed: feed}
}

// SwitchActive switches to the named profile and always connects afterwards.
func (s *ProfileSwitcher) SwitchActive(ctx context.Context, p ProfileRef) error {
	return s.switchActive(ctx, p, true)
}

// SwitchActiveNoConnect switches to the named profile without connecting,
// tearing down any existing connection first.
func (s *ProfileSwitcher) SwitchActiveNoConnect(ctx context.Context, p ProfileRef) error {
	return s.switchActive(ctx, p, false)
}

func (s *ProfileSwitcher) switchActive(ctx context.Context, p ProfileRef, connect bool) error {
	// Returned unwrapped like the errors below, so the UI shows the daemon's classified message.
	gate, err := s.profiles.ConcurrentProfiles(ctx)
	if err != nil {
		return err
	}

	var prev Status
	if s.feed != nil {
		if st, err := s.feed.Get(ctx); err == nil {
			prev = st
		} else {
			log.Warnf("profileswitcher: get status: %v", err)
		}
	}
	if gate.Enabled {
		return s.switchFocus(ctx, p, prev, connect)
	}
	prevStatus := prev.Status

	needsDown := strings.EqualFold(prevStatus, StatusConnected) ||
		strings.EqualFold(prevStatus, StatusConnecting) ||
		strings.EqualFold(prevStatus, StatusNeedsLogin) ||
		strings.EqualFold(prevStatus, StatusLoginFailed) ||
		strings.EqualFold(prevStatus, StatusSessionExpired)

	log.Infof("profileswitcher: switch profile=%q prevStatus=%q connect=%v needsDown=%v",
		p.ProfileName, prevStatus, connect, needsDown)

	// Optimistic Connecting paint plus stale-push suppression during Down (see
	// DaemonFeed suppression table); also arms the login-watch that pops
	// browser-login when the new profile turns out to need SSO.
	if connect && s.feed != nil {
		s.feed.BeginProfileSwitch()
	}

	// Returned unwrapped: the Wails binding marshals the outermost error, so a
	// wrapper replaces the classified headline and the daemon's suggested
	// command with a raw gRPC string. The Infof above names the profile.
	resolvedID, err := s.profiles.Switch(ctx, p)
	if err != nil {
		return err
	}

	// Use the daemon-resolved ID rather than the handle we sent, since the
	// on-disk state is keyed by ID, not display name.
	mirrorActiveProfile(resolvedID)

	if needsDown {
		if err := s.connection.Down(ctx); err != nil {
			log.Errorf("profileswitcher: Down: %v", err)
		}
	}

	if connect {
		// Unwrapped for the same reason as the switch above.
		if err := s.connection.Up(ctx, UpParams(p)); err != nil {
			return err
		}
	}

	s.emitProfileChanged(p)
	return nil
}
