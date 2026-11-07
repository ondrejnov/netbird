//go:build !android && !ios && !freebsd && !js

package main

import (
	"github.com/netbirdio/netbird/client/ui/services"
)

// cacheSessions keeps the session list of a status snapshot for the Profiles
// submenu and reports whether it changed. With concurrent profiles a session
// that is not focused changes without touching the icon, so this is what tells
// the tray to repaint its row.
func (t *Tray) cacheSessions(st services.Status) bool {
	key := st.SessionsFingerprint()
	t.profilesMu.Lock()
	defer t.profilesMu.Unlock()
	if key == t.sessionsKey {
		return false
	}
	t.sessionsKey = key
	t.sessions = append([]services.SessionStatus(nil), st.Sessions...)
	return true
}

// profileRowLabel is the row of a profile in the Profiles submenu. With
// concurrent profiles every profile can be connected, so the row carries the
// state of its session. A profile the daemon does not list sits idle.
func (t *Tray) profileRowLabel(display, profileID string, sessions []services.SessionStatus) string {
	if len(sessions) == 0 {
		return display
	}
	var session services.SessionStatus
	for _, s := range sessions {
		if s.ProfileID == profileID {
			session = s
			break
		}
	}
	label := display + " · " + t.loc.StatusLabel(session.Status)
	if session.Conflict != "" {
		label += " · " + t.loc.T("tray.profile.conflict", "resource", session.Conflict)
	}
	return label
}
