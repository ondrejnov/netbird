//go:build !android && !ios && !freebsd && !js

package main

import (
	"context"
	"time"

	"github.com/cenkalti/backoff/v4"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/ui/services"
)

// startupDaemonWait bounds how long the GUI waits for the daemon at start before it gives up on
// connecting the startup profiles, such as when the service starts with the session.
const startupDaemonWait = 2 * time.Minute

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

// connectStartupProfiles connects the profiles the user chose to come up with
// the GUI, once the daemon answers. Only reachability is retried: a profile the
// daemon refuses would be refused again.
func (t *Tray) connectStartupProfiles() {
	if t.svc.Preferences == nil {
		return
	}
	ids := t.svc.Preferences.Get().StartupProfiles
	if len(ids) == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), startupDaemonWait)
	defer cancel()
	reachable := func() error {
		_, err := t.svc.Profiles.ConcurrentProfiles(ctx)
		return err
	}
	if err := backoff.Retry(reachable, backoff.WithContext(backoff.NewExponentialBackOff(), ctx)); err != nil {
		log.Warnf("startup profiles: daemon not reachable: %v", err)
		return
	}

	if err := services.ConnectStartupProfiles(ctx, t.svc.Profiles, t.svc.Connection, t.svc.DaemonFeed, ids); err != nil {
		log.Errorf("startup profiles: %v", err)
		t.notifyError(t.loc.T("notify.error.startupProfiles"))
	}
}
