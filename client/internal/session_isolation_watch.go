package internal

import (
	"context"
	"errors"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"

	cProto "github.com/netbirdio/netbird/client/proto"
)

// isolationCheckInterval is how long a change of the isolation can go unnoticed. A flush of the
// firewall by whatever else manages the host is enough to open the way between the sessions, and
// nothing tells the daemon about it.
const isolationCheckInterval = 5 * time.Second

const (
	eventIsolationRestored = "isolation_restored"

	msgIsolationRestored = "Something on this host changed the rules that keep the networks of this daemon apart, " +
		"they were put back"
)

// isolationWatch is the check of the isolation while sessions run, one per daemon.
type isolationWatch struct {
	interval time.Duration
	// sessions holds where each attached session hears that its isolation is lost.
	sessions map[*SessionHost]chan error
	// cancel stops the goroutine of the check, nil when none runs.
	cancel context.CancelFunc
	// lost says the isolation could not be put back. The sessions are on their way down, and what
	// is left of the rules has to go before another session can start.
	lost bool
}

// SetIsolationCheckInterval changes how often the isolation is checked, from the next session that
// starts the check on. Tests use it, to see a change sooner or to keep one in place.
func (d *DaemonHost) SetIsolationCheckInterval(interval time.Duration) {
	d.attachMu.Lock()
	defer d.attachMu.Unlock()
	d.watch.interval = interval
}

// watchSessionLocked adds the session to those the check answers for, and returns where it hears
// about a lost isolation. The first session starts the check. The caller holds attachMu.
func (d *DaemonHost) watchSessionLocked(h *SessionHost) <-chan error {
	lost := make(chan error, 1)
	d.watch.sessions[h] = lost

	if d.watch.cancel == nil {
		ctx, cancel := context.WithCancel(context.Background())
		d.watch.cancel = cancel
		go d.runIsolationCheck(ctx, d.watch.interval)
	}
	return lost
}

// unwatchSessionLocked stops answering for the session, and the last one ends the check. The goroutine
// is not waited for: it needs attachMu, which the caller holds.
func (d *DaemonHost) unwatchSessionLocked(h *SessionHost) {
	delete(d.watch.sessions, h)
	if len(d.watch.sessions) == 0 && d.watch.cancel != nil {
		d.watch.cancel()
		d.watch.cancel = nil
	}
}

func (d *DaemonHost) runIsolationCheck(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.checkIsolation(ctx)
		}
	}
}

// checkIsolation puts a changed isolation back. When that fails no session may keep running (I6). The
// ones that run are told so, and leave through their usual way down.
func (d *DaemonHost) checkIsolation(ctx context.Context) {
	d.attachMu.Lock()
	defer d.attachMu.Unlock()

	// The last session can have left between the tick and the lock.
	if ctx.Err() != nil || d.watch.lost {
		return
	}

	err := d.isolation.Verify()
	if err == nil {
		return
	}
	log.Errorf("the isolation between the sessions changed: %v", err)

	err = d.restoreIsolationLocked()
	if err == nil {
		log.Warnf("the isolation between the sessions was put back")
		for h := range d.watch.sessions {
			h.warn(cProto.SystemEvent_SYSTEM, eventIsolationRestored, msgIsolationRestored, nil)
		}
		return
	}

	log.Errorf("failed to put the isolation between the sessions back, stopping all sessions: %v", err)
	d.watch.lost = true
	refused := fmt.Errorf("%w: %w: %w", ErrSessionRefused, ErrIsolationLost, err)
	for _, lost := range d.watch.sessions {
		lost <- refused
	}
}

func (d *DaemonHost) restoreIsolationLocked() error {
	if err := d.isolation.Restore(); err != nil {
		return err
	}
	return d.isolation.Verify()
}

// recoverIsolationLocked lets a session start after a lost isolation only once the sessions it took
// along are gone and so is what was left of the rules: they cannot count as isolation of the new one.
func (d *DaemonHost) recoverIsolationLocked() error {
	if !d.watch.lost {
		return nil
	}
	if len(d.watch.sessions) > 0 {
		return errors.New("the isolation between the sessions was lost and the running sessions are still stopping")
	}
	if err := d.isolation.RemoveAll(); err != nil {
		return fmt.Errorf("remove what is left of the lost isolation: %w", err)
	}
	d.watch.lost = false
	return nil
}

// resetLostIsolationLocked runs when a session has left, as the last one takes care of the rest.
func (d *DaemonHost) resetLostIsolationLocked() {
	if !d.watch.lost || len(d.watch.sessions) > 0 {
		return
	}
	if err := d.recoverIsolationLocked(); err != nil {
		log.Warnf("failed to clean up after the lost isolation, the next session tries again: %v", err)
	}
}

// isolationLost returns where the current attempt hears that it must stop, which never happens for a
// client that owns the host alone.
func (h *SessionHost) isolationLost() <-chan error {
	if h == nil {
		return nil
	}
	return h.lost
}
