package server

import (
	"context"
	"fmt"
	"slices"

	"github.com/hashicorp/go-multierror"

	nberrors "github.com/netbirdio/netbird/client/errors"
	"github.com/netbirdio/netbird/client/firewall"
	"github.com/netbirdio/netbird/client/internal/hostcoord"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
)

// restoreResidualAtStart undoes what a daemon that did not shut down cleanly left behind: every
// state file found in the sessions file and on disk, then the marked routes. It runs before the
// first session starts, so none of it can belong to a live one. The profile that ran can be
// any of them, since only memory knew it. The sessions file is only read, and a file with
// nothing to undo is not written.
func (s *Server) restoreResidualAtStart(ctx context.Context) error {
	var merr *multierror.Error

	records, err := hostcoord.StoredRecords(profilemanager.DefaultConfigPathDir)
	if err != nil {
		merr = multierror.Append(merr, fmt.Errorf("read stored sessions: %w", err))
	}

	onDisk, err := s.profileManager.StateFileProfiles()
	if err != nil {
		merr = multierror.Append(merr, fmt.Errorf("find state files: %w", err))
	}

	for _, statePath := range s.residualStatePaths(records, onDisk) {
		if err := cleanStateFile(ctx, statePath); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("clean %s: %w", statePath, err))
		}
	}

	if err := s.flushMarkedRoutes(); err != nil {
		merr = multierror.Append(merr, err)
	}

	// Without a sessions file no isolation ever ran here, and the host stays untouched.
	if len(records) > 0 {
		if err := s.removeResidualIsolation(records); err != nil {
			merr = multierror.Append(merr, err)
		}
	}

	return nberrors.FormatErrorOrNil(merr)
}

// removeResidualIsolation deletes the session interfaces and then the isolation. An interface that
// stays keeps the isolation, the one thing left between its peers and the other networks. The state
// files go first, since some of their cleanup needs the interface to find what to undo.
func (s *Server) removeResidualIsolation(records []hostcoord.SlotRecord) error {
	if err := s.removeSessionLinks(records); err != nil {
		return fmt.Errorf("remove session links, keeping the isolation: %w", err)
	}
	if err := firewall.RemoveResidualSessionIsolation(); err != nil {
		return fmt.Errorf("remove session isolation: %w", err)
	}
	return nil
}

func (s *Server) removeSessionLinks(records []hostcoord.SlotRecord) error {
	if s.removeLinksFn != nil {
		return s.removeLinksFn(records)
	}
	return hostcoord.RemoveSessionLinks(records)
}

// residualStatePaths lists each state file once, because NB_DNS_STATE_FILE gives all
// profiles the same one.
func (s *Server) residualStatePaths(records []hostcoord.SlotRecord, onDisk []profilemanager.SessionKey) []string {
	paths := make([]string, 0, len(records)+len(onDisk)+2)
	for _, record := range records {
		paths = append(paths, s.profileManager.GetStatePathFor(record.Key))
	}
	for _, key := range onDisk {
		paths = append(paths, s.profileManager.GetStatePathFor(key))
	}
	paths = append(paths,
		s.profileManager.GetStatePathFor(profilemanager.SessionKey{Profile: profilemanager.DefaultProfileName}),
		s.profileManager.GetStatePath(),
	)

	var unique []string
	for _, path := range paths {
		if !slices.Contains(unique, path) {
			unique = append(unique, path)
		}
	}
	return unique
}

// restoreOwnResidual cleans the state file of the session about to start. Other state files may
// belong to a running session, and so may the marked routes, which carry no owner: they are only
// flushed when no other session runs.
func (s *Server) restoreOwnResidual(ctx context.Context, key profilemanager.SessionKey) error {
	if s.otherSessionRunning(key) {
		return cleanStateFile(ctx, s.profileManager.GetStatePathFor(key))
	}
	return s.restoreResidualAlone(ctx, key)
}

// restoreResidualAlone undoes the residual state of key and the marked routes, for a caller
// that knows no other session runs.
func (s *Server) restoreResidualAlone(ctx context.Context, key profilemanager.SessionKey) error {
	var merr *multierror.Error

	if err := cleanStateFile(ctx, s.profileManager.GetStatePathFor(key)); err != nil {
		merr = multierror.Append(merr, err)
	}
	if err := s.flushMarkedRoutes(); err != nil {
		merr = multierror.Append(merr, err)
	}

	return nberrors.FormatErrorOrNil(merr)
}

// restoreLoginResidual is restoreOwnResidual for a Login, which gave up the server mutex after
// cancelling the run identified by cancelled. A run of key started since then owns the state
// file and the routes, so there is nothing to clean. The caller holds the server mutex.
func (s *Server) restoreLoginResidual(ctx context.Context, ss *session, key profilemanager.SessionKey, cancelled <-chan struct{}) error {
	running, ok := ss.runningKey()
	if _, giveUp := ss.runChans(); ok && giveUp != cancelled && sameSessionProfile(running, key) {
		return nil
	}
	return s.restoreOwnResidual(ctx, key)
}

// otherSessionRunning reports whether a session of another profile than key is running.
func (s *Server) otherSessionRunning(key profilemanager.SessionKey) bool {
	running, ok := s.focusedSession().runningKey()
	return ok && !sameSessionProfile(running, key)
}

func (s *Server) flushMarkedRoutes() error {
	if s.flushRoutesFn != nil {
		return s.flushRoutesFn()
	}
	return flushMarkedRoutes()
}

// openSlots takes over the slots stored in base, for a daemon that runs concurrent sessions. A
// state file without a sessions file comes from before slots and records the names of slot 0,
// so its profile becomes the owner of that slot. An existing sessions file already says who
// owns what, and NewSlots then ignores the owner.
func (s *Server) openSlots(base string, active profilemanager.SessionKey) (*hostcoord.Slots, error) {
	onDisk, err := s.profileManager.StateFileProfiles()
	if err != nil {
		return nil, fmt.Errorf("find state files: %w", err)
	}

	var opts []hostcoord.SlotsOption
	if owner, ok := s.slotZeroOwner(active, onDisk); ok {
		opts = append(opts, hostcoord.WithSlotZeroOwner(owner))
	}
	return hostcoord.NewSlots(base, opts...)
}

// slotZeroOwner picks the owner among the profiles with a state file. Several files give the
// slot to the active profile, even one without a file: the start cleans them all, so no names
// stay in use. Whether a file exists is what counts, as the cleanup keeps the files.
func (s *Server) slotZeroOwner(active profilemanager.SessionKey, onDisk []profilemanager.SessionKey) (profilemanager.SessionKey, bool) {
	switch len(onDisk) {
	case 0:
		return profilemanager.SessionKey{}, false
	case 1:
		// Paths and not keys: a key from disk carries the sanitized username.
		if s.profileManager.GetStatePathFor(onDisk[0]) != s.profileManager.GetStatePathFor(active) {
			return onDisk[0], true
		}
	}
	return active, true
}
