package server

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"

	"github.com/hashicorp/go-multierror"

	nberrors "github.com/netbirdio/netbird/client/errors"
	"github.com/netbirdio/netbird/client/internal/hostcoord"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
)

// restoreResidualAtStart undoes what a daemon that did not shut down cleanly left behind: the
// state files of all stored sessions and of the active profile, then the marked routes. It runs
// before the first session starts, so none of it can belong to a live one. The sessions file is
// only read: an installation without one keeps having none and gets the cleanup it always got.
func (s *Server) restoreResidualAtStart(ctx context.Context) error {
	var merr *multierror.Error

	records, err := hostcoord.StoredRecords(profilemanager.DefaultConfigPathDir)
	if err != nil {
		merr = multierror.Append(merr, fmt.Errorf("read stored sessions: %w", err))
	}

	for _, statePath := range s.residualStatePaths(records) {
		if err := cleanStateFile(ctx, statePath); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("clean %s: %w", statePath, err))
		}
	}

	if err := s.flushMarkedRoutes(); err != nil {
		merr = multierror.Append(merr, err)
	}

	return nberrors.FormatErrorOrNil(merr)
}

// residualStatePaths lists each state file once, because NB_DNS_STATE_FILE gives all
// profiles the same one.
func (s *Server) residualStatePaths(records []hostcoord.SlotRecord) []string {
	paths := make([]string, 0, len(records)+1)
	for _, record := range records {
		paths = append(paths, s.profileManager.GetStatePathFor(record.Key))
	}
	paths = append(paths, s.profileManager.GetStatePath())

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
	var merr *multierror.Error

	if err := cleanStateFile(ctx, s.profileManager.GetStatePathFor(key)); err != nil {
		merr = multierror.Append(merr, err)
	}

	if !s.otherSessionRunning(key) {
		if err := s.flushMarkedRoutes(); err != nil {
			merr = multierror.Append(merr, err)
		}
	}

	return nberrors.FormatErrorOrNil(merr)
}

// otherSessionRunning reports whether a session of another profile than key is running.
func (s *Server) otherSessionRunning(key profilemanager.SessionKey) bool {
	running, ok := s.session.runningKey()
	return ok && !sameSessionProfile(running, key)
}

func (s *Server) flushMarkedRoutes() error {
	if s.flushRoutesFn != nil {
		return s.flushRoutesFn()
	}
	return flushMarkedRoutes()
}

// openSlots takes over the slots stored in base, for a daemon that runs concurrent sessions. A
// state file without a sessions file comes from before slots and records the names of slot 0, so
// the active profile, which wrote it, becomes the owner of that slot. An existing sessions file
// already says who owns what, and NewSlots then ignores the owner.
func openSlots(base string, active profilemanager.SessionKey, activeStatePath string) (*hostcoord.Slots, error) {
	var opts []hostcoord.SlotsOption

	_, err := os.Stat(activeStatePath)
	switch {
	case err == nil:
		opts = append(opts, hostcoord.WithSlotZeroOwner(active))
	case !errors.Is(err, fs.ErrNotExist):
		return nil, fmt.Errorf("check state file: %w", err)
	}

	return hostcoord.NewSlots(base, opts...)
}
