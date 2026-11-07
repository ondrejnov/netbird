//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly || windows

package hostcoord

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStoreLock_SecondInstanceIsRefused(t *testing.T) {
	// The daemon gives profile X slot 1 while a foreground process holds an older copy of
	// the file. Letting that process write would drop X, so it must not get that far.
	base := t.TempDir()
	daemon := newFakeSlots(t, base)
	_, err := daemon.Reserve(sessionKey("x"), autoRequest)
	require.NoError(t, err)

	path := filepath.Join(base, sessionsFileName)
	before, err := os.ReadFile(path)
	require.NoError(t, err)

	second, err := NewSlots(base)
	if second != nil {
		t.Cleanup(func() { closeSlots(t, second) })
	}
	assert.ErrorIs(t, err, ErrSessionsLocked, "a second instance on one base is refused")
	assert.Nil(t, second, "a refused instance is not usable")

	_, err = NewSlots(base, WithSlotZeroOwner(sessionKey("y")))
	assert.ErrorIs(t, err, ErrSessionsLocked, "the migration does not get past the lock either")

	after, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, string(before), string(after), "the refused instance changes nothing")

	res, err := daemon.Reserve(sessionKey("z"), autoRequest)
	require.NoError(t, err, "the first instance keeps working")
	assert.Equal(t, Slot(1), res.Slot, "and keeps its view of the slots")
}

func TestStoreLock_ReleasedByClose(t *testing.T) {
	base := t.TempDir()
	first := newFakeSlots(t, base)
	_, err := first.Reserve(sessionKey("x"), autoRequest)
	require.NoError(t, err)
	closeSlots(t, first)

	second := newFakeSlots(t, base)
	assert.Equal(t, []SlotRecord{{Key: sessionKey("x"), Slot: 0, Desired: DesiredDown}}, second.Records(),
		"the next instance takes over the stored state")
}

func TestStoreLock_FollowsNoSymlink(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(t.TempDir(), "target")
	require.NoError(t, os.WriteFile(target, []byte("keep"), 0o600))
	if err := os.Symlink(target, filepath.Join(base, sessionsLockFileName)); err != nil {
		// Windows creates a symbolic link only with the privilege or in developer mode.
		t.Skipf("create symbolic link: %v", err)
	}

	_, err := NewSlots(base)
	require.Error(t, err, "a link at the lock path is refused, not followed")
	kept, readErr := os.ReadFile(target)
	require.NoError(t, readErr)
	assert.Equal(t, "keep", string(kept), "the target of the link is not touched")
	assert.NotErrorIs(t, err, ErrSessionsLocked, "nobody holds the lock")
}

func TestStoreLock_UnusableLockPathRefusesTheInstance(t *testing.T) {
	base := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(base, sessionsLockFileName), 0o700))

	_, err := NewSlots(base)
	require.Error(t, err, "without the lock the instance could overwrite another one")
	assert.NotErrorIs(t, err, ErrSessionsLocked, "the reason is the path, not another instance")
}

func TestStoreLock_CreatesMissingBase(t *testing.T) {
	base := filepath.Join(t.TempDir(), "missing", "base")

	s := newFakeSlots(t, base)
	res, err := s.Reserve(sessionKey("x"), autoRequest)
	require.NoError(t, err, "a missing base is not an error, the same as for the first save")
	assert.Equal(t, Slot(0), res.Slot, "the first session takes slot 0")
}
