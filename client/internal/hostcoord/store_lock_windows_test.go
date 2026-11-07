//go:build windows

package hostcoord

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStoreLock_FollowsNoJunction(t *testing.T) {
	// A junction needs no privilege, unlike a symbolic link, so it is the reparse point an
	// unprivileged user could plant. Opened as itself it is refused, and nothing lands in
	// the directory it points at.
	base := t.TempDir()
	target := t.TempDir()
	link := filepath.Join(base, sessionsLockFileName)
	out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput()
	require.NoError(t, err, "create junction: %s", out)

	_, err = NewSlots(base)
	require.Error(t, err, "a junction at the lock path is refused, not followed")
	assert.NotErrorIs(t, err, ErrSessionsLocked, "nobody holds the lock")

	entries, err := os.ReadDir(target)
	require.NoError(t, err)
	assert.Empty(t, entries, "the target of the junction is not touched")
}

func TestStoreLock_FileHoldsNoState(t *testing.T) {
	base := t.TempDir()
	_ = newFakeSlots(t, base)

	info, err := os.Stat(filepath.Join(base, sessionsLockFileName))
	require.NoError(t, err, "the lock lives in a file of its own, the sessions file gets replaced on save")
	assert.True(t, info.Mode().IsRegular(), "the lock is a regular file")
	assert.Zero(t, info.Size(), "the lock file carries no data")
}
