//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package hostcoord

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStoreLock_FileHoldsNoStateAndIsPrivate(t *testing.T) {
	base := t.TempDir()
	_ = newFakeSlots(t, base)

	info, err := os.Stat(filepath.Join(base, sessionsLockFileName))
	require.NoError(t, err, "the lock lives in a file of its own, the sessions file gets replaced on save")
	assert.Zero(t, info.Size(), "the lock file carries no data")
	assert.Equal(t, os.FileMode(sessionsFileMode), info.Mode().Perm(), "only the owner can take the lock")
}
