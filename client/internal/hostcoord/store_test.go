package hostcoord

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeSessionsFile(t *testing.T, base, content string) string {
	t.Helper()
	path := filepath.Join(base, sessionsFileName)
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

// entriesBesideLock lists base without the lock file, which holds no state and which
// platforms with file locks create as soon as an instance opens.
func entriesBesideLock(t *testing.T, base string) []string {
	t.Helper()
	entries, err := os.ReadDir(base)
	require.NoError(t, err)
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.Name() != sessionsLockFileName {
			names = append(names, entry.Name())
		}
	}
	return names
}

func TestStore_MissingFileIsEmptyAndNotCreated(t *testing.T) {
	base := t.TempDir()

	s, err := NewSlots(base)
	require.NoError(t, err, "older installations have no sessions.json")
	t.Cleanup(func() { closeSlots(t, s) })
	assert.Empty(t, s.Records(), "a missing file means an empty state")

	assert.Empty(t, entriesBesideLock(t, base), "without a slot 0 owner, opening stores no state (I1)")
}

func TestStore_CorruptFileReturnsErrorAndKeepsFile(t *testing.T) {
	const entry = `{"profile":"a","username":"u","slot":0,"desired":"up"}`
	tests := map[string]string{
		"empty file":        ``,
		"truncated":         `{"version":1,"sessions":[{"profile":"a"`,
		"not an object":     `[]`,
		"trailing data":     `{"version":1,"sessions":[]} {}`,
		"missing version":   `{"sessions":[]}`,
		"unknown version":   `{"version":2,"sessions":[]}`,
		"unknown field":     `{"version":1,"sessions":[{"profile":"a","username":"u","slot":0,"desired":"up","key":"x"}]}`,
		"negative slot":     `{"version":1,"sessions":[{"profile":"a","username":"u","slot":-1,"desired":"up"}]}`,
		"fractional slot":   `{"version":1,"sessions":[{"profile":"a","username":"u","slot":1.5,"desired":"up"}]}`,
		"overflowing slot":  `{"version":1,"sessions":[{"profile":"a","username":"u","slot":4294967296,"desired":"up"}]}`,
		"missing slot":      `{"version":1,"sessions":[{"profile":"a","username":"u","desired":"up"}]}`,
		"null slot":         `{"version":1,"sessions":[{"profile":"a","username":"u","slot":null,"desired":"up"}]}`,
		"unknown desired":   `{"version":1,"sessions":[{"profile":"a","username":"u","slot":0,"desired":"maybe"}]}`,
		"missing desired":   `{"version":1,"sessions":[{"profile":"a","username":"u","slot":0}]}`,
		"empty profile":     `{"version":1,"sessions":[{"profile":"","username":"u","slot":0,"desired":"up"}]}`,
		"traversal profile": `{"version":1,"sessions":[{"profile":"../../etc/x","username":"u","slot":0,"desired":"up"}]}`,
		"duplicate key":     `{"version":1,"sessions":[` + entry + `,{"profile":"a","username":"u","slot":1,"desired":"up"}]}`,
		"duplicate slot":    `{"version":1,"sessions":[` + entry + `,{"profile":"b","username":"u","slot":0,"desired":"up"}]}`,
	}
	for name, content := range tests {
		t.Run(name, func(t *testing.T) {
			base := t.TempDir()
			path := writeSessionsFile(t, base, content)

			_, err := NewSlots(base)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrCorruptSessions)

			_, err = NewSlots(base)
			assert.ErrorIs(t, err, ErrCorruptSessions, "the refused instance must not keep the lock")

			got, err := os.ReadFile(path)
			require.NoError(t, err, "the corrupt file must stay in place")
			assert.Equal(t, content, string(got), "the corrupt file must stay byte for byte")
			assert.Len(t, entriesBesideLock(t, base), 1, "no state may appear next to the corrupt file")
		})
	}
}

func TestStore_UnreadableFileIsNotTreatedAsMissing(t *testing.T) {
	base := t.TempDir()
	// A directory at the path fails the read for a reason other than "not found".
	require.NoError(t, os.Mkdir(filepath.Join(base, sessionsFileName), 0o700))

	_, err := NewSlots(base)
	assert.Error(t, err, "only a missing file means an empty state")
}

func TestStore_FileHoldsOnlySlotAndDesiredState(t *testing.T) {
	base := t.TempDir()
	s := newFakeSlots(t, base)
	_, err := s.Reserve(sessionKey("a"), ResourceRequest{WgIface: "custom0", WgPort: 40000})
	require.NoError(t, err)
	require.NoError(t, s.SetDesired(sessionKey("a"), DesiredUp))

	data, err := os.ReadFile(filepath.Join(base, sessionsFileName))
	require.NoError(t, err)

	var file struct {
		Version  int              `json:"version"`
		Sessions []map[string]any `json:"sessions"`
	}
	require.NoError(t, json.Unmarshal(data, &file))
	assert.Equal(t, 1, file.Version, "the format carries a version")
	require.Len(t, file.Sessions, 1, "one session was reserved")
	assert.Equal(t, map[string]any{
		"profile":  "a",
		"username": "u",
		"slot":     float64(0),
		"desired":  "up",
	}, file.Sessions[0], "only identity, slot and desired state are stored: no secrets, no interface, no port")
}

func TestStore_SaveUsesRestrictedPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits do not apply")
	}
	base := t.TempDir()
	// A looser file left behind by an administrator must not stay loose.
	path := writeSessionsFile(t, base, `{"version":1,"sessions":[]}`)
	require.NoError(t, os.Chmod(path, 0o644))

	s := newFakeSlots(t, base)
	_, err := s.Reserve(sessionKey("a"), ResourceRequest{WgIface: autoIface, WgPort: autoPort})
	require.NoError(t, err)

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "sessions.json must be readable only by its owner")
}

func TestStore_FailedSaveKeepsMemoryAndLeavesNoTempFile(t *testing.T) {
	base := t.TempDir()
	s := newFakeSlots(t, base)

	// Rename onto a non-empty directory fails even for root, unlike permission tricks.
	path := filepath.Join(base, sessionsFileName)
	require.NoError(t, os.Mkdir(path, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(path, "x"), nil, 0o600))

	_, err := s.Reserve(sessionKey("a"), ResourceRequest{WgIface: autoIface, WgPort: autoPort})
	require.Error(t, err, "a slot that cannot be stored would not survive a restart")
	assert.Empty(t, s.Records(), "the slot is published only after the write")

	assert.Len(t, entriesBesideLock(t, base), 1, "the temporary file is removed after a failed write")

	require.NoError(t, os.RemoveAll(path))
	res, err := s.Reserve(sessionKey("a"), ResourceRequest{WgIface: autoIface, WgPort: autoPort})
	require.NoError(t, err)
	assert.Equal(t, Slot(0), res.Slot, "the failed attempt must not have used up a slot")
}

func TestStore_RejectsKeyThatWouldCorruptTheFile(t *testing.T) {
	base := t.TempDir()
	s := newFakeSlots(t, base)

	_, err := s.Reserve(SessionKey{Profile: "../x", Username: "u"}, ResourceRequest{WgIface: autoIface, WgPort: autoPort})
	require.Error(t, err, "the next start would refuse a file holding this key")

	closeSlots(t, s)
	reopened, err := NewSlots(base)
	require.NoError(t, err, "the file on disk must stay loadable")
	t.Cleanup(func() { closeSlots(t, reopened) })
	assert.Empty(t, reopened.Records(), "the rejected key is not stored")
}
