package hostcoord

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
)

const (
	sessionsFileName     = "sessions.json"
	sessionsLockFileName = "sessions.lock"
	sessionsFileVersion  = 1
	sessionsFileMode     = 0o600
	sessionsDirMode      = 0o750
)

// ErrCorruptSessions reports a sessions file the daemon cannot trust. The file stays
// in place, because its slots decide which state files and interfaces a session owns.
var ErrCorruptSessions = errors.New("corrupt sessions file")

// ErrSessionsLocked reports another instance holding the sessions file. A save from
// here would replace the whole file and drop the slots that instance assigned.
var ErrSessionsLocked = errors.New("sessions file is held by another instance")

// slotState is what the sessions file remembers about one session.
type slotState struct {
	slot    Slot
	desired DesiredState
}

// sessionsFile is the on-disk format. It must never hold secrets. Interface names and
// ports stay out as well, since they are derived from the slot and the profile config.
type sessionsFile struct {
	Version  int           `json:"version"`
	Sessions []fileSession `json:"sessions"`
}

// fileSession uses a pointer for the slot so a missing number is not read as slot 0.
type fileSession struct {
	Profile  profilemanager.ID `json:"profile"`
	Username string            `json:"username"`
	Slot     *Slot             `json:"slot"`
	Desired  DesiredState      `json:"desired"`
}

// sessionStore reads and writes the sessions file of one daemon.
type sessionStore struct {
	path string
}

func newSessionStore(base string) *sessionStore {
	return &sessionStore{path: filepath.Join(base, sessionsFileName)}
}

// load returns the stored sessions and whether the file exists. A missing file is an
// empty state, which is how an installation from before this file looks. Nothing is
// written or removed.
func (st *sessionStore) load() (map[SessionKey]slotState, bool, error) {
	data, err := os.ReadFile(st.path)
	if errors.Is(err, fs.ErrNotExist) {
		return make(map[SessionKey]slotState), false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("read sessions file: %w", err)
	}

	records, err := decodeSessions(data)
	if err != nil {
		return nil, false, fmt.Errorf("%w %s: %v", ErrCorruptSessions, st.path, err)
	}
	return records, true, nil
}

// save replaces the sessions file. Anything load would refuse is refused here too, so
// the daemon cannot write a file that stops its next start.
func (st *sessionStore) save(records map[SessionKey]slotState) error {
	file := encodeSessions(records)
	if _, err := parseSessions(file); err != nil {
		return fmt.Errorf("invalid session record: %w", err)
	}

	data, err := json.MarshalIndent(file, "", "    ")
	if err != nil {
		return fmt.Errorf("marshal sessions: %w", err)
	}
	if err := writeFileAtomic(st.path, data); err != nil {
		return fmt.Errorf("write sessions file: %w", err)
	}
	return nil
}

func closeSessionsLock(lock io.Closer) {
	if err := lock.Close(); err != nil {
		log.Debugf("failed to close sessions lock: %v", err)
	}
}

// decodeSessions refuses unknown fields because a later save would silently drop them.
func decodeSessions(data []byte) (map[SessionKey]slotState, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	var file sessionsFile
	if err := decoder.Decode(&file); err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("data after the sessions object")
	}
	return parseSessions(file)
}

func parseSessions(file sessionsFile) (map[SessionKey]slotState, error) {
	if file.Version != sessionsFileVersion {
		return nil, fmt.Errorf("unsupported version %d", file.Version)
	}

	records := make(map[SessionKey]slotState, len(file.Sessions))
	slots := make(map[Slot]struct{}, len(file.Sessions))
	for _, entry := range file.Sessions {
		if !profilemanager.IsValidProfileFilenameStem(entry.Profile) {
			return nil, fmt.Errorf("invalid profile ID %q", entry.Profile)
		}
		if entry.Slot == nil {
			return nil, fmt.Errorf("profile %q has no slot", entry.Profile)
		}
		if !entry.Desired.valid() {
			return nil, fmt.Errorf("profile %q has unknown desired state %q", entry.Profile, entry.Desired)
		}

		key := SessionKey{Profile: entry.Profile, Username: entry.Username}
		if _, seen := records[key]; seen {
			return nil, fmt.Errorf("profile %q is listed twice", entry.Profile)
		}
		if _, seen := slots[*entry.Slot]; seen {
			return nil, fmt.Errorf("slot %d is listed twice", *entry.Slot)
		}
		slots[*entry.Slot] = struct{}{}
		records[key] = slotState{slot: *entry.Slot, desired: entry.Desired}
	}
	return records, nil
}

func encodeSessions(records map[SessionKey]slotState) sessionsFile {
	sessions := make([]fileSession, 0, len(records))
	for key, state := range records {
		slot := state.slot
		sessions = append(sessions, fileSession{
			Profile:  key.Profile,
			Username: key.Username,
			Slot:     &slot,
			Desired:  state.desired,
		})
	}
	slices.SortFunc(sessions, func(a, b fileSession) int {
		return cmp.Compare(*a.Slot, *b.Slot)
	})
	return sessionsFile{Version: sessionsFileVersion, Sessions: sessions}
}

// writeFileAtomic syncs before the rename: a crash must not leave an empty file behind,
// because load treats that as corruption and the daemon would refuse to continue.
func writeFileAtomic(path string, data []byte) (err error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, sessionsDirMode); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		if err == nil {
			return
		}
		if removeErr := os.Remove(tmpPath); removeErr != nil && !errors.Is(removeErr, fs.ErrNotExist) {
			log.Debugf("failed to remove temp file %s: %v", tmpPath, removeErr)
		}
	}()

	if err := writeAndClose(tmp, data); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename temp file: %w", err)
	}
	syncDir(dir)
	return nil
}

func writeAndClose(file *os.File, data []byte) error {
	_, err := file.Write(data)
	if err == nil {
		err = file.Chmod(sessionsFileMode)
	}
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}
	return nil
}

// syncDir makes the rename durable. The new content is already in place when this runs
// and not every platform can sync a directory, so a failure does not fail the write.
func syncDir(dir string) {
	handle, err := os.Open(dir)
	if err != nil {
		log.Debugf("failed to open directory for sync: %v", err)
		return
	}
	defer func() {
		if err := handle.Close(); err != nil {
			log.Debugf("failed to close directory after sync: %v", err)
		}
	}()
	if err := handle.Sync(); err != nil {
		log.Debugf("failed to sync directory: %v", err)
	}
}
