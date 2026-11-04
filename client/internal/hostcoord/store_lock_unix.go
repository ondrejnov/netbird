//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package hostcoord

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// lockSessions holds an exclusive lock on a file of its own in base until the returned
// closer closes. The kernel drops it when the process dies, so a crash leaves nothing
// stale. The sessions file cannot carry the lock, since every save replaces it.
func lockSessions(base string) (io.Closer, error) {
	if err := os.MkdirAll(base, sessionsDirMode); err != nil {
		return nil, fmt.Errorf("create directory: %w", err)
	}

	path := filepath.Join(base, sessionsLockFileName)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, sessionsFileMode)
	if err != nil {
		return nil, fmt.Errorf("open sessions lock: %w", err)
	}
	if err := flockExclusive(file); err != nil {
		closeSessionsLock(file)
		return nil, err
	}
	return file, nil
}

func flockExclusive(file *os.File) error {
	for {
		err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		switch {
		case err == nil:
			return nil
		case errors.Is(err, syscall.EINTR):
			continue
		case errors.Is(err, syscall.EWOULDBLOCK):
			return fmt.Errorf("%w: %s", ErrSessionsLocked, file.Name())
		default:
			return fmt.Errorf("lock %s: %w", file.Name(), err)
		}
	}
}
