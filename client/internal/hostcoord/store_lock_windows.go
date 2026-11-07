//go:build windows

package hostcoord

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// lockSessions holds an exclusive lock on a file of its own in base until the returned
// closer closes. The kernel drops it when the process dies, so a crash leaves nothing
// stale. The sessions file cannot carry the lock, since every save replaces it.
func lockSessions(base string) (io.Closer, error) {
	if err := os.MkdirAll(base, sessionsDirMode); err != nil {
		return nil, fmt.Errorf("create directory: %w", err)
	}

	path := filepath.Join(base, sessionsLockFileName)
	file, err := openLockFile(path)
	if err != nil {
		return nil, fmt.Errorf("open sessions lock: %w", err)
	}
	if err := refuseReparsePoint(file); err != nil {
		closeSessionsLock(file)
		return nil, err
	}
	if err := lockFileExclusive(file); err != nil {
		closeSessionsLock(file)
		return nil, err
	}
	return file, nil
}

// openLockFile opens path without following a reparse point, the Windows counterpart of
// O_NOFOLLOW, so a link placed there cannot point the lock at another file.
func openLockFile(path string) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		name,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(handle), path), nil
}

// refuseReparsePoint refuses a lock path that is not a regular file: a directory, a symbolic
// link or a junction opened as itself.
func refuseReparsePoint(file *os.File) error {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &info); err != nil {
		return fmt.Errorf("inspect %s: %w", file.Name(), err)
	}
	const notRegular = windows.FILE_ATTRIBUTE_REPARSE_POINT | windows.FILE_ATTRIBUTE_DIRECTORY
	if info.FileAttributes&notRegular != 0 {
		return fmt.Errorf("lock %s: not a regular file", file.Name())
	}
	return nil
}

func lockFileExclusive(file *os.File) error {
	var overlapped windows.Overlapped
	err := windows.LockFileEx(
		windows.Handle(file.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0,
		1,
		0,
		&overlapped,
	)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, windows.ERROR_LOCK_VIOLATION):
		return fmt.Errorf("%w: %s", ErrSessionsLocked, file.Name())
	default:
		return fmt.Errorf("lock %s: %w", file.Name(), err)
	}
}
