//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly || windows)

package hostcoord

import "io"

type noSessionsLock struct{}

func (noSessionsLock) Close() error { return nil }

// lockSessions takes no lock: this platform has neither flock nor LockFileEx, and concurrent
// sessions and the foreground instance that could race the daemon for the file do not run here.
func lockSessions(string) (io.Closer, error) {
	return noSessionsLock{}, nil
}
