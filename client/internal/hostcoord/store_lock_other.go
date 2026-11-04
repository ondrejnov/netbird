//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly)

package hostcoord

import "io"

type noSessionsLock struct{}

func (noSessionsLock) Close() error { return nil }

// lockSessions takes no lock: this platform has no flock, and concurrent sessions and
// the foreground instance that could race the daemon for the file only exist on Linux.
func lockSessions(string) (io.Closer, error) {
	return noSessionsLock{}, nil
}
