//go:build !windows

package internal

import "github.com/netbirdio/netbird/client/internal/hostcoord"

// shareSessionInterfaces does nothing: outside Windows, sockets keep off the NetBird interfaces by
// fwmark, by binding to the physical interface on macOS, or do not run concurrent sessions.
func shareSessionInterfaces(*hostcoord.Sessions) {}
