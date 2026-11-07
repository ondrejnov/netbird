package internal

import (
	"github.com/netbirdio/netbird/client/internal/hostcoord"
	nbnet "github.com/netbirdio/netbird/client/net"
)

// shareSessionInterfaces makes the sockets of every session skip the interfaces of all of them.
func shareSessionInterfaces(sessions *hostcoord.Sessions) {
	nbnet.SetSessionInterfacesSource(sessions.SessionInterfaces)
}
