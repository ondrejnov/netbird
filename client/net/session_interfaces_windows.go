package net

import (
	"slices"
	"sync/atomic"
)

// sessionInterfaces reports the interfaces of all sessions of the daemon. The daemon sets it once;
// the interfaces themselves live in its coordinator, not here.
var sessionInterfaces atomic.Pointer[func() []string]

// SetSessionInterfacesSource makes socket binding skip every interface src reports, besides the one
// named by SetVPNInterfaceName. With concurrent sessions that name is the interface of whichever
// engine started or stopped last, so it alone would let a socket of one session pick the interface
// of another, an exit node for instance. Nil removes the source.
func SetSessionInterfacesSource(src func() []string) {
	if src == nil {
		sessionInterfaces.Store(nil)
		return
	}
	sessionInterfaces.Store(&src)
}

// excludedInterfaces returns the interfaces a socket must not be bound to.
func excludedInterfaces() []string {
	var names []string
	if name := GetVPNInterfaceName(); name != "" {
		names = append(names, name)
	}
	src := sessionInterfaces.Load()
	if src == nil {
		return names
	}
	for _, name := range (*src)() {
		if name != "" && !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	return names
}
