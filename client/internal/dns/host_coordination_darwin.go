//go:build !ios

package dns

// newCoordinatedHostManager returns the host manager of a session sharing the host with other
// sessions. Its scutil keys are named after slot, so the cleanup of one session leaves the keys of
// the others, and every domain and the catch-all have one owning session.
func newCoordinatedHostManager(slot uint32, coordinator HostDNSCoordinator) hostManager {
	configurator := newSlotHostManager(slot)
	configurator.strict = true
	return &ownedDomainsHostManager{hostManager: configurator, coordinator: coordinator}
}
