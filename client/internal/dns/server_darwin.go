//go:build !ios

package dns

func (s *DefaultServer) initialize() (manager hostManager, err error) {
	if s.hostDNS != nil {
		return newCoordinatedHostManager(s.hostSlot, s.hostDNS), nil
	}
	return newHostManager()
}
