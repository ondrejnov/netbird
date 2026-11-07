package dns

func (s *DefaultServer) initialize() (hostManager, error) {
	if s.hostDNS != nil {
		return newCoordinatedHostManager(s.wgInterface, s.hostSlot, s.hostDNS)
	}
	return newHostManager(s.wgInterface)
}
