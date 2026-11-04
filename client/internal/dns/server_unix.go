//go:build (linux && !android) || freebsd

package dns

func (s *DefaultServer) initialize() (manager hostManager, err error) {
	if s.hostDNS != nil {
		return newCoordinatedHostManager(s.wgInterface.Name(), s.hostDNS)
	}
	return newHostManager(s.wgInterface.Name())
}
