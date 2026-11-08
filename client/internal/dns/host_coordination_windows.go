package dns

import (
	"fmt"
	"net"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// newCoordinatedHostManager returns the host manager of a session sharing the host with other
// sessions. Its rule keys are named after slot, so the cleanup of one session leaves the rules
// of the others.
func newCoordinatedHostManager(wgInterface WGIface, slot uint32, coordinator HostDNSCoordinator) (hostManager, error) {
	guid, err := wgInterface.GetInterfaceGUIDString()
	if err != nil {
		return nil, fmt.Errorf("get interface GUID: %w", err)
	}
	configurator, err := newRegistryConfigurator(&registryConfigurator{
		guid:       guid,
		slot:       slot,
		otherGUIDs: adapterGUIDs(coordinator.NetbirdInterfaces(), wgInterface.Name()),
		strict:     true,
	})
	if err != nil {
		return nil, err
	}
	return &ownedDomainsHostManager{hostManager: configurator, coordinator: coordinator}, nil
}

// adapterGUIDs returns the GUIDs of the named adapters other than own. An adapter that is gone
// has no nameservers to leave out.
func adapterGUIDs(names []string, own string) []string {
	var guids []string
	for _, name := range names {
		if name == own {
			continue
		}
		intf, err := net.InterfaceByName(name)
		if err != nil {
			log.Debugf("skip adapter %s of another session: %v", name, err)
			continue
		}
		luid, err := winipcfg.LUIDFromIndex(uint32(intf.Index))
		if err != nil {
			log.Debugf("skip adapter %s of another session: %v", name, err)
			continue
		}
		guid, err := luid.GUID()
		if err != nil {
			log.Debugf("skip adapter %s of another session: %v", name, err)
			continue
		}
		guids = append(guids, guid.String())
	}
	return guids
}
