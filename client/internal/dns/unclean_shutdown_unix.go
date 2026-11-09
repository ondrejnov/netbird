//go:build (linux && !android) || freebsd

package dns

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/statemanager"
)

type ShutdownState struct {
	ManagerType osManagerType
	DNSAddress  netip.Addr
	WgIface     string
}

func (s *ShutdownState) Name() string {
	return "dns_state"
}

func (s *ShutdownState) Cleanup() error {
	if s.isGoneResolvedLink() {
		log.Infof("interface %s is gone, systemd-resolved dropped its DNS configuration with it", s.WgIface)
		return nil
	}

	manager, err := newHostManagerFromType(s.WgIface, s.ManagerType, nil)
	if err != nil {
		return fmt.Errorf("create previous host manager: %w", err)
	}

	if err := manager.restoreUncleanShutdownDNS(s.DNSAddress); err != nil {
		return fmt.Errorf("restore unclean shutdown dns: %w", err)
	}

	return nil
}

// isGoneResolvedLink reports whether the state names a systemd-resolved link that no longer exists.
// resolved forgets the configuration of a link when the link is removed, so there is nothing to revert.
func (s *ShutdownState) isGoneResolvedLink() bool {
	if s.ManagerType != systemdManager || s.WgIface == "" {
		return false
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Debugf("failed to list interfaces: %v", err)
		return false
	}
	for _, iface := range ifaces {
		if iface.Name == s.WgIface {
			return false
		}
	}
	return true
}

// TODO: move file contents to state manager
func createUncleanShutdownIndicator(sourcePath string, dnsAddress netip.Addr, stateManager *statemanager.Manager) error {
	dir := filepath.Dir(fileUncleanShutdownResolvConfLocation)
	if err := os.MkdirAll(dir, os.FileMode(0755)); err != nil {
		return fmt.Errorf("create dir %s: %w", dir, err)
	}

	if err := copyFile(sourcePath, fileUncleanShutdownResolvConfLocation); err != nil {
		return fmt.Errorf("create %s: %w", sourcePath, err)
	}

	state := &ShutdownState{
		ManagerType: fileManager,
		DNSAddress:  dnsAddress,
	}
	if err := stateManager.UpdateState(state); err != nil {
		return fmt.Errorf("update state: %w", err)
	}

	return nil
}
