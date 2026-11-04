//go:build linux && !android

package ipfwdstate

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/routemanager/sysctl"
)

const (
	ipv4ForwardingKey      = "net.ipv4.ip_forward"
	ipv4ForwardingProcPath = "/proc/sys/net/ipv4/ip_forward"
	acceptRAKeyFormat      = "net.ipv6.conf.%s.accept_ra"
)

func readV4Forwarding() (int, error) {
	raw, err := os.ReadFile(ipv4ForwardingProcPath)
	if err != nil {
		return 0, fmt.Errorf("read %s: %w", ipv4ForwardingKey, err)
	}
	value, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", ipv4ForwardingKey, err)
	}
	return value, nil
}

func writeV4Forwarding(value int) error {
	_, err := sysctl.Set(ipv4ForwardingKey, value, false)
	return err
}

// restoreAcceptRA writes the saved accept_ra value back for the given
// interfaces and drops them from saved, so a later restore leaves them alone.
// An interface that is already gone has nothing left to restore.
func restoreAcceptRA(saved map[string]int, names []string) {
	for _, name := range names {
		key := fmt.Sprintf(acceptRAKeyFormat, sysctl.EscapeInterfaceName(name))
		value, ok := saved[key]
		if !ok {
			continue
		}
		delete(saved, key)
		if _, err := sysctl.Set(key, value, false); err != nil {
			log.Debugf("restore %s: %v", key, err)
		}
	}
}
