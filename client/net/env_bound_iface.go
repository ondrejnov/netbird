//go:build (darwin && !ios) || windows

package net

import (
	"os"
	"strconv"
	"sync"
	"sync/atomic"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/iface/netstack"
)

var (
	vpnInterfaceName string
	vpnInitMutex     sync.RWMutex

	advancedRoutingSupported atomic.Bool
)

// Init detects whether advanced routing can be used. The daemon calls it once at startup,
// and clients that run without a daemon call it on every run. It is safe to repeat and
// to call concurrently.
func Init() {
	advancedRoutingSupported.Store(checkAdvancedRoutingSupport())
}

func checkAdvancedRoutingSupport() bool {
	legacyRouting := false
	if val := os.Getenv(envUseLegacyRouting); val != "" {
		parsed, err := strconv.ParseBool(val)
		if err != nil {
			log.Warnf("ignoring unparsable %s=%q: %v", envUseLegacyRouting, val, err)
		} else {
			legacyRouting = parsed
		}
	}

	if legacyRouting {
		log.Infof("advanced routing disabled: legacy routing requested via %s", envUseLegacyRouting)
		return false
	}
	if netstack.IsEnabled() {
		log.Info("advanced routing disabled: netstack mode is enabled")
		return false
	}

	log.Info("system supports advanced routing")

	return true
}

// AdvancedRouting reports whether routing loops can be avoided without using exclusion routes
func AdvancedRouting() bool {
	return advancedRoutingSupported.Load()
}

// GetVPNInterfaceName returns the stored VPN interface name
func GetVPNInterfaceName() string {
	vpnInitMutex.RLock()
	defer vpnInitMutex.RUnlock()
	return vpnInterfaceName
}

// SetVPNInterfaceName sets the VPN interface name for lazy initialization
func SetVPNInterfaceName(name string) {
	vpnInitMutex.Lock()
	defer vpnInitMutex.Unlock()
	vpnInterfaceName = name

	if name != "" {
		log.Infof("VPN interface name set to %s for route exclusion", name)
	}
}
