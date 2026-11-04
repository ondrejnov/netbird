//go:build linux && !android

package net

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/netbirdio/netbird/client/iface/netstack"
)

const (
	// these have the same effect, skip socket env supported for backward compatibility
	envSkipSocketMark = "NB_SKIP_SOCKET_MARK"

	fwmarkProbeTimeout = 100 * time.Millisecond
)

var (
	advancedRoutingSupported atomic.Bool
	// probeMu orders the probes, so that the last Init decides the result.
	probeMu sync.Mutex
)

// Init detects whether the host supports advanced routing. The daemon calls it once at
// startup, and clients that run without a daemon call it on every run. It is safe to
// repeat and to call concurrently. Readers keep the previous result until a probe ends.
func Init() {
	probeMu.Lock()
	defer probeMu.Unlock()

	advancedRoutingSupported.Store(checkAdvancedRoutingSupport())
}

// AdvancedRouting reports whether routing loops can be avoided without using exclusion routes
func AdvancedRouting() bool {
	return advancedRoutingSupported.Load()
}

func checkAdvancedRoutingSupport() bool {
	var err error

	var legacyRouting bool
	if val := os.Getenv(envUseLegacyRouting); val != "" {
		legacyRouting, err = strconv.ParseBool(val)
		if err != nil {
			log.Warnf("failed to parse %s: %v", envUseLegacyRouting, err)
		}
	}

	var skipSocketMark bool
	if val := os.Getenv(envSkipSocketMark); val != "" {
		skipSocketMark, err = strconv.ParseBool(val)
		if err != nil {
			log.Warnf("failed to parse %s: %v", envSkipSocketMark, err)
		}
	}

	// requested to disable advanced routing
	if legacyRouting || skipSocketMark ||
		// envCustomRoutingDisabled disables the custom dialers.
		// There is no point in using advanced routing without those, as they set up fwmarks on the sockets.
		CustomRoutingDisabled() ||
		// netstack mode doesn't need routing at all
		netstack.IsEnabled() {

		log.Info("advanced routing has been requested to be disabled")
		return false
	}

	if !CheckFwmarkSupport() || !CheckRuleOperationsSupport() {
		log.Warn("system doesn't support required routing features, falling back to legacy routing")
		return false
	}

	log.Info("system supports advanced routing")

	return true
}

// CheckFwmarkSupport reports whether a socket with the control plane fwmark can send.
func CheckFwmarkSupport() bool {
	conn, err := dialFwmarkProbe()
	if err != nil {
		log.Warnf("failed to dial with fwmark: %v", err)
		return false
	}

	defer func() {
		if err := conn.Close(); err != nil {
			log.Warnf("failed to close connection: %v", err)
		}
	}()

	if err := conn.SetWriteDeadline(time.Now().Add(fwmarkProbeTimeout)); err != nil {
		log.Warnf("failed to set write deadline: %v", err)
		return false
	}

	if _, err := conn.Write([]byte("")); err != nil {
		log.Warnf("failed to write to fwmark connection: %v", err)
		return false
	}

	return true
}

// dialFwmarkProbe marks the socket itself: the package Dialer only marks once advanced
// routing is on, and that is what the probe has yet to decide.
func dialFwmarkProbe() (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout: fwmarkProbeTimeout,
		Control: func(_, _ string, c syscall.RawConn) error {
			var markErr error
			if err := c.Control(func(fd uintptr) {
				markErr = setSocketOptInt(int(fd))
			}); err != nil {
				return fmt.Errorf("control: %w", err)
			}
			if markErr != nil {
				return fmt.Errorf("set SO_MARK: %w", markErr)
			}
			return nil
		},
	}
	return dialer.Dial("udp", "127.0.0.1:9")
}

// CheckRuleOperationsSupport reports whether the kernel supports ip rule operations.
func CheckRuleOperationsSupport() bool {
	rule := netlink.NewRule()
	// low precedence, semi-random
	rule.Priority = 32321
	rule.Table = syscall.RT_TABLE_MAIN
	rule.Family = netlink.FAMILY_V4

	if err := netlink.RuleAdd(rule); err != nil {
		// Another process is probing, or a crashed one left the rule behind. The kernel
		// got as far as comparing rules, so they work. Deleting the rule is up to its owner.
		if errors.Is(err, syscall.EEXIST) {
			log.Debugf("test rule already exists: %v", err)
			return true
		}
		if errors.Is(err, syscall.EOPNOTSUPP) {
			log.Warn("IP rule operations are not supported")
			return false
		}
		log.Warnf("failed to test rule support: %v", err)
		return false
	}

	if err := netlink.RuleDel(rule); err != nil {
		log.Warnf("failed to delete test rule: %v", err)
	}
	return true
}

// SetVPNInterfaceName is a no-op on Linux
func SetVPNInterfaceName(name string) {
	// No-op on Linux - not needed for fwmark-based routing
}

// GetVPNInterfaceName returns empty string on Linux
func GetVPNInterfaceName() string {
	return ""
}
