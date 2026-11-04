//go:build linux && !android && privileged

package net

import (
	"sync"
	"sync/atomic"
	"syscall"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
)

const probeRulePriority = 32321

// foreignProbeRule is the rule CheckRuleOperationsSupport adds, spelled out here so
// the test plays the part of another process that is probing at the same moment.
func foreignProbeRule() *netlink.Rule {
	rule := netlink.NewRule()
	rule.Priority = probeRulePriority
	rule.Table = syscall.RT_TABLE_MAIN
	rule.Family = netlink.FAMILY_V4
	return rule
}

func probeRuleInstalled(t *testing.T) bool {
	t.Helper()

	rules, err := netlink.RuleList(netlink.FAMILY_V4)
	require.NoError(t, err)
	for _, rule := range rules {
		if rule.Priority == probeRulePriority {
			return true
		}
	}
	return false
}

// quietInit keeps the probes of a tight loop out of the test output.
func quietInit(t *testing.T) {
	t.Helper()

	level := log.GetLevel()
	log.SetLevel(log.ErrorLevel)
	t.Cleanup(func() { log.SetLevel(level) })
}

// requireAdvancedRoutingBaseline leaves the process in advanced routing, as a daemon
// on a capable host is, and restores that once the test's environment is restored.
func requireAdvancedRoutingBaseline(t *testing.T) {
	t.Helper()

	t.Cleanup(Init)
	Init()
	require.True(t, AdvancedRouting(), "the test needs a host with advanced routing")
}

// Two sessions starting at once used to collide on the probe rule. The loser saw
// EEXIST and moved the whole process to legacy routing, which stops marking sockets
// for every session. Readers run alongside so that -race sees the published flag.
func TestInit_ConcurrentStartsStayOnAdvancedRouting(t *testing.T) {
	quietInit(t)
	requireAdvancedRoutingBaseline(t)

	stop := make(chan struct{})
	var readers sync.WaitGroup
	var sawLegacy atomic.Bool
	for range 2 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
					if !AdvancedRouting() {
						sawLegacy.Store(true)
					}
				}
			}
		}()
	}

	const rounds, starters = 200, 4
	legacyRounds := 0
	for range rounds {
		var wg sync.WaitGroup
		for range starters {
			wg.Add(1)
			go func() {
				defer wg.Done()
				Init()
			}()
		}
		wg.Wait()
		if !AdvancedRouting() {
			legacyRounds++
		}
	}
	close(stop)
	readers.Wait()

	assert.Zero(t, legacyRounds, "concurrent Init ended on legacy routing in %d of %d rounds", legacyRounds, rounds)
	assert.False(t, sawLegacy.Load(), "a reader saw legacy routing while sessions were starting")
	assert.False(t, probeRuleInstalled(t), "the probes must not leave their rule behind")
}

// A foreground client or login in another process can hold the probe rule while the
// daemon starts, and a crash can leave it behind. EEXIST comes from the kernel's rule
// code, so it proves rule operations work. The rule is not ours to delete.
func TestInit_ExistingProbeRuleKeepsAdvancedRouting(t *testing.T) {
	quietInit(t)
	requireAdvancedRoutingBaseline(t)

	require.NoError(t, netlink.RuleAdd(foreignProbeRule()))
	t.Cleanup(func() {
		if err := netlink.RuleDel(foreignProbeRule()); err != nil {
			t.Logf("delete probe rule: %v", err)
		}
	})

	Init()

	assert.True(t, AdvancedRouting(), "a probe rule held by someone else must not mean legacy routing")
	assert.True(t, probeRuleInstalled(t), "Init must leave a rule it did not add in place")
}

// The probe used to raise the process flag for its own socket. On a host in legacy
// routing, every dial and listen of a running session could then see advanced routing
// for as long as the probe lasted, and skip its exclusion route hooks.
func TestCheckFwmarkSupport_LeavesAdvancedRoutingAlone(t *testing.T) {
	quietInit(t)
	requireAdvancedRoutingBaseline(t)

	t.Setenv(envUseLegacyRouting, "true")
	Init()
	require.False(t, AdvancedRouting(), "%s must select legacy routing", envUseLegacyRouting)

	stop := make(chan struct{})
	done := make(chan struct{})
	var sawAdvanced atomic.Bool
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
				if AdvancedRouting() {
					sawAdvanced.Store(true)
				}
			}
		}
	}()

	supported := true
	for range 200 {
		supported = CheckFwmarkSupport() && supported
	}
	close(stop)
	<-done

	assert.True(t, supported, "the host supports fwmarks, the probe must report it")
	assert.False(t, sawAdvanced.Load(), "the probe switched the process to advanced routing")
	assert.False(t, AdvancedRouting(), "the probe must leave legacy routing in place")
}

// The probe only says something if its socket really carries the mark. A socket from
// the package Dialer stays unmarked while advanced routing is off, and writing on an
// unmarked socket succeeds on any host, so the probe would stop detecting anything.
func TestFwmarkProbeSocketCarriesMark(t *testing.T) {
	quietInit(t)
	requireAdvancedRoutingBaseline(t)

	t.Setenv(envUseLegacyRouting, "true")
	Init()
	require.False(t, AdvancedRouting(), "%s must select legacy routing", envUseLegacyRouting)

	conn, err := dialFwmarkProbe()
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Logf("close probe socket: %v", err)
		}
	})

	sysConn, ok := conn.(syscall.Conn)
	require.True(t, ok, "the probe socket must expose its descriptor")
	raw, err := sysConn.SyscallConn()
	require.NoError(t, err)

	var mark int
	var markErr error
	require.NoError(t, raw.Control(func(fd uintptr) {
		mark, markErr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK)
	}))
	require.NoError(t, markErr)

	assert.Equal(t, int(ControlPlaneMark), mark, "the probe socket must carry the control plane mark")
}
