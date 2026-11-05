//go:build privileged && linux

package internal

import (
	"errors"
	"net/netip"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/dns"
	"github.com/netbirdio/netbird/client/internal/hostcoord"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	cProto "github.com/netbirdio/netbird/client/proto"
)

func newTestDaemonHost(t *testing.T) *DaemonHost {
	t.Helper()
	// A namespace of its own, as the isolation rules are real.
	runtime.LockOSThread()
	require.NoError(t, unix.Unshare(unix.CLONE_NEWNET), "enter a network namespace")

	slots, err := hostcoord.NewSlots(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, slots.Close()) })
	return NewDaemonHost(slots)
}

func attachTestSession(t *testing.T, host *DaemonHost, profile string, addr wgaddr.Address) (*EngineConfig, func(), error) {
	t.Helper()
	config := &profilemanager.Config{WgIface: iface.WgInterfaceDefault, WgPort: iface.DefaultWgPort}
	engineConfig := &EngineConfig{WgIfaceName: config.WgIface, WgPort: config.WgPort, WgAddr: addr}
	detach, err := host.Session(hostcoord.SessionKey{Profile: profilemanager.ID(profile)}, nil).attach(config, engineConfig)
	return engineConfig, detach, err
}

func v6Address(t *testing.T, v4, v6 string) wgaddr.Address {
	t.Helper()
	addr := wgaddr.MustParseWGAddress(v4)
	prefix := netip.MustParsePrefix(v6)
	addr.IPv6 = prefix.Addr()
	addr.IPv6Net = prefix.Masked()
	return addr
}

func TestAttachGivesTheSessionItsSlot(t *testing.T) {
	host := newTestDaemonHost(t)

	first, detachFirst, err := attachTestSession(t, host, "work", wgaddr.MustParseWGAddress("100.71.0.1/16"))
	require.NoError(t, err)
	t.Cleanup(detachFirst)
	assert.Equal(t, "wt0", first.WgIfaceName)
	assert.Equal(t, 51820, first.WgPort)
	assert.NotNil(t, first.Sessions, "the engine should know the other sessions")

	second, detachSecond, err := attachTestSession(t, host, "home", wgaddr.MustParseWGAddress("100.72.0.1/16"))
	require.NoError(t, err)
	t.Cleanup(detachSecond)
	assert.Equal(t, "wt1", second.WgIfaceName, "the default in the config means the name of the slot")
	assert.Equal(t, 51821, second.WgPort, "the default in the config means the port of the slot")

	assert.NoError(t, host.Isolation().Verify())
}

// An overlapping IPv4 overlay is a refusal that leaves nothing behind and is not worth a retry.
func TestAttachRefusesOverlappingOverlay(t *testing.T) {
	host := newTestDaemonHost(t)

	_, detach, err := attachTestSession(t, host, "work", wgaddr.MustParseWGAddress("100.71.0.1/16"))
	require.NoError(t, err)
	t.Cleanup(detach)

	key := hostcoord.SessionKey{Profile: "home"}
	_, _, err = attachTestSession(t, host, "home", wgaddr.MustParseWGAddress("100.71.0.2/16"))
	require.ErrorIs(t, err, ErrSessionRefused)
	assert.ErrorIs(t, err, ErrOverlayOverlap)

	_, running := host.slots.Running(key)
	assert.False(t, running, "a refused session must not keep its reservation")
	assert.Equal(t, []string{"wt0"}, host.coordinator.Sessions().SessionInterfaces(), "a refused session must not count as one")
	assert.NoError(t, host.Isolation().Verify(), "the isolation should be as the running session needs it")
}

// Q13, Q15: an IPv6 overlay that cannot be isolated goes away and the session runs on IPv4. The
// engine must not read the address Management keeps sending as a change, or it would restart forever.
func TestAttachDropsOverlappingIPv6(t *testing.T) {
	host := newTestDaemonHost(t)

	first, detach, err := attachTestSession(t, host, "work", v6Address(t, "100.71.0.1/16", "fd00:1234::1/64"))
	require.NoError(t, err)
	t.Cleanup(detach)
	assert.True(t, first.WgAddr.HasIPv6(), "the first session keeps its IPv6 overlay")
	assert.False(t, first.DisableIPv6)

	second, detachSecond, err := attachTestSession(t, host, "home", v6Address(t, "100.72.0.1/16", "fd00:1234::2/64"))
	require.NoError(t, err)
	t.Cleanup(detachSecond)
	assert.False(t, second.WgAddr.HasIPv6(), "the second session should run without IPv6")
	assert.True(t, second.DisableIPv6, "the engine should ignore the address from Management")

	for _, prefix := range host.coordinator.Sessions().OverlayPrefixesExcept(hostcoord.SessionKey{Profile: "work"}) {
		assert.True(t, prefix.Addr().Is4(), "the second session must not claim an IPv6 overlay, has %s", prefix)
	}
	assert.NoError(t, host.Isolation().Verify())
}

// Section 6: the session carries on without its IPv6 overlay and hears of it, under its own profile.
func TestAttachWarnsAboutTheSkippedIPv6(t *testing.T) {
	host := newTestDaemonHost(t)

	_, detach, err := attachTestSession(t, host, "work", v6Address(t, "100.71.0.1/16", "fd00:1234::1/64"))
	require.NoError(t, err)
	t.Cleanup(detach)

	recorder := peer.NewRecorder("")
	recorder.SetEventProfile("home")
	addr := v6Address(t, "100.72.0.1/16", "fd00:1234::2/64")
	config := &profilemanager.Config{WgIface: iface.WgInterfaceDefault, WgPort: iface.DefaultWgPort}
	engineConfig := &EngineConfig{WgIfaceName: config.WgIface, WgPort: config.WgPort, WgAddr: addr}
	detachSecond, err := host.Session(hostcoord.SessionKey{Profile: "home"}, recorder).attach(config, engineConfig)
	require.NoError(t, err)
	t.Cleanup(detachSecond)

	events := recorder.GetEventHistory()
	require.Len(t, events, 1, "the session should be warned once")
	assert.Equal(t, cProto.SystemEvent_WARNING, events[0].GetSeverity())
	assert.Equal(t, eventIPv6Skipped, events[0].GetMetadata()[cProto.MetadataKindKey])
	assert.Equal(t, "home", events[0].GetProfileId())
	assert.False(t, engineConfig.WgAddr.HasIPv6(), "the session should run on IPv4")
	assert.Equal(t, addr.IP, engineConfig.WgAddr.IP, "the session keeps its IPv4 address")
}

// Each kind has its text, and a route in it.
func TestRouteEventsAreWarningsOfTheirSession(t *testing.T) {
	for kind := range routeEventMessages {
		t.Run(string(kind), func(t *testing.T) {
			recorder := peer.NewRecorder("")
			recorder.SetEventProfile("home")
			host := NewDaemonHost(nil)
			prefix := netip.MustParsePrefix("10.77.0.0/16")

			host.Session(hostcoord.SessionKey{Profile: "home"}, recorder).routeEvent(hostcoord.RouteEvent{Kind: kind, Prefix: prefix})

			events := recorder.GetEventHistory()
			require.Len(t, events, 1)
			assert.Equal(t, "home", events[0].GetProfileId())
			assert.Equal(t, cProto.SystemEvent_WARNING, events[0].GetSeverity())
			assert.Equal(t, string(kind), events[0].GetMetadata()[cProto.MetadataKindKey])
			assert.Equal(t, prefix.String(), events[0].GetMetadata()[cProto.MetadataPrefixKey])
			assert.Contains(t, events[0].GetUserMessage(), prefix.String())
			assert.NotContains(t, events[0].GetUserMessage(), "%!", "the text should take the route")
		})
	}
}

// The DNS warnings reach the session they are for, a shared domain with its name.
func TestDNSWarningsAreEventsOfTheirSession(t *testing.T) {
	host := NewDaemonHost(nil)
	recorder := peer.NewRecorder("")
	recorder.SetEventProfile("home")
	session := host.Session(hostcoord.SessionKey{Profile: "home"}, recorder)

	coordinator := session.hostDNS()
	coordinator.WarnHostDNS(dns.HostDNSWarning{Kind: dns.HostDNSHeld})
	coordinator.WarnHostDNS(dns.HostDNSWarning{Kind: dns.HostDNSCatchAllHeld})
	coordinator.WarnHostDNS(dns.HostDNSWarning{Kind: dns.HostDNSDomainShared, Domains: []string{"netbird.selfhosted"}})

	events := recorder.GetEventHistory()
	require.Len(t, events, 3)
	for _, event := range events {
		assert.Equal(t, "home", event.GetProfileId())
		assert.Equal(t, cProto.SystemEvent_DNS, event.GetCategory())
		assert.Equal(t, cProto.SystemEvent_WARNING, event.GetSeverity())
	}
	assert.Equal(t, "netbird.selfhosted", events[2].GetMetadata()[cProto.MetadataDomainsKey])
}

// The handover a failed attempt left waiting runs when an interface is back.
func TestSessionHostRetriesHandovers(t *testing.T) {
	coordinator := hostcoord.New()
	routes := coordinator.Routes()
	prefix := netip.MustParsePrefix("10.77.0.0/16")

	var failInstall bool
	var installed []string
	claim := func(dev string) hostcoord.RouteClaim {
		return hostcoord.RouteClaim{
			Dev: dev,
			Install: func() error {
				if failInstall {
					return errors.New("interface is down")
				}
				installed = append(installed, dev)
				return nil
			},
			Remove: func() error { return nil },
		}
	}

	work := hostcoord.SessionKey{Profile: "work"}
	home := hostcoord.SessionKey{Profile: "home"}
	_, err := routes.Add(work, prefix, claim("wt0"))
	require.NoError(t, err)
	_, err = routes.Add(home, prefix, claim("wt1"))
	require.NoError(t, err)

	failInstall = true
	// Whether the failure comes back from Remove does not matter here, the prefix stays waiting.
	if err := routes.Remove(work, prefix); err != nil {
		t.Logf("remove with a failing handover: %v", err)
	}
	require.Equal(t, []string{"wt0"}, installed, "the handover should not have happened")

	failInstall = false
	host := &SessionHost{daemon: &DaemonHost{coordinator: coordinator}, key: home}
	host.retryHandovers()
	assert.Equal(t, []string{"wt0", "wt1"}, installed, "the waiting session should get the prefix once its interface is back")
}

// A client without the gate has a nil host, and each hook of the engine has to take it.
func TestNilSessionHostKeepsTodaysBehavior(t *testing.T) {
	var host *SessionHost
	assert.NoError(t, host.verifyIsolation())
	assert.Nil(t, host.hostDNS())
	assert.Nil(t, host.conntrackOptions())
	assert.Nil(t, host.networkMonitorOptions())
	assert.Nil(t, host.newSysOps(nil))
	host.retryHandovers()
}
