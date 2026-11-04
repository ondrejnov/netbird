package internal

import (
	"context"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/iface/udpmux"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/hostcoord"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/system"
)

func twoSessions(t *testing.T, otherPrefix netip.Prefix) *hostcoord.Sessions {
	t.Helper()
	s := hostcoord.NewSessions()
	key := func(p string) hostcoord.SessionKey {
		return hostcoord.SessionKey{Profile: profilemanager.ID(p), Username: "u"}
	}
	require.NoError(t, s.Set(key("a"), "wt0", netip.MustParsePrefix("100.64.0.0/24")))
	require.NoError(t, s.Set(key("b"), "wt1", otherPrefix))
	return s
}

// A host address that belongs to the overlay of another session must not reach the
// metadata sent to Management, while without a source nothing changes.
func TestEngine_SyncInfoExcludesOtherSessionAddresses(t *testing.T) {
	addrs := system.GetInfo(context.Background()).NetworkAddresses
	if len(addrs) == 0 {
		t.Skip("no network addresses on this host")
	}
	foreign := addrs[0].NetIP.Addr()

	build := func(src hostcoord.SessionSource) *Engine {
		return &Engine{config: &EngineConfig{
			WgAddr:   wgaddr.Address{IP: netip.MustParseAddr("100.64.0.5"), Network: netip.MustParsePrefix("100.64.0.0/24")},
			Sessions: src,
		}}
	}
	sentTo := func(e *Engine) []netip.Addr {
		info := e.syncInfoFunc(nil)(context.Background())
		var ips []netip.Addr
		for _, a := range info.NetworkAddresses {
			ips = append(ips, a.NetIP.Addr())
		}
		return ips
	}

	assert.Contains(t, sentTo(build(nil)), foreign, "without a source the address is reported as today")

	sent := sentTo(build(twoSessions(t, netip.PrefixFrom(foreign, foreign.BitLen()))))
	assert.NotContains(t, sent, foreign, "the address of another session is not sent")
}

func TestEngine_OverlayAddressesWithoutSourceAreOwnOnly(t *testing.T) {
	own := netip.MustParseAddr("100.64.0.5")
	e := &Engine{config: &EngineConfig{WgAddr: wgaddr.Address{IP: own}}}
	assert.Equal(t, []netip.Addr{own}, e.overlayAddresses())
}

// The ICE config is what the agent filters candidates with: both session interfaces
// stay out, including a name that the prefix blacklist would not catch.
func TestEngine_ICEConfigBlacklistsSessionInterfaces(t *testing.T) {
	src := twoSessions(t, netip.MustParsePrefix("100.65.0.0/24"))
	e := &Engine{udpMux: &udpmux.UniversalUDPMuxDefault{}, config: &EngineConfig{IFaceBlackList: []string{"docker"}, Sessions: src}}

	cfg := e.createICEConfig()
	assert.ElementsMatch(t, []string{"docker", "wt0", "wt1"}, cfg.InterfaceBlackList)

	assert.Equal(t, []string{"docker"}, (&Engine{udpMux: &udpmux.UniversalUDPMuxDefault{}, config: &EngineConfig{IFaceBlackList: []string{"docker"}}}).createICEConfig().InterfaceBlackList,
		"without a source the blacklist is unchanged")
}

func TestEngine_NATMappingRejectsSessionInterface(t *testing.T) {
	src := twoSessions(t, netip.MustParsePrefix("100.65.0.0/24"))
	e := &Engine{config: &EngineConfig{NATExternalIPs: []string{"1.2.3.4/wt1"}, Sessions: src}}
	assert.Empty(t, e.parseNATExternalIPMappings(), "a mapping bound to another session interface is ignored")
}
