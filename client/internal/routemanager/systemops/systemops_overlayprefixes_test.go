package systemops

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/hostcoord"
	"github.com/netbirdio/netbird/client/internal/routemanager/vars"
)

type overlayTestIface struct {
	addr wgaddr.Address
}

func (i overlayTestIface) Address() wgaddr.Address { return i.addr }
func (i overlayTestIface) Name() string            { return "wt-own" }

type nilOverlaySource struct{}

func (*nilOverlaySource) OverlayPrefixesExcept(hostcoord.SessionKey) []netip.Prefix { return nil }

func TestValidateRoute_OtherSessionOverlay(t *testing.T) {
	own := netip.MustParsePrefix("100.64.0.1/16")
	ownIface := overlayTestIface{addr: wgaddr.Address{
		IP:      own.Addr(),
		Network: own.Masked(),
	}}

	sessions := hostcoord.NewSessions()
	require.NoError(t, sessions.Set(hostcoord.SessionKey{Profile: "other", Username: "u"}, "wt-other",
		netip.MustParsePrefix("10.1.0.0/16"), netip.MustParsePrefix("fd00:1::/64")))

	newOps := func(opts ...SharedOption) *SysOps {
		return NewShared(ownIface, nil, nil, hostcoord.SessionKey{}, opts...)
	}

	tests := []struct {
		name    string
		ops     *SysOps
		prefix  string
		allowed bool
	}{
		{"exact match", newOps(WithOverlayPrefixes(sessions)), "10.1.0.0/16", false},
		{"broader prefix", newOps(WithOverlayPrefixes(sessions)), "10.0.0.0/8", false},
		{"narrower prefix", newOps(WithOverlayPrefixes(sessions)), "10.1.2.0/24", false},
		{"single host inside", newOps(WithOverlayPrefixes(sessions)), "10.1.2.3/32", false},
		{"v6 exact match", newOps(WithOverlayPrefixes(sessions)), "fd00:1::/64", false},
		{"v6 narrower", newOps(WithOverlayPrefixes(sessions)), "fd00:1::/96", false},
		{"v4 mapped in v6 form", newOps(WithOverlayPrefixes(sessions)), "::ffff:10.1.2.0/120", false},
		{"unrelated prefix", newOps(WithOverlayPrefixes(sessions)), "192.168.5.0/24", true},
		{"default v4 stays allowed", newOps(WithOverlayPrefixes(sessions)), "0.0.0.0/0", true},
		{"default v6 stays allowed", newOps(WithOverlayPrefixes(sessions)), "::/0", true},
		{"nil source option", newOps(WithOverlayPrefixes(nil)), "10.1.0.0/16", true},
		{"no option", newOps(), "10.1.0.0/16", true},
		{"source without prefixes", newOps(WithOverlayPrefixes(&nilOverlaySource{})), "10.1.0.0/16", true},
		{"own overlay still rejected", newOps(WithOverlayPrefixes(sessions)), "100.64.3.4/32", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.ops.validateRoute(netip.MustParsePrefix(tt.prefix))
			if tt.allowed {
				assert.NoError(t, err, "route %s must be allowed", tt.prefix)
				return
			}
			assert.ErrorIs(t, err, vars.ErrRouteNotAllowed, "route %s must be rejected", tt.prefix)
		})
	}
}

func TestValidateRoute_OwnSessionInOverlaySource(t *testing.T) {
	// The source lists every running session, the own one included. Only the others count:
	// a route around the own overlay is what a network route of a CGNAT range looks like,
	// and it must not be refused because of the session that carries it.
	ownKey := hostcoord.SessionKey{Profile: "own", Username: "u"}
	otherKey := hostcoord.SessionKey{Profile: "other", Username: "u"}
	ownV4 := netip.MustParsePrefix("100.119.0.1/16")
	ownV6 := netip.MustParsePrefix("fd00:a:0:1::1/64")
	ownIface := overlayTestIface{addr: wgaddr.Address{
		IP:      ownV4.Addr(),
		Network: ownV4.Masked(),
		IPv6:    ownV6.Addr(),
		IPv6Net: ownV6.Masked(),
	}}

	sessionsWith := func(t *testing.T, other ...netip.Prefix) *hostcoord.Sessions {
		t.Helper()
		sessions := hostcoord.NewSessions()
		require.NoError(t, sessions.Set(ownKey, "wt-own", ownV4, ownV6))
		if len(other) > 0 {
			require.NoError(t, sessions.Set(otherKey, "wt-other", other...))
		}
		return sessions
	}

	tests := []struct {
		name    string
		other   []netip.Prefix
		prefix  string
		allowed bool
	}{
		{name: "around the own v4 overlay, single session", prefix: "100.64.0.0/10", allowed: true},
		{name: "around the own v6 overlay, single session", prefix: "fd00:a::/48", allowed: true},
		{name: "around the own overlay beside another session",
			other:  []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16")},
			prefix: "100.64.0.0/10", allowed: true},
		{name: "own overlay address stays refused", prefix: "100.119.3.4/32"},
		{name: "own v6 overlay address stays refused", prefix: "fd00:a:0:1::5/128"},
		{name: "overlay of the other session stays refused",
			other:  []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16")},
			prefix: "10.1.0.0/16"},
		{name: "around both overlays is refused for the other one",
			other:  []netip.Prefix{netip.MustParsePrefix("100.65.0.0/16")},
			prefix: "100.64.0.0/10"},
		{name: "other session on the same prefix is not mistaken for the own one",
			other:  []netip.Prefix{netip.MustParsePrefix("100.119.0.0/16")},
			prefix: "100.64.0.0/10"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ops := NewShared(ownIface, nil, nil, ownKey, WithOverlayPrefixes(sessionsWith(t, tt.other...)))
			err := ops.validateRoute(netip.MustParsePrefix(tt.prefix))
			if tt.allowed {
				assert.NoError(t, err, "route %s must be allowed", tt.prefix)
				return
			}
			assert.ErrorIs(t, err, vars.ErrRouteNotAllowed, "route %s must be rejected", tt.prefix)
		})
	}
}
