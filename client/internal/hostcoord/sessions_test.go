package hostcoord

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
)

func sessionKey(profile string) SessionKey {
	return SessionKey{Profile: profilemanager.ID(profile), Username: "u"}
}

func TestSessions_ReportsAllSessions(t *testing.T) {
	s := NewSessions()
	require.NoError(t, s.Set(sessionKey("a"), "wt0", netip.MustParsePrefix("100.64.0.5/10")))
	require.NoError(t, s.Set(sessionKey("b"), "wt10", netip.MustParsePrefix("100.65.1.1/16"), netip.MustParsePrefix("fd00::1/64")))

	assert.ElementsMatch(t, []string{"wt0", "wt10"}, s.SessionInterfaces())
	assert.ElementsMatch(t, []netip.Prefix{
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("100.65.0.0/16"),
		netip.MustParsePrefix("fd00::/64"),
	}, s.OverlayPrefixes(), "prefixes are masked")
}

func TestSessions_SetReplacesAndRemoveDrops(t *testing.T) {
	s := NewSessions()
	require.NoError(t, s.Set(sessionKey("a"), "wt0", netip.MustParsePrefix("100.64.0.0/16")))
	require.NoError(t, s.Set(sessionKey("a"), "wt1", netip.MustParsePrefix("100.66.0.0/16")))

	assert.Equal(t, []string{"wt1"}, s.SessionInterfaces())
	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("100.66.0.0/16")}, s.OverlayPrefixes())

	s.Remove(sessionKey("a"))
	assert.Empty(t, s.SessionInterfaces())
	assert.Empty(t, s.OverlayPrefixes())
}

func TestSessions_ResultIsACopy(t *testing.T) {
	s := NewSessions()
	require.NoError(t, s.Set(sessionKey("a"), "wt0", netip.MustParsePrefix("100.64.0.0/16")))

	s.SessionInterfaces()[0] = "changed"
	s.OverlayPrefixes()[0] = netip.MustParsePrefix("10.0.0.0/8")

	assert.Equal(t, []string{"wt0"}, s.SessionInterfaces())
	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("100.64.0.0/16")}, s.OverlayPrefixes())
}

func TestSessions_OverlayPrefixesExcept(t *testing.T) {
	own := netip.MustParsePrefix("100.64.0.0/16")
	other := netip.MustParsePrefix("100.65.0.0/16")
	otherV6 := netip.MustParsePrefix("fd00::/64")
	s := NewSessions()
	require.NoError(t, s.Set(sessionKey("a"), "wt0", own))
	require.NoError(t, s.Set(sessionKey("b"), "wt1", other, otherV6))

	assert.ElementsMatch(t, []netip.Prefix{other, otherV6}, s.OverlayPrefixesExcept(sessionKey("a")),
		"the own session is left out")
	assert.Equal(t, []netip.Prefix{own}, s.OverlayPrefixesExcept(sessionKey("b")), "and so is the other one for b")
	assert.ElementsMatch(t, []netip.Prefix{own, other, otherV6}, s.OverlayPrefixesExcept(sessionKey("unknown")),
		"a session without a record leaves out nothing")
	assert.ElementsMatch(t, []netip.Prefix{own, other, otherV6}, s.OverlayPrefixes(),
		"the full list stays complete for the engine filters")

	sameProfile := SessionKey{Profile: "a", Username: "other-user"}
	assert.ElementsMatch(t, []netip.Prefix{own, other, otherV6}, s.OverlayPrefixesExcept(sameProfile),
		"the username is part of the key, legacy profile IDs are not unique across users")

	s.OverlayPrefixesExcept(sessionKey("a"))[0] = netip.MustParsePrefix("10.0.0.0/8")
	assert.ElementsMatch(t, []netip.Prefix{other, otherV6}, s.OverlayPrefixesExcept(sessionKey("a")),
		"the result is a copy")

	s.Remove(sessionKey("b"))
	assert.Empty(t, s.OverlayPrefixesExcept(sessionKey("a")), "the view follows the running sessions")
}

func TestSessions_RejectsInvalidInput(t *testing.T) {
	valid := netip.MustParsePrefix("100.64.0.0/16")
	tests := map[string]struct {
		iface  string
		prefix netip.Prefix
	}{
		"empty name":         {"", valid},
		"longer than kernel": {strings.Repeat("x", 16), valid},
		"slash in name":      {"wt/0", valid},
		"space in name":      {"wt 0", valid},
		"invalid prefix":     {"wt0", netip.Prefix{}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			s := NewSessions()
			require.Error(t, s.Set(sessionKey("a"), tc.iface, tc.prefix))
			assert.Empty(t, s.SessionInterfaces(), "a rejected session is not recorded, nothing is truncated")
			assert.Empty(t, s.OverlayPrefixes())
		})
	}
}

func TestSessions_AcceptsLongestKernelName(t *testing.T) {
	s := NewSessions()
	name := strings.Repeat("x", 15)
	require.NoError(t, s.Set(sessionKey("a"), name, netip.MustParsePrefix("100.64.0.0/16")))
	assert.Equal(t, []string{name}, s.SessionInterfaces())
}

func TestSessions_ConcurrentUse(t *testing.T) {
	s := NewSessions()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			_ = s.Set(sessionKey("a"), "wt0", netip.MustParsePrefix("100.64.0.0/16"))
			s.Remove(sessionKey("a"))
		}
	}()
	for i := 0; i < 200; i++ {
		s.SessionInterfaces()
		s.OverlayPrefixes()
		s.OverlayPrefixesExcept(sessionKey("b"))
	}
	<-done
}
