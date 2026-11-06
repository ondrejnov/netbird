package hostcoord

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsolationSourceReportsOnlyTheOtherSessions(t *testing.T) {
	work := SessionKey{Profile: "work"}
	home := SessionKey{Profile: "home"}
	sessions := NewSessions()
	source := sessions.IsolationSource(work)

	snapshot, err := source.OtherSessions()
	require.NoError(t, err)
	assert.Empty(t, snapshot.Overlays, "no session means nothing to keep out")

	workOverlay := netip.MustParsePrefix("100.64.1.5/16")
	homeOverlay := netip.MustParsePrefix("100.65.1.5/16")
	require.NoError(t, sessions.Set(work, "wt0", workOverlay))
	require.NoError(t, sessions.Set(home, "wt1", homeOverlay))

	snapshot, err = source.OtherSessions()
	require.NoError(t, err)
	assert.Equal(t, []string{"wt1"}, snapshot.Interfaces, "only the other session's interface")
	assert.Equal(t, []netip.Prefix{homeOverlay.Masked()}, snapshot.Overlays, "only the other session's overlay")
	assert.NoError(t, snapshot.Validate())
	assert.True(t, snapshot.Covers(netip.MustParseAddr("100.65.9.9")))
	assert.False(t, snapshot.Covers(netip.MustParseAddr("100.64.9.9")), "the own overlay is not foreign")

	sessions.Remove(home)
	snapshot, err = source.OtherSessions()
	require.NoError(t, err)
	assert.Empty(t, snapshot.Interfaces, "the session left")
	assert.Empty(t, snapshot.Overlays, "the session left")
}

// A session that has no record yet treats every session as foreign, so it is covered from the first
// packet whatever the order of the steps.
func TestIsolationSourceOfUnrecordedSessionSeesAll(t *testing.T) {
	sessions := NewSessions()
	require.NoError(t, sessions.Set(SessionKey{Profile: "home"}, "wt1", netip.MustParsePrefix("100.65.0.0/16")))

	snapshot, err := sessions.IsolationSource(SessionKey{Profile: "work"}).OtherSessions()
	require.NoError(t, err)
	assert.Equal(t, []string{"wt1"}, snapshot.Interfaces)
}

func TestSlotsRunningFollowsTheLease(t *testing.T) {
	slots, err := NewSlots(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, slots.Close()) })

	key := SessionKey{Profile: "work"}
	_, running := slots.Running(key)
	assert.False(t, running, "nothing is reserved yet")

	reserved, err := slots.Reserve(key, ResourceRequest{WgIface: "wt0", WgPort: 0})
	require.NoError(t, err)
	got, running := slots.Running(key)
	require.True(t, running)
	assert.Equal(t, reserved, got)

	slots.Release(reserved.Lease)
	_, running = slots.Running(key)
	assert.False(t, running, "the lease is gone")
}
