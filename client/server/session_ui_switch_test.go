package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/proto"
)

// The desktop UI switches the profile and then sends a plain Down (client/ui/services/profileswitcher.go).
// With the gate the Down reaches the new focused session, so the session the UI switched away from
// keeps running, which is the known limit of version 1: the UI shows only the focused session.
func TestGate_UISwitchLeavesTheOriginalSessionRunning(t *testing.T) {
	f := newGateFixture(t)
	require.NoError(t, f.up(f.first))
	require.NoError(t, f.up(f.second))
	f.focus(t, f.first)
	original := f.session(f.first)
	originalClient := original.client()
	require.NotNil(t, originalClient)

	// What the switcher does when the UI is on the first profile and the user picks the second.
	f.focus(t, f.second)
	_, err := f.s.Down(f.ctx, &proto.DownRequest{})
	require.NoError(t, err)
	awaitRunEndOf(t, f.session(f.second))

	assert.Equal(t, f.second, f.s.focusedSession().key, "the switch moved the focus")
	assert.False(t, f.session(f.second).isClientRunning(), "the Down ended the session of the new focus")
	assert.True(t, original.isClientRunning(), "the session the UI switched away from runs on")
	assert.Same(t, originalClient, original.client(), "and it is the same run, not a restart")
	assert.Equal(t, internal.StatusConnected, original.state.CurrentStatus())
	assert.Equal(t, 1, f.runCount(f.first), "the original session was started once")
}

// The switcher sends the Down also when the new profile is not connected, as the old status of the
// UI says it has to. That Down finds nothing to end and must leave the other session alone.
func TestGate_UISwitchToAnIdleProfileEndsNothing(t *testing.T) {
	f := newGateFixture(t)
	require.NoError(t, f.up(f.first))
	original := f.session(f.first)

	f.focus(t, f.second)
	_, err := f.s.Down(f.ctx, &proto.DownRequest{})

	assert.ErrorIs(t, err, ErrServiceNotUp, "the new focus has no run to end")
	assert.True(t, original.isClientRunning(), "the other session runs on")
	assert.Equal(t, 1, f.runCount(f.first))
}
