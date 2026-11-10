package server

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
)

func (c *capturingStatusStream) lastSessionStatus(profileID string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.sent) == 0 {
		return ""
	}
	for _, entry := range c.sent[len(c.sent)-1].GetSessions() {
		if entry.GetProfileId() == profileID {
			return entry.GetStatus()
		}
	}
	return ""
}

// The desktop UI lists every session from the one stream, so a change of a session that is not
// focused has to reach a stream that describes the focused one.
func TestGate_StatusStreamHearsEverySession(t *testing.T) {
	subscribe := func(t *testing.T, f *gateFixture) *capturingStatusStream {
		t.Helper()
		ctx, cancel := context.WithCancel(f.ctx)
		t.Cleanup(cancel)
		stream := &capturingStatusStream{fakeServerStream: fakeServerStream[proto.StatusResponse]{ctx: ctx}, onSend: func() {}}
		go func() { _ = f.s.SubscribeStatus(&proto.StatusRequest{}, stream) }()
		require.Eventually(t, func() bool { return stream.count() > 0 }, 5*time.Second, 10*time.Millisecond, "the first snapshot")
		return stream
	}

	t.Run("a session that existed before the subscription", func(t *testing.T) {
		f := newGateFixture(t)
		f.s.mutex.Lock()
		other := f.s.sessionOfLocked(f.second)
		f.s.mutex.Unlock()
		stream := subscribe(t, f)

		other.state.Set(internal.StatusNeedsLogin)
		require.Eventually(t, func() bool {
			return stream.lastSessionStatus(string(f.second.Profile)) == string(internal.StatusNeedsLogin)
		}, 5*time.Second, 10*time.Millisecond, "the change of the other session should reach the stream")
		assert.Equal(t, string(internal.StatusIdle), stream.lastStatus(), "the top level should still describe the focused session")
	})

	t.Run("a session that joins after the subscription", func(t *testing.T) {
		f := newGateFixture(t)
		stream := subscribe(t, f)

		f.s.mutex.Lock()
		other := f.s.sessionOfLocked(f.third)
		f.s.mutex.Unlock()
		other.state.Set(internal.StatusLoginFailed)
		require.Eventually(t, func() bool {
			return stream.lastSessionStatus(string(f.third.Profile)) == string(internal.StatusLoginFailed)
		}, 5*time.Second, 10*time.Millisecond, "the change of the new session should reach the stream")
	})
}

func (c *capturingStatusStream) sawStatus(status string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, resp := range c.sent {
		if resp.GetStatus() == status {
			return true
		}
	}
	return false
}

// A status stream without a selector follows the focus only to sessions its caller may read. When
// bob takes the focus, the stream of alice ends instead of describing the session of bob.
func TestGate_StatusStreamFollowsTheFocusOnlyWhereTheCallerMayRead(t *testing.T) {
	f := newAccessFixture(t)
	f.focus(t, f.alice)
	sessionOf := func(key profilemanager.SessionKey) *session {
		f.s.mutex.Lock()
		defer f.s.mutex.Unlock()
		return f.s.sessionOfLocked(key)
	}
	own := sessionOf(f.alice)
	// A status no session of alice reports, so a snapshot of the session of bob stands out.
	sessionOf(f.bob).state.Set(internal.StatusLoginFailed)

	ctx, cancel := context.WithCancel(aliceCtx())
	t.Cleanup(cancel)
	stream := &capturingStatusStream{fakeServerStream: fakeServerStream[proto.StatusResponse]{ctx: ctx}, onSend: func() {}}
	done := make(chan error, 1)
	go func() { done <- f.s.SubscribeStatus(&proto.StatusRequest{}, stream) }()
	require.Eventually(t, func() bool { return stream.count() > 0 }, 5*time.Second, 10*time.Millisecond, "the first snapshot")

	// The default profile is alice's too, so the stream may follow the focus there. Moving the
	// focus wakes no stream, so a change of the session of alice does.
	ownDefaultProfile(t, aliceIdentity())
	f.focus(t, f.shared)
	shared := sessionOf(f.shared)
	shared.state.Set(internal.StatusNeedsLogin)
	require.Eventually(t, func() bool {
		own.statusRecorder.NotifyStateChange()
		return stream.lastStatus() == string(internal.StatusNeedsLogin)
	}, 5*time.Second, 50*time.Millisecond, "the stream should move with the focus to a session alice may read")

	shared.state.Set(internal.StatusSessionExpired)
	require.Eventually(t, func() bool { return stream.lastStatus() == string(internal.StatusSessionExpired) }, 5*time.Second, 10*time.Millisecond,
		"the stream should hear the session it moved to")

	f.focus(t, f.bob)
	var err error
	require.Eventually(t, func() bool {
		own.statusRecorder.NotifyStateChange()
		select {
		case err = <-done:
			return true
		default:
			return false
		}
	}, 5*time.Second, 50*time.Millisecond, "the stream should end when the focus moves to a session of someone else")
	requireRefusedAsForeign(t, err, "the focus moved to a session alice may not read")
	assert.False(t, stream.sawStatus(string(internal.StatusLoginFailed)), "the stream must not describe the session of bob")
	for _, resp := range stream.sent {
		for _, entry := range resp.GetSessions() {
			assert.NotEqual(t, string(f.bob.Profile), entry.GetProfileId(), "the stream must not list the session of bob")
		}
	}
}
