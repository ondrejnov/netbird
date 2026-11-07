package server

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal"
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
