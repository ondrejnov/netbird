//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/proto"
)

// With concurrent profiles a switch in the UI moves the focus only. The session the user switches
// away from keeps running and stays listed, so no Down may reach the daemon.
func TestProfileSwitcher_GateSwitchBringsNothingDown(t *testing.T) {
	daemon := &switchDaemon{
		gate:   true,
		status: StatusConnected,
		sessions: []*proto.SessionStatus{
			{ProfileId: "prace", Status: StatusConnected, Focused: true},
		},
	}
	switcher := newSwitcher(t, daemon)

	require.NoError(t, switcher.SwitchActive(context.Background(), ProfileRef{ProfileName: "doma", Username: "alice"}))

	assert.Equal(t, []string{"Status", "SwitchProfile doma", "Up doma"}, daemon.calls,
		"the switch should move the focus and connect the idle profile, nothing else")
	assert.Empty(t, daemon.down, "no session may be brought down by a switch")
}

func TestProfileSwitcher_GateSwitchToARunningSessionOnlyFocuses(t *testing.T) {
	daemon := &switchDaemon{
		gate:   true,
		status: StatusConnected,
		sessions: []*proto.SessionStatus{
			{ProfileId: "prace", Status: StatusConnected, Focused: true},
			{ProfileId: "doma", Status: StatusConnected},
		},
	}
	switcher := newSwitcher(t, daemon)

	require.NoError(t, switcher.SwitchActive(context.Background(), ProfileRef{ProfileName: "doma", Username: "alice"}))

	assert.Equal(t, []string{"Status", "SwitchProfile doma"}, daemon.calls,
		"a running session has nothing to connect")
}

func TestProfileSwitcher_GateNoConnectOnlyFocuses(t *testing.T) {
	daemon := &switchDaemon{
		gate:     true,
		status:   StatusConnected,
		sessions: []*proto.SessionStatus{{ProfileId: "prace", Status: StatusConnected, Focused: true}},
	}
	switcher := newSwitcher(t, daemon)

	require.NoError(t, switcher.SwitchActiveNoConnect(context.Background(), ProfileRef{ProfileName: "doma", Username: "alice"}))

	assert.Equal(t, []string{"Status", "SwitchProfile doma"}, daemon.calls)
}

// A refused Up, such as the session limit or an overlapping overlay, gives the focus back, so a
// plain disconnect afterwards does not aim at the session that never came up.
func TestProfileSwitcher_GateFailedConnectGivesTheFocusBack(t *testing.T) {
	daemon := &switchDaemon{
		gate:     true,
		status:   StatusConnected,
		sessions: []*proto.SessionStatus{{ProfileId: "prace", Status: StatusConnected, Focused: true}},
		upErr:    gstatus.Error(codes.ResourceExhausted, "session limit reached"),
	}
	switcher := newSwitcher(t, daemon)

	err := switcher.SwitchActive(context.Background(), ProfileRef{ProfileName: "doma", Username: "alice"})
	require.Error(t, err)

	assert.Equal(t, []string{"Status", "SwitchProfile doma", "Up doma", "SwitchProfile prace"}, daemon.calls,
		"the focus should go back to the profile that had it")
	assert.Empty(t, daemon.down)
}

func TestConnection_DownSessionNamesTheProfile(t *testing.T) {
	daemon := &switchDaemon{gate: true}
	conn := NewConnection(stubConn{client: daemon}, nil, nil)

	require.NoError(t, conn.DownSession(context.Background(), SessionParams{ProfileName: "doma", Username: "alice"}))
	require.Len(t, daemon.down, 1)
	assert.Equal(t, "doma", daemon.down[0].GetSession().GetProfile(), "the Down should carry the selector")
	assert.Equal(t, "alice", daemon.down[0].GetSession().GetUsername())
	assert.False(t, daemon.down[0].GetAll())

	assert.Error(t, conn.DownSession(context.Background(), SessionParams{}),
		"an empty profile would aim at the focused session")
	assert.Len(t, daemon.down, 1, "the refused request must not reach the daemon")
}

// Quitting the UI disconnects; with concurrent profiles a plain Down would end the focused session
// only and leave the others running with no UI left to show them.
func TestDisconnectOnQuit(t *testing.T) {
	quit := func(t *testing.T, gate bool) *proto.DownRequest {
		t.Helper()
		daemon := &switchDaemon{gate: gate}
		conn := stubConn{client: daemon}
		require.NoError(t, DisconnectOnQuit(context.Background(), NewProfiles(conn, nil, nil), NewConnection(conn, nil, nil)))
		require.Len(t, daemon.down, 1, "quitting should send one Down")
		return daemon.down[0]
	}

	t.Run("with the gate every session the caller reaches", func(t *testing.T) {
		req := quit(t, true)
		assert.True(t, req.GetAll(), "the Down should ask for all sessions")
		assert.Nil(t, req.GetSession(), "all and a selector together are refused by the daemon")
	})

	t.Run("without the gate the one connection", func(t *testing.T) {
		req := quit(t, false)
		assert.False(t, req.GetAll(), "a daemon without the gate has one connection and no all")
	})
}

// The GUI connects the profiles chosen for its start, without moving the focus, and leaves alone
// what runs already, what waits for a login and what was removed since.
func TestConnectStartupProfiles(t *testing.T) {
	newDaemon := func(gate bool) *switchDaemon {
		return &switchDaemon{
			gate: gate,
			profiles: []*proto.Profile{
				{Id: "prace"}, {Id: "doma"}, {Id: "chata"}, {Id: "login"},
			},
			sessions: []*proto.SessionStatus{
				{ProfileId: "prace", Status: StatusConnected, Focused: true},
				{ProfileId: "login", Status: StatusNeedsLogin},
			},
		}
	}
	run := func(t *testing.T, daemon *switchDaemon, ids []string) {
		t.Helper()
		switcher := newSwitcher(t, daemon)
		require.NoError(t, ConnectStartupProfiles(context.Background(), switcher.profiles, switcher.connection, switcher.feed, ids))
	}

	t.Run("with the gate", func(t *testing.T) {
		daemon := newDaemon(true)
		run(t, daemon, []string{"prace", "doma", "removed", "login", "chata"})

		assert.Equal(t, []string{"Status", "Up doma", "Up chata"}, daemon.calls,
			"only the idle profiles should be connected, and the focus left alone")
		for _, up := range daemon.up {
			assert.NotEmpty(t, up.GetUsername(), "an Up naming a profile carries the user it belongs to")
			assert.True(t, up.GetAsync(), "the GUI does not wait for each connection")
		}
	})

	t.Run("without the gate nothing connects", func(t *testing.T) {
		daemon := newDaemon(false)
		run(t, daemon, []string{"doma"})
		assert.Empty(t, daemon.up, "without the gate an Up would switch the one connection")
	})

	t.Run("one refused profile does not keep the others down", func(t *testing.T) {
		daemon := newDaemon(true)
		daemon.upErr = gstatus.Error(codes.ResourceExhausted, "session limit reached")
		switcher := newSwitcher(t, daemon)
		err := ConnectStartupProfiles(context.Background(), switcher.profiles, switcher.connection, switcher.feed, []string{"doma", "chata"})
		assert.Error(t, err)
		assert.Len(t, daemon.up, 2, "every chosen profile should be tried")
	})
}
