//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	gproto "google.golang.org/protobuf/proto"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
)

// switchDaemon records the calls of a profile switch in the order the daemon gets them. The
// embedded interface is nil, so any other call panics rather than passing quietly.
type switchDaemon struct {
	proto.DaemonServiceClient
	status string
	calls  []string
	down   []*proto.DownRequest
	up     []*proto.UpRequest

	// gate, sessions and upErr shape a daemon with concurrent profiles.
	gate     bool
	sessions []*proto.SessionStatus
	upErr    error
}

func (d *switchDaemon) GetFeatures(context.Context, *proto.GetFeaturesRequest, ...grpc.CallOption) (*proto.GetFeaturesResponse, error) {
	return &proto.GetFeaturesResponse{ConcurrentProfilesEnabled: d.gate}, nil
}

func (d *switchDaemon) Status(context.Context, *proto.StatusRequest, ...grpc.CallOption) (*proto.StatusResponse, error) {
	d.calls = append(d.calls, "Status")
	return &proto.StatusResponse{Status: d.status, Sessions: d.sessions}, nil
}

func (d *switchDaemon) SwitchProfile(_ context.Context, req *proto.SwitchProfileRequest, _ ...grpc.CallOption) (*proto.SwitchProfileResponse, error) {
	d.calls = append(d.calls, "SwitchProfile "+req.GetProfileName())
	return &proto.SwitchProfileResponse{Id: "id-" + req.GetProfileName()}, nil
}

func (d *switchDaemon) Down(_ context.Context, req *proto.DownRequest, _ ...grpc.CallOption) (*proto.DownResponse, error) {
	d.calls = append(d.calls, "Down")
	d.down = append(d.down, req)
	return &proto.DownResponse{}, nil
}

func (d *switchDaemon) Up(_ context.Context, req *proto.UpRequest, _ ...grpc.CallOption) (*proto.UpResponse, error) {
	d.calls = append(d.calls, "Up "+req.GetProfileName())
	d.up = append(d.up, req)
	if d.upErr != nil {
		return nil, d.upErr
	}
	return &proto.UpResponse{}, nil
}

type nopEmitter struct{}

func (nopEmitter) Emit(string, ...any) bool { return true }

func newSwitcher(t *testing.T, daemon *switchDaemon) *ProfileSwitcher {
	t.Helper()

	// The switcher mirrors the choice into the profile state of the user, which must not be the
	// state of whoever runs the tests.
	dir := t.TempDir()
	origState := profilemanager.ActiveProfileStatePath
	profilemanager.ActiveProfileStatePath = dir + "/active_profile.json"
	profilemanager.ConfigDirOverride = dir
	t.Cleanup(func() {
		profilemanager.ActiveProfileStatePath = origState
		profilemanager.ConfigDirOverride = ""
	})

	conn := stubConn{client: daemon}
	return NewProfileSwitcher(NewProfiles(conn), NewConnection(conn, nil, nil), &DaemonFeed{conn: conn, emitter: nopEmitter{}})
}

// Without the concurrent profiles gate the switch keeps the upstream order: the focus moves before
// the plain Down, so the Down ends the one connection the daemon has. The behavior of an older UI
// against a daemon with the gate is covered by TestGate_UISwitchLeavesTheOriginalSessionRunning in
// client/server; this switcher takes switchFocus there, see TestProfileSwitcher_Gate*.
func TestProfileSwitcher_DownIsPlainSoItReachesTheNewFocus(t *testing.T) {
	daemon := &switchDaemon{status: StatusConnected}
	switcher := newSwitcher(t, daemon)

	require.NoError(t, switcher.SwitchActive(context.Background(), ProfileRef{ProfileName: "doma", Username: "alice"}))

	assert.Equal(t, []string{"Status", "SwitchProfile doma", "Down", "Up doma"}, daemon.calls,
		"the focus moves before the Down, so the Down is for the new focus")
	require.Len(t, daemon.down, 1)
	assert.True(t, gproto.Equal(&proto.DownRequest{}, daemon.down[0]),
		"the Down carries neither a selector nor all, got %v", daemon.down[0])
}

func TestProfileSwitcher_NoConnectKeepsTheSamePlainDown(t *testing.T) {
	daemon := &switchDaemon{status: StatusConnected}
	switcher := newSwitcher(t, daemon)

	require.NoError(t, switcher.SwitchActiveNoConnect(context.Background(), ProfileRef{ProfileName: "doma", Username: "alice"}))

	assert.Equal(t, []string{"Status", "SwitchProfile doma", "Down"}, daemon.calls)
	assert.True(t, gproto.Equal(&proto.DownRequest{}, daemon.down[0]))
}

func TestProfileSwitcher_IdleStatusSendsNoDown(t *testing.T) {
	daemon := &switchDaemon{status: StatusIdle}
	switcher := newSwitcher(t, daemon)

	require.NoError(t, switcher.SwitchActive(context.Background(), ProfileRef{ProfileName: "doma", Username: "alice"}))

	assert.Equal(t, []string{"Status", "SwitchProfile doma", "Up doma"}, daemon.calls)
}
