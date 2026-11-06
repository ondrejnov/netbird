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
}

func (d *switchDaemon) Status(context.Context, *proto.StatusRequest, ...grpc.CallOption) (*proto.StatusResponse, error) {
	d.calls = append(d.calls, "Status")
	return &proto.StatusResponse{Status: d.status}, nil
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

// With concurrent profiles the daemon aims a Down without a selector at the focused session, which
// after the switch is the new profile. The switcher must therefore send that plain Down and no
// selector: it never names the profile it switches away from, whose session keeps running and is
// not shown by the UI, see 5.7 of the specification. The daemon side of this is covered by
// TestGate_UISwitchLeavesTheOriginalSessionRunning in client/server.
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
