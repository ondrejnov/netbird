package client

import (
	"context"
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	gproto "google.golang.org/protobuf/proto"

	"github.com/netbirdio/netbird/client/proto"
)

// recordingDaemon keeps the SSH requests it gets.
type recordingDaemon struct {
	proto.UnimplementedDaemonServiceServer

	mu       sync.Mutex
	hostKey  *proto.GetPeerSSHHostKeyRequest
	jwtAuth  *proto.RequestJWTAuthRequest
	jwtToken *proto.WaitJWTTokenRequest
}

func (d *recordingDaemon) GetPeerSSHHostKey(_ context.Context, req *proto.GetPeerSSHHostKeyRequest) (*proto.GetPeerSSHHostKeyResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.hostKey = req
	return &proto.GetPeerSSHHostKeyResponse{}, nil
}

func (d *recordingDaemon) RequestJWTAuth(_ context.Context, req *proto.RequestJWTAuthRequest) (*proto.RequestJWTAuthResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.jwtAuth = req
	return &proto.RequestJWTAuthResponse{}, nil
}

func (d *recordingDaemon) WaitJWTToken(_ context.Context, req *proto.WaitJWTTokenRequest) (*proto.WaitJWTTokenResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.jwtToken = req
	return &proto.WaitJWTTokenResponse{}, nil
}

func startRecordingDaemon(t *testing.T) (*recordingDaemon, string) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	d := &recordingDaemon{}
	srv := grpc.NewServer()
	proto.RegisterDaemonServiceServer(srv, d)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return d, "tcp://" + lis.Addr().String()
}

func callSSHRPCs(t *testing.T, addr string, session *proto.SessionSelector) {
	t.Helper()
	conn, err := connectToDaemon(addr, session)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	client := proto.NewDaemonServiceClient(conn)
	ctx := context.Background()
	_, err = client.GetPeerSSHHostKey(ctx, &proto.GetPeerSSHHostKeyRequest{PeerAddress: "100.72.0.7"})
	require.NoError(t, err)
	_, err = client.RequestJWTAuth(ctx, &proto.RequestJWTAuthRequest{})
	require.NoError(t, err)
	_, err = client.WaitJWTToken(ctx, &proto.WaitJWTTokenRequest{DeviceCode: "device"})
	require.NoError(t, err)
}

// The calls of an SSH connection reach the session the user named.
func TestConnectToDaemon_SessionReachesTheSSHCalls(t *testing.T) {
	d, addr := startRecordingDaemon(t)
	session := &proto.SessionSelector{Profile: "e5f6a7b8", Username: "alice"}

	callSSHRPCs(t, addr, session)

	assert.True(t, gproto.Equal(session, d.hostKey.GetSession()), "host key lookup: %v", d.hostKey.GetSession())
	assert.True(t, gproto.Equal(session, d.jwtAuth.GetSession()), "JWT auth: %v", d.jwtAuth.GetSession())
	assert.True(t, gproto.Equal(session, d.jwtToken.GetSession()), "JWT token: %v", d.jwtToken.GetSession())
	assert.Equal(t, "100.72.0.7", d.hostKey.GetPeerAddress(), "the rest of the request is as it was")
	assert.Equal(t, "device", d.jwtToken.GetDeviceCode())
}

// Without a session the requests are what they were: they act on the focused session.
func TestConnectToDaemon_WithoutSessionSendsNone(t *testing.T) {
	d, addr := startRecordingDaemon(t)

	callSSHRPCs(t, addr, nil)

	assert.Nil(t, d.hostKey.GetSession())
	assert.Nil(t, d.jwtAuth.GetSession())
	assert.Nil(t, d.jwtToken.GetSession())
}
