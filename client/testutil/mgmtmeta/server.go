// Package mgmtmeta runs a Management service that only records the system metadata its peers send,
// for tests that check what reaches Management.
package mgmtmeta

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/netbirdio/netbird/encryption"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

// Request is what one login or registration said about the peer.
type Request struct {
	Registration bool
	Addresses    []string
}

// Server answers every login with PermissionDenied, which makes a client without a setup key stop
// and one with a key go on to register.
type Server struct {
	mgmProto.UnimplementedManagementServiceServer

	key  wgtypes.Key
	addr string

	mu       sync.Mutex
	requests []Request
}

// Start runs a Server until the end of the test.
func Start(t *testing.T) *Server {
	t.Helper()

	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	s := &Server{key: key, addr: lis.Addr().String()}
	grpcServer := grpc.NewServer()
	mgmProto.RegisterManagementServiceServer(grpcServer, s)
	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			t.Logf("serve management: %v", err)
		}
	}()
	t.Cleanup(grpcServer.Stop)
	return s
}

// URL returns the address a client config can use.
func (s *Server) URL() string {
	return "http://" + s.addr
}

// Requests returns what the service has received so far.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.requests...)
}

// GetServerKey returns the key the clients encrypt their messages for.
func (s *Server) GetServerKey(context.Context, *mgmProto.Empty) (*mgmProto.ServerKeyResponse, error) {
	return &mgmProto.ServerKeyResponse{
		Key:       s.key.PublicKey().String(),
		ExpiresAt: timestamppb.New(time.Now().Add(time.Hour)),
	}, nil
}

// Login records the metadata of the peer and refuses it.
func (s *Server) Login(_ context.Context, msg *mgmProto.EncryptedMessage) (*mgmProto.EncryptedMessage, error) {
	peerKey, err := wgtypes.ParseKey(msg.GetWgPubKey())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	req := &mgmProto.LoginRequest{}
	if err := encryption.DecryptMessage(peerKey, s.key, msg.GetBody(), req); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	recorded := Request{Registration: req.GetSetupKey() != ""}
	for _, addr := range req.GetMeta().GetNetworkAddresses() {
		recorded.Addresses = append(recorded.Addresses, addr.GetNetIP())
	}

	s.mu.Lock()
	s.requests = append(s.requests, recorded)
	s.mu.Unlock()

	return nil, status.Error(codes.PermissionDenied, "this test refuses every peer")
}
