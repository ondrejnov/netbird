package client

import (
	"context"

	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/client/proto"
)

// sessionInterceptor addresses the daemon calls of an SSH connection to one session. The calls
// are the ones that look up a peer's host key and log in for the connection, so that they reach
// the network of the session the user named and not the one the daemon has focused.
func sessionInterceptor(session *proto.SessionSelector) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		switch r := req.(type) {
		case *proto.GetPeerSSHHostKeyRequest:
			r.Session = session
		case *proto.RequestJWTAuthRequest:
			r.Session = session
		case *proto.WaitJWTTokenRequest:
			r.Session = session
		}
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}
