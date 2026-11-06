package client

import (
	"context"
	"fmt"
	"net"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/client/proto"
	nbssh "github.com/netbirdio/netbird/client/ssh"
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

// jwtHostKeyCallback returns how a server that gets a JWT has its host key verified. With concurrent
// profiles the token is of one session, and a server of another network must not get it (I9): that
// network could replay it against the servers of the first. Only the daemon can tell that the key
// belongs to a peer of the session, so known_hosts and an ignored key do not count.
func jwtHostKeyCallback(fallback ssh.HostKeyCallback, gate bool, daemonAddr string, session *proto.SessionSelector) ssh.HostKeyCallback {
	if !gate {
		return fallback
	}
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		return verifyHostKeyViaDaemon(hostname, remote, key, daemonAddr, session)
	}
}

// fixJWTSession asks the daemon which session answers for the connection, see nbssh.FixSession.
func fixJWTSession(ctx context.Context, daemonAddr string, session *proto.SessionSelector) (*proto.SessionSelector, bool, error) {
	conn, err := connectToDaemon(daemonAddr, session)
	if err != nil {
		return nil, false, fmt.Errorf("connect to daemon: %w", err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			log.Debugf("daemon connection close error: %v", err)
		}
	}()

	return nbssh.FixSession(ctx, proto.NewDaemonServiceClient(conn), session)
}
