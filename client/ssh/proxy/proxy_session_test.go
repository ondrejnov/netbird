package proxy

import (
	"context"
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/proto"
	nbssh "github.com/netbirdio/netbird/client/ssh"
)

// focusDaemon holds two sessions, and the focus moves to home as soon as a token is handed out. A
// request without a selector goes to whichever has the focus at that moment.
type focusDaemon struct {
	proto.UnimplementedDaemonServiceServer
	features  *proto.GetFeaturesResponse
	activeErr error
	knownKeys map[string][]byte

	mu      sync.Mutex
	focused string
	asked   int
	jwtFor  []string
}

func (d *focusDaemon) sessionOf(selector *proto.SessionSelector) string {
	if selector != nil {
		return selector.GetProfile()
	}
	return d.focused
}

func (d *focusDaemon) GetFeatures(context.Context, *proto.GetFeaturesRequest) (*proto.GetFeaturesResponse, error) {
	return d.features, nil
}

func (d *focusDaemon) GetActiveProfile(context.Context, *proto.GetActiveProfileRequest) (*proto.GetActiveProfileResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.asked++
	if d.activeErr != nil {
		return nil, d.activeErr
	}
	return &proto.GetActiveProfileResponse{Id: d.focused, Username: "alice"}, nil
}

func (d *focusDaemon) RequestJWTAuth(_ context.Context, req *proto.RequestJWTAuthRequest) (*proto.RequestJWTAuthResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.jwtFor = append(d.jwtFor, d.sessionOf(req.GetSession()))
	d.focused = "home"
	return &proto.RequestJWTAuthResponse{CachedToken: "token"}, nil
}

func (d *focusDaemon) GetPeerSSHHostKey(_ context.Context, req *proto.GetPeerSSHHostKeyRequest) (*proto.GetPeerSSHHostKeyResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	key := d.knownKeys[d.sessionOf(req.GetSession())]
	return &proto.GetPeerSSHHostKeyResponse{Found: key != nil, SshHostKey: key}, nil
}

func (d *focusDaemon) requests() (asked int, jwtFor []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.asked, append([]string(nil), d.jwtFor...)
}

func newProxyOf(t *testing.T, daemon *focusDaemon) *SSHProxy {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := grpc.NewServer()
	proto.RegisterDaemonServiceServer(srv, daemon)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	p, err := New("tcp://"+lis.Addr().String(), "100.72.0.7", 22, nil, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func proxyServerKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	private, err := nbssh.GeneratePrivateKey(nbssh.ED25519)
	require.NoError(t, err)
	public, err := nbssh.GeneratePublicKey(private)
	require.NoError(t, err)
	key, _, _, _, err := ssh.ParseAuthorizedKey(public)
	require.NoError(t, err)
	return key
}

// A proxy lives as long as its connection. The server it hands the token to has to be one of the
// session that gave the token, wherever the focus went in the meantime (I9).
func TestProxyStaysWithTheSessionOfItsToken(t *testing.T) {
	gateOn := &proto.GetFeaturesResponse{ConcurrentProfilesEnabled: true}
	remote := &net.TCPAddr{IP: net.IPv4(100, 72, 0, 7), Port: 22}

	t.Run("a server only the session in focus now knows is refused", func(t *testing.T) {
		key := proxyServerKey(t)
		daemon := &focusDaemon{features: gateOn, focused: "work", knownKeys: map[string][]byte{"home": ssh.MarshalAuthorizedKey(key)}}
		p := newProxyOf(t, daemon)

		_, err := p.authenticate(t.Context())
		require.NoError(t, err)

		assert.Error(t, p.verifyHostKey("100.72.0.7:22", remote, key), "the session of the token does not know the server")
	})

	t.Run("a server of the session of the token is accepted", func(t *testing.T) {
		key := proxyServerKey(t)
		daemon := &focusDaemon{features: gateOn, focused: "work", knownKeys: map[string][]byte{"work": ssh.MarshalAuthorizedKey(key)}}
		p := newProxyOf(t, daemon)

		_, err := p.authenticate(t.Context())
		require.NoError(t, err)

		assert.NoError(t, p.verifyHostKey("100.72.0.7:22", remote, key))
	})

	t.Run("a focus the caller may not read asks for no token", func(t *testing.T) {
		daemon := &focusDaemon{features: gateOn, focused: "work", activeErr: status.Error(codes.PermissionDenied, "not yours")}
		p := newProxyOf(t, daemon)

		_, err := p.authenticate(t.Context())
		assert.Error(t, err)
		_, jwtFor := daemon.requests()
		assert.Empty(t, jwtFor, "without knowing the session no token should be asked for")
	})

	t.Run("without the gate nothing is fixed", func(t *testing.T) {
		key := proxyServerKey(t)
		daemon := &focusDaemon{features: &proto.GetFeaturesResponse{}, focused: "work", knownKeys: map[string][]byte{"home": ssh.MarshalAuthorizedKey(key)}}
		p := newProxyOf(t, daemon)

		_, err := p.authenticate(t.Context())
		require.NoError(t, err)

		asked, _ := daemon.requests()
		assert.Zero(t, asked, "a daemon without the gate has no focus to fix")
		assert.NoError(t, p.verifyHostKey("100.72.0.7:22", remote, key), "the proxy keeps following the focus as before")
	})
}
