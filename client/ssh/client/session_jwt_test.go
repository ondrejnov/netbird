package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/client/ssh/detection"
)

const jwtOfTheSession = "jwt-of-the-focused-session"

// jwtDaemon answers as a daemon whose session holds a JWT. knownKey is the host key of a peer it
// knows, nil when the peer is in another network.
type jwtDaemon struct {
	proto.UnimplementedDaemonServiceServer
	features    *proto.GetFeaturesResponse
	featuresErr error
	knownKey    []byte
}

func (d *jwtDaemon) GetFeatures(context.Context, *proto.GetFeaturesRequest) (*proto.GetFeaturesResponse, error) {
	if d.featuresErr != nil {
		return nil, d.featuresErr
	}
	return d.features, nil
}

// GetActiveProfile names the focused session, which a connection without --profile is fixed to.
func (d *jwtDaemon) GetActiveProfile(context.Context, *proto.GetActiveProfileRequest) (*proto.GetActiveProfileResponse, error) {
	return &proto.GetActiveProfileResponse{Id: "work", ProfileName: "work", Username: "alice"}, nil
}

func (d *jwtDaemon) RequestJWTAuth(context.Context, *proto.RequestJWTAuthRequest) (*proto.RequestJWTAuthResponse, error) {
	return &proto.RequestJWTAuthResponse{CachedToken: jwtOfTheSession}, nil
}

func (d *jwtDaemon) GetPeerSSHHostKey(context.Context, *proto.GetPeerSSHHostKeyRequest) (*proto.GetPeerSSHHostKeyResponse, error) {
	return &proto.GetPeerSSHHostKeyResponse{Found: d.knownKey != nil, SshHostKey: d.knownKey}, nil
}

func startJWTDaemon(t *testing.T, daemon *jwtDaemon) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := grpc.NewServer()
	proto.RegisterDaemonServiceServer(srv, daemon)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return "tcp://" + lis.Addr().String()
}

// jwtServer is an SSH server that wants a JWT and keeps what it gets.
type jwtServer struct {
	addr     string
	hostKey  ssh.PublicKey
	mu       sync.Mutex
	received []string
}

func (s *jwtServer) tokens() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.received...)
}

func startJWTServer(t *testing.T) *jwtServer {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(private)
	require.NoError(t, err)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = lis.Close() })

	server := &jwtServer{addr: lis.Addr().String(), hostKey: signer.PublicKey()}
	config := &ssh.ServerConfig{
		ServerVersion: "SSH-2.0-" + detection.ServerIdentifier + "-" + detection.JWTRequiredMarker,
		PasswordCallback: func(_ ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			server.mu.Lock()
			defer server.mu.Unlock()
			server.received = append(server.received, string(password))
			return &ssh.Permissions{}, nil
		},
	}
	config.AddHostKey(signer)

	go func() {
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				if _, _, _, err := ssh.NewServerConn(conn, config); err != nil {
					t.Logf("handshake: %v", err)
				}
			}()
		}
	}()
	return server
}

func knownHostsWith(t *testing.T, addr string, key ssh.PublicKey) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "known_hosts")
	require.NoError(t, os.WriteFile(path, []byte(knownhosts.Line([]string{addr}, key)+"\n"), 0o600))
	return path
}

// The token of a session is for the servers of its network. A server of another network that known_hosts
// happens to vouch for could replay it against the servers of the first (I9). With concurrent profiles
// only the daemon can say the server belongs to the session.
func TestJWTGoesOnlyToAServerTheSessionKnows(t *testing.T) {
	gateOn := &proto.GetFeaturesResponse{ConcurrentProfilesEnabled: true}
	gateOff := &proto.GetFeaturesResponse{}

	marshalledKey := func(server *jwtServer) []byte { return ssh.MarshalAuthorizedKey(server.hostKey) }

	for _, tc := range []struct {
		name        string
		daemon      func(server *jwtServer) *jwtDaemon
		insecure    bool
		wantToken   bool
		wantDialErr bool
	}{
		{
			name:        "known_hosts does not vouch for a peer the session does not know",
			daemon:      func(*jwtServer) *jwtDaemon { return &jwtDaemon{features: gateOn} },
			wantDialErr: true,
		},
		{
			name:        "an ignored host key does not either",
			daemon:      func(*jwtServer) *jwtDaemon { return &jwtDaemon{features: gateOn} },
			insecure:    true,
			wantDialErr: true,
		},
		{
			name: "the daemon vouches for a peer of the session",
			daemon: func(server *jwtServer) *jwtDaemon {
				return &jwtDaemon{features: gateOn, knownKey: marshalledKey(server)}
			},
			wantToken: true,
		},
		{
			name:        "not knowing whether the gate is on keeps the token",
			daemon:      func(*jwtServer) *jwtDaemon { return &jwtDaemon{featuresErr: status.Error(codes.Internal, "broken")} },
			wantDialErr: true,
		},
		{
			name:      "without the gate known_hosts counts as before",
			daemon:    func(*jwtServer) *jwtDaemon { return &jwtDaemon{features: gateOff} },
			wantToken: true,
		},
		{
			name:      "a daemon without the features counts as before",
			daemon:    func(*jwtServer) *jwtDaemon { return &jwtDaemon{featuresErr: status.Error(codes.Unimplemented, "old")} },
			wantToken: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := startJWTServer(t)
			daemonAddr := startJWTDaemon(t, tc.daemon(server))

			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			client, err := Dial(ctx, server.addr, "user", DialOptions{
				KnownHostsFile:     knownHostsWith(t, server.addr, server.hostKey),
				DaemonAddr:         daemonAddr,
				InsecureSkipVerify: tc.insecure,
				NoBrowser:          true,
			})
			if client != nil {
				t.Cleanup(func() { _ = client.Close() })
			}

			if tc.wantDialErr {
				assert.Error(t, err, "the connection should not go through")
			} else {
				assert.NoError(t, err)
			}
			if tc.wantToken {
				assert.Equal(t, []string{jwtOfTheSession}, server.tokens(), "the server should get the token")
			} else {
				assert.Empty(t, server.tokens(), "the server must not get the token")
			}
		})
	}
}

// focusDaemon holds two sessions, and the focus moves to the other one as soon as the first token is
// handed out. A request without a selector goes to whichever has the focus at that moment.
type focusDaemon struct {
	proto.UnimplementedDaemonServiceServer
	features  *proto.GetFeaturesResponse
	activeErr error
	// knownKeys has the host key each session knows the server by.
	knownKeys map[string][]byte

	mu        sync.Mutex
	focused   string
	focusNext string
	asked     int
	jwtFor    []string
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
	return &proto.GetActiveProfileResponse{Id: d.focused, ProfileName: "name of " + d.focused, Username: "alice"}, nil
}

func (d *focusDaemon) RequestJWTAuth(_ context.Context, req *proto.RequestJWTAuthRequest) (*proto.RequestJWTAuthResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.jwtFor = append(d.jwtFor, d.sessionOf(req.GetSession()))
	d.focused = d.focusNext
	return &proto.RequestJWTAuthResponse{CachedToken: jwtOfTheSession}, nil
}

func (d *focusDaemon) GetPeerSSHHostKey(_ context.Context, req *proto.GetPeerSSHHostKeyRequest) (*proto.GetPeerSSHHostKeyResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	key := d.knownKeys[d.sessionOf(req.GetSession())]
	return &proto.GetPeerSSHHostKeyResponse{Found: key != nil, SshHostKey: key}, nil
}

func (d *focusDaemon) tokenRequests() (asked int, jwtFor []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.asked, slices.Clone(d.jwtFor)
}

func startFocusDaemon(t *testing.T, daemon *focusDaemon) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := grpc.NewServer()
	proto.RegisterDaemonServiceServer(srv, daemon)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return "tcp://" + lis.Addr().String()
}

// A token of one session must not go to a server that only another session knows, however the focus
// moves between the two questions to the daemon (I9).
func TestJWTAndHostKeyOfOneConnectionAskTheSameSession(t *testing.T) {
	gateOn := &proto.GetFeaturesResponse{ConcurrentProfilesEnabled: true}

	dial := func(t *testing.T, server *jwtServer, daemon *focusDaemon, session *proto.SessionSelector) error {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		client, err := Dial(ctx, server.addr, "user", DialOptions{
			KnownHostsFile: knownHostsWith(t, server.addr, server.hostKey),
			DaemonAddr:     startFocusDaemon(t, daemon),
			NoBrowser:      true,
			Session:        session,
		})
		if client != nil {
			t.Cleanup(func() { _ = client.Close() })
		}
		return err
	}

	t.Run("the focus moves to a session that knows the server", func(t *testing.T) {
		server := startJWTServer(t)
		daemon := &focusDaemon{
			features:  gateOn,
			focused:   "work",
			focusNext: "home",
			knownKeys: map[string][]byte{"home": ssh.MarshalAuthorizedKey(server.hostKey)},
		}

		assert.Error(t, dial(t, server, daemon, nil), "the session of the token does not know the server")
		assert.Empty(t, server.tokens(), "the server must not get the token of the other session")
	})

	t.Run("the focus moves away from the session that knows the server", func(t *testing.T) {
		server := startJWTServer(t)
		daemon := &focusDaemon{
			features:  gateOn,
			focused:   "work",
			focusNext: "home",
			knownKeys: map[string][]byte{"work": ssh.MarshalAuthorizedKey(server.hostKey)},
		}

		assert.NoError(t, dial(t, server, daemon, nil))
		assert.Equal(t, []string{jwtOfTheSession}, server.tokens(), "the server should get the token of its session")
	})

	t.Run("a focus the caller may not read refuses the connection", func(t *testing.T) {
		server := startJWTServer(t)
		daemon := &focusDaemon{
			features:  gateOn,
			focused:   "work",
			focusNext: "work",
			activeErr: status.Error(codes.PermissionDenied, "not yours"),
			knownKeys: map[string][]byte{"work": ssh.MarshalAuthorizedKey(server.hostKey)},
		}

		assert.Error(t, dial(t, server, daemon, nil))
		_, jwtFor := daemon.tokenRequests()
		assert.Empty(t, jwtFor, "without knowing the session no token should be asked for")
	})

	t.Run("a named session is asked as it is", func(t *testing.T) {
		server := startJWTServer(t)
		daemon := &focusDaemon{
			features:  gateOn,
			focused:   "work",
			focusNext: "work",
			knownKeys: map[string][]byte{"home": ssh.MarshalAuthorizedKey(server.hostKey)},
		}

		assert.NoError(t, dial(t, server, daemon, &proto.SessionSelector{Profile: "home", Username: "alice"}))
		asked, jwtFor := daemon.tokenRequests()
		assert.Zero(t, asked, "the focus does not matter for a named session")
		assert.Equal(t, []string{"home"}, jwtFor)
	})

	t.Run("without the gate nothing is fixed", func(t *testing.T) {
		server := startJWTServer(t)
		daemon := &focusDaemon{features: &proto.GetFeaturesResponse{}, focused: "work", focusNext: "work"}

		assert.NoError(t, dial(t, server, daemon, nil), "known_hosts counts as before")
		asked, _ := daemon.tokenRequests()
		assert.Zero(t, asked, "a daemon without the gate has no focus to fix")
	})
}
