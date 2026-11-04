//go:build (linux && !android) || freebsd

package dns

import (
	"context"
	"fmt"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/peer"
)

// TestBackend selects a host DNS backend without probing the host, whose real
// resolver the test must not depend on.
type TestBackend osManagerType

// The backends the tests exercise.
const (
	TestBackendSystemd        = TestBackend(systemdManager)
	TestBackendNetworkManager = TestBackend(networkManager)
	TestBackendResolvConf     = TestBackend(resolvConfManager)
	TestBackendFile           = TestBackend(fileManager)
)

type testSessionIface struct {
	mockNetstackProvider
	name string
}

func (i *testSessionIface) Name() string { return i.name }

// testSessionService stands in for the listener: these tests observe what is
// programmed on the host, not what is answered on the DNS port.
type testSessionService struct {
	ip netip.Addr
}

func (s *testSessionService) Listen() error                   { return nil }
func (s *testSessionService) Stop() error                     { return nil }
func (s *testSessionService) RuntimeIP() netip.Addr           { return s.ip }
func (s *testSessionService) RuntimePort() int                { return DefaultPort }
func (s *testSessionService) RegisterMux(string, dns.Handler) {}
func (s *testSessionService) DeregisterMux(string)            {}

// NewTestSessionServer returns a DefaultServer on the real host manager of backend.
// A nil coordinator takes the path a daemon without sessions takes.
func NewTestSessionServer(t *testing.T, iface string, ip netip.Addr, backend TestBackend, coordinator HostDNSCoordinator) *DefaultServer {
	t.Helper()

	var (
		manager hostManager
		err     error
	)
	if coordinator == nil {
		manager, err = newHostManagerFromType(iface, osManagerType(backend), nil)
	} else {
		manager, err = coordinatedManagerFromType(iface, osManagerType(backend), coordinator)
	}
	require.NoError(t, err)

	server := newDefaultServer(context.Background(), &testSessionIface{name: iface}, &testSessionService{ip: ip}, peer.NewRecorder("test"), nil, false)
	server.hostManager = manager
	server.hostDNS = coordinator
	t.Cleanup(server.Stop)
	return server
}

// NewTestConfiguredServer returns a server built the way the engine builds one.
func NewTestConfiguredServer(t *testing.T, iface string, coordinator HostDNSCoordinator) *DefaultServer {
	t.Helper()
	server, err := NewDefaultServer(context.Background(), DefaultServerConfig{
		WgInterface:    &testSessionIface{name: iface},
		StatusRecorder: peer.NewRecorder("test"),
		HostDNS:        coordinator,
	})
	require.NoError(t, err)
	return server
}

// InitializedHostManagerType returns the type of the manager the server picks on this
// host, which depends on the host's real DNS setup.
func InitializedHostManagerType(server *DefaultServer) (string, error) {
	manager, err := server.initialize()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%T", manager), nil
}

// OriginalNameservers returns what the server's host manager captured.
func OriginalNameservers(server *DefaultServer) []netip.Addr {
	return server.hostManager.getOriginalNameservers()
}
