package cmd

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.uber.org/mock/gomock"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	"github.com/netbirdio/netbird/management/server/integrations/integrated_validator/validator"

	nbcache "github.com/netbirdio/netbird/management/server/cache"

	"github.com/netbirdio/netbird/management/internals/controllers/network_map/controller"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map/update_channel"
	"github.com/netbirdio/netbird/management/internals/controllers/peerliveness/peerlivenesstest"
	"github.com/netbirdio/netbird/management/internals/modules/peers"
	"github.com/netbirdio/netbird/management/internals/modules/peers/ephemeral/manager"
	nbgrpc "github.com/netbirdio/netbird/management/internals/shared/grpc"
	"github.com/netbirdio/netbird/management/server/job"

	"github.com/netbirdio/netbird/client/internal/ipcauth"
	clientProto "github.com/netbirdio/netbird/client/proto"
	client "github.com/netbirdio/netbird/client/server"
	"github.com/netbirdio/netbird/management/internals/server/config"
	mgmt "github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/groups"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/settings"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/netbirdio/netbird/management/server/types"
	mgmtProto "github.com/netbirdio/netbird/shared/management/proto"
	sigProto "github.com/netbirdio/netbird/shared/signal/proto"
	sig "github.com/netbirdio/netbird/signal/server"
	"github.com/netbirdio/netbird/util"
)

func startTestingServices(t *testing.T) string {
	t.Helper()
	config := &config.Config{}
	_, err := util.ReadJson("../testdata/management.json", config)
	if err != nil {
		t.Fatal(err)
	}

	_, signalLis := startSignal(t)
	signalAddr := signalLis.Addr().String()
	config.Signal.URI = signalAddr

	_, mgmLis := startManagement(t, config, "../testdata/store.sql")
	mgmAddr := mgmLis.Addr().String()
	return mgmAddr
}

func startSignal(t *testing.T) (*grpc.Server, net.Listener) {
	t.Helper()
	lis, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	s := grpc.NewServer()
	srv, err := sig.NewServer(context.Background(), otel.Meter(""))
	require.NoError(t, err)

	sigProto.RegisterSignalExchangeServer(s, srv)
	go func() {
		if err := s.Serve(lis); err != nil {
			panic(err)
		}
	}()

	return s, lis
}

func startManagement(t *testing.T, config *config.Config, testFile string) (*grpc.Server, net.Listener) {
	t.Helper()

	lis, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	s := grpc.NewServer()
	store, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), testFile, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanUp)

	eventStore := &activity.InMemoryEventStore{}

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	permissionsManagerMock := permissions.NewMockManager(ctrl)
	peerLiveness := peerlivenesstest.NewStarted(t, store)
	peersmanager := peers.NewManager(store, permissionsManagerMock, peerLiveness)
	settingsManagerMock := settings.NewMockManager(ctrl)

	jobManager := job.NewJobManager(nil, store, peersmanager)

	ctx := context.Background()

	cacheStore, err := nbcache.NewStore(ctx, 100*time.Millisecond, 300*time.Millisecond, 100)
	if err != nil {
		t.Fatal(err)
	}

	iv, _ := validator.NewIntegratedValidator(ctx, peersmanager, settingsManagerMock, eventStore, cacheStore)

	metrics, err := telemetry.NewDefaultAppMetrics(ctx)
	require.NoError(t, err)

	settingsMockManager := settings.NewMockManager(ctrl)
	groupsManager := groups.NewManagerMock()

	settingsMockManager.EXPECT().
		GetSettings(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(&types.Settings{}, nil).
		AnyTimes()

	updateManager := update_channel.NewPeersUpdateManager(metrics)
	requestBuffer := mgmt.NewAccountRequestBuffer(ctx, store)
	networkMapController := controller.NewController(ctx, store, metrics, updateManager, requestBuffer, mgmt.MockIntegratedValidator{}, settingsMockManager, "netbird.cloud", manager.NewEphemeralManager(store, peersmanager), config, nil)

	accountManager, err := mgmt.BuildManager(ctx, config, store, networkMapController, jobManager, nil, "", eventStore, nil, false, iv, metrics, settingsMockManager, permissionsManagerMock, false, cacheStore, peerLiveness)
	if err != nil {
		t.Fatal(err)
	}

	secretsManager, err := nbgrpc.NewTimeBasedAuthSecretsManager(updateManager, config.TURNConfig, config.Relay, settingsMockManager, groupsManager)
	if err != nil {
		t.Fatal(err)
	}
	mgmtServer, err := nbgrpc.NewServer(config, accountManager, settingsMockManager, jobManager, secretsManager, nil, nil, &mgmt.MockIntegratedValidator{}, networkMapController, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	mgmtProto.RegisterManagementServiceServer(s, mgmtServer)
	go func() {
		if err := s.Serve(lis); err != nil {
			t.Error(err)
		}
	}()

	return s, lis
}

func startClientDaemon(
	t *testing.T, ctx context.Context, _, _ string,
) (*grpc.Server, net.Listener) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := ipcauth.CurrentProcessIdentity()
	require.NoError(t, err)
	gate := ipcauth.NewAuthzGate()
	// A TCP listener carries no caller identity, which the daemon refuses. The process is the
	// caller of every RPC here, so its identity stands in for what the unix socket reports.
	s := grpc.NewServer(
		grpc.ChainUnaryInterceptor(withCallerIdentity(identity), gate.UnaryPolicyInterceptor()),
		grpc.ChainStreamInterceptor(withStreamCallerIdentity(identity), gate.StreamPolicyInterceptor()),
	)

	server := client.New(ctx,
		"", "", false, false, false, false, false)
	gate.SetState(server)
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	clientProto.RegisterDaemonServiceServer(s, server)
	go func() {
		if err := s.Serve(lis); err != nil {
			t.Error(err)
		}
	}()

	time.Sleep(time.Second)

	return s, lis
}

func callerContext(ctx context.Context, identity ipcauth.Identity) context.Context {
	return peer.NewContext(ctx, &peer.Peer{AuthInfo: ipcauth.AuthInfo{
		CommonAuthInfo: credentials.CommonAuthInfo{SecurityLevel: credentials.NoSecurity},
		Identity:       identity,
	}})
}

func withCallerIdentity(identity ipcauth.Identity) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		return handler(callerContext(ctx, identity), req)
	}
}

func withStreamCallerIdentity(identity ipcauth.Identity) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		return handler(srv, identityStream{ServerStream: ss, ctx: callerContext(ss.Context(), identity)})
	}
}

type identityStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s identityStream) Context() context.Context { return s.ctx }
