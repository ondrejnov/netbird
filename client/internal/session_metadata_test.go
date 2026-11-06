package internal

import (
	"context"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/hostcoord"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/ssh"
	"github.com/netbirdio/netbird/client/system"
	"github.com/netbirdio/netbird/client/testutil/mgmtmeta"
	mgm "github.com/netbirdio/netbird/shared/management/client"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

// hostAddress returns an address of this host as system.GetInfo reports it.
func hostAddress(t *testing.T) string {
	t.Helper()
	addrs := system.GetInfo(context.Background()).NetworkAddresses
	if len(addrs) == 0 {
		t.Skip("no network addresses on this host")
	}
	return addrs[0].NetIP.String()
}

func newMetadataConfig(t *testing.T, management string) *profilemanager.Config {
	t.Helper()
	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	sshKey, err := ssh.GeneratePrivateKey(ssh.ED25519)
	require.NoError(t, err)
	mgmtURL, err := url.Parse(management)
	require.NoError(t, err)
	return &profilemanager.Config{PrivateKey: key.String(), SSHKey: string(sshKey), ManagementURL: mgmtURL}
}

// runUntilRefused runs a client against the recording Management, which refuses it.
func runUntilRefused(t *testing.T, config *profilemanager.Config, opts ...ConnectClientOption) {
	t.Helper()
	ctx := CtxInitState(context.Background())
	opts = append(opts, WithStatePath(t.TempDir()+"/state.json"))
	client := NewConnectClient(ctx, config, peer.NewRecorder(""), opts...)
	assert.Error(t, client.Run(nil, ""), "the recording Management refuses every peer")
}

// The login of a run is the first thing a network hears from this host. Session A has its overlay
// on the interface by then, and that address is none of the business of the Management of B, on any
// path that reports addresses (I5). Without the gate there is no filter, and nothing changes (I1).
func TestRunLoginLeavesOutTheAddressesOfSessions(t *testing.T) {
	foreign := hostAddress(t)

	t.Run("without the gate the address goes out as it always did", func(t *testing.T) {
		management := mgmtmeta.Start(t)
		runUntilRefused(t, newMetadataConfig(t, management.URL()))

		requests := management.Requests()
		require.NotEmpty(t, requests, "the client should have logged in")
		assert.Contains(t, requests[0].Addresses, foreign)
	})

	t.Run("with the gate the address of a session stays home", func(t *testing.T) {
		management := mgmtmeta.Start(t)

		slots, err := hostcoord.NewSlots(t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, slots.Close()) })
		host := NewDaemonHost(slots)
		require.NoError(t, host.Coordinator().Sessions().Set(hostcoord.SessionKey{Profile: "a"}, "wt0", wgaddr.MustParseWGAddress(foreign).Network))

		runUntilRefused(t, newMetadataConfig(t, management.URL()), WithSessionHost(host.Session(hostcoord.SessionKey{Profile: "b"}, nil)))

		requests := management.Requests()
		require.NotEmpty(t, requests, "the client should have logged in")
		for _, request := range requests {
			assert.NotContains(t, request.Addresses, foreign, "the overlay address of another session must not reach this Management")
		}
	})
}

// Extending the auth session reports the host again, later and with the session running.
func TestExtendAuthSessionLeavesOutTheAddressesOfSessions(t *testing.T) {
	foreign := hostAddress(t)
	sessions := hostcoord.NewSessions()
	require.NoError(t, sessions.Set(hostcoord.SessionKey{Profile: "a"}, "wt0", wgaddr.MustParseWGAddress(foreign).Network))

	var sent []string
	e := &Engine{
		ctx:    context.Background(),
		config: &EngineConfig{Sessions: sessions},
		mgmClient: &mgm.MockClient{
			ExtendAuthSessionFunc: func(info *system.Info, _ string) (*mgmProto.ExtendAuthSessionResponse, error) {
				for _, addr := range info.NetworkAddresses {
					sent = append(sent, addr.NetIP.String())
				}
				return &mgmProto.ExtendAuthSessionResponse{}, nil
			},
		},
		statusRecorder: peer.NewRecorder(""),
	}

	_, err := e.ExtendAuthSession(context.Background(), "token")
	require.NoError(t, err)
	assert.NotContains(t, sent, foreign, "the overlay address of another session must not reach this Management")
}
