package server

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/hostcoord"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/ssh"
	"github.com/netbirdio/netbird/client/system"
	"github.com/netbirdio/netbird/client/testutil/mgmtmeta"
)

func loginAgainst(t *testing.T, s *Server, management *mgmtmeta.Server, setupKey string) {
	t.Helper()
	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	sshKey, err := ssh.GeneratePrivateKey(ssh.ED25519)
	require.NoError(t, err)
	config, err := profilemanager.UpdateOrCreateConfig(profilemanager.ConfigInput{
		ConfigPath:    t.TempDir() + "/login.json",
		ManagementURL: management.URL(),
	})
	require.NoError(t, err)
	config.PrivateKey, config.SSHKey = key.String(), string(sshKey)

	_, err = s.loginAttempt(context.Background(), config, setupKey, "")
	assert.Error(t, err, "the recording Management refuses every peer")
}

// A login and a registration are both on the way to the Management of one network while another
// session has its overlay on the host. Its address goes out only without the gate, where it is the
// address of the one network there is (I1, I5).
func TestLoginAndRegistrationLeaveOutTheAddressesOfSessions(t *testing.T) {
	addrs := system.GetInfo(context.Background()).NetworkAddresses
	if len(addrs) == 0 {
		t.Skip("no network addresses on this host")
	}
	foreign := addrs[0].NetIP.String()
	setupKey := "A2C8E62B-38F5-4553-B31E-DD66C696CEBB"

	t.Run("without the gate", func(t *testing.T) {
		s, _, _, _, _ := setupServerWithProfile(t)
		management := mgmtmeta.Start(t)

		loginAgainst(t, s, management, setupKey)

		requests := management.Requests()
		require.Len(t, requests, 2, "a refused login goes on to register")
		for _, request := range requests {
			assert.Contains(t, request.Addresses, foreign, "registration %t", request.Registration)
		}
	})

	t.Run("with the gate", func(t *testing.T) {
		f := newGateFixture(t)
		management := mgmtmeta.Start(t)
		require.NoError(t, f.s.host.Coordinator().Sessions().Set(hostcoord.SessionKey{Profile: "a"}, "wt0", wgaddr.MustParseWGAddress(foreign).Network))

		loginAgainst(t, f.s, management, setupKey)

		requests := management.Requests()
		require.Len(t, requests, 2, "a refused login goes on to register")
		assert.False(t, requests[0].Registration)
		assert.True(t, requests[1].Registration)
		for _, request := range requests {
			assert.NotContains(t, request.Addresses, foreign, "registration %t: the overlay address of another session must not reach this Management", request.Registration)
		}
	})
}
