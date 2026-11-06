package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbssh "github.com/netbirdio/netbird/client/ssh"
)

func TestNewForSlot_NamesTheFileAfterTheSlot(t *testing.T) {
	assert.Equal(t, nbssh.NetBirdSSHConfigFile, NewForSlot(0).GetSSHConfigFile(), "slot 0 has the file of today")
	assert.Equal(t, New().GetSSHConfigFile(), NewForSlot(0).GetSSHConfigFile(), "slot 0 is what New gives")
	assert.Equal(t, New().GetSSHConfigDir(), NewForSlot(1).GetSSHConfigDir(), "all slots share the directory ssh reads")
	assert.Equal(t, "99-netbird-1.conf", NewForSlot(1).GetSSHConfigFile())
	assert.Equal(t, "99-netbird-12.conf", NewForSlot(12).GetSSHConfigFile(), "the number of a slot has no upper bound")
}

func slotManagerIn(dir string, slot uint) *Manager {
	m := NewForSlot(slot)
	m.sshConfigDir = dir
	return m
}

// Each session writes its own file, and neither its stop nor the cleanup of its state after a crash
// reaches the file of another session.
func TestSlotFiles_StayApart(t *testing.T) {
	t.Setenv(EnvDisableSSHConfig, "")
	peersOf := func(fqdn string) []PeerSSHInfo { return []PeerSSHInfo{{Hostname: "peer", FQDN: fqdn}} }

	for _, stop := range []struct {
		name string
		run  func(t *testing.T, m *Manager)
	}{
		{"stop", func(t *testing.T, m *Manager) { require.NoError(t, m.RemoveSSHClientConfig()) }},
		{"state cleanup", func(t *testing.T, m *Manager) {
			state := &ShutdownState{SSHConfigDir: m.GetSSHConfigDir(), SSHConfigFile: m.GetSSHConfigFile()}
			require.NoError(t, state.Cleanup())
		}},
	} {
		t.Run(stop.name, func(t *testing.T) {
			dir := t.TempDir()
			first, second := slotManagerIn(dir, 0), slotManagerIn(dir, 1)
			require.NoError(t, first.SetupSSHClientConfig(peersOf("a.work.example")))
			require.NoError(t, second.SetupSSHClientConfig(peersOf("b.home.example")))

			firstFile := filepath.Join(dir, nbssh.NetBirdSSHConfigFile)
			secondFile := filepath.Join(dir, "99-netbird-1.conf")
			firstContent, err := os.ReadFile(firstFile)
			require.NoError(t, err)
			secondContent, err := os.ReadFile(secondFile)
			require.NoError(t, err)
			assert.Contains(t, string(firstContent), "a.work.example", "a file has the peers of its session")
			assert.NotContains(t, string(firstContent), "b.home.example", "a file has the peers of no other session")
			assert.Contains(t, string(secondContent), "b.home.example", "a file has the peers of its session")

			stop.run(t, second)
			assert.NoFileExists(t, secondFile, "the file of the session goes away")
			after, err := os.ReadFile(firstFile)
			require.NoError(t, err, "the file of the other session must stay")
			assert.Equal(t, firstContent, after, "the file of the other session must stay as it was")

			require.NoError(t, second.SetupSSHClientConfig(peersOf("b.home.example")))
			stop.run(t, first)
			assert.NoFileExists(t, firstFile, "slot 0 goes away just the same")
			assert.FileExists(t, secondFile, "the file of the other session must stay")
		})
	}
}
