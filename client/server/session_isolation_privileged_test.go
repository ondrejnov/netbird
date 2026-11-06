//go:build privileged && linux

package server

import (
	"testing"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/google/nftables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/firewall"
	nbnftables "github.com/netbirdio/netbird/client/firewall/nftables"
	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/hostcoord"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
)

const (
	testIsolationCheckInterval = 200 * time.Millisecond
	isolationRecoveryTimeout   = 20 * time.Second

	eventIsolationRestored = "isolation_restored"
)

func skipNftables(t *testing.T) {
	t.Helper()
	t.Setenv(firewall.SkipNftablesEnv, "true")
}

// startBothSessions brings up two sessions, with the check of the isolation running often.
func startBothSessions(t *testing.T, f *sessionsFixture) (work, home *session) {
	t.Helper()
	f.s.host.SetIsolationCheckInterval(testIsolationCheckInterval)

	upProfile(t, f.ctx, f.s, f.work, f.username)
	work = f.session(t, f.work)
	awaitConnected(t, work, f.work)
	upProfile(t, f.ctx, f.s, f.home, f.username)
	home = f.session(t, f.home)
	awaitConnected(t, home, f.home)
	require.NoError(t, f.s.host.Isolation().Verify())
	return work, home
}

func deleteNftablesIsolation(t *testing.T) {
	t.Helper()
	conn := &nftables.Conn{}
	conn.DelTable(&nftables.Table{Name: nbnftables.IsolationTableName, Family: nftables.TableFamilyINet})
	require.NoError(t, conn.Flush())
}

func flushMangleHooks(t *testing.T) {
	t.Helper()
	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	require.NoError(t, err)
	for _, chain := range []string{"FORWARD", "INPUT"} {
		require.NoError(t, ipt.ClearChain("mangle", chain))
	}
}

func awaitIsolationBack(t *testing.T, f *sessionsFixture, sessions ...*session) {
	t.Helper()
	require.Eventually(t, func() bool {
		for _, ss := range sessions {
			if len(eventsOfKind(ss, eventIsolationRestored)) == 0 {
				return false
			}
		}
		return f.s.host.Isolation().Verify() == nil
	}, isolationRecoveryTimeout, 50*time.Millisecond, "the isolation should be put back")
}

// Whatever else manages the firewall of the host can take the rules away while sessions run, and
// nothing tells the daemon. The rules come back on their own, and the sessions stay isolated by
// them: the packets are the proof, the record agreeing with the kernel is not.
func TestIsolationComesBackWhileSessionsRun(t *testing.T) {
	for _, backend := range []struct {
		name  string
		setup func(t *testing.T)
		wipe  func(t *testing.T)
	}{
		{name: "nftables", setup: requireNftablesBackend, wipe: deleteNftablesIsolation},
		{name: "iptables", setup: skipNftables, wipe: flushMangleHooks},
	} {
		t.Run(backend.name, func(t *testing.T) {
			backend.setup(t)
			f := newSessionsFixture(t)
			work, home := startBothSessions(t, f)

			backend.wipe(t)
			awaitIsolationBack(t, f, work, home)

			assert.Equal(t, internal.StatusConnected, work.state.CurrentStatus(), "the session should keep running")
			assert.Equal(t, internal.StatusConnected, home.state.CurrentStatus(), "the session should keep running")

			workSide := sessionSide{ss: work, iface: "wt0", network: networkWork}
			homeSide := sessionSide{ss: home, iface: "wt1", network: networkHome}
			assertIsolated(t, f, workSide, homeSide, 41200)
			assertIsolated(t, f, homeSide, workSide, 41300)
		})
	}
}

// A flush of the whole ruleset takes more than the isolation. It has to come back all the same, and
// a session arriving after that must not fail because of a table that is gone.
func TestSessionStartsAfterTheRulesetWasFlushed(t *testing.T) {
	requireNftablesBackend(t)
	f := newSessionsFixture(t)
	f.s.host.SetIsolationCheckInterval(testIsolationCheckInterval)

	upProfile(t, f.ctx, f.s, f.work, f.username)
	work := f.session(t, f.work)
	awaitConnected(t, work, f.work)

	conn := &nftables.Conn{}
	conn.FlushRuleset()
	require.NoError(t, conn.Flush())
	awaitIsolationBack(t, f, work)

	upProfile(t, f.ctx, f.s, f.home, f.username)
	home := f.session(t, f.home)
	awaitConnected(t, home, f.home)
	assert.NoError(t, f.s.host.Isolation().Verify())
}

// I6: when the isolation cannot come back no session runs without it. A rule that uses an ipset of the
// isolation keeps the set from going away, which the iptables backend has to do. The sessions stop,
// with a reason, and come back only after what is left of the rules is gone.
func TestLostIsolationStopsAllSessions(t *testing.T) {
	skipNftables(t)
	f := newSessionsFixture(t)
	work, home := startBothSessions(t, f)

	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	require.NoError(t, err)
	pin := []string{"-m", "set", "--match-set", "nb-iso-overlays", "src", "-j", "ACCEPT"}
	require.NoError(t, ipt.Append("filter", "INPUT", pin...))
	t.Cleanup(func() {
		if err := ipt.DeleteIfExists("filter", "INPUT", pin...); err != nil {
			t.Logf("remove the rule: %v", err)
		}
	})
	flushMangleHooks(t)

	awaitRunEnd(t, work)
	awaitRunEnd(t, home)

	for name, ss := range map[string]*session{"wt0": work, "wt1": home} {
		_, err := netlink.LinkByName(name)
		assert.Error(t, err, "the interface %s should be gone with its session", name)
		assert.Equal(t, internal.StatusIdle, ss.state.CurrentStatus(), "the session on %s should not run", name)
		refusal := ss.currentRefusal()
		require.NotNil(t, refusal, "the session on %s should say why it stopped", name)
		assert.Contains(t, refusal.Message, "stopped", "the session on %s should say it stopped", name)
		assert.NotEmpty(t, eventsOfKind(ss, internal.EventSessionRefused), "the session on %s should report it", name)
	}
	records, err := hostcoord.StoredRecords(profilemanager.DefaultConfigPathDir)
	require.NoError(t, err)
	for _, record := range records {
		if record.Key == work.key {
			assert.Equal(t, hostcoord.DesiredUp, record.Desired, "the session should come back with the service")
		}
	}

	// What is left of the rules cannot count as the isolation of a new session.
	name, username := f.work, f.username
	_, err = f.s.Up(f.ctx, &proto.UpRequest{ProfileName: &name, Username: &username})
	require.Error(t, err, "a session must not start while the rules cannot be removed")
	assert.Equal(t, codes.FailedPrecondition, gstatus.Code(err), "the Up should say the session is refused: %v", err)

	require.NoError(t, ipt.DeleteIfExists("filter", "INPUT", pin...))
	upProfile(t, f.ctx, f.s, f.work, f.username)
	awaitConnected(t, work, f.work)
	assert.NoError(t, f.s.host.Isolation().Verify())
}
