//go:build privileged && linux

package internal

import (
	"testing"

	"github.com/coreos/go-iptables/iptables"
	"github.com/google/nftables"
	"github.com/lrh3321/ipset-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/firewall"
	nbnftables "github.com/netbirdio/netbird/client/firewall/nftables"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
)

const isolationOverlaysIPSet = "nb-iso-overlays"

func useNftablesIsolation(t *testing.T) {
	t.Helper()
	// With a filter table in nftables the discovery settles on nftables.
	conn := &nftables.Conn{}
	table := conn.AddTable(&nftables.Table{Name: "filter", Family: nftables.TableFamilyIPv4})
	policy := nftables.ChainPolicyAccept
	conn.AddChain(&nftables.Chain{
		Name:     "INPUT",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &policy,
	})
	require.NoError(t, conn.Flush(), "create the filter table")
}

func deleteIsolationTable(t *testing.T) {
	t.Helper()
	conn := &nftables.Conn{}
	conn.DelTable(&nftables.Table{Name: nbnftables.IsolationTableName, Family: nftables.TableFamilyINet})
	require.NoError(t, conn.Flush(), "delete the table of the isolation")
}

// destroyIsolationIPSets takes the sets away from under the chains, which an ipset delete cannot survive.
func destroyIsolationIPSets(t *testing.T) {
	t.Helper()
	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	require.NoError(t, err)
	for _, chain := range []string{"NETBIRD-ISO-FWD", "NETBIRD-ISO-IN"} {
		require.NoError(t, ipt.ClearChain("mangle", chain))
	}
	for _, set := range []string{isolationOverlaysIPSet, "nb-iso-own"} {
		require.NoError(t, ipset.Destroy(set), "destroy the ipset %s", set)
	}
}

// A session that failed to leave the isolation must not stay in it. It would come back with every
// restore, and refuse any later session on its overlay until the daemon restarts (I7).
func TestFailedRemovalIsRepeated(t *testing.T) {
	for _, backend := range []struct {
		name  string
		setup func(t *testing.T)
		// breakRemoval changes the rules so that taking a session out fails, until the next restore.
		breakRemoval func(t *testing.T)
	}{
		{name: "nftables", setup: useNftablesIsolation, breakRemoval: deleteIsolationTable},
		{name: "iptables", setup: func(t *testing.T) { t.Setenv(firewall.SkipNftablesEnv, "true") }, breakRemoval: destroyIsolationIPSets},
	} {
		t.Run(backend.name, func(t *testing.T) {
			host := newTestDaemonHost(t)
			backend.setup(t)

			first := wgaddr.MustParseWGAddress("100.71.0.1/16")
			second := wgaddr.MustParseWGAddress("100.72.0.1/16")

			_, detachFirst, err := attachTestSession(t, host, "first", first)
			require.NoError(t, err)
			t.Cleanup(detachFirst)
			_, detachSecond, err := attachTestSession(t, host, "second", second)
			require.NoError(t, err)

			backend.breakRemoval(t)
			detachSecond()

			// The first round finds the rules changed and puts them back, the second can finish.
			ctx := t.Context()
			host.checkIsolation(ctx)
			host.checkIsolation(ctx)
			require.NoError(t, host.isolation.Verify(), "the rules should be back")

			_, detachThird, err := attachTestSession(t, host, "third", second)
			require.NoError(t, err, "the overlay of a session that left should be free")
			t.Cleanup(detachThird)
			assert.NoError(t, host.isolation.Verify())
		})
	}
}

// The last session ends the check. A removal that fails then has nobody left to repeat it, and the
// rules would stay on the host until the next session.
func TestFailedRemovalOfTheLastSessionIsRepeatedWithoutSessions(t *testing.T) {
	host := newTestDaemonHost(t)
	t.Setenv(firewall.SkipNftablesEnv, "true")

	_, detach, err := attachTestSession(t, host, "only", wgaddr.MustParseWGAddress("100.71.0.1/16"))
	require.NoError(t, err)

	// A rule that uses an ipset of the isolation keeps the set from going away.
	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	require.NoError(t, err)
	pin := []string{"-m", "set", "--match-set", isolationOverlaysIPSet, "src", "-j", "ACCEPT"}
	require.NoError(t, ipt.Append("filter", "INPUT", pin...))

	detach()
	_, err = ipset.List(isolationOverlaysIPSet)
	require.NoError(t, err, "the removal should have failed for this test to mean anything")

	require.NoError(t, ipt.DeleteIfExists("filter", "INPUT", pin...))
	host.checkIsolation(t.Context())

	_, err = ipset.List(isolationOverlaysIPSet)
	assert.Error(t, err, "the rules of the last session should be gone")
	assert.False(t, watchIsRunning(host), "with nothing left to do the check should have ended")
}

func watchIsRunning(host *DaemonHost) bool {
	host.attachMu.Lock()
	defer host.attachMu.Unlock()
	return host.watch.cancel != nil
}
