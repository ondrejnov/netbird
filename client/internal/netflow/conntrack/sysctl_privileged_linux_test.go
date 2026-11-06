//go:build privileged && linux && !android

package conntrack

import (
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	nfct "github.com/ti-mo/conntrack"
	"github.com/ti-mo/netfilter"
	"golang.org/x/sys/unix"
)

const acctFile = "/proc/sys/net/netfilter/nf_conntrack_acct"

// enterNewNetns moves the test goroutine into a fresh network namespace so the
// sysctl it flips never touches the namespace the test binary was started in.
// The thread stays locked and ends with the goroutine, taking the namespace
// with it.
func enterNewNetns(t *testing.T) {
	t.Helper()
	runtime.LockOSThread()
	require.NoError(t, unix.Unshare(unix.CLONE_NEWNET), "unshare network namespace")
	if _, err := os.Stat(acctFile); err != nil {
		t.Skipf("nf_conntrack_acct is not available: %v", err)
	}
}

func readAcct(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(acctFile)
	require.NoError(t, err, "read nf_conntrack_acct")
	return strings.TrimSpace(string(raw))
}

func runAccountingStopOrder(t *testing.T, firstStop, secondStop int) {
	enterNewNetns(t)
	require.NoError(t, os.WriteFile(acctFile, []byte("0"), 0o644), "set the original")

	shared := NewAccounting()
	require.NoError(t, shared.Acquire(), "A starts")
	require.NoError(t, shared.Acquire(), "B starts, finding the counters already on")
	assert.Equal(t, "1", readAcct(t), "counters on while sessions run")
	assert.Equal(t, 2, shared.Holders(), "both sessions hold the counters")

	stops := []func() error{shared.Release, shared.Release}
	require.NoError(t, stops[firstStop](), "first stop")
	assert.Equal(t, "1", readAcct(t), "counters stay on for the remaining session")
	require.NoError(t, stops[secondStop](), "second stop")
	assert.Equal(t, "0", readAcct(t), "counters back to the original after the last stop")
	assert.Zero(t, shared.Holders(), "no holders left")
}

// TestAccountingStopOrderAB stops A first, then B.
func TestAccountingStopOrderAB(t *testing.T) {
	runAccountingStopOrder(t, 0, 1)
}

// TestAccountingStopOrderBA stops B first, then A.
func TestAccountingStopOrderBA(t *testing.T) {
	runAccountingStopOrder(t, 1, 0)
}

// TestAccountingKeepsOriginalOn leaves the counters on when the host had them
// on already.
func TestAccountingKeepsOriginalOn(t *testing.T) {
	enterNewNetns(t)
	require.NoError(t, os.WriteFile(acctFile, []byte("1"), 0o644), "set the original")

	shared := NewAccounting()
	require.NoError(t, shared.Acquire(), "start")
	require.NoError(t, shared.Release(), "stop")
	assert.Equal(t, "1", readAcct(t), "counters stay at their original on")
}

// TestAccountingReleaseWithoutHolder keeps an unbalanced release a no-op.
func TestAccountingReleaseWithoutHolder(t *testing.T) {
	enterNewNetns(t)
	require.NoError(t, os.WriteFile(acctFile, []byte("0"), 0o644), "set the original")

	shared := NewAccounting()
	require.NoError(t, shared.Release(), "release without a holder")
	assert.Equal(t, "0", readAcct(t), "sysctl untouched")
	assert.Zero(t, shared.Holders(), "holder count does not go negative")
}

type stubListener struct{}

func (stubListener) Listen(chan<- nfct.Event, uint8, []netfilter.NetlinkGroup) (chan error, error) {
	return make(chan error), nil
}

func (stubListener) Close() error { return nil }

// TestConnTracksShareAccounting runs the real instances: the one that stops first must leave the
// counters on for the other, and the instance holds one reference however often it starts.
func TestConnTracksShareAccounting(t *testing.T) {
	enterNewNetns(t)
	require.NoError(t, os.WriteFile(acctFile, []byte("0"), 0o644), "set the original")

	shared := NewAccounting()
	dial := func() (listener, error) { return stubListener{}, nil }
	first := New(nil, nil, WithDialer(dial), WithAccounting(shared))
	second := New(nil, nil, WithDialer(dial), WithAccounting(shared))

	require.NoError(t, first.Start(true), "first starts")
	first.EnableAccounting()
	require.NoError(t, second.Start(true), "second starts")
	assert.Equal(t, 2, shared.Holders(), "each instance holds one reference")
	assert.Equal(t, "1", readAcct(t), "counters on while they run")

	require.NoError(t, first.Close(), "first stops")
	assert.Equal(t, "1", readAcct(t), "counters stay on for the other instance")

	require.NoError(t, second.Close(), "second stops")
	assert.Equal(t, "0", readAcct(t), "counters back to the original after the last stop")
	assert.Zero(t, shared.Holders(), "no holders left")
}
