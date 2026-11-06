//go:build privileged

package nftables

import (
	"os"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/stretchr/testify/require"
)

// TestExternalChainMonitorRootIntegration verifies that adding a new chain
// in an external (non-netbird) filter table triggers the reconciler.
// Requires CAP_NET_ADMIN; skip otherwise.
func TestExternalChainMonitorRootIntegration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root required")
	}

	calls := make(chan struct{}, 8)
	var count atomic.Int32
	rec := &countingReconciler{calls: calls, count: &count}

	m := newExternalChainMonitor(rec)
	m.start()
	t.Cleanup(m.stop)

	// Give the netlink subscription a moment to register.
	time.Sleep(200 * time.Millisecond)

	conn := &nftables.Conn{}
	table := conn.AddTable(&nftables.Table{
		Name:   "nbmon_integration_test",
		Family: nftables.TableFamilyINet,
	})
	t.Cleanup(func() {
		cleanup := &nftables.Conn{}
		cleanup.DelTable(table)
		_ = cleanup.Flush()
	})

	chain := conn.AddChain(&nftables.Chain{
		Name:     "filter_INPUT",
		Table:    table,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
		Type:     nftables.ChainTypeFilter,
	})
	_ = chain
	require.NoError(t, conn.Flush(), "create external test chain")

	select {
	case <-calls:
		// success
	case <-time.After(3 * time.Second):
		t.Fatalf("reconcile was not invoked after creating an external chain")
	}
	require.GreaterOrEqual(t, count.Load(), int32(1))
}

type countingReconciler struct {
	calls chan struct{}
	count *atomic.Int32
}

func (c *countingReconciler) reconcileExternalChains() error {
	c.count.Add(1)
	select {
	case c.calls <- struct{}{}:
	default:
	}
	return nil
}

// The library hands over events on an unbuffered channel. A monitor that stops with events on their
// way, which is what a session sees when other sessions come and go, must not leave its goroutines
// waiting for a reader that is gone.
func TestExternalChainMonitorStopLeavesNoGoroutines(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root required")
	}
	const rounds = 20

	m := newExternalChainMonitor(&countingReconciler{calls: make(chan struct{}, 1), count: &atomic.Int32{}})
	before := runtime.NumGoroutine()
	for range rounds {
		_, closeMonitor, err := m.subscribe()
		require.NoError(t, err)

		conn := &nftables.Conn{}
		table := conn.AddTable(&nftables.Table{Name: "nbmon_stop_test", Family: nftables.TableFamilyINet})
		require.NoError(t, conn.Flush(), "create a table")
		conn.DelTable(table)
		require.NoError(t, conn.Flush(), "delete the table")

		// The events have reached the monitor before it stops.
		time.Sleep(20 * time.Millisecond)
		closeMonitor()
	}

	require.Eventuallyf(t, func() bool {
		return runtime.NumGoroutine() <= before+1
	}, 5*time.Second, 50*time.Millisecond, "%d stopped monitors should leave no goroutines, %d before", rounds, before)
}
