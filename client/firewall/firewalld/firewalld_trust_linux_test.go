//go:build linux

package firewalld

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeFirewallCmd puts a firewall-cmd on the PATH that answers as a running firewalld and records
// what it was asked. action runs before an interface is recorded.
func fakeFirewallCmd(t *testing.T, action string) string {
	t.Helper()
	if conn, err := dbus.SystemBus(); err == nil {
		_ = conn
		t.Skip("a system bus is available, the calls would reach the real firewalld")
	}

	dir := t.TempDir()
	calls := filepath.Join(dir, "calls")
	script := "#!/bin/sh\n" +
		"[ \"$1\" = \"--state\" ] && exit 0\n" +
		action + "\n" +
		"echo \"$2\" >> " + calls + "\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "firewall-cmd"), []byte(script), 0o755))
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return calls
}

func calledFor(t *testing.T, calls, iface string) bool {
	t.Helper()
	raw, err := os.ReadFile(calls)
	if os.IsNotExist(err) {
		return false
	}
	require.NoError(t, err)
	return strings.Contains(string(raw), "--change-interface="+iface)
}

// Each session passes its own context: the one that ended does nothing, and the other is not
// affected by that, which one parent for the process could not offer.
func TestTrustInterface_FollowsTheContextOfTheCaller(t *testing.T) {
	calls := fakeFirewallCmd(t, "")

	ended, cancel := context.WithCancel(context.Background())
	cancel()
	assert.NoError(t, TrustInterface(ended, "wt0"), "firewalld going unasked is no error")
	assert.False(t, calledFor(t, calls, "wt0"), "a session that ended must not trust its interface")

	assert.NoError(t, TrustInterface(context.Background(), "wt1"))
	assert.True(t, calledFor(t, calls, "wt1"), "the other session is not affected")
}

// A firewalld that does not answer holds up only the session that asked, until its context ends.
func TestTrustInterface_CancelEndsTheCallInFlight(t *testing.T) {
	calls := fakeFirewallCmd(t, "exec sleep 30")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- TrustInterface(ctx, "wt0") }()

	time.Sleep(200 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		assert.Error(t, err, "a call cut short did not trust the interface")
		assert.Less(t, time.Since(start), 2*time.Second, "the call should end with the context, ahead of its own timeout")
	case <-time.After(10 * time.Second):
		require.FailNow(t, "the call should end with the context")
	}
	assert.False(t, calledFor(t, calls, "wt0"), "the call was cut short")
}
