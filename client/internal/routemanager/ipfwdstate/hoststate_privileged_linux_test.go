//go:build privileged && linux && !android

package ipfwdstate

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	v4ForwardingFile = "/proc/sys/net/ipv4/ip_forward"
	v6ForwardingFile = "/proc/sys/net/ipv6/conf/all/forwarding"
	acceptRAFileFmt  = "/proc/sys/net/ipv6/conf/%s/accept_ra"
)

// enterNewNetns moves the test goroutine into a fresh network namespace so the
// sysctls it flips never touch the namespace the test binary was started in. The
// thread stays locked and ends with the goroutine, taking the namespace with it.
func enterNewNetns(t *testing.T) {
	t.Helper()
	runtime.LockOSThread()
	require.NoError(t, unix.Unshare(unix.CLONE_NEWNET), "unshare network namespace")
}

func readSysctlFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err, "read %s", path)
	return strings.TrimSpace(string(raw))
}

func writeSysctlFile(t *testing.T, path, value string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte(value), 0o644), "write %s", path)
}

func addDummy(t *testing.T, name string) {
	t.Helper()
	require.NoError(t, netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}), "add %s", name)
}

// hostFixture is a namespace in which the host sysctls and the interfaces of two
// sessions and of one host interface are at known original values.
type hostFixture struct {
	ifaceA, ifaceB, hostIface string
}

func newHostFixture(t *testing.T) hostFixture {
	t.Helper()
	enterNewNetns(t)

	f := hostFixture{ifaceA: "wt-a", ifaceB: "wt-b", hostIface: "eth-host"}
	for _, name := range []string{f.ifaceA, f.ifaceB, f.hostIface} {
		addDummy(t, name)
		writeSysctlFile(t, fmt.Sprintf(acceptRAFileFmt, name), "1")
	}
	writeSysctlFile(t, fmt.Sprintf(acceptRAFileFmt, "default"), "1")
	writeSysctlFile(t, v4ForwardingFile, "0")
	writeSysctlFile(t, v6ForwardingFile, "0")
	return f
}

func (f hostFixture) assertOriginal(t *testing.T, msg string) {
	t.Helper()
	assert.Equal(t, "0", readSysctlFile(t, v4ForwardingFile), "%s: ip_forward back to the original", msg)
	assert.Equal(t, "0", readSysctlFile(t, v6ForwardingFile), "%s: v6 forwarding back to the original", msg)
	for _, name := range []string{f.ifaceA, f.ifaceB, f.hostIface, "default"} {
		assert.Equal(t, "1", readSysctlFile(t, fmt.Sprintf(acceptRAFileFmt, name)), "%s: accept_ra of %s back to the original", msg, name)
	}
}

func (f hostFixture) assertForwarding(t *testing.T, msg string) {
	t.Helper()
	assert.Equal(t, "1", readSysctlFile(t, v4ForwardingFile), "%s: ip_forward still on", msg)
	assert.Equal(t, "1", readSysctlFile(t, v6ForwardingFile), "%s: v6 forwarding still on", msg)
}

func sharedPair(f hostFixture) (a, b *IPForwardingState) {
	host := NewHostState()
	return NewIPForwardingState(f.ifaceA, WithHostState(host)), NewIPForwardingState(f.ifaceB, WithHostState(host))
}

func runStopOrder(t *testing.T, firstStop, secondStop string) {
	f := newHostFixture(t)
	a, b := sharedPair(f)
	sessions := map[string]*IPForwardingState{"A": a, "B": b}

	require.NoError(t, a.RequestRouting(true), "A requests routing")
	require.NoError(t, b.RequestRouting(true), "B requests routing")
	f.assertForwarding(t, "both running")
	v4, v6 := a.Counts()
	assert.Equal(t, 2, v4, "both sessions hold a v4 reference")
	assert.Equal(t, 2, v6, "both sessions hold a v6 reference")

	// The host interface is bumped so RA-installed defaults survive, the
	// interfaces of both sessions are not, whichever session enabled first.
	assert.Equal(t, "2", readSysctlFile(t, fmt.Sprintf(acceptRAFileFmt, f.hostIface)), "host interface keeps accepting RAs")
	assert.Equal(t, "1", readSysctlFile(t, fmt.Sprintf(acceptRAFileFmt, f.ifaceA)), "session A interface is left alone")
	assert.Equal(t, "1", readSysctlFile(t, fmt.Sprintf(acceptRAFileFmt, f.ifaceB)), "session B interface is left alone")

	require.NoError(t, sessions[firstStop].ReleaseRouting(), "first stop")
	f.assertForwarding(t, "after "+firstStop+" stopped")
	assert.Equal(t, "2", readSysctlFile(t, fmt.Sprintf(acceptRAFileFmt, f.hostIface)), "host interface still bumped while a session runs")

	require.NoError(t, sessions[secondStop].ReleaseRouting(), "second stop")
	f.assertOriginal(t, "after both stopped")
	v4, v6 = a.Counts()
	assert.Zero(t, v4, "v4 references released")
	assert.Zero(t, v6, "v6 references released")
}

// TestSharedHostStateStopOrderAB stops A first, then B.
func TestSharedHostStateStopOrderAB(t *testing.T) {
	runStopOrder(t, "A", "B")
}

// TestSharedHostStateStopOrderBA stops B first, then A.
func TestSharedHostStateStopOrderBA(t *testing.T) {
	runStopOrder(t, "B", "A")
}

// TestSharedHostStateKeepsFirstOriginal starts B after A with ip_forward
// already flipped by A. B must not take that flipped value as its original.
func TestSharedHostStateKeepsFirstOriginal(t *testing.T) {
	f := newHostFixture(t)
	a, b := sharedPair(f)

	require.NoError(t, a.RequestRouting(true), "A requests routing")
	require.NoError(t, b.RequestRouting(false), "B requests v4 routing")
	require.NoError(t, a.ReleaseRouting(), "A stops")
	assert.Equal(t, "1", readSysctlFile(t, v4ForwardingFile), "ip_forward stays on for B")
	assert.Equal(t, "0", readSysctlFile(t, v6ForwardingFile), "v6 forwarding goes off with its last holder")

	require.NoError(t, b.ReleaseRouting(), "B stops")
	f.assertOriginal(t, "after both stopped")
}

// TestSharedHostStateLateSession attaches B after A has already enabled v6
// forwarding with B's interface present. B's accept_ra must be put back, and
// stay out of the restore at the end.
func TestSharedHostStateLateSession(t *testing.T) {
	f := newHostFixture(t)
	host := NewHostState()
	a := NewIPForwardingState(f.ifaceA, WithHostState(host))

	require.NoError(t, a.RequestRouting(true), "A requests routing")
	assert.Equal(t, "2", readSysctlFile(t, fmt.Sprintf(acceptRAFileFmt, f.ifaceB)), "B interface is bumped while nobody excludes it")

	b := NewIPForwardingState(f.ifaceB, WithHostState(host))
	assert.Equal(t, "1", readSysctlFile(t, fmt.Sprintf(acceptRAFileFmt, f.ifaceB)), "attaching B puts its accept_ra back")

	// B's interface goes away before the last stop, which must not fail.
	link, err := netlink.LinkByName(f.ifaceB)
	require.NoError(t, err)
	require.NoError(t, netlink.LinkDel(link))

	require.NoError(t, b.RequestRouting(true), "B requests routing")
	require.NoError(t, a.ReleaseRouting(), "A stops")
	require.NoError(t, b.ReleaseRouting(), "B stops without an error for its removed interface")
	assert.Equal(t, "0", readSysctlFile(t, v4ForwardingFile), "ip_forward back to the original")
	assert.Equal(t, "0", readSysctlFile(t, v6ForwardingFile), "v6 forwarding back to the original")
	assert.Equal(t, "1", readSysctlFile(t, fmt.Sprintf(acceptRAFileFmt, f.hostIface)), "host interface back to the original")
}

// TestSharedHostStateClose checks that Close releases the held references, that
// it is idempotent, and that a closed instance refuses further requests.
func TestSharedHostStateClose(t *testing.T) {
	f := newHostFixture(t)
	a, b := sharedPair(f)

	require.NoError(t, a.RequestRouting(true), "A requests routing")
	require.NoError(t, b.RequestRouting(true), "B requests routing")
	require.NoError(t, a.Close(), "close A")
	require.NoError(t, a.Close(), "close A again")
	f.assertForwarding(t, "B still running")
	assert.Error(t, a.RequestRouting(true), "closed instance refuses a request")

	require.NoError(t, b.Close(), "close B")
	f.assertOriginal(t, "after both closed")
}

// TestSharedHostStateKeepsOriginalOn keeps ip_forward on when the host already
// had it on, as there is nothing to restore.
func TestSharedHostStateKeepsOriginalOn(t *testing.T) {
	f := newHostFixture(t)
	writeSysctlFile(t, v4ForwardingFile, "1")
	a, _ := sharedPair(f)

	require.NoError(t, a.RequestRouting(false), "A requests routing")
	require.NoError(t, a.ReleaseRouting(), "A stops")
	assert.Equal(t, "1", readSysctlFile(t, v4ForwardingFile), "ip_forward stays at its original on")
}

// TestUnsharedStateKeepsTodaysBehavior covers instances without a HostState:
// private refcounts, and ip_forward is not restored.
func TestUnsharedStateKeepsTodaysBehavior(t *testing.T) {
	f := newHostFixture(t)
	a := NewIPForwardingState(f.ifaceA)
	b := NewIPForwardingState(f.ifaceB)

	require.NoError(t, a.RequestRouting(false), "A requests routing")
	v4, _ := b.Counts()
	assert.Zero(t, v4, "refcounts are private to the instance")
	require.NoError(t, b.RequestRouting(false), "B requests routing")
	require.NoError(t, a.ReleaseRouting(), "A stops")
	require.NoError(t, b.ReleaseRouting(), "B stops")
	assert.Equal(t, "1", readSysctlFile(t, v4ForwardingFile), "ip_forward is not restored without a shared state")
}
