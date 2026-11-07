//go:build privileged && linux && !android

package hostcoord

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func enterLinksNetns(t *testing.T) {
	t.Helper()
	// The thread stays locked and ends with the test, taking the namespace with it.
	runtime.LockOSThread()
	require.NoError(t, unix.Unshare(unix.CLONE_NEWNET), "enter a network namespace")
}

func addWireguardLink(t *testing.T, name string) {
	t.Helper()
	err := netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: name}})
	if err != nil {
		t.Skipf("kernel WireGuard is not available: %v", err)
	}
}

func linkExists(t *testing.T, name string) bool {
	t.Helper()
	_, err := netlink.LinkByName(name)
	if err == nil {
		return true
	}
	var notFound netlink.LinkNotFoundError
	require.ErrorAs(t, err, &notFound)
	return false
}

// Only a WireGuard link with the name of a stored slot is ours. A dummy on the name of a slot and a
// WireGuard link on a name no slot has belong to someone else, as does a link no record names.
func TestRemoveSessionLinksOnlyTakesStoredWireguardLinks(t *testing.T) {
	enterLinksNetns(t)

	addWireguardLink(t, "wt0")
	addWireguardLink(t, "wt1")
	addWireguardLink(t, "wt5")
	addWireguardLink(t, "wg0")
	require.NoError(t, netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "wt2"}}))

	records := []SlotRecord{
		{Slot: 0, Desired: DesiredUp},
		{Slot: 1, Desired: DesiredDown},
		{Slot: 2, Desired: DesiredUp},
		{Slot: 3, Desired: DesiredUp},
	}
	require.Error(t, VerifyNoSessionLinks(records), "the links of slots 0 and 1 are there")

	require.NoError(t, RemoveSessionLinks(records))

	assert.False(t, linkExists(t, "wt0"), "the link of an up session should be gone")
	assert.False(t, linkExists(t, "wt1"), "the link of a down session should be gone too, the file does not say what ran")
	assert.True(t, linkExists(t, "wt2"), "a dummy on the name of a slot is not ours")
	assert.True(t, linkExists(t, "wt5"), "no record names this link")
	assert.True(t, linkExists(t, "wg0"), "no slot has this name")
	assert.NoError(t, VerifyNoSessionLinks(records), "what stays cannot be a session link")
}

func TestRemoveSessionLinksWithoutRecordsTouchesNothing(t *testing.T) {
	enterLinksNetns(t)

	addWireguardLink(t, "wt0")

	require.NoError(t, RemoveSessionLinks(nil))
	assert.NoError(t, VerifyNoSessionLinks(nil))
	assert.True(t, linkExists(t, "wt0"), "no sessions file means no daemon with the gate ever ran here")
}

// A session deletes whatever has the name of its interface when it comes up. Only what a session
// would have left there may go.
func TestRefuseForeignLink(t *testing.T) {
	enterLinksNetns(t)

	assert.NoError(t, RefuseForeignLink(t.Context(), "wt0", 0), "a free name")

	require.NoError(t, netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "wt1"}}))
	assert.ErrorIs(t, RefuseForeignLink(t.Context(), "wt1", 0), ErrForeignLink, "a link that is no interface of a session")
	assert.True(t, linkExists(t, "wt1"), "the check must leave the link")

	addWireguardLink(t, "wt2")
	assert.NoError(t, RefuseForeignLink(t.Context(), "wt2", 0), "what a session of a previous attempt can leave")
}

// addClosingTun creates the TUN of a session that is closing: it goes away with its descriptors.
func addClosingTun(t *testing.T, name string) (closeTun func()) {
	t.Helper()
	tun := &netlink.Tuntap{
		LinkAttrs:  netlink.LinkAttrs{Name: name},
		Mode:       netlink.TUNTAP_MODE_TUN,
		Flags:      netlink.TUNTAP_DEFAULTS | netlink.TUNTAP_NO_PI,
		NonPersist: true,
		Queues:     1,
	}
	require.NoError(t, netlink.LinkAdd(tun))
	return func() {
		for _, fd := range tun.Fds {
			assert.NoError(t, fd.Close())
		}
	}
}

// addForeignTun creates a TUN something else on the host keeps.
func addForeignTun(t *testing.T, name string) {
	t.Helper()
	tun := &netlink.Tuntap{
		LinkAttrs: netlink.LinkAttrs{Name: name},
		Mode:      netlink.TUNTAP_MODE_TUN,
		Flags:     netlink.TUNTAP_DEFAULTS | netlink.TUNTAP_NO_PI,
	}
	require.NoError(t, netlink.LinkAdd(tun))
	link, err := netlink.LinkByName(name)
	require.NoError(t, err)
	require.Equal(t, tunLinkType, link.Type(), "the kernel should report the TUN as the code expects it")
}

// The TUN of the previous attempt of a session can outlive the attempt for a moment. It goes away by
// itself, and the session must not be taken down for it.
func TestRefuseForeignLinkWaitsForAClosingTun(t *testing.T) {
	enterLinksNetns(t)

	closeTun := addClosingTun(t, "wt0")
	timer := time.AfterFunc(200*time.Millisecond, closeTun)
	t.Cleanup(func() { timer.Stop() })

	assert.NoError(t, RefuseForeignLink(t.Context(), "wt0", 0), "a TUN that goes away is what a previous attempt leaves")
	assert.False(t, linkExists(t, "wt0"), "the check should have seen the TUN go")
}

// A TUN that does not go away is someone else's. It is refused, and it stays.
func TestRefuseForeignLinkKeepsATunThatStays(t *testing.T) {
	enterLinksNetns(t)

	addForeignTun(t, "wt0")
	before, err := netlink.LinkByName("wt0")
	require.NoError(t, err)

	started := time.Now()
	assert.ErrorIs(t, RefuseForeignLink(t.Context(), "wt0", 0), ErrForeignLink)
	assert.GreaterOrEqual(t, time.Since(started), closingTunWait, "the TUN should have had its time to go away")

	after, err := netlink.LinkByName("wt0")
	require.NoError(t, err, "the TUN must not be deleted")
	assert.Equal(t, before.Attrs().Index, after.Attrs().Index, "the TUN must be the same one")
}

// A session going down must not wait for an interface.
func TestRefuseForeignLinkStopsWaitingWithItsContext(t *testing.T) {
	enterLinksNetns(t)

	addForeignTun(t, "wt0")
	ctx, cancel := context.WithCancel(t.Context())
	timer := time.AfterFunc(100*time.Millisecond, cancel)
	t.Cleanup(func() { timer.Stop(); cancel() })

	started := time.Now()
	err := RefuseForeignLink(ctx, "wt0", 0)
	assert.ErrorIs(t, err, context.Canceled)
	assert.NotErrorIs(t, err, ErrForeignLink, "nothing is known about the link yet")
	assert.Less(t, time.Since(started), closingTunWait, "the wait should end with the context")
	assert.True(t, linkExists(t, "wt0"), "the TUN must not be deleted")
}
