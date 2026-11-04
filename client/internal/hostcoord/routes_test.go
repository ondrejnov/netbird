package hostcoord

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	keyC         = SessionKey{Profile: "c", Username: "alice"}
	testPrefix   = netip.MustParsePrefix("198.51.100.0/24")
	testDefault  = netip.MustParsePrefix("0.0.0.0/0")
	testDefault6 = netip.MustParsePrefix("::/0")
)

// fakeKernel is the route table behind the claims: Install replaces the route of a
// prefix, as the replace semantics of the real backend do.
type fakeKernel struct {
	mu         sync.Mutex
	routes     map[netip.Prefix]string
	failAdd    map[string]error
	failDel    map[string]error
	installLog []string
	removeLog  []string
}

func newFakeKernel() *fakeKernel {
	return &fakeKernel{
		routes:  make(map[netip.Prefix]string),
		failAdd: make(map[string]error),
		failDel: make(map[string]error),
	}
}

func (k *fakeKernel) dev(prefix netip.Prefix) string {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.routes[prefix]
}

func (k *fakeKernel) setFailAdd(dev string, err error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.failAdd[dev] = err
}

func (k *fakeKernel) setFailDel(dev string, err error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.failDel[dev] = err
}

func (k *fakeKernel) claim(prefix netip.Prefix, dev string, events *eventLog) RouteClaim {
	claim := RouteClaim{
		Dev: dev,
		Install: func() error {
			k.mu.Lock()
			defer k.mu.Unlock()
			if err := k.failAdd[dev]; err != nil {
				return err
			}
			k.routes[prefix] = dev
			k.installLog = append(k.installLog, dev)
			return nil
		},
		Remove: func() error {
			k.mu.Lock()
			defer k.mu.Unlock()
			if err := k.failDel[dev]; err != nil {
				return err
			}
			if k.routes[prefix] == dev {
				delete(k.routes, prefix)
			}
			k.removeLog = append(k.removeLog, dev)
			return nil
		},
	}
	if events != nil {
		claim.Notify = events.record
	}
	return claim
}

type eventLog struct {
	mu     sync.Mutex
	events []RouteEvent
}

func (l *eventLog) record(event RouteEvent) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, event)
}

func (l *eventLog) kinds() []RouteEventKind {
	l.mu.Lock()
	defer l.mu.Unlock()
	kinds := make([]RouteEventKind, 0, len(l.events))
	for _, event := range l.events {
		kinds = append(kinds, event.Kind)
	}
	return kinds
}

func TestRoutesOnlyOwnerInstalls(t *testing.T) {
	routes := NewRoutes()
	kernel := newFakeKernel()
	eventsB := &eventLog{}

	result, err := routes.Add(keyA, testPrefix, kernel.claim(testPrefix, "wt0", nil))
	require.NoError(t, err)
	assert.True(t, result.Installed, "the first session should own the prefix")
	assert.Equal(t, keyA, result.Owner, "the first session should be reported as the owner")

	result, err = routes.Add(keyB, testPrefix, kernel.claim(testPrefix, "wt1", eventsB))
	require.NoError(t, err)
	assert.False(t, result.Installed, "the second session should wait")
	assert.Equal(t, keyA, result.Owner, "the waiting session should learn the owner")
	assert.Equal(t, "wt0", result.OwnerDev, "the waiting session should learn the owner's device")

	assert.Equal(t, "wt0", kernel.dev(testPrefix), "the route should stay on the owner's device")
	assert.Equal(t, []string{"wt0"}, kernel.installLog, "only the owner should touch the kernel")
	assert.Equal(t, []RouteEventKind{RouteEventShadowed}, eventsB.kinds(), "the waiting session should get a warning")
}

func TestRoutesHandoverFollowsArrivalOrder(t *testing.T) {
	routes := NewRoutes()
	kernel := newFakeKernel()
	eventsB, eventsC := &eventLog{}, &eventLog{}

	_, err := routes.Add(keyA, testPrefix, kernel.claim(testPrefix, "wt0", nil))
	require.NoError(t, err)
	_, err = routes.Add(keyB, testPrefix, kernel.claim(testPrefix, "wt1", eventsB))
	require.NoError(t, err)
	_, err = routes.Add(keyC, testPrefix, kernel.claim(testPrefix, "wt2", eventsC))
	require.NoError(t, err)

	require.NoError(t, routes.Remove(keyA, testPrefix))
	assert.Equal(t, "wt1", kernel.dev(testPrefix), "the route should move to the next session in order")
	assert.Empty(t, kernel.removeLog, "the new route replaces the old one, a delete would open a gap")
	assert.Equal(t, []RouteEventKind{RouteEventShadowed, RouteEventAcquired}, eventsB.kinds(), "the next owner should be told")
	assert.Equal(t, []RouteEventKind{RouteEventShadowed}, eventsC.kinds(), "a session still waiting should get nothing new")

	require.NoError(t, routes.Remove(keyB, testPrefix))
	assert.Equal(t, "wt2", kernel.dev(testPrefix), "the route should move to the last session")

	require.NoError(t, routes.Remove(keyC, testPrefix))
	assert.Empty(t, kernel.dev(testPrefix), "the last release should remove the route")
	assert.Equal(t, []string{"wt2"}, kernel.removeLog, "only the last owner's route needs a delete")
	assert.Empty(t, routes.prefixes, "a released prefix must not stay in memory")
}

func TestRoutesRemoveWaiterChangesNothing(t *testing.T) {
	routes := NewRoutes()
	kernel := newFakeKernel()

	_, err := routes.Add(keyA, testPrefix, kernel.claim(testPrefix, "wt0", nil))
	require.NoError(t, err)
	_, err = routes.Add(keyB, testPrefix, kernel.claim(testPrefix, "wt1", nil))
	require.NoError(t, err)
	_, err = routes.Add(keyC, testPrefix, kernel.claim(testPrefix, "wt2", nil))
	require.NoError(t, err)

	require.NoError(t, routes.Remove(keyB, testPrefix))
	assert.Equal(t, "wt0", kernel.dev(testPrefix), "removing a waiter must not touch the route")
	assert.Equal(t, []string{"wt0"}, kernel.installLog, "removing a waiter must not touch the kernel")

	require.NoError(t, routes.Remove(keyA, testPrefix))
	assert.Equal(t, "wt2", kernel.dev(testPrefix), "the removed waiter must be skipped in the order")
}

func TestRoutesRemoveUnknownClaim(t *testing.T) {
	routes := NewRoutes()
	kernel := newFakeKernel()

	require.NoError(t, routes.Remove(keyA, testPrefix), "nothing claimed yet")

	_, err := routes.Add(keyA, testPrefix, kernel.claim(testPrefix, "wt0", nil))
	require.NoError(t, err)
	require.NoError(t, routes.Remove(keyB, testPrefix), "another session never claimed the prefix")
	assert.Equal(t, "wt0", kernel.dev(testPrefix), "an unknown remove must not touch the owner's route")
}

func TestRoutesRepeatedAddKeepsOneClaim(t *testing.T) {
	t.Run("owner refreshes its route", func(t *testing.T) {
		routes := NewRoutes()
		kernel := newFakeKernel()

		_, err := routes.Add(keyA, testPrefix, kernel.claim(testPrefix, "wt0", nil))
		require.NoError(t, err)
		result, err := routes.Add(keyA, testPrefix, kernel.claim(testPrefix, "wt0", nil))
		require.NoError(t, err)
		assert.True(t, result.Installed, "a repeated add of the owner should stay installed")

		require.NoError(t, routes.Remove(keyA, testPrefix))
		assert.Empty(t, kernel.dev(testPrefix), "one remove should drop the single claim")
		assert.Empty(t, routes.prefixes, "no claim should be left behind")
	})

	t.Run("waiter keeps its position", func(t *testing.T) {
		routes := NewRoutes()
		kernel := newFakeKernel()

		_, err := routes.Add(keyA, testPrefix, kernel.claim(testPrefix, "wt0", nil))
		require.NoError(t, err)
		_, err = routes.Add(keyB, testPrefix, kernel.claim(testPrefix, "wt1", nil))
		require.NoError(t, err)
		_, err = routes.Add(keyC, testPrefix, kernel.claim(testPrefix, "wt2", nil))
		require.NoError(t, err)
		_, err = routes.Add(keyB, testPrefix, kernel.claim(testPrefix, "wt1", nil))
		require.NoError(t, err)

		require.NoError(t, routes.Remove(keyA, testPrefix))
		assert.Equal(t, "wt1", kernel.dev(testPrefix), "a repeated add must not lose the place in line")

		require.NoError(t, routes.Remove(keyB, testPrefix))
		assert.Equal(t, "wt2", kernel.dev(testPrefix), "the session must be queued once")
	})
}

func TestRoutesInstallFailureLeavesNoClaim(t *testing.T) {
	routes := NewRoutes()
	kernel := newFakeKernel()
	errAdd := errors.New("add")
	kernel.setFailAdd("wt0", errAdd)

	_, err := routes.Add(keyA, testPrefix, kernel.claim(testPrefix, "wt0", nil))
	require.ErrorIs(t, err, errAdd)
	assert.Empty(t, routes.prefixes, "a failed install must not leave a claim")

	result, err := routes.Add(keyB, testPrefix, kernel.claim(testPrefix, "wt1", nil))
	require.NoError(t, err)
	assert.True(t, result.Installed, "the next session should own the free prefix")
}

func TestRoutesHandoverSkipsFailingSession(t *testing.T) {
	routes := NewRoutes()
	kernel := newFakeKernel()
	errAdd := errors.New("add")
	eventsB, eventsC := &eventLog{}, &eventLog{}

	_, err := routes.Add(keyA, testPrefix, kernel.claim(testPrefix, "wt0", nil))
	require.NoError(t, err)
	_, err = routes.Add(keyB, testPrefix, kernel.claim(testPrefix, "wt1", eventsB))
	require.NoError(t, err)
	_, err = routes.Add(keyC, testPrefix, kernel.claim(testPrefix, "wt2", eventsC))
	require.NoError(t, err)

	kernel.setFailAdd("wt1", errAdd)
	require.NoError(t, routes.Remove(keyA, testPrefix))

	assert.Equal(t, "wt2", kernel.dev(testPrefix), "the route should move past the failing session")
	assert.Equal(t, []RouteEventKind{RouteEventShadowed, RouteEventHandoverFailed}, eventsB.kinds(), "the skipped session should be told")
	assert.Equal(t, []RouteEventKind{RouteEventShadowed, RouteEventAcquired}, eventsC.kinds(), "the new owner should be told")

	kernel.setFailAdd("wt1", nil)
	require.NoError(t, routes.Remove(keyC, testPrefix))
	assert.Equal(t, "wt1", kernel.dev(testPrefix), "the skipped session should stay in line")
}

func TestRoutesHandoverWithNoWorkingSession(t *testing.T) {
	routes := NewRoutes()
	kernel := newFakeKernel()
	errAdd := errors.New("add")

	_, err := routes.Add(keyA, testPrefix, kernel.claim(testPrefix, "wt0", nil))
	require.NoError(t, err)
	_, err = routes.Add(keyB, testPrefix, kernel.claim(testPrefix, "wt1", nil))
	require.NoError(t, err)

	kernel.setFailAdd("wt1", errAdd)
	require.NoError(t, routes.Remove(keyA, testPrefix))
	assert.Empty(t, kernel.dev(testPrefix), "the route of the departing session must not stay")

	// The next add retries the session that could not take over, in order.
	kernel.setFailAdd("wt1", nil)
	result, err := routes.Add(keyC, testPrefix, kernel.claim(testPrefix, "wt2", nil))
	require.NoError(t, err)
	assert.False(t, result.Installed, "the session earlier in line should win")
	assert.Equal(t, keyB, result.Owner, "the session earlier in line should own the prefix")
	assert.Equal(t, "wt1", kernel.dev(testPrefix), "the route should use the device of the session earlier in line")
}

func TestRoutesRemoveFailure(t *testing.T) {
	errDel := errors.New("del")

	t.Run("remove keeps the claim for a retry", func(t *testing.T) {
		routes := NewRoutes()
		kernel := newFakeKernel()
		_, err := routes.Add(keyA, testPrefix, kernel.claim(testPrefix, "wt0", nil))
		require.NoError(t, err)

		kernel.setFailDel("wt0", errDel)
		require.ErrorIs(t, routes.Remove(keyA, testPrefix), errDel)
		assert.Equal(t, "wt0", kernel.dev(testPrefix), "the route is still in the table")

		kernel.setFailDel("wt0", nil)
		require.NoError(t, routes.Remove(keyA, testPrefix))
		assert.Empty(t, kernel.dev(testPrefix), "the retry should remove the route")
	})

	t.Run("session release drops the claim", func(t *testing.T) {
		routes := NewRoutes()
		kernel := newFakeKernel()
		_, err := routes.Add(keyA, testPrefix, kernel.claim(testPrefix, "wt0", nil))
		require.NoError(t, err)

		kernel.setFailDel("wt0", errDel)
		require.ErrorIs(t, routes.ReleaseSession(keyA), errDel)
		assert.Empty(t, routes.prefixes, "a stopped session must not keep blocking the prefix")

		result, err := routes.Add(keyB, testPrefix, kernel.claim(testPrefix, "wt1", nil))
		require.NoError(t, err)
		assert.True(t, result.Installed, "the next session should own the prefix")
		assert.Equal(t, "wt1", kernel.dev(testPrefix), "the install should replace the leftover route")
	})
}

func TestRoutesReleaseSessionTouchesOnlyOwnClaims(t *testing.T) {
	routes := NewRoutes()
	kernel := newFakeKernel()
	ownPrefix := netip.MustParsePrefix("198.51.100.0/25")
	sharedPrefix := netip.MustParsePrefix("198.51.100.128/25")
	waitingPrefix := netip.MustParsePrefix("203.0.113.0/25")
	otherPrefix := netip.MustParsePrefix("203.0.113.128/25")

	_, err := routes.Add(keyA, ownPrefix, kernel.claim(ownPrefix, "wt0", nil))
	require.NoError(t, err)
	_, err = routes.Add(keyA, sharedPrefix, kernel.claim(sharedPrefix, "wt0", nil))
	require.NoError(t, err)
	_, err = routes.Add(keyB, sharedPrefix, kernel.claim(sharedPrefix, "wt1", nil))
	require.NoError(t, err)
	_, err = routes.Add(keyB, waitingPrefix, kernel.claim(waitingPrefix, "wt1", nil))
	require.NoError(t, err)
	_, err = routes.Add(keyA, waitingPrefix, kernel.claim(waitingPrefix, "wt0", nil))
	require.NoError(t, err)
	_, err = routes.Add(keyB, otherPrefix, kernel.claim(otherPrefix, "wt1", nil))
	require.NoError(t, err)

	require.NoError(t, routes.ReleaseSession(keyA))

	assert.Empty(t, kernel.dev(ownPrefix), "the session's own route should go")
	assert.Equal(t, "wt1", kernel.dev(sharedPrefix), "a shared route should move to the next session")
	assert.Equal(t, "wt1", kernel.dev(waitingPrefix), "a route the session waited for should stay")
	assert.Equal(t, "wt1", kernel.dev(otherPrefix), "a route of another session should stay")

	require.NoError(t, routes.ReleaseSession(keyA), "a repeated release should change nothing")
	assert.Equal(t, "wt1", kernel.dev(otherPrefix), "a repeated release must not touch other sessions")
}

func TestRoutesExitNodeIsNotHandedOver(t *testing.T) {
	routes := NewRoutes()
	kernel := newFakeKernel()
	eventsB, eventsC := &eventLog{}, &eventLog{}

	result, err := routes.Add(keyA, testDefault, kernel.claim(testDefault, "wt0", nil))
	require.NoError(t, err)
	require.True(t, result.Installed, "the first session should own the exit node")

	result, err = routes.Add(keyB, testDefault, kernel.claim(testDefault, "wt1", eventsB))
	require.NoError(t, err)
	assert.False(t, result.Installed, "a later session must not take the default route")
	assert.Equal(t, keyA, result.Owner, "a later session should learn the exit node owner")
	assert.Equal(t, []RouteEventKind{RouteEventExitNodeHeld}, eventsB.kinds(), "a later session should get a warning")

	// The other family belongs to the same exit node, so it is held too.
	result, err = routes.Add(keyC, testDefault6, kernel.claim(testDefault6, "wt2", eventsC))
	require.NoError(t, err)
	assert.False(t, result.Installed, "the exit node owner should also hold the other family")
	assert.Empty(t, kernel.dev(testDefault6), "the other family must not be installed for another session")

	require.NoError(t, routes.Remove(keyA, testDefault))

	assert.Empty(t, kernel.dev(testDefault), "the default route must not be handed over")
	assert.Empty(t, kernel.dev(testDefault6), "the default route must not be handed over in the other family")
	assert.Equal(t, []RouteEventKind{RouteEventExitNodeHeld, RouteEventExitNodeReleased}, eventsB.kinds(), "a waiting session should learn the exit node is gone")
	assert.Equal(t, []RouteEventKind{RouteEventExitNodeHeld, RouteEventExitNodeReleased}, eventsC.kinds(), "a session waiting on the other family should learn it too")
	assert.Empty(t, routes.prefixes, "no claim should wait for an exit node that is never handed over")

	require.NoError(t, routes.Remove(keyB, testDefault), "the old waiter still removes its route")

	result, err = routes.Add(keyC, testDefault, kernel.claim(testDefault, "wt2", nil))
	require.NoError(t, err)
	assert.True(t, result.Installed, "the next request after the release should become the owner")
	assert.Equal(t, "wt2", kernel.dev(testDefault), "the new owner's device should carry the route")
}

func TestRoutesExitNodeHeldUntilOwnerDropsBothFamilies(t *testing.T) {
	routes := NewRoutes()
	kernel := newFakeKernel()
	eventsB := &eventLog{}

	_, err := routes.Add(keyA, testDefault, kernel.claim(testDefault, "wt0", nil))
	require.NoError(t, err)
	result, err := routes.Add(keyA, testDefault6, kernel.claim(testDefault6, "wt0", nil))
	require.NoError(t, err)
	assert.True(t, result.Installed, "the owner should install its other family")

	_, err = routes.Add(keyB, testDefault, kernel.claim(testDefault, "wt1", eventsB))
	require.NoError(t, err)

	require.NoError(t, routes.Remove(keyA, testDefault))
	assert.Equal(t, []RouteEventKind{RouteEventExitNodeHeld}, eventsB.kinds(), "the exit node is still held by the other family")
	result, err = routes.Add(keyC, testDefault, kernel.claim(testDefault, "wt2", nil))
	require.NoError(t, err)
	assert.False(t, result.Installed, "the exit node is still held by the other family")

	require.NoError(t, routes.ReleaseSession(keyA))
	assert.Equal(t, []RouteEventKind{RouteEventExitNodeHeld, RouteEventExitNodeReleased}, eventsB.kinds(), "the last family should release the exit node")
	assert.Empty(t, kernel.dev(testDefault6), "the owner's route should be removed")
}

func TestRoutesExitNodeRemoveFailure(t *testing.T) {
	errDel := errors.New("del")
	routes := NewRoutes()
	kernel := newFakeKernel()
	eventsB := &eventLog{}

	_, err := routes.Add(keyA, testDefault, kernel.claim(testDefault, "wt0", nil))
	require.NoError(t, err)
	_, err = routes.Add(keyB, testDefault, kernel.claim(testDefault, "wt1", eventsB))
	require.NoError(t, err)

	kernel.setFailDel("wt0", errDel)
	require.ErrorIs(t, routes.Remove(keyA, testDefault), errDel)
	assert.Equal(t, []RouteEventKind{RouteEventExitNodeHeld}, eventsB.kinds(), "the route is still there, so the exit node is still held")

	require.ErrorIs(t, routes.ReleaseSession(keyA), errDel)
	assert.Equal(t, []RouteEventKind{RouteEventExitNodeHeld, RouteEventExitNodeReleased}, eventsB.kinds(), "a stopped session must release the exit node")
	assert.Empty(t, routes.prefixes, "a stopped session must not keep blocking the exit node")
}

// blackholeClaim is an exit node claim that also holds the v6 blackhole, which has no
// device and so outlives the interface of a stopped session. The default route itself
// is left out to keep the tests on the blackhole.
func (k *fakeKernel) blackholeClaim(dev string) RouteClaim {
	return RouteClaim{
		Dev: dev,
		Install: func() error {
			k.mu.Lock()
			defer k.mu.Unlock()
			k.routes[testDefault6] = "blackhole of " + dev
			return nil
		},
		Remove: func() error {
			k.mu.Lock()
			defer k.mu.Unlock()
			if err := k.failDel[dev]; err != nil {
				return err
			}
			delete(k.routes, testDefault6)
			return nil
		},
	}
}

// A stopped owner never retries, and the blackhole does not go away with its interface,
// so the registry has to delete it or v6 stays unreachable for the sessions still running.
func TestRoutesExitNodeLeftoverIsDeletedLater(t *testing.T) {
	errDel := errors.New("del")
	const leftover = "blackhole of wt0"

	// stoppedOwner leaves the blackhole of session A behind.
	stoppedOwner := func(t *testing.T) (*Routes, *fakeKernel) {
		t.Helper()
		routes := NewRoutes()
		kernel := newFakeKernel()
		_, err := routes.Add(keyA, testDefault, kernel.blackholeClaim("wt0"))
		require.NoError(t, err)

		kernel.setFailDel("wt0", errDel)
		require.ErrorIs(t, routes.ReleaseSession(keyA), errDel)
		require.Equal(t, leftover, kernel.dev(testDefault6), "the failed delete should leave the blackhole")
		kernel.setFailDel("wt0", nil)
		return routes, kernel
	}

	t.Run("by the stop of another session", func(t *testing.T) {
		routes, kernel := stoppedOwner(t)
		_, err := routes.Add(keyB, testPrefix, kernel.claim(testPrefix, "wt1", nil))
		require.NoError(t, err)

		require.NoError(t, routes.ReleaseSession(keyB))
		assert.Empty(t, kernel.dev(testDefault6), "the blackhole should be gone")
		assert.Empty(t, routes.leftovers, "a deleted leftover must not stay in memory")
	})

	t.Run("by the next claim of the exit node", func(t *testing.T) {
		routes, kernel := stoppedOwner(t)
		var seenAtInstall string
		claim := kernel.claim(testDefault, "wt1", nil)
		install := claim.Install
		claim.Install = func() error {
			seenAtInstall = kernel.dev(testDefault6)
			return install()
		}

		_, err := routes.Add(keyB, testDefault, claim)
		require.NoError(t, err)
		assert.Empty(t, seenAtInstall, "a new owner without a blackhole must not inherit the old one")
		assert.Empty(t, routes.leftovers, "a deleted leftover must not stay in memory")
	})

	t.Run("by the removal of an exit node claim", func(t *testing.T) {
		routes, kernel := stoppedOwner(t)
		require.NoError(t, routes.Remove(keyB, testDefault))
		assert.Empty(t, kernel.dev(testDefault6), "the blackhole should be gone")
	})

	t.Run("by an explicit retry that reports failure", func(t *testing.T) {
		routes, kernel := stoppedOwner(t)

		kernel.setFailDel("wt0", errDel)
		require.ErrorIs(t, routes.RetryHandovers(), errDel)
		assert.Equal(t, leftover, kernel.dev(testDefault6), "the blackhole is still in the table")

		kernel.setFailDel("wt0", nil)
		require.NoError(t, routes.RetryHandovers())
		assert.Empty(t, kernel.dev(testDefault6), "the retry should delete the blackhole")
		require.NoError(t, routes.RetryHandovers(), "nothing is left to retry")
	})

	t.Run("never under a new owner", func(t *testing.T) {
		routes, kernel := stoppedOwner(t)

		// The kernel keeps refusing while session B takes over the exit node, whose
		// blackhole replaces the leftover. Deleting the leftover now would delete it.
		kernel.setFailDel("wt0", errDel)
		_, err := routes.Add(keyB, testDefault, kernel.blackholeClaim("wt1"))
		require.NoError(t, err, "a leftover must not block the exit node")
		require.Equal(t, "blackhole of wt1", kernel.dev(testDefault6), "the new owner should hold the blackhole")

		kernel.setFailDel("wt0", nil)
		require.NoError(t, routes.RetryHandovers())
		_, err = routes.Add(keyC, testPrefix, kernel.claim(testPrefix, "wt2", nil))
		require.NoError(t, err)
		require.NoError(t, routes.ReleaseSession(keyC))
		assert.Equal(t, "blackhole of wt1", kernel.dev(testDefault6), "the leftover must not take the blackhole of the owner")

		require.NoError(t, routes.Remove(keyB, testDefault))
		assert.Empty(t, kernel.dev(testDefault6), "the owner should remove its blackhole")
		assert.Empty(t, routes.leftovers, "a free exit node should settle the leftover")
	})
}

// The refcounter of a waiting session never adds again, so its route must come back
// without another Add.
func TestRoutesRetryHandovers(t *testing.T) {
	errAdd := errors.New("add")

	// failedHandover leaves the prefix without a route and sessions B and C in line.
	failedHandover := func(t *testing.T) (*Routes, *fakeKernel, *eventLog, *eventLog) {
		t.Helper()
		routes := NewRoutes()
		kernel := newFakeKernel()
		eventsB, eventsC := &eventLog{}, &eventLog{}

		_, err := routes.Add(keyA, testPrefix, kernel.claim(testPrefix, "wt0", nil))
		require.NoError(t, err)
		_, err = routes.Add(keyB, testPrefix, kernel.claim(testPrefix, "wt1", eventsB))
		require.NoError(t, err)
		_, err = routes.Add(keyC, testPrefix, kernel.claim(testPrefix, "wt2", eventsC))
		require.NoError(t, err)

		kernel.setFailAdd("wt1", errAdd)
		kernel.setFailAdd("wt2", errAdd)
		require.NoError(t, routes.Remove(keyA, testPrefix))
		require.Empty(t, kernel.dev(testPrefix), "no session could take over")
		return routes, kernel, eventsB, eventsC
	}

	t.Run("recovers in order without an add", func(t *testing.T) {
		routes, kernel, eventsB, eventsC := failedHandover(t)
		kernel.setFailAdd("wt1", nil)
		kernel.setFailAdd("wt2", nil)

		require.NoError(t, routes.RetryHandovers())
		assert.Equal(t, "wt1", kernel.dev(testPrefix), "the session first in line should carry the route")
		assert.Equal(t,
			[]RouteEventKind{RouteEventShadowed, RouteEventHandoverFailed, RouteEventAcquired},
			eventsB.kinds(), "the new owner should be told")
		assert.Equal(t,
			[]RouteEventKind{RouteEventShadowed, RouteEventHandoverFailed},
			eventsC.kinds(), "a session still waiting should get nothing new")

		require.NoError(t, routes.Remove(keyB, testPrefix))
		assert.Equal(t, "wt2", kernel.dev(testPrefix), "the line should carry on after the retry")
	})

	t.Run("still failing keeps the line and reports no event", func(t *testing.T) {
		routes, kernel, eventsB, _ := failedHandover(t)

		require.ErrorIs(t, routes.RetryHandovers(), errAdd)
		assert.Equal(t,
			[]RouteEventKind{RouteEventShadowed, RouteEventHandoverFailed},
			eventsB.kinds(), "a handler of the event calls the retry, a new event would loop")

		kernel.setFailAdd("wt1", nil)
		require.NoError(t, routes.RetryHandovers())
		assert.Equal(t, "wt1", kernel.dev(testPrefix), "the session should still be first in line")
	})

	t.Run("a working session later in line is enough", func(t *testing.T) {
		routes, kernel, _, eventsC := failedHandover(t)
		kernel.setFailAdd("wt2", nil)

		require.NoError(t, routes.RetryHandovers(), "the prefix has a route again")
		assert.Equal(t, "wt2", kernel.dev(testPrefix), "the route should move past the failing session")
		assert.Equal(t,
			[]RouteEventKind{RouteEventShadowed, RouteEventHandoverFailed, RouteEventAcquired},
			eventsC.kinds(), "the new owner should be told")
	})

	t.Run("a waiter leaving retries the rest of the line", func(t *testing.T) {
		routes, kernel, _, eventsC := failedHandover(t)
		kernel.setFailAdd("wt2", nil)

		require.NoError(t, routes.Remove(keyB, testPrefix))
		assert.Equal(t, "wt2", kernel.dev(testPrefix), "the next operation on the prefix should retry")
		assert.Equal(t,
			[]RouteEventKind{RouteEventShadowed, RouteEventHandoverFailed, RouteEventAcquired},
			eventsC.kinds(), "the new owner should be told")
	})

	t.Run("a waiter stopping retries the rest of the line", func(t *testing.T) {
		routes, kernel, _, _ := failedHandover(t)
		kernel.setFailAdd("wt2", nil)

		require.NoError(t, routes.ReleaseSession(keyB))
		assert.Equal(t, "wt2", kernel.dev(testPrefix), "the next operation on the prefix should retry")
	})

	t.Run("the last waiter leaving forgets the prefix", func(t *testing.T) {
		routes, kernel, _, _ := failedHandover(t)

		require.NoError(t, routes.Remove(keyB, testPrefix))
		require.NoError(t, routes.Remove(keyC, testPrefix))
		assert.Empty(t, kernel.dev(testPrefix), "no session carries the prefix")
		assert.Empty(t, routes.prefixes, "a released prefix must not stay in memory")
	})

	t.Run("may be called from the failure event", func(t *testing.T) {
		routes := NewRoutes()
		kernel := newFakeKernel()
		var retryErr error
		retried := 0

		_, err := routes.Add(keyA, testPrefix, kernel.claim(testPrefix, "wt0", nil))
		require.NoError(t, err)
		claim := kernel.claim(testPrefix, "wt1", nil)
		claim.Notify = func(event RouteEvent) {
			if event.Kind == RouteEventHandoverFailed {
				retried++
				retryErr = routes.RetryHandovers()
			}
		}
		_, err = routes.Add(keyB, testPrefix, claim)
		require.NoError(t, err)

		kernel.setFailAdd("wt1", errAdd)
		require.NoError(t, routes.Remove(keyA, testPrefix))
		assert.Equal(t, 1, retried, "a failing retry must not raise the event again")
		assert.ErrorIs(t, retryErr, errAdd, "the retry should report the failure")
	})
}

// R4: a free default prefix stays free however often the retry runs.
func TestRoutesRetryDoesNotHandOverExitNode(t *testing.T) {
	routes := NewRoutes()
	kernel := newFakeKernel()

	_, err := routes.Add(keyA, testDefault6, kernel.claim(testDefault6, "wt0", nil))
	require.NoError(t, err)
	_, err = routes.Add(keyB, testDefault, kernel.claim(testDefault, "wt1", nil))
	require.NoError(t, err)
	_, err = routes.Add(keyC, testDefault, kernel.claim(testDefault, "wt2", nil))
	require.NoError(t, err)

	// The v4 default has waiters and no owner of its own while A holds the exit node.
	require.NoError(t, routes.RetryHandovers())
	assert.Empty(t, kernel.dev(testDefault), "the retry must not install a held exit node")

	require.NoError(t, routes.Remove(keyC, testDefault))
	assert.Empty(t, kernel.dev(testDefault), "a waiter leaving must not hand over the exit node")

	require.NoError(t, routes.Remove(keyA, testDefault6))
	require.NoError(t, routes.RetryHandovers())
	assert.Empty(t, kernel.dev(testDefault), "the exit node is not handed over after its owner left")
	assert.Empty(t, routes.prefixes, "the waiters should be gone with the exit node")
}

func TestRoutesRejectInvalidClaims(t *testing.T) {
	kernel := newFakeKernel()

	devs := map[string]string{
		"empty":       "",
		"too long":    strings.Repeat("w", maxInterfaceNameLen+1),
		"slash":       "wt/0",
		"colon":       "wt:0",
		"whitespace":  "wt 0",
		"current dir": ".",
		"parent dir":  "..",
	}
	for name, dev := range devs {
		t.Run(name, func(t *testing.T) {
			routes := NewRoutes()
			_, err := routes.Add(keyA, testPrefix, kernel.claim(testPrefix, dev, nil))
			require.ErrorIs(t, err, ErrInvalidRouteDev)
			assert.Empty(t, routes.prefixes, "a rejected claim must not be stored")
		})
	}

	t.Run("longest name is kept whole", func(t *testing.T) {
		routes := NewRoutes()
		dev := "wt" + strings.Repeat("1", maxInterfaceNameLen-2)
		result, err := routes.Add(keyA, testPrefix, kernel.claim(testPrefix, dev, nil))
		require.NoError(t, err)
		assert.Equal(t, dev, result.OwnerDev, "the name must not be cut")
		assert.Equal(t, dev, kernel.dev(testPrefix), "the name must not be cut")
	})

	t.Run("invalid prefix", func(t *testing.T) {
		_, err := NewRoutes().Add(keyA, netip.Prefix{}, kernel.claim(testPrefix, "wt0", nil))
		require.Error(t, err)
	})

	t.Run("missing backend", func(t *testing.T) {
		_, err := NewRoutes().Add(keyA, testPrefix, RouteClaim{Dev: "wt0"})
		require.Error(t, err)
	})
}

// The kernel keeps one route per masked prefix, so the claims have to use the same
// identity or two sessions would both believe they own the route.
func TestRoutesNormalizePrefix(t *testing.T) {
	routes := NewRoutes()
	kernel := newFakeKernel()

	_, err := routes.Add(keyA, netip.MustParsePrefix("198.51.100.7/24"), kernel.claim(testPrefix, "wt0", nil))
	require.NoError(t, err)

	result, err := routes.Add(keyB, testPrefix, kernel.claim(testPrefix, "wt1", nil))
	require.NoError(t, err)
	assert.False(t, result.Installed, "an unmasked prefix should identify the same route")

	result, err = routes.Add(keyC, netip.MustParsePrefix("::ffff:198.51.100.0/120"), kernel.claim(testPrefix, "wt2", nil))
	require.NoError(t, err)
	assert.False(t, result.Installed, "a v4-mapped prefix should identify the same route")

	require.NoError(t, routes.Remove(keyA, testPrefix))
	assert.Equal(t, "wt1", kernel.dev(testPrefix), "the removal should find the claim under the masked prefix")
}

// Notify runs outside the lock, so a session may react by changing its own routes.
func TestRoutesNotifyMayCallBack(t *testing.T) {
	routes := NewRoutes()
	kernel := newFakeKernel()

	_, err := routes.Add(keyA, testPrefix, kernel.claim(testPrefix, "wt0", nil))
	require.NoError(t, err)

	claim := kernel.claim(testPrefix, "wt1", nil)
	claim.Notify = func(event RouteEvent) {
		if event.Kind == RouteEventAcquired {
			assert.NoError(t, routes.Remove(event.Session, event.Prefix))
		}
	}
	_, err = routes.Add(keyB, testPrefix, claim)
	require.NoError(t, err)

	require.NoError(t, routes.Remove(keyA, testPrefix))
	assert.Empty(t, kernel.dev(testPrefix), "the callback should have released the route")
}

func TestRoutesConcurrentClaims(t *testing.T) {
	routes := NewRoutes()
	kernel := newFakeKernel()
	keys := []SessionKey{keyA, keyB, keyC}
	prefixes := []netip.Prefix{testPrefix, netip.MustParsePrefix("203.0.113.0/24"), testDefault, testDefault6}

	var wg sync.WaitGroup
	for i, key := range keys {
		wg.Add(1)
		go func(key SessionKey, dev string) {
			defer wg.Done()
			for range 200 {
				for _, prefix := range prefixes {
					_, err := routes.Add(key, prefix, kernel.claim(prefix, dev, nil))
					assert.NoError(t, err)
				}
				for _, prefix := range prefixes {
					assert.NoError(t, routes.Remove(key, prefix))
				}
			}
		}(key, fmt.Sprintf("wt%d", i))
	}
	wg.Wait()

	assert.Empty(t, routes.prefixes, "every claim should be gone after all sessions released")
	for _, prefix := range prefixes {
		assert.Empty(t, kernel.dev(prefix), "no route should stay without a claim")
	}
}
