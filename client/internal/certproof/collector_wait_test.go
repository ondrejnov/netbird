package certproof

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/management/certposture"
	"github.com/netbirdio/netbird/shared/management/certposture/certtest"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// holdSlot starts a collection on slots that runs until the returned func is called.
func holdSlot(t *testing.T, slots *collectSlots, timeout time.Duration) func() {
	t.Helper()
	holder := Collector{timeout: timeout, slots: slots}
	release := make(chan struct{})
	var once sync.Once
	releaseOnce := func() { once.Do(func() { close(release) }) }
	t.Cleanup(releaseOnce)

	done := make(chan struct{})
	go func() {
		defer close(done)
		holder.collect(context.Background(), challengeChecks, func(context.Context) []certposture.Proof {
			<-release
			return nil
		})
	}()
	require.Eventually(t, func() bool { return !slots.idle() }, time.Second, time.Millisecond, "the holder should get the slot")
	return releaseOnce
}

// A second session asks while the first is reading the store, as both do right after a network map.
// The real store answers it once the slot is free, with a proof management accepts.
func TestCollector_WaitsForAValidHolder(t *testing.T) {
	ca := certtest.NewCA(t, "corp-root")
	dir := storeDir(t)
	key := certtest.ECDSAKey(t)
	writeFile(t, dir, "device.pem", certtest.CertPEM(ca.Issue(t, key, "device"))+certtest.KeyPEM(t, key))
	t.Setenv(StoreDirEnv, dir)

	slots := &collectSlots{}
	release := holdSlot(t, slots, time.Minute)

	challenger := certposture.NewChallenger([]byte("secret"))
	checks := []*proto.Checks{{CertificateChallenge: &proto.CertificateChallenge{
		Nonce:          challenger.Nonce(peerKey, time.Now()),
		CaCertificates: []string{ca.PEM},
	}}}

	waiter := Collector{slots: slots, WaitForSlot: true}
	result := make(chan []certposture.Proof, 1)
	go func() { result <- waiter.Collect(context.Background(), checks, peerKey, Config{}) }()

	select {
	case <-result:
		require.FailNow(t, "the collection should wait while the holder runs")
	case <-time.After(100 * time.Millisecond):
	}

	release()
	select {
	case proofs := <-result:
		require.Len(t, proofs, 1, "the collection should prove the certificate once the slot is free")
		_, err := challenger.Verify(proofs[0], peerKey, time.Now())
		assert.NoError(t, err, "management should accept the proof")
	case <-time.After(10 * time.Second):
		require.FailNow(t, "the collection should run once the slot is free")
	}
}

// The engine stops while its watcher waits: the wait ends with the context, and nothing runs.
func TestCollector_WaitEndsWithTheContext(t *testing.T) {
	slots := &collectSlots{}
	holdSlot(t, slots, time.Minute)

	ctx, cancel := context.WithCancel(context.Background())
	waiter := Collector{slots: slots, WaitForSlot: true}
	var called atomic.Bool
	result := make(chan []certposture.Proof, 1)
	go func() {
		result <- waiter.collect(ctx, challengeChecks, func(context.Context) []certposture.Proof {
			called.Store(true)
			return []certposture.Proof{{}}
		})
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case proofs := <-result:
		assert.Nil(t, proofs, "a wait that was cut short proves nothing")
		assert.False(t, called.Load(), "a wait that was cut short runs nothing")
	case <-time.After(5 * time.Second):
		require.FailNow(t, "the wait should end with the context")
	}
}

// A holder wedged for good is no longer a valid one: the wait ends when it counts as lost, and the
// collection runs beside it.
func TestCollector_WaitEndsWhenTheHolderIsLost(t *testing.T) {
	slots := &collectSlots{}
	holdSlot(t, slots, time.Minute)

	waiter := Collector{timeout: 20 * time.Millisecond, slots: slots, WaitForSlot: true}
	start := time.Now()
	want := []certposture.Proof{{Nonce: []byte("nonce")}}
	proofs := waiter.collect(context.Background(), challengeChecks, func(context.Context) []certposture.Proof { return want })

	assert.Equal(t, want, proofs, "the collection should run beside the lost one")
	assert.GreaterOrEqual(t, time.Since(start), time.Duration(lostAfter)*waiter.deadline()/2, "the holder gets its time first")
}

// Every slot held by a lost collection is not worth waiting for: the store is wedged, the engine
// reports it, and the answer comes at once as it does without waiting.
func TestCollector_DoesNotWaitOnAStuckCollector(t *testing.T) {
	now := time.Now()
	slots := &collectSlots{}
	clock := func() time.Time { return now }
	starter := Collector{timeout: 10 * time.Millisecond, slots: slots, now: clock}
	lost := time.Duration(lostAfter) * starter.deadline()

	release := make(chan struct{})
	defer close(release)
	stuck := func(context.Context) []certposture.Proof {
		<-release
		return nil
	}
	starter.collect(context.Background(), challengeChecks, stuck)
	now = now.Add(lost)
	starter.collect(context.Background(), challengeChecks, stuck)
	now = now.Add(lost)
	require.True(t, starter.Stuck(), "both slots should be held by lost collections")

	waiter := Collector{timeout: 10 * time.Millisecond, slots: slots, now: clock, WaitForSlot: true}
	var called bool
	start := time.Now()
	proofs := waiter.collect(context.Background(), challengeChecks, func(context.Context) []certposture.Proof {
		called = true
		return []certposture.Proof{{}}
	})
	assert.Nil(t, proofs, "a wedged store proves nothing")
	assert.False(t, called, "no third collection starts")
	assert.Less(t, time.Since(start), time.Second, "there is nothing to wait for")
}

// Sessions in a row at the same slot all get their answer, one at a time.
func TestCollector_WaitersRunOneAtATime(t *testing.T) {
	slots := &collectSlots{}
	var running, most atomic.Int32
	var wg sync.WaitGroup
	results := make([][]certposture.Proof, 16)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			waiter := Collector{slots: slots, WaitForSlot: true}
			results[i] = waiter.collect(context.Background(), challengeChecks, func(context.Context) []certposture.Proof {
				current := running.Add(1)
				for {
					seen := most.Load()
					if current <= seen || most.CompareAndSwap(seen, current) {
						break
					}
				}
				time.Sleep(time.Millisecond)
				running.Add(-1)
				return []certposture.Proof{{Nonce: []byte("nonce")}}
			})
		}(i)
	}
	wg.Wait()

	for i, proofs := range results {
		assert.Lenf(t, proofs, 1, "waiter %d should get an answer", i)
	}
	assert.EqualValues(t, 1, most.Load(), "the collections should run one at a time")
	assert.True(t, slots.idle(), "no slot should stay taken")
}
