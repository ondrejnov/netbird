package hostcoord

import (
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	keyA = SessionKey{Profile: "a", Username: "alice"}
	keyB = SessionKey{Profile: "b", Username: "alice"}
)

// recorder counts how often the host state was installed and removed.
type recorder struct {
	setups, teardowns, idle int
}

func (r *recorder) setup() (RoutingBase, TeardownFunc, error) {
	r.setups++
	return RoutingBase{SysctlFailed: true}, func() error {
		r.teardowns++
		return nil
	}, nil
}

func (r *recorder) idleCleanup() error {
	r.idle++
	return nil
}

func TestRoutingBaseFirstHolderSetsUpLastHolderTearsDown(t *testing.T) {
	c := New()
	rec := &recorder{}

	_, err := c.AcquireRoutingBase(keyA, rec.setup)
	require.NoError(t, err)
	base, err := c.AcquireRoutingBase(keyB, rec.setup)
	require.NoError(t, err)

	assert.Equal(t, 1, rec.setups, "only the first holder should install the base")
	assert.True(t, base.SysctlFailed, "a later holder should see the state of the shared base")

	require.NoError(t, c.ReleaseRoutingBase(keyA, rec.idleCleanup))
	assert.Equal(t, 0, rec.teardowns, "the base must survive while another session holds it")

	require.NoError(t, c.ReleaseRoutingBase(keyB, rec.idleCleanup))
	assert.Equal(t, 1, rec.teardowns, "the last holder should tear the base down")
	assert.Equal(t, 0, rec.idle, "the setup teardown replaces the idle cleanup")
}

func TestRoutingBaseSameKeyHoldsOneReference(t *testing.T) {
	c := New()
	rec := &recorder{}

	for range 2 {
		_, err := c.AcquireRoutingBase(keyA, rec.setup)
		require.NoError(t, err)
	}
	assert.Equal(t, 1, rec.setups, "a repeated acquire should not install the base again")

	require.NoError(t, c.ReleaseRoutingBase(keyA, rec.idleCleanup))
	assert.Equal(t, 1, rec.teardowns, "one release should drop the single reference")
}

func TestRoutingBaseReleaseWithoutHolding(t *testing.T) {
	t.Run("another session holds the base", func(t *testing.T) {
		// This is the cleanup a starting engine runs before its own setup.
		c := New()
		rec := &recorder{}
		_, err := c.AcquireRoutingBase(keyA, rec.setup)
		require.NoError(t, err)

		require.NoError(t, c.ReleaseRoutingBase(keyB, rec.idleCleanup))
		assert.Equal(t, 0, rec.idle, "the cleanup of a non-holder must not touch a held base")
		assert.Equal(t, 0, rec.teardowns, "the cleanup of a non-holder must not tear down a held base")
	})

	t.Run("nobody holds the base", func(t *testing.T) {
		c := New()
		rec := &recorder{}

		require.NoError(t, c.ReleaseRoutingBase(keyA, rec.idleCleanup))
		assert.Equal(t, 1, rec.idle, "stale state should be cleaned when no session runs")
	})
}

func TestRoutingBaseSetupFailureLeavesBaseUnheld(t *testing.T) {
	c := New()
	rec := &recorder{}
	errSetup := errors.New("setup")

	_, err := c.AcquireRoutingBase(keyA, func() (RoutingBase, TeardownFunc, error) {
		return RoutingBase{}, nil, errSetup
	})
	require.ErrorIs(t, err, errSetup)

	_, err = c.AcquireRoutingBase(keyB, rec.setup)
	require.NoError(t, err)
	assert.Equal(t, 1, rec.setups, "the next session should install the base after a failed setup")
}

func TestRoutingBaseTeardownErrorIsReturnedAndStateCleared(t *testing.T) {
	c := New()
	errTeardown := errors.New("teardown")
	rec := &recorder{}

	_, err := c.AcquireRoutingBase(keyA, func() (RoutingBase, TeardownFunc, error) {
		return RoutingBase{}, func() error { return errTeardown }, nil
	})
	require.NoError(t, err)
	require.ErrorIs(t, c.ReleaseRoutingBase(keyA, rec.idleCleanup), errTeardown)

	_, err = c.AcquireRoutingBase(keyA, rec.setup)
	require.NoError(t, err)
	assert.Equal(t, 1, rec.setups, "a new session should install the base again")
}

func TestRoutingBaseConcurrentHolders(t *testing.T) {
	c := New()
	rec := &recorder{}

	var wg sync.WaitGroup
	for i := range 32 {
		key := keyA
		if i%2 == 1 {
			key = keyB
		}
		wg.Add(1)
		go func(key SessionKey) {
			defer wg.Done()
			_, err := c.AcquireRoutingBase(key, rec.setup)
			assert.NoError(t, err)
			assert.NoError(t, c.ReleaseRoutingBase(key, rec.idleCleanup))
		}(key)
	}
	wg.Wait()

	require.NoError(t, c.ReleaseRoutingBase(keyA, nil))
	assert.Equal(t, rec.setups, rec.teardowns, "every installed base should be removed exactly once")
}
