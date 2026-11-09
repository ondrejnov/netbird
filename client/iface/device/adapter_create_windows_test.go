//go:build windows

package device

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/windows"

	"github.com/netbirdio/netbird/client/iface/wgbackend"
)

// fakeTUN stands in for a created adapter; no test calls its methods.
type fakeTUN struct{ wgbackend.TUN }

func fakeCreateTUN(t *testing.T, fn func(string, *windows.GUID, int) (wgbackend.TUN, error)) {
	t.Helper()
	previousCreate, previousNap := createTUN, adapterRetryNap
	createTUN = fn
	adapterRetryNap = time.Millisecond
	t.Cleanup(func() {
		createTUN = previousCreate
		adapterRetryNap = previousNap
	})
}

func TestCreateAdapter_SessionsCreateOneAtATime(t *testing.T) {
	// Two sessions starting together after an install must not create their adapters at the
	// same time, or the second one loses its device while Wintun sets up the driver.
	var inFlight, maxInFlight atomic.Int32
	fakeCreateTUN(t, func(string, *windows.GUID, int) (wgbackend.TUN, error) {
		now := inFlight.Add(1)
		for {
			seen := maxInFlight.Load()
			if now <= seen || maxInFlight.CompareAndSwap(seen, now) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		inFlight.Add(-1)
		return &fakeTUN{}, nil
	})

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(slot int) {
			defer wg.Done()
			_, err := createAdapter(fmt.Sprintf("wt%d", slot), &windows.GUID{}, 1280)
			assert.NoError(t, err)
		}(i)
	}
	wg.Wait()

	assert.Equal(t, int32(1), maxInFlight.Load(), "adapters must be created one at a time")
}

func TestCreateAdapter_RetriesOnceWhenTheDeviceVanished(t *testing.T) {
	var calls atomic.Int32
	fakeCreateTUN(t, func(string, *windows.GUID, int) (wgbackend.TUN, error) {
		if calls.Add(1) == 1 {
			return nil, fmt.Errorf("Error creating interface: %w", windows.ERROR_FILE_NOT_FOUND)
		}
		return &fakeTUN{}, nil
	})

	_, err := createAdapter("wt2", &windows.GUID{}, 1280)

	assert.NoError(t, err)
	assert.Equal(t, int32(2), calls.Load(), "a vanished device gets exactly one retry")
}

func TestCreateAdapter_RetryFailureIsReturned(t *testing.T) {
	var calls atomic.Int32
	fakeCreateTUN(t, func(string, *windows.GUID, int) (wgbackend.TUN, error) {
		calls.Add(1)
		return nil, fmt.Errorf("Error creating interface: %w", windows.ERROR_FILE_NOT_FOUND)
	})

	_, err := createAdapter("wt2", &windows.GUID{}, 1280)

	assert.ErrorIs(t, err, windows.ERROR_FILE_NOT_FOUND)
	assert.Equal(t, int32(2), calls.Load(), "the retry happens once, not in a loop")
}

func TestCreateAdapter_OtherErrorsAreNotRetried(t *testing.T) {
	var calls atomic.Int32
	denied := errors.New("access denied")
	fakeCreateTUN(t, func(string, *windows.GUID, int) (wgbackend.TUN, error) {
		calls.Add(1)
		return nil, denied
	})

	_, err := createAdapter("wt2", &windows.GUID{}, 1280)

	assert.ErrorIs(t, err, denied)
	assert.Equal(t, int32(1), calls.Load(), "only ERROR_FILE_NOT_FOUND is retried")
}
