package device

import (
	"errors"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"

	"github.com/netbirdio/netbird/client/iface/wgbackend"
)

// adapterRetryDelay is the pause before the one retry of an adapter creation that failed
// with ERROR_FILE_NOT_FOUND.
const adapterRetryDelay = time.Second

var (
	// adapterCreateMu serializes Wintun adapter creation across sessions. The first creation
	// after an install sets up the Wintun driver, and an adapter created alongside it loses its
	// device and fails with ERROR_FILE_NOT_FOUND.
	adapterCreateMu sync.Mutex

	createTUN       = wgbackend.CreateTUNWithRequestedGUID
	adapterRetryNap = adapterRetryDelay
)

// createAdapter creates the Wintun adapter called name with guid, one at a time per process,
// and retries once when the device vanished during creation.
func createAdapter(name string, guid *windows.GUID, mtu int) (wgbackend.TUN, error) {
	adapterCreateMu.Lock()
	defer adapterCreateMu.Unlock()

	tunDevice, err := createTUN(name, guid, mtu)
	if err == nil || !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return tunDevice, err
	}

	log.Warnf("create adapter %s: %v, retrying once", name, err)
	time.Sleep(adapterRetryNap)
	return createTUN(name, guid, mtu)
}
