package ipfwdstate

import (
	"errors"
	"fmt"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/routemanager/systemops"
)

// errRestoreUnsupported is returned on platforms where the v4 original cannot
// be read or written back.
var errRestoreUnsupported = errors.New("restoring IP forwarding is not supported on this platform")

// HostState holds the host-wide IP-forwarding sysctl state that several
// IPForwardingState instances share. The 0 to 1 transition of a family stores
// one original and enables forwarding, the 1 to 0 transition restores it.
type HostState struct {
	mu sync.Mutex

	// restoreV4 is false for the private state of an unshared instance, which
	// has never restored net.ipv4.ip_forward.
	restoreV4 bool

	v4Count int
	// v4Pending is set while v4Original differs from the enabled value and has
	// not been written back yet. A failed restore keeps it for the next cycle.
	v4Pending  bool
	v4Original int

	v6Count int
	v6Saved map[string]int

	// ifaces counts the overlay interfaces attached to this state, which are
	// excluded from the accept_ra handling.
	ifaces map[string]int
}

// NewHostState returns a state to share between IPForwardingState instances
// through WithHostState. Unlike an unshared instance it also restores
// net.ipv4.ip_forward when the last reference is released.
func NewHostState() *HostState {
	return newHostState(true)
}

func newHostState(restoreV4 bool) *HostState {
	return &HostState{restoreV4: restoreV4, ifaces: map[string]int{}}
}

func (h *HostState) counts() (v4, v6 int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.v4Count, h.v6Count
}

// attach registers an overlay interface that must keep its accept_ra value. An
// interface that an earlier enable already bumped is put back right away.
func (h *HostState) attach(name string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.ifaces[name]++
	if h.v6Count > 0 {
		restoreAcceptRA(h.v6Saved, []string{name})
	}
}

func (h *HostState) detach(name string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.ifaces[name] <= 1 {
		delete(h.ifaces, name)
		return
	}
	h.ifaces[name]--
}

func (h *HostState) requestV4() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.v4Count == 0 {
		original, readable := h.readV4Original()
		if err := systemops.EnableV4IPForwarding(); err != nil {
			return fmt.Errorf("enable IPv4 forwarding: %w", err)
		}
		if readable && original != 1 {
			h.v4Original = original
			h.v4Pending = true
		}
		log.Info("IPv4 forwarding enabled")
	}
	h.v4Count++
	return nil
}

// readV4Original reads the value to restore later. A value kept from a failed
// restore is the true original and wins over what is read now.
func (h *HostState) readV4Original() (int, bool) {
	if !h.restoreV4 || h.v4Pending {
		return 0, false
	}
	original, err := readV4Forwarding()
	if err != nil {
		if !errors.Is(err, errRestoreUnsupported) {
			log.Warnf("read IPv4 forwarding, it will not be restored: %v", err)
		}
		return 0, false
	}
	return original, true
}

func (h *HostState) releaseV4() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.v4Count == 0 {
		return nil
	}
	h.v4Count--
	if h.v4Count > 0 || !h.v4Pending {
		return nil
	}

	if err := writeV4Forwarding(h.v4Original); err != nil {
		return fmt.Errorf("restore IPv4 forwarding: %w", err)
	}
	h.v4Pending = false
	log.Info("IPv4 forwarding restored")
	return nil
}

func (h *HostState) requestV6(requester string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.v6Count == 0 {
		saved, err := systemops.EnableV6IPForwarding(requester)
		if err != nil {
			if rerr := systemops.DisableV6IPForwarding(saved); rerr != nil {
				log.Warnf("rollback partial v6 sysctls: %v", rerr)
			}
			return fmt.Errorf("enable IPv6 forwarding: %w", err)
		}
		// A failed restore on a previous release keeps its saved values; those
		// are the true originals, so keep them over what this enable captured.
		if h.v6Saved == nil {
			h.v6Saved = saved
		} else {
			for k, v := range saved {
				if _, ok := h.v6Saved[k]; !ok {
					h.v6Saved[k] = v
				}
			}
		}
		// The enable excludes only the requester, the other sessions' interfaces
		// are put back here.
		restoreAcceptRA(h.v6Saved, h.otherIfaces(requester))
		log.Info("IPv6 forwarding enabled")
	}
	h.v6Count++
	return nil
}

func (h *HostState) otherIfaces(requester string) []string {
	others := make([]string, 0, len(h.ifaces))
	for name := range h.ifaces {
		if name != requester {
			others = append(others, name)
		}
	}
	return others
}

func (h *HostState) releaseV6() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.v6Count == 0 {
		return nil
	}
	h.v6Count--
	if h.v6Count > 0 {
		return nil
	}

	// Keep the saved values on failure so a later release or enable/release
	// cycle can still restore them; re-restoring an already-restored key is a
	// no-op since the sysctl already holds the desired value.
	if err := systemops.DisableV6IPForwarding(h.v6Saved); err != nil {
		return fmt.Errorf("disable IPv6 forwarding: %w", err)
	}
	h.v6Saved = nil
	log.Info("IPv6 forwarding disabled")
	return nil
}
