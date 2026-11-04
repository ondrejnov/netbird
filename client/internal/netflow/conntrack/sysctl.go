//go:build linux && !android

package conntrack

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
)

const (
	// conntrackAcctPath is the sysctl path for conntrack accounting
	conntrackAcctPath = "net.netfilter.nf_conntrack_acct"
)

// Accounting shares nf_conntrack_acct between several holders. The 0 to 1
// transition stores one original and enables the counters, the 1 to 0
// transition restores it, so one holder stopping cannot turn the counters off
// for another.
type Accounting struct {
	mu       sync.Mutex
	holders  int
	pending  bool
	original int
}

// NewAccounting returns an Accounting with no holders.
func NewAccounting() *Accounting {
	return &Accounting{}
}

// Holders returns the number of holders. Intended for diagnostics and tests.
func (a *Accounting) Holders() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.holders
}

// Acquire registers a holder and enables the counters on the first one. A
// failure registers nothing.
func (a *Accounting) Acquire() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.holders == 0 {
		previous, modified, err := setSysctlValue(conntrackAcctPath, 1)
		if err != nil {
			return fmt.Errorf("enable conntrack accounting: %w", err)
		}
		// A value kept from a failed restore is the true original.
		if modified && !a.pending {
			a.original = previous
			a.pending = true
		}
	}
	a.holders++
	return nil
}

// Release drops a holder and restores the stored original with the last one.
// A failed restore keeps the original for the next cycle.
func (a *Accounting) Release() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.holders == 0 {
		return nil
	}
	a.holders--
	if a.holders > 0 || !a.pending {
		return nil
	}

	if _, _, err := setSysctlValue(conntrackAcctPath, a.original); err != nil {
		return fmt.Errorf("restore conntrack accounting: %w", err)
	}
	a.pending = false
	return nil
}

// EnableAccounting ensures that connection tracking accounting is enabled  in the kernel.
func (c *ConnTrack) EnableAccounting() {
	// haven't restored yet
	if c.sysctlModified {
		return
	}

	modified, err := setSysctl(conntrackAcctPath, 1)
	if err != nil {
		log.Warnf("Failed to enable conntrack accounting: %v", err)
		return
	}
	c.sysctlModified = modified
}

// RestoreAccounting restores the connection tracking accounting setting to its original value.
func (c *ConnTrack) RestoreAccounting() {
	if !c.sysctlModified {
		return
	}

	if _, err := setSysctl(conntrackAcctPath, 0); err != nil {
		log.Warnf("Failed to restore conntrack accounting: %v", err)
		return
	}

	c.sysctlModified = false
}

// setSysctl sets a sysctl configuration and returns whether it was modified.
func setSysctl(key string, desiredValue int) (bool, error) {
	_, modified, err := setSysctlValue(key, desiredValue)
	return modified, err
}

// setSysctlValue sets a sysctl configuration and returns the previous value and
// whether it was modified.
func setSysctlValue(key string, desiredValue int) (int, bool, error) {
	path := fmt.Sprintf("/proc/sys/%s", strings.ReplaceAll(key, ".", "/"))

	currentValue, err := os.ReadFile(path)
	if err != nil {
		return 0, false, fmt.Errorf("read sysctl %s: %w", key, err)
	}

	currentV, err := strconv.Atoi(strings.TrimSpace(string(currentValue)))
	if err != nil && len(currentValue) > 0 {
		return 0, false, fmt.Errorf("convert current value to int: %w", err)
	}

	if currentV == desiredValue {
		return currentV, false, nil
	}

	// nolint:gosec
	if err := os.WriteFile(path, []byte(strconv.Itoa(desiredValue)), 0644); err != nil {
		return currentV, false, fmt.Errorf("write sysctl %s: %w", key, err)
	}

	log.Debugf("Set sysctl %s from %d to %d", key, currentV, desiredValue)
	return currentV, true, nil
}
