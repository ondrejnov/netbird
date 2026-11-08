//go:build !ios

package server

import (
	"context"
	"fmt"
	"os/exec"
	"time"
)

const (
	dsclPath = "/usr/bin/dscl"
	// dsclTimeout bounds the listing, which a directory server that does not answer could hold up.
	dsclTimeout = 10 * time.Second
)

// hostAccounts lists the accounts macOS knows, from every directory node it searches. The passwd
// file of macOS holds the system accounts only, the users live in Open Directory. A listing that
// fails is an error, so the caller denies.
func hostAccounts() ([]hostAccount, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dsclTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, dsclPath, "/Search", "-list", "/Users", "UniqueID").Output()
	if err != nil {
		return nil, fmt.Errorf("list accounts with dscl: %w", err)
	}
	return parseDsclAccounts(string(out)), nil
}
