//go:build !darwin || ios

package server

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

const passwdPath = "/etc/passwd"

// hostAccounts lists the accounts of the host from its passwd file.
func hostAccounts() ([]hostAccount, error) {
	return localAccounts()
}

// localAccounts reads the accounts of the host from its passwd file. No such file means no accounts,
// as in a container that runs on numeric identities. There is no way to list accounts through NSS.
func localAccounts() ([]hostAccount, error) {
	raw, err := os.ReadFile(passwdPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", passwdPath, err)
	}

	var accounts []hostAccount
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 3 {
			continue
		}
		uid, err := strconv.ParseUint(fields[2], 10, 32)
		if err != nil {
			continue
		}
		accounts = append(accounts, hostAccount{name: fields[0], uid: uint32(uid)})
	}
	return accounts, nil
}
