//go:build !ios

package server

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The passwd file of macOS holds the system accounts only, so the account of the test has to come
// from the directory for the check of a shared profile directory to see it.
func TestHostAccounts_ListsTheDirectoryUserOnMacOS(t *testing.T) {
	name := os.Getenv("USER")
	if name == "" || name == "root" {
		t.Skip("needs a regular user account")
	}

	accounts, err := hostAccounts()
	require.NoError(t, err)
	assert.Contains(t, accounts, hostAccount{name: name, uid: uint32(os.Getuid())}, "the directory lists the account")
}
