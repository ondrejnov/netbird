package server

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
)

// The name the SID of the caller resolves to is the name the CLI of that caller sends, or no
// unprivileged user would ever reach their profiles.
func TestWindowsAccountName_IsWhatTheCLISends(t *testing.T) {
	invoking, err := profilemanager.InvokingUser()
	require.NoError(t, err)

	name, err := windowsAccountName(invoking.Uid)
	require.NoError(t, err)
	assert.True(t, strings.EqualFold(invoking.Username, name), "the CLI sends %q, the SID resolves to %q", invoking.Username, name)
}

func TestWindowsAccountName_RefusesWhatIsNoSID(t *testing.T) {
	_, err := windowsAccountName("alice")
	assert.Error(t, err)
	_, err = windowsAccountName("S-1-5-21-1000000001-1000000002-1000000003-999999")
	assert.Error(t, err, "a SID of no account has no name")
}

// The local accounts are listed with the SIDs they resolve to inside the computer.
func TestLocalWindowsAccounts_ListsTheHost(t *testing.T) {
	accounts, err := localWindowsAccounts()
	require.NoError(t, err)
	require.NotEmpty(t, accounts, "every Windows host has local accounts")

	for _, account := range accounts {
		name, err := windowsAccountName(account.sid)
		require.NoError(t, err, "the SID of %s must resolve", account.name)
		assert.True(t, strings.EqualFold(name, account.name), "the SID of %s resolves to %s", account.name, name)
	}
}
