//go:build !windows

package server

import "errors"

var errNoWindowsAccounts = errors.New("no Windows account database on this platform")

// windowsAccountName fails: a Windows identity cannot reach a daemon on this platform.
func windowsAccountName(string) (string, error) {
	return "", errNoWindowsAccounts
}

// localWindowsAccounts fails for the same reason.
func localWindowsAccounts() ([]windowsAccount, error) {
	return nil, errNoWindowsAccounts
}
