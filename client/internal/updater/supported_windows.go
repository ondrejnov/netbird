package updater

import "github.com/netbirdio/netbird/version"

// The fork is not distributed for Windows, and the installer URLs of the official
// release would replace it with the upstream client.
func isAutoUpdateSupported() bool {
	return !version.ForkBuild()
}
