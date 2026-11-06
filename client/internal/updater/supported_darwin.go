package updater

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/updater/installer"
	"github.com/netbirdio/netbird/version"
)

func isAutoUpdateSupported() bool {
	// The fork is not distributed for macOS, and the installer URLs of the
	// official release would replace it with the upstream client.
	if version.ForkBuild() {
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	isBrew := !installer.TypeOfInstaller(ctx).Downloadable()
	if isBrew {
		log.Warnf("auto-update disabled on Homebrew installation")
		return false
	}
	return true
}
