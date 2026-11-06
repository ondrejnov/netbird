//go:build multiprofile

package updater

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// The fork is only distributed for Linux. Built for another platform anyway, it
// must not install the official release over itself.
func TestForkBuildDoesNotAutoUpdate(t *testing.T) {
	assert.False(t, isAutoUpdateSupported(), "the fork build must not auto-update on any platform")
}
