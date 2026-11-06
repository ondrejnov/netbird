//go:build privileged && linux

package server

import (
	"os"
	"testing"

	"github.com/netbirdio/netbird/client/testutil/isolatedhost"
)

// TestMain runs the tests on a host of their own, see isolatedhost.
func TestMain(m *testing.M) {
	os.Exit(isolatedhost.Run(m))
}
