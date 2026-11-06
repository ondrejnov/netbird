//go:build privileged

package nftables

import (
	"os"
	"testing"

	"github.com/netbirdio/netbird/client/testutil/isolatedhost"
)

// TestMain runs the tests on a host of their own, see isolatedhost. The checks of compatibility
// with iptables-nft expect its tables.
func TestMain(m *testing.M) {
	os.Exit(isolatedhost.Run(m, isolatedhost.WithIptablesTables()))
}
