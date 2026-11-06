//go:build multiprofile

package status

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/version"
)

// The status output and the status.txt of a debug bundle both print the daemon
// and CLI version, so the fork marker has to reach them to tell the builds apart.
func TestStatusShowsForkVersion(t *testing.T) {
	overview := ConvertToStatusOutputOverview(&proto.FullStatus{
		ManagementState: &proto.ManagementState{},
		SignalState:     &proto.SignalState{},
		LocalPeerState:  &proto.LocalPeerState{},
	}, ConvertOptions{
		DaemonVersion: version.NetbirdVersion(),
	})

	for _, out := range []string{overview.GeneralSummary(false, false, false, false), overview.FullDetailSummary()} {
		assert.Contains(t, out, "Daemon version: "+version.NetbirdVersion(), "the daemon version must show the fork marker")
		assert.Contains(t, out, "CLI version: "+version.NetbirdVersion(), "the CLI version must show the fork marker")
		assert.Contains(t, out, "+multiprofile", "the fork marker must be visible")
	}
}
