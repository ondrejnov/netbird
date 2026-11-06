//go:build privileged && linux

package server

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/iface/netstack"
	"github.com/netbirdio/netbird/client/proto"
)

// A daemon without the gate must leave on the host what it always did: the interface wt0 and the
// names and rules of slot 0, and no trace of sessions, for each kind of firewall.
func TestNoGateHostSnapshotMatchesToday(t *testing.T) {
	for _, backend := range hostBackends {
		t.Run(backend.name, func(t *testing.T) {
			backend.setup(t)
			t.Setenv("NB_WG_KERNEL_DISABLED", "true")
			t.Setenv("NB_DNS_STATE_FILE", "")
			t.Setenv(netstack.EnvUseNetstackMode, "false")

			s, ctx, profile, username, cfgPath := setupServerWithProfile(t)
			rootCtx, cancelRoot := context.WithCancel(ctx)
			s.rootCtx = rootCtx
			stopRunAtCleanup(t, s, cancelRoot)

			_, signalAddr, err := startSignal(t)
			require.NoError(t, err)
			startNetwork(t, ctx, filepath.Dir(cfgPath), profile, signalAddr, networkWork)
			require.NoError(t, s.Start())

			upProfile(t, ctx, s, profile, username)
			ss := s.focusedSession()
			awaitConnected(t, ss, profile)
			keepRouterConnected(t, ss.statusRecorder)

			normalize := overlayNormalizer(map[string]netip.Addr{"<overlay>": localOverlayAddr(t, ss)})
			require.Eventually(t, func() bool {
				routes := linesWith(snapshotRoutes(t), networkWork.route.String())
				return len(routes) > 0
			}, 30*time.Second, 100*time.Millisecond, "the route of the network should reach the table")

			snapshot := takeHostSnapshot(t, normalize).String()
			_, err = s.Down(ctx, &proto.DownRequest{})
			require.NoError(t, err)
			awaitRunEnd(t, ss)

			assert.NoFileExists(t, filepath.Join(filepath.Dir(cfgPath), "sessions.json"), "a daemon without the gate has no sessions file")

			path := filepath.Join("testdata", fmt.Sprintf("host_snapshot_%s.golden", backend.name))
			want, err := os.ReadFile(path)
			if errors.Is(err, os.ErrNotExist) {
				// The files come from a commit without the session wiring, see the spec. They are
				// not to be refreshed to make the test pass.
				require.NoError(t, os.WriteFile(path, []byte(snapshot), 0o644))
				t.Fatalf("wrote %s, nothing to compare with", path)
			}
			require.NoError(t, err)
			assert.Equal(t, withoutEmptyBuiltinLines(string(want)), withoutEmptyBuiltinLines(snapshot),
				"the host without the gate should look as it does today")
		})
	}
}

// withoutEmptyBuiltinLines compares what is not an artifact of iptables-nft, which earlier tests in
// the same container leave behind, see hostSnapshot.withoutEmptyBuiltins.
func withoutEmptyBuiltinLines(snapshot string) string {
	lines := strings.Split(snapshot, "\n")
	return strings.Join(slices.DeleteFunc(lines, isEmptyBuiltin), "\n")
}

func awaitRunEnd(t *testing.T, ss *session) {
	t.Helper()
	_, giveUp := ss.runChans()
	select {
	case <-giveUp:
	case <-time.After(30 * time.Second):
		t.Fatal("the run should end after Down")
	}
}
