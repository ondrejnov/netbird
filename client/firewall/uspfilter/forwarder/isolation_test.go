package forwarder

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"

	"github.com/netbirdio/netbird/client/firewall/uspfilter/common"
	nblog "github.com/netbirdio/netbird/client/firewall/uspfilter/log"
	nftypes "github.com/netbirdio/netbird/client/internal/netflow/types"
)

type fakeSessions struct {
	mu   sync.Mutex
	snap common.IsolationSnapshot
	err  error
}

func (s *fakeSessions) OtherSessions() (common.IsolationSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snap, s.err
}

func otherSessionSnapshot() common.IsolationSnapshot {
	return common.IsolationSnapshot{
		Interfaces: []string{"wt1"},
		Overlays:   []netip.Prefix{netip.MustParsePrefix("100.65.0.0/16"), netip.MustParsePrefix("fd00:b::/64")},
	}
}

func isolationForwarder(t *testing.T, src common.IsolationSource, flows nftypes.FlowLogger) *Forwarder {
	t.Helper()
	logger := nblog.NewFromLogrus(logrus.StandardLogger())
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		assert.NoError(t, logger.Stop(ctx))
	})

	// Netstack mode keeps the host routing table out of the verdict, only the other
	// sessions' overlays decide.
	f := &Forwarder{
		logger:     logger,
		ctx:        context.Background(),
		netstack:   true,
		ip:         addrFromNetipAddr(netip.MustParseAddr("100.64.0.1")),
		flowLogger: flows,
	}
	f.udpForwarder = newUDPForwarder(1500, logger, flows)
	t.Cleanup(f.udpForwarder.cancel)
	f.SetIsolation(src)
	return f
}

// The forwarder refuses a destination in another session's overlay and still accepts its own
// network and anything outside every overlay. Without a source nothing is refused.
func TestForwarderIsolation_RefusesOtherOverlay(t *testing.T) {
	other4 := netip.MustParseAddr("100.65.0.1")
	other6 := netip.MustParseAddr("fd00:b::1")
	own := netip.MustParseAddr("100.64.0.7")
	outside := netip.MustParseAddr("198.51.100.5")

	f := isolationForwarder(t, &fakeSessions{snap: otherSessionSnapshot()}, &recordingFlowLogger{})
	assert.True(t, f.egressesOverlay(other4), "other v4 overlay")
	assert.True(t, f.egressesOverlay(other6), "other v6 overlay")
	assert.False(t, f.egressesOverlay(own), "own overlay")
	assert.False(t, f.egressesOverlay(outside), "outside every overlay")

	f.SetIsolation(nil)
	assert.False(t, f.egressesOverlay(other4), "no source keeps today's behavior")
}

// A source that fails or returns state the forwarder cannot trust refuses everything (I6).
func TestForwarderIsolation_FailsClosed(t *testing.T) {
	outside := netip.MustParseAddr("198.51.100.5")

	f := isolationForwarder(t, &fakeSessions{err: errors.New("coordinator is gone")}, &recordingFlowLogger{})
	assert.True(t, f.egressesOverlay(outside), "source error")

	f.SetIsolation(&fakeSessions{snap: common.IsolationSnapshot{Overlays: []netip.Prefix{{}}}})
	assert.True(t, f.egressesOverlay(outside), "invalid snapshot")
}

// A refused UDP flow ends with one drop event and never dials.
func TestForwarderIsolation_UDPFlowIsDropped(t *testing.T) {
	flows := &recordingFlowLogger{}
	f := isolationForwarder(t, &fakeSessions{snap: otherSessionSnapshot()}, flows)

	id := stack.TransportEndpointID{
		RemoteAddress: addrFromNetipAddr(netip.MustParseAddr("100.64.0.9")),
		RemotePort:    40000,
		LocalAddress:  addrFromNetipAddr(netip.MustParseAddr("100.65.0.1")),
		LocalPort:     53,
	}
	require.False(t, f.handleUDP(udp.NewForwarderRequest(nil, id, nil)), "refused flow is not handled")

	var got []nftypes.Type
	for _, e := range flows.events {
		got = append(got, e.Type)
	}
	assert.Equal(t, []nftypes.Type{nftypes.TypeStart, nftypes.TypeDrop}, got, "exactly one closing event")
}

// An ICMP packet to another session ends its flow as dropped.
func TestForwarderIsolation_ICMPFlowIsDropped(t *testing.T) {
	flows := &recordingFlowLogger{}
	f := isolationForwarder(t, &fakeSessions{snap: otherSessionSnapshot()}, flows)

	id := stack.TransportEndpointID{
		RemoteAddress: addrFromNetipAddr(netip.MustParseAddr("100.64.0.9")),
		LocalAddress:  addrFromNetipAddr(netip.MustParseAddr("100.65.0.1")),
	}
	require.True(t, f.refuseOverlayEgress(uuid.New(), id, 8, 0))
	require.Len(t, flows.events, 1)
	assert.Equal(t, nftypes.TypeDrop, flows.events[0].Type)
}
