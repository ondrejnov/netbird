package uspfilter

import (
	"errors"
	"net/netip"
	"sync"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	fw "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/firewall/uspfilter/common"
	nbiface "github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/mocks"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/iface/wgbackend"
)

var (
	isoOwnNet    = netip.MustParsePrefix("100.64.0.1/16")
	isoOwnNet6   = netip.MustParsePrefix("fd00:a::1/64")
	isoOtherNet  = netip.MustParsePrefix("100.65.0.0/16")
	isoOtherNet6 = netip.MustParsePrefix("fd00:b::/64")

	isoPeer    = netip.MustParseAddr("100.64.0.9")
	isoPeer6   = netip.MustParseAddr("fd00:a::9")
	isoOwnIP   = netip.MustParseAddr("100.64.0.1")
	isoOwnIP6  = netip.MustParseAddr("fd00:a::1")
	isoOtherIP = netip.MustParseAddr("100.65.0.1")
	// The other session's address as the host holds it on its own interface.
	isoOtherIP6 = netip.MustParseAddr("fd00:b::1")
)

// isoSource is a mutable IsolationSource, standing in for the host coordinator.
type isoSource struct {
	mu   sync.Mutex
	snap common.IsolationSnapshot
	err  error
}

func (s *isoSource) OtherSessions() (common.IsolationSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snap, s.err
}

func (s *isoSource) set(snap common.IsolationSnapshot, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snap, s.err = snap, err
}

func otherSession() common.IsolationSnapshot {
	return common.IsolationSnapshot{
		Interfaces: []string{"wt1"},
		Overlays:   []netip.Prefix{isoOtherNet, isoOtherNet6},
	}
}

// newIsolationManager builds a manager on overlay A that accepts every peer on the local
// path, and whose host owns the addresses of overlay B on its own interface, like a Linux
// host with a second session does. The weak host model then delivers them locally.
func newIsolationManager(t *testing.T, src common.IsolationSource) *Manager {
	t.Helper()

	ctrl := gomock.NewController(t)
	dev := mocks.NewMockDevice(ctrl)
	dev.EXPECT().MTU().Return(1500, nil).AnyTimes()

	iface := &IFaceMock{
		SetFilterFunc: func(device.PacketFilter) error { return nil },
		AddressFunc: func() wgaddr.Address {
			return wgaddr.Address{IP: isoOwnIP, Network: isoOwnNet.Masked(), IPv6: isoOwnIP6, IPv6Net: isoOwnNet6.Masked()}
		},
		GetDeviceFunc:   func() *device.FilteredDevice { return &device.FilteredDevice{TUN: dev} },
		GetWGDeviceFunc: func() *wgbackend.Device { return &wgbackend.Device{} },
	}

	cfg := Config{IFace: iface, FlowLogger: flowLogger, MTU: nbiface.DefaultMTU}
	if src != nil {
		cfg.Isolation = src
	}
	m, err := Create(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, m.Close(nil)) })

	_, err = m.AddFilterRule(nil,
		[]netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")},
		fw.Network{}, fw.ProtocolALL, nil, nil, fw.ActionAccept)
	require.NoError(t, err)

	snapshot := m.localipmanager.snapshot.Load()
	ips := make(map[netip.Addr]struct{}, len(snapshot.ips)+2)
	for ip := range snapshot.ips {
		ips[ip] = struct{}{}
	}
	ips[isoOtherIP] = struct{}{}
	ips[isoOtherIP6] = struct{}{}
	m.localipmanager.snapshot.Store(&localIPSnapshot{ips: ips})
	return m
}

func isoTCP(t *testing.T, src, dst netip.Addr, dport uint16, fragment bool) []byte {
	t.Helper()
	tcp := &layers.TCP{SrcPort: 40000, DstPort: layers.TCPPort(dport), SYN: true, Window: 65535}
	return isoSerialize(t, src, dst, layers.IPProtocolTCP, fragment, tcp)
}

func isoUDP(t *testing.T, src, dst netip.Addr, dport uint16) []byte {
	t.Helper()
	udp := &layers.UDP{SrcPort: 40000, DstPort: layers.UDPPort(dport)}
	return isoSerialize(t, src, dst, layers.IPProtocolUDP, false, udp)
}

type isoTransport interface {
	gopacket.SerializableLayer
	SetNetworkLayerForChecksum(gopacket.NetworkLayer) error
}

func isoSerialize(t *testing.T, src, dst netip.Addr, proto layers.IPProtocol, fragment bool, transport isoTransport) []byte {
	t.Helper()
	var network gopacket.SerializableLayer
	if src.Is4() {
		ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: proto, SrcIP: src.AsSlice(), DstIP: dst.AsSlice()}
		if fragment {
			ip.Flags = layers.IPv4MoreFragments
		}
		require.NoError(t, transport.SetNetworkLayerForChecksum(ip))
		network = ip
	} else {
		ip := &layers.IPv6{Version: 6, HopLimit: 64, NextHeader: proto, SrcIP: src.AsSlice(), DstIP: dst.AsSlice()}
		require.NoError(t, transport.SetNetworkLayerForChecksum(ip))
		network = ip
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	require.NoError(t, gopacket.SerializeLayers(buf, opts, network, transport, gopacket.Payload([]byte("x"))))
	return buf.Bytes()
}

// Without a source the filter behaves as before: the address of another session is a local
// address like any other, so a peer reaches it.
func TestIsolation_NoSourceKeepsBehavior(t *testing.T) {
	m := newIsolationManager(t, nil)

	assert.False(t, m.FilterInbound(isoTCP(t, isoPeer, isoOtherIP, 22, false), 0), "v4 delivery is not dropped")
	assert.False(t, m.FilterInbound(isoTCP(t, isoPeer6, isoOtherIP6, 22, false), 0), "v6 delivery is not dropped")
	assert.False(t, m.FilterInbound(isoTCP(t, isoPeer, isoOwnIP, 22, false), 0), "own traffic is not dropped")
}

// A peer of network A cannot reach a local service through the address network B gave the
// host (I4), while its own traffic to the host and to the same ports keeps working.
func TestIsolation_DropsLocalDeliveryToOtherSession(t *testing.T) {
	src := &isoSource{}
	src.set(otherSession(), nil)
	m := newIsolationManager(t, src)

	tests := []struct {
		name   string
		packet []byte
		drop   bool
	}{
		{"tcp to other v4", isoTCP(t, isoPeer, isoOtherIP, 22, false), true},
		{"udp to other v4", isoUDP(t, isoPeer, isoOtherIP, 53), true},
		{"tcp to other v6", isoTCP(t, isoPeer6, isoOtherIP6, 22, false), true},
		{"udp to other v6", isoUDP(t, isoPeer6, isoOtherIP6, 53), true},
		{"first fragment to other v4", isoTCP(t, isoPeer, isoOtherIP, 22, true), true},
		{"tcp to own v4", isoTCP(t, isoPeer, isoOwnIP, 22, false), false},
		{"udp to own v4", isoUDP(t, isoPeer, isoOwnIP, 53), false},
		{"tcp to own v6", isoTCP(t, isoPeer6, isoOwnIP6, 22, false), false},
		{"udp to own v6", isoUDP(t, isoPeer6, isoOwnIP6, 53), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.drop, m.FilterInbound(tc.packet, len(tc.packet)), "verdict: true means dropped")
		})
	}
}

// The set of other sessions changes at runtime, the filter follows it on the next packet.
func TestIsolation_FollowsSessionChanges(t *testing.T) {
	src := &isoSource{}
	m := newIsolationManager(t, src)

	packet := isoTCP(t, isoPeer, isoOtherIP, 22, false)
	assert.False(t, m.FilterInbound(packet, len(packet)), "no other session yet")

	src.set(otherSession(), nil)
	assert.True(t, m.FilterInbound(packet, len(packet)), "other session came up")

	src.set(common.IsolationSnapshot{}, nil)
	assert.False(t, m.FilterInbound(packet, len(packet)), "other session left")
}

// A failed or inconsistent source means unknown state, and unknown state refuses (I6), including
// traffic that would otherwise be the session's own.
func TestIsolation_FailsClosed(t *testing.T) {
	own := isoTCP(t, isoPeer, isoOwnIP, 22, false)

	tests := []struct {
		name string
		snap common.IsolationSnapshot
		err  error
	}{
		{"source error", common.IsolationSnapshot{}, errors.New("coordinator is gone")},
		{"empty interface name", common.IsolationSnapshot{Interfaces: []string{""}, Overlays: []netip.Prefix{isoOtherNet}}, nil},
		{"invalid prefix", common.IsolationSnapshot{Interfaces: []string{"wt1"}, Overlays: []netip.Prefix{{}}}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			src := &isoSource{}
			src.set(tc.snap, tc.err)
			m := newIsolationManager(t, src)
			assert.True(t, m.FilterInbound(own, len(own)), "own traffic is refused while the state is unknown")
		})
	}
}

func TestIsolationSnapshot_Covers(t *testing.T) {
	snap := otherSession()
	assert.True(t, snap.Covers(isoOtherIP))
	assert.True(t, snap.Covers(netip.MustParseAddr("::ffff:100.65.3.4")), "v4-mapped form")
	assert.True(t, snap.Covers(netip.MustParseAddr("fd00:b::1%wt1")), "zoned address")
	assert.False(t, snap.Covers(isoOwnIP))
	assert.False(t, snap.Covers(netip.MustParseAddr("100.66.0.1")))
}

func TestDeniesAddr_NilSource(t *testing.T) {
	denied, err := common.DeniesAddr(nil, isoOtherIP)
	require.NoError(t, err)
	assert.False(t, denied)
}
