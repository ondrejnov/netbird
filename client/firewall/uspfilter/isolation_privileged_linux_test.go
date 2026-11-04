//go:build privileged && linux

package uspfilter

import (
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"go.uber.org/mock/gomock"
	"golang.org/x/sys/unix"

	fw "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/firewall/uspfilter/common"
	nbiface "github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/mocks"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/iface/wgbackend"
	nftypes "github.com/netbirdio/netbird/client/internal/netflow/types"
)

const (
	isoArrive   = 2 * time.Second
	isoNoArrive = 600 * time.Millisecond
)

var (
	// A routed destination the host owns, standing for a network behind this session.
	isoRoutedIP = netip.MustParseAddr("198.51.100.5")
	// A destination the host reaches through the interface of the other session.
	isoViaOtherIP = netip.MustParseAddr("203.0.113.9")
	// The same for IPv6, a documentation address the host routes out with the source of the other overlay.
	isoViaOtherIP6 = netip.MustParseAddr("2001:db8:1::9")
)

type isoFlows struct {
	nftypes.FlowLogger
	mu     sync.Mutex
	events []nftypes.EventFields
}

func (r *isoFlows) StoreEvent(e nftypes.EventFields) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

func (r *isoFlows) count(typ nftypes.Type, dst netip.Addr) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, e := range r.events {
		if e.Type == typ && e.DestIP == dst {
			n++
		}
	}
	return n
}

// isoHost gives the test host the addresses and the route a second session would leave behind:
// the address of the other overlay on a local interface, a routed network of its own, and a
// destination whose route leaves with the source address of the other overlay.
func isoHost(t *testing.T) {
	t.Helper()
	// Only the throwaway container may have its addresses changed.
	if os.Getenv("DOCKER_CI") != "true" {
		t.Skip("changes host addresses, runs only in the privileged container")
	}

	lo, err := netlink.LinkByName("lo")
	require.NoError(t, err)
	require.NoError(t, netlink.LinkSetUp(lo))

	for _, ip := range []netip.Addr{isoOtherIP, isoRoutedIP} {
		addr := &netlink.Addr{IPNet: &net.IPNet{IP: ip.AsSlice(), Mask: net.CIDRMask(32, 32)}}
		require.NoError(t, netlink.AddrAdd(lo, addr))
		t.Cleanup(func() { _ = netlink.AddrDel(lo, addr) })
	}

	route := &netlink.Route{
		LinkIndex: lo.Attrs().Index,
		Dst:       &net.IPNet{IP: net.ParseIP("203.0.113.0").To4(), Mask: net.CIDRMask(24, 32)},
		Src:       isoOtherIP.AsSlice(),
		Scope:     netlink.SCOPE_LINK,
	}
	require.NoError(t, netlink.RouteAdd(route))
	t.Cleanup(func() { _ = netlink.RouteDel(route) })
}

// isoHost6 adds what isoHost adds for IPv4: the IPv6 address of the other overlay on a local
// interface and a destination whose route leaves with that address as its source.
func isoHost6(t *testing.T) {
	t.Helper()
	isoHost(t)

	// The container may start with IPv6 off on lo, and the sysctl is namespaced to it.
	const disable = "/proc/sys/net/ipv6/conf/lo/disable_ipv6"
	prev, err := os.ReadFile(disable)
	if err != nil {
		t.Skipf("host has no IPv6: %v", err)
	}
	require.NoError(t, os.WriteFile(disable, []byte("0"), 0o644))
	t.Cleanup(func() { _ = os.WriteFile(disable, prev, 0o644) })

	lo, err := netlink.LinkByName("lo")
	require.NoError(t, err)

	addr := &netlink.Addr{IPNet: &net.IPNet{IP: isoOtherIP6.AsSlice(), Mask: net.CIDRMask(128, 128)}, Flags: unix.IFA_F_NODAD}
	require.NoError(t, netlink.AddrAdd(lo, addr))
	t.Cleanup(func() { _ = netlink.AddrDel(lo, addr) })

	route := &netlink.Route{
		LinkIndex: lo.Attrs().Index,
		Dst:       &net.IPNet{IP: net.ParseIP("2001:db8:1::"), Mask: net.CIDRMask(64, 128)},
		Src:       isoOtherIP6.AsSlice(),
		Scope:     netlink.SCOPE_UNIVERSE,
	}
	require.NoError(t, netlink.RouteAdd(route))
	t.Cleanup(func() { _ = netlink.RouteDel(route) })
}

// isoRouter builds the userspace firewall of network A with routing on and a route ACL that
// allows its peers to every destination the test uses, including the overlay of network B.
// The local address set holds only the session's own address, so every packet to a test
// destination takes the routed path through the forwarder, as a packet to a peer of network B
// does, while the listeners of isoHost stand in for those destinations.
func isoRouter(t *testing.T, src common.IsolationSource, flows nftypes.FlowLogger) *Manager {
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
	cfg := Config{IFace: iface, FlowLogger: flows, MTU: nbiface.DefaultMTU}
	if src != nil {
		cfg.Isolation = src
	}
	m, err := Create(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, m.Close(nil)) })
	m.localipmanager.snapshot.Store(&localIPSnapshot{ips: map[netip.Addr]struct{}{isoOwnIP: {}}})
	require.NoError(t, m.EnableRouting())

	for _, dst := range []string{"198.51.100.0/24", "100.65.0.0/16", "203.0.113.0/24"} {
		_, err := m.AddFilterRule(nil, []netip.Prefix{netip.MustParsePrefix("100.64.0.0/16")},
			fw.Network{Prefix: netip.MustParsePrefix(dst)}, fw.ProtocolALL, nil, nil, fw.ActionAccept)
		require.NoError(t, err)
	}
	for _, dst := range []string{"fd00:b::/64", "2001:db8:1::/64"} {
		_, err := m.AddFilterRule(nil, []netip.Prefix{isoOwnNet6.Masked()},
			fw.Network{Prefix: netip.MustParsePrefix(dst)}, fw.ProtocolALL, nil, nil, fw.ActionAccept)
		require.NoError(t, err)
	}
	return m
}

type isoListener struct {
	tcp     net.Listener
	udp     net.PacketConn
	tcpConn chan struct{}
	udpData chan struct{}
}

// isoListen opens a TCP and a UDP service on ip, and reports each connection and datagram it gets.
func isoListen(t *testing.T, ip netip.Addr) (*isoListener, uint16) {
	t.Helper()
	tcp, err := net.Listen("tcp4", net.JoinHostPort(ip.String(), "0"))
	require.NoError(t, err)
	port := uint16(tcp.Addr().(*net.TCPAddr).Port)
	udp, err := net.ListenPacket("udp4", net.JoinHostPort(ip.String(), strconv.Itoa(int(port))))
	require.NoError(t, err)

	l := &isoListener{tcp: tcp, udp: udp, tcpConn: make(chan struct{}, 16), udpData: make(chan struct{}, 16)}
	t.Cleanup(func() {
		_ = tcp.Close()
		_ = udp.Close()
	})
	go func() {
		for {
			conn, err := tcp.Accept()
			if err != nil {
				return
			}
			l.tcpConn <- struct{}{}
			_ = conn.Close()
		}
	}()
	go func() {
		buf := make([]byte, 1500)
		for {
			if _, _, err := udp.ReadFrom(buf); err != nil {
				return
			}
			l.udpData <- struct{}{}
		}
	}()
	return l, port
}

func (l *isoListener) gotTCP(within time.Duration) bool {
	select {
	case <-l.tcpConn:
		return true
	case <-time.After(within):
		return false
	}
}

func (l *isoListener) gotUDP(within time.Duration) bool {
	select {
	case <-l.udpData:
		return true
	case <-time.After(within):
		return false
	}
}

// isoSend puts real SYN and UDP packets of peer A through the filter, like the tunnel device would.
func isoSend(t *testing.T, m *Manager, dst netip.Addr, port uint16) {
	t.Helper()
	for _, packet := range [][]byte{isoTCP(t, isoPeer, dst, port, false), isoUDP(t, isoPeer, dst, port)} {
		m.FilterInbound(packet, len(packet))
	}
}

// isoInject hands the packets straight to the forwarder, so only its own checks can refuse them.
func isoInject(t *testing.T, m *Manager, dst netip.Addr, port uint16) {
	t.Helper()
	fwd := m.forwarder.Load()
	require.NotNil(t, fwd, "routing is enabled, so the forwarder exists")
	for _, packet := range [][]byte{isoTCP(t, isoPeer, dst, port, false), isoUDP(t, isoPeer, dst, port)} {
		require.NoError(t, fwd.InjectIncomingPacket(packet))
	}
}

// A peer of network A reaches a routed network through the filter and the forwarder, and the
// same peer is refused when the destination is an address of network B, even though a route
// ACL allows it (I3). The control run has no source and shows the packets do arrive today.
func TestIsolation_ForwardedTraffic(t *testing.T) {
	isoHost(t)

	t.Run("other overlay is refused by the filter", func(t *testing.T) {
		src := &isoSource{}
		src.set(otherSession(), nil)
		m := isoRouter(t, src, &isoFlows{})
		other, otherPort := isoListen(t, isoOtherIP)

		isoSend(t, m, isoOtherIP, otherPort)
		assert.False(t, other.gotTCP(isoNoArrive), "tcp to the other overlay must not connect")
		assert.False(t, other.gotUDP(isoNoArrive), "udp to the other overlay must not arrive")
	})

	t.Run("without a source the same packets arrive", func(t *testing.T) {
		m := isoRouter(t, nil, &isoFlows{})
		other, otherPort := isoListen(t, isoOtherIP)

		isoSend(t, m, isoOtherIP, otherPort)
		assert.True(t, other.gotTCP(isoArrive), "tcp connects as before")
		assert.True(t, other.gotUDP(isoArrive), "udp arrives as before")
	})

	t.Run("own routed traffic is kept", func(t *testing.T) {
		src := &isoSource{}
		src.set(otherSession(), nil)
		m := isoRouter(t, src, &isoFlows{})
		routed, routedPort := isoListen(t, isoRoutedIP)

		isoSend(t, m, isoRoutedIP, routedPort)
		assert.True(t, routed.gotTCP(isoArrive), "tcp to the routed network connects")
		assert.True(t, routed.gotUDP(isoArrive), "udp to the routed network arrives")
	})

	t.Run("failing source refuses own routed traffic", func(t *testing.T) {
		src := &isoSource{}
		src.set(common.IsolationSnapshot{}, assert.AnError)
		m := isoRouter(t, src, &isoFlows{})
		routed, routedPort := isoListen(t, isoRoutedIP)

		isoSend(t, m, isoRoutedIP, routedPort)
		assert.False(t, routed.gotTCP(isoNoArrive), "tcp is refused while the state is unknown")
		assert.False(t, routed.gotUDP(isoNoArrive), "udp is refused while the state is unknown")
	})
}

// The forwarder refuses the other overlay on its own, for a packet the filter let through.
func TestIsolation_ForwarderRefusesOnItsOwn(t *testing.T) {
	isoHost(t)

	t.Run("other overlay", func(t *testing.T) {
		src := &isoSource{}
		src.set(otherSession(), nil)
		flows := &isoFlows{}
		m := isoRouter(t, src, flows)
		other, otherPort := isoListen(t, isoOtherIP)

		isoInject(t, m, isoOtherIP, otherPort)
		assert.False(t, other.gotTCP(isoNoArrive), "tcp is refused by the forwarder")
		assert.False(t, other.gotUDP(isoNoArrive), "udp is refused by the forwarder")
		assert.Eventually(t, func() bool { return flows.count(nftypes.TypeDrop, isoOtherIP) == 2 },
			isoArrive, 20*time.Millisecond, "both flows end as dropped")
	})

	t.Run("control without a source", func(t *testing.T) {
		m := isoRouter(t, nil, &isoFlows{})
		other, otherPort := isoListen(t, isoOtherIP)

		isoInject(t, m, isoOtherIP, otherPort)
		assert.True(t, other.gotTCP(isoArrive), "tcp connects as before")
		assert.True(t, other.gotUDP(isoArrive), "udp arrives as before")
	})

	t.Run("own routed traffic", func(t *testing.T) {
		src := &isoSource{}
		src.set(otherSession(), nil)
		m := isoRouter(t, src, &isoFlows{})
		routed, routedPort := isoListen(t, isoRoutedIP)

		isoInject(t, m, isoRoutedIP, routedPort)
		assert.True(t, routed.gotTCP(isoArrive), "tcp connects")
		assert.True(t, routed.gotUDP(isoArrive), "udp arrives")
	})
}

// A destination outside every overlay can still leave through the interface of another session
// when the host routes it there. The forwarder sees which source address the host picks and
// refuses the flow (I3), where today it would be dialed. IPv6 takes the same path through
// the source address of the connected socket.
func TestIsolation_ForwarderRefusesEgressThroughOtherSession(t *testing.T) {
	families := []struct {
		name string
		host func(*testing.T)
		peer netip.Addr
		dst  netip.Addr
	}{
		{"v4", isoHost, isoPeer, isoViaOtherIP},
		{"v6", isoHost6, isoPeer6, isoViaOtherIP6},
	}
	for _, fam := range families {
		t.Run(fam.name, func(t *testing.T) {
			fam.host(t)

			tests := []struct {
				name     string
				isolated bool
				drops    int
			}{
				{"isolated", true, 2},
				{"control without a source", false, 0},
			}
			for _, tc := range tests {
				t.Run(tc.name, func(t *testing.T) {
					var src common.IsolationSource
					if tc.isolated {
						s := &isoSource{}
						s.set(otherSession(), nil)
						src = s
					}
					flows := &isoFlows{}
					m := isoRouter(t, src, flows)

					fwd := m.forwarder.Load()
					require.NotNil(t, fwd, "routing is enabled, so the forwarder exists")
					for _, packet := range [][]byte{isoTCP(t, fam.peer, fam.dst, 80, false), isoUDP(t, fam.peer, fam.dst, 80)} {
						require.NoError(t, fwd.InjectIncomingPacket(packet))
					}
					if tc.isolated {
						assert.Eventually(t, func() bool { return flows.count(nftypes.TypeDrop, fam.dst) == tc.drops },
							isoArrive, 20*time.Millisecond, "flows leaving through the other session end as dropped")
						return
					}
					time.Sleep(isoNoArrive)
					assert.Equal(t, 0, flows.count(nftypes.TypeDrop, fam.dst), "nothing is refused without a source")
				})
			}
		})
	}
}
