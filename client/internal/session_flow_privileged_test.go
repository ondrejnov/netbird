//go:build privileged && linux

package internal

import (
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/hostcoord"
	"github.com/netbirdio/netbird/client/internal/netflow/conntrack"
	"github.com/netbirdio/netbird/client/internal/netflow/logger"
	nftypes "github.com/netbirdio/netbird/client/internal/netflow/types"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	nbnet "github.com/netbirdio/netbird/client/net"
)

const (
	flowRouteLink = "flowroute0"
	flowEventWait = 15 * time.Second
)

// flowSession is one engine's view of the conntrack events of the host: the real tracker and the
// real logger, on the options the session gets from the daemon.
type flowSession struct {
	logger *logger.Logger
}

type flowInterface struct {
	name string
	addr wgaddr.Address
}

func (f flowInterface) IsUserspaceBind() bool   { return false }
func (f flowInterface) Name() string            { return f.name }
func (f flowInterface) Address() wgaddr.Address { return f.addr }

func startFlowSession(t *testing.T, name string, addr wgaddr.Address, opts []conntrack.Option) *flowSession {
	t.Helper()
	flowLogger := logger.New(peer.NewRecorder(""), addr.Network, addr.IPv6Net)
	flowLogger.UpdateConfig(true, true)
	flowLogger.Enable()
	t.Cleanup(flowLogger.Close)
	// Enable returns before the logger takes events. An event with no addresses tells when it does.
	require.Eventually(t, func() bool {
		flowLogger.StoreEvent(nftypes.EventFields{})
		return len(flowLogger.GetEvents()) > 0
	}, 5*time.Second, 10*time.Millisecond, "the logger should start")

	tracker := conntrack.New(flowLogger, flowInterface{name: name, addr: addr}, opts...)
	require.NoError(t, tracker.Start(false), "listen for conntrack events")
	t.Cleanup(tracker.Stop)
	return &flowSession{logger: flowLogger}
}

func (s *flowSession) sawPort(port uint16) bool {
	for _, event := range s.logger.GetEvents() {
		if event.DestPort == port {
			return true
		}
	}
	return false
}

func (s *flowSession) sawAddress(prefix netip.Prefix) bool {
	for _, event := range s.logger.GetEvents() {
		if prefix.Contains(event.SourceIP) || prefix.Contains(event.DestIP) {
			return true
		}
	}
	return false
}

// addFlowLink adds a link with addresses, and for each of their families a rule that gives whatever
// leaves through it the mark the rules of a session give its flows.
func addFlowLink(t *testing.T, name string, addrs ...netip.Prefix) {
	t.Helper()
	require.NoError(t, netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}))
	link, err := netlink.LinkByName(name)
	require.NoError(t, err)
	require.NoError(t, netlink.LinkSetUp(link))

	for _, addr := range addrs {
		mask := net.CIDRMask(addr.Bits(), addr.Addr().BitLen())
		// Without NODAD a v6 address cannot be bound until the detection ends.
		nlAddr := &netlink.Addr{IPNet: &net.IPNet{IP: addr.Addr().AsSlice(), Mask: mask}, Flags: unix.IFA_F_NODAD}
		require.NoError(t, netlink.AddrAdd(link, nlAddr))

		proto := iptables.ProtocolIPv4
		if addr.Addr().Is6() {
			proto = iptables.ProtocolIPv6
		}
		ipt, err := iptables.NewWithProtocol(proto)
		require.NoError(t, err)
		require.NoError(t, ipt.AppendUnique("mangle", "OUTPUT", "-o", name, "-j", "CONNMARK", "--set-mark", fmt.Sprintf("%#x", uint32(nbnet.DataPlaneMarkOut))))
	}
}

// sendFlow makes the kernel track one UDP flow. The dummy link drops the datagram after the
// conntrack has seen it leave.
func sendFlow(t *testing.T, src, dst netip.Addr, port uint16) {
	t.Helper()
	conn, err := net.DialUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(src, 0)), net.UDPAddrFromAddrPort(netip.AddrPortFrom(dst, port)))
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	_, err = conn.Write([]byte("flow"))
	require.NoError(t, err)
}

// Conntrack events cover the whole host and the marks are shared between sessions, so the tracker
// of each session sees the flows of the others with a mark that reads as its own. With the gate only
// a flow with an overlay address of the session may reach its logger, which is what goes to the Flow
// service of its network (R1, I5). A tracker without the gate is the control: it gets the same events
// and takes all of them, so what the others miss did happen.
func TestSessionFlowsStayWithTheirNetwork(t *testing.T) {
	host := newTestDaemonHost(t)

	workAddr := wgaddr.MustParseWGAddress("100.71.0.1/16")
	homeAddr := wgaddr.MustParseWGAddress("100.72.0.1/16")
	_, detachWork, err := attachTestSession(t, host, "work", workAddr)
	require.NoError(t, err)
	t.Cleanup(detachWork)
	_, detachHome, err := attachTestSession(t, host, "home", homeAddr)
	require.NoError(t, err)
	t.Cleanup(detachHome)

	routeAddr := netip.MustParsePrefix("10.9.0.1/24")
	// The second address stands for another peer of the network: on a routing peer the tuple has its
	// address and the one of the routed resource, and none of the host's own overlay address.
	workPeer := netip.MustParseAddr("100.71.0.5")
	addFlowLink(t, "wt0", netip.PrefixFrom(workAddr.IP, workAddr.Network.Bits()), netip.PrefixFrom(workPeer, 32))
	addFlowLink(t, "wt1", netip.PrefixFrom(homeAddr.IP, homeAddr.Network.Bits()))
	addFlowLink(t, flowRouteLink, routeAddr)

	workKey := hostcoord.SessionKey{Profile: profilemanager.ID("work")}
	homeKey := hostcoord.SessionKey{Profile: profilemanager.ID("home")}
	work := startFlowSession(t, "wt0", workAddr, host.Session(workKey).conntrackOptions())
	home := startFlowSession(t, "wt1", homeAddr, host.Session(homeKey).conntrackOptions())
	var noGate *SessionHost
	control := startFlowSession(t, "wt0", workAddr, noGate.conntrackOptions())

	const (
		homePort     uint16 = 41001
		routePort    uint16 = 41002
		mixedPort    uint16 = 41003
		workPort     uint16 = 41004
		routedPort   uint16 = 41005
		homeLastPort uint16 = 41006
		workLastPort uint16 = 41007
	)
	sendFlow(t, homeAddr.IP, netip.MustParseAddr("100.72.0.9"), homePort)
	sendFlow(t, routeAddr.Addr(), netip.MustParseAddr("10.9.0.9"), routePort)
	// A local process can send from the address of one network to a peer of the other. The flow
	// carries the addresses of both and belongs to neither.
	sendFlow(t, workAddr.IP, netip.MustParseAddr("100.72.0.9"), mixedPort)
	sendFlow(t, workAddr.IP, netip.MustParseAddr("100.71.0.9"), workPort)
	sendFlow(t, workPeer, netip.MustParseAddr("10.9.0.9"), routedPort)
	// The events come in order, so once these two arrived the ones before them have been decided.
	sendFlow(t, homeAddr.IP, netip.MustParseAddr("100.72.0.9"), homeLastPort)
	sendFlow(t, workAddr.IP, netip.MustParseAddr("100.71.0.9"), workLastPort)

	require.Eventually(t, func() bool { return work.sawPort(workLastPort) }, flowEventWait, 50*time.Millisecond,
		"the flow of work should reach its logger")
	require.Eventually(t, func() bool { return home.sawPort(homeLastPort) }, flowEventWait, 50*time.Millisecond,
		"the flow of home should reach its logger")
	require.Eventually(t, func() bool { return control.sawPort(workLastPort) }, flowEventWait, 50*time.Millisecond,
		"the tracker without the gate should get the same events")

	assert.True(t, work.sawPort(workPort), "the first flow of work should have reached its logger")
	assert.True(t, home.sawPort(homePort), "the first flow of home should have reached its logger")
	assert.True(t, work.sawPort(routedPort), "a flow of another peer of work to a routed resource is a flow of work")
	assert.True(t, control.sawPort(homePort), "without the gate the mark decides, as it does today, so the flow of home counts")
	assert.True(t, control.sawPort(routePort), "without the gate a marked flow without an overlay address counts")
	assert.True(t, control.sawPort(mixedPort), "without the gate the flow between the networks counts")

	assert.False(t, work.sawPort(homePort), "a flow of home must not reach the logger of work, whatever its mark says")
	assert.False(t, work.sawAddress(homeAddr.Network), "no address of home may reach the logger of work")
	assert.False(t, home.sawPort(workPort), "a flow of work must not reach the logger of home")
	assert.False(t, home.sawAddress(workAddr.Network), "no address of work may reach the logger of home")
	assert.False(t, work.sawPort(routePort), "a flow without an overlay address is not reported with the gate")
	assert.False(t, home.sawPort(routePort), "a flow without an overlay address is not reported with the gate")
	assert.False(t, work.sawPort(mixedPort), "a flow between the networks is not reported with the gate")
	assert.False(t, home.sawPort(mixedPort), "a flow between the networks is not reported with the gate")
	assert.False(t, home.sawPort(routedPort), "a routed flow of work must not reach the logger of home")
}

// The overlay of a session can have two families and each of them says whose flow it is.
func TestSessionFlowsStayWithTheirNetworkOnIPv6(t *testing.T) {
	host := newTestDaemonHost(t)

	workConfig, detachWork, err := attachTestSession(t, host, "work", v6Address(t, "100.71.0.1/16", "fd00:71::1/64"))
	require.NoError(t, err)
	t.Cleanup(detachWork)
	homeConfig, detachHome, err := attachTestSession(t, host, "home", v6Address(t, "100.72.0.1/16", "fd00:72::1/64"))
	require.NoError(t, err)
	t.Cleanup(detachHome)
	workAddr, homeAddr := workConfig.WgAddr, homeConfig.WgAddr
	require.True(t, workAddr.HasIPv6(), "the first session should keep its IPv6 overlay")
	require.True(t, homeAddr.HasIPv6(), "the second session should keep its IPv6 overlay")

	addFlowLink(t, "wt0", netip.PrefixFrom(workAddr.IPv6, workAddr.IPv6Net.Bits()))
	addFlowLink(t, "wt1", netip.PrefixFrom(homeAddr.IPv6, homeAddr.IPv6Net.Bits()))

	workKey := hostcoord.SessionKey{Profile: profilemanager.ID("work")}
	homeKey := hostcoord.SessionKey{Profile: profilemanager.ID("home")}
	work := startFlowSession(t, "wt0", workAddr, host.Session(workKey).conntrackOptions())
	home := startFlowSession(t, "wt1", homeAddr, host.Session(homeKey).conntrackOptions())

	const (
		homePort     uint16 = 41101
		mixedPort    uint16 = 41102
		workPort     uint16 = 41103
		homeLastPort uint16 = 41104
	)
	workPeer, homePeer := netip.MustParseAddr("fd00:71::9"), netip.MustParseAddr("fd00:72::9")
	sendFlow(t, homeAddr.IPv6, homePeer, homePort)
	sendFlow(t, workAddr.IPv6, homePeer, mixedPort)
	sendFlow(t, homeAddr.IPv6, homePeer, homeLastPort)
	sendFlow(t, workAddr.IPv6, workPeer, workPort)

	require.Eventually(t, func() bool { return work.sawPort(workPort) }, flowEventWait, 50*time.Millisecond,
		"the flow of work should reach its logger")
	require.Eventually(t, func() bool { return home.sawPort(homeLastPort) }, flowEventWait, 50*time.Millisecond,
		"the flow of home should reach its logger")

	assert.True(t, home.sawPort(homePort), "the first flow of home should have reached its logger")
	assert.False(t, work.sawPort(homePort), "a flow of home must not reach the logger of work")
	assert.False(t, work.sawAddress(homeAddr.IPv6Net), "no address of home may reach the logger of work")
	assert.False(t, home.sawAddress(workAddr.IPv6Net), "no address of work may reach the logger of home")
	assert.False(t, work.sawPort(mixedPort), "a flow between the networks is not reported with the gate")
	assert.False(t, home.sawPort(mixedPort), "a flow between the networks is not reported with the gate")
}
