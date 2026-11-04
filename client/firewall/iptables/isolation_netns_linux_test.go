//go:build privileged

package iptables

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/netbirdio/netbird/client/iface/wgaddr"
)

const (
	// Long enough for a neighbor lookup, short enough for many probes that must not arrive.
	isoProbeTimeout  = 600 * time.Millisecond
	isoProbeInterval = 40 * time.Millisecond
	isoProbePort     = 7777
)

// isoNS is a network namespace for one side of a test topology. A nil isoNS is the namespace
// the test runs in, which plays the host running the sessions.
type isoNS struct {
	file *os.File
}

func newIsoNS(t *testing.T) *isoNS {
	t.Helper()
	opened := make(chan error, 1)
	ns := &isoNS{}
	go func() {
		// The thread never returns to the pool, its namespace would leak into other goroutines.
		runtime.LockOSThread()
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			opened <- fmt.Errorf("unshare: %w", err)
			return
		}
		file, err := os.Open("/proc/thread-self/ns/net")
		if err != nil {
			opened <- fmt.Errorf("open namespace: %w", err)
			return
		}
		ns.file = file
		opened <- nil
	}()
	require.NoError(t, <-opened)
	t.Cleanup(func() { _ = ns.file.Close() })

	ns.run(t, func() error {
		lo, err := netlink.LinkByName("lo")
		if err != nil {
			return fmt.Errorf("find lo: %w", err)
		}
		return netlink.LinkSetUp(lo)
	})
	return ns
}

// run executes fn on a thread inside the namespace. Sockets opened there stay in the
// namespace and can be used from any goroutine afterwards.
func (n *isoNS) run(t *testing.T, fn func() error) {
	t.Helper()
	if n == nil {
		require.NoError(t, fn())
		return
	}
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		if err := unix.Setns(int(n.file.Fd()), unix.CLONE_NEWNET); err != nil {
			done <- fmt.Errorf("enter namespace: %w", err)
			return
		}
		done <- fn()
	}()
	require.NoError(t, <-done)
}

func writeSysctl(path, value string) error {
	return os.WriteFile("/proc/sys/net/"+path, []byte(value), 0o644)
}

func allowAsymmetricTraffic(link string) error {
	for _, name := range []string{"all", "default", link} {
		if err := writeSysctl("ipv4/conf/"+name+"/rp_filter", "0"); err != nil {
			return fmt.Errorf("disable rp_filter on %s: %w", name, err)
		}
	}
	return nil
}

func enableIPv6(link string) {
	// A soft failure: hosts without v6 run the v4 half of every test.
	for _, name := range []string{"all", "default", link} {
		_ = writeSysctl("ipv6/conf/"+name+"/disable_ipv6", "0")
	}
}

func addNodadAddr(link netlink.Link, addr netip.Addr, bits int) error {
	ipnet := &net.IPNet{IP: addr.AsSlice(), Mask: net.CIDRMask(bits, addr.BitLen())}
	return netlink.AddrAdd(link, &netlink.Addr{IPNet: ipnet, Flags: unix.IFA_F_NODAD})
}

func addRoute(link netlink.Link, dst netip.Prefix, gateway netip.Addr) error {
	ipnet := &net.IPNet{IP: dst.Addr().AsSlice(), Mask: net.CIDRMask(dst.Bits(), dst.Addr().BitLen())}
	return netlink.RouteAdd(&netlink.Route{LinkIndex: link.Attrs().Index, Dst: ipnet, Gw: gateway.AsSlice()})
}

// isoNetwork is one overlay as the host sees it: an interface named like a session interface
// and a peer in its own namespace behind it, with a route to a network only that peer reaches.
type isoNetwork struct {
	slot   uint
	name   string
	addr   wgaddr.Address
	ns     *isoNS
	peer4  netip.Addr
	peer6  netip.Addr
	behind netip.Prefix
}

func (n *isoNetwork) ifaceMock() *iFaceMock {
	return &iFaceMock{
		NameFunc:    func() string { return n.name },
		AddressFunc: func() wgaddr.Address { return n.addr },
	}
}

func isoAddress(slot uint) wgaddr.Address {
	second := byte(slot + 96)
	return wgaddr.Address{
		IP:      netip.AddrFrom4([4]byte{100, second, 0, 1}),
		Network: netip.PrefixFrom(netip.AddrFrom4([4]byte{100, second, 0, 0}), 16),
		IPv6:    netip.AddrFrom16([16]byte{0xfd, 0x00, 0x1b, second, 15: 1}),
		IPv6Net: netip.PrefixFrom(netip.AddrFrom16([16]byte{0xfd, 0x00, 0x1b, second}), 64),
	}
}

func newIsoNetwork(t *testing.T, slot uint) *isoNetwork {
	t.Helper()
	return newIsoNetworkWithAddress(t, slot, isoAddress(slot))
}

func newIsoNetworkV4Only(t *testing.T, slot uint) *isoNetwork {
	t.Helper()
	addr := isoAddress(slot)
	addr.IPv6 = netip.Addr{}
	addr.IPv6Net = netip.Prefix{}
	return newIsoNetworkWithAddress(t, slot, addr)
}

func newIsoNetworkWithAddress(t *testing.T, slot uint, addr wgaddr.Address) *isoNetwork {
	t.Helper()
	n := &isoNetwork{
		slot:   slot,
		name:   fmt.Sprintf("wt%d", slot),
		addr:   addr,
		ns:     newIsoNS(t),
		peer4:  addr.IP.Next(),
		peer6:  addr.IPv6.Next(),
		behind: netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 99, byte(slot), 1}), 24),
	}
	connectIsoPeer(t, n.name, n.ns, addr, n.peer4, n.peer6)

	link, err := netlink.LinkByName(n.name)
	require.NoError(t, err)
	require.NoError(t, addRoute(link, n.behind.Masked(), n.peer4))

	n.ns.run(t, func() error {
		lo, err := netlink.LinkByName("lo")
		if err != nil {
			return fmt.Errorf("find lo: %w", err)
		}
		return addNodadAddr(lo, n.behind.Addr(), 32)
	})
	return n
}

// connectIsoPeer links the host and a peer namespace with a veth pair and points the peer at
// the host for everything off-link.
func connectIsoPeer(t *testing.T, name string, ns *isoNS, addr wgaddr.Address, peer4, peer6 netip.Addr) {
	t.Helper()
	veth := &netlink.Veth{
		LinkAttrs:     netlink.LinkAttrs{Name: name},
		PeerName:      "peer0",
		PeerNamespace: netlink.NsFd(int(ns.file.Fd())),
	}
	require.NoError(t, netlink.LinkAdd(veth), "create veth %s", name)
	t.Cleanup(func() { _ = netlink.LinkDel(veth) })

	link, err := netlink.LinkByName(name)
	require.NoError(t, err)
	enableIPv6(name)
	require.NoError(t, allowAsymmetricTraffic(name))
	require.NoError(t, addNodadAddr(link, addr.IP, addr.Network.Bits()))
	require.NoError(t, netlink.LinkSetUp(link))

	hasV6 := addr.IPv6.IsValid() && peer6.IsValid()
	if hasV6 {
		require.NoError(t, addNodadAddr(link, addr.IPv6, addr.IPv6Net.Bits()))
	}

	hostMAC := link.Attrs().HardwareAddr
	var peerMAC net.HardwareAddr
	ns.run(t, func() error {
		peer, err := netlink.LinkByName("peer0")
		if err != nil {
			return fmt.Errorf("find peer link: %w", err)
		}
		peerMAC = peer.Attrs().HardwareAddr
		enableIPv6("peer0")
		if err := allowAsymmetricTraffic("peer0"); err != nil {
			return err
		}
		if err := addNodadAddr(peer, peer4, addr.Network.Bits()); err != nil {
			return fmt.Errorf("add peer address: %w", err)
		}
		if err := netlink.LinkSetUp(peer); err != nil {
			return fmt.Errorf("bring up peer: %w", err)
		}
		if err := addRoute(peer, netip.MustParsePrefix("0.0.0.0/0"), addr.IP); err != nil {
			return fmt.Errorf("add default route: %w", err)
		}
		if !hasV6 {
			return nil
		}
		if err := addNodadAddr(peer, peer6, addr.IPv6Net.Bits()); err != nil {
			return fmt.Errorf("add peer v6 address: %w", err)
		}
		if err := addRoute(peer, netip.MustParsePrefix("::/0"), addr.IPv6); err != nil {
			return fmt.Errorf("add v6 default route: %w", err)
		}
		return addStaticNeighbor(peer, addr.IPv6, hostMAC)
	})
	if hasV6 {
		// A tunnel has no neighbor discovery, and the ACLs of a manager do not let it pass.
		require.NoError(t, addStaticNeighbor(link, peer6, peerMAC))
	}
}

func addStaticNeighbor(link netlink.Link, addr netip.Addr, mac net.HardwareAddr) error {
	return netlink.NeighAdd(&netlink.Neigh{
		LinkIndex:    link.Attrs().Index,
		State:        netlink.NUD_PERMANENT,
		IP:           addr.AsSlice(),
		HardwareAddr: mac,
	})
}

// enableHostForwarding lets the namespace of the test route between its interfaces, the state
// a routing peer runs in.
func enableHostForwarding(t *testing.T) {
	t.Helper()
	require.NoError(t, writeSysctl("ipv4/ip_forward", "1"))
	enableIPv6("lo")
	_ = writeSysctl("ipv6/conf/all/forwarding", "1")
}

// isoFlow is a UDP socket pair between two namespaces. It keeps its ports, so once traffic went
// both ways every later datagram belongs to an established conntrack flow.
type isoFlow struct {
	client *net.UDPConn
	server *net.UDPConn
	dst    netip.AddrPort
	src    netip.AddrPort
}

func newIsoFlow(t *testing.T, srcNS *isoNS, src netip.Addr, dstNS *isoNS, dst netip.Addr, port uint16) *isoFlow {
	t.Helper()
	flow := &isoFlow{
		dst: netip.AddrPortFrom(dst, port),
		src: netip.AddrPortFrom(src, port+1),
	}
	dstNS.run(t, func() error {
		conn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(flow.dst))
		if err != nil {
			return fmt.Errorf("listen on destination: %w", err)
		}
		flow.server = conn
		return nil
	})
	t.Cleanup(func() { _ = flow.server.Close() })
	srcNS.run(t, func() error {
		conn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(flow.src))
		if err != nil {
			return fmt.Errorf("listen on source: %w", err)
		}
		flow.client = conn
		return nil
	})
	t.Cleanup(func() { _ = flow.client.Close() })
	return flow
}

func (f *isoFlow) forward() bool {
	return deliver(f.client, f.server, f.dst)
}

func (f *isoFlow) reply() bool {
	return deliver(f.server, f.client, f.src)
}

// deliver reports whether a datagram sent from one socket came out of the other. It sends
// repeatedly since a first packet can be lost while a neighbor resolves.
func deliver(from, to *net.UDPConn, dst netip.AddrPort) bool {
	payload := []byte(fmt.Sprintf("probe-%d", time.Now().UnixNano()))
	deadline := time.Now().Add(isoProbeTimeout)
	buf := make([]byte, 128)
	for time.Now().Before(deadline) {
		// A refused or unreachable destination only shows that this attempt did not arrive.
		_, _ = from.WriteToUDPAddrPort(payload, dst)
		_ = to.SetReadDeadline(time.Now().Add(isoProbeInterval))
		n, _, err := to.ReadFromUDPAddrPort(buf)
		if err == nil && bytes.Equal(buf[:n], payload) {
			return true
		}
	}
	return false
}

// reaches opens a throwaway flow and reports whether a datagram gets through.
func reaches(t *testing.T, srcNS *isoNS, src netip.Addr, dstNS *isoNS, dst netip.Addr) bool {
	t.Helper()
	return newIsoFlow(t, srcNS, src, dstNS, dst, nextIsoPort()).forward()
}

var isoPortCounter uint16 = isoProbePort

func nextIsoPort() uint16 {
	isoPortCounter += 2
	return isoPortCounter
}

func hostIPNet(addr netip.Addr) *net.IPNet {
	return &net.IPNet{IP: addr.AsSlice(), Mask: net.CIDRMask(addr.BitLen(), addr.BitLen())}
}

// reachesHost listens on every address of the host, so it also shows whether a packet to an
// address the host no longer has would be delivered locally.
func reachesHost(t *testing.T, srcNS *isoNS, src, dst netip.Addr) bool {
	t.Helper()
	port := nextIsoPort()
	server, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.IPv6Unspecified(), port)))
	require.NoError(t, err)
	t.Cleanup(func() { _ = server.Close() })

	var client *net.UDPConn
	srcNS.run(t, func() error {
		conn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(src, port+1)))
		if err != nil {
			return fmt.Errorf("listen on source: %w", err)
		}
		client = conn
		return nil
	})
	t.Cleanup(func() { _ = client.Close() })
	return deliver(client, server, netip.AddrPortFrom(dst, port))
}

func isoV6Address(slot uint, overlay6 string) wgaddr.Address {
	prefix := netip.MustParsePrefix(overlay6)
	addr := isoAddress(slot)
	addr.IPv6 = prefix.Addr()
	addr.IPv6Net = prefix.Masked()
	return addr
}

type isoV6Overlap struct {
	name          string
	first, second wgaddr.Address
}

// isoV6Overlaps are the shapes of an overlap: the kernel sets and rules differ for an address
// inside and outside the prefix of the session that was first.
func isoV6Overlaps() []isoV6Overlap {
	return []isoV6Overlap{
		{"same prefix", isoV6Address(1, "fd00:aa::1/64"), isoV6Address(2, "fd00:aa::10/64")},
		{"wider prefix, address outside the first", isoV6Address(1, "fd00:aa::1/64"), isoV6Address(2, "fd00:aa:0:1::10/48")},
		{"narrower prefix inside the first", isoV6Address(1, "fd00:aa::1/48"), isoV6Address(2, "fd00:aa:0:1::10/64")},
	}
}

// connectOverlappingPeers gives both peers a way to the addresses of the other network, which
// they may see as on-link, and the host a route to each peer that survives the removal of an
// address. A tunnel has no neighbor discovery to rely on either.
func connectOverlappingPeers(t *testing.T, networks ...*isoNetwork) {
	t.Helper()
	for _, n := range networks {
		link, err := netlink.LinkByName(n.name)
		require.NoError(t, err)
		require.NoError(t, netlink.RouteAdd(&netlink.Route{LinkIndex: link.Attrs().Index, Dst: hostIPNet(n.peer6)}))

		hostMAC := link.Attrs().HardwareAddr
		n.ns.run(t, func() error {
			peer, err := netlink.LinkByName("peer0")
			if err != nil {
				return fmt.Errorf("find peer link: %w", err)
			}
			for _, other := range networks {
				if other == n {
					continue
				}
				for _, addr := range []netip.Addr{other.addr.IPv6, other.peer6} {
					if err := addStaticNeighbor(peer, addr, hostMAC); err != nil {
						return fmt.Errorf("add neighbor %s: %w", addr, err)
					}
				}
			}
			return nil
		})
	}
}

// dropOwnIPv6 is what a session has to do when the isolation reports its IPv6 as disabled.
func dropOwnIPv6(t *testing.T, n *isoNetwork) {
	t.Helper()
	link, err := netlink.LinkByName(n.name)
	require.NoError(t, err)
	ipnet := &net.IPNet{IP: n.addr.IPv6.AsSlice(), Mask: net.CIDRMask(n.addr.IPv6Net.Bits(), n.addr.IPv6.BitLen())}
	require.NoError(t, netlink.AddrDel(link, &netlink.Addr{IPNet: ipnet}))
}
