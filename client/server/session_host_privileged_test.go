//go:build privileged && linux

package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/netbirdio/netbird/client/firewall"
	nbiptables "github.com/netbirdio/netbird/client/firewall/iptables"
	fwmanager "github.com/netbirdio/netbird/client/firewall/manager"
	nbnftables "github.com/netbirdio/netbird/client/firewall/nftables"
	"github.com/netbirdio/netbird/client/firewall/uspfilter"
	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/netstack"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/hostcoord"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
)

// sessionsFixture is a daemon with the gate and two profiles, each registered with a Management
// of its own.
type sessionsFixture struct {
	s        *Server
	ctx      context.Context
	username string
	work     string
	home     string
	// signalAddr is the Signal both networks use, for a test that adds a network.
	signalAddr string
}

func newSessionsFixture(t *testing.T) *sessionsFixture {
	t.Helper()
	// Userspace mode with a native firewall: the kernel sees the same interface, and a packet can
	// be handed to it as if it came from a peer.
	t.Setenv("NB_WG_KERNEL_DISABLED", "true")
	return newSessionsFixtureInMode(t)
}

func newSessionsFixtureInMode(t *testing.T) *sessionsFixture {
	t.Helper()
	t.Setenv("NB_DNS_STATE_FILE", "")
	t.Setenv(netstack.EnvUseNetstackMode, "false")

	s, ctx, work, username, cfgPath := setupServerWithProfile(t)
	rootCtx, cancelRoot := context.WithCancel(ctx)
	s.rootCtx = rootCtx
	s.sessionSet = newSessionSet(true)
	s.localMetrics = s.newLocalMetrics(rootCtx)
	t.Cleanup(cancelRoot)

	dir := filepath.Dir(cfgPath)
	_, signalAddr, err := startSignal(t)
	require.NoError(t, err)

	const home = "home"
	startNetwork(t, ctx, dir, work, signalAddr, networkWork)
	startNetwork(t, ctx, dir, home, signalAddr, networkHome)

	// A stored session that stays down keeps the start from connecting the active profile.
	writeDesiredSessions(t, map[profilemanager.SessionKey]hostcoord.DesiredState{
		{Profile: profilemanager.ID(work), Username: username}: hostcoord.DesiredDown,
	})
	require.NoError(t, s.Start())
	return &sessionsFixture{s: s, ctx: ctx, username: username, work: work, home: home, signalAddr: signalAddr}
}

func (f *sessionsFixture) session(t *testing.T, profile string) *session {
	t.Helper()
	key := sessionKeyOf(profilemanager.ID(profile), f.username)
	f.s.mutex.Lock()
	defer f.s.mutex.Unlock()
	ss, ok := f.s.sessions[key]
	require.Truef(t, ok, "profile %s should have a session", profile)
	return ss
}

func (f *sessionsFixture) down(t *testing.T, ss *session) {
	t.Helper()
	require.NoError(t, f.s.downSession(f.ctx, ss), "take the session down")
	awaitRunEnd(t, ss)
}

// awaitRoute waits until the shared table has prefix through dev.
func awaitRoute(t *testing.T, prefix netip.Prefix, dev string) {
	t.Helper()
	want := fmt.Sprintf("table=%d dst=%s dev=%s", hostFixtureTable, prefix, dev)
	require.Eventuallyf(t, func() bool {
		return len(linesWith(snapshotRoutes(t), want)) > 0
	}, 30*time.Second, 100*time.Millisecond, "the table should get %s", want)
}

func requireInterfaceAddress(t *testing.T, name string, overlay netip.Prefix, ss *session) {
	t.Helper()
	link, err := netlink.LinkByName(name)
	require.NoErrorf(t, err, "interface %s should exist", name)
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	require.NoError(t, err)
	require.Len(t, addrs, 1, "interface %s should have one IPv4 address", name)

	got, ok := netip.AddrFromSlice(addrs[0].IP.To4())
	require.True(t, ok)
	assert.True(t, overlay.Contains(got), "interface %s should have an address of its network, has %s", name, got)
	assert.Equal(t, localOverlayAddr(t, ss), got, "interface %s should have the address of its session", name)
}

// sessionPart is what belongs to one session in a snapshot: everything naming its interface or
// its tables, or the addresses of its network.
func sessionPart(snapshot hostSnapshot, names ...string) map[string][]string {
	part := make(map[string][]string, len(snapshot))
	for _, section := range []string{"links", "routes", "nftables", "iptables"} {
		part[section] = linesWith(snapshot[section], names...)
	}
	part["rules"] = snapshot["rules"]
	return part
}

// Two networks on real engines, the acceptance scenario of the spec: each session gets its own
// interface and address next to the other one, stopping one leaves the routes, the firewall and
// the DNS of the other as they were, and after the last one the host is what it was before.
//
// The native firewall of the host runs in both modes of the interface.
func TestTwoSessionsOnRealEngines(t *testing.T) {
	for _, mode := range []struct {
		name  string
		setup func(t *testing.T)
	}{
		{name: "userspace", setup: func(t *testing.T) { t.Setenv("NB_WG_KERNEL_DISABLED", "true") }},
		{name: "kernel", setup: requireKernelInterface},
	} {
		for _, backend := range hostBackends {
			t.Run(mode.name+"/"+backend.name, func(t *testing.T) {
				mode.setup(t)
				backend.setup(t)
				runTwoSessions(t)
			})
		}
	}
}

func requireKernelInterface(t *testing.T) {
	t.Helper()
	t.Setenv("NB_WG_KERNEL_DISABLED", "false")
	if !device.WireGuardModuleIsLoaded() {
		t.Skip("kernel WireGuard is not available in this container")
	}
}

func runTwoSessions(t *testing.T) {
	clean := takeHostSnapshot(t, identityLine)
	f := newSessionsFixtureInMode(t)

	// Started in sequence: the first session owns the host DNS and the shared route.
	upProfile(t, f.ctx, f.s, f.work, f.username)
	work := f.session(t, f.work)
	awaitConnected(t, work, f.work)
	keepRouterConnected(t, work.statusRecorder)
	awaitRoute(t, networkWork.shared, "wt0")
	resolvWithWork := snapshotResolvConf(t)

	upProfile(t, f.ctx, f.s, f.home, f.username)
	home := f.session(t, f.home)
	awaitConnected(t, home, f.home)
	keepRouterConnected(t, home.statusRecorder)

	requireInterfaceAddress(t, "wt0", networkWork.overlay, work)
	requireInterfaceAddress(t, "wt1", networkHome.overlay, home)
	awaitRoute(t, networkWork.route, "wt0")
	awaitRoute(t, networkHome.route, "wt1")
	assert.Empty(t, linesWith(snapshotRoutes(t), networkWork.shared.String()+" dev=wt1"), "the second session waits for the shared prefix")
	assert.Equal(t, resolvWithWork, snapshotResolvConf(t), "the host DNS stays with the first session")

	owner, held := f.s.host.Coordinator().DNSOwners().HostDNSOwner()
	assert.True(t, held, "a primary nameserver should claim the host DNS")
	assert.Equal(t, work.key, owner, "the first session should own the host DNS")

	// Each session has the resources of its slot, and the configs still say "automatic".
	for key, want := range map[profilemanager.SessionKey]struct {
		iface string
		port  uint16
	}{work.key: {"wt0", 51820}, home.key: {"wt1", 51821}} {
		resources, running := f.s.slots.Running(key)
		require.True(t, running)
		assert.Equal(t, want.iface, resources.Interface)
		assert.Equal(t, want.port, resources.Port)

		stored, err := profilemanager.GetExistingConfig(filepath.Join(profilemanager.DefaultConfigPathDir, string(key.Profile)+".json"))
		require.NoError(t, err)
		assert.Equal(t, iface.WgInterfaceDefault, stored.WgIface, "the name of the slot must not be written back")
		assert.Equal(t, iface.DefaultWgPort, stored.WgPort, "the port of the slot must not be written back")
	}
	assert.NotEqual(t, f.s.profileManager.GetStatePathFor(work.key), f.s.profileManager.GetStatePathFor(home.key), "each session has its own state file")
	assert.NoError(t, f.s.host.Isolation().Verify())

	statuses := f.s.sessionStatuses(f.s.callerOf(f.ctx), work, internal.StatusConnected, false)
	names := make(map[string]string, len(statuses))
	for _, status := range statuses {
		names[status.ProfileId] = status.InterfaceName
	}
	assert.Equal(t, map[string]string{f.work: "wt0", f.home: "wt1"}, names, "the status should name the interface each session runs on")

	// Stopping the session that does not own the DNS and the shared prefix.
	withHome := takeHostSnapshot(t, identityLine)
	f.down(t, home)
	afterHome := takeHostSnapshot(t, identityLine)
	assert.Equal(t, sessionPart(withHome, "wt0", "netbird\"", "netbird chain", "100.71."), sessionPart(afterHome, "wt0", "netbird\"", "netbird chain", "100.71."),
		"stopping the second session should leave what belongs to the first as it was")
	assert.Equal(t, withHome["resolv"], afterHome["resolv"], "stopping the second session should leave the DNS of the first")
	assert.Empty(t, linesWith(afterHome["links"], "wt1"), "the interface of the stopped session should be gone")

	// And the other way round: the owner leaves, the routes of the other session stay and it
	// takes over the shared prefix.
	upProfile(t, f.ctx, f.s, f.home, f.username)
	awaitConnected(t, home, f.home)
	awaitRoute(t, networkHome.route, "wt1")
	withWork := takeHostSnapshot(t, identityLine)

	f.down(t, work)
	awaitRoute(t, networkHome.shared, "wt1")
	afterWork := takeHostSnapshot(t, identityLine)
	wantHome := sessionPart(withWork, "wt1", "netbird-1", "100.72.")
	gotHome := sessionPart(afterWork, "wt1", "netbird-1", "100.72.")
	gotHome["routes"] = slices.DeleteFunc(gotHome["routes"], func(line string) bool { return strings.Contains(line, networkHome.shared.String()) })
	assert.Equal(t, wantHome, gotHome, "stopping the first session should leave what belongs to the second as it was")
	assert.Empty(t, linesWith(afterWork["links"], "wt0"), "the interface of the stopped session should be gone")
	assert.Empty(t, linesWith(afterWork["routes"], "dev=wt0"), "the routes of the stopped session should be gone")

	// I7: the last session takes everything with it.
	f.down(t, home)
	assert.Equal(t, clean.withoutEmptyBuiltins(), takeHostSnapshot(t, identityLine).withoutEmptyBuiltins(),
		"after the last session the host should be what it was before the first")
}

// Sessions that come and go at the same moment: the allocation and the shared state take it in turn,
// and the host ends up clean.
func TestSessionsStartAndStopTogether(t *testing.T) {
	for _, backend := range hostBackends {
		t.Run(backend.name, func(t *testing.T) {
			backend.setup(t)
			clean := takeHostSnapshot(t, identityLine)
			f := newSessionsFixture(t)

			for range 3 {
				var wg sync.WaitGroup
				for _, profile := range []string{f.work, f.home} {
					wg.Add(1)
					go func(profile string) {
						defer wg.Done()
						_, err := f.s.Up(f.ctx, &proto.UpRequest{ProfileName: &profile, Username: &f.username, Async: true})
						assert.NoError(t, err, "Up of profile %s", profile)
					}(profile)
				}
				wg.Wait()

				work, home := f.session(t, f.work), f.session(t, f.home)
				awaitConnected(t, work, f.work)
				awaitConnected(t, home, f.home)
				assert.NoError(t, f.s.host.Isolation().Verify())

				_, err := f.s.Down(f.ctx, &proto.DownRequest{All: true})
				require.NoError(t, err)
				awaitRunEnd(t, work)
				awaitRunEnd(t, home)
			}

			assert.Equal(t, clean.withoutEmptyBuiltins(), takeHostSnapshot(t, identityLine).withoutEmptyBuiltins(),
				"after the last session the host should be what it was before the first")
		})
	}
}

func identityLine(line string) string {
	return line
}

// setIPForward makes the host start with forwarding off, so that the restore shows.
func setIPForward(t *testing.T, value string) {
	t.Helper()
	const path = "/proc/sys/net/ipv4/ip_forward"
	original, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, []byte(value), 0o644))
	t.Cleanup(func() {
		if err := os.WriteFile(path, original, 0o644); err != nil {
			t.Logf("restore %s: %v", path, err)
		}
	})
}

func readIPForward(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	require.NoError(t, err)
	return strings.TrimSpace(string(raw))
}

// udpPacket builds what a peer would send through the tunnel.
func udpPacket(t *testing.T, src, dst netip.Addr, srcPort, dstPort uint16) []byte {
	t.Helper()
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: src.AsSlice(), DstIP: dst.AsSlice()}
	udp := &layers.UDP{SrcPort: layers.UDPPort(srcPort), DstPort: layers.UDPPort(dstPort)}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	require.NoError(t, gopacket.SerializeLayers(buf, opts, ip, udp, gopacket.Payload("isolation probe")))
	return buf.Bytes()
}

// probeListener receives what reaches a local UDP port.
type probeListener struct {
	received chan netip.Addr
}

func listenProbe(t *testing.T, port uint16) *probeListener {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: int(port)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	probe := &probeListener{received: make(chan netip.Addr, 16)}
	go func() {
		buf := make([]byte, 1500)
		for {
			if _, _, err := conn.ReadFromUDPAddrPort(buf); err != nil {
				return
			}
			probe.received <- netip.Addr{}
		}
	}()
	return probe
}

func (p *probeListener) delivered() bool {
	select {
	case <-p.received:
		return true
	case <-time.After(time.Second):
		return false
	}
}

// drain forgets what arrived so far, for a check of what arrives from now on.
func (p *probeListener) drain() {
	for {
		select {
		case <-p.received:
		default:
			return
		}
	}
}

// interfaceSniffer sees what the kernel sends out of an interface, the way to tell a forwarded
// packet from a dropped one.
type interfaceSniffer struct {
	fd int
}

func sniffInterface(t *testing.T, name string) *interfaceSniffer {
	t.Helper()
	link, err := netlink.LinkByName(name)
	require.NoError(t, err)

	// The protocol goes in network byte order.
	proto := (unix.ETH_P_ALL&0xff)<<8 | unix.ETH_P_ALL>>8
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM, proto)
	require.NoError(t, err)
	t.Cleanup(func() { _ = unix.Close(fd) })
	require.NoError(t, unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: uint16(proto), Ifindex: link.Attrs().Index}))
	timeout := unix.NsecToTimeval(int64(200 * time.Millisecond))
	require.NoError(t, unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout))
	return &interfaceSniffer{fd: fd}
}

// sawPacket reports whether a packet for the UDP port dst leaves the interface within a second.
func (s *interfaceSniffer) sawPacket(dst netip.Addr, port uint16) bool {
	buf := make([]byte, 2048)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		n, _, err := unix.Recvfrom(s.fd, buf, 0)
		if err != nil || n < 28 {
			continue
		}
		packet := gopacket.NewPacket(buf[:n], layers.LayerTypeIPv4, gopacket.Default)
		ip, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		if !ok || !ip.DstIP.Equal(dst.AsSlice()) {
			continue
		}
		if udp, ok := packet.Layer(layers.LayerTypeUDP).(*layers.UDP); ok && uint16(udp.DstPort) == port {
			return true
		}
	}
	return false
}

// sessionSide is one end of the isolation the packets test.
type sessionSide struct {
	ss      *session
	iface   string
	network hostNetwork
}

func (side sessionSide) inject(t *testing.T, packet []byte) {
	t.Helper()
	engine := side.ss.client().Engine()
	require.NotNil(t, engine, "the session should have an engine")
	require.NoError(t, engine.InjectFromPeer(packet), "hand the packet to the interface")
}

// requireReachesOwnAddress proves the way in works. The session reports connected before the first
// network map brings the ACL that lets the peer in, so it takes a few tries.
func (side sessionSide) requireReachesOwnAddress(t *testing.T, probe *probeListener, port uint16) {
	t.Helper()
	own := udpPacket(t, side.network.router, localOverlayAddr(t, side.ss), 40000, port)
	for range 30 {
		side.inject(t, own)
		if probe.delivered() {
			return
		}
	}
	t.Fatalf("a peer of %s should reach the host by the address of its own network", side.iface)
}

func (side sessionSide) address(t *testing.T) wgaddr.Address {
	t.Helper()
	addr, err := wgaddr.ParseWGAddress(side.ss.statusRecorder.GetLocalPeerState().IP)
	require.NoError(t, err)
	return addr
}

// assertIsolated sends what a peer of from could send towards the network of to, and checks that
// it gets through only with from taken out of the isolation. Without that control a drop could
// have any other cause. The packets stay of one flow, which the conntrack remembers by the end:
// an established flow must not get past the isolation either.
func assertIsolated(t *testing.T, f *sessionsFixture, from, to sessionSide, basePort uint16) {
	t.Helper()
	isolation := f.s.host.Isolation()
	require.NoError(t, isolation.Verify(), "the isolation should hold before the test")

	withoutSender := func(check func()) {
		require.NoError(t, isolation.Remove(from.iface))
		check()
		_, err := isolation.Add(from.iface, from.address(t))
		require.NoError(t, err)
		require.NoError(t, isolation.Verify())
	}

	// I4: a peer of one network reaches the host by an address of the other network.
	localPort := basePort
	probe := listenProbe(t, localPort)
	from.requireReachesOwnAddress(t, probe, localPort)

	foreign := udpPacket(t, from.network.router, localOverlayAddr(t, to.ss), 40000, localPort)
	from.inject(t, foreign)
	assert.False(t, probe.delivered(), "I4: a peer of %s must not reach the host by the address on %s", from.iface, to.iface)

	withoutSender(func() {
		from.inject(t, foreign)
		require.True(t, probe.delivered(), "without the isolation the packet should arrive, or the drop proves nothing")
	})

	from.inject(t, foreign)
	assert.False(t, probe.delivered(), "I4: the isolation should drop the flow the conntrack knows")

	// I3: a peer of one network reaches the other network through this host, with a route ACL
	// that allows it, as on a routing peer.
	firewallManager := from.ss.client().Engine().GetFirewallManager()
	// After the first network map, which gives up the routing of a peer with no server routes.
	require.NoError(t, firewallManager.EnableRouting())
	require.Equal(t, "1", readIPForward(t))
	rule, err := firewallManager.AddFilterRule([]byte("isolation-test"),
		[]netip.Prefix{netip.PrefixFrom(from.network.router, 32)},
		fwmanager.Network{Prefix: to.network.overlay}, fwmanager.ProtocolALL, nil, nil, fwmanager.ActionAccept)
	require.NoError(t, err)
	require.NoError(t, firewallManager.Flush())
	t.Cleanup(func() {
		if engine := from.ss.client().Engine(); engine != nil {
			_ = engine.GetFirewallManager().DeleteFilterRule(rule)
		}
	})

	sniffer := sniffInterface(t, to.iface)
	forwardPort := basePort + 1
	forwarded := udpPacket(t, from.network.router, to.network.router, 40001, forwardPort)
	from.inject(t, forwarded)
	assert.False(t, sniffer.sawPacket(to.network.router, forwardPort), "I3: a packet of %s must not leave through %s", from.iface, to.iface)

	withoutSender(func() {
		from.inject(t, forwarded)
		require.True(t, sniffer.sawPacket(to.network.router, forwardPort), "without the isolation the packet should be forwarded, or the drop proves nothing")
	})

	from.inject(t, forwarded)
	assert.False(t, sniffer.sawPacket(to.network.router, forwardPort), "I3: the isolation should drop the flow the conntrack knows")
}

// Both sessions run with route ACLs that would let a peer through and forwarding on, which is a
// routing peer: only the isolation is left to stop the packet.
func TestPacketBetweenNetworksIsDropped(t *testing.T) {
	for _, backend := range hostBackends {
		t.Run(backend.name, func(t *testing.T) {
			backend.setup(t)
			setIPForward(t, "0")
			f := newSessionsFixture(t)

			upProfile(t, f.ctx, f.s, f.work, f.username)
			work := f.session(t, f.work)
			awaitConnected(t, work, f.work)
			upProfile(t, f.ctx, f.s, f.home, f.username)
			home := f.session(t, f.home)
			awaitConnected(t, home, f.home)

			workSide := sessionSide{ss: work, iface: "wt0", network: networkWork}
			homeSide := sessionSide{ss: home, iface: "wt1", network: networkHome}
			assertIsolated(t, f, workSide, homeSide, 41000)
			assertIsolated(t, f, homeSide, workSide, 41100)

			// The forwarding is shared: one session leaving keeps it for the other, the last one
			// restores what the host had, with no explicit disable in between. Without server routes
			// a network map can give up the reference, so it is taken again first.
			require.NoError(t, home.client().Engine().GetFirewallManager().EnableRouting())
			f.down(t, work)
			assert.Equal(t, "1", readIPForward(t), "the remaining session still routes")
			f.down(t, home)
			assert.Equal(t, "0", readIPForward(t), "the last session should restore the forwarding")
		})
	}
}

// A selector reaches the engine of the session it names: its networks, its selection, and its capture,
// which leaves with its own debug bundle and no other.
func TestSelectorReachesTheEngineOfItsSession(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	f := newSessionsFixture(t)

	upProfile(t, f.ctx, f.s, f.work, f.username)
	work := f.session(t, f.work)
	awaitConnected(t, work, f.work)
	upProfile(t, f.ctx, f.s, f.home, f.username)
	home := f.session(t, f.home)
	awaitConnected(t, home, f.home)
	require.Same(t, work, f.s.focusedSession(), "the session of the second network is not focused")

	workSelector := &proto.SessionSelector{Profile: f.work, Username: f.username}
	homeSelector := &proto.SessionSelector{Profile: f.home, Username: f.username}

	networks := func(selector *proto.SessionSelector) map[string]*proto.Network {
		t.Helper()
		resp, err := f.s.ListNetworks(f.ctx, &proto.ListNetworksRequest{Session: selector})
		require.NoError(t, err)
		byRange := make(map[string]*proto.Network, len(resp.GetRoutes()))
		for _, network := range resp.GetRoutes() {
			byRange[network.GetRange()] = network
		}
		return byRange
	}
	require.Eventually(t, func() bool {
		return networks(homeSelector)[networkHome.route.String()] != nil && networks(nil)[networkWork.route.String()] != nil
	}, 60*time.Second, 100*time.Millisecond, "both sessions should get their routes")

	assert.NotContains(t, networks(homeSelector), networkWork.route.String(), "the networks of the named session and no other")
	assert.NotContains(t, networks(workSelector), networkHome.route.String(), "the networks of the named session and no other")
	assert.NotContains(t, networks(nil), networkHome.route.String(), "no selector means the focused session")

	// A selection in one session leaves the same network ID of the other as it was.
	_, err := f.s.DeselectNetworks(f.ctx, &proto.SelectNetworksRequest{Session: homeSelector, NetworkIDs: []string{"own"}})
	require.NoError(t, err)
	assert.False(t, networks(homeSelector)[networkHome.route.String()].GetSelected())
	assert.True(t, networks(workSelector)[networkWork.route.String()].GetSelected(), "the other session keeps its selection")
	_, err = f.s.SelectNetworks(f.ctx, &proto.SelectNetworksRequest{Session: homeSelector, NetworkIDs: []string{"own"}, Append: true})
	require.NoError(t, err)
	assert.True(t, networks(homeSelector)[networkHome.route.String()].GetSelected())

	// A capture of each session, and traffic only in one of them.
	_, err = f.s.StartBundleCapture(f.ctx, &proto.StartBundleCaptureRequest{Session: workSelector})
	require.NoError(t, err)
	_, err = f.s.StartBundleCapture(f.ctx, &proto.StartBundleCaptureRequest{Session: homeSelector})
	require.NoError(t, err)
	require.NotNil(t, work.currentCapture(), "the capture of the first session should run")
	require.NotNil(t, home.currentCapture(), "the capture of the second session should run")

	packet := udpPacket(t, networkWork.router, networkWork.overlay.Addr().Next(), 42000, 42001)
	workSide := sessionSide{ss: work, iface: "wt0", network: networkWork}
	workSide.inject(t, packet)

	bundleCapture := func(selector *proto.SessionSelector) (string, bool) {
		t.Helper()
		resp, err := f.s.DebugBundle(f.ctx, &proto.DebugBundleRequest{Session: selector})
		require.NoError(t, err)
		raw, found := bundleEntries(t, resp.GetPath())["capture.pcap"]
		return raw, found
	}

	// The second session goes first: its bundle takes its own capture, and leaves the first running.
	homeCapture, found := bundleCapture(homeSelector)
	require.True(t, found, "the bundle of the second session carries its capture")
	assert.NotContains(t, homeCapture, "isolation probe", "the capture of the second session has no packet of the first")
	assert.NotNil(t, work.currentCapture(), "a bundle of another session must leave the capture running")

	workCapture, found := bundleCapture(workSelector)
	require.True(t, found, "the bundle of the first session carries its capture")
	assert.Contains(t, workCapture, "isolation probe", "the capture of the first session has its packet")
}

// A session whose overlay overlaps a running one does not start and does not keep trying (section
// 6), and the running one does not notice. The refusal is not sticky.
func TestOverlappingOverlayIsRefused(t *testing.T) {
	for _, backend := range hostBackends {
		t.Run(backend.name, func(t *testing.T) {
			backend.setup(t)
			f := newSessionsFixture(t)

			upProfile(t, f.ctx, f.s, f.work, f.username)
			work := f.session(t, f.work)
			awaitConnected(t, work, f.work)
			requireInterfaceAddress(t, "wt0", networkWork.overlay, work)

			const clash = "clash"
			startNetwork(t, f.ctx, profilemanager.DefaultConfigPathDir, clash, f.signalAddr, networkWork)
			upProfile(t, f.ctx, f.s, clash, f.username)
			refused := f.session(t, clash)
			awaitRunEnd(t, refused)

			assert.NotEqual(t, internal.StatusConnected, refused.state.CurrentStatus(), "the session must not connect")
			_, err := netlink.LinkByName("wt1")
			assert.Error(t, err, "the refused session must not get an interface")
			assert.Equal(t, internal.StatusConnected, work.state.CurrentStatus(), "the running session should not notice")
			assert.NoError(t, f.s.host.Isolation().Verify(), "the isolation should be as the running session needs it")

			f.down(t, work)
			upProfile(t, f.ctx, f.s, clash, f.username)
			awaitConnected(t, refused, clash)
			f.down(t, refused)
		})
	}
}

// I6: the isolation is checked again once the engine runs. A rule that lets traffic past it means
// the session does not start, and the session that runs stays as it is.
func TestFailedIsolationCheckRefusesTheSession(t *testing.T) {
	for _, backend := range []struct {
		name   string
		setup  func(t *testing.T)
		tamper func(t *testing.T)
	}{
		{name: "nftables", setup: requireNftablesBackend, tamper: tamperNftablesIsolation},
		{name: "iptables", setup: func(t *testing.T) { t.Setenv(firewall.SkipNftablesEnv, "true") }, tamper: tamperIptablesIsolation},
	} {
		t.Run(backend.name, func(t *testing.T) {
			backend.setup(t)
			f := newSessionsFixture(t)

			upProfile(t, f.ctx, f.s, f.work, f.username)
			work := f.session(t, f.work)
			awaitConnected(t, work, f.work)
			require.NoError(t, f.s.host.Isolation().Verify())

			backend.tamper(t)
			require.Error(t, f.s.host.Isolation().Verify(), "the rule should break the isolation")

			upProfile(t, f.ctx, f.s, f.home, f.username)
			home := f.session(t, f.home)
			awaitRunEnd(t, home)

			assert.NotEqual(t, internal.StatusConnected, home.state.CurrentStatus(), "the session must not stay up")
			_, err := netlink.LinkByName("wt1")
			assert.Error(t, err, "the refused session must not keep its interface")
			assert.Equal(t, internal.StatusConnected, work.state.CurrentStatus(), "the running session should not notice")
		})
	}
}

func tamperNftablesIsolation(t *testing.T) {
	t.Helper()
	conn := &nftables.Conn{}
	table := &nftables.Table{Name: nbnftables.IsolationTableName, Family: nftables.TableFamilyINet}
	chains, err := conn.ListChainsOfTableFamily(nftables.TableFamilyINet)
	require.NoError(t, err)
	for _, chain := range chains {
		if chain.Table.Name == table.Name && chain.Name == "forward" {
			conn.InsertRule(&nftables.Rule{Table: table, Chain: chain, Exprs: []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}}})
		}
	}
	require.NoError(t, conn.Flush())
}

func tamperIptablesIsolation(t *testing.T) {
	t.Helper()
	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	require.NoError(t, err)
	require.NoError(t, ipt.Insert("mangle", "FORWARD", 1, "-j", "ACCEPT"))
	t.Cleanup(func() {
		if err := ipt.DeleteIfExists("mangle", "FORWARD", "-j", "ACCEPT"); err != nil {
			t.Logf("remove the rule: %v", err)
		}
	})
}

// I2 for a restart: the interface of one session goes away, its engine comes back on the same name
// and port, and the other session does not notice.
func TestRestartOfOneSessionLeavesTheOther(t *testing.T) {
	for _, backend := range hostBackends {
		t.Run(backend.name, func(t *testing.T) {
			backend.setup(t)
			f := newSessionsFixture(t)

			upProfile(t, f.ctx, f.s, f.work, f.username)
			work := f.session(t, f.work)
			awaitConnected(t, work, f.work)
			keepRouterConnected(t, work.statusRecorder)
			upProfile(t, f.ctx, f.s, f.home, f.username)
			home := f.session(t, f.home)
			awaitConnected(t, home, f.home)
			keepRouterConnected(t, home.statusRecorder)
			awaitRoute(t, networkWork.route, "wt0")
			awaitRoute(t, networkHome.route, "wt1")

			before := takeHostSnapshot(t, identityLine)
			resources, running := f.s.slots.Running(home.key)
			require.True(t, running)
			engineBefore := home.client().Engine()

			link, err := netlink.LinkByName("wt1")
			require.NoError(t, err)
			require.NoError(t, netlink.LinkDel(link), "take the interface away")

			require.Eventually(t, func() bool {
				engine := home.client().Engine()
				return engine != nil && engine != engineBefore && home.state.CurrentStatus() == internal.StatusConnected
			}, 60*time.Second, 100*time.Millisecond, "the engine should come back")
			requireInterfaceAddress(t, "wt1", networkHome.overlay, home)
			awaitRoute(t, networkHome.route, "wt1")

			after, running := f.s.slots.Running(home.key)
			require.True(t, running)
			assert.Equal(t, resources.Interface, after.Interface, "the session should stay on its interface")
			assert.Equal(t, resources.Port, after.Port, "the session should stay on its port")

			names := []string{"wt0", "netbird\"", "netbird chain", "100.71."}
			assert.Equal(t, sessionPart(before, names...), sessionPart(takeHostSnapshot(t, identityLine), names...),
				"the restart of one session should leave the other as it was")
			assert.Equal(t, internal.StatusConnected, work.state.CurrentStatus())
			assert.NoError(t, f.s.host.Isolation().Verify())

			f.down(t, home)
			f.down(t, work)
		})
	}
}

// Q9: no native firewall on the host, so the userspace firewall of each session is what isolates it.
func TestUserspaceFirewallIsolatesWithoutNativeBackend(t *testing.T) {
	// Discovery finds neither backend: no iptables binary and the nftables check off.
	t.Setenv("PATH", "/nonexistent")
	t.Setenv(firewall.SkipNftablesEnv, "true")
	f := newSessionsFixture(t)

	upProfile(t, f.ctx, f.s, f.work, f.username)
	work := f.session(t, f.work)
	awaitConnected(t, work, f.work)
	upProfile(t, f.ctx, f.s, f.home, f.username)
	home := f.session(t, f.home)
	awaitConnected(t, home, f.home)

	_, isUserspace := work.client().Engine().GetFirewallManager().(*uspfilter.Manager)
	require.True(t, isUserspace, "the session should run on the userspace firewall")
	assert.Empty(t, linesWith(snapshotNftables(t), nbnftables.IsolationTableName), "there is no native backend to hold the isolation")

	const port = uint16(42000)
	probe := listenProbe(t, port)
	workSide := sessionSide{ss: work, iface: "wt0", network: networkWork}

	workSide.requireReachesOwnAddress(t, probe, port)

	workSide.inject(t, udpPacket(t, networkWork.router, localOverlayAddr(t, home), 40000, port))
	assert.False(t, probe.delivered(), "I4: a peer must not reach the host by the address of the other network")

	// I3 through the forwarder, which only runs with routing on and a route ACL to allow the packet.
	firewallManager := work.client().Engine().GetFirewallManager()
	require.NoError(t, firewallManager.EnableRouting())
	_, err := firewallManager.AddFilterRule([]byte("isolation-test"),
		[]netip.Prefix{netip.PrefixFrom(networkWork.router, 32)},
		fwmanager.Network{Prefix: networkHome.overlay}, fwmanager.ProtocolALL, nil, nil, fwmanager.ActionAccept)
	require.NoError(t, err)

	sniffer := sniffInterface(t, "wt1")
	forwarded := udpPacket(t, networkWork.router, networkHome.router, 40001, port+1)
	workSide.inject(t, forwarded)
	assert.False(t, sniffer.sawPacket(networkHome.router, port+1), "I3: a packet must not reach the other network")

	// Without the record of the other session the same packet gets through, or the drop proves nothing.
	sessions := f.s.host.Coordinator().Sessions()
	sessions.Remove(home.key)
	workSide.inject(t, forwarded)
	assert.True(t, sniffer.sawPacket(networkHome.router, port+1), "without the isolation source the packet should be forwarded")
	require.NoError(t, sessions.Set(home.key, "wt1", networkHome.overlay))

	f.down(t, work)
	f.down(t, home)
}

// Q10: with server routes disabled the userspace firewall hands routed packets to the kernel, and
// without a native backend nothing there isolates them. The session must not start.
func TestRoutingThroughKernelWithoutNativeBackendIsRefused(t *testing.T) {
	t.Setenv("PATH", "/nonexistent")
	t.Setenv(firewall.SkipNftablesEnv, "true")
	f := newSessionsFixture(t)

	disabled := true
	path := filepath.Join(profilemanager.DefaultConfigPathDir, f.work+".json")
	_, err := profilemanager.UpdateOrCreateConfig(profilemanager.ConfigInput{ConfigPath: path, DisableServerRoutes: &disabled})
	require.NoError(t, err)

	upProfile(t, f.ctx, f.s, f.work, f.username)
	work := f.session(t, f.work)
	awaitRunEnd(t, work)

	assert.NotEqual(t, internal.StatusConnected, work.state.CurrentStatus(), "the session must not connect")
	_, err = netlink.LinkByName("wt0")
	assert.Error(t, err, "the refused session must not keep an interface")
}

// A crashed daemon leaves its isolation behind. With a sessions file the start removes it from both
// backends. Without one no daemon with the gate ever ran here, and the start touches nothing (I1).
func TestStartRemovesIsolationResidual(t *testing.T) {
	addr := wgaddr.MustParseWGAddress("100.71.0.1/16")

	install := func(t *testing.T) {
		t.Helper()
		_, err := nbnftables.NewIsolation().Add("wt0", addr)
		require.NoError(t, err)
		ipt, err := nbiptables.NewIsolation()
		require.NoError(t, err)
		_, err = ipt.Add("wt0", addr)
		require.NoError(t, err)
		t.Cleanup(func() {
			if err := firewall.RemoveResidualSessionIsolation(); err != nil {
				t.Logf("remove isolation: %v", err)
			}
		})
	}
	present := func(t *testing.T) (nft, ipt bool) {
		t.Helper()
		snapshot := takeHostSnapshot(t, identityLine)
		return len(linesWith(snapshot["nftables"], nbnftables.IsolationTableName)) > 0, len(linesWith(snapshot["iptables"], "NETBIRD-ISO")) > 0
	}

	t.Run("no sessions file leaves everything", func(t *testing.T) {
		t.Setenv("NB_DNS_STATE_FILE", "")
		s, ctx, _, _, _ := setupServerWithProfile(t)
		rootCtx, cancel := context.WithCancel(ctx)
		t.Cleanup(cancel)
		s.rootCtx = rootCtx
		install(t)
		requireKernelInterface(t)
		addResidualLink(t, "wt0")

		require.NoError(t, s.restoreResidualAtStart(ctx))

		nft, ipt := present(t)
		assert.True(t, nft, "the table is not known to be ours")
		assert.True(t, ipt, "the chains are not known to be ours")
		_, err := netlink.LinkByName("wt0")
		assert.NoError(t, err, "the interface is not known to be ours")
	})

	t.Run("a sessions file removes both", func(t *testing.T) {
		t.Setenv("NB_DNS_STATE_FILE", "")
		s, ctx, profile, username, _ := setupServerWithProfile(t)
		rootCtx, cancel := context.WithCancel(ctx)
		t.Cleanup(cancel)
		s.rootCtx = rootCtx
		writeDesiredSessions(t, map[profilemanager.SessionKey]hostcoord.DesiredState{
			{Profile: profilemanager.ID(profile), Username: username}: hostcoord.DesiredUp,
		})
		install(t)

		require.NoError(t, s.restoreResidualAtStart(ctx))

		nft, ipt := present(t)
		assert.False(t, nft, "the nftables isolation should be gone")
		assert.False(t, ipt, "the iptables isolation should be gone")
	})

	// The isolation is what still keeps an interface that cannot go from the other networks, and
	// the daemon does not run next to it.
	t.Run("a link that stays keeps the isolation and refuses the start", func(t *testing.T) {
		t.Setenv("NB_DNS_STATE_FILE", "")
		t.Setenv(netstack.EnvUseNetstackMode, "false")
		requireKernelInterface(t)
		s, ctx, profile, username, _ := setupServerWithProfile(t)
		rootCtx, cancel := context.WithCancel(ctx)
		t.Cleanup(cancel)
		s.rootCtx = rootCtx
		s.sessionSet = newSessionSet(true)
		s.removeLinksFn = func([]hostcoord.SlotRecord) error { return errors.New("cannot delete the link") }
		writeDesiredSessions(t, map[profilemanager.SessionKey]hostcoord.DesiredState{
			{Profile: profilemanager.ID(profile), Username: username}: hostcoord.DesiredUp,
		})
		install(t)
		addResidualLink(t, "wt0")

		require.Error(t, s.Start(), "the start must not go on next to a live session interface")

		nft, ipt := present(t)
		assert.True(t, nft, "the nftables isolation should stay with the link")
		assert.True(t, ipt, "the iptables isolation should stay with the link")
		assert.Nil(t, s.slots, "a refused start should leave no slots behind")
		_, running := s.focusedSession().runningKey()
		assert.False(t, running, "a refused start should run no session")
	})
}

// addResidualLink leaves the kernel interface a crashed daemon would.
func addResidualLink(t *testing.T, name string) {
	t.Helper()
	link := &netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: name}}
	require.NoError(t, netlink.LinkAdd(link))
	t.Cleanup(func() {
		if existing, err := netlink.LinkByName(name); err == nil {
			_ = netlink.LinkDel(existing)
		}
	})
}
