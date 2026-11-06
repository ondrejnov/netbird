//go:build privileged && linux

package server

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc/codes"

	fwmanager "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/client/system"
)

const (
	scaleRounds  = 4
	stressCycles = 100
	// Below the ephemeral range, which the sockets of the sessions keep drawing from.
	scaleI4BasePort    = 23000
	scaleI3BasePort    = 24000
	stressProbePort    = 25000
	scaleControlPort   = 25500
	stressSendInterval = 5 * time.Millisecond
	// A leak of one goroutine or descriptor per cycle would exceed these by far. They leave room for
	// the NAT discoveries of stopped engines, which hold a socket and a goroutine for up to 128 s.
	stressGoroutineSlack = 40
	stressFDSlack        = 40
	// What a running session may lose beside the stress. The peer of the other session goes through
	// the same kernel, so anything but a stray packet means the other session got in the way.
	stressMaxLossPercent = 0.5
	stressMaxGap         = time.Second

	slotBasePort = 51820
)

// envScaleTests turns on the scale tests and the measurement, which take longer than CI gives the
// whole package.
const envScaleTests = "NB_TEST_SCALE"

// requireScaleTests skips a scale test unless envScaleTests asks for it.
func requireScaleTests(t *testing.T) {
	t.Helper()
	val := os.Getenv(envScaleTests)
	if val == "" {
		t.Skipf("runs only on request, set %s=true", envScaleTests)
	}
	enabled, err := strconv.ParseBool(val)
	if err != nil {
		t.Fatalf("parse %s: %v", envScaleTests, err)
	}
	if !enabled {
		t.Skipf("turned off by %s=%s", envScaleTests, val)
	}
}

// scaleNetwork returns a network of its own for one index. Its addresses stay apart from networkWork
// and networkHome, and from the route the networks share.
func scaleNetwork(index int) hostNetwork {
	octet := byte(80 + index)
	return hostNetwork{
		overlay: netip.PrefixFrom(netip.AddrFrom4([4]byte{100, octet, 0, 0}), 16),
		router:  netip.AddrFrom4([4]byte{100, octet, 0, 2}),
		route:   netip.PrefixFrom(netip.AddrFrom4([4]byte{10, octet, 0, 0}), 16),
		shared:  networkWork.shared,
	}
}

// scaleFixture is a daemon with the gate, a limit the test injects, and a Management per network.
// There is one network more than the limit, for the session the limit refuses.
type scaleFixture struct {
	*sessionsFixture
	size     int
	profiles []string
	networks []hostNetwork
	// kept tracks which sessions already have their routing peer marked connected.
	kept map[int]bool
}

func newScaleFixture(t *testing.T, size int) *scaleFixture {
	t.Helper()
	f := &scaleFixture{sessionsFixture: newSessionsFixtureInMode(t), size: size, kept: make(map[int]bool)}
	WithMaxSessions(uint32(size))(f.s)
	f.profiles = []string{f.work, f.home}
	f.networks = []hostNetwork{networkWork, networkHome}

	for index := 2; index <= size; index++ {
		profile := fmt.Sprintf("scale-%d", index)
		network := scaleNetwork(index)
		startNetwork(t, f.ctx, profilemanager.DefaultConfigPathDir, profile, f.signalAddr, network)
		f.profiles = append(f.profiles, profile)
		f.networks = append(f.networks, network)
	}

	// A failed test leaves no sessions behind for the next backend.
	t.Cleanup(func() {
		all := f.s.allSessions()
		if _, err := f.s.Down(f.ctx, &proto.DownRequest{All: true}); err != nil {
			t.Logf("final down: %v", err)
		}
		for _, ss := range all {
			_, giveUp := ss.runChans()
			if giveUp == nil {
				continue
			}
			select {
			case <-giveUp:
			case <-time.After(30 * time.Second):
				t.Logf("a run of %s did not end", ss.key.Profile)
			}
		}
	})
	return f
}

func (f *scaleFixture) setLimit(limit uint32) {
	f.s.mutex.Lock()
	defer f.s.mutex.Unlock()
	WithMaxSessions(limit)(f.s)
}

func (f *scaleFixture) sessionAt(t *testing.T, index int) *session {
	t.Helper()
	return f.session(t, f.profiles[index])
}

func (f *scaleFixture) keepRouter(t *testing.T, index int, ss *session) {
	t.Helper()
	if !f.kept[index] {
		f.kept[index] = true
		keepRouterConnected(t, ss.statusRecorder)
	}
}

// up connects the session of index and waits until its own route is in the shared table.
func (f *scaleFixture) up(t *testing.T, index int) *session {
	t.Helper()
	upProfile(t, f.ctx, f.s, f.profiles[index], f.username)
	ss := f.sessionAt(t, index)
	awaitConnected(t, ss, f.profiles[index])
	f.keepRouter(t, index, ss)
	awaitRoute(t, f.networks[index].route, f.interfaceOf(t, ss))
	return ss
}

func (f *scaleFixture) downAt(t *testing.T, index int) {
	t.Helper()
	ss := f.sessionAt(t, index)
	_, err := f.s.Down(f.ctx, &proto.DownRequest{Session: f.selector(ss)})
	require.NoErrorf(t, err, "Down of profile %s", f.profiles[index])
	awaitRunEnd(t, ss)
}

func (f *scaleFixture) enginesOf(t *testing.T, indices []int) map[int]*internal.Engine {
	t.Helper()
	engines := make(map[int]*internal.Engine, len(indices))
	for _, index := range indices {
		engine := f.sessionAt(t, index).client().Engine()
		require.NotNilf(t, engine, "session %d should have an engine", index)
		engines[index] = engine
	}
	return engines
}

// assertUntouched is I2 and I8 from the side of a session: any restart, by a network monitor or by a
// retry, replaces the engine.
func (f *scaleFixture) assertUntouched(t *testing.T, engines map[int]*internal.Engine, what string) {
	t.Helper()
	for index, engine := range engines {
		ss := f.sessionAt(t, index)
		assert.Samef(t, engine, ss.client().Engine(), "%s should not restart session %d", what, index)
		assert.Equalf(t, internal.StatusConnected, ss.state.CurrentStatus(), "%s should leave session %d connected", what, index)
	}
}

func indicesExcept(size int, excluded ...int) []int {
	indices := make([]int, 0, size)
	for index := range size {
		if !slices.Contains(excluded, index) {
			indices = append(indices, index)
		}
	}
	return indices
}

// slotLines matches what belongs to one slot. The whole name has to match: slot 1 next to slot 10
// is where a prefix would take the wrong session along.
func slotLines(slot int) *regexp.Regexp {
	// An nftables rule in a foreign chain spells the interface name in bytes.
	var spelled []string
	for _, char := range fmt.Appendf(nil, "wt%d\x00", slot) {
		spelled = append(spelled, strconv.Itoa(int(char)))
	}
	return regexp.MustCompile(fmt.Sprintf(`\bwt%[1]d\b|\bnetbird-%[1]d\b|\bNETBIRD-[A-Z0-9-]+-%[1]d\b|\bnb-[0-9a-f]+(-v6)?-%[1]d\b|Data:\[%[2]s\]`, slot, strings.Join(spelled, " ")))
}

// minusLines returns the lines of a that b does not have, counting duplicates.
func minusLines(a, b []string) []string {
	counts := make(map[string]int, len(b))
	for _, line := range b {
		counts[line]++
	}
	var out []string
	for _, line := range a {
		if counts[line] > 0 {
			counts[line]--
			continue
		}
		out = append(out, line)
	}
	return out
}

// assertOnlySlotLeft compares the host before and after a session stopped: nothing appears, and all
// that goes names the slot of that session.
func assertOnlySlotLeft(t *testing.T, before, after hostSnapshot, slot int) {
	t.Helper()
	own := slotLines(slot)
	for section, lines := range before {
		assert.Emptyf(t, minusLines(after[section], lines), "stopping slot %d should add nothing to %s", slot, section)
		foreign := slices.DeleteFunc(minusLines(lines, after[section]), own.MatchString)
		assert.Emptyf(t, foreign, "stopping slot %d should take only its own from %s", slot, section)
	}
	for section, lines := range after {
		assert.Emptyf(t, slices.DeleteFunc(slices.Clone(lines), func(line string) bool { return !own.MatchString(line) }),
			"slot %d should leave nothing in %s", slot, section)
	}
}

// sharedRouteDevs returns the interfaces that hold the shared prefix in the shared table.
func sharedRouteDevs(t *testing.T, prefix netip.Prefix) []string {
	t.Helper()
	marker := fmt.Sprintf("table=%d dst=%s dev=", hostFixtureTable, prefix)
	var devs []string
	for _, line := range snapshotRoutes(t) {
		_, rest, found := strings.Cut(line, marker)
		if found {
			devs = append(devs, strings.Fields(rest)[0])
		}
	}
	return devs
}

func awaitOneSharedOwner(t *testing.T, prefix netip.Prefix, candidates []string) string {
	t.Helper()
	var owner string
	require.Eventuallyf(t, func() bool {
		devs := sharedRouteDevs(t, prefix)
		if len(devs) != 1 || !slices.Contains(candidates, devs[0]) {
			return false
		}
		owner = devs[0]
		return true
	}, 30*time.Second, 50*time.Millisecond, "one of %v should hold the shared prefix alone", candidates)
	return owner
}

// outgoingSniffer sees what the kernel sends out of any interface. A packet handed to the interface
// of the sender arrives there as incoming, so only a forwarded packet counts.
type outgoingSniffer struct {
	fd int
}

func sniffOutgoing(t *testing.T) *outgoingSniffer {
	t.Helper()
	// The protocol goes in network byte order.
	protocol := (unix.ETH_P_ALL&0xff)<<8 | unix.ETH_P_ALL>>8
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM, protocol)
	require.NoError(t, err)
	t.Cleanup(func() { _ = unix.Close(fd) })
	timeout := unix.NsecToTimeval(int64(100 * time.Millisecond))
	require.NoError(t, unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout))
	return &outgoingSniffer{fd: fd}
}

// forwardedTo collects for a second the addresses that packets for the UDP port left towards.
func (s *outgoingSniffer) forwardedTo(port uint16) map[netip.Addr]bool {
	seen := make(map[netip.Addr]bool)
	buf := make([]byte, 2048)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		n, from, err := unix.Recvfrom(s.fd, buf, 0)
		if err != nil || n < 28 {
			continue
		}
		if link, ok := from.(*unix.SockaddrLinklayer); !ok || link.Pkttype != unix.PACKET_OUTGOING {
			continue
		}
		packet := gopacket.NewPacket(buf[:n], layers.LayerTypeIPv4, gopacket.Default)
		ip, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		if !ok {
			continue
		}
		udp, ok := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
		if !ok || uint16(udp.DstPort) != port {
			continue
		}
		if addr, ok := netip.AddrFromSlice(ip.DstIP.To4()); ok {
			seen[addr] = true
		}
	}
	return seen
}

func (f *scaleFixture) side(t *testing.T, index int) sessionSide {
	t.Helper()
	ss := f.sessionAt(t, index)
	return sessionSide{ss: ss, iface: f.interfaceOf(t, ss), network: f.networks[index]}
}

// allowEverything gives the session of side a route ACL that lets a peer through to every other
// network and turns forwarding on, so that the isolation alone is left to stop a packet (I3).
func allowEverything(t *testing.T, side sessionSide) {
	t.Helper()
	firewallManager := side.ss.client().Engine().GetFirewallManager()
	require.NoError(t, firewallManager.EnableRouting())
	require.Equal(t, "1", readIPForward(t))
	_, err := firewallManager.AddFilterRule([]byte("scale-test"),
		[]netip.Prefix{netip.PrefixFrom(side.network.router, 32)},
		fwmanager.Network{Prefix: tunnelPeerAllowed}, fwmanager.ProtocolALL, nil, nil, fwmanager.ActionAccept)
	require.NoError(t, err)
	require.NoError(t, firewallManager.Flush())
}

// assertAllPairsIsolated sends from each session towards all others, at once, and finds nothing got
// anywhere. Sessions at both ends of the table run the same packets with the sender out of the
// isolation, which all must pass: without that a quiet second could have any other cause, and it
// shows the interfaces past the first ten behave like the others.
func assertAllPairsIsolated(t *testing.T, f *scaleFixture, members []int, roundOffset uint16) {
	t.Helper()
	isolation := f.s.host.Isolation()
	require.NoError(t, isolation.Verify(), "the isolation should hold before the test")
	sniffer := sniffOutgoing(t)
	sides := make(map[int]sessionSide, len(members))
	for _, index := range members {
		sides[index] = f.side(t, index)
	}

	controlled := []int{members[0], members[len(members)-1]}
	for _, from := range members {
		side := sides[from]
		localPort := scaleI4BasePort + roundOffset + uint16(from)
		forwardPort := scaleI3BasePort + roundOffset + uint16(from)
		probe := listenProbe(t, localPort)
		side.requireReachesOwnAddress(t, probe, localPort)
		allowEverything(t, side)

		send := func() map[netip.Addr]bool {
			for _, to := range members {
				if to == from {
					continue
				}
				side.inject(t, udpPacket(t, side.network.router, localOverlayAddr(t, sides[to].ss), 40000, localPort))
				side.inject(t, udpPacket(t, side.network.router, sides[to].network.router, 40001, forwardPort))
			}
			return sniffer.forwardedTo(forwardPort)
		}

		probe.drain()
		forwarded := send()
		assert.Emptyf(t, forwarded, "I3: a peer of %s must not get through this host", side.iface)
		assert.Falsef(t, probe.delivered(), "I4: a peer of %s must not reach the host by the address of another network", side.iface)

		if !slices.Contains(controlled, from) {
			continue
		}
		require.NoError(t, isolation.Remove(side.iface))
		forwarded = send()
		for _, to := range members {
			if to != from {
				assert.Truef(t, forwarded[sides[to].network.router], "without the isolation a peer of %s should get to %s, or the drop proves nothing", side.iface, sides[to].iface)
				assert.Truef(t, probe.delivered(), "without the isolation a peer of %s should reach the host, or the drop proves nothing", side.iface)
			}
		}
		_, err := isolation.Add(side.iface, side.address(t))
		require.NoError(t, err)
		require.NoError(t, isolation.Verify())

		// The conntrack knows these flows by now.
		probe.drain()
		assert.Emptyf(t, send(), "I3: the isolation should drop the flows of %s the conntrack knows", side.iface)
		assert.Falsef(t, probe.delivered(), "I4: the isolation should drop the flows of %s the conntrack knows", side.iface)
	}
}

// assertAddressesLeftOut is I5 with all overlays on record: the system info a session sends loses the
// address of each of them and keeps the others, and the interfaces of all sessions stay out of the
// ICE candidates.
func assertAddressesLeftOut(t *testing.T, f *scaleFixture, members []int) {
	t.Helper()
	physical := system.NetworkAddress{NetIP: netip.MustParsePrefix("192.0.2.10/24")}
	info := &system.Info{NetworkAddresses: []system.NetworkAddress{physical}}
	interfaces := f.s.host.Coordinator().Sessions().SessionInterfaces()
	for _, index := range members {
		ss := f.sessionAt(t, index)
		info.NetworkAddresses = append(info.NetworkAddresses, system.NetworkAddress{NetIP: netip.PrefixFrom(localOverlayAddr(t, ss), 16)})
		assert.Containsf(t, interfaces, f.interfaceOf(t, ss), "the ICE candidates should leave out the interface of session %d", index)
	}
	f.s.host.ExcludeSessionAddresses(info)
	assert.Equal(t, []system.NetworkAddress{physical}, info.NetworkAddresses, "I5: only what is not an overlay address goes to Management")
}

// assertLimit runs what the one check of 5.8 does to the session past the limit, and shows that no
// limit means no limit.
func assertLimit(t *testing.T, f *scaleFixture) {
	t.Helper()
	assert.EqualValues(t, 4, newSessionSet(true).maxSessions, "the default limit is the decision of the owner")

	features, err := f.s.GetFeatures(f.ctx, &proto.GetFeaturesRequest{})
	require.NoError(t, err)
	assert.EqualValues(t, f.size, features.GetMaxSessions(), "the daemon should report the injected limit")

	before := takeHostSnapshot(t, identityLine)
	over := f.profiles[f.size]
	_, err = f.s.Up(f.ctx, &proto.UpRequest{ProfileName: &over, Username: &f.username, Async: true})
	requireCode(t, codes.ResourceExhausted, err)
	assert.Equal(t, before, takeHostSnapshot(t, identityLine), "the refused session should leave the host as it was")

	f.setLimit(0)
	t.Cleanup(func() { f.setLimit(uint32(f.size)) })
	ss := f.up(t, f.size)
	assert.Equal(t, fmt.Sprintf("wt%d", f.size), f.interfaceOf(t, ss), "the session past the old limit should get the next slot")
	assert.NoError(t, f.s.host.Isolation().Verify())
	f.downAt(t, f.size)
	assert.Equal(t, before, takeHostSnapshot(t, identityLine), "the session past the old limit should leave the host as it was")
	f.setLimit(uint32(f.size))
}

// assertResources checks each session has what its slot says, whichever came up first.
func assertResources(t *testing.T, f *scaleFixture) map[string]string {
	t.Helper()
	interfaces := make(map[string]string, f.size)
	ports := make(map[uint16]bool, f.size)
	for index := range f.size {
		ss := f.sessionAt(t, index)
		name := fmt.Sprintf("wt%d", index)
		assert.Equal(t, name, f.interfaceOf(t, ss))
		resources, running := f.s.slots.Running(ss.key)
		require.True(t, running)
		logMovedPort(t, index, resources.Port)
		ports[resources.Port] = true
		requireInterfaceAddress(t, name, f.networks[index].overlay, ss)
		interfaces[f.profiles[index]] = name
	}
	assert.Len(t, ports, f.size, "each session should have a port of its own")
	return interfaces
}

// logMovedPort tells when a slot is not on its port. 5.1 allows it: the port of a slot is in the
// ephemeral range of Linux, and any socket of the host can hold it at the moment the session starts.
func logMovedPort(t *testing.T, slot int, port uint16) {
	t.Helper()
	if int(port) != slotBasePort+slot {
		t.Logf("SCALE slot=%d runs on port %d instead of %d", slot, port, slotBasePort+slot)
	}
}

func assertStatusNames(t *testing.T, f *scaleFixture, want map[string]string) {
	t.Helper()
	resp, err := f.s.Status(f.ctx, &proto.StatusRequest{})
	require.NoError(t, err)
	got := make(map[string]string, len(resp.GetSessions()))
	for _, entry := range resp.GetSessions() {
		got[entry.GetProfileId()] = entry.GetInterfaceName()
	}
	assert.Equal(t, want, got, "the status should name the interface of each session")
}

type scaleMode struct {
	name    string
	setup   func(t *testing.T)
	packets bool
}

var scaleModes = []scaleMode{
	{name: "userspace", setup: func(t *testing.T) { t.Setenv("NB_WG_KERNEL_DISABLED", "true") }, packets: true},
	// A kernel interface takes no packet from the test, see TestTwoSessionsOnRealEngines.
	{name: "kernel", setup: requireKernelInterface},
}

// N sessions on real engines, past the point where the names get a second digit: resources, limit,
// isolation with packets between all pairs, addresses, one session stopped and restarted beside the
// others, the shared route passed along from owner to owner, and a clean host at the end.
func TestScaleSessions(t *testing.T) {
	requireScaleTests(t)
	for _, size := range []int{8, 16} {
		for _, mode := range scaleModes {
			for _, backend := range hostBackends {
				t.Run(fmt.Sprintf("%d/%s/%s", size, mode.name, backend.name), func(t *testing.T) {
					mode.setup(t)
					backend.setup(t)
					runScaleSessions(t, size, mode.packets)
				})
			}
		}
	}
}

func runScaleSessions(t *testing.T, size int, packets bool) {
	setIPForward(t, "0")
	clean := takeHostSnapshot(t, identityLine)
	f := newScaleFixture(t, size)

	all := indicesExcept(size)
	began := time.Now()
	for _, index := range all {
		f.up(t, index)
	}
	t.Logf("SCALE size=%d started in sequence in %s", size, time.Since(began).Round(time.Millisecond))

	interfaces := assertResources(t, f)
	assertStatusNames(t, f, interfaces)
	assert.NoError(t, f.s.host.Isolation().Verify())
	shared := f.networks[0].shared
	assert.Equal(t, []string{"wt0"}, sharedRouteDevs(t, shared), "the first session should hold the shared prefix alone")
	owner, held := f.s.host.Coordinator().DNSOwners().HostDNSOwner()
	assert.True(t, held, "a primary nameserver should claim the host DNS")
	assert.Equal(t, f.sessionAt(t, 0).key, owner, "the first session should own the host DNS")

	assertLimit(t, f)
	assertAddressesLeftOut(t, f, all)
	if packets {
		assertAllPairsIsolated(t, f, all, 0)
	}

	// Slot 1 with the slots 10 and up running, which share its prefix.
	const stopped = 1
	others := indicesExcept(size, stopped)
	engines := f.enginesOf(t, others)
	before := takeHostSnapshot(t, identityLine)
	f.downAt(t, stopped)
	assertOnlySlotLeft(t, before, takeHostSnapshot(t, identityLine), stopped)
	f.assertUntouched(t, engines, "stopping another session")
	assert.NoError(t, f.s.host.Isolation().Verify())

	f.up(t, stopped)
	assert.Equal(t, interfaces, assertResources(t, f), "a session should come back on its slot")
	f.assertUntouched(t, engines, "starting another session")
	assertScaleRestart(t, f, stopped, engines)

	// The owner leaves each time, the prefix passes on through all sessions and the rest stay.
	remaining := all
	for len(remaining) > 0 {
		owner := awaitOneSharedOwner(t, shared, namesOf(f, t, remaining))
		ownerIndex := slices.IndexFunc(remaining, func(index int) bool { return f.interfaceOf(t, f.sessionAt(t, index)) == owner })
		require.GreaterOrEqual(t, ownerIndex, 0)
		leaving := remaining[ownerIndex]
		remaining = slices.Delete(slices.Clone(remaining), ownerIndex, ownerIndex+1)

		engines := f.enginesOf(t, remaining)
		f.downAt(t, leaving)
		f.assertUntouched(t, engines, "the owner of the shared prefix leaving")
		for _, index := range remaining {
			awaitRoute(t, f.networks[index].route, f.interfaceOf(t, f.sessionAt(t, index)))
		}
		if holder, held := f.s.host.Coordinator().DNSOwners().HostDNSOwner(); held {
			assert.NotEqual(t, f.sessionAt(t, leaving).key, holder, "a session that left should not hold the host DNS")
		}
		assert.NoError(t, f.s.host.Isolation().Verify())
	}
	assert.Empty(t, sharedRouteDevs(t, shared), "nobody is left to hold the shared prefix")

	// I7: the last session takes everything with it.
	assert.Equal(t, clean.withoutEmptyBuiltins(), takeHostSnapshot(t, identityLine).withoutEmptyBuiltins(),
		"after the last session the host should be what it was before the first")
}

func namesOf(f *scaleFixture, t *testing.T, indices []int) []string {
	t.Helper()
	names := make([]string, 0, len(indices))
	for _, index := range indices {
		names = append(names, f.interfaceOf(t, f.sessionAt(t, index)))
	}
	return names
}

// assertScaleRestart takes the interface of one session away. Its engine comes back on the same name
// and port, and no other session notices.
func assertScaleRestart(t *testing.T, f *scaleFixture, index int, engines map[int]*internal.Engine) {
	t.Helper()
	ss := f.sessionAt(t, index)
	name := f.interfaceOf(t, ss)
	engineBefore := ss.client().Engine()
	before := takeHostSnapshot(t, identityLine)
	own := slotLines(index)

	link, err := netlink.LinkByName(name)
	require.NoError(t, err)
	require.NoError(t, netlink.LinkDel(link), "take the interface away")
	require.Eventually(t, func() bool {
		engine := ss.client().Engine()
		return engine != nil && engine != engineBefore && ss.state.CurrentStatus() == internal.StatusConnected
	}, 60*time.Second, 100*time.Millisecond, "the engine should come back")
	requireInterfaceAddress(t, name, f.networks[index].overlay, ss)
	awaitRoute(t, f.networks[index].route, name)

	after := takeHostSnapshot(t, identityLine)
	for _, section := range []string{"links", "routes", "nftables", "iptables"} {
		keep := func(lines []string) []string {
			return slices.DeleteFunc(slices.Clone(lines), own.MatchString)
		}
		assert.Equalf(t, keep(before[section]), keep(after[section]), "the restart of one session should leave the others in %s", section)
	}
	f.assertUntouched(t, engines, "the restart of another session")
	assert.NoError(t, f.s.host.Isolation().Verify())
}

// togetherAll runs one operation for each index at once, the way a change of the network or a script
// would, and returns how long the slowest took.
func togetherAll(indices []int, op func(index int)) time.Duration {
	began := time.Now()
	var wg sync.WaitGroup
	for _, index := range indices {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			op(index)
		}(index)
	}
	wg.Wait()
	return time.Since(began)
}

// Sessions come and go in groups at the same moment, including one group leaving while another
// arrives, with a group that stays through all of it.
func TestScaleChurn(t *testing.T) {
	requireScaleTests(t)
	for _, size := range []int{8, 16} {
		for _, backend := range hostBackends {
			t.Run(fmt.Sprintf("%d/%s", size, backend.name), func(t *testing.T) {
				t.Setenv("NB_WG_KERNEL_DISABLED", "true")
				backend.setup(t)
				runScaleChurn(t, size)
			})
		}
	}
}

func runScaleChurn(t *testing.T, size int) {
	setIPForward(t, "0")
	clean := takeHostSnapshot(t, identityLine)
	f := newScaleFixture(t, size)

	upAsync := func(index int) {
		profile := f.profiles[index]
		_, err := f.s.Up(f.ctx, &proto.UpRequest{ProfileName: &profile, Username: &f.username, Async: true})
		assert.NoErrorf(t, err, "Up of profile %s", profile)
	}
	downAsync := func(index int) {
		profile := f.profiles[index]
		f.s.mutex.Lock()
		ss := f.s.sessions[sessionKeyOf(profilemanager.ID(profile), f.username)]
		f.s.mutex.Unlock()
		if _, err := f.s.Down(f.ctx, &proto.DownRequest{Session: f.selector(ss)}); err != nil {
			assert.NoErrorf(t, err, "Down of profile %s", profile)
		}
	}
	awaitUp := func(indices []int) {
		t.Helper()
		for _, index := range indices {
			ss := f.sessionAt(t, index)
			awaitConnected(t, ss, f.profiles[index])
			f.keepRouter(t, index, ss)
		}
	}
	awaitDown := func(indices []int) {
		t.Helper()
		for _, index := range indices {
			ss := f.sessionAt(t, index)
			awaitRunEnd(t, ss)
			assert.NotEqualf(t, internal.StatusConnected, ss.state.CurrentStatus(), "session %d should be down", index)
		}
	}

	// A start of all at once, which is also what a change of the network asks for.
	all := indicesExcept(size)
	began := time.Now()
	togetherAll(all, upAsync)
	awaitUp(all)
	t.Logf("SCALE size=%d all connected in %s, started together", size, time.Since(began).Round(time.Millisecond))
	require.NoError(t, f.s.host.Isolation().Verify())

	resources := make(map[int]string, size)
	ports := make(map[int]uint16, size)
	for _, index := range all {
		ss := f.sessionAt(t, index)
		held, running := f.s.slots.Running(ss.key)
		require.True(t, running)
		resources[index], ports[index] = held.Interface, held.Port
		logMovedPort(t, slotOfInterface(t, held.Interface), held.Port)
		awaitRoute(t, f.networks[index].route, held.Interface)
	}
	assert.Len(t, uniqueValues(resources), size, "each session should have an interface of its own")
	assert.Len(t, uniqueValues(ports), size, "each session should have a port of its own")

	var stayers, groupA, groupB []int
	for _, index := range all {
		switch index % 4 {
		case 0:
			stayers = append(stayers, index)
		case 1, 2:
			groupA = append(groupA, index)
		default:
			groupB = append(groupB, index)
		}
	}
	engines := f.enginesOf(t, stayers)

	togetherAll(groupB, downAsync)
	awaitDown(groupB)
	up, down := groupA, groupB
	for round := range scaleRounds {
		took := togetherAll(append(slices.Clone(up), down...), func(index int) {
			if slices.Contains(up, index) {
				downAsync(index)
				return
			}
			upAsync(index)
		})
		awaitDown(up)
		awaitUp(down)
		t.Logf("SCALE size=%d round=%d %d left and %d arrived in %s", size, round, len(up), len(down), took.Round(time.Millisecond))

		f.assertUntouched(t, engines, "the sessions next to it coming and going")
		assert.NoError(t, f.s.host.Isolation().Verify())
		assert.Lenf(t, f.s.host.Coordinator().Sessions().SessionInterfaces(), len(stayers)+len(down), "round %d should end with those that are up on record", round)
		for _, index := range append(slices.Clone(stayers), down...) {
			awaitRoute(t, f.networks[index].route, resources[index])
		}
		for _, index := range up {
			_, err := netlink.LinkByName(resources[index])
			assert.Errorf(t, err, "the interface of session %d should be gone", index)
		}
		awaitOneSharedOwner(t, f.networks[0].shared, resourceNames(resources, append(slices.Clone(stayers), down...)))
		up, down = down, up
	}

	togetherAll(down, upAsync)
	awaitUp(down)
	portsNow := make(map[int]uint16, size)
	for _, index := range all {
		held, running := f.s.slots.Running(f.sessionAt(t, index).key)
		require.True(t, running)
		assert.Equalf(t, resources[index], held.Interface, "session %d should stay on its interface", index)
		logMovedPort(t, slotOfInterface(t, held.Interface), held.Port)
		portsNow[index] = held.Port
	}
	assert.Len(t, uniqueValues(portsNow), size, "each session should have a port of its own")
	assertAllPairsIsolated(t, f, all, 200)

	_, err := f.s.Down(f.ctx, &proto.DownRequest{All: true})
	require.NoError(t, err)
	awaitDown(all)
	assert.Equal(t, clean.withoutEmptyBuiltins(), takeHostSnapshot(t, identityLine).withoutEmptyBuiltins(),
		"after the last session the host should be what it was before the first")
}

func slotOfInterface(t *testing.T, name string) int {
	t.Helper()
	slot, err := strconv.Atoi(strings.TrimPrefix(name, "wt"))
	require.NoErrorf(t, err, "the interface %s should be named after its slot", name)
	return slot
}

func uniqueValues[V comparable](values map[int]V) map[V]bool {
	unique := make(map[V]bool, len(values))
	for _, value := range values {
		unique[value] = true
	}
	return unique
}

func resourceNames(resources map[int]string, indices []int) []string {
	names := make([]string, 0, len(indices))
	for _, index := range indices {
		names = append(names, resources[index])
	}
	return names
}

// countingListener counts what reaches a UDP port and remembers the longest silence.
type countingListener struct {
	received atomic.Int64
	gap      atomic.Int64
}

func listenCounting(t *testing.T, port uint16) *countingListener {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: int(port)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	listener := &countingListener{}
	go func() {
		buf := make([]byte, 1500)
		var last time.Time
		for {
			if _, _, err := conn.ReadFromUDPAddrPort(buf); err != nil {
				return
			}
			now := time.Now()
			if !last.IsZero() {
				if gap := int64(now.Sub(last)); gap > listener.gap.Load() {
					listener.gap.Store(gap)
				}
			}
			last = now
			listener.received.Add(1)
		}
	}()
	return listener
}

func openDescriptors(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	require.NoError(t, err)
	return len(entries)
}

func percentile(sorted []time.Duration, percent int) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	return sorted[(len(sorted)-1)*percent/100]
}

func logCycleTimes(t *testing.T, what string, times []time.Duration) {
	t.Helper()
	sorted := slices.Clone(times)
	slices.Sort(sorted)
	t.Logf("SCALE stress %s p50=%s p99=%s max=%s", what, percentile(sorted, 50).Round(time.Millisecond), percentile(sorted, 99).Round(time.Millisecond), sorted[len(sorted)-1].Round(time.Millisecond))
}

// 100 times up and down of one session, while a peer of the other one keeps sending to the host. The
// session that runs keeps its engine, its status, its routes and its traffic, and what the cycles use
// comes back.
func TestScaleStress(t *testing.T) {
	requireScaleTests(t)
	for _, backend := range hostBackends {
		t.Run(backend.name, func(t *testing.T) {
			t.Setenv("NB_WG_KERNEL_DISABLED", "true")
			backend.setup(t)
			runScaleStress(t)
		})
	}
}

func runScaleStress(t *testing.T) {
	setIPForward(t, "0")
	clean := takeHostSnapshot(t, identityLine)
	f := newSessionsFixtureInMode(t)

	upProfile(t, f.ctx, f.s, f.work, f.username)
	work := f.session(t, f.work)
	awaitConnected(t, work, f.work)
	keepRouterConnected(t, work.statusRecorder)
	awaitRoute(t, networkWork.route, "wt0")
	engine := work.client().Engine()
	workSide := sessionSide{ss: work, iface: "wt0", network: networkWork}

	control := listenProbe(t, scaleControlPort)
	workSide.requireReachesOwnAddress(t, control, scaleControlPort)
	listener := listenCounting(t, stressProbePort)
	packet := udpPacket(t, networkWork.router, localOverlayAddr(t, work), 40000, stressProbePort)

	// The other session stays out of the table while this one holds the prefix, so the part of the
	// host that belongs to this session is the same before and after each cycle.
	workLines := func() map[string][]string {
		return sessionPart(takeHostSnapshot(t, identityLine), "wt0", "netbird\"", "netbird chain", "100.71.")
	}
	before := workLines()

	stop := make(chan struct{})
	var background sync.WaitGroup
	var sent, notConnected atomic.Int64
	background.Add(2)
	go func() {
		defer background.Done()
		ticker := time.NewTicker(stressSendInterval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				if err := engine.InjectFromPeer(packet); err != nil {
					t.Errorf("hand the packet to the interface: %v", err)
					return
				}
				sent.Add(1)
			}
		}
	}()
	go func() {
		defer background.Done()
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				if work.state.CurrentStatus() != internal.StatusConnected {
					notConnected.Add(1)
				}
			}
		}
	}()
	stopBackground := sync.OnceFunc(func() {
		close(stop)
		background.Wait()
	})
	t.Cleanup(stopBackground)

	var ups, downs []time.Duration
	var goroutinesWarm, fdsWarm int
	var memWarm, memEnd runtime.MemStats
	// A failed cycle ends the test here, with the state it left to look at in the log.
	for cycle := range stressCycles {
		began := time.Now()
		upProfile(t, f.ctx, f.s, f.home, f.username)
		home := f.session(t, f.home)
		awaitConnected(t, home, f.home)
		ups = append(ups, time.Since(began))
		require.NoErrorf(t, f.s.host.Isolation().Verify(), "the isolation in cycle %d", cycle)
		if cycle == 0 {
			keepRouterConnected(t, home.statusRecorder)
		}

		began = time.Now()
		_, err := f.s.Down(f.ctx, &proto.DownRequest{Session: f.selector(home)})
		require.NoErrorf(t, err, "Down in cycle %d", cycle)
		awaitRunEnd(t, home)
		downs = append(downs, time.Since(began))

		_, err = netlink.LinkByName("wt1")
		require.Errorf(t, err, "the interface should be gone in cycle %d", cycle)
		require.Samef(t, engine, work.client().Engine(), "the session that runs should keep its engine in cycle %d", cycle)

		// The first cycles fill what stays: caches, a pool, the connections of the Management.
		if cycle == 9 {
			runtime.GC()
			goroutinesWarm, fdsWarm = runtime.NumGoroutine(), openDescriptors(t)
			runtime.ReadMemStats(&memWarm)
		}
	}
	stopBackground()
	// The last packets are on their way, and a cycle that ended just now may still be closing.
	time.Sleep(500 * time.Millisecond)

	logCycleTimes(t, "up", ups)
	logCycleTimes(t, "down", downs)

	received, total := listener.received.Load(), sent.Load()
	lossPercent := 100 * float64(total-received) / float64(total)
	gap := time.Duration(listener.gap.Load())
	t.Logf("SCALE stress traffic sent=%d received=%d loss=%.3f%% longest silence=%s", total, received, lossPercent, gap.Round(time.Millisecond))
	assert.Positive(t, total, "the traffic should have run")
	assert.Lessf(t, lossPercent, stressMaxLossPercent, "the session that runs should keep its traffic")
	assert.Lessf(t, gap, stressMaxGap, "the session that runs should not go silent")
	assert.Zero(t, notConnected.Load(), "the session that runs should stay connected")
	assert.Same(t, engine, work.client().Engine(), "the session that runs should keep its engine")
	assert.Equal(t, before, workLines(), "the cycles should leave what belongs to the session that runs")

	runtime.GC()
	require.Eventuallyf(t, func() bool {
		return runtime.NumGoroutine() <= goroutinesWarm+stressGoroutineSlack && openDescriptors(t) <= fdsWarm+stressFDSlack
	}, 30*time.Second, 500*time.Millisecond, "what the cycles use should come back, %d goroutines and %d descriptors after the warm-up", goroutinesWarm, fdsWarm)
	runtime.ReadMemStats(&memEnd)
	t.Logf("SCALE stress resources goroutines %d -> %d fds %d -> %d heap %d KiB -> %d KiB", goroutinesWarm, runtime.NumGoroutine(), fdsWarm, openDescriptors(t), memWarm.HeapAlloc/1024, memEnd.HeapAlloc/1024)

	f.down(t, work)
	assert.Equal(t, clean.withoutEmptyBuiltins(), takeHostSnapshot(t, identityLine).withoutEmptyBuiltins(),
		"after the last session the host should be what it was before the first")
}
