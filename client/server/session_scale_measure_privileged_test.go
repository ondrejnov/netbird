//go:build privileged && linux

package server

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/netbirdio/netbird/client/firewall"
	"github.com/netbirdio/netbird/client/iface/netstack"
	"github.com/netbirdio/netbird/client/internal/hostcoord"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
)

const (
	scaleDaemonDirEnv  = "NB_TEST_SCALE_DAEMON_DIR"
	scaleDaemonUserEnv = "NB_TEST_SCALE_DAEMON_USER"

	scaleCommandUp    = "up"
	scaleCommandDown  = "down"
	scaleCommandStats = "stats"
	scaleCommandCycle = "cycle"
	scaleReplyOK      = "ok"

	// A daemon has to hold still for this long before what it uses means anything.
	measureSettle = 15 * time.Second
	measureWindow = 20 * time.Second
	// The ticks of /proc/pid/stat, USER_HZ, are 100 per second on every Linux port the agent has.
	procTicksPerSecond = 100

	rttSamples               = 20000
	rttDiscard               = 200
	rttTimeout               = 200 * time.Millisecond
	rttBlocks                = 4
	echoPort                 = 27300
	foreignProbePort         = 27400
	isolationControlAttempts = 3
	// Longer than the check of the isolation, which runs every 5 s.
	isolationCheckWait = 6 * time.Second
	// go-nat-pmp retries with a doubling timeout for 128 s.
	discoverySettle = 135 * time.Second
	// The watcher of a session stays with the session, as does what the test marks its router with.
	settledGoroutinesPerSession = 2
	settledGoroutinesSlack      = 10
	settledHeapKiB              = 30 * 1024
	settledDescriptorsSlack     = 10
	farRootLink                 = "nbscale0"
	farLink                     = "nbscale1"
	measuredRouter              = 5 * time.Second
)

var (
	farRootAddr = netip.MustParsePrefix("198.18.78.1/30")
	farAddr     = netip.MustParsePrefix("198.18.78.2/30")
	allFarRange = netip.MustParsePrefix("198.18.78.0/30")
	// The sizes the daemon goes through. 0 is the daemon before the first session.
	measureLevels = []int{0, 1, 2, 4, 8, 16}
)

// TestScaleDaemon is the daemon TestScaleMeasure measures: in a process of its own, so that what the
// Managements and the sampling use does not count. It takes one command per line on its stdin and
// answers on the file descriptor 3.
func TestScaleDaemon(t *testing.T) {
	dir := os.Getenv(scaleDaemonDirEnv)
	if dir == "" {
		t.Skip("runs only as the daemon of TestScaleMeasure")
	}
	username := os.Getenv(scaleDaemonUserEnv)

	profilemanager.ConfigDirOverride = dir
	profilemanager.DefaultConfigPathDir = dir
	profilemanager.ActiveProfileStatePath = filepath.Join(dir, "active_profile.json")
	profilemanager.DefaultConfigPath = filepath.Join(dir, "default.json")

	ctx := privilegedTestCtx()
	s := New(ctx, "console", "", false, false, false, false, true, WithMaxSessions(0))
	require.NoError(t, s.Start())

	replies := os.NewFile(3, "replies")
	reply := func(format string, args ...any) {
		_, err := fmt.Fprintf(replies, format+"\n", args...)
		require.NoError(t, err)
	}
	reply(scaleReplyOK)

	marked := make(map[string]bool)
	input := bufio.NewScanner(os.Stdin)
	for input.Scan() {
		fields := strings.Fields(input.Text())
		switch fields[0] {
		case scaleCommandUp:
			profile := fields[1]
			upProfile(t, ctx, s, profile, username)
			key := sessionKeyOf(profilemanager.ID(profile), username)
			ss := crashSession(t, s, key)
			awaitConnected(t, ss, profile)
			require.Eventually(t, func() bool {
				_, err := ss.statusRecorder.GetPeer(fixtureRouterKey)
				return err == nil
			}, 60*time.Second, 100*time.Millisecond, "the session should get its network map")
			if !marked[profile] {
				marked[profile] = true
				go markRouterConnected(ss.statusRecorder)
			}
			reply(scaleReplyOK)
		case scaleCommandDown:
			_, err := s.Down(ctx, &proto.DownRequest{All: true})
			require.NoError(t, err)
			for _, ss := range s.allSessions() {
				awaitRunEnd(t, ss)
			}
			reply(scaleReplyOK)
		case scaleCommandCycle:
			cycles, err := strconv.Atoi(fields[2])
			require.NoError(t, err)
			cycleSession(t, s, fields[1], username, cycles)
			reply(scaleReplyOK)
		case scaleCommandStats:
			// The second collection empties the sync.Pools, whose content survives the first. The
			// heap is then what the daemon keeps, not what it got around to free.
			runtime.GC()
			runtime.GC()
			var mem runtime.MemStats
			runtime.ReadMemStats(&mem)
			reply("%s %d %d %d", scaleReplyOK, mem.HeapAlloc/1024, mem.Sys/1024, runtime.NumGoroutine())
		default:
			t.Fatalf("unknown command %q", fields[0])
		}
	}
}

// cycleSession takes a running session down and up again, as often as asked.
func cycleSession(t *testing.T, s *Server, profile, username string, cycles int) {
	t.Helper()
	ctx := privilegedTestCtx()
	ss := crashSession(t, s, sessionKeyOf(profilemanager.ID(profile), username))
	selector := &proto.SessionSelector{Profile: profile, Username: username}
	for range cycles {
		_, err := s.Down(ctx, &proto.DownRequest{Session: selector})
		require.NoError(t, err)
		awaitRunEnd(t, ss)
		upProfile(t, ctx, s, profile, username)
		awaitConnected(t, ss, profile)
	}
}

// markRouterConnected is keepRouterConnected at a pace that does not show in the CPU of the daemon.
// It lives until the process ends.
func markRouterConnected(recorder *peer.Status) {
	for {
		_ = recorder.UpdatePeerState(peer.State{
			PubKey:           fixtureRouterKey,
			ConnStatus:       peer.StatusConnected,
			ConnStatusUpdate: time.Now(),
		})
		time.Sleep(measuredRouter)
	}
}

// scaleDaemon is the daemon process as TestScaleMeasure sees it.
type scaleDaemon struct {
	cmd     *exec.Cmd
	stdin   *os.File
	replies *bufio.Scanner
	log     string
	exited  chan struct{}
}

func startScaleDaemon(t *testing.T, dir, username string) *scaleDaemon {
	t.Helper()
	logFile, err := os.Create(filepath.Join(t.TempDir(), "daemon.log"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = logFile.Close() })

	stdinRead, stdinWrite, err := os.Pipe()
	require.NoError(t, err)
	repliesRead, repliesWrite, err := os.Pipe()
	require.NoError(t, err)

	cmd := exec.Command(os.Args[0], "-test.run=^TestScaleDaemon$", "-test.timeout=30m")
	cmd.Env = append(os.Environ(), scaleDaemonDirEnv+"="+dir, scaleDaemonUserEnv+"="+username)
	cmd.Stdin = stdinRead
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.ExtraFiles = []*os.File{repliesWrite}
	require.NoError(t, cmd.Start())
	_ = stdinRead.Close()
	_ = repliesWrite.Close()

	d := &scaleDaemon{cmd: cmd, stdin: stdinWrite, replies: bufio.NewScanner(repliesRead), log: logFile.Name(), exited: make(chan struct{})}
	go func() {
		defer close(d.exited)
		_ = cmd.Wait()
	}()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		<-d.exited
		_ = stdinWrite.Close()
		_ = repliesRead.Close()
		removeSessionResidue(t)
	})
	d.await(t)
	return d
}

// removeSessionResidue takes away what a daemon that had to be killed leaves, for the next backend.
func removeSessionResidue(t *testing.T) {
	t.Helper()
	links, err := netlink.LinkList()
	if err != nil {
		t.Logf("list links: %v", err)
		return
	}
	for _, link := range links {
		if slotInterface.MatchString(link.Attrs().Name) {
			_ = netlink.LinkDel(link)
		}
	}
	if err := firewall.RemoveResidualSessionIsolation(); err != nil {
		t.Logf("remove isolation: %v", err)
	}
	conn := &nftables.Conn{}
	tables, err := conn.ListTables()
	if err != nil {
		t.Logf("list tables: %v", err)
		return
	}
	for _, table := range tables {
		if strings.HasPrefix(table.Name, "netbird") {
			conn.DelTable(table)
		}
	}
	if err := conn.Flush(); err != nil {
		t.Logf("delete tables: %v", err)
	}
}

var slotInterface = regexp.MustCompile(`^wt\d+$`)

// await reads one reply. It reads in the test goroutine, and the log tells why when the daemon ended.
func (d *scaleDaemon) await(t *testing.T) string {
	t.Helper()
	if d.replies.Scan() {
		reply := d.replies.Text()
		require.Truef(t, strings.HasPrefix(reply, scaleReplyOK), "the daemon answered %q", reply)
		return strings.TrimSpace(strings.TrimPrefix(reply, scaleReplyOK))
	}
	raw, _ := os.ReadFile(d.log)
	t.Fatalf("the daemon ended early\n%s", tailOf(raw, 8000))
	return ""
}

func tailOf(raw []byte, size int) []byte {
	if len(raw) > size {
		return raw[len(raw)-size:]
	}
	return raw
}

func (d *scaleDaemon) command(t *testing.T, line string) string {
	t.Helper()
	_, err := fmt.Fprintln(d.stdin, line)
	require.NoError(t, err)
	return d.await(t)
}

func (d *scaleDaemon) openDescriptors(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", d.cmd.Process.Pid))
	require.NoError(t, err)
	return len(entries)
}

func (d *scaleDaemon) rssKiB(t *testing.T) int {
	t.Helper()
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", d.cmd.Process.Pid))
	require.NoError(t, err)
	for _, line := range strings.Split(string(raw), "\n") {
		if rest, found := strings.CutPrefix(line, "VmRSS:"); found {
			value, err := strconv.Atoi(strings.Fields(rest)[0])
			require.NoError(t, err)
			return value
		}
	}
	t.Fatal("the process has no VmRSS")
	return 0
}

// cpuTime is what the daemon has used so far, its threads and the ones that ended.
func (d *scaleDaemon) cpuTime(t *testing.T) time.Duration {
	t.Helper()
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", d.cmd.Process.Pid))
	require.NoError(t, err)
	// The name of the process can have spaces, the rest starts after its closing parenthesis.
	stat := string(raw)
	fields := strings.Fields(stat[strings.LastIndex(stat, ")")+1:])
	// utime and stime are fields 14 and 15 of the file, here counted from its third field.
	utime, err := strconv.ParseInt(fields[11], 10, 64)
	require.NoError(t, err)
	stime, err := strconv.ParseInt(fields[12], 10, 64)
	require.NoError(t, err)
	return time.Duration(utime+stime) * time.Second / procTicksPerSecond
}

// rttResult is one path at one size.
type rttResult struct {
	p50, p90, p99 time.Duration
	// bestBlock is the lowest median of the blocks, what is left without a busy moment of the host.
	bestBlock time.Duration
	lost      int
}

func (r rttResult) String() string {
	return fmt.Sprintf("p50=%.1f p90=%.1f p99=%.1f best=%.1f lost=%d", micros(r.p50), micros(r.p90), micros(r.p99), micros(r.bestBlock), r.lost)
}

func micros(d time.Duration) float64 {
	return float64(d.Nanoseconds()) / 1000
}

// echoServer answers on a UDP socket until the test ends.
func echoServer(t *testing.T, conn *net.UDPConn) {
	t.Helper()
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buf := make([]byte, 128)
		for {
			n, from, err := conn.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			if _, err := conn.WriteToUDPAddrPort(buf[:n], from); err != nil {
				return
			}
		}
	}()
}

// measureRTT sends one datagram at a time and takes how long the answer takes. The socket was opened
// where the path starts, so it stays there whichever thread uses it.
func measureRTT(t *testing.T, conn *net.UDPConn) rttResult {
	t.Helper()
	buf := make([]byte, 128)
	payload := make([]byte, 64)
	all := make([]time.Duration, 0, rttSamples)
	result := rttResult{bestBlock: time.Hour}
	blockSize := rttSamples / rttBlocks
	for block := range rttBlocks {
		samples := make([]time.Duration, 0, blockSize)
		for sequence := range blockSize + rttDiscard {
			binary.BigEndian.PutUint64(payload, uint64(sequence))
			began := time.Now()
			_, err := conn.Write(payload)
			require.NoErrorf(t, err, "send in block %d", block)
			require.NoError(t, conn.SetReadDeadline(began.Add(rttTimeout)))
			n, err := conn.Read(buf)
			if errors.Is(err, os.ErrDeadlineExceeded) {
				result.lost++
				continue
			}
			require.NoError(t, err)
			if n != len(payload) || binary.BigEndian.Uint64(buf) != uint64(sequence) {
				continue
			}
			if sequence >= rttDiscard {
				samples = append(samples, time.Since(began))
			}
		}
		require.NotEmptyf(t, samples, "block %d should get answers", block)
		slices.Sort(samples)
		result.bestBlock = min(result.bestBlock, percentile(samples, 50))
		all = append(all, samples...)
	}
	slices.Sort(all)
	result.p50, result.p90, result.p99 = percentile(all, 50), percentile(all, 90), percentile(all, 99)
	return result
}

// udpSocketTo opens a socket connected to dst in the namespace of run.
func udpSocketTo(t *testing.T, run func(func()), dst netip.Addr, port uint16) *net.UDPConn {
	t.Helper()
	var conn *net.UDPConn
	var err error
	run(func() {
		conn, err = net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(dst, port)))
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// startFarEnd is a host behind this one: a namespace of its own, one veth pair away, answering on UDP.
// What goes there from the peer goes through the forward path, as through a routing peer.
func startFarEnd(t *testing.T, tunnel *tunnelPeer) netip.Addr {
	t.Helper()
	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: farRootLink}, PeerName: farLink}
	require.NoError(t, netlink.LinkAdd(veth))
	t.Cleanup(func() { deleteLink(farRootLink) })
	root, err := netlink.LinkByName(farRootLink)
	require.NoError(t, err)
	require.NoError(t, netlink.AddrAdd(root, &netlink.Addr{IPNet: prefixToIPNet(farRootAddr)}))
	require.NoError(t, netlink.LinkSetUp(root))

	ops := make(chan func())
	threadID := make(chan int, 1)
	done := make(chan struct{})
	entered := make(chan error, 1)
	// The thread stays locked and ends with the goroutine, and the namespace ends with it.
	go func() {
		defer close(done)
		runtime.LockOSThread()
		err := unix.Unshare(unix.CLONE_NEWNET)
		entered <- err
		if err != nil {
			return
		}
		threadID <- unix.Gettid()
		for op := range ops {
			op()
		}
	}()
	require.NoError(t, <-entered, "enter a network namespace")
	t.Cleanup(func() {
		close(ops)
		<-done
	})
	run := func(op func()) {
		finished := make(chan struct{})
		ops <- func() {
			defer close(finished)
			op()
		}
		<-finished
	}

	farEnd, err := netlink.LinkByName(farLink)
	require.NoError(t, err)
	require.NoError(t, netlink.LinkSetNsPid(farEnd, <-threadID), "move the veth end")

	var setupErr error
	var conn *net.UDPConn
	run(func() {
		setupErr = configureFarEnd()
		if setupErr == nil {
			conn, setupErr = net.ListenUDP("udp4", &net.UDPAddr{Port: echoPort})
		}
	})
	require.NoError(t, setupErr, "set up the far end")
	echoServer(t, conn)

	tunnel.run(func() {
		underlay, err := netlink.LinkByName(tunnelPeerLink)
		if err != nil {
			setupErr = err
			return
		}
		setupErr = netlink.RouteAdd(&netlink.Route{LinkIndex: underlay.Attrs().Index, Dst: prefixToIPNet(allFarRange), Gw: tunnelPeerRootAddr.Addr().AsSlice()})
	})
	require.NoError(t, setupErr, "route the peer to the far end")
	return farAddr.Addr()
}

func configureFarEnd() error {
	link, err := netlink.LinkByName(farLink)
	if err != nil {
		return err
	}
	if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: prefixToIPNet(farAddr)}); err != nil {
		return err
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return err
	}
	return netlink.RouteAdd(&netlink.Route{LinkIndex: link.Attrs().Index, Dst: prefixToIPNet(netip.MustParsePrefix("198.18.0.0/15")), Gw: farRootAddr.Addr().AsSlice()})
}

func deleteLink(name string) {
	if link, err := netlink.LinkByName(name); err == nil {
		_ = netlink.LinkDel(link)
	}
}

// hookLoad is how much each packet of the host has to go through: the base chains of nftables per hook
// and the rules of both backends.
func hookLoad(t *testing.T) string {
	t.Helper()
	conn := &nftables.Conn{}
	chains, err := conn.ListChains()
	require.NoError(t, err)
	hooks := make(map[string]int)
	tables := make(map[string]bool)
	for _, chain := range chains {
		if chain.Hooknum == nil {
			continue
		}
		tables[chain.Table.Name] = true
		hooks[hookName(*chain.Hooknum)]++
	}
	names := make([]string, 0, len(hooks))
	for name := range hooks {
		names = append(names, name)
	}
	slices.Sort(names)
	parts := make([]string, 0, len(names))
	for _, name := range names {
		parts = append(parts, fmt.Sprintf("%s=%d", name, hooks[name]))
	}

	rules := 0
	for _, chain := range chains {
		list, err := conn.GetRules(chain.Table, chain)
		require.NoError(t, err)
		rules += len(list)
	}
	iptablesRules := len(linesWith(snapshotIptables(t), " -A "))
	return fmt.Sprintf("tables=%d basechains=[%s] nft_rules=%d iptables_rules=%d", len(tables), strings.Join(parts, " "), rules, iptablesRules)
}

func hookName(hook nftables.ChainHook) string {
	switch hook {
	case *nftables.ChainHookPrerouting:
		return "prerouting"
	case *nftables.ChainHookInput:
		return "input"
	case *nftables.ChainHookForward:
		return "forward"
	case *nftables.ChainHookOutput:
		return "output"
	case *nftables.ChainHookPostrouting:
		return "postrouting"
	default:
		return fmt.Sprintf("hook%d", hook)
	}
}

// measurePaths samples the paths that end at this host and that go through it.
type measurePaths struct {
	overlay  *net.UDPConn
	underlay *net.UDPConn
	forward  *net.UDPConn
}

// Memory, CPU and packet latency of a real daemon at 0 to 16 sessions, in its own process. The numbers
// go to the log with the prefix SCALE and into section 2.5 of the spec; the test asserts only what
// has to hold for them to mean anything: the paths work at every size and the host is clean after.
//
// The latency runs on three paths from a kernel WireGuard peer in a namespace: through the tunnel of
// the first session to this host, past the tunnel to this host, and past the tunnel through this host
// to a further namespace. The last two have nothing to do with the sessions, so what grows there is
// what every packet of the host pays for their rules.
func TestScaleMeasure(t *testing.T) {
	requireScaleTests(t)
	for _, mode := range scaleModes {
		for _, backend := range hostBackends {
			t.Run(mode.name+"/"+backend.name, func(t *testing.T) {
				mode.setup(t)
				backend.setup(t)
				runScaleMeasure(t, mode.name+"/"+backend.name, backendIsolationRemovers[backend.name])
			})
		}
	}
}

// backendIsolationRemovers take the isolation away behind the back of the daemon, each from its backend.
var backendIsolationRemovers = map[string]func(t *testing.T){
	"nftables": deleteNftablesIsolation,
	"iptables": flushMangleHooks,
}

// assertPeerStopsAtOwnNetwork is I4 with a real peer on a real tunnel of a real daemon, in both modes of
// the interface: what arrives at a local socket came in by the address of another network. The control
// takes the isolation away, the daemon then has seconds before it notices and puts it back (I6), and
// the same packet has to get through in that window.
func assertPeerStopsAtOwnNetwork(t *testing.T, tunnel *tunnelPeer, sessions int, removeIsolation func(t *testing.T)) {
	t.Helper()
	probe := listenProbe(t, foreignProbePort)
	foreign := make([]netip.Addr, 0, sessions-1)
	for slot := 1; slot < sessions; slot++ {
		foreign = append(foreign, interfaceAddress(t, fmt.Sprintf("wt%d", slot)))
	}
	assertNoneArrives := func(when string) {
		t.Helper()
		for _, dst := range foreign {
			tunnel.send(t, dst, foreignProbePort)
		}
		assert.Falsef(t, probe.delivered(), "I4: a peer of wt0 must not reach the host by the address of another network %s", when)
	}
	assertNoneArrives("with the isolation")

	last := foreign[len(foreign)-1]
	got := false
	for attempt := 0; attempt < isolationControlAttempts && !got; attempt++ {
		removeIsolation(t)
		tunnel.send(t, last, foreignProbePort)
		got = probe.delivered()
		// Long enough for the next removal to find the rules back.
		time.Sleep(isolationCheckWait)
	}
	assert.True(t, got, "without the isolation the packet should arrive, or the drop proves nothing")

	require.Eventually(t, func() bool {
		probe.drain()
		tunnel.send(t, last, foreignProbePort)
		return !probe.delivered()
	}, isolationRecoveryTimeout, 50*time.Millisecond, "the daemon should put the isolation back")
	probe.drain()
	assertNoneArrives("once the isolation is back")
}

// registerScaleProfiles writes a registered profile per network and gives each the slot of its index.
// The network of home goes first, for a tunnel peer: it has the address newTunnelPeer speaks from.
func registerScaleProfiles(t *testing.T, ctx context.Context, dir, signalAddr, work, username string, size int) ([]string, []hostNetwork) {
	t.Helper()
	profiles := []string{"home", work}
	networks := []hostNetwork{networkHome, networkWork}
	for index := 2; index < size; index++ {
		profiles = append(profiles, fmt.Sprintf("scale-%d", index))
		networks = append(networks, scaleNetwork(index))
	}
	for index, profile := range profiles {
		startNetwork(t, ctx, dir, profile, signalAddr, networks[index])
		key := profilemanager.SessionKey{Profile: profilemanager.ID(profile), Username: username}
		// One at a time, for the slot of each to be its index.
		writeDesiredSessions(t, map[profilemanager.SessionKey]hostcoord.DesiredState{key: hostcoord.DesiredDown})
	}
	return profiles, networks
}

func runScaleMeasure(t *testing.T, label string, removeIsolation func(t *testing.T)) {
	t.Setenv("NB_DNS_STATE_FILE", "")
	t.Setenv(netstack.EnvUseNetstackMode, "false")
	restoreSysctlsAfter(t)
	setIPForward(t, "1")
	removeLinksAfter(t)
	clean := takeHostSnapshot(t, identityLine)

	_, ctx, work, username, cfgPath := setupServerWithProfile(t)
	dir := filepath.Dir(cfgPath)
	_, signalAddr, err := startSignal(t)
	require.NoError(t, err)

	profiles, _ := registerScaleProfiles(t, ctx, dir, signalAddr, work, username, slices.Max(measureLevels))

	daemon := startScaleDaemon(t, dir, username)

	echo, err := net.ListenUDP("udp4", &net.UDPAddr{Port: echoPort})
	require.NoError(t, err)
	echoServer(t, echo)

	var (
		paths   *measurePaths
		tunnel  *tunnelPeer
		started int
	)
	sample := func(t *testing.T, level int) {
		t.Helper()
		// A start does more than the steady state: rules, routes, the first peer attempts.
		time.Sleep(measureSettle)
		cpuBefore := daemon.cpuTime(t)
		time.Sleep(measureWindow)
		idle := daemon.cpuTime(t) - cpuBefore
		cpuPercent := 100 * idle.Seconds() / measureWindow.Seconds()

		rss := daemon.rssKiB(t)
		stats := strings.Fields(daemon.command(t, scaleCommandStats))
		require.Len(t, stats, 3)
		t.Logf("SCALE measure %s sessions=%d rss_kib=%d heap_kib=%s sys_kib=%s goroutines=%s idle_cpu_pct=%.2f %s",
			label, level, rss, stats[0], stats[1], stats[2], cpuPercent, hookLoad(t))

		cpuBefore = daemon.cpuTime(t)
		began := time.Now()
		overlay := measureRTT(t, paths.overlay)
		elapsed := time.Since(began)
		load := daemon.cpuTime(t) - cpuBefore
		t.Logf("SCALE rtt %s sessions=%d path=overlay %s rtt_cpu_pct=%.1f", label, level, overlay, 100*load.Seconds()/elapsed.Seconds())
		t.Logf("SCALE rtt %s sessions=%d path=underlay %s", label, level, measureRTT(t, paths.underlay))
		t.Logf("SCALE rtt %s sessions=%d path=forward %s", label, level, measureRTT(t, paths.forward))
	}

	// The peer needs the key of a session, so the paths come up with the first session and the level
	// of none is measured last.
	setUpPaths := func(t *testing.T) {
		t.Helper()
		tunnel = newTunnelPeer(t, "wt0")
		far := startFarEnd(t, tunnel)
		overlayAddr := interfaceAddress(t, "wt0")
		paths = &measurePaths{
			overlay:  udpSocketTo(t, tunnel.run, overlayAddr, echoPort),
			underlay: udpSocketTo(t, tunnel.run, tunnelPeerRootAddr.Addr(), echoPort),
			forward:  udpSocketTo(t, tunnel.run, far, echoPort),
		}
		// The ACL of the session comes with its network map, and the handshake with the first packet.
		require.Eventually(t, func() bool {
			_, err := paths.overlay.Write([]byte("hello"))
			if err != nil {
				return false
			}
			_ = paths.overlay.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			buf := make([]byte, 64)
			_, err = paths.overlay.Read(buf)
			return err == nil
		}, 60*time.Second, 100*time.Millisecond, "the tunnel of the first session should answer")
	}

	first := strings.Fields(daemon.command(t, scaleCommandStats))
	firstDescriptors := daemon.openDescriptors(t)
	t.Logf("SCALE measure %s sessions=0 rss_kib=%d heap_kib=%s goroutines=%s fds=%d before any session", label, daemon.rssKiB(t), first[0], first[2], firstDescriptors)

	for _, level := range measureLevels[1:] {
		began := time.Now()
		for started < level {
			daemon.command(t, scaleCommandUp+" "+profiles[started])
			started++
		}
		t.Logf("SCALE measure %s sessions=%d up in %s", label, level, time.Since(began).Round(time.Millisecond))
		if paths == nil {
			setUpPaths(t)
		}
		sample(t, level)
	}

	assertPeerStopsAtOwnNetwork(t, tunnel, started, removeIsolation)

	// What the cycles leave in the daemon alone, without the Managements of the test next to it. A
	// session that just started has more going on than one that settled, a leak grows with each round.
	last := profiles[len(profiles)-1]
	stats := strings.Fields(daemon.command(t, scaleCommandStats))
	t.Logf("SCALE cycles %s sessions=%d done=0 heap_kib=%s goroutines=%s rss_kib=%d", label, started, stats[0], stats[2], daemon.rssKiB(t))
	for round := 1; round <= 2; round++ {
		daemon.command(t, fmt.Sprintf("%s %s %d", scaleCommandCycle, last, stressCycles))
		time.Sleep(measureSettle)
		stats = strings.Fields(daemon.command(t, scaleCommandStats))
		t.Logf("SCALE cycles %s sessions=%d done=%d heap_kib=%s goroutines=%s rss_kib=%d", label, started, round*stressCycles, stats[0], stats[2], daemon.rssKiB(t))
	}

	// The level of none: rules gone, paths left. It also shows how much the host itself moved.
	daemon.command(t, scaleCommandDown)
	time.Sleep(measureSettle)
	stats = strings.Fields(daemon.command(t, scaleCommandStats))
	t.Logf("SCALE measure %s sessions=0 rss_kib=%d heap_kib=%s goroutines=%s after the last session %s", label, daemon.rssKiB(t), stats[0], stats[2], hookLoad(t))
	t.Logf("SCALE rtt %s sessions=0 path=underlay %s", label, measureRTT(t, paths.underlay))
	t.Logf("SCALE rtt %s sessions=0 path=forward %s", label, measureRTT(t, paths.forward))

	// A NAT discovery of a stopped engine waits for its answer in a library with no way to cancel it.
	// Past that wait only what stays with a session and with the daemon is left.
	time.Sleep(discoverySettle)
	stats = strings.Fields(daemon.command(t, scaleCommandStats))
	descriptors := daemon.openDescriptors(t)
	t.Logf("SCALE measure %s sessions=0 rss_kib=%d heap_kib=%s goroutines=%s fds=%d settled", label, daemon.rssKiB(t), stats[0], stats[2], descriptors)
	assert.LessOrEqualf(t, descriptors, firstDescriptors+settledDescriptorsSlack, "the %d cycles should leave no descriptors", 2*stressCycles)
	goroutines, err := strconv.Atoi(stats[2])
	require.NoError(t, err)
	firstGoroutines, err := strconv.Atoi(first[2])
	require.NoError(t, err)
	assert.LessOrEqualf(t, goroutines, firstGoroutines+settledGoroutinesPerSession*started+settledGoroutinesSlack, "the %d cycles should leave no goroutines", 2*stressCycles)
	heap, err := strconv.Atoi(stats[0])
	require.NoError(t, err)
	firstHeap, err := strconv.Atoi(first[0])
	require.NoError(t, err)
	assert.LessOrEqualf(t, heap, firstHeap+settledHeapKiB, "the %d cycles should leave no memory", 2*stressCycles)

	deleteLink(tunnelPeerRootLink)
	deleteLink(farRootLink)
	assert.Equal(t, clean.withoutEmptyBuiltins(), takeHostSnapshot(t, identityLine).withoutEmptyBuiltins(), "after the last session the host should be what it was before the first")
}

// The daemon with all its sessions dies the way a panic would end it. The interfaces of a kernel
// session survive that. The next start cleans up after all of them, brings them back on their slots
// at once, and after the last one the host is what it was, but for the original sysctls (Q22).
func TestScaleCrash(t *testing.T) {
	requireScaleTests(t)
	for _, backend := range hostBackends {
		t.Run(backend.name, func(t *testing.T) {
			requireKernelInterface(t)
			backend.setup(t)
			runScaleCrash(t, slices.Max(measureLevels))
		})
	}
}

func runScaleCrash(t *testing.T, size int) {
	t.Setenv("NB_DNS_STATE_FILE", "")
	t.Setenv(netstack.EnvUseNetstackMode, "false")
	restoreSysctlsAfter(t)
	clean := takeHostSnapshot(t, identityLine)

	_, ctx, work, username, cfgPath := setupServerWithProfile(t)
	dir := filepath.Dir(cfgPath)
	_, signalAddr, err := startSignal(t)
	require.NoError(t, err)
	profiles, networks := registerScaleProfiles(t, ctx, dir, signalAddr, work, username, size)

	daemon := startScaleDaemon(t, dir, username)
	for _, profile := range profiles {
		daemon.command(t, scaleCommandUp+" "+profile)
	}
	require.NoError(t, daemon.cmd.Process.Kill())
	<-daemon.exited

	for index := range size {
		_, err := netlink.LinkByName(fmt.Sprintf("wt%d", index))
		require.NoErrorf(t, err, "the crash should leave the interface of slot %d", index)
	}

	rootCtx, cancelRoot := context.WithCancel(ctx)
	restarted := New(rootCtx, "console", "", false, false, false, false, true, WithMaxSessions(0))
	began := time.Now()
	require.NoError(t, restarted.Start(), "the start after the crash")
	t.Cleanup(func() {
		if err := restarted.StopSessions(ctx); err != nil {
			t.Logf("stop sessions: %v", err)
		}
		cancelRoot()
	})
	sessions := make([]*session, 0, size)
	for index, profile := range profiles {
		ss := crashSession(t, restarted, profilemanager.SessionKey{Profile: profilemanager.ID(profile), Username: username})
		awaitConnected(t, ss, profile)
		resources, running := restarted.slots.Running(ss.key)
		require.Truef(t, running, "session %d should hold its resources", index)
		assert.Equalf(t, fmt.Sprintf("wt%d", index), resources.Interface, "session %d should come back on its slot", index)
		requireInterfaceAddress(t, resources.Interface, networks[index].overlay, ss)
		sessions = append(sessions, ss)
	}
	t.Logf("SCALE crash size=%d back in %s", size, time.Since(began).Round(time.Millisecond))
	assert.NoError(t, restarted.host.Isolation().Verify())

	_, err = restarted.Down(ctx, &proto.DownRequest{All: true})
	require.NoError(t, err)
	for _, ss := range sessions {
		awaitRunEnd(t, ss)
	}

	want, got := clean.withoutEmptyBuiltins(), takeHostSnapshot(t, identityLine).withoutEmptyBuiltins()
	delete(want, "sysctl")
	delete(got, "sysctl")
	assert.Equal(t, want, got, "after the last session the host should be what it was before the crash")
}
