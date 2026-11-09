//go:build privileged && linux

package server

import (
	"context"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/firewall"
	"github.com/netbirdio/netbird/client/iface/netstack"
	"github.com/netbirdio/netbird/client/internal/hostcoord"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
)

const (
	crashDaemonDirEnv  = "NB_TEST_CRASH_DAEMON_DIR"
	crashDaemonReady   = "daemon-ready"
	crashWorkInterface = "wt0"
	crashHomeInterface = "wt1"

	tunnelPeerRootLink = "nbcrash0"
	tunnelPeerLink     = "nbcrash1"
	tunnelPeerDevice   = "wtpeer"
	crashProbePort     = 47123
)

var (
	tunnelPeerRootAddr = netip.MustParsePrefix("198.18.77.1/30")
	tunnelPeerUnderlay = netip.MustParsePrefix("198.18.77.2/30")
	// The address of the routing peer of home, the one peer its firewall rules let in.
	tunnelPeerOverlay = netip.PrefixFrom(networkHome.router, 32)
	tunnelPeerAllowed = netip.MustParsePrefix("100.64.0.0/10")
)

// TestCrashingDaemon is the daemon TestCrashedSessionInterfaceCarriesNoPeerTraffic kills. It brings
// back the stored sessions, reports them connected and waits for its end, so everything a crash
// leaves on the host is what a real daemon left there.
func TestCrashingDaemon(t *testing.T) {
	dir := os.Getenv(crashDaemonDirEnv)
	if dir == "" {
		t.Skip("runs only as the daemon of TestCrashedSessionInterfaceCarriesNoPeerTraffic")
	}

	profilemanager.ConfigDirOverride = dir
	profilemanager.DefaultConfigPathDir = dir
	profilemanager.ActiveProfileStatePath = filepath.Join(dir, "active_profile.json")
	profilemanager.DefaultConfigPath = filepath.Join(dir, "default.json")

	s := New(privilegedTestCtx(), "console", "", false, false, false, false, true)
	require.NoError(t, s.Start())

	records, err := hostcoord.StoredRecords(dir)
	require.NoError(t, err)
	for _, record := range records {
		ss := crashSession(t, s, record.Key)
		awaitConnected(t, ss, string(record.Key.Profile))
		// The engine applies the ACL of a network map before it adds the peers, so the peer on
		// the status means the firewall of the session lets it in.
		require.Eventually(t, func() bool {
			_, err := ss.statusRecorder.GetPeer(fixtureRouterKey)
			return err == nil
		}, 60*time.Second, 100*time.Millisecond, "the session should get its network map")
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, crashDaemonReady), nil, 0o600))
	select {}
}

func crashSession(t *testing.T, s *Server, key profilemanager.SessionKey) *session {
	t.Helper()
	normalized := sessionKeyOf(key.Profile, key.Username)
	var ss *session
	require.Eventuallyf(t, func() bool {
		s.mutex.Lock()
		defer s.mutex.Unlock()
		if found, ok := s.sessions[normalized]; ok {
			ss = found
			return true
		}
		// A session an Up started for a profile in the shared directory carries no username.
		for candidate, found := range s.sessions {
			if candidate.Profile == key.Profile {
				ss = found
				return true
			}
		}
		return false
	}, 60*time.Second, 100*time.Millisecond, "profile %s should have a session", key.Profile)
	return ss
}

// runCrashingDaemon starts the daemon in a process of its own, waits for both sessions and kills
// it the way a panic would end it: nothing of the daemon runs after that.
func runCrashingDaemon(t *testing.T, dir string) {
	t.Helper()

	logFile, err := os.Create(filepath.Join(t.TempDir(), "daemon.log"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = logFile.Close() })

	cmd := exec.Command(os.Args[0], "-test.run=^TestCrashingDaemon$", "-test.timeout=5m")
	cmd.Env = append(os.Environ(), crashDaemonDirEnv+"="+dir)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	require.NoError(t, cmd.Start())

	var waitErr error
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		waitErr = cmd.Wait()
	}()

	ready := filepath.Join(dir, crashDaemonReady)
	deadline := time.After(2 * time.Minute)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		select {
		case <-exited:
			raw, _ := os.ReadFile(logFile.Name())
			t.Fatalf("the daemon ended early: %v\n%s", waitErr, raw)
		case <-deadline:
			_ = cmd.Process.Kill()
			<-exited
			raw, _ := os.ReadFile(logFile.Name())
			t.Fatalf("the sessions of the daemon did not connect\n%s", raw)
		case <-time.After(100 * time.Millisecond):
		}
	}

	require.NoError(t, cmd.Process.Kill())
	<-exited
}

// tunnelPeer is a peer of the network behind a session interface: a kernel WireGuard device in a
// namespace of its own, connected to the host over a veth pair. What it sends arrives through the
// interface of the session exactly as the traffic of a real peer does.
type tunnelPeer struct {
	run func(func())
}

func newTunnelPeer(t *testing.T, sessionInterface string) *tunnelPeer {
	t.Helper()

	wg, err := wgctrl.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = wg.Close() })
	device, err := wg.Device(sessionInterface)
	require.NoError(t, err, "the crash should leave the device of the session")
	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)

	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: tunnelPeerRootLink}, PeerName: tunnelPeerLink}
	require.NoError(t, netlink.LinkAdd(veth))
	t.Cleanup(func() {
		if link, err := netlink.LinkByName(tunnelPeerRootLink); err == nil {
			_ = netlink.LinkDel(link)
		}
	})
	root, err := netlink.LinkByName(tunnelPeerRootLink)
	require.NoError(t, err)
	require.NoError(t, netlink.AddrAdd(root, &netlink.Addr{IPNet: prefixToIPNet(tunnelPeerRootAddr)}))
	require.NoError(t, netlink.LinkSetUp(root))

	peer := &tunnelPeer{}
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
	peer.run = func(op func()) {
		finished := make(chan struct{})
		ops <- func() {
			defer close(finished)
			op()
		}
		<-finished
	}

	peerLink, err := netlink.LinkByName(tunnelPeerLink)
	require.NoError(t, err)
	require.NoError(t, netlink.LinkSetNsPid(peerLink, <-threadID), "move the veth end to the peer")

	var setupErr error
	peer.run(func() { setupErr = configureTunnelPeer(key, device.PublicKey, device.ListenPort) })
	require.NoError(t, setupErr, "set up the peer")

	require.NoError(t, wg.ConfigureDevice(sessionInterface, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{{
			PublicKey:  key.PublicKey(),
			AllowedIPs: []net.IPNet{*prefixToIPNet(tunnelPeerOverlay)},
		}},
	}), "make the peer known to the session interface, as Management did before the crash")
	return peer
}

func configureTunnelPeer(key wgtypes.Key, sessionKey wgtypes.Key, sessionPort int) error {
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		return err
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		return err
	}

	underlay, err := netlink.LinkByName(tunnelPeerLink)
	if err != nil {
		return err
	}
	if err := netlink.AddrAdd(underlay, &netlink.Addr{IPNet: prefixToIPNet(tunnelPeerUnderlay)}); err != nil {
		return err
	}
	if err := netlink.LinkSetUp(underlay); err != nil {
		return err
	}

	if err := netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: tunnelPeerDevice, MTU: 1280}}); err != nil {
		return err
	}
	device, err := netlink.LinkByName(tunnelPeerDevice)
	if err != nil {
		return err
	}
	wg, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer func() { _ = wg.Close() }()
	err = wg.ConfigureDevice(tunnelPeerDevice, wgtypes.Config{
		PrivateKey: &key,
		Peers: []wgtypes.PeerConfig{{
			PublicKey:  sessionKey,
			Endpoint:   &net.UDPAddr{IP: tunnelPeerRootAddr.Addr().AsSlice(), Port: sessionPort},
			AllowedIPs: []net.IPNet{*prefixToIPNet(tunnelPeerAllowed)},
		}},
	})
	if err != nil {
		return err
	}
	if err := netlink.AddrAdd(device, &netlink.Addr{IPNet: prefixToIPNet(tunnelPeerOverlay)}); err != nil {
		return err
	}
	if err := netlink.LinkSetUp(device); err != nil {
		return err
	}
	return netlink.RouteAdd(&netlink.Route{LinkIndex: device.Attrs().Index, Dst: prefixToIPNet(tunnelPeerAllowed)})
}

// send hands one UDP datagram for dst to the peer's kernel, which sends it through the tunnel.
func (p *tunnelPeer) send(t *testing.T, dst netip.Addr, port uint16) {
	t.Helper()
	var sendErr error
	p.run(func() {
		conn, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(dst, port)))
		if err != nil {
			sendErr = err
			return
		}
		defer func() { _ = conn.Close() }()
		_, sendErr = conn.Write([]byte("peer"))
	})
	require.NoError(t, sendErr, "the peer should be able to send to %s", dst)
}

func prefixToIPNet(prefix netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: prefix.Addr().AsSlice(), Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen())}
}

func interfaceAddress(t *testing.T, name string) netip.Addr {
	t.Helper()
	link, err := netlink.LinkByName(name)
	require.NoErrorf(t, err, "interface %s should exist", name)
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	require.NoError(t, err)
	require.NotEmptyf(t, addrs, "interface %s should have an address", name)
	addr, ok := netip.AddrFromSlice(addrs[0].IP.To4())
	require.True(t, ok)
	return addr
}

// restoreSysctlsAfter puts back what a crash leaves changed (Q22), for the tests after this one.
func restoreSysctlsAfter(t *testing.T) {
	t.Helper()
	paths := []string{
		"/proc/sys/net/ipv4/ip_forward",
		"/proc/sys/net/ipv4/conf/all/rp_filter",
		"/proc/sys/net/ipv4/conf/all/src_valid_mark",
	}
	for _, path := range paths {
		original, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		t.Cleanup(func() {
			if err := os.WriteFile(path, original, 0o644); err != nil {
				t.Logf("restore %s: %v", path, err)
			}
		})
	}
}

// removeLinksAfter deletes what the test leaves on a daemon's way out, whatever way it fails.
func removeLinksAfter(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		for _, name := range []string{crashWorkInterface, crashHomeInterface} {
			if link, err := netlink.LinkByName(name); err == nil {
				_ = netlink.LinkDel(link)
			}
		}
		if err := firewall.RemoveResidualSessionIsolation(); err != nil {
			t.Logf("remove isolation: %v", err)
		}
	})
}

// A daemon with two sessions crashes. On the next start the session of work comes back, while the
// Management of home is gone, so home never gets to the point of joining the isolation. Its
// interface survived the crash with its peers on it. Unless the start deals with it, such a peer
// has the interface for as long as home stays away, outside the isolation of the new daemon: it
// reaches a local service through the address of work, which is what I3, I4 and I6 forbid.
func TestCrashedSessionInterfaceCarriesNoPeerTraffic(t *testing.T) {
	for _, backend := range hostBackends {
		t.Run(backend.name, func(t *testing.T) {
			backend.setup(t)
			runCrashedSessionInterface(t)
		})
	}
}

func runCrashedSessionInterface(t *testing.T) {
	requireKernelInterface(t)
	t.Setenv("NB_DNS_STATE_FILE", "")
	t.Setenv(netstack.EnvUseNetstackMode, "false")
	restoreSysctlsAfter(t)
	removeLinksAfter(t)

	_, ctx, work, username, cfgPath := setupServerWithProfile(t)
	// The RPCs here name their profiles themselves, which the gate resolves one by one.
	ctx = withTarget(ctx, "")
	dir := filepath.Dir(cfgPath)
	_, signalAddr, err := startSignal(t)
	require.NoError(t, err)

	const home = "home"
	startNetwork(t, ctx, dir, work, signalAddr, networkWork)
	homeManagement := startNetwork(t, ctx, dir, home, signalAddr, networkHome)

	workKey := profilemanager.SessionKey{Profile: profilemanager.ID(work), Username: username}
	homeKey := profilemanager.SessionKey{Profile: profilemanager.ID(home), Username: username}
	writeDesiredSessions(t, map[profilemanager.SessionKey]hostcoord.DesiredState{workKey: hostcoord.DesiredUp})
	writeDesiredSessions(t, map[profilemanager.SessionKey]hostcoord.DesiredState{homeKey: hostcoord.DesiredUp})

	runCrashingDaemon(t, dir)

	workAddr := interfaceAddress(t, crashWorkInterface)
	homeAddr := interfaceAddress(t, crashHomeInterface)
	peer := newTunnelPeer(t, crashHomeInterface)
	probe := listenProbe(t, crashProbePort)

	// The control: the tunnel works, the interface of home carries the traffic of its peer.
	require.Eventually(t, func() bool {
		peer.send(t, homeAddr, crashProbePort)
		return probe.delivered()
	}, 30*time.Second, 100*time.Millisecond, "a peer should reach the host through the interface the crash left")

	homeManagement.Stop()

	rootCtx, cancelRoot := context.WithCancel(ctx)
	daemon := New(rootCtx, "console", "", false, false, false, false, true)
	require.NoError(t, daemon.Start(), "the start after the crash")
	t.Cleanup(func() {
		if err := daemon.StopSessions(ctx); err != nil {
			t.Logf("stop sessions: %v", err)
		}
		cancelRoot()
	})
	awaitConnected(t, crashSession(t, daemon, workKey), work)
	probe.drain()

	// The peer of home keeps trying. Nothing it sends may arrive anymore, through any address.
	for _, dst := range []netip.Addr{workAddr, homeAddr} {
		for range 3 {
			peer.send(t, dst, crashProbePort)
			assert.Falsef(t, probe.delivered(), "a peer of the crashed session reached a local service through %s", dst)
		}
	}

	_, err = netlink.LinkByName(crashHomeInterface)
	assert.Errorf(t, err, "the interface of the session that stayed away should be gone")
}
