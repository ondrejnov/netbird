//go:build e2e

package concurrentprofiles

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/e2e/harness"
)

const (
	connectTimeout = 2 * time.Minute
	pingCount      = 3
)

// daemonMode is one combination of the interface and the firewall of the host: where the packets
// flow and who isolates the sessions depend on it.
type daemonMode struct {
	name     string
	kernel   bool
	nftables bool
}

var daemonModes = []daemonMode{
	{name: "kernel-nftables", kernel: true, nftables: true},
	{name: "kernel-iptables", kernel: true},
	{name: "userspace-nftables", nftables: true},
	{name: "userspace-iptables"},
}

// The acceptance scenario of the specification, in each mode: both profiles come up through the
// CLI on one daemon, the data goes between real peers through the interface of each network, the
// end of one session leaves the routes, the firewall and the DNS of the other as they were, and a
// network overlapping another one is refused without touching anything.
func TestAcceptanceScenario(t *testing.T) {
	for _, mode := range daemonModes {
		t.Run(mode.name, func(t *testing.T) {
			runScenario(t, mode)
		})
	}
}

func runScenario(t *testing.T, mode daemonMode) {
	ctx := context.Background()
	d := startDaemon(ctx, t, mode)
	if mode.kernel {
		d.requireKernelInterface(ctx, t)
	}

	cleanHost := d.snapshot(ctx, t).withoutEmptyBuiltins()

	d.cli(ctx, t, "up", "--profile", work.profile, "--management-url", work.server.ExposedURL(), "--setup-key", work.setupKey)
	d.cli(ctx, t, "up", "--profile", home.profile, "--management-url", home.server.ExposedURL(), "--setup-key", home.setupKey)

	// `netbird status`: both connected, each with its interface and an address of its network.
	st := d.status(ctx, t)
	require.Len(t, st.sessionsNamed(work.profile, home.profile), 2, "status lists both sessions: %+v", st.Sessions)
	workSession, homeSession := st.session(t, work.profile), st.session(t, home.profile)
	assert.Equal(t, "Connected", workSession.Status, "the first session is connected")
	assert.Equal(t, "Connected", homeSession.Status, "the second session is connected")
	require.Equal(t, "wt0", workSession.InterfaceName, "the first session has slot 0")
	require.Equal(t, "wt1", homeSession.InterfaceName, "the second session has slot 1")
	workIP, homeIP := workSession.overlayAddr(t), homeSession.overlayAddr(t)
	assert.True(t, work.overlay.Contains(workIP), "the first session has %s, outside %s", workIP, work.overlay)
	assert.True(t, home.overlay.Contains(homeIP), "the second session has %s, outside %s", homeIP, home.overlay)
	assert.True(t, homeSession.Focused, "the profile of the last up has the focus")
	assert.Equal(t, mode.kernel, st.KernelInterface, "the daemon runs the interface this mode asks for")
	text := d.cli(ctx, t, "status")
	t.Log(text)
	assert.Contains(t, text, "Sessions:", "the text output lists the sessions")
	assert.Equal(t, work.profile, d.status(ctx, t, "--profile", work.profile).ProfileName, "--profile names the session of the summary")
	d.assertBackend(ctx, t, mode)

	// Ping through each interface, and back from each peer.
	d.pingThrough(ctx, t, work.peerIP(ctx, t), "wt0")
	d.pingThrough(ctx, t, home.peerIP(ctx, t), "wt1")
	d.pingThrough(ctx, t, work.routedHost, "wt0")
	d.pingThrough(ctx, t, home.routedHost, "wt1")
	pingFrom(ctx, t, work.peer, workIP)
	pingFrom(ctx, t, home.peer, homeIP)
	assert.Equal(t, work.peerIP(ctx, t).String(), d.resolve(ctx, t, work, mode, workIP, work.peerFQDN), "the DNS of the first network")
	assert.Equal(t, home.peerIP(ctx, t).String(), d.resolve(ctx, t, home, mode, homeIP, home.peerFQDN), "the DNS of the second network")

	// `netbird down --profile doma`: the first session has what it had, on the same link.
	bothUp := d.snapshot(ctx, t)
	assertHolds(t, bothUp, work.routed.String(), "the route of the first network is installed")
	assertHolds(t, bothUp, home.routed.String(), "the route of the second network is installed")
	assertFirewallOfSlotZero(t, bothUp.without(homeSide()), mode)
	workLink := d.linkIndex(ctx, t, "wt0")

	d.cli(ctx, t, "down", "--profile", home.profile)

	oneUp := d.snapshot(ctx, t)
	assert.Equal(t, bothUp.without(homeSide()), oneUp.without(homeSide()), "the end of one session changes nothing of the other")
	assertHolds(t, oneUp, "dev wt0", "the first interface keeps its routes")
	assertHolds(t, oneUp, work.routed.String(), "the route of the first network stays")
	assert.Empty(t, oneUp.lines(homeSide()), "the second session leaves nothing behind")

	assert.Equal(t, workLink, d.linkIndex(ctx, t, "wt0"), "the first interface was not recreated")
	st = d.status(ctx, t)
	assert.Equal(t, "Connected", st.session(t, work.profile).Status, "the first session runs on")
	assert.Equal(t, "Idle", d.status(ctx, t, "--profile", home.profile).DaemonStatus, "the second session is down")
	d.pingThrough(ctx, t, work.peerIP(ctx, t), "wt0")
	d.pingThrough(ctx, t, work.routedHost, "wt0")
	assert.Equal(t, work.peerIP(ctx, t).String(), d.resolve(ctx, t, work, mode, workIP, work.peerFQDN), "the DNS of the first network keeps answering")

	// An overlapping network is refused, says why, and touches nothing.
	require.NoError(t, home.setOverlay(ctx, work.overlay))
	t.Cleanup(func() { require.NoError(t, home.setOverlay(context.Background(), home.overlay)) })

	code, out := d.exec(ctx, t, "netbird", "up", "--profile", home.profile)
	assert.NotZero(t, code, "up of an overlapping network must fail: %s", out)
	t.Log(out)
	assert.Contains(t, out, "overlaps", "the refusal says why")
	refused := d.status(ctx, t, "--profile", home.profile)
	assert.Equal(t, "Idle", refused.DaemonStatus, "the refused session does not run")
	assert.Equal(t, "overlay", refused.session(t, home.profile).Conflict, "status names the conflict")
	t.Log(d.cli(ctx, t, "status"))
	assert.NotEqual(t, "wt1", refused.session(t, home.profile).InterfaceName, "the refused session has no interface")
	assert.Equal(t, oneUp, d.snapshot(ctx, t), "the refusal changes nothing on the host")
	assert.Equal(t, workLink, d.linkIndex(ctx, t, "wt0"), "the first interface was not recreated by the refusal")
	d.pingThrough(ctx, t, work.peerIP(ctx, t), "wt0")

	// The way out of the overlap the documentation gives: another range, and up again.
	require.NoError(t, home.setOverlay(ctx, home.overlay))
	d.cli(ctx, t, "up", "--profile", home.profile)
	back := d.status(ctx, t, "--profile", home.profile)
	// The file backend gives the DNS of the host to one session, so dns is a valid value here.
	assert.NotEqual(t, "overlay", back.session(t, home.profile).Conflict, "the conflict ended with the overlap")
	assert.Equal(t, "Connected", back.session(t, home.profile).Status, "the session runs again")
	assert.Equal(t, "wt1", back.session(t, home.profile).InterfaceName, "the session keeps its slot")
	d.pingThrough(ctx, t, home.peerIP(ctx, t), "wt1")

	// After the last session the host is what it was before the first one.
	d.cli(ctx, t, "down", "--all")
	assert.Equal(t, cleanHost, d.snapshot(ctx, t).withoutEmptyBuiltins(), "the host returns to its original state")
}

// daemon is the container with the gate on, driven only through the CLI in it.
type daemon struct {
	*harness.Client
}

func startDaemon(ctx context.Context, t *testing.T, mode daemonMode) *daemon {
	t.Helper()

	kernelDisabled := strconv.FormatBool(!mode.kernel)
	client, err := harness.StartDaemon(ctx, "multi-"+mode.name, []*harness.Combined{work.server, home.server}, map[string]string{
		"NB_DAEMON_ADDR":         daemonSocket,
		"NB_WG_KERNEL_DISABLED":  kernelDisabled,
		"NB_SKIP_NFTABLES_CHECK": strconv.FormatBool(!mode.nftables),
	}, "--enable-concurrent-profiles")
	require.NoError(t, err, "start the daemon")
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("log of the daemon:\n%s", client.Logs(context.Background()))
		}
		_ = client.Terminate(context.Background())
	})
	d := &daemon{Client: client}

	require.Eventually(t, func() bool {
		code, _, err := client.Exec(ctx, "netbird", "status", "--check", "live")
		return err == nil && code == 0
	}, time.Minute, time.Second, "the daemon must start")

	if mode.nftables {
		// The firewall of the daemon goes for iptables unless a table named filter has a chain.
		d.must(ctx, t, "nft", "add", "table", "ip", "filter")
		d.must(ctx, t, "nft", "add", "chain", "ip", "filter", "e2e-backend", "{ type filter hook forward priority 0; }")
	}
	return d
}

// requireKernelInterface skips the mode on a kernel without WireGuard, where the daemon would
// fall back to the userspace interface and the mode would not be what it says.
func (d *daemon) requireKernelInterface(ctx context.Context, t *testing.T) {
	t.Helper()
	const probe = "e2e-wg-probe"
	if code, out := d.exec(ctx, t, "ip", "link", "add", probe, "type", "wireguard"); code != 0 {
		t.Skipf("kernel WireGuard is not available here: %s", out)
	}
	d.must(ctx, t, "ip", "link", "del", probe)
}

// exec runs a command in the container and returns its exit code and output.
func (d *daemon) exec(ctx context.Context, t *testing.T, cmd ...string) (int, string) {
	t.Helper()
	code, out, err := d.Exec(ctx, cmd...)
	require.NoError(t, err, "exec %v", cmd)
	return code, out
}

// must runs a command in the container that has to succeed.
func (d *daemon) must(ctx context.Context, t *testing.T, cmd ...string) string {
	t.Helper()
	code, out := d.exec(ctx, t, cmd...)
	require.Zerof(t, code, "%v: %s", cmd, out)
	return out
}

// cli runs a command of the real CLI against the daemon of the container.
func (d *daemon) cli(ctx context.Context, t *testing.T, args ...string) string {
	t.Helper()
	return d.must(ctx, t, append([]string{"netbird"}, args...)...)
}

type sessionStatus struct {
	ProfileName   string `json:"profileName"`
	Status        string `json:"status"`
	InterfaceName string `json:"interfaceName"`
	OverlayIP     string `json:"overlayIp"`
	Focused       bool   `json:"focused"`
	Conflict      string `json:"conflict"`
}

type statusOutput struct {
	DaemonStatus    string          `json:"daemonStatus"`
	ProfileName     string          `json:"profileName"`
	IP              string          `json:"netbirdIp"`
	KernelInterface bool            `json:"usesKernelInterface"`
	Sessions        []sessionStatus `json:"sessions"`
}

func (d *daemon) status(ctx context.Context, t *testing.T, args ...string) statusOutput {
	t.Helper()
	return parseStatus(t, d.cli(ctx, t, append([]string{"status", "--json"}, args...)...))
}

// parseStatus reads the JSON of `netbird status`, which the logging of the CLI may surround on
// the combined output of the exec.
func parseStatus(t *testing.T, out string) statusOutput {
	t.Helper()
	start, end := strings.Index(out, "{"), strings.LastIndex(out, "}")
	require.True(t, start >= 0 && end > start, "no JSON in the output: %s", out)
	var st statusOutput
	require.NoError(t, json.Unmarshal([]byte(out[start:end+1]), &st), out)
	return st
}

func (s statusOutput) sessionsNamed(names ...string) []sessionStatus {
	var found []sessionStatus
	for _, session := range s.Sessions {
		for _, name := range names {
			if session.ProfileName == name {
				found = append(found, session)
			}
		}
	}
	return found
}

func (s statusOutput) session(t *testing.T, name string) sessionStatus {
	t.Helper()
	found := s.sessionsNamed(name)
	require.Lenf(t, found, 1, "status lists session %s once: %+v", name, s.Sessions)
	return found[0]
}

func (s sessionStatus) overlayAddr(t *testing.T) netip.Addr {
	t.Helper()
	prefix, err := netip.ParsePrefix(s.OverlayIP)
	if err == nil {
		return prefix.Addr()
	}
	addr, err := netip.ParseAddr(s.OverlayIP)
	require.NoError(t, err, "overlay address of %s", s.ProfileName)
	return addr
}

// peerIP is the current address of the peer. Management gives another one when the range changes.
func (n *overlayNetwork) peerIP(ctx context.Context, t *testing.T) netip.Addr {
	t.Helper()
	var addr netip.Addr
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		code, out, err := n.peer.Exec(ctx, "netbird", "status", "--json")
		if !assert.NoError(c, err) || !assert.Zero(c, code, out) {
			return
		}
		start, end := strings.Index(out, "{"), strings.LastIndex(out, "}")
		if !assert.True(c, start >= 0 && end > start, out) {
			return
		}
		var st statusOutput
		if !assert.NoError(c, json.Unmarshal([]byte(out[start:end+1]), &st)) {
			return
		}
		prefix, err := netip.ParsePrefix(st.IP)
		if assert.NoError(c, err, "address of the peer: %q", st.IP) && assert.True(c, n.overlay.Contains(prefix.Addr()), "the peer still has %s", prefix) {
			addr = prefix.Addr()
		}
	}, connectTimeout, time.Second, "the peer of %s must have an address of its network", n.profile)
	return addr
}

// pingThrough pings the target until the tunnel carries it, and then shows that the packets of
// another ping leave through the interface of its network.
func (d *daemon) pingThrough(ctx context.Context, t *testing.T, target netip.Addr, iface string) {
	t.Helper()

	addr := target.String()
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		code, out, err := d.Exec(ctx, "ping", "-c", "1", "-W", "2", addr)
		assert.NoError(c, err)
		assert.Zero(c, code, out)
	}, connectTimeout, time.Second, "%s must answer through %s", addr, iface)

	assert.Contains(t, d.must(ctx, t, "ip", "route", "get", addr), "dev "+iface+" ", "the route to %s", addr)

	before := d.txPackets(ctx, t, iface)
	d.must(ctx, t, "ping", "-c", strconv.Itoa(pingCount), "-W", "2", addr)
	sent := d.txPackets(ctx, t, iface) - before
	assert.GreaterOrEqual(t, sent, uint64(pingCount), "the ping of %s must leave through %s", addr, iface)
}

func (d *daemon) txPackets(ctx context.Context, t *testing.T, iface string) uint64 {
	t.Helper()
	out := d.must(ctx, t, "cat", "/sys/class/net/"+iface+"/statistics/tx_packets")
	count, err := strconv.ParseUint(strings.TrimSpace(out), 10, 64)
	require.NoError(t, err, out)
	return count
}

func (d *daemon) linkIndex(ctx context.Context, t *testing.T, iface string) string {
	t.Helper()
	return strings.TrimSpace(d.must(ctx, t, "cat", "/sys/class/net/"+iface+"/ifindex"))
}

// pingFrom pings the daemon from a peer, the other direction of the same tunnel.
func pingFrom(ctx context.Context, t *testing.T, peer *harness.Client, target netip.Addr) {
	t.Helper()
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		code, out, err := peer.Exec(ctx, "ping", "-c", "1", "-W", "2", target.String())
		assert.NoError(c, err)
		assert.Zero(c, code, out)
	}, connectTimeout, time.Second, "%s must answer the peer", target)
}

// resolve asks the DNS server of a session for a name of its network. The hosts file of the
// container and the file backend do not say whether the server of the session runs, so the test
// asks it directly: on the address of the session with the kernel interface, on the last address
// of the network, which only the filter of the interface answers, with the userspace one.
func (d *daemon) resolve(ctx context.Context, t *testing.T, n *overlayNetwork, mode daemonMode, sessionIP netip.Addr, name string) string {
	t.Helper()

	server := sessionIP
	if !mode.kernel {
		server = lastAddrOf(n.overlay)
	}
	answer := regexp.MustCompile(`Address:\s*(\d+\.\d+\.\d+\.\d+)\s*$`)

	var found string
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		code, out, err := d.Exec(ctx, "nslookup", "-type=a", name, server.String())
		assert.NoError(c, err)
		if !assert.Zero(c, code, out) {
			return
		}
		lines := strings.Split(out, "\n")
		for _, line := range lines[min(2, len(lines)):] {
			if m := answer.FindStringSubmatch(strings.TrimSpace(line)); m != nil && m[1] != server.String() {
				found = m[1]
			}
		}
		assert.NotEmpty(c, found, out)
	}, connectTimeout, time.Second, "%s must answer for %s", server, name)
	return found
}

// lastAddrOf is the last usable address of a network, where the userspace DNS service answers.
func lastAddrOf(prefix netip.Prefix) netip.Addr {
	raw := prefix.Masked().Addr().As4()
	host := uint32(1)<<(32-prefix.Bits()) - 2
	value := uint32(raw[0])<<24 | uint32(raw[1])<<16 | uint32(raw[2])<<8 | uint32(raw[3])
	value += host
	return netip.AddrFrom4([4]byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)})
}

// assertBackend fails the mode that does not run on the firewall it names, so that the table of
// modes cannot stop meaning what it says.
func (d *daemon) assertBackend(ctx context.Context, t *testing.T, mode daemonMode) {
	t.Helper()
	tables := d.must(ctx, t, "nft", "list", "tables")
	if mode.nftables {
		assert.Contains(t, tables, "netbird-1", "the session of slot 1 has its nftables table")
		return
	}
	assert.NotContains(t, tables, "netbird", "the iptables backend has no table of its own")
	assert.Contains(t, d.must(ctx, t, "iptables-save"), "NETBIRD", "the iptables backend has its chains")
}

// assertFirewallOfSlotZero keeps the comparison of the snapshots from passing on nothing: what is
// left of the second session has to hold the rules of the first one.
func assertFirewallOfSlotZero(t *testing.T, snapshot hostSnapshot, mode daemonMode) {
	t.Helper()
	if mode.nftables {
		assert.Contains(t, strings.Join(snapshot["nft"], "\n"), "table ip netbird/chain", "the rules of slot 0 are in the comparison")
		return
	}
	assert.Contains(t, strings.Join(snapshot["iptables"], "\n"), "-A NETBIRD", "the rules of slot 0 are in the comparison")
}

func assertHolds(t *testing.T, snapshot hostSnapshot, part, message string) {
	t.Helper()
	assert.Truef(t, snapshot.holds(part), "%s: %s not in\n%s", message, part, snapshot)
}

// hostSnapshot is what the daemon has done to the network namespace of the container, one
// element per line and in a stable order, by section.
type hostSnapshot map[string][]string

var (
	iptablesCounters = regexp.MustCompile(`\s*\[\d+:\d+\]`)
	emptyBuiltin     = regexp.MustCompile(`^(iptables|ip6tables): (\*\w+|:[A-Z]+ ACCEPT|COMMIT)$`)
	emptyNftBuiltin  = regexp.MustCompile(`^table (ip|ip6) (filter|nat|mangle|raw)(/chain [A-Z]+(: type \w+ hook \w+ priority \w+; policy accept;)?)?$`)
)

// snapshot reads the routes, rules, firewall and DNS through the tools in the container.
func (d *daemon) snapshot(ctx context.Context, t *testing.T) hostSnapshot {
	t.Helper()

	s := hostSnapshot{
		"links":  d.nonEmptyLines(ctx, t, "sh", "-c", "ip -o link | awk '{print $2}' | grep -v -e '^lo:' -e '^eth'"),
		"routes": append(d.nonEmptyLines(ctx, t, "ip", "-4", "route", "show", "table", "all"), d.nonEmptyLines(ctx, t, "ip", "-6", "route", "show", "table", "all")...),
		"rules":  append(d.nonEmptyLines(ctx, t, "ip", "-4", "rule"), d.nonEmptyLines(ctx, t, "ip", "-6", "rule")...),
		"resolv": d.nonEmptyLines(ctx, t, "cat", "/etc/resolv.conf"),
		"sysctl": d.nonEmptyLines(ctx, t, "sysctl", "net.ipv4.ip_forward", "net.ipv4.conf.all.src_valid_mark", "net.ipv4.conf.all.rp_filter"),
		"ipset":  d.nonEmptyLines(ctx, t, "ipset", "save"),
		"nft":    flattenNft(d.must(ctx, t, "nft", "-s", "list", "ruleset")),
	}
	for _, tool := range []string{"iptables", "ip6tables"} {
		for _, line := range d.nonEmptyLines(ctx, t, tool+"-save") {
			if !strings.HasPrefix(line, "#") {
				s["iptables"] = append(s["iptables"], tool+": "+iptablesCounters.ReplaceAllString(line, ""))
			}
		}
	}
	for section, lines := range s {
		slices.Sort(lines)
		s[section] = lines
	}
	return s
}

func (d *daemon) nonEmptyLines(ctx context.Context, t *testing.T, cmd ...string) []string {
	t.Helper()
	_, out := d.exec(ctx, t, cmd...)
	var lines []string
	for _, line := range strings.Split(out, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// flattenNft gives every rule and every set element a line of its own that names the table and
// the chain or set it is in. A line can then be compared and attributed to a session without
// parsing the ruleset, and a set shared by the sessions loses only the elements of one.
//
// nft prints the elements of a set of plain interface names as "", the bytes in the kernel are
// right and the sets of the isolation that combine a name with something else print it. Those
// lines say nothing, so they are left out.
func flattenNft(ruleset string) []string {
	var (
		out      []string
		path     []string
		elements bool
	)
	context := func() string { return strings.Join(path, "/") }
	for _, raw := range strings.Split(ruleset, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
		case elements || strings.HasPrefix(line, "elements = {"):
			body := strings.TrimPrefix(line, "elements = {")
			elements = !strings.HasSuffix(body, "}")
			for _, element := range strings.Split(strings.TrimSuffix(body, "}"), ",") {
				if element = strings.TrimSpace(element); element != "" && element != `""` {
					out = append(out, context()+": element "+element)
				}
			}
		case strings.HasSuffix(line, "{"):
			path = append(path, strings.TrimSpace(strings.TrimSuffix(line, "{")))
			out = append(out, context())
		case line == "}":
			if len(path) > 0 {
				path = path[:len(path)-1]
			}
		default:
			out = append(out, context()+": "+line)
		}
	}
	return out
}

// homeSide matches what belongs to the session on slot 1 and its network: its interface, the
// names with the suffix of its slot and the addresses it brought. The network of the session on
// slot 0 has the names of today and no suffix.
func homeSide() *regexp.Regexp {
	overlay := strings.TrimSuffix(home.overlay.Masked().Addr().String(), "0.0")
	overlayV6 := strings.TrimSuffix(home.overlayV6.Masked().Addr().String(), ":")
	routed := strings.TrimSuffix(home.routed.Masked().Addr().String(), "0")
	return regexp.MustCompile(fmt.Sprintf(`\bwt1\b|-1\b|%s|%s|%s`, regexp.QuoteMeta(overlay), regexp.QuoteMeta(overlayV6), regexp.QuoteMeta(routed)))
}

func (s hostSnapshot) without(side *regexp.Regexp) hostSnapshot {
	out := make(hostSnapshot, len(s))
	for section, lines := range s {
		kept := []string{}
		for _, line := range lines {
			if !side.MatchString(line) {
				kept = append(kept, line)
			}
		}
		out[section] = kept
	}
	return out
}

func (s hostSnapshot) lines(side *regexp.Regexp) []string {
	var found []string
	for section, lines := range s {
		for _, line := range lines {
			if side.MatchString(line) {
				found = append(found, section+": "+line)
			}
		}
	}
	return found
}

func (s hostSnapshot) holds(part string) bool {
	for _, lines := range s {
		for _, line := range lines {
			if strings.Contains(line, part) {
				return true
			}
		}
	}
	return false
}

// withoutEmptyBuiltins drops what iptables-nft creates on any use, with or without NetBird:
// the tables and built-in chains with no rule in them.
func (s hostSnapshot) withoutEmptyBuiltins() hostSnapshot {
	out := make(hostSnapshot, len(s))
	for section, lines := range s {
		kept := []string{}
		for _, line := range lines {
			if !emptyBuiltin.MatchString(line) && !emptyNftBuiltin.MatchString(line) {
				kept = append(kept, line)
			}
		}
		out[section] = kept
	}
	return out
}

func (s hostSnapshot) String() string {
	var out strings.Builder
	for section, lines := range s {
		fmt.Fprintf(&out, "== %s ==\n%s\n", section, strings.Join(lines, "\n"))
	}
	return out.String()
}
