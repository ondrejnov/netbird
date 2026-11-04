//go:build privileged && linux

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/netbirdio/netbird/client/firewall"
	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
)

const (
	fixtureAccount = "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	fixtureGroup   = "cs1tnh0hhcjnqoiuebeg"
	// fixtureRouterKey is the routing peer of both networks. It exists only in the network map:
	// the test marks it connected, so that the real route watcher installs its routes.
	fixtureRouterKey = "6kjbmVq1hmucVzvBXo5OucY5OYv+jSsB1jUTLq291Do="

	hostFixtureTable = 7120
)

// hostNetwork describes one self-hosted network of the two a test connects to.
type hostNetwork struct {
	overlay netip.Prefix
	router  netip.Addr
	route   netip.Prefix
	shared  netip.Prefix
}

var (
	networkWork = hostNetwork{
		overlay: netip.MustParsePrefix("100.71.0.0/16"),
		router:  netip.MustParseAddr("100.71.0.2"),
		route:   netip.MustParsePrefix("10.71.0.0/16"),
		shared:  netip.MustParsePrefix("10.77.0.0/16"),
	}
	networkHome = hostNetwork{
		overlay: netip.MustParsePrefix("100.72.0.0/16"),
		router:  netip.MustParseAddr("100.72.0.2"),
		route:   netip.MustParsePrefix("10.72.0.0/16"),
		shared:  netip.MustParsePrefix("10.77.0.0/16"),
	}
)

// writeNetworkStore derives a Management store for network from the test store: its own overlay,
// a routing peer that never connects, a route of its own, a route both networks share and a primary
// nameserver, which makes the session want the host DNS.
func writeNetworkStore(t *testing.T, network hostNetwork) string {
	t.Helper()

	raw, err := os.ReadFile("../../management/server/testdata/store.sql")
	require.NoError(t, err)

	mask := net.CIDRMask(network.overlay.Bits(), 32)
	netJSON, err := json.Marshal(net.IPNet{IP: network.overlay.Addr().AsSlice(), Mask: mask})
	require.NoError(t, err)

	var lines []string
	for _, line := range strings.Split(string(raw), "\n") {
		switch {
		case strings.HasPrefix(line, "INSERT INTO peers"),
			strings.HasPrefix(line, "INSERT INTO network_routers"),
			strings.HasPrefix(line, "INSERT INTO network_resources"),
			strings.HasPrefix(line, "INSERT INTO networks"):
			continue
		}
		line = strings.ReplaceAll(line, `{"IP":"100.64.0.0","Mask":"//8AAA=="}`, string(netJSON))
		if strings.Contains(line, `INSERT INTO "groups"`) && strings.Contains(line, "'All'") {
			line = strings.Replace(line, "'[]'", `'["router-peer"]'`, 1)
		}
		lines = append(lines, line)
	}

	lines = append(lines,
		fmt.Sprintf(`INSERT INTO peers VALUES('router-peer','%s','%s','','"%s"','','','','','','','','','','','','','','','','','router','router','2023-01-01 00:00:00+00:00',0,0,0,'a23efe53-63fb-11ec-90d6-0242ac120003','',0,0,'2023-01-01 00:00:00+00:00','2023-01-01 00:00:00+00:00',0,'','','',0);`,
			fixtureAccount, fixtureRouterKey, network.router),
		fmt.Sprintf(`INSERT INTO routes VALUES('route-own','%s','"%s"',NULL,0,'own','','router-peer',NULL,1,0,9999,1,'["%s"]',NULL);`,
			fixtureAccount, network.route, fixtureGroup),
		fmt.Sprintf(`INSERT INTO routes VALUES('route-shared','%s','"%s"',NULL,0,'shared','','router-peer',NULL,1,0,9999,1,'["%s"]',NULL);`,
			fixtureAccount, network.shared, fixtureGroup),
		fmt.Sprintf(`INSERT INTO name_server_groups VALUES('ns-primary','%s','primary','','[{"IP":"192.0.2.53","NSType":1,"Port":53}]','["%s"]',1,'[]',1,0);`,
			fixtureAccount, fixtureGroup),
	)

	path := filepath.Join(t.TempDir(), "store.sql")
	require.NoError(t, os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o600))
	return path
}

// startNetwork runs a Management of its own for the network and writes a registered profile for it.
func startNetwork(t *testing.T, ctx context.Context, dir, profile, signalAddr string, network hostNetwork) {
	t.Helper()

	logins := 0
	_, mgmtAddr, err := startManagement(t, signalAddr, writeNetworkStore(t, network), &logins)
	require.NoError(t, err)

	config, err := profilemanager.UpdateOrCreateConfig(profilemanager.ConfigInput{
		ConfigPath:    filepath.Join(dir, profile+".json"),
		ManagementURL: "http://" + mgmtAddr,
	})
	require.NoError(t, err)
	registerPeer(t, ctx, config)
}

// keepRouterConnected marks the routing peer connected until the test ends. Without a counterpart
// the peer connection cannot get there, and it may report something else in between.
func keepRouterConnected(t *testing.T, recorder *peer.Status) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = recorder.UpdatePeerState(peer.State{
					PubKey:           fixtureRouterKey,
					ConnStatus:       peer.StatusConnected,
					ConnStatusUpdate: time.Now(),
				})
			}
		}
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
}

func awaitConnected(t *testing.T, ss *session, name string) {
	t.Helper()
	require.Eventuallyf(t, func() bool {
		return ss.state.CurrentStatus() == internal.StatusConnected
	}, 60*time.Second, 100*time.Millisecond, "session %s should connect", name)
}

func upProfile(t *testing.T, ctx context.Context, s *Server, profile, username string) {
	t.Helper()
	_, err := s.Up(ctx, &proto.UpRequest{ProfileName: &profile, Username: &username, Async: true})
	require.NoError(t, err, "Up of profile %s", profile)
}

// hostSnapshot is what a session leaves on the host, section by section.
type hostSnapshot map[string][]string

var (
	setIDPattern    = regexp.MustCompile(`SetID:\d+`)
	anonSetPattern  = regexp.MustCompile(`__set\d+`)
	handlePattern   = regexp.MustCompile(`Handle:\d+`)
	counterPattern  = regexp.MustCompile(`\[\d+:\d+\]`)
	nftCountPattern = regexp.MustCompile(`Counter[^}]*\}`)
	pointerPattern  = regexp.MustCompile(`Info:0x[0-9a-f]+`)

	emptyIptablesChain = regexp.MustCompile(`^ip6?tables-save \*\w+ :(INPUT|FORWARD|OUTPUT|PREROUTING|POSTROUTING) ACCEPT $`)
	emptyNftChain      = regexp.MustCompile(`^table \d+/(filter|mangle|nat) chain (INPUT|FORWARD|OUTPUT|PREROUTING|POSTROUTING) type=`)
	emptyNftTable      = regexp.MustCompile(`^table \d+/(filter|mangle|nat)$`)
)

// takeHostSnapshot records the names and the rules on the host. normalize replaces what differs
// between runs, the peer address Management picks.
func takeHostSnapshot(t *testing.T, normalize func(string) string) hostSnapshot {
	t.Helper()
	snapshot := hostSnapshot{
		"links":    snapshotLinks(t),
		"rules":    snapshotRules(t),
		"routes":   snapshotRoutes(t),
		"nftables": snapshotNftables(t),
		"iptables": snapshotIptables(t),
		"sysctl":   snapshotSysctls(t),
		"resolv":   snapshotResolvConf(t),
	}
	for section, lines := range snapshot {
		for i, line := range lines {
			lines[i] = normalize(line)
		}
		sort.Strings(lines)
		snapshot[section] = lines
	}
	return snapshot
}

// withoutEmptyBuiltins drops the empty built-in chains and tables: iptables-nft creates them on any
// use, as it does without NetBird, and a policy accept with no rules changes nothing. A chain of
// NetBird or a rule anywhere stays.
func (h hostSnapshot) withoutEmptyBuiltins() hostSnapshot {
	out := make(hostSnapshot, len(h))
	for section, lines := range h {
		out[section] = []string{}
		for _, line := range lines {
			if !isEmptyBuiltin(line) {
				out[section] = append(out[section], line)
			}
		}
	}
	return out
}

func isEmptyBuiltin(line string) bool {
	return emptyIptablesChain.MatchString(line) || emptyNftChain.MatchString(line) || emptyNftTable.MatchString(line)
}

func (h hostSnapshot) String() string {
	var out bytes.Buffer
	sections := make([]string, 0, len(h))
	for section := range h {
		sections = append(sections, section)
	}
	sort.Strings(sections)
	for _, section := range sections {
		fmt.Fprintf(&out, "== %s ==\n", section)
		for _, line := range h[section] {
			fmt.Fprintln(&out, line)
		}
	}
	return out.String()
}

func snapshotLinks(t *testing.T) []string {
	t.Helper()
	links, err := netlink.LinkList()
	require.NoError(t, err)
	var out []string
	for _, link := range links {
		attrs := link.Attrs()
		if attrs.Name == "lo" || strings.HasPrefix(attrs.Name, "eth") {
			continue
		}
		addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
		require.NoError(t, err)
		ips := make([]string, 0, len(addrs))
		for _, addr := range addrs {
			ips = append(ips, addr.IPNet.String())
		}
		out = append(out, fmt.Sprintf("%s type=%s mtu=%d addrs=%v", attrs.Name, link.Type(), attrs.MTU, ips))
	}
	return out
}

func snapshotRules(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		rules, err := netlink.RuleList(family)
		require.NoError(t, err)
		for _, rule := range rules {
			out = append(out, fmt.Sprintf("family=%d prio=%d table=%d mark=%d invert=%v suppress=%d", family, rule.Priority, rule.Table, rule.Mark, rule.Invert, rule.SuppressPrefixlen))
		}
	}
	return out
}

func snapshotRoutes(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		routes, err := netlink.RouteListFiltered(family, &netlink.Route{Table: unix.RT_TABLE_UNSPEC}, netlink.RT_FILTER_TABLE)
		require.NoError(t, err)
		for _, route := range routes {
			if route.Table == unix.RT_TABLE_LOCAL {
				continue
			}
			dev := ""
			if link, err := netlink.LinkByIndex(route.LinkIndex); err == nil {
				dev = link.Attrs().Name
			}
			if strings.HasPrefix(dev, "eth") || dev == "lo" {
				continue
			}
			dst := "default"
			if route.Dst != nil {
				dst = route.Dst.String()
			}
			out = append(out, fmt.Sprintf("family=%d table=%d dst=%s dev=%s type=%d scope=%d", family, route.Table, dst, dev, route.Type, route.Scope))
		}
	}
	return out
}

func snapshotNftables(t *testing.T) []string {
	t.Helper()
	conn := &nftables.Conn{}
	tables, err := conn.ListTables()
	require.NoError(t, err)

	var out []string
	for _, table := range tables {
		prefix := fmt.Sprintf("table %d/%s", table.Family, table.Name)
		out = append(out, prefix)
		chains, err := conn.ListChainsOfTableFamily(table.Family)
		require.NoError(t, err)
		for _, chain := range chains {
			if chain.Table.Name != table.Name {
				continue
			}
			out = append(out, fmt.Sprintf("%s chain %s", prefix, describeChain(chain)))
			rules, err := conn.GetRules(table, chain)
			require.NoError(t, err)
			for _, rule := range rules {
				out = append(out, fmt.Sprintf("%s chain %s rule %s", prefix, chain.Name, describeRule(rule)))
			}
		}
		sets, err := conn.GetSets(table)
		require.NoError(t, err)
		for _, set := range sets {
			if set.Anonymous {
				continue
			}
			out = append(out, fmt.Sprintf("%s set %s", prefix, set.Name))
		}
	}
	return out
}

func describeChain(chain *nftables.Chain) string {
	var policy string
	if chain.Policy != nil {
		policy = fmt.Sprint(*chain.Policy)
	}
	var hook, priority string
	if chain.Hooknum != nil {
		hook = fmt.Sprint(*chain.Hooknum)
	}
	if chain.Priority != nil {
		priority = fmt.Sprint(*chain.Priority)
	}
	return fmt.Sprintf("%s type=%s hook=%s prio=%s policy=%s", chain.Name, chain.Type, hook, priority, policy)
}

func describeRule(rule *nftables.Rule) string {
	parts := make([]string, 0, len(rule.Exprs))
	for _, e := range rule.Exprs {
		value := reflect.ValueOf(e)
		if value.Kind() == reflect.Pointer {
			value = value.Elem()
		}
		text := fmt.Sprintf("%T%+v", e, value.Interface())
		text = setIDPattern.ReplaceAllString(text, "SetID")
		text = anonSetPattern.ReplaceAllString(text, "__set")
		text = handlePattern.ReplaceAllString(text, "Handle")
		text = nftCountPattern.ReplaceAllString(text, "Counter}")
		text = pointerPattern.ReplaceAllString(text, "Info")
		parts = append(parts, text)
	}
	return fmt.Sprintf("%q %s", rule.UserData, strings.Join(parts, " "))
}

func snapshotIptables(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, tool := range []string{"iptables-save", "ip6tables-save"} {
		raw, err := exec.Command(tool).Output()
		if err != nil {
			t.Logf("%s: %v", tool, err)
			continue
		}
		table := ""
		for _, line := range strings.Split(string(raw), "\n") {
			switch {
			case line == "", strings.HasPrefix(line, "#"), line == "COMMIT":
				continue
			case strings.HasPrefix(line, "*"):
				table = line
			default:
				out = append(out, tool+" "+table+" "+counterPattern.ReplaceAllString(line, ""))
			}
		}
	}
	return out
}

func snapshotSysctls(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, path := range []string{
		"/proc/sys/net/ipv4/ip_forward",
		"/proc/sys/net/ipv4/conf/all/rp_filter",
		"/proc/sys/net/ipv4/conf/all/src_valid_mark",
		"/proc/sys/net/netfilter/nf_conntrack_acct",
	} {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		out = append(out, path+"="+strings.TrimSpace(string(raw)))
	}
	return out
}

func snapshotResolvConf(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile("/etc/resolv.conf")
	require.NoError(t, err)
	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

// requireNftablesBackend makes the firewall discovery pick nftables, which it does for a host
// whose filter table has chains. The container alone makes it pick iptables.
func requireNftablesBackend(t *testing.T) {
	t.Helper()
	conn := &nftables.Conn{}
	table := conn.AddTable(&nftables.Table{Name: "filter", Family: nftables.TableFamilyIPv4})
	policy := nftables.ChainPolicyAccept
	conn.AddChain(&nftables.Chain{
		Name:     "INPUT",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &policy,
	})
	require.NoError(t, conn.Flush(), "create the filter table")
	t.Cleanup(func() {
		conn := &nftables.Conn{}
		conn.DelTable(table)
		if err := conn.Flush(); err != nil {
			t.Logf("delete the filter table: %v", err)
		}
	})
}

// hostBackends are the firewalls a native session runs on, each set up for the test by setup.
var hostBackends = []struct {
	name  string
	setup func(t *testing.T)
}{
	{name: "nftables", setup: requireNftablesBackend},
	{name: "iptables", setup: func(t *testing.T) { t.Setenv(firewall.SkipNftablesEnv, "true") }},
}

// linesWith keeps the lines of a section that mention one of the names, the part of the snapshot
// that belongs to one session.
func linesWith(lines []string, names ...string) []string {
	var out []string
	for _, line := range lines {
		if slices.ContainsFunc(names, func(name string) bool { return strings.Contains(line, name) }) {
			out = append(out, line)
		}
	}
	return out
}

// overlayNormalizer replaces an address in every form the rules and the routes spell it in.
func overlayNormalizer(addresses map[string]netip.Addr) func(string) string {
	return func(line string) string {
		for label, addr := range addresses {
			if !addr.IsValid() {
				continue
			}
			raw := addr.As4()
			line = strings.ReplaceAll(line, addr.String(), label)
			line = strings.ReplaceAll(line, fmt.Sprintf("[%d %d %d %d]", raw[0], raw[1], raw[2], raw[3]), label)
		}
		return line
	}
}

func localOverlayAddr(t *testing.T, ss *session) netip.Addr {
	t.Helper()
	prefix, err := netip.ParsePrefix(ss.statusRecorder.GetLocalPeerState().IP)
	require.NoError(t, err, "the session should report its overlay address")
	return prefix.Addr()
}
