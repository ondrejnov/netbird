//go:build !android && privileged

package iptables

import (
	"fmt"
	"net/netip"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/coreos/go-iptables/iptables"
	"github.com/lrh3321/ipset-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	fw "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	nbnet "github.com/netbirdio/netbird/client/net"
	"github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/domain"
)

// slotCase describes one manager under test: its slot and the identifiers that
// only that slot's rules may carry.
type slotCase struct {
	slot  uint
	iface string
	mock  *iFaceMock
}

func newSlotCase(slot uint, name, v4Net, v4IP, v6Net, v6IP string) slotCase {
	addr := wgaddr.Address{
		IP:      netip.MustParseAddr(v4IP),
		Network: netip.MustParsePrefix(v4Net),
		IPv6:    netip.MustParseAddr(v6IP),
		IPv6Net: netip.MustParsePrefix(v6Net),
	}
	return slotCase{
		slot:  slot,
		iface: name,
		mock: &iFaceMock{
			NameFunc:    func() string { return name },
			AddressFunc: func() wgaddr.Address { return addr },
		},
	}
}

var (
	slot0Case = newSlotCase(0, "wg-slot0", "10.31.0.0/24", "10.31.0.1", "fd00:31::/64", "fd00:31::1")
	slot1Case = newSlotCase(1, "wg-slot1", "10.32.0.0/24", "10.32.0.1", "fd00:32::/64", "fd00:32::1")
	slot2Case = newSlotCase(2, "wg-slot2", "10.33.0.0/24", "10.33.0.1", "fd00:33::/64", "fd00:33::1")
)

func (c slotCase) start(t *testing.T) *Manager {
	t.Helper()

	var opts []Option
	if c.slot != 0 {
		opts = append(opts, WithSlot(c.slot))
	}
	m, err := Create(c.mock, iface.DefaultMTU, opts...)
	require.NoError(t, err, "create manager for slot %d", c.slot)
	require.NoError(t, m.Init(nil), "init manager for slot %d", c.slot)
	return m
}

// populate installs the rule kinds that own chains, sets and jumps: a peer ACL
// with a multi-source set, a route ACL, masquerade, both DNAT flavours and a
// destination domain set. Both sessions use identical sources on purpose so
// the content-hashed set names collide unless the slot is part of the name.
func (c slotCase) populate(t *testing.T, m *Manager) {
	t.Helper()

	sources := []netip.Prefix{
		netip.MustParsePrefix("100.64.0.0/16"),
		netip.MustParsePrefix("100.65.0.0/16"),
	}
	_, err := m.AddFilterRule(nil, sources, fw.Network{}, fw.ProtocolTCP, nil, &fw.Port{Values: []uint16{8080}}, fw.ActionAccept)
	require.NoError(t, err, "peer ACL with source set")

	_, err = m.AddFilterRule(nil, sources, fw.Network{Prefix: netip.MustParsePrefix("192.168.50.0/24")}, fw.ProtocolALL, nil, nil, fw.ActionAccept)
	require.NoError(t, err, "route ACL")

	v6Sources := []netip.Prefix{
		netip.MustParsePrefix("fd00:aa::/64"),
		netip.MustParsePrefix("fd00:ab::/64"),
	}
	_, err = m.AddFilterRule(nil, v6Sources, fw.Network{}, fw.ProtocolTCP, nil, &fw.Port{Values: []uint16{8080}}, fw.ActionAccept)
	require.NoError(t, err, "v6 peer ACL with source set")

	require.NoError(t, m.AddNatRule(fw.RouterPair{
		ID:          route.ID("masq-" + c.iface),
		Source:      fw.Network{Prefix: netip.MustParsePrefix("100.64.0.0/16")},
		Destination: fw.Network{Set: fw.NewDomainSet(domain.List{"example.org"})},
		Masquerade:  true,
		Dynamic:     true,
	}), "masquerade with domain set")

	require.NoError(t, m.AddInboundDNAT(netip.MustParseAddr("100.64.0.9"), fw.ProtocolTCP, 22, 22022), "inbound DNAT")
	require.NoError(t, m.AddOutputDNAT(netip.MustParseAddr("100.64.0.9"), fw.ProtocolTCP, 22, 22022), "output DNAT")
}

// ownsLine reports whether a rule or chain line belongs to the slot.
func (c slotCase) ownsLine(line string) bool {
	if c.slot == 0 {
		return false
	}
	suffix := regexp.MustCompile(`[A-Za-z0-9]-` + strconv.FormatUint(uint64(c.slot), 10) + `(\s|"|$)`)
	return strings.Contains(line, c.iface) || suffix.MatchString(line)
}

var counterRe = regexp.MustCompile(`\[\d+:\d+\]`)

// saveRules returns the normalized iptables-save and ip6tables-save lines of
// the filter, nat and mangle tables, without timestamps and packet counters.
func saveRules(t *testing.T) []string {
	t.Helper()

	var lines []string
	for _, bin := range []string{"iptables-save", "ip6tables-save"} {
		for _, table := range []string{tableFilter, tableNat, tableMangle} {
			out, err := exec.Command(bin, "-t", table).CombinedOutput()
			require.NoError(t, err, "%s -t %s: %s", bin, table, out)
			for _, line := range strings.Split(string(out), "\n") {
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				lines = append(lines, bin+" "+counterRe.ReplaceAllString(line, "[]"))
			}
		}
	}
	return lines
}

// without returns the lines that do not belong to any of the given slots.
func without(lines []string, cases ...slotCase) []string {
	var kept []string
	for _, line := range lines {
		owned := false
		for _, c := range cases {
			if c.ownsLine(line) {
				owned = true
				break
			}
		}
		if !owned {
			kept = append(kept, line)
		}
	}
	return kept
}

// only returns the lines that belong to the slot.
func only(lines []string, c slotCase) []string {
	var kept []string
	for _, line := range lines {
		if c.ownsLine(line) {
			kept = append(kept, line)
		}
	}
	return kept
}

// setSnapshot maps every ipset in the kernel to its sorted member list.
func setSnapshot(t *testing.T) map[string][]string {
	t.Helper()

	all, err := ipset.ListAll()
	require.NoError(t, err, "list ipsets")

	snapshot := make(map[string][]string, len(all))
	for _, s := range all {
		var members []string
		for _, e := range s.Entries {
			members = append(members, e.IP.String()+"/"+strconv.Itoa(int(e.CIDR)))
		}
		slices.Sort(members)
		snapshot[s.SetName] = members
	}
	return snapshot
}

func setsOf(snapshot map[string][]string, c slotCase) []string {
	var names []string
	for name := range snapshot {
		if strings.HasSuffix(name, "-"+strconv.FormatUint(uint64(c.slot), 10)) && c.slot != 0 {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}

func setsWithout(snapshot map[string][]string, cases ...slotCase) map[string][]string {
	kept := make(map[string][]string)
	for name, members := range snapshot {
		owned := false
		for _, c := range cases {
			if c.slot != 0 && strings.HasSuffix(name, "-"+strconv.FormatUint(uint64(c.slot), 10)) {
				owned = true
			}
		}
		if !owned {
			kept[name] = members
		}
	}
	return kept
}

func TestSlotZeroCreatesTodaysNames(t *testing.T) {
	client, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	require.NoError(t, err)

	m := slot0Case.start(t)
	t.Cleanup(func() { require.NoError(t, m.Close(nil)) })
	slot0Case.populate(t, m)

	for _, c := range []struct{ table, chain string }{
		{tableFilter, "NETBIRD-ACL-INPUT"},
		{tableFilter, "NETBIRD-RT-FWD-IN"},
		{tableFilter, "NETBIRD-RT-FWD-OUT"},
		{tableMangle, "NETBIRD-RT-PRE"},
		{tableMangle, "NETBIRD-RT-MSSCLAMP"},
		{tableNat, "NETBIRD-RT-NAT"},
		{tableNat, "NETBIRD-RT-RDR"},
		{tableNat, "NETBIRD-NAT-OUTPUT"},
	} {
		ok, err := client.ChainExists(c.table, c.chain)
		require.NoError(t, err)
		assert.Truef(t, ok, "chain %s in %s must keep its unsuffixed name", c.chain, c.table)
	}

	hashedName := fw.NewPrefixSet([]netip.Prefix{
		netip.MustParsePrefix("100.64.0.0/16"),
		netip.MustParsePrefix("100.65.0.0/16"),
	}).HashedName()
	snapshot := setSnapshot(t)
	assert.Contains(t, snapshot, hashedName, "slot 0 set keeps the plain hashed name")

	for _, line := range saveRules(t) {
		assert.Falsef(t, regexp.MustCompile(`NETBIRD-[A-Z-]+-\d`).MatchString(line), "slot 0 must not emit suffixed chains: %s", line)
	}
}

// TestSlotsAreIndependent proves that a second manager can start, run and stop
// next to the first without touching its chains, jumps, accept rules or sets,
// in either stop order.
func TestSlotsAreIndependent(t *testing.T) {
	client, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	require.NoError(t, err)

	m0 := slot0Case.start(t)
	slot0Case.populate(t, m0)
	// Only these managers may leave state behind after a failure.
	t.Cleanup(func() { _ = m0.Close(nil) })

	baseRules := saveRules(t)
	baseSets := setSnapshot(t)

	t.Run("starting slot 1 leaves slot 0 untouched", func(t *testing.T) {
		m1 := slot1Case.start(t)
		t.Cleanup(func() { _ = m1.Close(nil) })
		slot1Case.populate(t, m1)

		assert.Equal(t, baseRules, without(saveRules(t), slot1Case), "slot 0 rules, chains and jumps must not change")
		assert.Equal(t, baseSets, setsWithout(setSnapshot(t), slot1Case), "slot 0 sets must not change")

		own := only(saveRules(t), slot1Case)
		assert.NotEmpty(t, own, "slot 1 must have installed its own rules")
		assert.NotEmpty(t, setsOf(setSnapshot(t), slot1Case), "slot 1 must own suffixed sets")

		for _, chain := range []string{"NETBIRD-ACL-INPUT-1", "NETBIRD-RT-FWD-IN-1", "NETBIRD-RT-NAT-1", "NETBIRD-NAT-OUTPUT-1"} {
			joined := strings.Join(own, "\n")
			assert.Containsf(t, joined, chain, "slot 1 must use %s", chain)
		}

		// Stop slot 1 while slot 0 keeps running.
		require.NoError(t, m1.Close(nil), "stop slot 1")

		assert.Equal(t, baseRules, saveRules(t), "after stopping slot 1 the rule set must equal the slot 0 only state")
		assert.Equal(t, baseSets, setSnapshot(t), "after stopping slot 1 only slot 0 sets may remain")

		ok, err := client.ChainExists(tableFilter, "NETBIRD-ACL-INPUT")
		require.NoError(t, err)
		assert.True(t, ok, "slot 0 ACL chain must survive")
		ok, err = client.ChainExists(tableFilter, "NETBIRD-ACL-INPUT-1")
		require.NoError(t, err)
		assert.False(t, ok, "slot 1 ACL chain must be gone")

		// The interface agnostic accept in FORWARD is the case where slot 0
		// and slot 1 would otherwise share one rule.
		exists, err := client.Exists(tableFilter, chainForward, "-m", "mark", "--mark", redirectMark(), "-j", "ACCEPT")
		require.NoError(t, err)
		assert.True(t, exists, "slot 0 untagged FORWARD accept must survive the stop of slot 1")
	})

	t.Run("stopping slot 0 leaves slot 1 untouched", func(t *testing.T) {
		m1 := slot1Case.start(t)
		t.Cleanup(func() { _ = m1.Close(nil) })
		slot1Case.populate(t, m1)

		slot1Rules := only(saveRules(t), slot1Case)
		slot1Sets := setsOf(setSnapshot(t), slot1Case)
		require.NotEmpty(t, slot1Rules, "slot 1 must have installed its own rules")
		require.NotEmpty(t, slot1Sets, "slot 1 must own suffixed sets")

		require.NoError(t, m0.Close(nil), "stop slot 0")

		assert.Equal(t, slot1Rules, only(saveRules(t), slot1Case), "slot 1 rules must survive the stop of slot 0")
		assert.Equal(t, slot1Sets, setsOf(setSnapshot(t), slot1Case), "slot 1 sets must survive the stop of slot 0")

		exists, err := client.Exists(tableFilter, chainForward, "-i", slot1Case.iface, "-m", "mark", "--mark", redirectMark(), "-m", "comment", "--comment", "netbird-1", "-j", "ACCEPT")
		require.NoError(t, err)
		assert.True(t, exists, "slot 1 tagged FORWARD accept must survive the stop of slot 0")

		require.NoError(t, m1.Close(nil), "stop slot 1")
		assert.Empty(t, only(saveRules(t), slot1Case), "nothing of slot 1 may remain")
	})

	t.Run("three slots stop in any order", func(t *testing.T) {
		a := slot1Case.start(t)
		b := slot2Case.start(t)
		t.Cleanup(func() { _ = a.Close(nil); _ = b.Close(nil) })
		slot1Case.populate(t, a)
		slot2Case.populate(t, b)

		slot2Rules := only(saveRules(t), slot2Case)
		require.NoError(t, a.Close(nil))
		assert.Equal(t, slot2Rules, only(saveRules(t), slot2Case), "slot 2 must not notice slot 1 stopping")
		require.NoError(t, b.Close(nil))
		assert.Empty(t, only(saveRules(t), slot2Case), "nothing of slot 2 may remain")
	})
}

// TestSlotUpdateSetTouchesOnlyOwnSet shows that a dynamic set update reaches
// the suffixed set of its own slot and not the set another slot built from the
// same content hash.
func TestSlotUpdateSetTouchesOnlyOwnSet(t *testing.T) {
	m0 := slot0Case.start(t)
	t.Cleanup(func() { _ = m0.Close(nil) })
	m1 := slot1Case.start(t)
	t.Cleanup(func() { _ = m1.Close(nil) })
	slot0Case.populate(t, m0)
	slot1Case.populate(t, m1)

	set := fw.NewDomainSet(domain.List{"example.org"})
	before := setSnapshot(t)

	require.NoError(t, m1.UpdateSet(set, []netip.Prefix{netip.MustParsePrefix("203.0.113.7/32")}))

	after := setSnapshot(t)
	assert.Equal(t, before[set.HashedName()], after[set.HashedName()], "slot 0 set must not receive the slot 1 update")
	assert.Contains(t, after[set.HashedName()+"-1"], "203.0.113.7/32", "slot 1 set must receive its update")
}

// TestSlotShutdownStateCleansOnlyItsSlot covers crash recovery: the persisted
// state of a slot must clean that slot's chains and nothing of another slot.
func TestSlotShutdownStateCleansOnlyItsSlot(t *testing.T) {
	m0 := slot0Case.start(t)
	t.Cleanup(func() { _ = m0.Close(nil) })
	slot0Case.populate(t, m0)
	baseRules := saveRules(t)
	baseSets := setSnapshot(t)

	m1 := slot1Case.start(t)
	t.Cleanup(func() { _ = m1.Close(nil) })
	slot1Case.populate(t, m1)
	require.NotEmpty(t, only(saveRules(t), slot1Case))

	state := &ShutdownState{
		InterfaceState: &InterfaceState{
			NameStr:   slot1Case.iface,
			WGAddress: slot1Case.mock.Address(),
			MTU:       iface.DefaultMTU,
			Slot:      slot1Case.slot,
		},
		RouteRules:         m1.family4.rules,
		RouteRules6:        m1.family6.rules,
		RouteIPsetCounter:  m1.family4.ipsetCounter,
		RouteIPsetCounter6: m1.family6.ipsetCounter,
		ACLEntries:         m1.family4.entries,
		ACLEntries6:        m1.family6.entries,
	}
	require.NoError(t, state.Cleanup(), "crash recovery of slot 1")

	assert.Empty(t, only(saveRules(t), slot1Case), "slot 1 must be fully cleaned")
	assert.Equal(t, baseRules, saveRules(t), "slot 0 must be untouched by the cleanup of slot 1")
	assert.Equal(t, baseSets, setSnapshot(t), "slot 0 sets must be untouched by the cleanup of slot 1")
}

func redirectMark() string {
	return fmt.Sprintf("%#x", nbnet.PreroutingFwmarkRedirected)
}

// forwardRule is one FORWARD rule reduced to what decides a packet's fate.
type forwardRule struct {
	line   string
	inIf   string
	outIf  string
	mark   string
	target string
}

// forwardRules lists the rules of the filter FORWARD chain in evaluation order.
func forwardRules(t *testing.T, bin string) []forwardRule {
	t.Helper()

	out, err := exec.Command(bin, "-t", tableFilter, "-S", chainForward).CombinedOutput()
	require.NoError(t, err, "%s -S FORWARD: %s", bin, out)

	var rules []forwardRule
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.HasPrefix(line, "-A "+chainForward+" ") {
			continue
		}
		fields := strings.Fields(line)
		rule := forwardRule{line: line}
		for i := 0; i+1 < len(fields); i++ {
			switch fields[i] {
			case "-i":
				rule.inIf = fields[i+1]
			case "-o":
				rule.outIf = fields[i+1]
			case "--mark":
				rule.mark = strings.SplitN(fields[i+1], "/", 2)[0]
			case "-j":
				rule.target = fields[i+1]
			}
		}
		rules = append(rules, rule)
	}
	return rules
}

// firstForwardMatch walks FORWARD like the kernel does for a packet that
// arrives on inIf, leaves through a foreign interface and carries the redirect
// mark. Every rule that is not a plain jump into one of the NetBird chains
// and does not match the interface is skipped. It returns the first rule that
// would take the packet.
func firstForwardMatch(rules []forwardRule, inIf string) (forwardRule, bool) {
	for _, r := range rules {
		if r.inIf != "" && r.inIf != inIf {
			continue
		}
		if r.outIf != "" {
			continue
		}
		if r.mark != "" && r.mark != redirectMark() {
			continue
		}
		return r, true
	}
	return forwardRule{}, false
}

// TestRedirectedAcceptDoesNotBypassOtherSlots proves the order of FORWARD: a
// marked packet arriving on the interface of slot 0 must reach the route ACL
// jump of slot 0 before any accept that a later slot installed above it.
func TestRedirectedAcceptDoesNotBypassOtherSlots(t *testing.T) {
	m0 := slot0Case.start(t)
	t.Cleanup(func() { _ = m0.Close(nil) })
	slot0Case.populate(t, m0)

	m1 := slot1Case.start(t)
	t.Cleanup(func() { _ = m1.Close(nil) })
	slot1Case.populate(t, m1)

	m2 := slot2Case.start(t)
	t.Cleanup(func() { _ = m2.Close(nil) })
	slot2Case.populate(t, m2)

	for _, bin := range []string{"iptables", "ip6tables"} {
		rules := forwardRules(t, bin)
		require.NotEmpty(t, rules, "%s FORWARD must hold rules", bin)

		for _, c := range []slotCase{slot0Case, slot1Case, slot2Case} {
			first, ok := firstForwardMatch(rules, c.iface)
			require.Truef(t, ok, "%s: a marked packet from %s must match a rule", bin, c.iface)
			assert.Equalf(t, c.iface, first.inIf, "%s: the first rule for a marked packet from %s must be bound to it: %s", bin, c.iface, first.line)
			assert.NotEqualf(t, "ACCEPT", first.target, "%s: a marked packet from %s must reach its route ACL jump before an accept: %s", bin, c.iface, first.line)
			assert.Equalf(t, "NETBIRD-RT-FWD-IN"+c.suffix(), first.target, "%s: first rule for %s", bin, c.iface)
		}
	}
}

// suffix is the chain name suffix of the slot.
func (c slotCase) suffix() string {
	if c.slot == 0 {
		return ""
	}
	return "-" + strconv.FormatUint(uint64(c.slot), 10)
}
