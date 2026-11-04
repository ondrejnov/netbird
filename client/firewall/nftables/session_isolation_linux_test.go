//go:build privileged

package nftables

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	fw "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
)

const (
	testTagForwardIif = "frwacceptiif"
	testTagForwardOif = "frwacceptoif"
	testTagInput      = "inputaccept"
)

func sessionIface(slot uint) *iFaceMock {
	second := byte(slot + 96)
	return &iFaceMock{
		NameFunc: func() string { return fmt.Sprintf("wt%d", slot) },
		AddressFunc: func() wgaddr.Address {
			return wgaddr.Address{
				IP:      netip.AddrFrom4([4]byte{100, second, 0, 1}),
				Network: netip.PrefixFrom(netip.AddrFrom4([4]byte{100, second, 0, 0}), 16),
				IPv6:    netip.AddrFrom16([16]byte{0xfd, 0x00, 0x1b, second, 15: 1}),
				IPv6Net: netip.PrefixFrom(netip.AddrFrom16([16]byte{0xfd, 0x00, 0x1b, second}), 64),
			}
		},
	}
}

// hookedTable is a table with filter chains on both hooks the engine opens, which is what
// findExternalChains looks for.
type hookedTable struct {
	table   *nftables.Table
	input   *nftables.Chain
	forward *nftables.Chain
}

func addHookedTable(t *testing.T, name string) hookedTable {
	t.Helper()
	conn := &nftables.Conn{}
	table := conn.AddTable(&nftables.Table{Name: name, Family: nftables.TableFamilyINet})
	input := addHookedChain(conn, table, "ext_input", nftables.ChainHookInput)
	forward := addHookedChain(conn, table, "ext_forward", nftables.ChainHookForward)
	require.NoError(t, conn.Flush(), "create table %s", name)
	t.Cleanup(func() {
		c := &nftables.Conn{}
		c.DelTable(table)
		_ = c.Flush()
	})
	return hookedTable{table: table, input: input, forward: forward}
}

func addHookedChain(conn *nftables.Conn, table *nftables.Table, name string, hook *nftables.ChainHook) *nftables.Chain {
	return conn.AddChain(&nftables.Chain{
		Name:     name,
		Table:    table,
		Hooknum:  hook,
		Priority: nftables.ChainPriorityFilter,
		Type:     nftables.ChainTypeFilter,
	})
}

func (h hookedTable) tags(t *testing.T) []string {
	t.Helper()
	tags := append(chainTags(t, h.table, h.input), chainTags(t, h.table, h.forward)...)
	slices.Sort(tags)
	return tags
}

func chainTags(t *testing.T, table *nftables.Table, chain *nftables.Chain) []string {
	t.Helper()
	tags := []string{}
	for _, rule := range listRules(t, table, chain) {
		if len(rule.UserData) > 0 {
			tags = append(tags, string(rule.UserData))
		}
	}
	return tags
}

// assertTagsMatchInterface shows a tag is not just a label: the rule carrying it opens exactly the
// interface of the session the tag belongs to.
func assertTagsMatchInterface(t *testing.T, h hookedTable, session *runningSession) {
	t.Helper()
	want := ifname(session.manager.wgIface.Name())
	for _, chain := range []*nftables.Chain{h.input, h.forward} {
		for _, rule := range listRules(t, h.table, chain) {
			if !newAcceptTags(session.names.TagSuffix).contains(rule.UserData) {
				continue
			}
			cmp, ok := rule.Exprs[1].(*expr.Cmp)
			require.True(t, ok, "rule %q must compare the interface name first", rule.UserData)
			assert.Equal(t, want, cmp.Data, "rule %q must match the interface of its session", rule.UserData)
		}
	}
}

func sessionTagsSorted(suffixes ...string) []string {
	tags := []string{}
	for _, suffix := range suffixes {
		tags = append(tags, testTagForwardIif+suffix, testTagForwardOif+suffix, testTagInput+suffix)
	}
	slices.Sort(tags)
	return tags
}

// ruleIdentity includes the kernel handle, so a rule that was deleted and recreated counts as a
// change even when it looks the same.
type ruleIdentity struct {
	Family nftables.TableFamily
	Chain  string
	Handle uint64
	Tag    string
}

func snapshotTableRules(t *testing.T, name string) []ruleIdentity {
	t.Helper()
	conn := &nftables.Conn{}
	chains, err := conn.ListChains()
	require.NoError(t, err)

	rules := []ruleIdentity{}
	for _, chain := range chains {
		if chain.Table.Name != name {
			continue
		}
		listed, err := conn.GetRules(chain.Table, chain)
		require.NoError(t, err)
		for _, rule := range listed {
			rules = append(rules, ruleIdentity{chain.Table.Family, chain.Name, rule.Handle, string(rule.UserData)})
		}
	}
	return rules
}

func tableFamilies(t *testing.T, name string) []nftables.TableFamily {
	t.Helper()
	conn := &nftables.Conn{}
	tables, err := conn.ListTables()
	require.NoError(t, err)
	families := []nftables.TableFamily{}
	for _, table := range tables {
		if table.Name == name {
			families = append(families, table.Family)
		}
	}
	slices.Sort(families)
	return families
}

func assertNoAcceptTags(t *testing.T, tableName string, context string) {
	t.Helper()
	for _, rule := range snapshotTableRules(t, tableName) {
		assert.False(t, strings.HasPrefix(rule.Tag, testTagForwardIif) ||
			strings.HasPrefix(rule.Tag, testTagForwardOif) ||
			strings.HasPrefix(rule.Tag, testTagInput),
			"%s: accept rule %q must not be in table %s, chain %s", context, rule.Tag, tableName, rule.Chain)
	}
}

type runningSession struct {
	slot    uint
	names   SessionNames
	manager *Manager
}

func startSession(t *testing.T, slot uint) *runningSession {
	t.Helper()
	names, err := NamesForSlot(slot)
	require.NoError(t, err)
	manager, err := CreateForSession(sessionIface(slot), iface.DefaultMTU, names)
	require.NoError(t, err)
	require.NoError(t, manager.Init(nil))

	// A rule from the management side, so the snapshots also cover what a live session
	// accumulates after its start.
	source := netip.PrefixFrom(netip.AddrFrom4([4]byte{100, byte(slot + 96), 0, 2}), 32)
	_, err = manager.AddFilterRule(nil, []netip.Prefix{source}, fw.Network{}, fw.ProtocolTCP, nil,
		&fw.Port{Values: []uint16{uint16(1000 + slot)}}, fw.ActionAccept)
	require.NoError(t, err)
	require.NoError(t, manager.Flush())

	s := &runningSession{slot: slot, names: names, manager: manager}
	t.Cleanup(func() { s.stop(t) })
	return s
}

func (s *runningSession) stop(t *testing.T) {
	t.Helper()
	if s.manager == nil {
		return
	}
	manager := s.manager
	s.manager = nil
	require.NoError(t, manager.Close(nil))
}

// TestSessionManagersAreIndependent runs real managers side by side, slots 1 and 10 included
// because one tag being the prefix of the other must not matter. It checks after every start and
// stop that the other sessions kept their table, rules and tags, down to the rule handles.
func TestSessionManagersAreIndependent(t *testing.T) {
	tests := []struct {
		name  string
		start []uint
		stop  []uint
	}{
		{name: "slot zero first, stopped first", start: []uint{0, 1, 10}, stop: []uint{0, 1, 10}},
		{name: "slot zero last, stopped last", start: []uint{10, 1, 0}, stop: []uint{10, 1, 0}},
		{name: "middle stopped first", start: []uint{0, 1, 10}, stop: []uint{1, 10, 0}},
		{name: "longer tag stopped first", start: []uint{1, 10, 0}, stop: []uint{10, 0, 1}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			foreign := addHookedTable(t, "nbtest_foreign")
			isolation := addHookedTable(t, IsolationTableName)

			running := map[uint]*runningSession{}
			snapshots := map[uint][]ruleIdentity{}

			assertOthersUntouched := func(context string) {
				t.Helper()
				suffixes := []string{}
				for slot, session := range running {
					assert.Equal(t, snapshots[slot], snapshotTableRules(t, session.names.Table),
						"%s: table of slot %d must not change", context, slot)
					assert.Equal(t, []nftables.TableFamily{nftables.TableFamilyIPv4, nftables.TableFamilyIPv6},
						tableFamilies(t, session.names.Table), "%s: slot %d must keep its tables", context, slot)
					suffixes = append(suffixes, session.names.TagSuffix)
				}
				assert.Equal(t, sessionTagsSorted(suffixes...), foreign.tags(t),
					"%s: foreign chains must carry exactly the tags of the running sessions", context)
				assertNoAcceptTags(t, IsolationTableName, context)
				for _, session := range running {
					assertNoAcceptTags(t, session.names.Table, context)
				}
			}

			for _, slot := range tc.start {
				session := startSession(t, slot)
				running[slot] = session
				snapshots[slot] = snapshotTableRules(t, session.names.Table)
				assertOthersUntouched(fmt.Sprintf("after start of slot %d", slot))
			}

			for _, session := range running {
				require.NoError(t, session.manager.reconcileExternalChains())
			}
			assertOthersUntouched("after explicit reconcile")
			assert.Empty(t, isolation.tags(t), "isolation table must stay closed")
			for _, session := range running {
				assertTagsMatchInterface(t, foreign, session)
			}

			for _, slot := range tc.stop {
				session := running[slot]
				session.stop(t)
				delete(running, slot)

				assert.Empty(t, tableFamilies(t, session.names.Table), "slot %d must remove its table", slot)
				assertOthersUntouched(fmt.Sprintf("after stop of slot %d", slot))
			}
			assert.Empty(t, foreign.tags(t), "all tags must be gone")
		})
	}
}

// TestSessionManagerMonitorSkipsSessionTables covers the path F0 found separately from the start:
// a chain appearing later in another session's table or in the isolation table, while the monitors
// run. The foreign chain created last proves the reconcile ran after the others were visible.
func TestSessionManagerMonitorSkipsSessionTables(t *testing.T) {
	first := startSession(t, 0)
	second := startSession(t, 1)
	isolation := addHookedTable(t, IsolationTableName)
	foreign := addHookedTable(t, "nbtest_foreign_late")

	require.Eventually(t, func() bool {
		return len(foreign.tags(t)) == len(sessionTagsSorted("", "-1"))
	}, 5*time.Second, 50*time.Millisecond, "monitors must open a foreign table that appears later")

	conn := &nftables.Conn{}
	firstTable := &nftables.Table{Name: first.names.Table, Family: nftables.TableFamilyIPv4}
	secondTable := &nftables.Table{Name: second.names.Table, Family: nftables.TableFamilyIPv4}
	addHookedChain(conn, firstTable, "nbtest_late_forward", nftables.ChainHookForward)
	addHookedChain(conn, secondTable, "nbtest_late_forward", nftables.ChainHookForward)
	addHookedChain(conn, isolation.table, "nbtest_late_forward", nftables.ChainHookForward)
	require.NoError(t, conn.Flush(), "create late chains")

	lateForeign := &nftables.Chain{Name: "nbtest_late_forward", Table: foreign.table}
	addHookedChain(conn, foreign.table, lateForeign.Name, nftables.ChainHookForward)
	require.NoError(t, conn.Flush(), "create late foreign chain")

	require.Eventually(t, func() bool {
		return len(chainTags(t, foreign.table, lateForeign)) == 4
	}, 5*time.Second, 50*time.Millisecond, "both sessions must open the late foreign chain")

	assertNoAcceptTags(t, first.names.Table, "first session table")
	assertNoAcceptTags(t, second.names.Table, "second session table")
	assertNoAcceptTags(t, IsolationTableName, "isolation table")
}

// TestSlotZeroMatchesCreate pins I1: the session constructor in slot 0 and the plain constructor
// produce the same rule set, and the literal names below are the ones released clients use.
func TestSlotZeroMatchesCreate(t *testing.T) {
	foreign := addHookedTable(t, "nbtest_foreign")

	dump := func(manager *Manager) ([]ruleDump, []string, string) {
		require.NoError(t, manager.Init(nil))
		rules := dumpTableRules(t, "netbird")
		tags := foreign.tags(t)
		state, err := json.Marshal(manager.shutdownState())
		require.NoError(t, err)
		require.NoError(t, manager.Close(nil))
		return rules, tags, string(state)
	}

	plain, err := Create(sessionIface(0), iface.DefaultMTU)
	require.NoError(t, err)
	plainRules, plainTags, plainState := dump(plain)

	names, err := NamesForSlot(0)
	require.NoError(t, err)
	assert.Equal(t, SessionNames{Table: "netbird"}, names, "slot 0 must keep the table name and have no suffix")

	slotZero, err := CreateForSession(sessionIface(0), iface.DefaultMTU, names)
	require.NoError(t, err)
	slotRules, slotTags, slotState := dump(slotZero)

	require.NotEmpty(t, plainRules, "plain manager must create rules")
	assert.Equal(t, plainRules, slotRules, "slot 0 must create the same rules as Create")
	assert.Equal(t, []string{testTagForwardIif, testTagForwardOif, testTagInput}, plainTags, "released tags must not change")
	assert.Equal(t, plainTags, slotTags, "slot 0 must use the same tags as Create")
	assert.Equal(t, plainState, slotState, "slot 0 must persist the same state as Create")
	assert.NotContains(t, slotState, "table_name", "state of slot 0 must keep the old format")
	assert.NotContains(t, slotState, "tag_suffix", "state of slot 0 must keep the old format")
	assert.Empty(t, foreign.tags(t), "both must clean up")
	assert.Empty(t, tableFamilies(t, "netbird"), "both must remove the table")
}

type ruleDump struct {
	Family nftables.TableFamily
	Chain  string
	Tag    string
	Exprs  []expr.Any
}

func dumpTableRules(t *testing.T, name string) []ruleDump {
	t.Helper()
	conn := &nftables.Conn{}
	chains, err := conn.ListChains()
	require.NoError(t, err)

	rules := []ruleDump{}
	for _, chain := range chains {
		if chain.Table.Name != name {
			continue
		}
		listed, err := conn.GetRules(chain.Table, chain)
		require.NoError(t, err)
		for _, rule := range listed {
			rules = append(rules, ruleDump{chain.Table.Family, chain.Name, string(rule.UserData), rule.Exprs})
		}
	}
	return rules
}

// TestCreateKeepsOpeningLookalikeTables pins that nothing changes until the session API is used:
// without it a table that merely looks like a session table is a foreign table, as it is today.
// The isolation table is the one exception: only the gate creates it.
func TestCreateKeepsOpeningLookalikeTables(t *testing.T) {
	lookalike := addHookedTable(t, "netbird-5")
	isolation := addHookedTable(t, IsolationTableName)

	manager, err := Create(sessionIface(0), iface.DefaultMTU)
	require.NoError(t, err)
	require.NoError(t, manager.Init(nil))
	t.Cleanup(func() { assert.NoError(t, manager.Close(nil)) })

	assert.Equal(t, sessionTagsSorted(""), lookalike.tags(t), "Create must treat netbird-5 as foreign")
	assert.Empty(t, isolation.tags(t), "the isolation table is never foreign, not even for Create")
}

// TestNameLimitsMatchTheKernel creates the longest name we accept and shows the kernel refuses one
// byte more, so the limit in validateTableName is the real one.
func TestNameLimitsMatchTheKernel(t *testing.T) {
	const slot = 7
	base := strings.Repeat("a", maxTableNameLen-len("-"+strconv.Itoa(slot)))
	t.Setenv(envTableName, base)

	names, err := NamesForSlot(slot)
	require.NoError(t, err)
	require.Len(t, names.Table, maxTableNameLen)

	manager, err := CreateForSession(sessionIface(slot), iface.DefaultMTU, names)
	require.NoError(t, err)
	require.NoError(t, manager.Init(nil))
	t.Cleanup(func() { assert.NoError(t, manager.Close(nil)) })
	assert.NotEmpty(t, tableFamilies(t, names.Table), "the kernel must accept the longest valid name")

	t.Setenv(envTableName, base+"a")
	_, err = NamesForSlot(slot)
	assert.Error(t, err, "one byte more must be an error, not a truncated name")

	conn := &nftables.Conn{}
	conn.AddTable(&nftables.Table{Name: strings.Repeat("a", maxTableNameLen+1), Family: nftables.TableFamilyIPv4})
	assert.Error(t, conn.Flush(), "the kernel must refuse a name over the limit")
}

// TestShutdownStateCleansOnlyItsSession replays what the daemon does after a crash, with another
// session alive: the state read back from JSON must remove that session's objects and nothing else.
func TestShutdownStateCleansOnlyItsSession(t *testing.T) {
	foreign := addHookedTable(t, "nbtest_foreign")
	survivor := startSession(t, 0)
	crashed := startSession(t, 1)
	survivorRules := snapshotTableRules(t, survivor.names.Table)

	raw, err := json.Marshal(crashed.manager.shutdownState())
	require.NoError(t, err)
	crashed.manager.extMonitor.stop()
	crashed.manager = nil

	var restored ShutdownState
	require.NoError(t, json.Unmarshal(raw, &restored))
	require.NoError(t, restored.Cleanup())

	assert.Empty(t, tableFamilies(t, "netbird-1"), "the crashed session's table must be gone")
	assert.Equal(t, survivorRules, snapshotTableRules(t, "netbird"), "the live session must keep its rules")
	assert.Equal(t, sessionTagsSorted(""), foreign.tags(t), "only the crashed session's tags may go")
}

// TestShutdownStateWithoutNamesBelongsToSlotZero covers state files written before slots existed.
func TestShutdownStateWithoutNamesBelongsToSlotZero(t *testing.T) {
	foreign := addHookedTable(t, "nbtest_foreign")
	slotZero := startSession(t, 0)
	other := startSession(t, 1)
	otherRules := snapshotTableRules(t, other.names.Table)

	slotZero.manager.extMonitor.stop()
	slotZero.manager = nil

	var restored ShutdownState
	require.NoError(t, json.Unmarshal([]byte(`{"interface_state":{"name":"wt0","wg_address":{"IP":"100.96.0.1","Network":"100.96.0.0/16"},"mtu":1280}}`), &restored))
	require.NoError(t, restored.Cleanup())

	assert.Empty(t, tableFamilies(t, "netbird"), "state without names must clean the default table")
	assert.Equal(t, otherRules, snapshotTableRules(t, other.names.Table), "slot 1 must keep its rules")
	assert.Equal(t, sessionTagsSorted("-1"), foreign.tags(t), "slot 1 must keep its tags")
}

// TestInvalidShutdownStateIsRefused shows a damaged state cannot make cleanup delete a table it
// does not own, or fall back to the names of slot 0.
func TestInvalidShutdownStateIsRefused(t *testing.T) {
	foreign := addHookedTable(t, "nbtest_foreign")
	live := startSession(t, 0)
	liveRules := snapshotTableRules(t, live.names.Table)

	address := wgaddr.Address{IP: netip.MustParseAddr("100.97.0.1"), Network: netip.MustParsePrefix("100.97.0.0/16")}
	interfaceState := &InterfaceState{NameStr: "wt1", WGAddress: address, MTU: iface.DefaultMTU}

	for name, state := range map[string]*ShutdownState{
		"suffix without table":        {InterfaceState: interfaceState, TagSuffix: "-1"},
		"table of another name":       {InterfaceState: interfaceState, TableName: "filter"},
		"isolation table":             {InterfaceState: interfaceState, TableName: IsolationTableName},
		"mismatched suffix":           {InterfaceState: interfaceState, TableName: "netbird-1", TagSuffix: "-2"},
		"unsuffixed other table":      {InterfaceState: interfaceState, TableName: "netbird-1"},
		"foreign table with a suffix": {InterfaceState: interfaceState, TableName: "myfw-1", TagSuffix: "-1"},
		"base table without suffix":   {InterfaceState: interfaceState, TableName: "netbird"},
		"no interface state":          {},
		"suffix that is not a slot":   {InterfaceState: interfaceState, TableName: "netbird-x", TagSuffix: "-x"},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Error(t, state.Cleanup(), "invalid names must be refused")
			assert.Equal(t, liveRules, snapshotTableRules(t, live.names.Table), "the live session must be untouched")
			assert.Equal(t, sessionTagsSorted(""), foreign.tags(t), "the live session's tags must be untouched")
		})
	}
}

// TestSessionManagersShareFilterTable covers the iptables-managed filter table, which is opened by
// interface instead of by tag and through either iptables or nftables, whichever works here. The
// assertion is on the interface a rule matches, so it holds for both.
func TestSessionManagersShareFilterTable(t *testing.T) {
	conn := &nftables.Conn{}
	table := conn.AddTable(&nftables.Table{Name: tableNameFilter, Family: nftables.TableFamilyIPv4})
	input := addHookedChain(conn, table, chainNameInput, nftables.ChainHookInput)
	forward := addHookedChain(conn, table, chainNameForward, nftables.ChainHookForward)
	require.NoError(t, conn.Flush(), "create filter table")
	t.Cleanup(func() {
		c := &nftables.Conn{}
		c.DelTable(table)
		_ = c.Flush()
	})

	opensInterface := func(chain *nftables.Chain, name string) bool {
		return slices.ContainsFunc(listRules(t, table, chain), func(rule *nftables.Rule) bool {
			return slices.ContainsFunc(rule.Exprs, func(e expr.Any) bool {
				cmp, ok := e.(*expr.Cmp)
				return ok && strings.TrimRight(string(cmp.Data), "\x00") == name
			})
		})
	}

	first := startSession(t, 0)
	second := startSession(t, 1)
	for _, chain := range []*nftables.Chain{input, forward} {
		assert.True(t, opensInterface(chain, "wt0"), "%s must open wt0", chain.Name)
		assert.True(t, opensInterface(chain, "wt1"), "%s must open wt1", chain.Name)
	}

	second.stop(t)
	for _, chain := range []*nftables.Chain{input, forward} {
		assert.True(t, opensInterface(chain, "wt0"), "%s must keep wt0 open after wt1 stops", chain.Name)
		assert.False(t, opensInterface(chain, "wt1"), "%s must close wt1", chain.Name)
	}

	first.stop(t)
	for _, chain := range []*nftables.Chain{input, forward} {
		assert.False(t, opensInterface(chain, "wt0"), "%s must close wt0", chain.Name)
	}
}

// TestSessionInterfaceAllowers is the userspace-mode counterpart: only INPUT is opened and no table
// is created, but tags and the exclusion of session tables must hold the same way.
func TestSessionInterfaceAllowers(t *testing.T) {
	foreign := addHookedTable(t, "nbtest_foreign")
	sessionTable := addHookedTable(t, "netbird-1")
	isolation := addHookedTable(t, IsolationTableName)

	namesZero, err := NamesForSlot(0)
	require.NoError(t, err)
	namesOne, err := NamesForSlot(1)
	require.NoError(t, err)

	allowerZero, err := NewInterfaceAllowerForSession(sessionIface(0), iface.DefaultMTU, namesZero)
	require.NoError(t, err)
	require.NoError(t, allowerZero.Apply())
	t.Cleanup(func() { assert.NoError(t, allowerZero.Close()) })

	allowerOne, err := NewInterfaceAllowerForSession(sessionIface(1), iface.DefaultMTU, namesOne)
	require.NoError(t, err)
	require.NoError(t, allowerOne.Apply())

	assert.Equal(t, []string{testTagInput, testTagInput + "-1"}, foreign.tags(t), "foreign INPUT must be opened per session")
	assert.Empty(t, sessionTable.tags(t), "another session's table must stay closed")
	assert.Empty(t, isolation.tags(t), "the isolation table must stay closed")

	require.NoError(t, allowerOne.Close())
	assert.Equal(t, []string{testTagInput}, foreign.tags(t), "close must remove only its own tag")
}
