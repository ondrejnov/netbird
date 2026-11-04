package nftables

import (
	"encoding/json"
	"math"
	"strings"
	"testing"

	"github.com/google/nftables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNamesForSlot(t *testing.T) {
	tests := []struct {
		name string
		env  string
		slot uint
		want SessionNames
	}{
		{name: "slot zero keeps the historic table", slot: 0, want: SessionNames{Table: "netbird"}},
		{name: "first slot", slot: 1, want: SessionNames{Table: "netbird-1", TagSuffix: "-1"}},
		{name: "two digits", slot: 10, want: SessionNames{Table: "netbird-10", TagSuffix: "-10"}},
		{
			name: "no limit on the number",
			slot: math.MaxUint32,
			want: SessionNames{Table: "netbird-4294967295", TagSuffix: "-4294967295"},
		},
		{name: "env is the whole name of slot zero", env: "custom", slot: 0, want: SessionNames{Table: "custom"}},
		{name: "env is only the base", env: "custom", slot: 3, want: SessionNames{Table: "custom-3", TagSuffix: "-3"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(envTableName, tc.env)
			got, err := NamesForSlot(tc.slot)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got, "names of slot %d", tc.slot)
		})
	}
}

func TestNamesForSlotRefusesInsteadOfTruncating(t *testing.T) {
	const suffix = "-12"
	t.Setenv(envTableName, strings.Repeat("a", maxTableNameLen-len(suffix)))
	names, err := NamesForSlot(12)
	require.NoError(t, err)
	assert.Len(t, names.Table, maxTableNameLen, "the longest name the kernel takes must be accepted")

	t.Setenv(envTableName, strings.Repeat("a", maxTableNameLen-len(suffix)+1))
	_, err = NamesForSlot(12)
	assert.Error(t, err, "a longer name must be refused")

	_, err = NamesForSlot(0)
	assert.NoError(t, err, "the same base still fits without a suffix")
}

func TestNamesForSlotRefusesReservedBase(t *testing.T) {
	for _, base := range []string{IsolationTableName, firewalldTableName, tableNameFilter, tableNat, tableMangle, tableRaw, tableSecurity} {
		t.Run(base, func(t *testing.T) {
			t.Setenv(envTableName, base)
			_, err := NamesForSlot(0)
			assert.Error(t, err, "closing a manager deletes its table, so it must not own %s", base)
		})
	}
}

func TestSessionNamesValidate(t *testing.T) {
	tests := []struct {
		name    string
		names   SessionNames
		wantErr bool
	}{
		{name: "slot zero", names: SessionNames{Table: "netbird"}},
		{name: "slot one", names: SessionNames{Table: "netbird-1", TagSuffix: "-1"}},
		{name: "empty", names: SessionNames{}, wantErr: true},
		{name: "suffix without table", names: SessionNames{TagSuffix: "-1"}, wantErr: true},
		{name: "unsuffixed tags on a slot table", names: SessionNames{Table: "netbird-1"}, wantErr: true},
		{name: "unsuffixed tags on another table", names: SessionNames{Table: "other"}, wantErr: true},
		{name: "suffix on a foreign table", names: SessionNames{Table: "myfw-1", TagSuffix: "-1"}, wantErr: true},
		{name: "suffix of another slot", names: SessionNames{Table: "netbird-1", TagSuffix: "-2"}, wantErr: true},
		{name: "suffix without a number", names: SessionNames{Table: "netbird-", TagSuffix: "-"}, wantErr: true},
		{name: "suffix with letters", names: SessionNames{Table: "netbird-1a", TagSuffix: "-1a"}, wantErr: true},
		{name: "suffix without separator", names: SessionNames{Table: "netbird1", TagSuffix: "1"}, wantErr: true},
		{name: "NUL in the table", names: SessionNames{Table: "net\x00bird-1", TagSuffix: "-1"}, wantErr: true},
		{
			name:    "table over the limit",
			names:   SessionNames{Table: strings.Repeat("a", maxTableNameLen-1) + "-1", TagSuffix: "-1"},
			wantErr: true,
		},
		{
			name: "tag over the limit",
			names: SessionNames{
				Table:     getTableName() + "-" + strings.Repeat("1", maxRuleTagLen),
				TagSuffix: "-" + strings.Repeat("1", maxRuleTagLen),
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(envTableName, "")
			err := tc.names.validate()
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestCreateForSessionRefusesInvalidNames(t *testing.T) {
	t.Setenv(envTableName, "")
	_, err := CreateForSession(nil, 0, SessionNames{Table: IsolationTableName})
	assert.Error(t, err, "manager")
	_, err = NewInterfaceAllowerForSession(nil, 0, SessionNames{Table: "netbird-1"})
	assert.Error(t, err, "allower")
}

func externalChainFixture(table string, family nftables.TableFamily) *nftables.Chain {
	return &nftables.Chain{
		Name:     "chain",
		Table:    &nftables.Table{Name: table, Family: family},
		Hooknum:  nftables.ChainHookForward,
		Type:     nftables.ChainTypeFilter,
		Priority: nftables.ChainPriorityFilter,
	}
}

func TestIsExternalChainInSession(t *testing.T) {
	tests := []struct {
		table string
		want  bool
	}{
		{table: "netbird-1", want: false},
		{table: "netbird", want: false},
		{table: "netbird-2", want: false},
		{table: "netbird-10", want: false},
		{table: "netbird-123456789012345678901234567890", want: false},
		{table: IsolationTableName, want: false},
		{table: "firewalld", want: false},
		{table: "netbird-", want: true},
		{table: "netbird-1a", want: true},
		{table: "netbird-a1", want: true},
		{table: "netbird1", want: true},
		{table: "netbirdx-1", want: true},
		{table: "xnetbird-1", want: true},
		{table: "netbird-1-1", want: true},
		{table: "user_table", want: true},
	}

	t.Setenv(envTableName, "")
	scope, err := newSessionScope(SessionNames{Table: "netbird-1", TagSuffix: "-1"})
	require.NoError(t, err)
	r := &family{workTable: &nftables.Table{Name: "netbird-1"}}
	r.bindSession(scope)

	for _, tc := range tests {
		for _, tableFamily := range []nftables.TableFamily{nftables.TableFamilyIPv4, nftables.TableFamilyINet} {
			assert.Equal(t, tc.want, r.isExternalChain(externalChainFixture(tc.table, tableFamily)),
				"table %q in family %d", tc.table, tableFamily)
		}
	}
}

func TestIsExternalChainFollowsTheBaseFromEnv(t *testing.T) {
	t.Setenv(envTableName, "custom")
	names, err := NamesForSlot(2)
	require.NoError(t, err)
	scope, err := newSessionScope(names)
	require.NoError(t, err)
	r := &family{workTable: &nftables.Table{Name: names.Table}}
	r.bindSession(scope)

	assert.False(t, r.isExternalChain(externalChainFixture("custom", nftables.TableFamilyIPv4)), "base table")
	assert.False(t, r.isExternalChain(externalChainFixture("custom-7", nftables.TableFamilyIPv4)), "sibling table")
	assert.False(t, r.isExternalChain(externalChainFixture(IsolationTableName, nftables.TableFamilyINet)), "isolation table")
	assert.True(t, r.isExternalChain(externalChainFixture("netbird-7", nftables.TableFamilyIPv4)), "another base is foreign")
}

// Without a session scope only the own table is excluded, exactly as before sessions existed.
func TestIsExternalChainWithoutSession(t *testing.T) {
	t.Setenv(envTableName, "")
	r := &family{workTable: &nftables.Table{Name: "netbird"}}

	assert.False(t, r.isExternalChain(externalChainFixture("netbird", nftables.TableFamilyIPv4)), "own table")
	assert.True(t, r.isExternalChain(externalChainFixture("netbird-1", nftables.TableFamilyIPv4)), "lookalike")
	assert.True(t, r.isExternalChain(externalChainFixture(IsolationTableName, nftables.TableFamilyINet)), "isolation name")
}

func TestAcceptTags(t *testing.T) {
	plain := newAcceptTags("")
	assert.Equal(t, acceptTags{"frwacceptiif", "frwacceptoif", "inputaccept"}, plain, "historic tags must not change")

	one := newAcceptTags("-1")
	ten := newAcceptTags("-10")
	assert.Equal(t, acceptTags{"frwacceptiif-1", "frwacceptoif-1", "inputaccept-1"}, one, "suffixed tags")

	for _, tags := range []acceptTags{plain, one, ten} {
		for _, own := range []string{tags.forwardIif, tags.forwardOif, tags.input} {
			assert.True(t, tags.contains([]byte(own)), "own tag %q", own)
		}
	}
	assert.False(t, plain.contains([]byte(one.input)), "slot 0 must not claim a tag of slot 1")
	assert.False(t, one.contains([]byte(plain.input)), "slot 1 must not claim a tag of slot 0")
	assert.False(t, one.contains([]byte(ten.input)), "slot 1 must not claim a tag of slot 10")
	assert.False(t, ten.contains([]byte(one.input)), "slot 10 must not claim a tag of slot 1")
	assert.False(t, one.contains(nil), "an untagged rule belongs to nobody")
}

func TestMonitorIgnoresSessionTablesOnlyInSession(t *testing.T) {
	t.Setenv(envTableName, "")
	scope, err := newSessionScope(SessionNames{Table: "netbird-1", TagSuffix: "-1"})
	require.NoError(t, err)

	newChain := func(table string) *nftables.MonitorEvent {
		return &nftables.MonitorEvent{
			Type: nftables.MonitorEventTypeNewChain,
			Data: &nftables.Chain{Name: "c", Table: &nftables.Table{Name: table, Family: nftables.TableFamilyINet}},
		}
	}
	newTable := func(table string) *nftables.MonitorEvent {
		return &nftables.MonitorEvent{
			Type: nftables.MonitorEventTypeNewTable,
			Data: &nftables.Table{Name: table, Family: nftables.TableFamilyINet},
		}
	}

	session := newExternalChainMonitor(&fakeReconciler{})
	session.scope = scope
	plain := newExternalChainMonitor(&fakeReconciler{})

	for _, table := range []string{"netbird", "netbird-1", "netbird-99", IsolationTableName} {
		assert.False(t, session.isRelevant(newChain(table)), "new chain in %s", table)
		assert.False(t, session.isRelevant(newTable(table)), "new table %s", table)
		assert.True(t, plain.isRelevant(newChain(table)), "without a session, new chain in %s", table)
		assert.True(t, plain.isRelevant(newTable(table)), "without a session, new table %s", table)
	}
	assert.True(t, session.isRelevant(newChain("firewalld")), "firewalld reload must still reconcile")
	assert.True(t, session.isRelevant(newTable("user_table")), "a foreign table must still reconcile")
	assert.False(t, session.isRelevant(&nftables.MonitorEvent{Type: nftables.MonitorEventTypeNewChain}), "no data")
}

// The state format is the part of slot 0 that survives a restart, so it is pinned literally.
func TestShutdownStateFormat(t *testing.T) {
	plain, err := json.Marshal(&ShutdownState{InterfaceState: &InterfaceState{NameStr: "wt0"}})
	require.NoError(t, err)
	assert.JSONEq(t, `{"interface_state":{"name":"wt0","wg_address":{"IP":"","Network":"","IPv6":"","IPv6Net":""},"mtu":0}}`,
		string(plain), "state without session names")

	var old ShutdownState
	require.NoError(t, json.Unmarshal([]byte(`{"interface_state":{"name":"wt0"}}`), &old))
	assert.Empty(t, old.TableName, "an old state file has no table name")
	assert.Empty(t, old.TagSuffix, "an old state file has no tag suffix")
}

// A state naming a table other than the base with the suffix, or a table without a suffix, is
// refused before any table is touched: Close would delete whatever the state names.
func TestDamagedShutdownStateIsRefusedWithoutHost(t *testing.T) {
	t.Setenv(envTableName, "")
	interfaceState := &InterfaceState{NameStr: "wt1", MTU: 1280}

	for name, state := range map[string]*ShutdownState{
		"foreign table with a suffix": {InterfaceState: interfaceState, TableName: "myfw-1", TagSuffix: "-1"},
		"base table without suffix":   {InterfaceState: interfaceState, TableName: "netbird"},
		"no interface state":          {},
		"names without interface":     {TableName: "netbird-1", TagSuffix: "-1"},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Error(t, state.Cleanup(), "a damaged state must be refused")
		})
	}
}
