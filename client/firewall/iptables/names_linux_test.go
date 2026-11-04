//go:build !android

package iptables

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSlotZeroKeepsTodaysNames(t *testing.T) {
	names, err := newChainNames(0)
	require.NoError(t, err)

	assert.Equal(t, chainACLInput, names.aclInput)
	assert.Equal(t, chainRTNAT, names.rtNAT)
	assert.Equal(t, chainRTFwdIn, names.rtFwdIn)
	assert.Equal(t, chainRTFwdOut, names.rtFwdOut)
	assert.Equal(t, chainRTPre, names.rtPre)
	assert.Equal(t, chainRTRdr, names.rtRdr)
	assert.Equal(t, chainNATOutput, names.natOutput)
	assert.Equal(t, chainRTMSSClamp, names.rtMSSClamp)
	assert.Empty(t, names.acceptTag(), "slot 0 must not tag its accept rules")

	setName, err := names.ipsetName("nb-0a1b2c3d", false)
	require.NoError(t, err)
	assert.Equal(t, "nb-0a1b2c3d", setName)

	setName, err = names.ipsetName("nb-0a1b2c3d", true)
	require.NoError(t, err)
	assert.Equal(t, "nb-0a1b2c3d-v6", setName)
}

func TestSlotSuffixIsAppendedToEveryChainAndSet(t *testing.T) {
	names, err := newChainNames(12)
	require.NoError(t, err)

	assert.Equal(t, "NETBIRD-ACL-INPUT-12", names.aclInput)
	assert.Equal(t, "NETBIRD-RT-NAT-12", names.rtNAT)
	assert.Equal(t, "NETBIRD-RT-FWD-IN-12", names.rtFwdIn)
	assert.Equal(t, "NETBIRD-RT-FWD-OUT-12", names.rtFwdOut)
	assert.Equal(t, "NETBIRD-RT-PRE-12", names.rtPre)
	assert.Equal(t, "NETBIRD-RT-RDR-12", names.rtRdr)
	assert.Equal(t, "NETBIRD-NAT-OUTPUT-12", names.natOutput)
	assert.Equal(t, "NETBIRD-RT-MSSCLAMP-12", names.rtMSSClamp)
	assert.Equal(t, "netbird-12", names.acceptTag())

	setName, err := names.ipsetName("nb-0a1b2c3d", false)
	require.NoError(t, err)
	assert.Equal(t, "nb-0a1b2c3d-12", setName)

	setName, err = names.ipsetName("nb-0a1b2c3d", true)
	require.NoError(t, err)
	assert.Equal(t, "nb-0a1b2c3d-v6-12", setName)
}

func TestSameSetInTwoSlotsGetsDifferentNames(t *testing.T) {
	slot1, err := newChainNames(1)
	require.NoError(t, err)
	slot2, err := newChainNames(2)
	require.NoError(t, err)

	for _, v6 := range []bool{false, true} {
		first, err := slot1.ipsetName("nb-0a1b2c3d", v6)
		require.NoError(t, err)
		second, err := slot2.ipsetName("nb-0a1b2c3d", v6)
		require.NoError(t, err)
		assert.NotEqual(t, first, second, "v6=%v: one hash must not map to one kernel object", v6)
	}
}

// The longest chain name is 19 characters against the kernel limit of 28, so
// the largest suffix that fits is 9 characters: "-" plus 8 digits.
func TestChainNameLimitIsReportedNeverTruncated(t *testing.T) {
	names, err := newChainNames(99999999)
	require.NoError(t, err, "a suffix that exactly fits the limit must be accepted")
	assert.Equal(t, "NETBIRD-RT-MSSCLAMP-99999999", names.rtMSSClamp)
	assert.Len(t, names.rtMSSClamp, maxChainNameLen)

	_, err = newChainNames(100000000)
	require.Error(t, err, "one digit more must be rejected")
	assert.Contains(t, err.Error(), "NETBIRD-RT-MSSCLAMP-100000000", "the error must name the rejected chain in full")
}

func TestIPSetNameLimitIsReportedNeverTruncated(t *testing.T) {
	// A slot that fits the chain limit still has to leave room in the set name.
	names, err := newChainNames(99999999)
	require.NoError(t, err)

	setName, err := names.ipsetName("nb-0a1b2c3d", true)
	require.NoError(t, err)
	assert.LessOrEqual(t, len(setName), maxIPSetNameLen)

	longBase := "nb-" + strings.Repeat("a", maxIPSetNameLen)
	_, err = names.ipsetName(longBase, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), fmt.Sprintf("%s-99999999", longBase), "the error must carry the whole rejected name")

	// Slot 0 must not start rejecting a name it accepts today only if it is within the limit.
	zero, err := newChainNames(0)
	require.NoError(t, err)
	exact := strings.Repeat("b", maxIPSetNameLen)
	got, err := zero.ipsetName(exact, false)
	require.NoError(t, err)
	assert.Equal(t, exact, got)
	_, err = zero.ipsetName(exact+"b", false)
	require.Error(t, err)
}

func TestWithSlotConfiguresFamilyNames(t *testing.T) {
	cfg := newConfig(WithSlot(3))
	assert.Equal(t, uint(3), cfg.slot)
	assert.Equal(t, uint(0), newConfig().slot, "no option means slot 0")
}

func TestPersistedInterfaceStateKeepsSlotZeroFormat(t *testing.T) {
	zero, err := json.Marshal(&InterfaceState{NameStr: "wt0", MTU: 1280})
	require.NoError(t, err)
	assert.NotContains(t, string(zero), "slot", "slot 0 must serialize as it does today")

	other, err := json.Marshal(&InterfaceState{NameStr: "wt3", MTU: 1280, Slot: 3})
	require.NoError(t, err)

	var restored InterfaceState
	require.NoError(t, json.Unmarshal(other, &restored))
	assert.Equal(t, uint(3), restored.Slot)

	var legacy InterfaceState
	require.NoError(t, json.Unmarshal(zero, &legacy))
	assert.Equal(t, uint(0), legacy.Slot, "a state written before slots existed restores as slot 0")
}
