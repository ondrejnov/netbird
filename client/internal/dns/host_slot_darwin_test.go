//go:build !ios

package dns

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSystemConfigurator_SlotKeys(t *testing.T) {
	zero := newSlotHostManager(0)
	assert.Equal(t, "State:/Network/Service/NetBird-Match/DNS", zero.stateKey(matchSuffix), "slot 0 keeps the names from before sessions")
	assert.Equal(t, "State:/Network/Service/NetBird-Search-2/DNS", zero.indexedStateKey(searchSuffix, 2))

	one := newSlotHostManager(1)
	assert.Equal(t, "State:/Network/Service/NetBirdS1-Local/DNS", one.stateKey(localSuffix))
	assert.Equal(t, "State:/Network/Service/NetBirdS1-Match-0/DNS", one.indexedStateKey(matchSuffix, 0))

	// The discovery after a lost state file goes by whole keys, so no slot may find the keys of
	// another one inside its own.
	eleven := newSlotHostManager(11)
	for _, other := range []*systemConfigurator{zero, one} {
		assert.NotContains(t, eleven.indexedStateKey(matchSuffix, 0), other.indexedStateKey(matchSuffix, 0))
		assert.NotContains(t, other.indexedStateKey(matchSuffix, 0), eleven.indexedStateKey(matchSuffix, 0))
	}
}

func TestShutdownState_KeepsTheSlot(t *testing.T) {
	raw, err := json.Marshal(&ShutdownState{CreatedKeys: []string{"k"}, Slot: 3})
	require.NoError(t, err)

	var restored ShutdownState
	require.NoError(t, json.Unmarshal(raw, &restored))
	assert.Equal(t, uint32(3), restored.Slot, "the cleanup after a crash must look for the keys of the slot")

	raw, err = json.Marshal(&ShutdownState{CreatedKeys: []string{"k"}})
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "Slot", "slot 0 writes the state it wrote before sessions")
}
