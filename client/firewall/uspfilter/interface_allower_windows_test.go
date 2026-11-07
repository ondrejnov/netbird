package uspfilter

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSlotFirewallRuleName(t *testing.T) {
	assert.Equal(t, "Netbird", SlotFirewallRuleName(0), "slot 0 keeps the rule of a client without sessions")
	assert.Equal(t, "Netbird-1", SlotFirewallRuleName(1))
	assert.Equal(t, "Netbird-12", SlotFirewallRuleName(12))

	zero := NewWindowsInterfaceAllowerForSlot(nil, 0)
	assert.Equal(t, NewWindowsInterfaceAllower(nil), zero, "slot 0 behaves exactly as today, also on a stale rule")
	one := NewWindowsInterfaceAllowerForSlot(nil, 1)
	assert.Equal(t, "Netbird-1", one.ruleName)
	assert.True(t, one.replaceStale, "a rule a crash left on slot 1 is replaced, its address may be stale")
}
