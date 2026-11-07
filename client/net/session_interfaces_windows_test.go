package net

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExcludedInterfaces(t *testing.T) {
	t.Cleanup(func() {
		SetVPNInterfaceName("")
		SetSessionInterfacesSource(nil)
	})

	SetVPNInterfaceName("")
	SetSessionInterfacesSource(nil)
	assert.Empty(t, excludedInterfaces(), "a client without interfaces excludes nothing")

	SetVPNInterfaceName("wt0")
	assert.Equal(t, []string{"wt0"}, excludedInterfaces(), "a client without sessions excludes its interface, as before")

	sessions := []string{"wt0", "wt1"}
	SetSessionInterfacesSource(func() []string { return sessions })
	assert.ElementsMatch(t, []string{"wt0", "wt1"}, excludedInterfaces(), "every session's interface, once")

	// Session wt1 stopped last and cleared the name; wt0 still runs and must stay excluded.
	SetVPNInterfaceName("")
	sessions = []string{"wt0"}
	assert.Equal(t, []string{"wt0"}, excludedInterfaces(), "the stop of one session does not unexclude another")
}
