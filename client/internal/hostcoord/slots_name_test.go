package hostcoord

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSlotInterfaceName_PerPlatform(t *testing.T) {
	want := map[Slot]string{0: "wt0", 1: "wt1", 12: "wt12", 4294967295: "wt4294967295"}
	if runtime.GOOS == "darwin" {
		// utun names carry only a unit number, so slot N sits N units above utun100.
		want = map[Slot]string{0: "utun100", 1: "utun101", 12: "utun112", 4294967295: "utun4294967395"}
	}
	for slot, name := range want {
		assert.Equal(t, name, slotInterfaceName(slot), "interface name of slot %d", slot)
		assert.NoError(t, validateSlotInterfaceName(name), "the name of slot %d must be valid", slot)
	}
}
