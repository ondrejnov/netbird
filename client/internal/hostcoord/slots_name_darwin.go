//go:build darwin && !ios

package hostcoord

// The kernel names a utun interface by its unit number only. Slot 0 keeps utun100, the name of
// NetBird before concurrent sessions, and slot N takes the unit N above it.
const (
	slotInterfacePrefix        = "utun"
	slotInterfaceOffset uint64 = 100
)
