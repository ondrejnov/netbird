//go:build !linux || android

package hostcoord

import "context"

// RemoveSessionLinks does nothing, as no session interface can outlive the daemon on this platform.
func RemoveSessionLinks([]SlotRecord) error {
	return nil
}

// VerifyNoSessionLinks finds nothing, for the same reason.
func VerifyNoSessionLinks([]SlotRecord) error {
	return nil
}

// RefuseForeignLink finds nothing to refuse, for the same reason.
func RefuseForeignLink(context.Context, string) error {
	return nil
}
