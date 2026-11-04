//go:build !linux || android

package ipfwdstate

// readV4Forwarding fails here, so no original is stored and nothing is restored,
// which matches the platform's no-op EnableV4IPForwarding.
func readV4Forwarding() (int, error) {
	return 0, errRestoreUnsupported
}

func writeV4Forwarding(int) error {
	return errRestoreUnsupported
}

func restoreAcceptRA(map[string]int, []string) {}
