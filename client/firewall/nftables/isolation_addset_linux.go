//go:build !android

package nftables

import (
	"sync"

	"github.com/google/nftables"
)

// addSetMu covers the process-wide set ID counter inside the library, which AddSet updates
// without synchronization while managers of several sessions create sets at once. Assigning
// Set.ID ourselves is no way around it: the library names anonymous sets only for ID 0.
var addSetMu sync.Mutex

// addSet is the only way this package may call Conn.AddSet.
func addSet(conn *nftables.Conn, set *nftables.Set, elements []nftables.SetElement) error {
	addSetMu.Lock()
	defer addSetMu.Unlock()
	return conn.AddSet(set, elements)
}
