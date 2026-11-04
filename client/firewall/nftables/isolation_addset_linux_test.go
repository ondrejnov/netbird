//go:build privileged

package nftables

import (
	"fmt"
	"net/netip"
	"sync"
	"testing"

	"github.com/google/nftables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	fw "github.com/netbirdio/netbird/client/firewall/manager"
)

// TestConcurrentSetCreationHasNoRace runs the two paths that create sets, the named source
// set and the anonymous port set, from independent managers at once. The library counts set
// IDs in an unsynchronized process-wide variable, so this reports a data race under -race
// unless every AddSet in the package is serialized.
func TestConcurrentSetCreationHasNoRace(t *testing.T) {
	const rulesPerSession = 8

	sessions := []*runningSession{}
	for slot := uint(1); slot <= 4; slot++ {
		sessions = append(sessions, startSession(t, slot))
	}

	var wg sync.WaitGroup
	errs := make(chan error, len(sessions)*rulesPerSession)
	for _, session := range sessions {
		wg.Add(1)
		go func(session *runningSession) {
			defer wg.Done()
			for i := range rulesPerSession {
				errs <- addRuleWithTwoSets(session, i)
			}
		}(session)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	for _, session := range sessions {
		sets, err := (&nftables.Conn{}).GetSets(&nftables.Table{Name: session.names.Table, Family: nftables.TableFamilyIPv4})
		require.NoError(t, err)

		named, anonymous := 0, 0
		for _, set := range sets {
			if set.Anonymous {
				anonymous++
			} else {
				named++
			}
		}
		assert.Equal(t, rulesPerSession, named, "slot %d must have one source set per rule", session.slot)
		assert.GreaterOrEqual(t, anonymous, rulesPerSession, "slot %d must have port sets for every rule", session.slot)
	}
}

func addRuleWithTwoSets(session *runningSession, i int) error {
	second := byte(session.slot + 96)
	sources := []netip.Prefix{
		netip.PrefixFrom(netip.AddrFrom4([4]byte{100, second, byte(i), 2}), 32),
		netip.PrefixFrom(netip.AddrFrom4([4]byte{100, second, byte(i), 3}), 32),
	}
	ports := &fw.Port{Values: []uint16{uint16(2000 + i), uint16(3000 + i)}}
	if _, err := session.manager.AddFilterRule(nil, sources, fw.Network{}, fw.ProtocolTCP, nil, ports, fw.ActionAccept); err != nil {
		return fmt.Errorf("add rule %d of slot %d: %w", i, session.slot, err)
	}
	return session.manager.Flush()
}

// TestAddSetGivesEverySetItsOwnID checks what the kernel relies on inside a batch: a nonzero ID
// unique per set, and anonymous sets still named by the library.
func TestAddSetGivesEverySetItsOwnID(t *testing.T) {
	const workers, perWorker = 8, 100
	table := &nftables.Table{Name: "nbtest_ids", Family: nftables.TableFamilyINet}

	ids := make(chan *nftables.Set, workers*perWorker)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn := &nftables.Conn{}
			for i := range perWorker {
				set := &nftables.Set{Table: table, KeyType: nftables.TypeInetService, Anonymous: true, Constant: true}
				if i%2 == 0 {
					set = &nftables.Set{Table: table, Name: fmt.Sprintf("named%d", i), KeyType: nftables.TypeInetService}
				}
				assert.NoError(t, addSet(conn, set, nil))
				ids <- set
			}
		}()
	}
	wg.Wait()
	close(ids)

	seen := map[uint32]bool{}
	for set := range ids {
		assert.NotZero(t, set.ID, "the library must assign an ID")
		assert.False(t, seen[set.ID], "ID %d must not repeat", set.ID)
		seen[set.ID] = true
		if set.Anonymous {
			assert.Equal(t, "__set%d", set.Name, "the library must name an anonymous set")
		}
	}
	assert.Len(t, seen, workers*perWorker, "every set must have its own ID")
}
