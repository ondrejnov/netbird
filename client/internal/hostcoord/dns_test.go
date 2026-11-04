package hostcoord

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/dns"
)

var (
	dnsSessionA = SessionKey{Profile: "a", Username: "alice"}
	dnsSessionB = SessionKey{Profile: "b", Username: "alice"}
)

func TestDNSOwners_CatchAllFirstClaimWins(t *testing.T) {
	owners := NewDNSOwners()

	require.NoError(t, owners.ClaimCatchAll(dnsSessionA))
	assert.ErrorIs(t, owners.ClaimCatchAll(dnsSessionB), ErrDNSHeld)

	owner, held := owners.CatchAllOwner()
	assert.True(t, held, "the first claim must stick")
	assert.Equal(t, dnsSessionA, owner, "the first session must stay the owner")

	assert.NoError(t, owners.ClaimCatchAll(dnsSessionA), "the owner may claim again")
}

func TestDNSOwners_ReleaseIsExplicitAndOwnerOnly(t *testing.T) {
	owners := NewDNSOwners()
	require.NoError(t, owners.ClaimCatchAll(dnsSessionA))

	// A session that lost the claim stops: the owner must keep the catch-all.
	owners.ReleaseCatchAll(dnsSessionB)
	owner, held := owners.CatchAllOwner()
	assert.True(t, held, "a release by another session must not free the claim")
	assert.Equal(t, dnsSessionA, owner, "a release by another session must not change the owner")
	assert.ErrorIs(t, owners.ClaimCatchAll(dnsSessionB), ErrDNSHeld)

	// The loser does not inherit the catch-all on release: it has to claim.
	owners.ReleaseCatchAll(dnsSessionA)
	_, held = owners.CatchAllOwner()
	assert.False(t, held, "the owner's release must free the claim and hand it to nobody")

	require.NoError(t, owners.ClaimCatchAll(dnsSessionB))
	owner, _ = owners.CatchAllOwner()
	assert.Equal(t, dnsSessionB, owner, "a free catch-all must go to the next claimer")
}

func TestDNSOwners_HostDNSIndependentOfCatchAll(t *testing.T) {
	owners := NewDNSOwners()
	require.NoError(t, owners.ClaimCatchAll(dnsSessionA))

	require.NoError(t, owners.ClaimHostDNS(dnsSessionB), "the two claims must not share an owner")
	assert.ErrorIs(t, owners.ClaimHostDNS(dnsSessionA), ErrDNSHeld)

	owner, held := owners.HostDNSOwner()
	assert.True(t, held, "the first host DNS claim must stick")
	assert.Equal(t, dnsSessionB, owner, "the first session must own host DNS")

	owners.ReleaseHostDNS(dnsSessionA)
	_, held = owners.HostDNSOwner()
	assert.True(t, held, "a release by another session must not free host DNS")

	owners.ReleaseHostDNS(dnsSessionB)
	_, held = owners.HostDNSOwner()
	assert.False(t, held, "the owner's release must free host DNS")

	owner, held = owners.CatchAllOwner()
	assert.True(t, held, "releasing host DNS must not touch the catch-all")
	assert.Equal(t, dnsSessionA, owner, "releasing host DNS must not change the catch-all owner")
}

func TestDNSOwners_ConcurrentClaimsHaveOneWinner(t *testing.T) {
	owners := NewDNSOwners()

	var winners atomic.Int32
	var wg sync.WaitGroup
	for _, username := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
		wg.Add(1)
		go func(key SessionKey) {
			defer wg.Done()
			if owners.ClaimCatchAll(key) == nil {
				winners.Add(1)
			}
		}(SessionKey{Profile: "default", Username: username})
	}
	wg.Wait()

	assert.Equal(t, int32(1), winners.Load(), "exactly one concurrent claim must win")
}

func TestDNSSession_BindsKeyAndForwards(t *testing.T) {
	owners := NewDNSOwners()

	var warnings []dns.HostDNSWarning
	sessionA := owners.Session(dnsSessionA, func() []string { return []string{"wt0", "wt1"} }, func(w dns.HostDNSWarning) {
		warnings = append(warnings, w)
	})
	sessionB := owners.Session(dnsSessionB, nil, nil)

	assert.Equal(t, []string{"wt0", "wt1"}, sessionA.NetbirdInterfaces(), "interfaces come from the caller")
	assert.Empty(t, sessionB.NetbirdInterfaces(), "a session without a source has no other interfaces")

	require.NoError(t, sessionA.ClaimCatchAll())
	assert.ErrorIs(t, sessionB.ClaimCatchAll(), ErrDNSHeld)
	sessionB.ReleaseCatchAll()
	owner, held := owners.CatchAllOwner()
	assert.True(t, held, "the session must release under its own key")
	assert.Equal(t, dnsSessionA, owner, "the session must claim under its own key")

	require.NoError(t, sessionB.ClaimHostDNS())
	assert.ErrorIs(t, sessionA.ClaimHostDNS(), ErrDNSHeld)
	sessionB.ReleaseHostDNS()
	require.NoError(t, sessionA.ClaimHostDNS())

	warning := dns.HostDNSWarning{Kind: dns.HostDNSCatchAllHeld, Err: ErrDNSHeld}
	sessionA.WarnHostDNS(warning)
	sessionB.WarnHostDNS(warning)
	assert.Equal(t, []dns.HostDNSWarning{warning}, warnings, "the warning must reach the callback, and a missing one must be ignored")
}
