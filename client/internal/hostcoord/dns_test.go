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

func TestDNSOwners_ConflictFollowsTheClaims(t *testing.T) {
	owners := NewDNSOwners()

	require.NoError(t, owners.ClaimHostDNS(dnsSessionA))
	assert.False(t, owners.InConflict(dnsSessionA), "the owner is in no conflict")
	assert.False(t, owners.InConflict(dnsSessionB), "a session that asked for nothing is in no conflict")

	require.ErrorIs(t, owners.ClaimHostDNS(dnsSessionB), ErrDNSHeld)
	assert.True(t, owners.InConflict(dnsSessionB), "a refused claim is a conflict")
	assert.False(t, owners.InConflict(dnsSessionA), "a refused claim is the problem of the one refused")

	owners.ReleaseHostDNS(dnsSessionA)
	assert.True(t, owners.InConflict(dnsSessionB), "a free resource is not handed over, and the session has not claimed it yet")

	require.NoError(t, owners.ClaimHostDNS(dnsSessionB))
	assert.False(t, owners.InConflict(dnsSessionB), "the claim went through")

	require.NoError(t, owners.ClaimCatchAll(dnsSessionA))
	require.ErrorIs(t, owners.ClaimCatchAll(dnsSessionB), ErrDNSHeld)
	assert.True(t, owners.InConflict(dnsSessionB), "the catch-all counts as well")
	owners.ReleaseCatchAll(dnsSessionB)
	assert.False(t, owners.InConflict(dnsSessionB), "a session that stopped asking is in no conflict")

	require.ErrorIs(t, owners.ClaimCatchAll(dnsSessionB), ErrDNSHeld)
	owners.ForgetSession(dnsSessionB)
	assert.False(t, owners.InConflict(dnsSessionB), "a stopped session is in no conflict")
	owner, held := owners.HostDNSOwner()
	assert.True(t, held, "forgetting a session must not free what it holds")
	assert.Equal(t, dnsSessionB, owner)
}

func TestDNSOwners_SharedDomainWarnsBothSessionsOnce(t *testing.T) {
	owners := NewDNSOwners()

	warningsOf := func(log *[][]string) func(dns.HostDNSWarning) {
		return func(w dns.HostDNSWarning) {
			assert.Equal(t, dns.HostDNSDomainShared, w.Kind)
			*log = append(*log, w.Domains)
		}
	}
	var warnedA, warnedB [][]string
	sessionA := owners.Session(dnsSessionA, nil, warningsOf(&warnedA))
	sessionB := owners.Session(dnsSessionB, nil, warningsOf(&warnedB))

	sessionA.ServeDomains([]string{"netbird.selfhosted", "a.test"})
	sessionB.ServeDomains([]string{"b.test"})
	assert.Empty(t, warnedA, "different domains are no conflict")
	assert.Empty(t, warnedB, "different domains are no conflict")
	assert.False(t, owners.InConflict(dnsSessionB), "different domains are no conflict")

	sessionB.ServeDomains([]string{"b.test", "netbird.selfhosted"})
	assert.Equal(t, [][]string{{"netbird.selfhosted"}}, warnedA, "the session that had the domain first is warned too")
	assert.Equal(t, [][]string{{"netbird.selfhosted"}}, warnedB, "the session that came second is warned")
	assert.True(t, owners.InConflict(dnsSessionA), "both sessions are in conflict")
	assert.True(t, owners.InConflict(dnsSessionB), "both sessions are in conflict")

	sessionA.ServeDomains([]string{"netbird.selfhosted", "a.test"})
	sessionB.ServeDomains([]string{"b.test", "netbird.selfhosted"})
	assert.Len(t, warnedA, 1, "an unchanged state must not warn again")
	assert.Len(t, warnedB, 1, "an unchanged state must not warn again")

	sessionB.ServeDomains([]string{"b.test"})
	assert.False(t, owners.InConflict(dnsSessionA), "the domain is no longer shared")
	assert.False(t, owners.InConflict(dnsSessionB), "the domain is no longer shared")

	sessionB.ServeDomains([]string{"netbird.selfhosted"})
	assert.Len(t, warnedB, 2, "sharing the domain again is new")

	owners.ForgetSession(dnsSessionB)
	assert.False(t, owners.InConflict(dnsSessionA), "a stopped session shares nothing")
}
