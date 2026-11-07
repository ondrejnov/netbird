package dns_test

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/dns"
	"github.com/netbirdio/netbird/client/internal/hostcoord"
)

var (
	nrptWork = hostcoord.SessionKey{Profile: "work", Username: "alice"}
	nrptHome = hostcoord.SessionKey{Profile: "home", Username: "alice"}
	nrptIP   = netip.MustParseAddr("192.0.2.53")
)

type warningLog struct {
	warnings []dns.HostDNSWarning
}

func (l *warningLog) record(w dns.HostDNSWarning) { l.warnings = append(l.warnings, w) }

func (l *warningLog) kinds() []dns.HostDNSWarningKind {
	var kinds []dns.HostDNSWarningKind
	for _, w := range l.warnings {
		kinds = append(kinds, w.Kind)
	}
	return kinds
}

func domainConfig(domains ...string) dns.HostDNSConfig {
	config := dns.HostDNSConfig{ServerIP: nrptIP}
	for _, d := range domains {
		config.Domains = append(config.Domains, dns.DomainConfig{Domain: d, MatchOnly: true})
	}
	return config
}

func appliedDomains(config dns.HostDNSConfig) []string {
	var domains []string
	for _, d := range config.Domains {
		domains = append(domains, d.Domain)
	}
	return domains
}

func newNRPTPair(t *testing.T) (*hostcoord.DNSOwners, *dns.TestNRPTSession, *dns.TestNRPTSession, *warningLog) {
	t.Helper()
	owners := hostcoord.NewDNSOwners()
	var workLog, homeLog warningLog
	work := dns.NewTestNRPTSession(owners.Session(nrptWork, nil, workLog.record))
	home := dns.NewTestNRPTSession(owners.Session(nrptHome, nil, homeLog.record))
	t.Cleanup(func() {
		assert.Empty(t, workLog.warnings, "the first session owns everything it asked for and is never warned")
	})
	return owners, work, home, &homeLog
}

// The NRPT answers a namespace from one rule only, so a domain both networks serve must be written
// by one session. The other one is told it does not resolve those names.
func TestNRPTSessions_DomainHasOneOwner(t *testing.T) {
	owners, work, home, homeLog := newNRPTPair(t)

	require.NoError(t, work.Apply(domainConfig("work.test", "Shared.Test.")))
	require.NoError(t, home.Apply(domainConfig("shared.test", "home.test")))
	assert.Equal(t, []string{"home.test"}, appliedDomains(home.Applied()), "the second session leaves the domain it does not own out of its rules")
	assert.Equal(t, []dns.HostDNSWarningKind{dns.HostDNSDomainHeld}, homeLog.kinds(), "the session that lost the domain is warned")
	assert.Equal(t, []string{"shared.test"}, homeLog.warnings[0].Domains)
	assert.True(t, owners.InConflict(nrptHome), "the status shows the conflict")
	assert.True(t, home.Pending(), "the DNS server tries again with the next update")

	require.NoError(t, home.Apply(domainConfig("shared.test", "home.test")))
	assert.Len(t, homeLog.warnings, 1, "an unchanged state must not warn again")
	assert.False(t, home.Retry(), "the owner still holds the domain")

	// The owner's network drops the domain, and its rules no longer carry it.
	require.NoError(t, work.Apply(domainConfig("work.test")))
	assert.True(t, home.Retry(), "the free domain can be claimed now")
	require.NoError(t, home.Apply(domainConfig("shared.test", "home.test")))
	assert.Equal(t, []string{"shared.test", "home.test"}, appliedDomains(home.Applied()), "the rules carry the domain now")
	assert.False(t, home.Pending(), "nothing is refused anymore")
	assert.False(t, owners.InConflict(nrptHome))

	require.NoError(t, home.Restore())
	owner, held := owners.DomainOwner("shared.test")
	assert.False(t, held, "a stopped session leaves its domains free, owner %v", owner)
}

func TestNRPTSessions_CatchAllHasOneOwner(t *testing.T) {
	owners, work, home, homeLog := newNRPTPair(t)

	routeAll := domainConfig("work.test")
	routeAll.RouteAll = true
	require.NoError(t, work.Apply(routeAll))
	assert.True(t, work.Applied().RouteAll, "the first session routes all DNS")

	homeAll := domainConfig("home.test", ".")
	homeAll.RouteAll = true
	require.NoError(t, home.Apply(homeAll))
	assert.False(t, home.Applied().RouteAll, "the second session must not write a second catch-all")
	assert.Equal(t, []string{"home.test"}, appliedDomains(home.Applied()), "the root domain is the catch-all too")
	assert.Equal(t, []dns.HostDNSWarningKind{dns.HostDNSCatchAllHeld}, homeLog.kinds())
	assert.True(t, owners.InConflict(nrptHome), "the status shows the conflict")
	assert.False(t, home.Retry(), "the catch-all is still held")

	require.NoError(t, work.Apply(domainConfig("work.test")))
	assert.True(t, home.Retry(), "the catch-all is free once the owner's rules dropped it")
	require.NoError(t, home.Apply(homeAll))
	assert.True(t, home.Applied().RouteAll)
	assert.False(t, home.Pending())
	assert.False(t, owners.InConflict(nrptHome))

	require.NoError(t, home.Apply(domainConfig("home.test")))
	owner, held := owners.CatchAllOwner()
	assert.False(t, held, "a session that stopped routing all DNS gives the catch-all up, owner %v", owner)
}

// A failed apply may leave the previous rules in place, so the domains they carry stay claimed.
func TestNRPTSessions_FailedApplyKeepsTheClaims(t *testing.T) {
	owners, work, home, _ := newNRPTPair(t)

	require.NoError(t, work.Apply(domainConfig("shared.test")))
	work.FailRules(true)
	require.Error(t, work.Apply(domainConfig()))
	owner, held := owners.DomainOwner("shared.test")
	assert.True(t, held && owner == nrptWork, "the rule may still be there, so the domain stays with its owner")
	assert.True(t, work.Pending(), "the failed configuration is tried again")

	require.NoError(t, home.Apply(domainConfig("shared.test")))
	assert.Empty(t, home.Applied().Domains, "the other session still cannot write the domain")

	work.FailRules(false)
	require.NoError(t, work.Apply(domainConfig()))
	_, held = owners.DomainOwner("shared.test")
	assert.False(t, held, "the domain is free once the rules are gone")
	assert.False(t, work.Pending())
}

// Each slot writes keys of its own name, and the stop of one session removes only its keys. The
// test writes match rules for TEST-NET names to the host's local policy store.
func TestNRPTSessions_SlotKeysOnTheHost(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping registry integration test in short mode")
	}
	owners := hostcoord.NewDNSOwners()
	work := dns.NewTestRegistrySession(t, "{7D4A2F10-0000-4000-8000-0000000000A0}", 0, owners.Session(nrptWork, nil, nil))
	home := dns.NewTestRegistrySession(t, "{7D4A2F10-0000-4000-8000-0000000000A1}", 71, owners.Session(nrptHome, nil, nil))

	require.NoError(t, work.Apply(domainConfig("w4-shared.test", "w4-work.test")))
	require.NoError(t, home.Apply(domainConfig("w4-shared.test", "w4-home.test")))
	assert.ElementsMatch(t, []string{".w4-shared.test", ".w4-work.test"}, dns.SlotRuleDomains(t, 0), "slot 0 keeps today's key names")
	assert.Equal(t, []string{".w4-home.test"}, dns.SlotRuleDomains(t, 71), "slot 71 writes its own keys, without the domain it does not own")

	require.NoError(t, work.Restore())
	assert.Empty(t, dns.SlotRuleDomains(t, 0), "the stop of slot 0 removes its rules")
	assert.Equal(t, []string{".w4-home.test"}, dns.SlotRuleDomains(t, 71), "and leaves those of slot 71")

	require.True(t, home.Retry(), "the domain is free")
	require.NoError(t, home.Apply(domainConfig("w4-shared.test", "w4-home.test")))
	assert.ElementsMatch(t, []string{".w4-shared.test", ".w4-home.test"}, dns.SlotRuleDomains(t, 71))

	require.NoError(t, work.Apply(domainConfig("w4-work.test")))
	require.NoError(t, home.Restore())
	assert.Empty(t, dns.SlotRuleDomains(t, 71), "the stop of slot 71 removes its rules")
	assert.Equal(t, []string{".w4-work.test"}, dns.SlotRuleDomains(t, 0), "and leaves those of slot 0")
}

// After a crash the state file of each session names its slot, and its cleanup removes only the
// keys of that slot.
func TestNRPTSessions_CrashCleanupOfOneSlot(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping registry integration test in short mode")
	}
	owners := hostcoord.NewDNSOwners()
	workGUID := "{7D4A2F10-0000-4000-8000-0000000000A2}"
	homeGUID := "{7D4A2F10-0000-4000-8000-0000000000A3}"
	work := dns.NewTestRegistrySession(t, workGUID, 0, owners.Session(nrptWork, nil, nil))
	home := dns.NewTestRegistrySession(t, homeGUID, 72, owners.Session(nrptHome, nil, nil))
	require.NoError(t, work.Apply(domainConfig("w4-work.test")))
	require.NoError(t, home.Apply(domainConfig("w4-home.test")))

	require.NoError(t, (&dns.ShutdownState{Guid: homeGUID, Slot: 72}).Cleanup())
	assert.Empty(t, dns.SlotRuleDomains(t, 72), "the cleanup removes the keys of its slot")
	assert.Equal(t, []string{".w4-work.test"}, dns.SlotRuleDomains(t, 0), "and leaves those of slot 0")

	require.NoError(t, (&dns.ShutdownState{Guid: workGUID}).Cleanup())
	assert.Empty(t, dns.SlotRuleDomains(t, 0), "state from before slots cleans slot 0")
}
