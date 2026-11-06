//go:build linux && !android && privileged

package dns_test

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sync"
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/netbirdio/netbird/client/internal/dns"
	"github.com/netbirdio/netbird/client/internal/hostcoord"
)

const (
	dbusPropertiesInterface = "org.freedesktop.DBus.Properties"
	resolvedDest            = "org.freedesktop.resolve1"
	resolvedPath            = dbus.ObjectPath("/org/freedesktop/resolve1")
	resolvedManagerIface    = "org.freedesktop.resolve1.Manager"
	resolvedLinkIface       = "org.freedesktop.resolve1.Link"
	nmDest                  = "org.freedesktop.NetworkManager"
	nmPath                  = dbus.ObjectPath("/org/freedesktop/NetworkManager")
	nmDeviceIface           = "org.freedesktop.NetworkManager.Device"

	busConfig = `<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <listen>unix:path=%s</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
</busconfig>`
)

// startPrivateBus runs a dbus-daemon that only this test knows about and makes the
// client code use it as the system bus. The services on it stand in for resolved and
// NetworkManager, which the container does not have; the client code talking to them
// is the production code, over the real D-Bus protocol.
func startPrivateBus(t *testing.T) *dbus.Conn {
	t.Helper()

	dir, err := os.MkdirTemp("", "nbdbus")
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, os.RemoveAll(dir)) })

	configPath := filepath.Join(dir, "bus.conf")
	socketPath := filepath.Join(dir, "bus")
	require.NoError(t, os.WriteFile(configPath, []byte(fmt.Sprintf(busConfig, socketPath)), 0o600))

	daemon := exec.Command("dbus-daemon", "--nofork", "--print-address", "--config-file="+configPath)
	stdout, err := daemon.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, daemon.Start(), "the privileged container installs dbus")
	t.Cleanup(func() {
		assert.NoError(t, daemon.Process.Kill())
		_ = daemon.Wait()
	})

	address, err := bufio.NewReader(stdout).ReadString('\n')
	require.NoError(t, err)
	address = address[:len(address)-1]
	t.Setenv("DBUS_SYSTEM_BUS_ADDRESS", address)

	conn, err := dbus.Connect(address)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, conn.Close()) })
	return conn
}

func requireName(t *testing.T, conn *dbus.Conn, name string) {
	t.Helper()
	reply, err := conn.RequestName(name, dbus.NameFlagDoNotQueue)
	require.NoError(t, err)
	require.Equal(t, dbus.RequestNameReplyPrimaryOwner, reply, "the private bus must grant the name")
}

// properties answers org.freedesktop.DBus.Properties.Get from a function.
type properties func(iface, name string) (any, bool)

// Get implements the D-Bus method.
func (p properties) Get(iface, name string) (dbus.Variant, *dbus.Error) {
	value, ok := p(iface, name)
	if !ok {
		return dbus.Variant{}, dbus.MakeFailedError(fmt.Errorf("unknown property %s.%s", iface, name))
	}
	return dbus.MakeVariant(value), nil
}

// resolvedDNSEntry and resolvedDomainEntry have the wire layout of the resolve1 API:
// a(iay) for DNS, a(sb) for Domains.
type resolvedDNSEntry struct {
	Family  int32
	Address []byte
}

type resolvedDomainEntry struct {
	Domain    string
	MatchOnly bool
}

// fakeLinkState is the per-link configuration of the fake resolved.
type fakeLinkState struct {
	DNS          []netip.Addr
	Domains      []resolvedDomainEntry
	DefaultRoute bool
	Reverts      int
	// DomainCalls counts the SetDomains calls that reached the link, failed ones too.
	DomainCalls int
}

// fakeResolved keeps the per-link state resolved keeps. A Revert clears the state of
// its own link, which is the behaviour F0 observed on systemd 257.
type fakeResolved struct {
	conn  *dbus.Conn
	mu    sync.Mutex
	links map[int32]*fakeLinkState
	// failDomains holds the links whose SetDomains fails, as it does when resolved
	// times out.
	failDomains map[int32]bool
}

// fakeResolvedManager is the Manager interface.
type fakeResolvedManager struct{ f *fakeResolved }

// GetLink implements the D-Bus method.
func (m fakeResolvedManager) GetLink(ifIndex int32) (dbus.ObjectPath, *dbus.Error) {
	path := dbus.ObjectPath(fmt.Sprintf("%s/link/_%d", resolvedPath, ifIndex))
	m.f.mu.Lock()
	defer m.f.mu.Unlock()
	if _, ok := m.f.links[ifIndex]; ok {
		return path, nil
	}
	m.f.links[ifIndex] = &fakeLinkState{}
	if err := m.f.exportLink(ifIndex, path); err != nil {
		return "", dbus.MakeFailedError(err)
	}
	return path, nil
}

// FlushCaches implements the D-Bus method.
func (m fakeResolvedManager) FlushCaches() *dbus.Error { return nil }

// fakeResolvedLink is the Link interface of one link.
type fakeResolvedLink struct {
	f     *fakeResolved
	index int32
}

func (l fakeResolvedLink) update(change func(*fakeLinkState)) *dbus.Error {
	l.f.mu.Lock()
	defer l.f.mu.Unlock()
	change(l.f.links[l.index])
	return nil
}

// SetDNS implements the D-Bus method.
func (l fakeResolvedLink) SetDNS(entries []resolvedDNSEntry) *dbus.Error {
	return l.update(func(state *fakeLinkState) {
		state.DNS = nil
		for _, entry := range entries {
			addr, _ := netip.AddrFromSlice(entry.Address)
			state.DNS = append(state.DNS, addr)
		}
	})
}

// SetDomains implements the D-Bus method.
func (l fakeResolvedLink) SetDomains(domains []resolvedDomainEntry) *dbus.Error {
	l.f.mu.Lock()
	defer l.f.mu.Unlock()
	state := l.f.links[l.index]
	state.DomainCalls++
	if l.f.failDomains[l.index] {
		return dbus.MakeFailedError(fmt.Errorf("set domains on link %d refused by the test", l.index))
	}
	state.Domains = domains
	return nil
}

// SetDefaultRoute implements the D-Bus method.
func (l fakeResolvedLink) SetDefaultRoute(enable bool) *dbus.Error {
	return l.update(func(state *fakeLinkState) { state.DefaultRoute = enable })
}

// SetDNSSEC implements the D-Bus method.
func (l fakeResolvedLink) SetDNSSEC(string) *dbus.Error { return nil }

// SetDNSOverTLS implements the D-Bus method.
func (l fakeResolvedLink) SetDNSOverTLS(string) *dbus.Error { return nil }

// Revert implements the D-Bus method.
func (l fakeResolvedLink) Revert() *dbus.Error {
	return l.update(func(state *fakeLinkState) {
		*state = fakeLinkState{Reverts: state.Reverts + 1}
	})
}

func (f *fakeResolved) exportLink(index int32, path dbus.ObjectPath) error {
	if err := f.conn.Export(fakeResolvedLink{f: f, index: index}, path, resolvedLinkIface); err != nil {
		return err
	}
	return f.conn.Export(properties(func(_, name string) (any, bool) {
		f.mu.Lock()
		defer f.mu.Unlock()
		state := f.links[index]
		switch name {
		case "DefaultRoute":
			return state.DefaultRoute, true
		case "DNS":
			entries := make([]resolvedDNSEntry, 0, len(state.DNS))
			for _, addr := range state.DNS {
				family := int32(unix.AF_INET)
				if addr.Is6() {
					family = unix.AF_INET6
				}
				entries = append(entries, resolvedDNSEntry{Family: family, Address: addr.AsSlice()})
			}
			return entries, true
		}
		return nil, false
	}), path, dbusPropertiesInterface)
}

func startFakeResolved(t *testing.T) *fakeResolved {
	t.Helper()
	conn := startPrivateBus(t)
	fake := &fakeResolved{conn: conn, links: make(map[int32]*fakeLinkState), failDomains: make(map[int32]bool)}
	require.NoError(t, conn.Export(fakeResolvedManager{f: fake}, resolvedPath, resolvedManagerIface))
	requireName(t, conn, resolvedDest)
	return fake
}

// seed gives a link the state the host's network configuration would give it.
func (f *fakeResolved) seed(t *testing.T, ifIndex int, state fakeLinkState) {
	t.Helper()
	_, dbusErr := fakeResolvedManager{f: f}.GetLink(int32(ifIndex))
	require.Nil(t, dbusErr)
	f.mu.Lock()
	defer f.mu.Unlock()
	*f.links[int32(ifIndex)] = state
}

// setFailDomains makes SetDomains on a link fail, or work again.
func (f *fakeResolved) setFailDomains(ifIndex int, fail bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failDomains[int32(ifIndex)] = fail
}

func (f *fakeResolved) link(ifIndex int) fakeLinkState {
	f.mu.Lock()
	defer f.mu.Unlock()
	state, ok := f.links[int32(ifIndex)]
	if !ok {
		return fakeLinkState{}
	}
	snapshot := *state
	snapshot.DNS = slices.Clone(state.DNS)
	snapshot.Domains = slices.Clone(state.Domains)
	return snapshot
}

func addLink(t *testing.T, name string) int {
	t.Helper()
	link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}
	require.NoError(t, netlink.LinkAdd(link))
	t.Cleanup(func() { assert.NoError(t, netlink.LinkDel(link)) })
	require.NoError(t, netlink.LinkSetUp(link))
	return link.Attrs().Index
}

func hasCatchAll(state fakeLinkState) bool {
	return state.DefaultRoute && slices.Contains(state.Domains, resolvedDomainEntry{Domain: ".", MatchOnly: true})
}

const (
	resolvedPhysLink = "nbdnsphys"
	resolvedLinkA    = "nbdnsa"
	resolvedLinkB    = "nbdnsb"
	resolvedLinkC    = "nbdnsc"
)

var (
	sessionKeyC = hostcoord.SessionKey{Profile: "c", Username: "alice"}

	physDNS       = netip.MustParseAddr("192.0.2.53")
	allLinks      = []string{resolvedLinkA, resolvedLinkB, resolvedLinkC}
	allLinksFunc  = func() []string { return allLinks }
	physLinkState = fakeLinkState{DNS: []netip.Addr{physDNS}, DefaultRoute: true}
)

type resolvedFixture struct {
	fake           *fakeResolved
	owners         *hostcoord.DNSOwners
	phys, ifA, ifB int
	warningsB      *warningLog
	serverA        *dns.DefaultServer
	serverB        *dns.DefaultServer
	stateB         fakeLinkState
	stateA         fakeLinkState
	statePhys      fakeLinkState
}

// startTwoResolvedSessions brings up session A, then session B. Both ask for the
// catch-all, and A's link carries NetBird DNS with a default route by the time B
// captures the original nameservers.
func startTwoResolvedSessions(t *testing.T) *resolvedFixture {
	t.Helper()
	fixture := &resolvedFixture{fake: startFakeResolved(t), owners: hostcoord.NewDNSOwners(), warningsB: &warningLog{}}
	fixture.phys = addLink(t, resolvedPhysLink)
	fixture.ifA = addLink(t, resolvedLinkA)
	fixture.ifB = addLink(t, resolvedLinkB)
	fixture.fake.seed(t, fixture.phys, physLinkState)

	fixture.serverA = dns.NewTestSessionServer(t, resolvedLinkA, dnsIPA, dns.TestBackendSystemd, fixture.owners.Session(sessionKeyA, allLinksFunc, nil))
	require.NoError(t, fixture.serverA.UpdateDNSServer(1, dnsConfig("a.test", true)))

	fixture.serverB = dns.NewTestSessionServer(t, resolvedLinkB, dnsIPB, dns.TestBackendSystemd, fixture.owners.Session(sessionKeyB, allLinksFunc, fixture.warningsB.add))
	require.NoError(t, fixture.serverB.UpdateDNSServer(1, dnsConfig("b.test", true)))

	fixture.stateA = fixture.fake.link(fixture.ifA)
	fixture.stateB = fixture.fake.link(fixture.ifB)
	fixture.statePhys = fixture.fake.link(fixture.phys)
	return fixture
}

func TestResolved_TwoSessionsShareTheHost(t *testing.T) {
	fixture := startTwoResolvedSessions(t)

	stateA := fixture.stateA
	assert.Equal(t, []netip.Addr{dnsIPA}, stateA.DNS, "session A must program its own DNS on its link")
	assert.True(t, hasCatchAll(stateA), "the first session must own the catch-all: %+v", stateA)

	stateB := fixture.stateB
	assert.Equal(t, []netip.Addr{dnsIPB}, stateB.DNS, "session B must program its own DNS on its link")
	assert.False(t, hasCatchAll(stateB), "the second session must not get a catch-all: %+v", stateB)
	assert.False(t, stateB.DefaultRoute, "the second session must not be a default route")
	assert.Contains(t, stateB.Domains, resolvedDomainEntry{Domain: "b.test.", MatchOnly: true}, "the second session must keep its own domains")
	assert.Equal(t, []dns.HostDNSWarningKind{dns.HostDNSCatchAllHeld}, fixture.warningsB.kinds(), "the second session must be warned")

	owner, held := fixture.owners.CatchAllOwner()
	assert.True(t, held, "the catch-all must have an owner")
	assert.Equal(t, sessionKeyA, owner, "the first session must own the catch-all")
}

func TestResolved_CaptureSkipsOtherSessions(t *testing.T) {
	fixture := startTwoResolvedSessions(t)

	assert.Equal(t, []netip.Addr{physDNS}, dns.OriginalNameservers(fixture.serverA), "session A must capture only the physical nameserver")
	assert.Equal(t, []netip.Addr{physDNS}, dns.OriginalNameservers(fixture.serverB), "session B must not capture the NetBird DNS of session A")

	// A third session sees two NetBird links, and one of them is a default route.
	addLink(t, resolvedLinkC)
	serverC := dns.NewTestSessionServer(t, resolvedLinkC, netip.MustParseAddr("100.66.0.53"), dns.TestBackendSystemd, fixture.owners.Session(sessionKeyC, allLinksFunc, nil))
	assert.Equal(t, []netip.Addr{physDNS}, dns.OriginalNameservers(serverC), "session C must capture only the physical nameserver")
}

func TestResolved_StopOfOwnerKeepsOtherLink(t *testing.T) {
	fixture := startTwoResolvedSessions(t)

	fixture.serverA.Stop()

	assert.Equal(t, 1, fixture.fake.link(fixture.ifA).Reverts, "the owner must revert its own link")
	assert.Empty(t, fixture.fake.link(fixture.ifA).DNS, "the owner's DNS must be gone")
	assert.Equal(t, fixture.stateB, fixture.fake.link(fixture.ifB), "stopping session A must not change the link of session B")
	assert.Equal(t, fixture.statePhys, fixture.fake.link(fixture.phys), "stopping session A must not change the physical link")

	_, held := fixture.owners.CatchAllOwner()
	assert.False(t, held, "the owner's stop must release the catch-all")
	assert.False(t, hasCatchAll(fixture.fake.link(fixture.ifB)), "the catch-all must not move by itself")

	// The free catch-all goes to whoever claims next, here with B's next update.
	require.NoError(t, fixture.serverB.UpdateDNSServer(2, dnsConfig("b2.test", true)))
	assert.True(t, hasCatchAll(fixture.fake.link(fixture.ifB)), "the next update must take the free catch-all")
	owner, held := fixture.owners.CatchAllOwner()
	assert.True(t, held, "the catch-all must have a new owner")
	assert.Equal(t, sessionKeyB, owner, "session B must own the catch-all")
}

// A session keeps getting the same network map after the owner left. Nothing changes in
// its configuration, and it must still take the free catch-all.
func TestResolved_ReleasedCatchAllTakenWithSameConfig(t *testing.T) {
	fixture := startTwoResolvedSessions(t)

	fixture.serverA.Stop()
	require.NoError(t, fixture.serverB.UpdateDNSServer(2, dnsConfig("b.test", true)))

	assert.True(t, hasCatchAll(fixture.fake.link(fixture.ifB)), "an update with the same configuration must take the free catch-all: %+v", fixture.fake.link(fixture.ifB))
	owner, held := fixture.owners.CatchAllOwner()
	assert.True(t, held, "the catch-all must have a new owner")
	assert.Equal(t, sessionKeyB, owner, "session B must own the catch-all")
	assert.Len(t, fixture.warningsB.kinds(), 1, "taking the catch-all must not warn again")
}

// Section 6: the same domain on two links works as 5.3 describes, and both sessions hear of it. A
// session that stops serving it, or stops altogether, has no conflict left.
func TestResolved_SharedDomainWarnsBothSessions(t *testing.T) {
	fake := startFakeResolved(t)
	owners := hostcoord.NewDNSOwners()
	addLink(t, resolvedLinkA)
	ifB := addLink(t, resolvedLinkB)
	warningsA, warningsB := &warningLog{}, &warningLog{}

	serverA := dns.NewTestSessionServer(t, resolvedLinkA, dnsIPA, dns.TestBackendSystemd, owners.Session(sessionKeyA, allLinksFunc, warningsA.add))
	require.NoError(t, serverA.UpdateDNSServer(1, dnsConfig("shared.test", false)))
	serverB := dns.NewTestSessionServer(t, resolvedLinkB, dnsIPB, dns.TestBackendSystemd, owners.Session(sessionKeyB, allLinksFunc, warningsB.add))
	require.NoError(t, serverB.UpdateDNSServer(1, dnsConfig("own.test", false)))
	assert.Empty(t, warningsA.kinds(), "different domains are no conflict")
	assert.Empty(t, warningsB.kinds(), "different domains are no conflict")

	require.NoError(t, serverB.UpdateDNSServer(2, dnsConfig("shared.test", false)))

	shared := []dns.HostDNSWarningKind{dns.HostDNSDomainShared}
	assert.Equal(t, shared, warningsA.kinds(), "the session that had the domain first must be warned")
	assert.Equal(t, shared, warningsB.kinds(), "the session that came second must be warned")
	assert.Contains(t, fake.link(ifB).Domains, resolvedDomainEntry{Domain: "shared.test.", MatchOnly: true}, "the domain must stay on the link: resolved asks both")
	assert.True(t, owners.InConflict(sessionKeyA), "both sessions are in conflict")
	assert.True(t, owners.InConflict(sessionKeyB), "both sessions are in conflict")

	require.NoError(t, serverB.UpdateDNSServer(3, dnsConfig("own.test", false)))
	assert.False(t, owners.InConflict(sessionKeyA), "the domain is no longer shared")

	require.NoError(t, serverB.UpdateDNSServer(4, dnsConfig("shared.test", false)))
	assert.True(t, owners.InConflict(sessionKeyA), "the domain is shared again")
	serverB.Stop()
	assert.False(t, owners.InConflict(sessionKeyA), "the stop of the other session ends it")
}

// While the owner stays, retrying the claim must not reprogram the link: on
// NetworkManager the same path would reapply the connection with every network map.
func TestResolved_RefusedClaimDoesNotReprogramLink(t *testing.T) {
	fixture := startTwoResolvedSessions(t)

	require.NoError(t, fixture.serverB.UpdateDNSServer(2, dnsConfig("b.test", true)))
	require.NoError(t, fixture.serverB.UpdateDNSServer(3, dnsConfig("b.test", true)))

	assert.Equal(t, fixture.stateB, fixture.fake.link(fixture.ifB), "a refused retry must leave the link alone")
	assert.Len(t, fixture.warningsB.kinds(), 1, "the warning must be given once per state")
	owner, held := fixture.owners.CatchAllOwner()
	assert.True(t, held, "the owner must keep the catch-all")
	assert.Equal(t, sessionKeyA, owner, "a refused retry must not change the owner")
}

// A configuration limited by a refused claim does not count as applied, so going back
// to the configuration applied before it still programs the link.
func TestResolved_RefusedSessionFollowsConfigChanges(t *testing.T) {
	fixture := startTwoResolvedSessions(t)
	domainOf := func(zone string) resolvedDomainEntry { return resolvedDomainEntry{Domain: zone + ".", MatchOnly: true} }

	require.NoError(t, fixture.serverB.UpdateDNSServer(2, dnsConfig("b2.test", false)))
	assert.Contains(t, fixture.fake.link(fixture.ifB).Domains, domainOf("b2.test"), "a configuration without the catch-all must reach the link")

	require.NoError(t, fixture.serverB.UpdateDNSServer(3, dnsConfig("b3.test", true)))
	assert.Contains(t, fixture.fake.link(fixture.ifB).Domains, domainOf("b3.test"), "a refused configuration must reach the link without the catch-all")

	require.NoError(t, fixture.serverB.UpdateDNSServer(4, dnsConfig("b2.test", false)))
	state := fixture.fake.link(fixture.ifB)
	assert.Contains(t, state.Domains, domainOf("b2.test"), "going back to the earlier configuration must reach the link")
	assert.False(t, hasCatchAll(state), "the session must still not get the catch-all: %+v", state)
}

// SetDomains can fail after SetDefaultRoute worked. The link then still routes "." to
// this session, so the claim must stay until the domains are really gone.
func TestResolved_FailedDomainsKeepCatchAllClaim(t *testing.T) {
	fixture := startTwoResolvedSessions(t)
	rootDomain := resolvedDomainEntry{Domain: ".", MatchOnly: true}

	fixture.fake.setFailDomains(fixture.ifA, true)
	require.NoError(t, fixture.serverA.UpdateDNSServer(2, dnsConfig("a.test", false)))
	require.Contains(t, fixture.fake.link(fixture.ifA).Domains, rootDomain, "the failed call must leave the root domain on the link")

	owner, held := fixture.owners.CatchAllOwner()
	assert.True(t, held, "the claim must stay while the link carries the root domain")
	assert.Equal(t, sessionKeyA, owner, "the claim must stay with the session whose link carries the root domain")

	require.NoError(t, fixture.serverB.UpdateDNSServer(2, dnsConfig("b.test", true)))
	assert.NotContains(t, fixture.fake.link(fixture.ifB).Domains, rootDomain, "only one link may carry the root domain")

	// The same network map comes again once resolved answers: the drop is retried.
	fixture.fake.setFailDomains(fixture.ifA, false)
	require.NoError(t, fixture.serverA.UpdateDNSServer(3, dnsConfig("a.test", false)))
	assert.NotContains(t, fixture.fake.link(fixture.ifA).Domains, rootDomain, "the retry must remove the root domain")
	_, held = fixture.owners.CatchAllOwner()
	assert.False(t, held, "the claim must go once the root domain is gone")

	require.NoError(t, fixture.serverB.UpdateDNSServer(3, dnsConfig("b.test", true)))
	assert.True(t, hasCatchAll(fixture.fake.link(fixture.ifB)), "the other session must then take the catch-all")
	assert.NotContains(t, fixture.fake.link(fixture.ifA).Domains, rootDomain, "only one link may carry the root domain")
}

// Without a coordinator a failed SetDomains stays a logged error and nothing is retried.
func TestResolved_NoCoordinatorFailedDomainsKeepTodaysBehaviour(t *testing.T) {
	fake := startFakeResolved(t)
	ifA := addLink(t, resolvedLinkA)
	fake.setFailDomains(ifA, true)

	server := dns.NewTestSessionServer(t, resolvedLinkA, dnsIPA, dns.TestBackendSystemd, nil)
	require.NoError(t, server.UpdateDNSServer(1, dnsConfig("a.test", false)))
	require.Equal(t, 1, fake.link(ifA).DomainCalls, "the first update must reach the link")

	require.NoError(t, server.UpdateDNSServer(2, dnsConfig("a.test", false)))
	assert.Equal(t, 1, fake.link(ifA).DomainCalls, "without a coordinator the same configuration must not be applied again")
}

func TestResolved_StopOfNonOwnerKeepsOtherLink(t *testing.T) {
	fixture := startTwoResolvedSessions(t)

	fixture.serverB.Stop()

	assert.Equal(t, 1, fixture.fake.link(fixture.ifB).Reverts, "session B must revert its own link")
	assert.Equal(t, fixture.stateA, fixture.fake.link(fixture.ifA), "stopping session B must not change the link of session A")
	assert.Equal(t, fixture.statePhys, fixture.fake.link(fixture.phys), "stopping session B must not change the physical link")

	owner, held := fixture.owners.CatchAllOwner()
	assert.True(t, held, "a stop of another session must not release the catch-all")
	assert.Equal(t, sessionKeyA, owner, "a stop of another session must not change the owner")
}

func TestResolved_OwnerDroppingRouteAllReleases(t *testing.T) {
	fixture := startTwoResolvedSessions(t)

	require.NoError(t, fixture.serverA.UpdateDNSServer(2, dnsConfig("a.test", false)))

	assert.False(t, hasCatchAll(fixture.fake.link(fixture.ifA)), "the update must remove the catch-all from the link")
	_, held := fixture.owners.CatchAllOwner()
	assert.False(t, held, "a session no longer asking for the catch-all must not hold it")
}

// Pins the behaviour without a coordinator: the capture takes every default-route link
// and every session gets the catch-all. It also shows the fake can tell the two apart.
func TestResolved_NoCoordinatorKeepsTodaysBehaviour(t *testing.T) {
	fake := startFakeResolved(t)
	phys := addLink(t, resolvedPhysLink)
	ifA := addLink(t, resolvedLinkA)
	ifB := addLink(t, resolvedLinkB)
	fake.seed(t, phys, physLinkState)

	serverA := dns.NewTestSessionServer(t, resolvedLinkA, dnsIPA, dns.TestBackendSystemd, nil)
	require.NoError(t, serverA.UpdateDNSServer(1, dnsConfig("a.test", true)))
	serverB := dns.NewTestSessionServer(t, resolvedLinkB, dnsIPB, dns.TestBackendSystemd, nil)
	require.NoError(t, serverB.UpdateDNSServer(1, dnsConfig("b.test", true)))

	assert.True(t, hasCatchAll(fake.link(ifA)), "session A must get the catch-all")
	assert.True(t, hasCatchAll(fake.link(ifB)), "without a coordinator session B must get the catch-all too")
	assert.ElementsMatch(t, []netip.Addr{physDNS, dnsIPA}, dns.OriginalNameservers(serverB), "without a coordinator the capture must take every default-route link")
}

// fakeNMDevice is the state of one NetworkManager device.
type fakeNMDevice struct {
	name       string
	dnsServers []netip.Addr
	domains    []string
	priority   int32
	deleted    bool
}

// fakeNM keeps the per-device state NetworkManager keeps.
type fakeNM struct {
	conn    *dbus.Conn
	mu      sync.Mutex
	devices map[dbus.ObjectPath]*fakeNMDevice
}

// fakeNMManager is the NetworkManager interface.
type fakeNMManager struct{ f *fakeNM }

// GetDeviceByIpIface implements the D-Bus method.
func (m fakeNMManager) GetDeviceByIpIface(name string) (dbus.ObjectPath, *dbus.Error) {
	m.f.mu.Lock()
	defer m.f.mu.Unlock()
	for path, device := range m.f.devices {
		if device.name == name && !device.deleted {
			return path, nil
		}
	}
	return "", dbus.MakeFailedError(fmt.Errorf("no device %s", name))
}

// GetDevices implements the D-Bus method.
func (m fakeNMManager) GetDevices() ([]dbus.ObjectPath, *dbus.Error) {
	m.f.mu.Lock()
	defer m.f.mu.Unlock()
	paths := make([]dbus.ObjectPath, 0, len(m.f.devices))
	for path, device := range m.f.devices {
		if !device.deleted {
			paths = append(paths, path)
		}
	}
	slices.Sort(paths)
	return paths, nil
}

// fakeNMDeviceObject is the Device interface of one device.
type fakeNMDeviceObject struct {
	f    *fakeNM
	path dbus.ObjectPath
}

// GetAppliedConnection implements the D-Bus method.
func (d fakeNMDeviceObject) GetAppliedConnection(uint32) (map[string]map[string]dbus.Variant, uint64, *dbus.Error) {
	settings := map[string]map[string]dbus.Variant{
		"ipv4": {"method": dbus.MakeVariant("manual")},
		"ipv6": {"method": dbus.MakeVariant("ignore")},
	}
	return settings, 1, nil
}

// Reapply implements the D-Bus method.
func (d fakeNMDeviceObject) Reapply(settings map[string]map[string]dbus.Variant, _ uint64, _ uint32) *dbus.Error {
	d.f.mu.Lock()
	defer d.f.mu.Unlock()
	device := d.f.devices[d.path]
	ipv4 := settings["ipv4"]
	device.dnsServers = nil
	if servers, ok := ipv4["dns"].Value().([]uint32); ok {
		for _, server := range servers {
			var raw [4]byte
			binary.LittleEndian.PutUint32(raw[:], server)
			device.dnsServers = append(device.dnsServers, netip.AddrFrom4(raw))
		}
	}
	device.domains, _ = ipv4["dns-search"].Value().([]string)
	device.priority, _ = ipv4["dns-priority"].Value().(int32)
	return nil
}

// Delete implements the D-Bus method.
func (d fakeNMDeviceObject) Delete() *dbus.Error {
	d.f.mu.Lock()
	defer d.f.mu.Unlock()
	device := d.f.devices[d.path]
	*device = fakeNMDevice{name: device.name, deleted: true}
	return nil
}

func startFakeNM(t *testing.T) *fakeNM {
	t.Helper()
	conn := startPrivateBus(t)
	fake := &fakeNM{conn: conn, devices: make(map[dbus.ObjectPath]*fakeNMDevice)}
	require.NoError(t, conn.Export(fakeNMManager{f: fake}, nmPath, nmDest))
	requireName(t, conn, nmDest)
	return fake
}

func (f *fakeNM) addDevice(t *testing.T, name string, servers ...netip.Addr) dbus.ObjectPath {
	t.Helper()
	path := dbus.ObjectPath(fmt.Sprintf("%s/Devices/%s", nmPath, name))
	configPath := dbus.ObjectPath(fmt.Sprintf("%s/IP4Config/%s", nmPath, name))
	f.devices[path] = &fakeNMDevice{name: name, dnsServers: servers}

	require.NoError(t, f.conn.Export(fakeNMDeviceObject{f: f, path: path}, path, nmDeviceIface))
	require.NoError(t, f.conn.Export(properties(func(_, property string) (any, bool) {
		switch property {
		case "Interface":
			return name, true
		case "Ip4Config":
			return configPath, true
		case "Ip6Config":
			return dbus.ObjectPath("/"), true
		}
		return nil, false
	}), path, dbusPropertiesInterface))
	require.NoError(t, f.conn.Export(properties(func(_, property string) (any, bool) {
		if property != "NameserverData" {
			return nil, false
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		data := make([]map[string]dbus.Variant, 0, len(f.devices[path].dnsServers))
		for _, server := range f.devices[path].dnsServers {
			data = append(data, map[string]dbus.Variant{"address": dbus.MakeVariant(server.String())})
		}
		return data, true
	}), configPath, dbusPropertiesInterface))
	return path
}

func (f *fakeNM) device(path dbus.ObjectPath) fakeNMDevice {
	f.mu.Lock()
	defer f.mu.Unlock()
	return *f.devices[path]
}

func TestNetworkManager_TwoSessionsShareTheHost(t *testing.T) {
	fake := startFakeNM(t)
	phys := fake.addDevice(t, "eth0", physDNS)
	deviceA := fake.addDevice(t, "wt0")
	deviceB := fake.addDevice(t, "wt1")
	owners := hostcoord.NewDNSOwners()
	interfaces := func() []string { return []string{"wt0", "wt1"} }
	warningsB := &warningLog{}

	serverA := dns.NewTestSessionServer(t, "wt0", dnsIPA, dns.TestBackendNetworkManager, owners.Session(sessionKeyA, interfaces, nil))
	require.NoError(t, serverA.UpdateDNSServer(1, dnsConfig("a.test", true)))
	serverB := dns.NewTestSessionServer(t, "wt1", dnsIPB, dns.TestBackendNetworkManager, owners.Session(sessionKeyB, interfaces, warningsB.add))
	require.NoError(t, serverB.UpdateDNSServer(1, dnsConfig("b.test", true)))

	assert.Contains(t, fake.device(deviceA).domains, "~.", "the first session must own the catch-all")
	assert.NotContains(t, fake.device(deviceB).domains, "~.", "the second session must not get a catch-all")
	assert.Contains(t, fake.device(deviceB).domains, "~.b.test.", "the second session must keep its own domains")
	assert.Equal(t, []dns.HostDNSWarningKind{dns.HostDNSCatchAllHeld}, warningsB.kinds(), "the second session must be warned")
	assert.Equal(t, []netip.Addr{physDNS}, dns.OriginalNameservers(serverB), "session B must not capture the NetBird DNS of session A")

	stateA := fake.device(deviceA)
	serverB.Stop()
	assert.True(t, fake.device(deviceB).deleted, "session B must delete its own device")
	assert.Equal(t, stateA, fake.device(deviceA), "stopping session B must not change the device of session A")
	owner, held := owners.CatchAllOwner()
	assert.True(t, held, "a stop of another session must not release the catch-all")
	assert.Equal(t, sessionKeyA, owner, "a stop of another session must not change the owner")

	statePhys := fake.device(phys)
	serverA.Stop()
	assert.True(t, fake.device(deviceA).deleted, "session A must delete its own device")
	assert.Equal(t, statePhys, fake.device(phys), "stopping session A must not change the physical device")
	_, held = owners.CatchAllOwner()
	assert.False(t, held, "the owner's stop must release the catch-all")
}

// The same network map after the owner left must take the free catch-all.
func TestNetworkManager_ReleasedCatchAllTakenWithSameConfig(t *testing.T) {
	fake := startFakeNM(t)
	fake.addDevice(t, "eth0", physDNS)
	fake.addDevice(t, "wt0")
	deviceB := fake.addDevice(t, "wt1")
	owners := hostcoord.NewDNSOwners()
	interfaces := func() []string { return []string{"wt0", "wt1"} }

	serverA := dns.NewTestSessionServer(t, "wt0", dnsIPA, dns.TestBackendNetworkManager, owners.Session(sessionKeyA, interfaces, nil))
	require.NoError(t, serverA.UpdateDNSServer(1, dnsConfig("a.test", true)))
	serverB := dns.NewTestSessionServer(t, "wt1", dnsIPB, dns.TestBackendNetworkManager, owners.Session(sessionKeyB, interfaces, nil))
	require.NoError(t, serverB.UpdateDNSServer(1, dnsConfig("b.test", true)))
	require.NotContains(t, fake.device(deviceB).domains, "~.", "the second session must not get a catch-all")

	serverA.Stop()
	require.NoError(t, serverB.UpdateDNSServer(2, dnsConfig("b.test", true)))
	assert.Contains(t, fake.device(deviceB).domains, "~.", "an update with the same configuration must take the free catch-all")
	owner, held := owners.CatchAllOwner()
	assert.True(t, held, "the catch-all must have a new owner")
	assert.Equal(t, sessionKeyB, owner, "session B must own the catch-all")
}

// The container has neither resolved nor NetworkManager, so the real probe of the host
// picks the file backend. A coordinator must change what that choice is wrapped in, and
// no coordinator must leave the manager as it is today.
func TestInitialize_OnlyCoordinatorWrapsTheManager(t *testing.T) {
	owners := hostcoord.NewDNSOwners()

	coordinated, err := dns.InitializedHostManagerType(dns.NewTestConfiguredServer(t, "wt0", owners.Session(sessionKeyA, nil, nil)))
	require.NoError(t, err)
	assert.Equal(t, "*dns.exclusiveHostManager", coordinated, "a coordinator must arbitrate the backend")

	plain, err := dns.InitializedHostManagerType(dns.NewTestConfiguredServer(t, "wt0", nil))
	require.NoError(t, err)
	assert.Equal(t, "*dns.fileConfigurator", plain, "without a coordinator the manager must be the plain backend")
}

// The file backend has one resolv.conf: it runs against the container's own file.
func TestFileBackend_FirstSessionOwnsHostDNS(t *testing.T) {
	const resolvConf = "/etc/resolv.conf"
	original, err := os.ReadFile(resolvConf)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, os.WriteFile(resolvConf, original, 0o644)) })

	owners := hostcoord.NewDNSOwners()
	warningsB := &warningLog{}
	serverA := dns.NewTestSessionServer(t, "wt0", dnsIPA, dns.TestBackendFile, owners.Session(sessionKeyA, nil, nil))
	serverB := dns.NewTestSessionServer(t, "wt1", dnsIPB, dns.TestBackendFile, owners.Session(sessionKeyB, nil, warningsB.add))

	require.NoError(t, serverA.UpdateDNSServer(1, dnsConfig("a.test", false)))
	written, err := os.ReadFile(resolvConf)
	require.NoError(t, err)
	assert.Contains(t, string(written), "nameserver "+dnsIPA.String(), "the first session must write resolv.conf")

	require.NoError(t, serverB.UpdateDNSServer(1, dnsConfig("b.test", false)))
	afterB, err := os.ReadFile(resolvConf)
	require.NoError(t, err)
	assert.Equal(t, string(written), string(afterB), "the second session must not touch resolv.conf")
	assert.Equal(t, []dns.HostDNSWarningKind{dns.HostDNSHeld}, warningsB.kinds(), "the second session must be warned")
	assert.Empty(t, dns.OriginalNameservers(serverB), "a session without host DNS must not report originals")

	serverB.Stop()
	afterStopB, err := os.ReadFile(resolvConf)
	require.NoError(t, err)
	assert.Equal(t, string(written), string(afterStopB), "stopping the second session must not restore resolv.conf")

	serverA.Stop()
	restored, err := os.ReadFile(resolvConf)
	require.NoError(t, err)
	assert.Equal(t, string(original), string(restored), "the owner's stop must restore resolv.conf")
	_, held := owners.HostDNSOwner()
	assert.False(t, held, "the owner's stop must free the host DNS")
}
