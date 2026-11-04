//go:build (linux && !android) || freebsd

package dns_test

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/dns"
	"github.com/netbirdio/netbird/client/internal/hostcoord"
	nbdns "github.com/netbirdio/netbird/dns"
)

var (
	dnsIPA = netip.MustParseAddr("100.64.0.53")
	dnsIPB = netip.MustParseAddr("100.65.0.53")

	sessionKeyA = hostcoord.SessionKey{Profile: "a", Username: "alice"}
	sessionKeyB = hostcoord.SessionKey{Profile: "b", Username: "alice"}
)

// warningLog collects the warnings a session receives.
type warningLog struct {
	mu       sync.Mutex
	warnings []dns.HostDNSWarning
}

func (l *warningLog) add(warning dns.HostDNSWarning) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.warnings = append(l.warnings, warning)
}

func (l *warningLog) kinds() []dns.HostDNSWarningKind {
	l.mu.Lock()
	defer l.mu.Unlock()
	kinds := make([]dns.HostDNSWarningKind, 0, len(l.warnings))
	for _, warning := range l.warnings {
		kinds = append(kinds, warning.Kind)
	}
	return kinds
}

// dnsConfig is a network map DNS update for one session: its own zone and, when
// routeAll is set, a primary nameserver group, which asks for the catch-all.
func dnsConfig(zone string, routeAll bool) nbdns.Config {
	config := nbdns.Config{
		ServiceEnable: true,
		CustomZones:   []nbdns.CustomZone{{Domain: zone, SearchDomainDisabled: true}},
	}
	if routeAll {
		config.NameServerGroups = []*nbdns.NameServerGroup{{
			Primary: true,
			NameServers: []nbdns.NameServer{{
				IP:     netip.MustParseAddr("192.0.2.1"),
				NSType: nbdns.UDPNameServerType,
				Port:   dns.DefaultPort,
			}},
		}}
	}
	return config
}

// installFakeOpenresolv puts a resolvconf on PATH that records its calls instead of
// changing the host, so the test sees exactly what the backend asks for.
func installFakeOpenresolv(t *testing.T) (callLog string) {
	t.Helper()
	dir := t.TempDir()
	callLog = filepath.Join(dir, "calls")
	script := fmt.Sprintf(`#!/bin/sh
if [ "$1" = "--version" ]; then
	echo "openresolv 3.13.2"
	exit 0
fi
echo "$*" >> %q
cat > /dev/null
`, callLog)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "resolvconf"), []byte(script), 0o755))
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return callLog
}

func readCalls(t *testing.T, callLog string) []string {
	t.Helper()
	content, err := os.ReadFile(callLog)
	if os.IsNotExist(err) {
		return nil
	}
	require.NoError(t, err)
	return strings.Split(strings.TrimSpace(string(content)), "\n")
}

// With openresolv's -x only one session can be on the host, and the first one stays
// there: a later session writes nothing, gets a warning, and leaves nothing to undo.
func TestOpenresolv_FirstSessionOwnsHostDNS(t *testing.T) {
	callLog := installFakeOpenresolv(t)
	owners := hostcoord.NewDNSOwners()

	warningsB := &warningLog{}
	serverA := dns.NewTestSessionServer(t, "wt0", dnsIPA, dns.TestBackendResolvConf, owners.Session(sessionKeyA, nil, nil))
	serverB := dns.NewTestSessionServer(t, "wt1", dnsIPB, dns.TestBackendResolvConf, owners.Session(sessionKeyB, nil, warningsB.add))

	require.NoError(t, serverA.UpdateDNSServer(1, dnsConfig("a.test", true)))
	require.NoError(t, serverB.UpdateDNSServer(1, dnsConfig("b.test", true)))

	assert.Equal(t, []string{"-x -a wt0"}, readCalls(t, callLog), "only the first session may reach openresolv")
	assert.Equal(t, []dns.HostDNSWarningKind{dns.HostDNSHeld}, warningsB.kinds(), "the session left out must be warned")
	assert.Empty(t, dns.OriginalNameservers(serverB), "a session without host DNS must not report the owner's nameserver as original")

	// A repeated update must not warn again about the same state.
	require.NoError(t, serverB.UpdateDNSServer(2, dnsConfig("b2.test", true)))
	assert.Len(t, warningsB.kinds(), 1, "the warning must be given once per state")

	// Stopping the session without host DNS undoes nothing on the host.
	serverB.Stop()
	assert.Equal(t, []string{"-x -a wt0"}, readCalls(t, callLog), "a session that wrote nothing must not call openresolv on stop")
	owner, held := owners.HostDNSOwner()
	assert.True(t, held, "the owner must keep the host DNS when another session stops")
	assert.Equal(t, sessionKeyA, owner, "the owner must not change when another session stops")

	serverA.Stop()
	assert.Equal(t, []string{"-x -a wt0", "-f -d wt0"}, readCalls(t, callLog), "the owner must remove its own record")
	_, held = owners.HostDNSOwner()
	assert.False(t, held, "the owner's stop must free the host DNS")
}

// The host DNS goes to the next session only when that session applies a configuration.
func TestOpenresolv_NextSessionClaimsAfterRelease(t *testing.T) {
	callLog := installFakeOpenresolv(t)
	owners := hostcoord.NewDNSOwners()

	warningsB := &warningLog{}
	serverA := dns.NewTestSessionServer(t, "wt0", dnsIPA, dns.TestBackendResolvConf, owners.Session(sessionKeyA, nil, nil))
	serverB := dns.NewTestSessionServer(t, "wt1", dnsIPB, dns.TestBackendResolvConf, owners.Session(sessionKeyB, nil, warningsB.add))

	require.NoError(t, serverA.UpdateDNSServer(1, dnsConfig("a.test", false)))
	require.NoError(t, serverB.UpdateDNSServer(1, dnsConfig("b.test", false)))
	serverA.Stop()
	assert.Equal(t, []string{"-x -a wt0", "-f -d wt0"}, readCalls(t, callLog), "nothing may be handed over on release")

	require.NoError(t, serverB.UpdateDNSServer(2, dnsConfig("b2.test", false)))
	assert.Equal(t, []string{"-x -a wt0", "-f -d wt0", "-x -a wt1"}, readCalls(t, callLog), "the next update must take the free host DNS")
	owner, held := owners.HostDNSOwner()
	assert.True(t, held, "the next session must own the host DNS")
	assert.Equal(t, sessionKeyB, owner, "the next session must own the host DNS")
}

// A session keeps getting the same network map after the owner left. Nothing changes in
// its configuration, and it must still take the free host DNS, and only then.
func TestOpenresolv_NextSessionClaimsWithSameConfig(t *testing.T) {
	callLog := installFakeOpenresolv(t)
	owners := hostcoord.NewDNSOwners()

	warningsB := &warningLog{}
	serverA := dns.NewTestSessionServer(t, "wt0", dnsIPA, dns.TestBackendResolvConf, owners.Session(sessionKeyA, nil, nil))
	serverB := dns.NewTestSessionServer(t, "wt1", dnsIPB, dns.TestBackendResolvConf, owners.Session(sessionKeyB, nil, warningsB.add))

	require.NoError(t, serverA.UpdateDNSServer(1, dnsConfig("a.test", false)))
	require.NoError(t, serverB.UpdateDNSServer(1, dnsConfig("b.test", false)))

	require.NoError(t, serverB.UpdateDNSServer(2, dnsConfig("b.test", false)))
	assert.Equal(t, []string{"-x -a wt0"}, readCalls(t, callLog), "the retry must not reach openresolv while the owner stays")
	assert.Len(t, warningsB.kinds(), 1, "the warning must be given once per state")

	serverA.Stop()
	require.NoError(t, serverB.UpdateDNSServer(3, dnsConfig("b.test", false)))
	assert.Equal(t, []string{"-x -a wt0", "-f -d wt0", "-x -a wt1"}, readCalls(t, callLog), "an update with the same configuration must take the free host DNS")
	owner, held := owners.HostDNSOwner()
	assert.True(t, held, "the next session must own the host DNS")
	assert.Equal(t, sessionKeyB, owner, "the next session must own the host DNS")

	// Once owned, the same configuration is deduplicated again.
	require.NoError(t, serverB.UpdateDNSServer(4, dnsConfig("b.test", false)))
	assert.Len(t, readCalls(t, callLog), 3, "a session that owns the host DNS must not write the same configuration again")
}

// A session whose write fails must not block the host DNS for the others.
func TestOpenresolv_FailedApplyDoesNotHoldHostDNS(t *testing.T) {
	dir := t.TempDir()
	script := "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo openresolv; exit 0; fi\nexit 1\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "resolvconf"), []byte(script), 0o755))
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	owners := hostcoord.NewDNSOwners()
	serverA := dns.NewTestSessionServer(t, "wt0", dnsIPA, dns.TestBackendResolvConf, owners.Session(sessionKeyA, nil, nil))
	require.NoError(t, serverA.UpdateDNSServer(1, dnsConfig("a.test", false)))

	_, held := owners.HostDNSOwner()
	assert.False(t, held, "a failed first write must release the claim")
}

// Without a coordinator every session reaches the backend, as it does today.
func TestOpenresolv_NoCoordinatorKeepsTodaysBehaviour(t *testing.T) {
	callLog := installFakeOpenresolv(t)

	serverA := dns.NewTestSessionServer(t, "wt0", dnsIPA, dns.TestBackendResolvConf, nil)
	serverB := dns.NewTestSessionServer(t, "wt1", dnsIPB, dns.TestBackendResolvConf, nil)

	require.NoError(t, serverA.UpdateDNSServer(1, dnsConfig("a.test", false)))
	require.NoError(t, serverB.UpdateDNSServer(1, dnsConfig("b.test", false)))
	assert.Equal(t, []string{"-x -a wt0", "-x -a wt1"}, readCalls(t, callLog), "without a coordinator nothing may be arbitrated")

	require.NoError(t, serverB.UpdateDNSServer(2, dnsConfig("b.test", false)))
	assert.Len(t, readCalls(t, callLog), 2, "without a coordinator the same configuration must not be applied again")

	serverA.Stop()
	serverB.Stop()
	assert.Equal(t, []string{"-x -a wt0", "-x -a wt1", "-f -d wt0", "-f -d wt1"}, readCalls(t, callLog), "without a coordinator every session must restore")
}
