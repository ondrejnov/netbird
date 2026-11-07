package dns

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows/registry"

	"github.com/netbirdio/netbird/client/internal/statemanager"
)

// TestNRPTSession is a session sharing the NRPT with others.
type TestNRPTSession struct {
	manager *nrptHostManager
	rules   *recordedRules
}

// recordedRules keeps the configurations instead of writing rules.
type recordedRules struct {
	applied  []HostDNSConfig
	fail     bool
	restored int
}

func (r *recordedRules) applyDNSConfig(config HostDNSConfig, _ *statemanager.Manager) error {
	if r.fail {
		return errTestRules
	}
	r.applied = append(r.applied, config)
	return nil
}

func (r *recordedRules) restoreHostDNS() error {
	r.restored++
	return nil
}

func (r *recordedRules) supportCustomPort() bool              { return false }
func (r *recordedRules) string() string                       { return "recorded" }
func (r *recordedRules) getOriginalNameservers() []netip.Addr { return nil }

type testRulesError struct{}

func (testRulesError) Error() string { return "rules not written" }

var errTestRules = testRulesError{}

// NewTestNRPTSession returns a session whose rules are recorded instead of written.
func NewTestNRPTSession(coordinator HostDNSCoordinator) *TestNRPTSession {
	rules := &recordedRules{}
	return &TestNRPTSession{
		manager: &nrptHostManager{hostManager: rules, coordinator: coordinator},
		rules:   rules,
	}
}

// NewTestRegistrySession returns a session writing the rules of slot to the local policy store,
// for an adapter guid that has an interface key. The rules are removed when the test ends.
func NewTestRegistrySession(t *testing.T, guid string, slot uint32, coordinator HostDNSCoordinator) *TestNRPTSession {
	t.Helper()
	interfacePath := InterfaceConfigPath + `\` + guid
	key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, interfacePath, registry.SET_VALUE)
	require.NoError(t, err, "create the interface key")
	require.NoError(t, key.Close())
	t.Cleanup(func() { _ = registry.DeleteKey(registry.LOCAL_MACHINE, interfacePath) })

	configurator, err := newRegistryConfigurator(&registryConfigurator{guid: guid, slot: slot, strict: true})
	require.NoError(t, err)
	t.Cleanup(func() { _ = configurator.removeDNSMatchPolicies() })
	return &TestNRPTSession{manager: &nrptHostManager{hostManager: configurator, coordinator: coordinator}}
}

// Apply applies config as the DNS server would.
func (s *TestNRPTSession) Apply(config HostDNSConfig) error {
	return s.manager.applyDNSConfig(config, nil)
}

// Restore restores the host DNS as a stopping session does.
func (s *TestNRPTSession) Restore() error {
	return s.manager.restoreHostDNS()
}

// Applied returns the configuration the rules got last.
func (s *TestNRPTSession) Applied() HostDNSConfig {
	if len(s.rules.applied) == 0 {
		return HostDNSConfig{}
	}
	return s.rules.applied[len(s.rules.applied)-1]
}

// FailRules makes writing the rules fail or succeed again.
func (s *TestNRPTSession) FailRules(fail bool) {
	s.rules.fail = fail
}

// Pending reports whether the DNS server would try the configuration again.
func (s *TestNRPTSession) Pending() bool {
	return s.manager.hostClaimPending()
}

// Retry claims again what was refused, as the DNS server does with an unchanged configuration.
func (s *TestNRPTSession) Retry() bool {
	return s.manager.retryClaim()
}

// SlotRuleDomains returns the namespaces of the match rules of slot in the local policy store.
func SlotRuleDomains(t *testing.T, slot uint32) []string {
	t.Helper()
	names, err := listNRPTRuleKeys(DNSPolicyConfigRoot, nrptKeyPrefix(slot))
	require.NoError(t, err)

	var domains []string
	for _, name := range names {
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, DNSPolicyConfigRoot+`\`+name, registry.QUERY_VALUE)
		require.NoError(t, err)
		values, _, err := key.GetStringsValue(dnsPolicyConfigNameKey)
		_ = key.Close()
		require.NoError(t, err)
		domains = append(domains, values...)
	}
	return domains
}
