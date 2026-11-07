package internal

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/dns"
	"github.com/netbirdio/netbird/client/internal/hostcoord"
	"github.com/netbirdio/netbird/client/internal/peer"
	cProto "github.com/netbirdio/netbird/client/proto"
)

// A domain another session owns on Windows reaches the session that lost it, with its name.
func TestDNSDomainHeldIsAnEventOfItsSession(t *testing.T) {
	recorder := peer.NewRecorder("")
	recorder.SetEventProfile("home")
	session := &SessionHost{key: hostcoord.SessionKey{Profile: "home"}, recorder: recorder}

	session.dnsWarning(dns.HostDNSWarning{Kind: dns.HostDNSDomainHeld, Domains: []string{"a.test", "b.test"}})

	events := recorder.GetEventHistory()
	require.Len(t, events, 1)
	assert.Equal(t, cProto.SystemEvent_DNS, events[0].GetCategory())
	assert.Equal(t, cProto.SystemEvent_WARNING, events[0].GetSeverity())
	assert.Equal(t, "a.test, b.test", events[0].GetMetadata()[cProto.MetadataDomainsKey])
	assert.Contains(t, events[0].GetUserMessage(), "a.test, b.test", "the user learns which domains do not resolve here")
}
