package localmetrics

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/peer"
)

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "must find a free port")
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())
	return addr
}

func scrape(t *testing.T, addr string) string {
	t.Helper()
	var body string
	require.Eventually(t, func() bool {
		resp, err := http.Get(fmt.Sprintf("http://%s/metrics", addr))
		if err != nil {
			return false
		}
		defer func() { _ = resp.Body.Close() }()
		data, err := io.ReadAll(resp.Body)
		if err != nil || resp.StatusCode != http.StatusOK {
			return false
		}
		body = string(data)
		return true
	}, 2*time.Second, 20*time.Millisecond, "metrics endpoint should answer")
	return body
}

// clientGatherer is what the engine of a session exposes: a registry of its own.
func clientGatherer(t *testing.T, value float64) prometheus.Gatherer {
	t.Helper()
	registry := prometheus.NewRegistry()
	gauge := prometheus.NewGauge(prometheus.GaugeOpts{Name: "netbird_client_connection_stage", Help: "A client metric."})
	gauge.Set(value)
	require.NoError(t, registry.Register(gauge))
	return registry
}

func TestSessionManager_LabelsEverySeriesWithItsProfile(t *testing.T) {
	work := testStatus()
	home := &stubStatus{
		management: peer.ManagementState{Connected: false},
		signal:     peer.SignalState{Connected: true},
		peers: []peer.State{
			{FQDN: "peer-z.home.example", ConnStatus: peer.StatusConnected, Latency: 2 * time.Millisecond},
		},
	}
	var mu sync.Mutex
	sources := []SessionSource{
		{Profile: "work", Status: work, ClientMetrics: clientGatherer(t, 7)},
		{Profile: "home", Status: home, ClientMetrics: clientGatherer(t, 9)},
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	m := NewSessionManager(ctx, func() []SessionSource {
		mu.Lock()
		defer mu.Unlock()
		return sources
	})
	addr := freeAddr(t)
	m.Reconcile(true, addr)

	body := scrape(t, addr)
	for _, want := range []string{
		`netbird_management_connected{profile="work"} 1`,
		`netbird_management_connected{profile="home"} 0`,
		`netbird_signal_connected{profile="home"} 1`,
		`netbird_peers{profile="work"} 4`,
		`netbird_peers{profile="home"} 1`,
		`netbird_peers_connected{connection_type="relay",profile="work"} 1`,
		`netbird_peers_connected{connection_type="p2p",profile="home"} 1`,
		`netbird_peer_latency_seconds{peer="peer-a.netbird.cloud",profile="work"} 0.012`,
		`netbird_peer_latency_seconds{peer="peer-z.home.example",profile="home"} 0.002`,
		`netbird_client_connection_stage{profile="work"} 7`,
		`netbird_client_connection_stage{profile="home"} 9`,
	} {
		assert.Contains(t, body, want)
	}
	assert.NotContains(t, body, `peer="peer-z.home.example",profile="work"`, "a peer belongs to its own session")
	assert.Empty(t, regexp.MustCompile(`(?m)^netbird_[a-z_]+( |\{[^}]*\} )[0-9]`).FindAllString(withoutProfile(body), -1),
		"every series should say which profile it belongs to")

	// A session that ended is gone at the next scrape, and the other stays.
	mu.Lock()
	sources = sources[:1]
	mu.Unlock()
	body = scrape(t, addr)
	assert.Contains(t, body, `netbird_peers{profile="work"} 4`)
	assert.NotContains(t, body, `profile="home"`, "a session that ended should not be reported")

	mu.Lock()
	sources = nil
	mu.Unlock()
	assert.NotContains(t, scrape(t, addr), "netbird_peers", "with no session there is nothing to report")
}

// withoutProfile drops the series that carry the label, what is left has none.
func withoutProfile(body string) string {
	return regexp.MustCompile(`(?m)^.*profile=.*$`).ReplaceAllString(body, "")
}
