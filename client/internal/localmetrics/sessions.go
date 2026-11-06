package localmetrics

import (
	"context"
	"slices"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// ProfileLabel names the profile a series belongs to when a daemon runs several sessions.
const ProfileLabel = "profile"

// SessionSource is what one session contributes to a scrape.
type SessionSource struct {
	// Profile is the value of the profile label. It must differ between the sessions of one
	// scrape, as two series with the same name and labels fail the whole scrape.
	Profile string
	Status  statusSource
	// ClientMetrics is the gatherer of the running engine, nil when there is none.
	ClientMetrics prometheus.Gatherer
}

// SessionsProvider returns the sessions to report. It is called on every scrape.
type SessionsProvider func() []SessionSource

// NewSessionManager creates a manager whose one endpoint reports several sessions, each series
// labeled with the profile it belongs to. It shuts down when ctx is canceled.
func NewSessionManager(ctx context.Context, sessions SessionsProvider) *Manager {
	m := NewManager(ctx, nil, nil)
	m.sessions = sessions
	return m
}

// gatherSessions runs for every scrape, since sessions come and go between scrapes.
func (m *Manager) gatherSessions() ([]*dto.MetricFamily, error) {
	var gatherers prometheus.Gatherers
	for _, session := range m.sessions() {
		registry := prometheus.NewRegistry()
		if err := registry.Register(newCollector(session.Status)); err != nil {
			return nil, err
		}
		gatherers = append(gatherers, labeledGatherer{gatherer: registry, profile: session.Profile})
		if session.ClientMetrics != nil {
			gatherers = append(gatherers, labeledGatherer{gatherer: session.ClientMetrics, profile: session.Profile})
		}
	}
	return gatherers.Gather()
}

// labeledGatherer adds the profile label to all that gatherer collects. Both gatherers it is
// used with build the families anew for each call, so changing them hurts nobody.
type labeledGatherer struct {
	gatherer prometheus.Gatherer
	profile  string
}

// Gather implements prometheus.Gatherer.
func (g labeledGatherer) Gather() ([]*dto.MetricFamily, error) {
	families, err := g.gatherer.Gather()
	name := ProfileLabel
	for _, family := range families {
		for _, metric := range family.GetMetric() {
			metric.Label = append(metric.Label, &dto.LabelPair{Name: &name, Value: &g.profile})
			slices.SortFunc(metric.Label, func(a, b *dto.LabelPair) int {
				return strings.Compare(a.GetName(), b.GetName())
			})
		}
	}
	return families, err
}
