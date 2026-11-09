package server

import (
	"context"
	"strings"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/netbirdio/netbird/client/internal/localmetrics"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
)

// newLocalMetrics returns the metrics endpoint of the daemon. It is one for all sessions, and with
// the gate each series says which profile it is about.
func (s *Server) newLocalMetrics(ctx context.Context) *localmetrics.Manager {
	if s.concurrentProfiles {
		return localmetrics.NewSessionManager(ctx, s.metricSessions)
	}
	return localmetrics.NewManager(ctx, s.focusedSession().statusRecorder, s.clientMetricsGatherer)
}

// metricSessions lists what a scrape reports: the focused session, whose config decides that the
// endpoint exists, and each running session whose own config enabled metrics. The endpoint takes no
// credentials, so a session must not show up on it by being next to one that enabled them.
func (s *Server) metricSessions() []localmetrics.SessionSource {
	focused := s.focusedSession()
	sessions := s.allSessions()
	labels := sessionLabels(sessions)

	sources := make([]localmetrics.SessionSource, 0, len(sessions))
	for _, ss := range sessions {
		if ss != focused && !reportsMetrics(ss) {
			continue
		}
		sources = append(sources, localmetrics.SessionSource{
			Profile:       labels[ss],
			Status:        ss.statusRecorder,
			ClientMetrics: engineMetrics(ss),
		})
	}
	return sources
}

func reportsMetrics(ss *session) bool {
	if !ss.holdsHost() {
		return false
	}
	config := ss.connectionConfig()
	return config != nil && config.LocalMetricsEnabled
}

// engineMetrics returns the client metrics of the running engine of ss, nil when there is none.
func engineMetrics(ss *session) prometheus.Gatherer {
	connectClient := ss.client()
	if connectClient == nil {
		return nil
	}
	engine := connectClient.Engine()
	if engine == nil {
		return nil
	}
	return engine.GetClientMetrics().PrometheusGatherer()
}

// adoptStoredConfigLocked gives a session the config just written for its profile. Without it the
// metrics of a running session would stay on until its next run, after its owner turned them off.
// The caller holds s.mutex.
func (s *Server) adoptStoredConfigLocked(path string, config *profilemanager.Config) {
	if !s.concurrentProfiles {
		return
	}
	for _, ss := range s.sessions {
		if sessionPath, err := s.profileManager.ActiveProfilePath(profileStateOf(ss.key)); err == nil && sessionPath == path {
			ss.setConfig(ss.key, config)
			return
		}
	}
}

// sessionLabels names each session in what the daemon reports about several of them. The ID of a
// profile is enough, except that legacy IDs come from profile names and two users can share one.
func sessionLabels(sessions []*session) map[*session]string {
	counts := make(map[profilemanager.ID]int, len(sessions))
	for _, ss := range sessions {
		counts[ss.key.Profile]++
	}

	labels := make(map[*session]string, len(sessions))
	for _, ss := range sessions {
		label := ss.key.Profile.String()
		if counts[ss.key.Profile] > 1 {
			label += "@" + safeLabelPart(ss.key.Username)
		}
		labels[ss] = label
	}
	return labels
}

// safeLabelPart keeps a user name, which comes from the caller, from leaving the directory it names
// in a bundle.
func safeLabelPart(name string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		}
		return '_'
	}, name)
}
