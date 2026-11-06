//go:build !android && !ios

package server

import (
	"context"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/debug"
	"github.com/netbirdio/netbird/client/proto"
)

// bundleScope says what a debug bundle holds beyond the session it is about. The zero value is a
// bundle of one session, which is what a daemon without the gate has.
type bundleScope struct {
	others []*session
	labels map[*session]string
	// omitHostWide leaves out what describes the whole host, see debug.GeneratorDependencies.
	omitHostWide bool
	// omitDaemonLog leaves out the log alone, see debug.GeneratorDependencies.
	omitDaemonLog bool
}

// bundleScopeOf decides what a bundle about target holds for this caller. Without a selector it
// covers each session the caller may read, and a selector asks for that session alone. A session
// the caller may not read stays out, along with what also describes it (5.6). The log of the daemon
// goes back further than any record, so only a privileged caller gets it.
func (s *Server) bundleScopeOf(ctx context.Context, target *session, req *proto.DebugBundleRequest) bundleScope {
	if !s.concurrentProfiles {
		return bundleScope{}
	}

	caller := s.callerOf(ctx)
	focused := s.focusedSession()
	all := s.allSessions()

	scope := bundleScope{labels: sessionLabels(all), omitDaemonLog: !caller.privileged()}
	for _, ss := range all {
		if ss == target {
			continue
		}
		if !caller.mayReach(ss.key) {
			scope.omitHostWide = true
			continue
		}
		if req.GetSession() == nil && !isQuietSession(ss, focused) {
			scope.others = append(scope.others, ss)
		}
	}
	for _, record := range s.slots.Records() {
		if !caller.mayReach(sessionKeyOf(record.Key.Profile, record.Key.Username)) {
			scope.omitHostWide = true
		}
	}
	return scope
}

// sessionBundleOf gathers what a bundle says about ss. It runs without s.mutex: the status of a
// run and the engine that is going down answer for themselves.
func (s *Server) sessionBundleOf(ss *session, scope bundleScope) debug.SessionBundle {
	syncResponse, err := s.getLatestSyncResponse(ss)
	if err != nil {
		log.Warnf("failed to get latest sync response: %v", err)
	}

	bundle := debug.SessionBundle{
		Dir: scope.labels[ss],
		// Status, sync response and metrics describe the connection, so do its config and state.
		InternalConfig: ss.connectionConfig(),
		StatePath:      s.bundleStatePath(ss),
		StatusRecorder: ss.statusRecorder,
		SyncResponse:   syncResponse,
	}
	if s.concurrentProfiles {
		bundle.ProfileName = s.profileDisplayName(ss.key)
	}

	connectClient := ss.client()
	if connectClient == nil {
		return bundle
	}
	engine := connectClient.Engine()
	if engine == nil {
		return bundle
	}
	if cm := engine.GetClientMetrics(); cm != nil {
		bundle.ClientMetrics = cm
	}
	bundle.RefreshStatus = func() {
		log.Debug("refreshing system health status for debug bundle")
		// Background ctx: the bundle wants a full, fresh probe regardless
		// of the DebugBundle RPC client's lifetime. The engine's own ctx
		// still aborts it on shutdown.
		engine.RunHealthProbes(context.Background(), true)
	}
	return bundle
}

func (s *Server) otherSessionBundles(scope bundleScope) []debug.SessionBundle {
	bundles := make([]debug.SessionBundle, 0, len(scope.others))
	for _, ss := range scope.others {
		bundles = append(bundles, s.sessionBundleOf(ss, scope))
	}
	return bundles
}
