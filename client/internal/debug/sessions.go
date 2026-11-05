package debug

import (
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

// SessionBundle is what a bundle holds about one more session of the daemon.
type SessionBundle struct {
	// Dir names the directory of the session under sessions/. It must differ between sessions.
	Dir            string
	ProfileName    string
	InternalConfig *profilemanager.Config
	StatePath      string
	StatusRecorder *peer.Status
	SyncResponse   *mgmProto.SyncResponse
	RefreshStatus  func()
	ClientMetrics  MetricsExporter
}

const sessionsDir = "sessions/"

// sessionsReadme explains what a bundle holds beyond one session, nothing for a bundle that has
// no more than that.
func (g *BundleGenerator) sessionsReadme() string {
	var text string
	if len(g.otherSessions) > 0 {
		text += "\n" + sessionsDir + "<profile>/: The other sessions the requester may read, each with its own status.txt, config.txt, " +
			"resolved_domains.txt, network_map.json, state.json, corrupted_states/, metrics.txt and wgshow.txt. The files at the top of " +
			"this bundle describe one session, and status.txt says which. Logs and profiles describe the whole daemon and appear once.\n"
	}
	if g.omitHostWide {
		text += "\nThe logs of the daemon and the system information were left out: the host runs sessions the requester may not read, " +
			"and these describe them too.\n"
	}
	return text
}

// forSession returns a generator that writes the files of session into the same archive.
func (g *BundleGenerator) forSession(session SessionBundle) *BundleGenerator {
	sub := *g
	sub.zipPrefix = sessionsDir + session.Dir + "/"
	sub.profileName = session.ProfileName
	sub.internalConfig = session.InternalConfig
	sub.statePath = session.StatePath
	sub.statusRecorder = session.StatusRecorder
	sub.syncResponse = session.SyncResponse
	sub.refreshStatus = session.RefreshStatus
	sub.clientMetrics = session.ClientMetrics
	return &sub
}

// addOtherSessions writes what describes each other session. The failure of a file costs only that
// file, the requester still wants the rest.
func (g *BundleGenerator) addOtherSessions() {
	for _, session := range g.otherSessions {
		sub := g.forSession(session)
		for _, part := range []struct {
			name string
			add  func() error
		}{
			{"status", sub.addStatus},
			{"config", sub.addConfig},
			{"resolved domains", sub.addResolvedDomains},
			{"sync response", sub.addSyncResponse},
			{"state file", sub.addStateFile},
			{"corrupted state files", sub.addCorruptedStateFiles},
			{"metrics", sub.addMetrics},
			{"wg show", sub.addWgShow},
		} {
			if err := part.add(); err != nil {
				log.Errorf("failed to add %s of session %s to debug bundle: %v", part.name, session.Dir, err)
			}
		}
	}
}
