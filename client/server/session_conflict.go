package server

import (
	"errors"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/internal/routemanager"
	"github.com/netbirdio/netbird/client/internal/statemanager"
	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/route"
)

const (
	errExitNodeHeld          = "another session holds the exit node of this host, bring it down or deselect its exit node first"
	errResidualNextToSession = "this profile has state left from a failed cleanup, which may name the resources of a running session: " +
		"bring the other sessions down so it can be cleaned, or restart the service"
)

// bindKey makes key the identity of the session. The caller is the only one to know the session.
func (ss *session) bindKey(key profilemanager.SessionKey) {
	ss.key = key
	ss.statusRecorder.SetEventProfile(key.Profile.String())
}

// noteRefusedRun keeps why a run was refused for the Up that waits for it and for the status. It has to
// run before the retry goroutine closes its give up channel.
func noteRefusedRun(ss *session, err error) {
	if !errors.Is(err, internal.ErrSessionRefused) {
		return
	}
	refusal := internal.RefusalOf(err)
	if !ss.recordRefusal(refusal) {
		return
	}

	metadata := map[string]string{proto.MetadataKindKey: internal.EventSessionRefused}
	if refusal.Conflict != "" {
		metadata[proto.MetadataConflictKey] = string(refusal.Conflict)
	}
	ss.statusRecorder.PublishEvent(proto.SystemEvent_ERROR, proto.SystemEvent_SYSTEM, refusal.Message, refusal.Message, metadata)
	// The run has set its final status before this, and whoever watches it has to see the conflict too.
	ss.statusRecorder.NotifyStateChange()
}

// refusalError returns what an Up gets for a refused run, nil when the run was not refused.
func refusalError(ss *session) error {
	refusal := ss.currentRefusal()
	if refusal == nil {
		return nil
	}
	return gstatus.Error(codes.FailedPrecondition, refusal.Message)
}

// conflictOf returns the value of SessionStatus.conflict for ss. A refusal says it all: a session that
// does not run has no other conflict.
func (s *Server) conflictOf(ss *session) *string {
	var conflict internal.SessionConflict
	if refusal := ss.currentRefusal(); refusal != nil {
		conflict = refusal.Conflict
	} else {
		conflict = s.host.Conflict(ss.key)
	}
	if conflict == "" {
		return nil
	}
	value := string(conflict)
	return &value
}

// refuseHeldExitNode refuses a manual selection of an exit node while another session holds the only
// one of the host. Selecting everything is no such request: it falls back to auto-apply, which the
// routes then skip with a warning.
func (s *Server) refuseHeldExitNode(ss *session, routeManager routemanager.Manager, req *proto.SelectNetworksRequest) error {
	if !s.concurrentProfiles || req.GetAll() || !s.host.ExitNodeHeldByOther(ss.key) {
		return nil
	}

	routes := routeManager.GetClientRoutesWithNetID()
	for _, id := range req.GetNetworkIDs() {
		if isExitNodeRoute(routes[route.NetID(id)]) {
			return gstatus.Error(codes.FailedPrecondition, errExitNodeHeld)
		}
	}
	return nil
}

func isExitNodeRoute(routes []*route.Route) bool {
	return len(routes) > 0 && (route.IsV4DefaultRoute(routes[0].Network) || route.IsV6DefaultRoute(routes[0].Network))
}

// refuseResidualBesideOthers refuses a run next to another session while the state file of ss still
// holds something: a cleanup failed, and the names it records can be in use by the other session, so
// that cleaning it is out of the question. Running without would overwrite the record. A file that
// cannot be read cannot be told apart from that (I6).
func (s *Server) refuseResidualBesideOthers(ss *session, others int) error {
	if others == 0 {
		return nil
	}

	names, err := statemanager.New(s.profileManager.GetStatePathFor(ss.key)).GetSavedStateNames()
	if err != nil {
		log.Warnf("failed to read the state of profile %s next to another session: %v", ss.key.Profile, err)
		return gstatus.Error(codes.FailedPrecondition, errResidualNextToSession)
	}
	if residual := residualStateNames(names); len(residual) > 0 {
		log.Warnf("refusing profile %s next to another session, it has residual state: %v", ss.key.Profile, residual)
		return gstatus.Error(codes.FailedPrecondition, errResidualNextToSession)
	}
	return nil
}

// residualStateNames drops the states a clean stop keeps on purpose. The network selection of a
// profile undoes nothing on the host, so it names no resource of another session. Any other name,
// also one this build does not know, counts as residual.
func residualStateNames(names []string) []string {
	kept := (&routemanager.SelectorState{}).Name()
	residual := make([]string, 0, len(names))
	for _, name := range names {
		if name != kept {
			residual = append(residual, name)
		}
	}
	return residual
}
