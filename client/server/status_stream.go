package server

import (
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/proto"
)

// SubscribeStatus pushes a fresh StatusResponse on every connection state
// change. The first message is the current snapshot, so a re-subscribing
// client doesn't need to also call Status. Subsequent messages fire when
// the peer recorder reports any of: connected/disconnected/connecting,
// management or signal flip, address change, or peers list change.
//
// The change channel coalesces bursts to a single tick. If the consumer
// is slow the daemon drops extras (not blocks), and the next snapshot
// the consumer pulls already reflects everything.
func (s *Server) SubscribeStatus(req *proto.StatusRequest, stream proto.DaemonService_SubscribeStatusServer) error {
	ss, err := s.checkOpenSelector(stream.Context(), req.GetSession())
	if err != nil {
		return err
	}

	subID, ch := ss.statusRecorder.SubscribeToStateChanges()
	defer func() {
		ss.statusRecorder.UnsubscribeFromStateChanges(subID)
		log.Debug("client unsubscribed from status updates")
	}()

	log.Debug("client subscribed to status updates")

	if err := s.sendStatusSnapshot(ss, req, stream); err != nil {
		return err
	}

	for {
		select {
		case _, ok := <-ch:
			if !ok {
				return nil
			}
			if s.focusMovedFrom(ss, req.GetSession()) {
				ss.statusRecorder.UnsubscribeFromStateChanges(subID)
				ss = s.focusedSession()
				subID, ch = ss.statusRecorder.SubscribeToStateChanges()
			}
			if err := s.sendStatusSnapshot(ss, req, stream); err != nil {
				return err
			}
		case <-stream.Context().Done():
			return nil
		}
	}
}

func (s *Server) sendStatusSnapshot(ss *session, req *proto.StatusRequest, stream proto.DaemonService_SubscribeStatusServer) error {
	resp, err := s.buildStatusResponse(stream.Context(), ss, req)
	if err != nil {
		log.Warnf("build status snapshot for stream: %v", err)
		return err
	}
	if err := stream.Send(resp); err != nil {
		log.Warnf("send status snapshot to stream: %v", err)
		return err
	}
	return nil
}
