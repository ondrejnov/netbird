package server

import (
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/proto"
)

// sessionSetNotifier wakes the status streams when a session joins or leaves the set, so that a
// stream can start or stop following its recorder.
type sessionSetNotifier struct {
	mu   sync.Mutex
	next uint64
	subs map[uint64]chan struct{}
}

func newSessionSetNotifier() *sessionSetNotifier {
	return &sessionSetNotifier{subs: make(map[uint64]chan struct{})}
}

func (n *sessionSetNotifier) subscribe() (uint64, <-chan struct{}) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.next++
	ch := make(chan struct{}, 1)
	n.subs[n.next] = ch
	return n.next, ch
}

func (n *sessionSetNotifier) unsubscribe(id uint64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.subs, id)
}

// notify never blocks, so that it can run under Server.mutex. A subscriber with a pending tick
// re-reads the whole set anyway.
func (n *sessionSetNotifier) notify() {
	if n == nil {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, ch := range n.subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// sessionWatch merges the state changes of several session recorders into one channel.
type sessionWatch struct {
	changes chan struct{}
	subs    map[*session]string
}

func newSessionWatch() *sessionWatch {
	return &sessionWatch{changes: make(chan struct{}, 1), subs: make(map[*session]string)}
}

// sync follows exactly the sessions in want.
func (w *sessionWatch) sync(want []*session) {
	keep := make(map[*session]bool, len(want))
	for _, ss := range want {
		keep[ss] = true
		if _, ok := w.subs[ss]; ok {
			continue
		}
		id, ch := ss.statusRecorder.SubscribeToStateChanges()
		w.subs[ss] = id
		go w.forward(ch)
	}
	for ss, id := range w.subs {
		if !keep[ss] {
			ss.statusRecorder.UnsubscribeFromStateChanges(id)
			delete(w.subs, ss)
		}
	}
}

// forward ends when the recorder closes ch on unsubscribe.
func (w *sessionWatch) forward(ch <-chan struct{}) {
	for range ch {
		select {
		case w.changes <- struct{}{}:
		default:
		}
	}
}

func (w *sessionWatch) close() {
	w.sync(nil)
}

// subscribeAllSessions is SubscribeStatus with the gate. Every response lists the sessions the
// caller may read, so a change of any of them sends a snapshot, not only a change of ss.
func (s *Server) subscribeAllSessions(ss *session, req *proto.StatusRequest, stream proto.DaemonService_SubscribeStatusServer) error {
	setID, setChanged := s.sessionSetChanges.subscribe()
	defer s.sessionSetChanges.unsubscribe(setID)

	// The gate admitted the caller as holder of ss, which mayReach covers as well, so a stream
	// never watches a recorder only because it once described that session.
	caller := s.callerOf(stream.Context())
	reachable := func() []*session {
		var out []*session
		for _, candidate := range s.allSessions() {
			if caller.mayReach(candidate.key) {
				out = append(out, candidate)
			}
		}
		return out
	}

	watch := newSessionWatch()
	defer func() {
		watch.close()
		log.Debug("client unsubscribed from status updates")
	}()
	watch.sync(reachable())

	log.Debug("client subscribed to status updates of all sessions")

	if err := s.sendStatusSnapshot(ss, req, stream); err != nil {
		return err
	}

	for {
		select {
		case <-setChanged:
		case <-watch.changes:
		case <-stream.Context().Done():
			return nil
		}
		next, err := s.streamSessionAfter(stream.Context(), ss, req.GetSession())
		if err != nil {
			return err
		}
		ss = next
		watch.sync(reachable())
		if err := s.sendStatusSnapshot(ss, req, stream); err != nil {
			return err
		}
	}
}
