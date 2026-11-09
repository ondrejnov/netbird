package server

import (
	"context"
	"time"

	"github.com/netbirdio/netbird/client/internal/auth"
	"github.com/netbirdio/netbird/util/capture"
)

// oauthFlow returns a copy of the pending flow record. A decision about a flow has to
// run off one copy: Login, RequestJWTAuth and WaitSSOLogin replace the record while
// the IdP is being polled, so reading it field by field could mix two flows.
func (ss *session) oauthFlow() oauthAuthFlow {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return ss.oauthAuthFlow
}

// swapOAuthFlow installs next and returns the cancel of the wait it displaces, taken in
// one critical section so that two callers cannot both inherit the same wait. The caller
// decides whether to run the cancel, and does so after the unlock: the displaced wait
// reads the session as it unwinds.
func (ss *session) swapOAuthFlow(next oauthAuthFlow) context.CancelFunc {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	displaced := ss.oauthAuthFlow.waitCancel
	ss.oauthAuthFlow = next
	return displaced
}

// clearPendingAuthFlows drops both pending authentication flows of ss and wakes their
// waiters. A flow is only ever authorized against the profile it started for, so leaving one
// behind across a logout or a teardown would hand its result to whoever comes next.
func (ss *session) clearPendingAuthFlows() {
	if cancel := ss.swapOAuthFlow(oauthAuthFlow{}); cancel != nil {
		cancel()
	}
	ss.extendAuthSessionFlow.CancelWait()
	ss.extendAuthSessionFlow.Clear()
}

// clearOAuthFlowIf clears the record if flow is still the pending one, and reports
// whether it did. A flow that was replaced meanwhile belongs to its new owner.
func (ss *session) clearOAuthFlowIf(flow auth.OAuthFlow) bool {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if ss.oauthAuthFlow.flow != flow {
		return false
	}
	ss.oauthAuthFlow = oauthAuthFlow{}
	return true
}

func (ss *session) expireOAuthFlow(flow auth.OAuthFlow) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if ss.oauthAuthFlow.flow == flow {
		ss.oauthAuthFlow.expiresAt = time.Now()
	}
}

// claimOAuthWait makes cancel the wait of flow and returns the wait it displaces. It
// reports false, changing nothing, when flow is no longer the pending one.
func (ss *session) claimOAuthWait(flow auth.OAuthFlow, cancel context.CancelFunc) (context.CancelFunc, bool) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if ss.oauthAuthFlow.flow != flow {
		return nil, false
	}
	displaced := ss.oauthAuthFlow.waitCancel
	ss.oauthAuthFlow.waitCancel = cancel
	return displaced, true
}

func (ss *session) currentCapture() *capture.Session {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return ss.activeCapture
}

func (ss *session) setCapture(sess *capture.Session) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.activeCapture = sess
}
