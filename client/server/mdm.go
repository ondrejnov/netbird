package server

import (
	"context"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/mdm"
	"github.com/netbirdio/netbird/client/proto"
)

// onMDMPolicyChange is invoked by the MDM reload ticker every time the
// OS-native managed-config store reports a diff vs the last observation.
//
// Restart sequence:
//  1. Cancel the active engine context (terminates connectWithRetryRuns).
//  2. Wait briefly for that goroutine to exit (giveUpChan is closed on exit).
//  3. Re-resolve Config from disk + MDM policy (Config.apply re-runs
//     applyMDMPolicy with the freshly loaded Policy).
//  4. Spawn a fresh connectWithRetryRuns with the new context and config.
//  5. Broadcast a SystemEvent so any GUI / CLI subscriber (SubscribeEvents
//     RPC) can refresh its cached config view without polling.
//
// The callback runs in the ticker's own goroutine. Ticker has already
// logged the per-key diff before invoking this hook.
func (s *Server) onMDMPolicyChange(_, _ *mdm.Policy) error {
	log.Warn("MDM policy changed; restarting engine to apply new configuration")

	return s.forEachSession(s.allSessions(), s.applyMDMPolicyToSession)
}

// applyMDMPolicyToSession runs the restart sequence for one session.
func (s *Server) applyMDMPolicyToSession(ss *session) error {
	s.mutex.Lock()
	// Read before the cancel: the restart itself ends the run it has to bring back.
	restart, ok := ss.beginRestart()
	if !ok {
		s.refreshIdleSessionConfig(ss)
		s.mutex.Unlock()
		// The client is not running, so there's no engine to restart.
		return nil
	}
	ss.cancelAct()
	s.mutex.Unlock()

	// After the final unlock below, so an Up that wakes up here finds the new run.
	defer ss.endRestart()

	// Wait for previous connectWithRetryRuns to exit so we don't end up
	// with two goroutines fighting over the same status recorder + engine.
	// The teardown engages a fan-out of engine goroutines (peer workers,
	// signal handler, route manager, ...). close(clientGiveUpChan)
	// happens in the function-scope defer of connectWithRetryRuns, on
	// every exit path (ctx cancel, backoff exhausted, panic) — see the
	// defer in server.go. No lock is held here: the teardown can take
	// the full timeout, and the RPCs have to keep answering meanwhile.
	if restart.giveUp != nil {
		select {
		case <-restart.giveUp:
		case <-time.After(10 * time.Second):
			return fmt.Errorf("failed to restart the engine due to timeout")
		}
	}

	// Not bound to rootCtx: the decision below has to be taken either way, and whoever holds
	// the lifecycle releases it when its teardown ends.
	if err := ss.lockLifecycle(context.Background()); err != nil {
		return fmt.Errorf("wait for the session to settle: %w", err)
	}
	defer ss.unlockLifecycle()

	s.mutex.Lock()
	defer s.mutex.Unlock()

	// The lock was free during the wait, so the session may have moved on.
	if !ss.restartStillWanted(restart) {
		log.Info("MDM restart: the session was taken down or over during the wait, not restarting")
		s.refreshSelectedConfig(ss)
		s.publishConfigChangedEvent(ss, proto.MetadataSourceMDM)
		s.publishPolicyApplied(ss)
		return nil
	}

	if err := s.restartEngineForMDMLocked(ss, restart.key, restart.running); err != nil {
		log.Errorf("MDM restart failed: %v", err)
		return err
	}

	// publishConfigChangedEvent has already fired inside
	// restartEngineForMDMLocked with source="mdm".
	s.publishPolicyApplied(ss)
	return nil
}

// publishPolicyApplied emits an MDM-specific user-visible toast so the operator knows their
// IT policy was applied (UserMessage != "" triggers the GUI notifier).
func (s *Server) publishPolicyApplied(ss *session) {
	ss.statusRecorder.PublishEvent(
		proto.SystemEvent_INFO,
		proto.SystemEvent_SYSTEM,
		"MDM policy applied",
		"NetBird configuration was updated by your IT policy.",
		map[string]string{
			proto.MetadataSourceKey: proto.MetadataSourceMDM,
			proto.MetadataTypeKey:   proto.MetadataTypePolicyApplied,
		},
	)
}

// publishConfigChangedEvent broadcasts a SystemEvent informing any active
// SubscribeEvents subscriber (typically the GUI tray) that the daemon's
// effective Config has been replaced and any cached client-side view
// should be refreshed. Callers pass a stable `source` label so the GUI
// can distinguish a startup spawn from a user-triggered Up or an
// MDM-driven restart. Reusing the SYSTEM category keeps the proto enum
// stable; metadata.type="config_changed" routes to the GUI's refresh
// handler. UserMessage is left empty so the system tray does not toast
// for every internal restart; the MDM path emits a separate
// "policy_applied" event (with UserMessage) for that purpose.
func (s *Server) publishConfigChangedEvent(ss *session, source string) {
	if ss.statusRecorder == nil {
		return
	}
	ss.statusRecorder.PublishEvent(
		proto.SystemEvent_INFO,
		proto.SystemEvent_SYSTEM,
		fmt.Sprintf("daemon config changed (source=%s)", source),
		"",
		map[string]string{
			proto.MetadataSourceKey: source,
			proto.MetadataTypeKey:   proto.MetadataTypeConfigChanged,
		},
	)
}

// restartEngineForMDMLocked re-resolves the config of the profile the
// session runs (re-running applyMDMPolicy via Config.apply) and re-spawns
// connectWithRetryRuns. Mirrors the tail of Server.Start so a runtime
// MDM change behaves identically to a fresh boot under the new policy.
// A profile selected without a Down stays selected: the policy change is
// no request to connect it. When no run was alive, running is false and
// the active profile is the one started. The running profile is read as
// stored, without provisioning: it can have been removed since it started,
// and a new identity would bring it back. The run then stays ended.
//
// MUST be called with s.mutex held, so that the re-spawn is one step for
// the RPCs that decide on the run.
func (s *Server) restartEngineForMDMLocked(ss *session, runKey profilemanager.SessionKey, running bool) error {
	key, config, err := s.mdmRestartConfig(ss, runKey, running)
	if err != nil {
		return err
	}
	if err := s.admitRestartLocked(ss); err != nil {
		return err
	}

	s.refreshConfigsAfterRestart(ss, key, config)
	ss.statusRecorder.UpdateManagementAddress(config.ManagementURL.String())
	ss.statusRecorder.UpdateRosenpass(config.RosenpassEnabled, config.RosenpassPermissive)

	ctx, cancel := ss.runContext(s.rootCtx)
	ss.setActCancel(cancel)
	runningChan, giveUpChan := ss.beginRun(key, config)
	log.Info("MDM restart: spawning connectWithRetryRuns with re-resolved config")
	go s.connectWithRetryRuns(ctx, ss, key, config, runningChan, giveUpChan)
	s.publishConfigChangedEvent(ss, proto.MetadataSourceMDM)
	return nil
}

// refreshConfigsAfterRestart replaces the selected config for the new policy. A profile
// selected since the run started stays selected and gets its own config.
func (s *Server) refreshConfigsAfterRestart(ss *session, key profilemanager.SessionKey, config *profilemanager.Config) {
	selectedKey, selected := ss.selectedConfig()
	if selected == nil || sameSessionProfile(selectedKey, key) {
		ss.setConfig(key, config)
		return
	}
	s.refreshSelectedConfig(ss)
}

// refreshSelectedConfig re-reads the selected config, whose overlay the kill switches read,
// for a policy change that did not replace it. An unreadable file must not leave them on the
// old policy, so the new one then goes on a copy of what is there. The overlay cannot be
// undone: what the policy dropped stays until the next load.
func (s *Server) refreshSelectedConfig(ss *session) {
	key, config := ss.selectedConfig()
	if config == nil {
		return
	}
	fresh, err := s.storedRunningConfig(key)
	if err != nil {
		log.Warnf("failed to read the selected profile for the new MDM policy: %v", err)
		overlaid := *config
		overlaid.ApplyMDMPolicy(s.mdmLoader.Load())
		fresh = &overlaid
	}
	ss.setConfig(key, fresh)
}

// lockForStart takes the lifecycle of ss and s.mutex for an RPC that starts a run and needs
// the outcome of an MDM restart in progress, instead of the run that restart is taking down.
// It gives up with ctx.
func (s *Server) lockForStart(ctx context.Context, ss *session) error {
	for {
		if err := ss.awaitRestart(ctx); err != nil {
			return err
		}
		if err := ss.lockLifecycle(ctx); err != nil {
			return err
		}
		s.mutex.Lock()
		if !ss.restarting() {
			return nil
		}
		s.mutex.Unlock()
		ss.unlockLifecycle()
	}
}

func (s *Server) mdmRestartConfig(ss *session, runKey profilemanager.SessionKey, running bool) (profilemanager.SessionKey, *profilemanager.Config, error) {
	// With the gate a session belongs to one profile, the active one has nothing to do with it.
	if !running && s.concurrentProfiles {
		runKey, running = ss.key, true
	}
	if running {
		config, err := s.storedRunningConfig(runKey)
		if err != nil {
			ss.markClientDown()
			return profilemanager.SessionKey{}, nil, fmt.Errorf("get running profile config: %w", err)
		}
		return runKey, config, nil
	}

	activeProf, err := s.profileManager.GetActiveProfileState()
	if err != nil {
		return profilemanager.SessionKey{}, nil, fmt.Errorf("get active profile state: %w", err)
	}
	config, _, err := s.getConfig(activeProf)
	if err != nil {
		return profilemanager.SessionKey{}, nil, fmt.Errorf("get profile config: %w", err)
	}
	return activeProf.SessionKey(), config, nil
}

// mdmManagedFieldConflicts returns the names of MDM-managed keys whose
// requested value in the SetConfigRequest differs from the MDM-enforced
// value. A field set to the same value the policy already enforces is
// treated as a no-op echo (the GUI tray sends a full Config snapshot on
// every toggle, so most fields in a typical request match the policy
// exactly and must NOT be flagged as conflicts). The redacted PSK
// sentinel ("**********") returned by GetConfig is recognised and
// treated as no-op so the UI can safely round-trip it.
func mdmManagedFieldConflicts(msg *proto.SetConfigRequest, policy *mdm.Policy) []string {
	if msg == nil {
		return nil
	}

	pskGot := msg.OptionalPreSharedKey
	if pskGot != nil && *pskGot == mdm.PreSharedKeyRedactedSentinel {
		pskGot = nil
	}

	return mdm.ResolveConflicts(policy, []mdm.ConflictCheck{
		mdm.ConflictURL(mdm.KeyManagementURL, msg.ManagementUrl),
		mdm.ConflictStringPtr(mdm.KeyPreSharedKey, pskGot),
		mdm.ConflictBool(mdm.KeyRosenpassEnabled, msg.RosenpassEnabled),
		mdm.ConflictBool(mdm.KeyRosenpassPermissive, msg.RosenpassPermissive),
		mdm.ConflictBool(mdm.KeyDisableAutoConnect, msg.DisableAutoConnect),
		mdm.ConflictBool(mdm.KeyAllowServerSSH, msg.ServerSSHAllowed),
		mdm.ConflictBool(mdm.KeyRemoteJobsAllowed, msg.RemoteJobsAllowed),
		mdm.ConflictBool(mdm.KeyDisableClientRoutes, msg.DisableClientRoutes),
		mdm.ConflictBool(mdm.KeyDisableServerRoutes, msg.DisableServerRoutes),
		mdm.ConflictBool(mdm.KeyBlockInbound, msg.BlockInbound),
		mdm.ConflictInt64(mdm.KeyWireguardPort, msg.WireguardPort),
		mdm.ConflictBool(mdm.KeyEnableLocalMetrics, msg.EnableLocalMetrics),
		mdm.ConflictStringPtr(mdm.KeyLocalMetricsAddress, msg.LocalMetricsAddress),
	})
}

// loginRequestMDMConflicts mirrors mdmManagedFieldConflicts but for the
// LoginRequest surface. Same value-aware semantics: a field set to the
// MDM-enforced value is a no-op echo, not a conflict; only a divergent
// value is flagged. PSK has two proto fields — PreSharedKey (deprecated)
// and OptionalPreSharedKey (current); either route trips the gate if it
// diverges from the MDM-enforced PSK. OptionalPreSharedKey wins when
// both are set; the redaction sentinel ("**********") is accepted as
// a no-op echo.
func loginRequestMDMConflicts(msg *proto.LoginRequest, policy *mdm.Policy) []string {
	if msg == nil {
		return nil
	}

	pskGot := msg.OptionalPreSharedKey
	if pskGot == nil && msg.PreSharedKey != "" { //nolint:staticcheck // SA1019: legacy proto field still accepted by Login
		pskGot = &msg.PreSharedKey //nolint:staticcheck // SA1019
	}
	if pskGot != nil && *pskGot == mdm.PreSharedKeyRedactedSentinel {
		pskGot = nil
	}

	return mdm.ResolveConflicts(policy, []mdm.ConflictCheck{
		mdm.ConflictURL(mdm.KeyManagementURL, msg.ManagementUrl),
		mdm.ConflictStringPtr(mdm.KeyPreSharedKey, pskGot),
		mdm.ConflictBool(mdm.KeyRosenpassEnabled, msg.RosenpassEnabled),
		mdm.ConflictBool(mdm.KeyRosenpassPermissive, msg.RosenpassPermissive),
		mdm.ConflictBool(mdm.KeyDisableAutoConnect, msg.DisableAutoConnect),
		mdm.ConflictBool(mdm.KeyAllowServerSSH, msg.ServerSSHAllowed),
		mdm.ConflictBool(mdm.KeyRemoteJobsAllowed, msg.RemoteJobsAllowed),
		mdm.ConflictBool(mdm.KeyDisableClientRoutes, msg.DisableClientRoutes),
		mdm.ConflictBool(mdm.KeyDisableServerRoutes, msg.DisableServerRoutes),
		mdm.ConflictBool(mdm.KeyBlockInbound, msg.BlockInbound),
		mdm.ConflictInt64(mdm.KeyWireguardPort, msg.WireguardPort),
		mdm.ConflictBool(mdm.KeyEnableLocalMetrics, msg.EnableLocalMetrics),
		mdm.ConflictStringPtr(mdm.KeyLocalMetricsAddress, msg.LocalMetricsAddress),
	})
}

// rejectMDMManagedFieldConflicts returns a FailedPrecondition gRPC error
// with an MDMManagedFieldsViolation detail when any of the requested
// fields tries to change an MDM-enforced value to something else, and
// nil otherwise. The whole request is rejected on any conflict; non-
// conflicting fields in the same request are not applied either (no
// partial apply).
func rejectMDMManagedFieldConflicts(conflicts []string) error {
	if len(conflicts) == 0 {
		return nil
	}
	log.Warnf("MDM rejected request: tried to modify %d managed key(s): %v",
		len(conflicts), conflicts)
	st := gstatus.New(
		codes.FailedPrecondition,
		fmt.Sprintf("fields managed by MDM cannot be modified: %v", conflicts),
	)
	detailed, err := st.WithDetails(&proto.MDMManagedFieldsViolation{Fields: conflicts})
	if err != nil {
		// Detail attachment is best-effort; fall back to the plain status
		// so the caller still gets a usable FailedPrecondition.
		return st.Err()
	}
	return detailed.Err()
}
