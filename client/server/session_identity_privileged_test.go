//go:build privileged

package server

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal/auth"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
)

const identityTestSetupKey = "A2C8E62B-38F5-4553-B31E-DD66C696CEBB"

// retryGapHook runs a step in the retry goroutine itself, right after a failed
// connection attempt and before the next one, so the step needs no sleeping and
// cannot overlap an attempt.
type retryGapHook struct {
	once sync.Once
	step func()
}

func (h *retryGapHook) Levels() []log.Level { return []log.Level{log.DebugLevel} }

func (h *retryGapHook) Fire(entry *log.Entry) error {
	if strings.Contains(entry.Message, "Will retry in the background") {
		h.once.Do(h.step)
	}
	return nil
}

// A profile switch does not stop the running connection, so the retry loop keeps
// going with the config it was started with. Each attempt builds a new connect client,
// and that client must keep using the state file of the profile the config belongs to.
// With the file of the newly active profile, the routes and firewall rules of profile A
// would be recorded where a later restore of profile A never looks, and restoring
// profile B would tear them down.
//
// Everything here is the real path: Up, the retry loop, SwitchProfile, a Management and
// a Signal server, and an engine that writes its state to disk. The only stand-in is how
// the first attempt fails. Run hands an error back to the retry loop only for a config it
// cannot use, or once its own three month backoff runs out, so the test starts from an
// unusable private key and repairs it in the gap between the attempts.
func TestRetryAfterProfileSwitchKeepsStateFileOfRunningProfile(t *testing.T) {
	s, ctx, profileA, username, cfgPathA := setupServerWithProfile(t)
	s.rootCtx = ctx
	dir := filepath.Dir(cfgPathA)

	_, signalAddr, err := startSignal(t)
	require.NoError(t, err)
	logins := 0
	_, mgmtAddr, err := startManagement(t, signalAddr, "../testdata/store.sql", &logins)
	require.NoError(t, err)

	cfgA, err := profilemanager.UpdateOrCreateConfig(profilemanager.ConfigInput{
		ConfigPath:    cfgPathA,
		ManagementURL: "http://" + mgmtAddr,
	})
	require.NoError(t, err)
	registerPeer(t, ctx, cfgA)

	validKey := cfgA.PrivateKey
	cfgA.PrivateKey = "not-a-wireguard-key"
	require.NoError(t, profilemanager.WriteOutConfig(cfgPathA, cfgA))
	s.focusedSession().setConfig(profilemanager.SessionKey{Profile: profilemanager.ID(profileA), Username: username}, cfgA)

	profileB := "profile-b"
	_, err = profilemanager.UpdateOrCreateConfig(profilemanager.ConfigInput{
		ConfigPath:    filepath.Join(dir, profileB+".json"),
		ManagementURL: "http://" + mgmtAddr,
	})
	require.NoError(t, err)

	t.Setenv(retryInitialIntervalVar, "100ms")
	t.Setenv(maxRetryIntervalVar, "200ms")
	t.Setenv(maxRetryTimeVar, "2m")
	t.Setenv(retryMultiplierVar, "1")

	var switchErr error
	switched := make(chan struct{})
	installRetryGapHook(t, func() {
		defer close(switched)

		// The pointer the retry loop holds is the config Up published, read here
		// before SwitchProfile replaces it. This goroutine is the only one reading
		// the key, because no attempt is running.
		s.mutex.Lock()
		running := s.focusedSession().currentConfig()
		s.mutex.Unlock()
		running.PrivateKey = validKey

		_, switchErr = s.SwitchProfile(ctx, &proto.SwitchProfileRequest{
			ProfileName: &profileB,
			Username:    &username,
		})
	})

	_, err = s.Up(ctx, &proto.UpRequest{Async: true})
	require.NoError(t, err)

	s.mutex.Lock()
	running, gaveUp := s.focusedSession().runChans()
	s.mutex.Unlock()

	select {
	case <-running:
	case <-gaveUp:
		t.Fatal("retry loop gave up before the engine came up")
	case <-time.After(90 * time.Second):
		t.Fatal("engine did not come up after the retry")
	}

	<-switched
	require.NoError(t, switchErr)

	active, err := s.profileManager.GetActiveProfileState()
	require.NoError(t, err)
	require.Equal(t, profilemanager.ID(profileB), active.ID, "the switch must have landed before the retry")

	_, err = s.Down(ctx, &proto.DownRequest{})
	require.NoError(t, err)
	select {
	case <-gaveUp:
	case <-time.After(30 * time.Second):
		t.Fatal("retry loop did not exit after Down")
	}

	assert.NoFileExists(t, filepath.Join(dir, profileB+".state.json"),
		"the retry connected the config of profile A with the state file of profile B")
	assert.FileExists(t, filepath.Join(dir, profileA+".state.json"),
		"the engine of profile A must keep its state in the state file of profile A")
}

// switchedSession is a daemon connected on the default profile, with a second profile
// whose Management server is a different one, so a mixup of the two is observable.
type switchedSession struct {
	s         *Server
	ctx       context.Context
	dir       string
	username  string
	work      string
	mgmtAddrA string
	loginsB   *int
}

// startSessionOnDefault brings up a real engine on the default profile. Only the default
// profile's peer is registered, and only with its own Management server.
func startSessionOnDefault(t *testing.T) *switchedSession {
	t.Helper()
	s, ctx, _, username, cfgPath := setupServerWithProfile(t)
	s.rootCtx = ctx
	dir := filepath.Dir(cfgPath)

	_, signalAddr, err := startSignal(t)
	require.NoError(t, err)
	loginsA, loginsB := 0, 0
	_, mgmtAddrA, err := startManagement(t, signalAddr, "../testdata/store.sql", &loginsA)
	require.NoError(t, err)
	_, mgmtAddrB, err := startManagement(t, signalAddr, "../testdata/store.sql", &loginsB)
	require.NoError(t, err)

	cfgDefault, err := profilemanager.UpdateOrCreateConfig(profilemanager.ConfigInput{
		ConfigPath:    profilemanager.DefaultConfigPath,
		ManagementURL: "http://" + mgmtAddrA,
	})
	require.NoError(t, err)
	registerPeer(t, ctx, cfgDefault)

	work := "work"
	_, err = profilemanager.UpdateOrCreateConfig(profilemanager.ConfigInput{
		ConfigPath:    filepath.Join(dir, work+".json"),
		ManagementURL: "http://" + mgmtAddrB,
	})
	require.NoError(t, err)

	defaultKey := profilemanager.SessionKey{Profile: profilemanager.DefaultProfileName}
	require.NoError(t, s.profileManager.SetActiveProfileState(&profilemanager.ActiveProfileState{ID: defaultKey.Profile}))
	s.focusedSession().setConfig(defaultKey, cfgDefault)

	t.Cleanup(func() {
		if _, err := s.Down(ctx, &proto.DownRequest{}); err != nil {
			t.Logf("down during cleanup: %v", err)
		}
	})

	_, err = s.Up(ctx, &proto.UpRequest{Async: true})
	require.NoError(t, err)

	st := &switchedSession{s: s, ctx: ctx, dir: dir, username: username, work: work, mgmtAddrA: mgmtAddrA, loginsB: &loginsB}
	st.waitForEngine(t)
	return st
}

func (st *switchedSession) waitForEngine(t *testing.T) {
	t.Helper()
	running, gaveUp := st.s.focusedSession().runChans()
	select {
	case <-running:
	case <-gaveUp:
		t.Fatal("retry loop gave up before the engine came up")
	case <-time.After(90 * time.Second):
		t.Fatal("engine did not come up")
	}
}

func (st *switchedSession) selectWork(t *testing.T) {
	t.Helper()
	_, err := st.s.SwitchProfile(st.ctx, &proto.SwitchProfileRequest{ProfileName: &st.work, Username: &st.username})
	require.NoError(t, err)

	active, err := st.s.profileManager.GetActiveProfileState()
	require.NoError(t, err)
	require.Equal(t, profilemanager.ID(st.work), active.ID, "the switch must have landed before the policy change")
}

func (st *switchedSession) requireRunsDefault(t *testing.T) {
	t.Helper()
	assert.Equal(t, st.mgmtAddrA, st.s.focusedSession().connectionConfig().ManagementURL.Host,
		"the connection must keep the config of the default profile")
	key, running := st.s.focusedSession().runningKey()
	assert.True(t, running, "the session must run")
	assert.Equal(t, profilemanager.ID(profilemanager.DefaultProfileName), key.Profile, "the run must stay on the default profile")

	st.waitForEngine(t)

	assert.Equal(t, 0, *st.loginsB, "the Management server of the selected profile must not be contacted")
	assert.NoFileExists(t, filepath.Join(st.dir, st.work+".state.json"), "the run wrote the state file of the selected profile")
	assert.FileExists(t, filepath.Join(st.dir, "state.json"), "the engine of default must keep its state in the file of default")
}

// A policy change restarts what runs. The session runs on default, work is only selected
// because no Down followed the switch, and connecting work now would be a connection
// nobody asked for, dropping the one the user has.
func TestMDMRestartAfterSwitchKeepsRunningProfile(t *testing.T) {
	st := startSessionOnDefault(t)
	st.selectWork(t)

	require.NoError(t, st.s.onMDMPolicyChange(nil, nil))

	st.requireRunsDefault(t)
}

// The restart keeps the selection, so the config and the client stay two profiles and a session
// extend stays refused until the selection goes back or a Down follows.
func TestMDMRestartAfterSwitchKeepsSelectionAndRefusesExtend(t *testing.T) {
	st := startSessionOnDefault(t)
	st.selectWork(t)

	require.NoError(t, st.s.onMDMPolicyChange(nil, nil))
	st.waitForEngine(t)

	key, _ := st.s.focusedSession().selectedConfig()
	assert.Equal(t, profilemanager.ID(st.work), key.Profile, "the restart must not move the selection")

	ctx, cancel := context.WithTimeout(st.ctx, 10*time.Second)
	t.Cleanup(cancel)
	_, err := st.s.RequestExtendAuthSession(ctx, &proto.RequestExtendAuthSessionRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, gstatus.Code(err), "config and client are two profiles: %v", err)
}

// Without a switch a policy change restarts the same profile, as it always did.
func TestMDMRestartWithoutSwitchKeepsProfile(t *testing.T) {
	st := startSessionOnDefault(t)

	require.NoError(t, st.s.onMDMPolicyChange(nil, nil))

	st.requireRunsDefault(t)
}

// With the retry goroutine gone nothing runs, so the restart follows the active profile as
// it does today. A Login that took over ends up here, once it cancelled the old run.
func TestMDMRestartWithRunOverFollowsActiveProfile(t *testing.T) {
	s, ctx, activeProfile, username, cfgPath := setupServerWithProfile(t)
	s.rootCtx = ctx
	t.Setenv(retryInitialIntervalVar, "100ms")

	_, err := profilemanager.UpdateOrCreateConfig(profilemanager.ConfigInput{
		ConfigPath:    cfgPath,
		ManagementURL: unreachableManagementURL,
	})
	require.NoError(t, err)

	_, giveUp := s.focusedSession().beginRun(profilemanager.SessionKey{Profile: profilemanager.DefaultProfileName}, nil)
	close(giveUp)

	require.NoError(t, s.onMDMPolicyChange(nil, nil))
	t.Cleanup(func() {
		s.focusedSession().cancelAct()
		_, restartedGiveUp := s.focusedSession().runChans()
		<-restartedGiveUp
	})

	key, running := s.focusedSession().runningKey()
	assert.True(t, running, "the policy change must have started a new run")
	assert.Equal(t, profilemanager.SessionKey{Profile: profilemanager.ID(activeProfile), Username: username}, key,
		"the finished run must not decide the profile")
}

// Between a switch and a Down the session config is work's and the client is default's.
// A flow built from that config would obtain a token from work's IdP and hand it to the
// engine of default, so it is refused before the IdP is involved.
func TestExtendAuthSessionRefusedWhileAnotherProfileIsSelected(t *testing.T) {
	st := startSessionOnDefault(t)
	st.selectWork(t)

	ctx, cancel := context.WithTimeout(st.ctx, 10*time.Second)
	t.Cleanup(cancel)
	_, err := st.s.RequestExtendAuthSession(ctx, &proto.RequestExtendAuthSessionRequest{})

	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, gstatus.Code(err), "want the profile mismatch refusal, got %v", err)
	_, _, pending := st.s.focusedSession().extendAuthSessionFlow.Get()
	assert.False(t, pending, "a refused request must not leave a flow behind")
}

// The SSH token flow is refused the same way, on a real run.
func TestJWTAuthRefusedWhileAnotherProfileIsSelected(t *testing.T) {
	st := startSessionOnDefault(t)
	st.selectWork(t)

	ctx, cancel := context.WithTimeout(st.ctx, 10*time.Second)
	t.Cleanup(cancel)
	_, err := st.s.RequestJWTAuth(ctx, &proto.RequestJWTAuthRequest{})

	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, gstatus.Code(err), "want the profile mismatch refusal, got %v", err)
	assert.Zero(t, *st.loginsB, "the Management server of the selected profile must not be contacted")
}

// The status of a real run keeps showing its own Management after a switch.
func TestStatusShowsManagementOfTheRunAfterSwitch(t *testing.T) {
	st := startSessionOnDefault(t)
	st.selectWork(t)

	resp, err := st.s.Status(st.ctx, &proto.StatusRequest{GetFullPeerStatus: true})
	require.NoError(t, err)
	assert.Contains(t, resp.GetFullStatus().GetManagementState().GetURL(), st.mgmtAddrA,
		"status should show the Management of the running profile")
	assert.True(t, resp.GetFullStatus().GetManagementState().GetConnected(), "the run should stay connected")
}

// Switching back makes the config and the client one profile again.
func TestExtendAuthSessionAllowedAfterSwitchingBack(t *testing.T) {
	st := startSessionOnDefault(t)
	st.selectWork(t)

	defaultName := profilemanager.DefaultProfileName
	_, err := st.s.SwitchProfile(st.ctx, &proto.SwitchProfileRequest{ProfileName: &defaultName, Username: &st.username})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(st.ctx, 10*time.Second)
	t.Cleanup(cancel)
	_, err = st.s.RequestExtendAuthSession(ctx, &proto.RequestExtendAuthSessionRequest{})
	require.Error(t, err, "the test Management has no IdP, so a passed gate ends at the flow creation")
	assert.NotEqual(t, codes.FailedPrecondition, gstatus.Code(err), "config and client are one profile: %v", err)
}

func registerPeer(t *testing.T, ctx context.Context, cfg *profilemanager.Config) {
	t.Helper()

	authClient, err := auth.NewAuth(ctx, cfg.PrivateKey, cfg.ManagementURL, cfg)
	require.NoError(t, err)
	defer authClient.Close()

	err, _ = authClient.Login(ctx, identityTestSetupKey, "")
	require.NoError(t, err)
}

func installRetryGapHook(t *testing.T, step func()) {
	t.Helper()

	origLevel := log.GetLevel()
	log.SetLevel(log.DebugLevel)

	hooks := make(log.LevelHooks)
	hooks.Add(&retryGapHook{step: step})
	origHooks := log.StandardLogger().ReplaceHooks(hooks)

	t.Cleanup(func() {
		log.StandardLogger().ReplaceHooks(origHooks)
		log.SetLevel(origLevel)
	})
}
