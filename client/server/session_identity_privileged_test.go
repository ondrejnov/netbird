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

	"github.com/netbirdio/netbird/client/internal"
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
	s.rootCtx = internal.CtxInitState(ctx)
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
	s.config = cfgA

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
		running := s.config
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
	running, gaveUp := s.clientRunningChan, s.clientGiveUpChan
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
