//go:build !android && !ios

package server

import (
	"archive/zip"
	"context"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/auth"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/mdm"
	"github.com/netbirdio/netbird/client/proto"
)

const (
	runManagementURL      = "http://run.example:1"
	selectedManagementURL = "http://selected.example:2"
)

// switchedRun is a daemon whose run belongs to one profile and whose selection has moved to
// another, as a `profile select` without a Down leaves it. Each config has a Management URL
// of its own, so a mixup of the two is observable.
type switchedRun struct {
	f           *residualFixture
	s           *Server
	runKey      profilemanager.SessionKey
	selectedKey profilemanager.SessionKey
	run         *profilemanager.Config
	selected    *profilemanager.Config
	giveUp      chan struct{}
}

func testManagementConfig(t *testing.T, rawURL string) *profilemanager.Config {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	require.NoError(t, err)
	return &profilemanager.Config{ManagementURL: parsed}
}

func newSwitchedRun(t *testing.T) *switchedRun {
	t.Helper()
	f := newResidualFixture(t)
	r := &switchedRun{
		f:           f,
		s:           f.s,
		runKey:      f.active,
		selectedKey: f.other,
		run:         testManagementConfig(t, runManagementURL),
		selected:    testManagementConfig(t, selectedManagementURL),
	}
	r.s.focusedSession().setConfig(r.runKey, r.run)
	_, r.giveUp = r.s.focusedSession().beginRun(r.runKey, r.run)
	r.s.focusedSession().setConfig(r.selectedKey, r.selected)
	return r
}

// Without a switch during the run the operations must see what they always saw, including a
// config a Login resolved after the run started. Only a run of another profile changes it.
func TestConnectionConfig(t *testing.T) {
	work := profilemanager.SessionKey{Profile: "work", Username: "user"}
	other := profilemanager.SessionKey{Profile: "other", Username: "user"}
	client := newDummyConnectClient(internal.CtxInitState(context.Background()))

	tests := []struct {
		name    string
		prepare func(ss *session, run, selected *profilemanager.Config)
		wantRun bool
	}{
		{
			name: "nothing ever ran",
			prepare: func(ss *session, _, selected *profilemanager.Config) {
				ss.setConfig(work, selected)
			},
		},
		{
			name: "the run and the selection are one profile",
			prepare: func(ss *session, run, selected *profilemanager.Config) {
				ss.beginRun(work, run)
				ss.setConfig(work, selected)
			},
		},
		{
			name: "default is one profile for every user",
			prepare: func(ss *session, run, selected *profilemanager.Config) {
				ss.beginRun(profilemanager.SessionKey{Profile: profilemanager.DefaultProfileName, Username: "user"}, run)
				ss.setConfig(profilemanager.SessionKey{Profile: profilemanager.DefaultProfileName}, selected)
			},
		},
		{
			name: "another profile has a live run",
			prepare: func(ss *session, run, selected *profilemanager.Config) {
				ss.beginRun(work, run)
				ss.setConfig(other, selected)
			},
			wantRun: true,
		},
		{
			name: "another profile gave up and its client stays published",
			prepare: func(ss *session, run, selected *profilemanager.Config) {
				_, giveUp := ss.beginRun(work, run)
				ss.setClient(client)
				close(giveUp)
				ss.setConfig(other, selected)
			},
			wantRun: true,
		},
		{
			name: "another profile's run is being restarted",
			prepare: func(ss *session, run, selected *profilemanager.Config) {
				_, giveUp := ss.beginRun(work, run)
				ss.setConfig(other, selected)
				_, ok := ss.beginRestart()
				require.True(t, ok)
				close(giveUp)
			},
			wantRun: true,
		},
		{
			name: "another profile's run ended with a Down",
			prepare: func(ss *session, run, selected *profilemanager.Config) {
				_, giveUp := ss.beginRun(work, run)
				ss.setClient(client)
				ss.setConfig(other, selected)
				ss.markClientDown()
				ss.setClient(nil)
				close(giveUp)
			},
		},
		{
			name: "another profile's run gave up without a client",
			prepare: func(ss *session, run, selected *profilemanager.Config) {
				_, giveUp := ss.beginRun(work, run)
				close(giveUp)
				ss.setConfig(other, selected)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ss := newSession()
			run, selected := &profilemanager.Config{}, &profilemanager.Config{}
			tt.prepare(ss, run, selected)

			want := selected
			if tt.wantRun {
				want = run
			}
			assert.Same(t, want, ss.connectionConfig(), "the config the connection is described with")
			assert.Same(t, selected, ss.currentConfig(), "the selected config must stay the selected one")
		})
	}
}

// `netbird status` reports on the connection. Before the separation it showed the Management
// of the selected profile next to the peers of the running one.
func TestStatus_DescribesTheRunWhileAnotherProfileIsSelected(t *testing.T) {
	r := newSwitchedRun(t)
	r.run.RosenpassEnabled = true

	resp, err := r.s.Status(context.Background(), &proto.StatusRequest{GetFullPeerStatus: true})
	require.NoError(t, err)

	assert.Equal(t, runManagementURL, resp.GetFullStatus().GetManagementState().GetURL(),
		"status should show the Management of the running profile")
	assert.True(t, resp.GetFullStatus().GetLocalPeerState().GetRosenpassEnabled(),
		"status should show the Rosenpass setting of the running profile")

	// With the run gone the selected profile is what the next Up connects.
	r.s.focusedSession().markClientDown()
	close(r.giveUp)
	resp, err = r.s.Status(context.Background(), &proto.StatusRequest{GetFullPeerStatus: true})
	require.NoError(t, err)
	assert.Equal(t, selectedManagementURL, resp.GetFullStatus().GetManagementState().GetURL(),
		"after the run the status should show the selected profile")
}

func bundleEntry(t *testing.T, path, name string) string {
	t.Helper()
	archive, err := zip.OpenReader(path)
	require.NoError(t, err)
	defer func() { assert.NoError(t, archive.Close()) }()

	file, err := archive.Open(name)
	require.NoError(t, err, "the bundle should contain %s", name)
	defer func() { assert.NoError(t, file.Close()) }()
	content, err := io.ReadAll(file)
	require.NoError(t, err)
	return string(content)
}

// The status, sync response and metrics of a bundle describe the running client, and the
// upload goes to the deployment of that client, so config and state have to match them.
func TestDebugBundle_DescribesTheRunWhileAnotherProfileIsSelected(t *testing.T) {
	r := newSwitchedRun(t)
	require.NoError(t, os.WriteFile(r.f.statePath(r.runKey), []byte(`{"marker_of_the_run":{}}`), 0o600))
	require.NoError(t, os.WriteFile(r.f.statePath(r.selectedKey), []byte(`{"marker_of_the_selection":{}}`), 0o600))
	require.NoError(t, os.WriteFile(r.f.statePath(r.runKey)+".corrupted.1", []byte(`damaged`), 0o600))

	path, managementURL, err := r.s.generateDebugBundle(r.s.focusedSession(), &proto.DebugBundleRequest{}, nil, bundleScope{})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, os.Remove(path)) })

	assert.Equal(t, runManagementURL, managementURL, "the upload should identify the running deployment")
	config := bundleEntry(t, path, "config.txt")
	assert.Contains(t, config, runManagementURL, "the bundle should carry the config of the run")
	assert.NotContains(t, config, selectedManagementURL, "the bundle must not carry the config of the selection")
	assert.Contains(t, bundleEntry(t, path, "state.json"), "marker_of_the_run", "the bundle should carry the state of the run")
	corrupted := "corrupted_states/" + filepath.Base(r.f.statePath(r.runKey)) + ".corrupted.1"
	assert.Equal(t, "damaged", bundleEntry(t, path, corrupted), "the bundle should carry the damaged state of the run")
}

// With no switch the bundle stays on the active profile's state file, as it always did.
func TestDebugBundle_WithoutSwitchKeepsTheActiveState(t *testing.T) {
	f := newResidualFixture(t)
	config := testManagementConfig(t, runManagementURL)
	f.s.focusedSession().setConfig(f.active, config)
	f.s.focusedSession().beginRun(f.active, config)
	require.NoError(t, os.WriteFile(f.statePath(f.active), []byte(`{"marker_of_the_active":{}}`), 0o600))

	path, managementURL, err := f.s.generateDebugBundle(f.s.focusedSession(), &proto.DebugBundleRequest{}, nil, bundleScope{})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, os.Remove(path)) })

	assert.Equal(t, runManagementURL, managementURL, "the upload should identify the deployment")
	assert.Contains(t, bundleEntry(t, path, "state.json"), "marker_of_the_active", "the state file should stay the active one")
}

// Networks are those of the running engine, profiles and settings are what the selection
// addresses. The two configs normally carry the same policy, these tell which one is read.
func TestKillSwitches_ReadTheConfigOfTheirOperation(t *testing.T) {
	r := newSwitchedRun(t)
	allDisabled := mdm.NewPolicy(map[string]any{
		mdm.KeyDisableNetworks:       true,
		mdm.KeyDisableProfiles:       true,
		mdm.KeyDisableUpdateSettings: true,
		mdm.KeyDisableAdvancedView:   true,
	})

	r.run.ApplyMDMPolicy(allDisabled)
	r.selected.ApplyMDMPolicy(mdm.NewPolicy(nil))
	assert.True(t, r.s.checkNetworksDisabled(), "networks should follow the policy of the run")
	assert.False(t, r.s.checkProfilesDisabled(), "profiles should follow the policy of the selection")
	assert.False(t, r.s.checkUpdateSettingsDisabled(), "settings should follow the policy of the selection")
	assert.Nil(t, r.s.checkDisableAdvancedView(), "the advanced view should follow the policy of the selection")

	r.run.ApplyMDMPolicy(mdm.NewPolicy(nil))
	r.selected.ApplyMDMPolicy(allDisabled)
	assert.False(t, r.s.checkNetworksDisabled(), "networks should follow the policy of the run")
	assert.True(t, r.s.checkProfilesDisabled(), "profiles should follow the policy of the selection")
	assert.True(t, r.s.checkUpdateSettingsDisabled(), "settings should follow the policy of the selection")
	assert.NotNil(t, r.s.checkDisableAdvancedView(), "the advanced view should follow the policy of the selection")
}

// The session that expired is the one of the connection, and it is that profile's setting
// that decides about the notification.
func TestSessionExpire_ReadsTheSettingOfTheRun(t *testing.T) {
	r := newSwitchedRun(t)
	notify, silent := false, true
	r.run.DisableNotifications = &notify
	r.selected.DisableNotifications = &silent
	assert.True(t, r.s.sessionExpireNotifies(r.s.focusedSession()), "the running profile asked for notifications")

	r.run.DisableNotifications = &silent
	r.selected.DisableNotifications = &notify
	assert.False(t, r.s.sessionExpireNotifies(r.s.focusedSession()), "the running profile turned notifications off")
}

// A switch landing inside a Login must not send the peer key of one profile to the Management
// of another: the probe and the attempt use the config the Login resolved.
func TestLogin_StaysOnItsProfileWhenTheSelectionMoves(t *testing.T) {
	f := newResidualFixture(t)
	s := f.s
	f.s.rootCtx = context.Background()
	key := "setup-key"
	var probed, attempted *profilemanager.Config

	moved := testManagementConfig(t, selectedManagementURL)
	s.isLoginRequiredFn = func(_ context.Context, config *profilemanager.Config) (bool, error) {
		probed = config
		s.focusedSession().setConfig(f.other, moved)
		return true, nil
	}
	s.loginAttemptFn = func(_ context.Context, config *profilemanager.Config, _, _ string) (internal.StatusType, error) {
		attempted = config
		return "", nil
	}

	_, err := s.Login(f.ctx, &proto.LoginRequest{SetupKey: key})
	require.NoError(t, err)

	require.NotNil(t, probed, "the login should have probed Management")
	assert.NotSame(t, moved, probed, "the probe should stay on the profile of the login")
	assert.Same(t, probed, attempted, "the attempt should use the config the login resolved")
}

// The IdP answered for the profile the flow was created for. If the selection moved away while
// it was polled, the token still goes to that profile's Management and no other.
func TestWaitSSOLogin_LogsInToTheProfileOfTheFlow(t *testing.T) {
	s := newTestServer()
	flowKey := profilemanager.SessionKey{Profile: "work", Username: "user"}
	flowConfig := testManagementConfig(t, runManagementURL)
	moved := testManagementConfig(t, selectedManagementURL)
	s.focusedSession().setConfig(flowKey, flowConfig)

	var attempted *profilemanager.Config
	s.loginAttemptFn = func(_ context.Context, config *profilemanager.Config, _, _ string) (internal.StatusType, error) {
		attempted = config
		return "", nil
	}
	s.focusedSession().swapOAuthFlow(oauthAuthFlow{
		flow: &stubOAuthFlow{onWait: func() {
			s.focusedSession().setConfig(profilemanager.SessionKey{Profile: "other", Username: "user"}, moved)
		}},
		info:   auth.AuthFlowInfo{UserCode: "code"},
		key:    flowKey,
		config: flowConfig,
	})

	_, err := s.WaitSSOLogin(context.Background(), &proto.WaitSSOLoginRequest{UserCode: "code"})
	require.NoError(t, err)
	assert.Same(t, flowConfig, attempted, "the token should go to the profile of the flow")
}

// Without a switch the attempt reads the latest config of the profile, as it always did: a
// Login can have resolved a newer one after the flow was created.
func TestWaitSSOLogin_WithoutSwitchUsesTheLatestConfig(t *testing.T) {
	s := newTestServer()
	key := profilemanager.SessionKey{Profile: "work", Username: "user"}
	flowConfig := testManagementConfig(t, runManagementURL)
	latest := testManagementConfig(t, selectedManagementURL)
	s.focusedSession().setConfig(key, latest)

	var attempted *profilemanager.Config
	s.loginAttemptFn = func(_ context.Context, config *profilemanager.Config, _, _ string) (internal.StatusType, error) {
		attempted = config
		return "", nil
	}
	s.focusedSession().swapOAuthFlow(oauthAuthFlow{
		flow:   &stubOAuthFlow{},
		info:   auth.AuthFlowInfo{UserCode: "code"},
		key:    key,
		config: flowConfig,
	})

	_, err := s.WaitSSOLogin(context.Background(), &proto.WaitSSOLoginRequest{UserCode: "code"})
	require.NoError(t, err)
	assert.Same(t, latest, attempted, "the attempt should use the latest config of the profile")
}

// The same refusal as RequestExtendAuthSession: the flow would come from the IdP of the
// selection, and the SSH peers it is for belong to the run.
func TestRequestJWTAuth_RefusedWhileAnotherProfileRuns(t *testing.T) {
	r := newSwitchedRun(t)

	_, err := r.s.RequestJWTAuth(context.Background(), &proto.RequestJWTAuthRequest{})

	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, gstatus.Code(err), "want the profile mismatch refusal, got %v", err)
	assert.Nil(t, r.s.focusedSession().oauthFlow().flow, "a refused request must not leave a flow behind")
}

// A published client of another profile counts as well: it can come back on the next retry,
// and RequestExtendAuthSession refuses on the client too.
func TestRequestJWTAuth_RefusedWhileAnotherProfilesClientIsPublished(t *testing.T) {
	r := newSwitchedRun(t)
	r.s.focusedSession().setClient(newDummyConnectClient(internal.CtxInitState(context.Background())))
	close(r.giveUp)

	_, err := r.s.RequestJWTAuth(context.Background(), &proto.RequestJWTAuthRequest{})

	assert.Equal(t, codes.FailedPrecondition, gstatus.Code(err), "want the profile mismatch refusal, got %v", err)
}

// `netbird ssh` obtains its token with no run as well, and without a switch nothing refuses.
// The Management here is unreachable, so a passed gate ends at the flow creation.
func TestRequestJWTAuth_PassesWithoutSwitch(t *testing.T) {
	tests := []struct {
		name  string
		start func(f *residualFixture, config *profilemanager.Config)
	}{
		{name: "no run", start: func(*residualFixture, *profilemanager.Config) {}},
		{name: "the selected profile runs", start: func(f *residualFixture, config *profilemanager.Config) {
			f.s.focusedSession().beginRun(f.active, config)
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newResidualFixture(t)
			config, err := f.s.storedRunningConfig(f.active)
			require.NoError(t, err)
			f.s.focusedSession().setConfig(f.active, config)
			tt.start(f, config)

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_, err = f.s.RequestJWTAuth(ctx, &proto.RequestJWTAuthRequest{})

			require.Error(t, err, "the test Management is unreachable")
			assert.NotEqual(t, codes.FailedPrecondition, gstatus.Code(err), "nothing should refuse this request: %v", err)
		})
	}
}

// countingManagement counts the connections a deregistration would open.
func countingManagement(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, listener.Close()) })

	var connections atomic.Int32
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			connections.Add(1)
			_ = conn.Close()
		}
	}()
	return "http://" + listener.Addr().String(), &connections
}

// removalFixture is a daemon with a profile to remove, whose Management counts connections.
func removalFixture(t *testing.T) (*residualFixture, string, *atomic.Int32) {
	t.Helper()
	f := newResidualFixture(t)
	managementURL, connections := countingManagement(t)

	path := filepath.Join(profilemanager.DefaultConfigPathDir, string(f.other.Profile)+".json")
	_, err := profilemanager.UpdateOrCreateConfig(profilemanager.ConfigInput{ConfigPath: path, ManagementURL: managementURL})
	require.NoError(t, err)
	return f, path, connections
}

func removeOther(t *testing.T, f *residualFixture) error {
	t.Helper()
	// Bounded, as the deregistration of an allowed removal never gets an answer.
	ctx, cancel := context.WithTimeout(f.ctx, 2*time.Second)
	defer cancel()
	_, err := f.s.RemoveProfile(ctx, &proto.RemoveProfileRequest{
		ProfileName: string(f.other.Profile),
		Username:    f.other.Username,
	})
	return err
}

// Removing the running profile would take its config and identity away from a live run. The
// refusal comes before the deregistration, which cannot be undone.
func TestRemoveProfile_RefusesTheRunningProfile(t *testing.T) {
	tests := []struct {
		name  string
		start func(f *residualFixture)
	}{
		{name: "the selection moved away from the run", start: func(f *residualFixture) {
			f.s.focusedSession().beginRun(f.other, nil)
		}},
		{name: "a restart is replacing the run", start: func(f *residualFixture) {
			_, giveUp := f.s.focusedSession().beginRun(f.other, nil)
			_, ok := f.s.focusedSession().beginRestart()
			require.True(t, ok)
			close(giveUp)
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, path, connections := removalFixture(t)
			tt.start(f)

			err := removeOther(t, f)

			require.Error(t, err)
			assert.Equal(t, codes.FailedPrecondition, gstatus.Code(err), "want the refusal for a running profile, got %v", err)
			assert.FileExists(t, path, "a refused removal must keep the profile")
			assert.Zero(t, connections.Load(), "a refused removal must not deregister the peer")
		})
	}
}

// A profile that does not run stays removable, also after its run ended.
func TestRemoveProfile_AllowsAProfileThatDoesNotRun(t *testing.T) {
	tests := []struct {
		name  string
		start func(f *residualFixture)
	}{
		{name: "nothing runs", start: func(*residualFixture) {}},
		{name: "another profile runs", start: func(f *residualFixture) {
			f.s.focusedSession().beginRun(f.active, nil)
		}},
		{name: "its run was taken down", start: func(f *residualFixture) {
			_, giveUp := f.s.focusedSession().beginRun(f.other, nil)
			f.s.focusedSession().markClientDown()
			close(giveUp)
		}},
		{name: "its run gave up", start: func(f *residualFixture) {
			_, giveUp := f.s.focusedSession().beginRun(f.other, nil)
			close(giveUp)
		}},
		{name: "a namesake of another user runs", start: func(f *residualFixture) {
			f.s.focusedSession().beginRun(profilemanager.SessionKey{Profile: f.other.Profile, Username: "someone-else"}, nil)
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, path, connections := removalFixture(t)
			tt.start(f)

			require.NoError(t, removeOther(t, f))

			assert.NoFileExists(t, path, "the profile should be removed")
			assert.NotZero(t, connections.Load(), "the removal should have tried to deregister the peer")
		})
	}
}

// A policy change restarts the run and is no request to change the selection: the selected
// profile keeps its own config, read again for the new policy.
func TestMDMRestart_KeepsTheSelectionWithItsOwnConfig(t *testing.T) {
	p := startParkedRestart(t)
	s, f := p.f.s, p.f
	selected, err := s.storedRunningConfig(f.other)
	require.NoError(t, err)
	s.focusedSession().setConfig(f.other, selected)

	withMDMPolicy(t, s, mdm.NewPolicy(map[string]any{
		mdm.KeyDisableProfiles: true,
		mdm.KeyDisableNetworks: true,
	}))
	p.endRun()
	require.NoError(t, p.waitRestarted(t))

	key, config := s.focusedSession().selectedConfig()
	assert.Equal(t, f.other, key, "the selection should stay on its profile")
	assert.NotSame(t, selected, config, "the selected config should be read again")
	assert.True(t, s.checkProfilesDisabled(), "the selected config should carry the new policy")

	running, alive := s.focusedSession().runningKey()
	assert.True(t, alive, "the restart should have brought the run back")
	assert.Equal(t, f.active, running, "the run should stay on its profile")
	assert.NotSame(t, config, s.focusedSession().connectionConfig(), "the run should keep a config of its own")
	assert.True(t, s.checkNetworksDisabled(), "the config of the run should carry the new policy")
}

// A selected profile that cannot be read must not keep the kill switches on the old policy.
func TestMDMRestart_UnreadableSelectionStillGetsThePolicy(t *testing.T) {
	p := startParkedRestart(t)
	s, f := p.f.s, p.f
	selected, err := s.storedRunningConfig(f.other)
	require.NoError(t, err)
	s.focusedSession().setConfig(f.other, selected)

	path, err := profileStateOf(f.other).FilePath()
	require.NoError(t, err)
	require.NoError(t, os.Remove(path))

	withMDMPolicy(t, s, mdm.NewPolicy(map[string]any{mdm.KeyDisableProfiles: true}))
	p.endRun()
	require.NoError(t, p.waitRestarted(t))

	assert.True(t, s.checkProfilesDisabled(), "the kill switches should see the new policy")
	key, _ := s.focusedSession().selectedConfig()
	assert.Equal(t, f.other, key, "the selection should stay where it was")
}
