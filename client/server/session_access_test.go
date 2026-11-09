package server

import (
	"archive/zip"
	"context"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/auth"
	"github.com/netbirdio/netbird/client/internal/hostcoord"
	"github.com/netbirdio/netbird/client/internal/ipcauth"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/util/capture"
)

// High enough not to be the user the tests run as, which a daemon that is not root delegates to.
const (
	aliceUID uint32 = 20001
	bobUID   uint32 = 20002
)

// selectorRPCCount is the number of RPCs with a selector. A new one has to join selectorRPCs.
const selectorRPCCount = 24

// accessFixture is a daemon with the gate on, a profile each owned by alice and bob next to the
// default profile nobody has claimed, and the four callers an RPC can have.
type accessFixture struct {
	*gateFixture
	alice  profilemanager.SessionKey
	bob    profilemanager.SessionKey
	shared profilemanager.SessionKey
}

func newAccessFixture(t *testing.T) *accessFixture {
	t.Helper()
	t.Setenv("TMPDIR", t.TempDir())

	f := newGateFixture(t)
	f.s.captureEnabled = true

	dir := profilemanager.DefaultConfigPathDir
	require.NoError(t, profilemanager.StampOwner(filepath.Join(dir, string(f.second.Profile)+".json"), aliceIdentity()))
	require.NoError(t, profilemanager.StampOwner(filepath.Join(dir, string(f.third.Profile)+".json"), bobIdentity()))

	return &accessFixture{
		gateFixture: f,
		alice:       f.second,
		bob:         f.third,
		shared:      profilemanager.SessionKey{Profile: profilemanager.DefaultProfileName},
	}
}

// ownDefaultProfile records owner on the default profile, creating it when it is not there yet.
func ownDefaultProfile(t *testing.T, owner ipcauth.Identity) {
	t.Helper()
	if _, err := os.Stat(profilemanager.DefaultConfigPath); err == nil {
		require.NoError(t, profilemanager.StampOwner(profilemanager.DefaultConfigPath, owner))
		return
	}
	_, err := profilemanager.UpdateOrCreateConfig(profilemanager.ConfigInput{
		ConfigPath:    profilemanager.DefaultConfigPath,
		ManagementURL: "http://127.0.0.1:1",
		Owner:         &owner,
	})
	require.NoError(t, err)
}

func aliceIdentity() ipcauth.Identity {
	return ipcauth.KnownForTest(ipcauth.Identity{UID: aliceUID, GID: aliceUID})
}

func bobIdentity() ipcauth.Identity {
	return ipcauth.KnownForTest(ipcauth.Identity{UID: bobUID, GID: bobUID})
}

func aliceCtx() context.Context { return ctxWithIdentity(aliceIdentity()) }

func bobCtx() context.Context { return ctxWithIdentity(bobIdentity()) }

// unknownCtx is a caller on a control channel that carries no identity.
func unknownCtx() context.Context { return context.Background() }

func selectorOf(key profilemanager.SessionKey) *proto.SessionSelector {
	return &proto.SessionSelector{Profile: string(key.Profile), Username: key.Username}
}

// requireRefusedAsForeign checks a refusal, whether the gate or the handler gave it.
func requireRefusedAsForeign(t *testing.T, err error, msgAndArgs ...any) {
	t.Helper()
	require.Error(t, err, msgAndArgs...)
	require.Equal(t, codes.PermissionDenied, gstatus.Code(err), "unexpected status: %v", err)
}

// cancelledCopy keeps the identity of ctx and makes a handler that got past the check return early:
// the table asks only who gets through, and a real wait or network call would stall it.
func cancelledCopy(ctx context.Context) context.Context {
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	return cancelled
}

// Who may reach what, for every RPC with a selector, behind the authorization gate. The owner
// recorded in the profile decides; the default profile nobody has claimed is root's alone.
func TestSessionAccess_EveryRPCWithASelector(t *testing.T) {
	f := newAccessFixture(t)

	callers := []struct {
		name    string
		ctx     context.Context
		reaches map[string]bool
	}{
		{"alice", aliceCtx(), map[string]bool{"alice": true}},
		{"bob", bobCtx(), map[string]bool{"bob": true}},
		{"root", rootCtx(), map[string]bool{"alice": true, "bob": true, "shared": true}},
		{"unknown", unknownCtx(), map[string]bool{}},
	}
	targets := map[string]profilemanager.SessionKey{"alice": f.alice, "bob": f.bob, "shared": f.shared}

	for _, caller := range callers {
		for targetName, target := range targets {
			calls := gatedSelectorRPCs(f.s, cancelledCopy(caller.ctx), selectorOf(target))
			require.Len(t, calls, selectorRPCCount, "every RPC with a selector should be in the table")
			for rpc, call := range calls {
				t.Run(caller.name+"/"+targetName+"/"+rpc, func(t *testing.T) {
					err := call()
					if caller.reaches[targetName] {
						assert.NotEqual(t, codes.PermissionDenied, gstatus.Code(err), "%s should get through: %v", caller.name, err)
						if err != nil {
							assert.NotContains(t, err.Error(), errSelectorNotFocused)
						}
						return
					}
					requireRefusedAsForeign(t, err, "%s must not reach the session of %s", caller.name, targetName)
				})
			}
		}
	}
}

// A refused request leaves the session as it was, whichever RPC it was.
func TestSessionAccess_RefusalHasNoEffect(t *testing.T) {
	f := newAccessFixture(t)
	require.NoError(t, f.up(f.alice))
	aliceSession := f.session(f.alice)
	client := aliceSession.client()

	for rpc, call := range gatedSelectorRPCs(f.s, cancelledCopy(bobCtx()), selectorOf(f.alice)) {
		requireRefusedAsForeign(t, call(), rpc)
		assert.Same(t, client, aliceSession.client(), "%s must leave the client", rpc)
		assert.True(t, aliceSession.isClientRunning(), "%s must leave the run", rpc)
		assert.Equal(t, internal.StatusConnected, aliceSession.state.CurrentStatus(), rpc)
		assert.Equal(t, hostcoord.DesiredUp, f.stored(t)[f.alice], rpc)
	}
	assert.Equal(t, 1, f.runCount(f.alice))
}

// The username a selector carries is left over from per-user directories and decides nothing.
func TestSessionAccess_SelectorUsernameDecidesNothing(t *testing.T) {
	f := newAccessFixture(t)
	selector := &proto.SessionSelector{Profile: string(f.alice.Profile), Username: "bob"}

	err := viaGate(f.s, aliceCtx(), "Status", &proto.StatusRequest{Session: selector}, func(ctx context.Context) error {
		_, err := f.s.Status(ctx, &proto.StatusRequest{Session: selector})
		return err
	})
	assert.NoError(t, err, "alice owns the profile, whatever name the selector carries")

	selector = &proto.SessionSelector{Profile: string(f.alice.Profile), Username: "alice"}
	err = viaGate(f.s, bobCtx(), "Status", &proto.StatusRequest{Session: selector}, func(ctx context.Context) error {
		_, err := f.s.Status(ctx, &proto.StatusRequest{Session: selector})
		return err
	})
	requireRefusedAsForeign(t, err, "naming the owner gets bob nothing")
}

// Without a selector the RPCs act on the focused session, and the gate asks for its owner. Only
// Status answers anyone it can identify, without the peer detail.
func TestSessionAccess_NoSelectorFollowsTheFocus(t *testing.T) {
	exempt := map[string]bool{"Status": true}

	t.Run("focused on the session of a user", func(t *testing.T) {
		f := newAccessFixture(t)
		f.focus(t, f.alice)

		for name, want := range map[string]struct {
			ctx     context.Context
			reaches bool
		}{
			"alice":   {aliceCtx(), true},
			"root":    {rootCtx(), true},
			"bob":     {bobCtx(), false},
			"unknown": {unknownCtx(), false},
		} {
			for rpc, call := range gatedSelectorRPCs(f.s, cancelledCopy(want.ctx), nil) {
				t.Run(name+"/"+rpc, func(t *testing.T) {
					err := call()
					if want.reaches || (exempt[rpc] && name != "unknown") {
						assert.NotEqual(t, codes.PermissionDenied, gstatus.Code(err), "should get through: %v", err)
						return
					}
					requireRefusedAsForeign(t, err)
				})
			}
		}
	})

	t.Run("focused on the default profile nobody claimed", func(t *testing.T) {
		f := newAccessFixture(t)
		f.focus(t, f.shared)

		for _, caller := range []struct {
			name string
			ctx  context.Context
		}{{"bob", bobCtx()}, {"unknown", unknownCtx()}} {
			for rpc, call := range gatedSelectorRPCs(f.s, cancelledCopy(caller.ctx), nil) {
				t.Run(caller.name+"/"+rpc, func(t *testing.T) {
					if exempt[rpc] && caller.name != "unknown" {
						assert.NotEqual(t, codes.PermissionDenied, gstatus.Code(call()), "should get through")
						return
					}
					requireRefusedAsForeign(t, call(), "an unclaimed profile is no user's")
				})
			}
		}
	})
}

// A Down without a selector is for the owner of the focused session.
func TestSessionAccess_DownWithoutSelectorNeedsTheFocusedOwner(t *testing.T) {
	f := newAccessFixture(t)
	require.NoError(t, f.up(f.alice))
	f.focus(t, f.alice)

	down := func(ctx context.Context) error {
		return viaGate(f.s, ctx, "Down", &proto.DownRequest{}, func(ctx context.Context) error {
			_, err := f.s.Down(ctx, &proto.DownRequest{})
			return err
		})
	}

	requireRefusedAsForeign(t, down(bobCtx()))
	assert.True(t, f.session(f.alice).isClientRunning(), "bob must not take down the session of alice")

	require.NoError(t, down(aliceCtx()))
	assert.False(t, f.session(f.alice).isClientRunning())
}

func TestSessionAccess_DownAll(t *testing.T) {
	start := func(t *testing.T) *accessFixture {
		t.Helper()
		f := newAccessFixture(t)
		for _, key := range []profilemanager.SessionKey{f.alice, f.bob, f.shared} {
			require.NoError(t, f.up(key))
		}
		return f
	}
	stays := func(t *testing.T, f *accessFixture, key profilemanager.SessionKey) {
		t.Helper()
		assert.True(t, f.session(key).isClientRunning(), "the session of %s must stay up", key.Username)
		assert.Equal(t, internal.StatusConnected, f.session(key).state.CurrentStatus())
		assert.Equal(t, hostcoord.DesiredUp, f.stored(t)[key], "the session of %s must come back after a restart", key.Username)
	}
	goes := func(t *testing.T, f *accessFixture, key profilemanager.SessionKey) {
		t.Helper()
		assert.False(t, f.session(key).isClientRunning(), "the session of %q must go down", key.Username)
		assert.Equal(t, hostcoord.DesiredDown, f.stored(t)[key])
	}

	downAll := func(f *accessFixture, ctx context.Context, req *proto.DownRequest) error {
		return viaGate(f.s, ctx, "Down", req, func(ctx context.Context) error {
			_, err := f.s.Down(ctx, req)
			return err
		})
	}

	t.Run("a user takes down what is theirs", func(t *testing.T) {
		f := start(t)
		require.NoError(t, downAll(f, aliceCtx(), &proto.DownRequest{All: true}))
		goes(t, f, f.alice)
		stays(t, f, f.shared)
		stays(t, f, f.bob)
	})

	t.Run("root takes down every session", func(t *testing.T) {
		f := start(t)
		require.NoError(t, downAll(f, rootCtx(), &proto.DownRequest{All: true}))
		goes(t, f, f.alice)
		goes(t, f, f.bob)
		goes(t, f, f.shared)
	})

	t.Run("an unknown caller reaches nothing", func(t *testing.T) {
		f := start(t)
		requireRefusedAsForeign(t, downAll(f, unknownCtx(), &proto.DownRequest{All: true}))
		stays(t, f, f.shared)
		stays(t, f, f.alice)
		stays(t, f, f.bob)
	})

	t.Run("a selector does not combine with all", func(t *testing.T) {
		f := start(t)
		err := downAll(f, aliceCtx(), &proto.DownRequest{All: true, Session: selectorOf(f.alice)})
		requireCode(t, codes.InvalidArgument, err)
		stays(t, f, f.alice)
	})
}

func TestSessionAccess_StatusListsWhatTheCallerMayRead(t *testing.T) {
	f := newAccessFixture(t)
	for _, key := range []profilemanager.SessionKey{f.alice, f.bob, f.shared} {
		require.NoError(t, f.up(key))
	}

	for name, want := range map[string]struct {
		ctx      context.Context
		profiles []string
		full     bool
	}{
		// Neither holds the focused session, so the gate leaves out the peer detail.
		"alice": {aliceCtx(), []string{string(f.alice.Profile)}, false},
		"bob":   {bobCtx(), []string{string(f.bob.Profile)}, false},
		"root":  {rootCtx(), []string{string(f.first.Profile), string(f.alice.Profile), string(f.bob.Profile), profilemanager.DefaultProfileName}, true},
	} {
		t.Run(name, func(t *testing.T) {
			req := &proto.StatusRequest{GetFullPeerStatus: true}
			var status *proto.StatusResponse
			err := viaGate(f.s, want.ctx, "Status", req, func(ctx context.Context) error {
				var err error
				status, err = f.s.Status(ctx, req)
				return err
			})
			require.NoError(t, err)

			var profiles []string
			for _, entry := range status.GetSessions() {
				profiles = append(profiles, entry.GetProfileId())
				assert.Equal(t, want.full, entry.GetFullStatus() != nil, "full status of %s", entry.GetProfileId())
			}
			assert.ElementsMatch(t, want.profiles, profiles, "the sessions the caller may read")
		})
	}

	t.Run("an unknown caller is refused", func(t *testing.T) {
		err := viaGate(f.s, unknownCtx(), "Status", &proto.StatusRequest{}, func(ctx context.Context) error {
			_, err := f.s.Status(ctx, &proto.StatusRequest{})
			return err
		})
		requireRefusedAsForeign(t, err)
	})

	t.Run("the stream filters the same", func(t *testing.T) {
		f.focus(t, f.bob)
		ctx, cancel := context.WithCancel(bobCtx())
		stream := &capturingStatusStream{fakeServerStream: fakeServerStream[proto.StatusResponse]{ctx: ctx}, onSend: cancel}
		req := &proto.StatusRequest{GetFullPeerStatus: true}
		err := viaGateStream(f.s, ctx, "SubscribeStatus", req, func(context.Context) error {
			return f.s.SubscribeStatus(req, stream)
		})
		require.NoError(t, err)

		require.NotEmpty(t, stream.sent)
		for _, entry := range stream.sent[0].GetSessions() {
			assert.NotEqual(t, string(f.alice.Profile), entry.GetProfileId(), "bob must not read the session of alice")
		}
	})
}

type capturingStatusStream struct {
	fakeServerStream[proto.StatusResponse]
	mu     sync.Mutex
	sent   []*proto.StatusResponse
	onSend func()
}

func (c *capturingStatusStream) Send(resp *proto.StatusResponse) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sent = append(c.sent, resp)
	c.onSend()
	return nil
}

func (c *capturingStatusStream) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.sent)
}

func (c *capturingStatusStream) lastStatus() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sent[len(c.sent)-1].GetStatus()
}

func TestSessionAccess_Up(t *testing.T) {
	name := func(key profilemanager.SessionKey) (*string, *string) {
		profile, username := string(key.Profile), key.Username
		return &profile, &username
	}

	t.Run("the username of someone else is refused", func(t *testing.T) {
		f := newAccessFixture(t)
		profile, username := name(f.bob)
		_, err := f.s.Up(aliceCtx(), &proto.UpRequest{ProfileName: profile, Username: username, Async: true})
		requireRefusedAsForeign(t, err)
		assert.Zero(t, f.runCount(f.bob), "the session must not start")
		assert.NotContains(t, f.stored(t), f.bob, "the refused session must leave no record")
	})

	t.Run("the identity decides and not the field", func(t *testing.T) {
		f := newAccessFixture(t)
		// Alice saying she is bob gets her nothing, and bob asking for his own passes.
		profile, username := name(f.bob)
		_, err := f.s.Up(bobCtx(), &proto.UpRequest{ProfileName: profile, Username: username})
		require.NoError(t, err)
		assert.Equal(t, 1, f.runCount(f.bob))
	})

	t.Run("an unknown caller reaches nothing", func(t *testing.T) {
		f := newAccessFixture(t)
		profile, username := name(f.alice)
		_, err := f.s.Up(unknownCtx(), &proto.UpRequest{ProfileName: profile, Username: username, Async: true})
		requireRefusedAsForeign(t, err)

		defaultName := profilemanager.DefaultProfileName
		_, err = f.s.Up(unknownCtx(), &proto.UpRequest{ProfileName: &defaultName})
		requireRefusedAsForeign(t, err)
		assert.Zero(t, f.runCount(f.shared))
	})

	t.Run("root starts anyone's session", func(t *testing.T) {
		f := newAccessFixture(t)
		profile, username := name(f.alice)
		_, err := f.s.Up(rootCtx(), &proto.UpRequest{ProfileName: profile, Username: username})
		require.NoError(t, err)
		assert.Equal(t, 1, f.runCount(f.alice))
	})

	t.Run("no name means the focused session, which has an owner too", func(t *testing.T) {
		f := newAccessFixture(t)
		f.focus(t, f.alice)
		_, err := f.s.Up(bobCtx(), &proto.UpRequest{Async: true})
		requireRefusedAsForeign(t, err)
		assert.Zero(t, f.runCount(f.alice))

		_, err = f.s.Up(aliceCtx(), &proto.UpRequest{})
		require.NoError(t, err)
		assert.Equal(t, 1, f.runCount(f.alice))
	})
}

// The other RPCs that name a profile act on its session as well: SwitchProfile would otherwise hand
// the session of someone else to everything that follows the focus.
func TestSessionAccess_RPCsNamingAProfile(t *testing.T) {
	f := newAccessFixture(t)
	profile, username := string(f.bob.Profile), f.bob.Username
	focused := f.s.focusedSession().key

	login := &proto.LoginRequest{ProfileName: &profile, Username: &username}
	logout := &proto.LogoutRequest{ProfileName: &profile, Username: &username}
	switchProfile := &proto.SwitchProfileRequest{ProfileName: &profile, Username: &username}
	remove := &proto.RemoveProfileRequest{ProfileName: profile, Username: username}
	getConfig := &proto.GetConfigRequest{ProfileName: profile, Username: username}
	setConfig := &proto.SetConfigRequest{ProfileName: profile, Username: username}
	gated := func(method string, req any, call func(ctx context.Context) error) func(ctx context.Context) error {
		return func(ctx context.Context) error { return viaGate(f.s, ctx, method, req, call) }
	}
	refused := map[string]func(ctx context.Context) error{
		"Login": gated("Login", login, func(ctx context.Context) error {
			_, err := f.s.Login(ctx, login)
			return err
		}),
		"Logout": gated("Logout", logout, func(ctx context.Context) error {
			_, err := f.s.Logout(ctx, logout)
			return err
		}),
		"SwitchProfile": gated("SwitchProfile", switchProfile, func(ctx context.Context) error {
			_, err := f.s.SwitchProfile(ctx, switchProfile)
			return err
		}),
		"RemoveProfile": gated("RemoveProfile", remove, func(ctx context.Context) error {
			_, err := f.s.RemoveProfile(ctx, remove)
			return err
		}),
		"GetConfig": gated("GetConfig", getConfig, func(ctx context.Context) error {
			_, err := f.s.GetConfig(ctx, getConfig)
			return err
		}),
		"SetConfig": gated("SetConfig", setConfig, func(ctx context.Context) error {
			_, err := f.s.SetConfig(ctx, setConfig)
			return err
		}),
	}
	for rpc, call := range refused {
		t.Run(rpc, func(t *testing.T) {
			requireRefusedAsForeign(t, call(aliceCtx()), "alice")
			requireRefusedAsForeign(t, call(unknownCtx()), "unknown")
			assert.Equal(t, focused, f.s.focusedSession().key, "the focus must stay")
			_, err := os.Stat(filepath.Join(profilemanager.DefaultConfigPathDir, profile+".json"))
			assert.NoError(t, err, "the profile must stay")
		})
	}
}

func TestSessionSelector_Resolution(t *testing.T) {
	f := newAccessFixture(t)

	writeProfile := func(id, name string) {
		t.Helper()
		owner := aliceIdentity()
		_, err := profilemanager.UpdateOrCreateConfig(profilemanager.ConfigInput{
			ConfigPath:    filepath.Join(profilemanager.DefaultConfigPathDir, id+".json"),
			ManagementURL: "http://127.0.0.1:1",
			Owner:         &owner,
		})
		require.NoError(t, err)
		if name != "" {
			path := filepath.Join(profilemanager.DefaultConfigPathDir, id+".json")
			raw, err := os.ReadFile(path)
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(path, append(raw[:len(raw)-2], []byte(",\n\"name\":\""+name+"\"\n}")...), 0o600))
		}
	}
	writeProfile("abc123", "office")
	writeProfile("abc456", "twin")
	writeProfile("zzz111", "twin")

	key := func(id string) profilemanager.SessionKey {
		return profilemanager.SessionKey{Profile: profilemanager.ID(id), Username: "alice"}
	}

	for name, tc := range map[string]struct {
		handle string
		want   profilemanager.SessionKey
	}{
		"an ID":              {handle: "abc123", want: key("abc123")},
		"a unique ID prefix": {handle: "abc1", want: key("abc123")},
		"a unique name":      {handle: "office", want: key("abc123")},
	} {
		t.Run(name, func(t *testing.T) {
			// A status no other session has, so the answer shows which session the handle reached.
			f.s.mutex.Lock()
			ss := f.s.sessionOfLocked(tc.want)
			f.s.mutex.Unlock()
			ss.state.Set(internal.StatusNeedsLogin)
			defer ss.state.Set(internal.StatusIdle)

			status, err := f.s.Status(aliceCtx(), &proto.StatusRequest{Session: &proto.SessionSelector{Profile: tc.handle, Username: "alice"}})
			require.NoError(t, err)
			assert.Equal(t, string(internal.StatusNeedsLogin), status.GetStatus())
		})
	}

	for name, tc := range map[string]struct {
		selector *proto.SessionSelector
		code     codes.Code
	}{
		"an ambiguous ID prefix": {&proto.SessionSelector{Profile: "abc", Username: "alice"}, codes.InvalidArgument},
		"an ambiguous name":      {&proto.SessionSelector{Profile: "twin", Username: "alice"}, codes.InvalidArgument},
		"an unknown profile":     {&proto.SessionSelector{Profile: "no-such-profile", Username: "alice"}, codes.NotFound},
		"no handle":              {&proto.SessionSelector{Username: "alice"}, codes.InvalidArgument},
	} {
		t.Run(name, func(t *testing.T) {
			for rpc, call := range selectorRPCs(f.s, cancelledCopy(aliceCtx()), tc.selector) {
				assert.Equal(t, tc.code, gstatus.Code(call()), rpc)
			}
		})
	}
}

// The handler works with the session the selector named, whatever the focus says by then.
func TestSessionSelector_ReachesTheNamedSession(t *testing.T) {
	f := newAccessFixture(t)
	// The focused session runs, with a client that has no engine; the named one has no client. A
	// handler that looks at the wrong session answers with the other message.
	require.NoError(t, f.up(f.first))
	focused := f.s.focusedSession()
	named := selectorOf(f.second)
	ctx := rootCtx()

	for rpc, tc := range map[string]struct {
		call      func(selector *proto.SessionSelector) error
		ofNamed   string
		ofFocused string
	}{
		"GetPeerSSHHostKey": {
			call: func(selector *proto.SessionSelector) error {
				_, err := f.s.GetPeerSSHHostKey(ctx, &proto.GetPeerSSHHostKeyRequest{Session: selector})
				return err
			},
			ofNamed: "client not initialized", ofFocused: "engine not started",
		},
		"TracePacket": {
			call: func(selector *proto.SessionSelector) error {
				_, err := f.s.TracePacket(ctx, &proto.TracePacketRequest{Session: selector})
				return err
			},
			ofNamed: "connect client not initialized", ofFocused: "engine not initialized",
		},
		"StartCapture": {
			call: func(selector *proto.SessionSelector) error {
				return f.s.StartCapture(&proto.StartCaptureRequest{Session: selector}, fakeServerStream[proto.CapturePacket]{ctx: ctx})
			},
			ofNamed: "client not connected", ofFocused: "engine not initialized",
		},
		"ExposeService": {
			call: func(selector *proto.SessionSelector) error {
				return f.s.ExposeService(&proto.ExposeServiceRequest{Session: selector}, fakeServerStream[proto.ExposeServiceEvent]{ctx: ctx})
			},
			ofNamed: "client is not running", ofFocused: "engine not initialized",
		},
		"RequestExtendAuthSession": {
			call: func(selector *proto.SessionSelector) error {
				_, err := f.s.RequestExtendAuthSession(ctx, &proto.RequestExtendAuthSessionRequest{Session: selector})
				return err
			},
			ofNamed: "client is not configured", ofFocused: "session can no longer be extended",
		},
	} {
		t.Run(rpc, func(t *testing.T) {
			err := tc.call(named)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.ofNamed)
			err = tc.call(nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.ofFocused)
		})
	}

	t.Run("the auth flows belong to the named session", func(t *testing.T) {
		f.s.mutex.Lock()
		ss := f.s.sessionOfLocked(f.second)
		f.s.mutex.Unlock()
		ss.oauthAuthFlow = oauthAuthFlow{flow: &stubOAuthFlow{token: auth.TokenInfo{AccessToken: "named"}}, info: auth.AuthFlowInfo{DeviceCode: "device"}}
		ss.extendAuthSessionFlow.Set(&stubOAuthFlow{}, auth.AuthFlowInfo{DeviceCode: "extend"})

		_, err := f.s.WaitJWTToken(ctx, &proto.WaitJWTTokenRequest{DeviceCode: "device"})
		requireCode(t, codes.InvalidArgument, err)
		token, err := f.s.WaitJWTToken(ctx, &proto.WaitJWTTokenRequest{DeviceCode: "device", Session: named})
		require.NoError(t, err)
		assert.Equal(t, "named", token.GetToken())

		_, err = f.s.WaitExtendAuthSession(ctx, &proto.WaitExtendAuthSessionRequest{DeviceCode: "extend"})
		requireCode(t, codes.InvalidArgument, err)
		_, err = f.s.WaitExtendAuthSession(ctx, &proto.WaitExtendAuthSessionRequest{DeviceCode: "extend", Session: named})
		requireCode(t, codes.FailedPrecondition, err)
		assert.Contains(t, err.Error(), "client is not running", "the flow was found, the session does not run")
	})

	t.Run("the sync response setting stays with the named session", func(t *testing.T) {
		_, err := f.s.SetSyncResponsePersistence(ctx, &proto.SetSyncResponsePersistenceRequest{Session: named, Enabled: false})
		require.NoError(t, err)
		assert.False(t, f.session(f.second).syncResponsePersistence())
		assert.True(t, focused.syncResponsePersistence(), "the focused session keeps its own")
	})

	t.Run("Down takes down the named session and nothing else", func(t *testing.T) {
		require.NoError(t, f.up(f.second))
		_, err := f.s.Down(ctx, &proto.DownRequest{Session: named})
		require.NoError(t, err)
		assert.False(t, f.session(f.second).isClientRunning())
		assert.True(t, focused.isClientRunning(), "the focused session must stay up")
		assert.Equal(t, hostcoord.DesiredDown, f.stored(t)[f.second])
		assert.Equal(t, hostcoord.DesiredUp, f.stored(t)[f.first])
	})

	t.Run("Status describes the named session", func(t *testing.T) {
		status, err := f.s.Status(ctx, &proto.StatusRequest{Session: named, GetFullPeerStatus: true})
		require.NoError(t, err)
		assert.Equal(t, string(internal.StatusIdle), status.GetStatus())
		assert.NotNil(t, status.GetFullStatus())

		byID := make(map[string]*proto.SessionStatus)
		for _, entry := range status.GetSessions() {
			byID[entry.GetProfileId()] = entry
		}
		require.Contains(t, byID, string(f.second.Profile), "the named session is listed even when it does nothing")
		assert.False(t, byID[string(f.second.Profile)].GetFocused(), "the focus did not move")
		assert.True(t, byID[string(f.first.Profile)].GetFocused(), "the flag says where the focus is")

		status, err = f.s.Status(ctx, &proto.StatusRequest{})
		require.NoError(t, err)
		assert.Equal(t, string(internal.StatusConnected), status.GetStatus(), "no selector means the focused session")
	})
}

// A session that never ran has no config yet, and Status must still answer about it.
func TestSessionSelector_StatusOfASessionThatNeverRan(t *testing.T) {
	f := newAccessFixture(t)
	status, err := f.s.Status(aliceCtx(), &proto.StatusRequest{Session: selectorOf(f.alice), GetFullPeerStatus: true})
	require.NoError(t, err)
	assert.Equal(t, string(internal.StatusIdle), status.GetStatus())
}

// The state RPCs read the state file of the session they got from the selector, and not of the
// active profile, which is what a selector check followed by a second look at the focus would do.
func TestSessionSelector_StateRPCsUseTheFileOfTheSession(t *testing.T) {
	f := newAccessFixture(t)
	ctx := rootCtx()
	secondPath := f.s.profileManager.GetStatePathFor(f.second)
	thirdPath := f.s.profileManager.GetStatePathFor(f.third)
	require.NoError(t, os.WriteFile(secondPath, []byte(residualStateJSON), 0o600))
	require.NoError(t, os.WriteFile(thirdPath, []byte(residualStateJSON), 0o600))
	f.focus(t, f.third)

	listed, err := f.s.ListStates(ctx, &proto.ListStatesRequest{Session: selectorOf(f.first)})
	require.NoError(t, err)
	assert.Empty(t, listed.GetStates(), "the session named has no state, the focused one has")

	_, err = f.s.DeleteState(ctx, &proto.DeleteStateRequest{Session: selectorOf(f.second), All: true})
	require.NoError(t, err)
	listed, err = f.s.ListStates(ctx, &proto.ListStatesRequest{Session: selectorOf(f.second)})
	require.NoError(t, err)
	assert.Empty(t, listed.GetStates(), "the state of the named session should be gone")

	listed, err = f.s.ListStates(ctx, &proto.ListStatesRequest{})
	require.NoError(t, err)
	assert.NotEmpty(t, listed.GetStates(), "the state of the focused session must stay")

	// Only the named session is cleaned, with the focused one left alone.
	require.NoError(t, os.WriteFile(secondPath, []byte(residualStateJSON), 0o600))
	_, err = f.s.CleanState(ctx, &proto.CleanStateRequest{Session: selectorOf(f.second), All: true})
	require.NoError(t, err)
	listed, err = f.s.ListStates(ctx, &proto.ListStatesRequest{Session: selectorOf(f.second)})
	require.NoError(t, err)
	assert.Empty(t, listed.GetStates())
	listed, err = f.s.ListStates(ctx, &proto.ListStatesRequest{})
	require.NoError(t, err)
	assert.NotEmpty(t, listed.GetStates(), "the state of the focused session must stay")
}

// A CleanState claims the session before it looks at it: a run that started while it waited for the
// claim holds the state by the time it gets there.
func TestCleanState_ChecksTheClientUnderTheClaim(t *testing.T) {
	f := newGateFixture(t)
	ss := f.s.focusedSession()

	require.NoError(t, ss.lockLifecycle(f.ctx))
	done := make(chan error, 1)
	go func() {
		_, err := f.s.CleanState(f.ctx, &proto.CleanStateRequest{All: true})
		done <- err
	}()
	require.Never(t, func() bool { return len(done) > 0 }, 200*time.Millisecond, 20*time.Millisecond,
		"CleanState should wait for the session")

	config := ss.currentConfig()
	require.NoError(t, f.s.launchSession(f.ctx, ss, sessionLaunch{
		resolve: func() (*profilemanager.Config, error) { return config, nil },
		source:  proto.MetadataSourceUpRPC,
	}))
	running, _ := ss.runChans()
	<-running
	ss.unlockLifecycle()

	requireCode(t, codes.FailedPrecondition, <-done)
	assert.True(t, ss.isClientRunning())
}

func TestGate_LoginTargetsTheNamedSession(t *testing.T) {
	newLogin := func(t *testing.T) *gateFixture {
		t.Helper()
		f := newGateFixture(t)
		f.s.isLoginRequiredFn = func(context.Context, *profilemanager.Config) (bool, error) { return false, nil }
		return f
	}

	t.Run("the focus stays and the session gets the config", func(t *testing.T) {
		f := newLogin(t)
		require.NoError(t, f.up(f.first))
		firstClient := f.session(f.first).client()

		name, username := string(f.third.Profile), f.third.Username
		_, err := f.s.Login(f.ctx, &proto.LoginRequest{ProfileName: &name, Username: &username})
		require.NoError(t, err)

		assert.Equal(t, f.first, f.s.focusedSession().key, "a login does not move the focus")
		active, err := f.s.profileManager.GetActiveProfileState()
		require.NoError(t, err)
		assert.Equal(t, f.first.Profile, active.ID, "a login does not change the active profile")

		key, config := f.session(f.third).selectedConfig()
		assert.Equal(t, f.third, key)
		assert.NotNil(t, config, "the named session should have its config")

		assert.Same(t, firstClient, f.session(f.first).client(), "a login of another session must not end this one")
		assert.Equal(t, internal.StatusConnected, f.session(f.first).state.CurrentStatus())
	})

	t.Run("no name means the focused session", func(t *testing.T) {
		f := newLogin(t)
		f.focus(t, f.second)
		_, err := f.s.Login(f.ctx, &proto.LoginRequest{})
		require.NoError(t, err)
		key, _ := f.session(f.second).selectedConfig()
		assert.Equal(t, f.second, key)
	})

	t.Run("the kill switch guards a session other than the focused one", func(t *testing.T) {
		f := newLogin(t)
		f.s.profilesDisabled = true
		name, username := string(f.third.Profile), f.third.Username
		_, err := f.s.Login(f.ctx, &proto.LoginRequest{ProfileName: &name, Username: &username})
		requireCode(t, codes.Unavailable, err)

		name, username = string(f.first.Profile), f.first.Username
		_, err = f.s.Login(f.ctx, &proto.LoginRequest{ProfileName: &name, Username: &username})
		assert.NoError(t, err, "a login of the focused session is no profile management")
	})

	t.Run("WaitSSOLogin finishes the login of the session it names", func(t *testing.T) {
		f := newLogin(t)
		var loggedIn *profilemanager.Config
		f.s.loginAttemptFn = func(_ context.Context, config *profilemanager.Config, _, _ string) (internal.StatusType, error) {
			loggedIn = config
			return "", nil
		}

		name, username := string(f.third.Profile), f.third.Username
		_, err := f.s.Login(f.ctx, &proto.LoginRequest{ProfileName: &name, Username: &username})
		require.NoError(t, err)
		ss := f.session(f.third)
		_, config := ss.selectedConfig()
		ss.oauthAuthFlow = oauthAuthFlow{flow: &stubOAuthFlow{}, info: auth.AuthFlowInfo{UserCode: "code"}, key: f.third, config: config}

		ctx, cancel := context.WithCancel(f.ctx)
		defer cancel()
		_, err = f.s.WaitSSOLogin(ctx, &proto.WaitSSOLoginRequest{UserCode: "code"})
		requireCode(t, codes.Internal, err)

		_, err = f.s.WaitSSOLogin(ctx, &proto.WaitSSOLoginRequest{UserCode: "code", Session: selectorOf(f.third)})
		require.NoError(t, err)
		assert.Same(t, config, loggedIn, "the token should log in the session the flow belongs to")
		assert.Equal(t, f.first, f.s.focusedSession().key, "the focus must stay")
	})
}

// I9: a logout of a profile that is not focused leaves nothing of its login behind, and nothing of
// the focused session goes with it.
func TestGate_LogoutOfAnUnfocusedProfileClearsItsSession(t *testing.T) {
	f := newGateFixture(t)
	writeLogoutProfile(t, filepath.Join(profilemanager.DefaultConfigPathDir, string(f.third.Profile)+".json"), false, false)
	f.focus(t, f.second)
	focused := f.s.focusedSession()

	f.s.mutex.Lock()
	target := f.s.sessionOfLocked(f.third)
	f.s.mutex.Unlock()

	owner := aliceIdentity()
	arm := func(ss *session) (loginCancelled, extendCancelled *bool) {
		loginCancelled, extendCancelled = new(bool), new(bool)
		require.True(t, ss.jwtCache.store("token", owner, time.Minute, ss.jwtCache.currentGeneration()))
		ss.oauthAuthFlow = oauthAuthFlow{flow: &stubOAuthFlow{}, waitCancel: func() { *loginCancelled = true }}
		ss.extendAuthSessionFlow.Set(&stubOAuthFlow{}, auth.AuthFlowInfo{DeviceCode: "device"})
		ss.extendAuthSessionFlow.SetWaitCancel(func() { *extendCancelled = true })
		ss.armAccountPrompt()
		return loginCancelled, extendCancelled
	}
	targetLogin, targetExtend := arm(target)
	focusedLogin, focusedExtend := arm(focused)
	focused.state.Set(internal.StatusIdle)

	name, username := string(f.third.Profile), f.third.Username
	_, err := f.s.Logout(f.ctx, &proto.LogoutRequest{ProfileName: &name, Username: &username})
	require.NoError(t, err)

	_, cached := target.jwtCache.get(owner)
	assert.False(t, cached, "the token of the logged out session must be gone")
	assert.Nil(t, target.oauthFlow().flow, "the pending login must be gone")
	assert.True(t, *targetLogin, "the wait of the pending login must end")
	_, _, pending := target.extendAuthSessionFlow.Get()
	assert.False(t, pending, "the pending session extension must be gone")
	assert.True(t, *targetExtend, "the wait of the pending session extension must end")
	assert.False(t, target.takeAccountPrompt(), "the account prompt was about the old login")
	assert.Equal(t, internal.StatusNeedsLogin, target.state.CurrentStatus())

	_, cached = focused.jwtCache.get(owner)
	assert.True(t, cached, "the token of the focused session must stay")
	assert.NotNil(t, focused.oauthFlow().flow, "the pending login of the focused session must stay")
	assert.False(t, *focusedLogin, "the wait of the focused session must go on")
	assert.False(t, *focusedExtend, "the wait of the focused session must go on")
	assert.Equal(t, internal.StatusIdle, focused.state.CurrentStatus())
	assert.Equal(t, f.second, f.s.focusedSession().key, "the focus must stay")
}

func newTestBundleCapture(t *testing.T) *bundleCapture {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "capture.*.pcap")
	require.NoError(t, err)
	sess, err := capture.NewSession(capture.Options{Output: file})
	require.NoError(t, err)
	return &bundleCapture{sess: sess, file: file}
}

func bundleEntries(t *testing.T, path string) map[string]string {
	t.Helper()
	reader, err := zip.OpenReader(path)
	require.NoError(t, err)
	defer func() { require.NoError(t, reader.Close()) }()

	entries := make(map[string]string, len(reader.File))
	for _, file := range reader.File {
		opened, err := file.Open()
		require.NoError(t, err)
		raw, err := io.ReadAll(opened)
		require.NoError(t, err)
		require.NoError(t, opened.Close())
		entries[file.Name] = string(raw)
	}
	return entries
}

// I5: the capture of one session must not leave with the debug bundle of another, whichever way the
// focus went in between, and what one session does to its capture leaves the other's running.
func TestBundleCapture_StaysWithItsSession(t *testing.T) {
	f := newGateFixture(t)
	t.Setenv("TMPDIR", t.TempDir())
	ctx := f.ctx

	f.s.mutex.Lock()
	owner := f.s.sessionOfLocked(f.second)
	running := newTestBundleCapture(t)
	owner.bundleCapture = running
	f.s.mutex.Unlock()

	bundleOf := func(selector *proto.SessionSelector) map[string]string {
		t.Helper()
		resp, err := f.s.DebugBundle(ctx, &proto.DebugBundleRequest{Session: selector})
		require.NoError(t, err)
		return bundleEntries(t, resp.GetPath())
	}

	_, err := f.s.StartBundleCapture(ctx, &proto.StartBundleCaptureRequest{Session: selectorOf(f.first)})
	require.NoError(t, err)
	_, err = f.s.StopBundleCapture(ctx, &proto.StopBundleCaptureRequest{Session: selectorOf(f.first)})
	require.NoError(t, err)
	assert.Same(t, running, owner.bundleCapture, "another session must not replace the capture")
	assert.False(t, running.stopped, "another session must not stop the capture")

	assert.NotContains(t, bundleOf(nil), "capture.pcap", "the bundle of the focused session must not carry the capture of another")
	assert.NotContains(t, bundleOf(selectorOf(f.first)), "capture.pcap")
	assert.False(t, running.stopped, "a bundle of another session must not stop the capture")
	require.NotEmpty(t, running.path(), "a bundle of another session must not remove the capture")

	path := running.path()
	assert.Contains(t, bundleOf(selectorOf(f.second)), "capture.pcap", "the bundle of the session carries its capture")
	assert.True(t, running.stopped, "the capture ends with its bundle")
	assert.Nil(t, owner.bundleCapture)
	_, err = os.Stat(path)
	assert.True(t, os.IsNotExist(err), "the capture file ends with its bundle")
}

// The state file in a bundle is the one of the session the bundle is about.
func TestDebugBundle_CarriesTheStateOfItsSession(t *testing.T) {
	f := newGateFixture(t)
	t.Setenv("TMPDIR", t.TempDir())
	require.NoError(t, os.WriteFile(f.s.profileManager.GetStatePathFor(f.second), []byte(residualStateJSON), 0o600))

	resp, err := f.s.DebugBundle(f.ctx, &proto.DebugBundleRequest{Session: selectorOf(f.second)})
	require.NoError(t, err)
	assert.Contains(t, bundleEntries(t, resp.GetPath()), "state.json", "the session has a state file")

	resp, err = f.s.DebugBundle(f.ctx, &proto.DebugBundleRequest{})
	require.NoError(t, err)
	assert.NotContains(t, bundleEntries(t, resp.GetPath()), "state.json", "the focused session has none")
}

// A profile that goes away takes its capture with it: nothing else could reach it any more.
func TestGate_RemoveProfileEndsItsBundleCapture(t *testing.T) {
	f := newGateFixture(t)
	writeLogoutProfile(t, filepath.Join(profilemanager.DefaultConfigPathDir, string(f.third.Profile)+".json"), false, false)

	f.s.mutex.Lock()
	ss := f.s.sessionOfLocked(f.third)
	running := newTestBundleCapture(t)
	ss.bundleCapture = running
	f.s.mutex.Unlock()
	path := running.path()

	_, err := f.s.RemoveProfile(f.ctx, &proto.RemoveProfileRequest{ProfileName: string(f.third.Profile), Username: f.third.Username})
	require.NoError(t, err)

	assert.True(t, running.stopped)
	_, err = os.Stat(path)
	assert.True(t, os.IsNotExist(err), "the capture file must go with the profile")
}

// With the handle resolving to another profile than the session decided about, the logout would
// deregister one peer and clear the login of another session.
func TestGate_LogoutRefusesAHandleThatMovedToAnotherProfile(t *testing.T) {
	f := newGateFixture(t)
	f.s.mutex.Lock()
	target := f.s.sessionOfLocked(f.second)
	f.s.mutex.Unlock()

	name, username := string(f.third.Profile), f.third.Username
	_, err := f.s.handleProfileLogout(f.ctx, target, &proto.LogoutRequest{ProfileName: &name, Username: &username})
	requireCode(t, codes.FailedPrecondition, err)
}

// A login decides on the stored config of the session it targets, whatever the handle resolves to
// by the time the gates read it.
func TestGate_LoginGatesReadTheConfigOfTheTarget(t *testing.T) {
	f := newGateFixture(t)
	state := profileStateOf(f.second)
	name, username := string(f.third.Profile), f.third.Username

	stored, err := f.s.storedLoginConfig(f.ctx, state, &proto.LoginRequest{ProfileName: &name, Username: &username})
	require.NoError(t, err)

	path, err := f.s.profileManager.ActiveProfilePath(state)
	require.NoError(t, err)
	want, err := profilemanager.GetExistingConfig(path)
	require.NoError(t, err)
	assert.Equal(t, want.PrivateKey, stored.PrivateKey)
}

// Without a selector a stream describes the focused session, also after the focus moved.
func TestGate_StatusStreamFollowsTheFocus(t *testing.T) {
	subscribe := func(t *testing.T, f *gateFixture, selector *proto.SessionSelector) (*capturingStatusStream, <-chan error) {
		t.Helper()
		ctx, cancel := context.WithCancel(f.ctx)
		t.Cleanup(cancel)
		stream := &capturingStatusStream{fakeServerStream: fakeServerStream[proto.StatusResponse]{ctx: ctx}, onSend: func() {}}
		done := make(chan error, 1)
		go func() { done <- f.s.SubscribeStatus(&proto.StatusRequest{Session: selector}, stream) }()
		require.Eventually(t, func() bool { return stream.count() > 0 }, 5*time.Second, 10*time.Millisecond, "the first snapshot")
		return stream, done
	}
	nextSession := func(t *testing.T, f *gateFixture) *session {
		t.Helper()
		f.s.mutex.Lock()
		defer f.s.mutex.Unlock()
		return f.s.sessionOfLocked(f.second)
	}

	t.Run("no selector", func(t *testing.T) {
		f := newGateFixture(t)
		next := nextSession(t, f)
		next.state.Set(internal.StatusNeedsLogin)
		stream, _ := subscribe(t, f, nil)

		f.focus(t, f.second)
		require.Eventually(t, func() bool { return stream.lastStatus() == string(internal.StatusNeedsLogin) }, 5*time.Second, 10*time.Millisecond,
			"the stream should move with the focus")

		// A change of the new session reaches the stream, so the subscription moved as well.
		next.state.Set(internal.StatusLoginFailed)
		require.Eventually(t, func() bool { return stream.lastStatus() == string(internal.StatusLoginFailed) }, 5*time.Second, 10*time.Millisecond,
			"the stream should hear the session it moved to")
	})

	t.Run("a selector stays with its session", func(t *testing.T) {
		f := newGateFixture(t)
		next := nextSession(t, f)
		next.state.Set(internal.StatusNeedsLogin)
		stream, _ := subscribe(t, f, selectorOf(f.first))

		f.focus(t, f.second)
		f.s.focusedSession().state.Set(internal.StatusLoginFailed)
		f.session(f.first).statusRecorder.NotifyStateChange()
		require.Never(t, func() bool { return stream.lastStatus() != string(internal.StatusIdle) }, 300*time.Millisecond, 20*time.Millisecond,
			"the stream should keep describing the session it named")
	})
}

// The events of a session are for those who may read it, also when the focus moves on to one.
func TestGate_EventStreamFollowsTheFocus(t *testing.T) {
	f := newAccessFixture(t)
	f.focus(t, f.alice)

	ctx, cancel := context.WithCancel(aliceCtx())
	t.Cleanup(cancel)
	stream := &capturingEventStream{fakeServerStream: fakeServerStream[proto.SystemEvent]{ctx: ctx}}
	done := make(chan error, 1)
	go func() { done <- f.s.SubscribeEvents(&proto.SubscribeRequest{}, stream) }()
	require.Eventually(t, func() bool { return stream.count() > 0 }, 5*time.Second, 10*time.Millisecond, "the log level event")

	// The default profile is alice's too, so the stream may follow the focus there.
	ownDefaultProfile(t, aliceIdentity())
	f.focus(t, f.shared)
	publish := func(message string) {
		f.s.focusedSession().statusRecorder.PublishEvent(proto.SystemEvent_INFO, proto.SystemEvent_SYSTEM, message, "", nil)
	}
	require.Eventually(t, func() bool {
		publish("on the default session")
		return stream.saw("on the default session")
	}, 5*time.Second, 50*time.Millisecond, "the stream should move with the focus")

	f.focus(t, f.bob)
	select {
	case err := <-done:
		requireRefusedAsForeign(t, err, "the focus moved to a session alice may not read")
		assert.False(t, stream.sawProfile(string(f.bob.Profile)), "the stream must not tell which session the focus moved to")
	case <-time.After(5 * time.Second):
		t.Fatal("the stream should end when the focus moves to a session of someone else")
	}
}

type capturingEventStream struct {
	fakeServerStream[proto.SystemEvent]
	mu   sync.Mutex
	sent []*proto.SystemEvent
}

func (c *capturingEventStream) Send(event *proto.SystemEvent) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sent = append(c.sent, event)
	return nil
}

func (c *capturingEventStream) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.sent)
}

func (c *capturingEventStream) sawProfile(profile string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, event := range c.sent {
		if event.GetMetadata()[proto.MetadataProfileKey] == profile {
			return true
		}
	}
	return false
}

func (c *capturingEventStream) saw(message string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, event := range c.sent {
		if event.GetMessage() == message {
			return true
		}
	}
	return false
}

// The profiles of a user are theirs: another user neither sees nor renames them, whatever username
// the request carries.
func TestSessionAccess_ProfileRPCs(t *testing.T) {
	f := newAccessFixture(t)
	rename := func(ctx context.Context, name string) error {
		req := &proto.RenameProfileRequest{Handle: string(f.alice.Profile), Username: "bob", NewProfileName: name}
		return viaGate(f.s, ctx, "RenameProfile", req, func(ctx context.Context) error {
			_, err := f.s.RenameProfile(ctx, req)
			return err
		})
	}
	list := func(ctx context.Context) ([]string, error) {
		req := &proto.ListProfilesRequest{Username: "alice"}
		var ids []string
		err := viaGate(f.s, ctx, "ListProfiles", req, func(ctx context.Context) error {
			resp, err := f.s.ListProfiles(ctx, req)
			for _, profile := range resp.GetProfiles() {
				ids = append(ids, profile.GetId())
			}
			return err
		})
		return ids, err
	}

	requireRefusedAsForeign(t, rename(bobCtx(), "renamed"), "bob renames the profile of alice")
	requireRefusedAsForeign(t, rename(unknownCtx(), "renamed"), "an unknown caller renames it")

	listed, err := list(bobCtx())
	require.NoError(t, err)
	assert.NotContains(t, listed, string(f.alice.Profile), "bob must not see the profile of alice")
	assert.Contains(t, listed, string(f.bob.Profile), "bob sees his own")

	_, err = list(unknownCtx())
	requireRefusedAsForeign(t, err, "a caller nobody can identify lists nothing")

	listed, err = list(aliceCtx())
	require.NoError(t, err)
	assert.Contains(t, listed, string(f.alice.Profile))

	require.NoError(t, rename(aliceCtx(), "renamed"), "alice renames her own profile")
}

// Which profile the focus is on says what another user is connected to, so only its owner reads
// its name.
func TestSessionAccess_GetActiveProfile(t *testing.T) {
	f := newAccessFixture(t)
	f.focus(t, f.alice)
	require.NoError(t, f.s.profileManager.RenameProfile(f.alice.Profile, "alice-work"))

	active := func(ctx context.Context) (*proto.GetActiveProfileResponse, error) {
		req := &proto.GetActiveProfileRequest{}
		var resp *proto.GetActiveProfileResponse
		err := viaGate(f.s, ctx, "GetActiveProfile", req, func(ctx context.Context) error {
			var err error
			resp, err = f.s.GetActiveProfile(ctx, req)
			return err
		})
		return resp, err
	}

	resp, err := active(bobCtx())
	require.NoError(t, err)
	assert.Empty(t, resp.GetProfileName(), "bob must not read the name of the profile of alice")

	_, err = active(unknownCtx())
	requireRefusedAsForeign(t, err)

	for name, ctx := range map[string]context.Context{"alice": aliceCtx(), "root": rootCtx()} {
		resp, err := active(ctx)
		require.NoError(t, err, name)
		assert.Equal(t, string(f.alice.Profile), resp.GetId(), "%s should read the focus", name)
		assert.Equal(t, "alice-work", resp.GetProfileName(), "%s should read its name", name)
	}
}

// A stream of a session with a selector stays there whatever happens to the focus. The profile
// another user moves the focus to is none of its business, and neither are the other changes to
// the list of profiles.
func TestProfileListEvent_NamesNoProfileWithTheGate(t *testing.T) {
	f := newAccessFixture(t)
	f.focus(t, f.alice)

	ctx, cancel := context.WithCancel(aliceCtx())
	t.Cleanup(cancel)
	stream := &capturingEventStream{fakeServerStream: fakeServerStream[proto.SystemEvent]{ctx: ctx}}
	go func() { _ = f.s.SubscribeEvents(&proto.SubscribeRequest{Session: selectorOf(f.alice)}, stream) }()
	require.Eventually(t, func() bool { return stream.count() > 0 }, 5*time.Second, 10*time.Millisecond, "the stream should start")

	profile, username := string(f.bob.Profile), f.bob.Username
	_, err := f.s.SwitchProfile(bobCtx(), &proto.SwitchProfileRequest{ProfileName: &profile, Username: &username})
	require.NoError(t, err)

	require.Eventually(t, func() bool { return stream.saw("Profile list changed") }, 5*time.Second, 10*time.Millisecond, "the list changed, which is what the event is for")
	assert.False(t, stream.sawProfile(profile), "the event must not name the profile of bob")
}

// netbird ssh and its proxy fix the session of a connection by naming the focus they were told about.
// The name has to come back to the same session.
func TestSelectorOfTheActiveProfileNamesTheFocusedSession(t *testing.T) {
	f := newAccessFixture(t)
	// The default profile is alice's as well, which a console user's claim would make it.
	ownDefaultProfile(t, aliceIdentity())
	for _, tc := range []struct {
		name string
		key  profilemanager.SessionKey
	}{
		{name: "the session of the caller", key: f.alice},
		{name: "the default session", key: f.shared},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f.focus(t, tc.key)

			active, err := f.s.GetActiveProfile(aliceCtx(), &proto.GetActiveProfileRequest{})
			require.NoError(t, err)
			ss, err := f.s.checkSessionSelector(aliceCtx(), &proto.SessionSelector{Profile: active.GetId(), Username: active.GetUsername()})
			require.NoError(t, err)

			assert.Equal(t, tc.key.Profile, ss.key.Profile, "the selector should name the focused session")
			assert.Same(t, f.s.focusedSession(), ss, "the selector should reach the focused session")
		})
	}
}
