package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"
	gproto "google.golang.org/protobuf/proto"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
)

// newGateDaemon is a daemon with the gate on and two profiles. It starts with the first command, so
// a test can set it up first.
func newGateDaemon(t *testing.T) *fakeDaemon {
	t.Helper()
	isolateProfiles(t)
	return &fakeDaemon{
		features: gateOn(),
		profiles: []*proto.Profile{profileWork, profileHome},
		focused:  profileWork.Id,
		status:   map[string]string{},
	}
}

func selectorOf(t *testing.T, id string) *proto.SessionSelector {
	t.Helper()
	return &proto.SessionSelector{Profile: id, Username: currentUsername(t)}
}

// A profile that is connected already is not brought down for the sake of the switch to it: with
// the gate the connected status is its own, and the other sessions stay as they are.
func TestUp_ProfileOfAConnectedSessionWithTheGateIsAlreadyConnected(t *testing.T) {
	d := newGateDaemon(t)
	d.status[profileWork.Id] = "Connected"
	d.status[profileHome.Id] = "Connected"

	res := runCLI(t, d, "up", "--profile", profileHome.Name)
	require.NoError(t, res.err, res.out)

	requireNoCall(t, d, "Down", "Login", "Up")
	assert.Equal(t, "Already connected\n", res.out)
}

func TestUp_ProfileWithTheGateStartsTheSessionAndKeepsTheOthers(t *testing.T) {
	d := newGateDaemon(t)
	// Another session is connected and the new profile is not: its own status is Idle.
	d.status[profileWork.Id] = "Connected"

	res := runCLI(t, d, "up", "--profile", profileHome.Name)
	require.NoError(t, res.err, res.out)

	requireNoCall(t, d, "Down")
	login := requestOf[proto.LoginRequest](t, d, "Login")
	assert.Equal(t, profileHome.Id, login.GetProfileName(), "the login is for the profile of the command")
	up := requestOf[proto.UpRequest](t, d, "Up")
	assert.Equal(t, profileHome.Id, up.GetProfileName())
	assert.Equal(t, "Connected\n", res.out)
}

// Without the gate the daemon has one connection, and a switch of the profile takes it down.
func TestUp_ProfileWithoutTheGateTakesTheConnectionDown(t *testing.T) {
	for name, features := range map[string]*proto.GetFeaturesResponse{
		"gate off":   {},
		"old daemon": nil,
	} {
		t.Run(name, func(t *testing.T) {
			d := newGateDaemon(t)
			d.features = features
			d.status[profileHome.Id] = "Connected"

			res := runCLI(t, d, "up", "--profile", profileHome.Name)
			require.NoError(t, res.err, res.out)

			assert.True(t, d.called(t, "Down"), "a daemon with one connection must be brought down, calls: %v", d.callList(t))
			assert.True(t, gproto.Equal(&proto.DownRequest{}, requestOf[proto.DownRequest](t, d, "Down")), "the Down is the plain one")
			assert.True(t, d.called(t, "Up"))
		})
	}
}

// The gate decides whether a connection is taken down, so a daemon that cannot answer leaves
// the connection alone.
func TestUp_UnreadableFeaturesTakeNothingDown(t *testing.T) {
	d := newGateDaemon(t)
	d.featuresErr = gstatus.Error(codes.Internal, "features are unavailable")
	d.status[profileHome.Id] = "Connected"

	res := runCLI(t, d, "up", "--profile", profileHome.Name)

	require.Error(t, res.err)
	requireNoCall(t, d, "Down", "Login", "Up")
}

// switchesOf are the profiles the command switched the daemon to, in order.
func switchesOf(t *testing.T, d *fakeDaemon) []string {
	t.Helper()
	var ids []string
	for _, req := range requestsOf[proto.SwitchProfileRequest](t, d, "SwitchProfile") {
		ids = append(ids, req.GetProfileName())
	}
	return ids
}

// A refused up gives the focus back to the session that had it, so that a plain down still ends
// that session and not the one that never came up.
func TestUp_RefusedProfileWithTheGateGivesTheFocusBack(t *testing.T) {
	for name, refusal := range map[string]error{
		"overlay": gstatus.Error(codes.FailedPrecondition, "the overlay 100.64.0.0/16 overlaps the session of prace"),
		"limit":   gstatus.Error(codes.ResourceExhausted, "the limit of 4 concurrent sessions is reached, bring a session down first"),
	} {
		t.Run(name, func(t *testing.T) {
			d := newGateDaemon(t)
			d.status[profileWork.Id] = "Connected"
			d.failures = map[string]error{"Up": refusal}

			res := runCLI(t, d, "up", "--profile", profileHome.Name)
			require.Error(t, res.err, res.out)

			require.Equal(t, []string{profileHome.Name, profileWork.Id}, switchesOf(t, d), "the focus goes back to the session that had it")
			back := requestsOf[proto.SwitchProfileRequest](t, d, "SwitchProfile")[1]
			assert.Equal(t, currentUsername(t), back.GetUsername(), "the focus goes back to the session of its user")
			mirror, err := profilemanager.NewProfileManager().GetActiveProfile()
			require.NoError(t, err)
			assert.Equal(t, profilemanager.ID("default"), mirror.ID, "the local active profile is the one before the command")
			requireNoCall(t, d, "Down")
		})
	}
}

// A session that runs after its up failed, such as one that is still connecting when the wait for
// it ends, keeps the focus: a plain down is then to end it.
func TestUp_FailedProfileThatRunsKeepsTheFocus(t *testing.T) {
	d := newGateDaemon(t)
	d.status[profileWork.Id] = "Connected"
	d.status[profileHome.Id] = "Connecting"
	d.failures = map[string]error{"Up": gstatus.Error(codes.DeadlineExceeded, "context deadline exceeded")}

	res := runCLI(t, d, "up", "--profile", profileHome.Name)
	require.Error(t, res.err, res.out)

	assert.Equal(t, []string{profileHome.Name}, switchesOf(t, d), "the focus stays on the session that runs")
}

// Without the gate the switch is the point of `up --profile`, and a failed up leaves it as today.
func TestUp_FailedProfileWithoutTheGateKeepsTheSwitch(t *testing.T) {
	for name, features := range map[string]*proto.GetFeaturesResponse{
		"gate off":   {},
		"old daemon": nil,
	} {
		t.Run(name, func(t *testing.T) {
			d := newGateDaemon(t)
			d.features = features
			d.failures = map[string]error{"Up": gstatus.Error(codes.FailedPrecondition, "up refused")}

			res := runCLI(t, d, "up", "--profile", profileHome.Name)
			require.Error(t, res.err, res.out)

			assert.Equal(t, []string{profileHome.Name}, switchesOf(t, d), "the switch stays")
			requireNoCall(t, d, "GetActiveProfile")
		})
	}
}

func TestDown_WithTheGateTakesDownTheFocusedAndNamesWhatRuns(t *testing.T) {
	d := newGateDaemon(t)
	d.sessions = []*proto.SessionStatus{
		{ProfileId: profileWork.Id, ProfileName: profileWork.Name, Status: "Idle", Focused: true},
		{ProfileId: profileHome.Id, ProfileName: profileHome.Name, Status: "Connected", InterfaceName: "wt1"},
	}

	res := runCLI(t, d, "down")
	require.NoError(t, res.err, res.out)

	down := requestOf[proto.DownRequest](t, d, "Down")
	assert.True(t, gproto.Equal(&proto.DownRequest{}, down), "a Down without parameters acts on the focused session")
	assert.Contains(t, res.out, "Disconnected")
	assert.Contains(t, res.out, profileHome.Name, "the session that keeps running is named")
	assert.Contains(t, res.out, "wt1")
	assert.NotContains(t, res.out, profileWork.Name, "the session that went down is not listed as running")
	assert.Contains(t, res.out, "netbird down --profile", "the way to take it down is named")
}

func TestDown_WithTheGateAndNothingElseRunningSaysNothingMore(t *testing.T) {
	d := newGateDaemon(t)
	d.sessions = []*proto.SessionStatus{
		{ProfileId: profileWork.Id, ProfileName: profileWork.Name, Status: "Idle", Focused: true},
	}

	res := runCLI(t, d, "down")
	require.NoError(t, res.err, res.out)

	assert.Equal(t, "Disconnected\n", res.out)
}

func TestDown_ProfileAndAllWithTheGate(t *testing.T) {
	t.Run("profile", func(t *testing.T) {
		d := newGateDaemon(t)
		res := runCLI(t, d, "down", "--profile", profileHome.Name)
		require.NoError(t, res.err, res.out)

		down := requestOf[proto.DownRequest](t, d, "Down")
		assert.True(t, gproto.Equal(selectorOf(t, profileHome.Id), down.GetSession()),
			"the selector names the profile by its ID, got %v", down.GetSession())
		assert.False(t, down.GetAll())
	})

	t.Run("all", func(t *testing.T) {
		d := newGateDaemon(t)
		res := runCLI(t, d, "down", "--all")
		require.NoError(t, res.err, res.out)

		down := requestOf[proto.DownRequest](t, d, "Down")
		assert.True(t, down.GetAll())
		assert.Nil(t, down.GetSession(), "all does not come with a selector")
	})

	t.Run("both", func(t *testing.T) {
		d := newGateDaemon(t)
		res := runCLI(t, d, "down", "--all", "--profile", profileHome.Name)
		require.Error(t, res.err, "the daemon refuses the combination, so the command does not send it")
		requireNoCall(t, d, "Down")
	})

	t.Run("unknown profile", func(t *testing.T) {
		d := newGateDaemon(t)
		res := runCLI(t, d, "down", "--profile", "nikdo")
		require.Error(t, res.err)
		assert.Contains(t, res.err.Error(), "not found")
		requireNoCall(t, d, "Down")
	})
}

// A daemon without the gate never sees a selector: an older one would ignore it and take down
// the one connection it has, whichever profile the user named.
func TestDown_ProfileAndAllWithoutTheGateAreRefused(t *testing.T) {
	for name, features := range map[string]*proto.GetFeaturesResponse{"gate off": {}, "old daemon": nil} {
		for _, args := range [][]string{{"down", "--profile", profileHome.Name}, {"down", "--all"}} {
			t.Run(name+" "+args[1], func(t *testing.T) {
				d := newGateDaemon(t)
				d.features = features

				res := runCLI(t, d, args...)

				require.Error(t, res.err)
				assert.Contains(t, res.err.Error(), "concurrent profiles")
				requireNoCall(t, d, "Down", "Status")
			})
		}
	}
}

func TestDown_WithoutTheGateIsWhatItWasToday(t *testing.T) {
	for name, features := range map[string]*proto.GetFeaturesResponse{"gate off": {}, "old daemon": nil} {
		t.Run(name, func(t *testing.T) {
			d := newGateDaemon(t)
			d.features = features

			res := runCLI(t, d, "down")
			require.NoError(t, res.err, res.out)

			assert.Equal(t, "Disconnected\n", res.out)
			assert.True(t, gproto.Equal(&proto.DownRequest{}, requestOf[proto.DownRequest](t, d, "Down")))
			requireNoCall(t, d, "Status", "ListProfiles")
		})
	}
}

func TestProfileSelect_WithTheGateKeepsTheConnections(t *testing.T) {
	d := newGateDaemon(t)
	d.status[profileHome.Id] = "Connected"

	res := runCLI(t, d, "profile", "select", profileHome.Name)
	require.NoError(t, res.err, res.out)

	switched := requestOf[proto.SwitchProfileRequest](t, d, "SwitchProfile")
	assert.Equal(t, profileHome.Name, switched.GetProfileName())
	requireNoCall(t, d, "Down")
	assert.Contains(t, res.out, "Profile switched to:")
}

func TestProfileSelect_WithoutTheGateTakesTheConnectionDown(t *testing.T) {
	for name, features := range map[string]*proto.GetFeaturesResponse{"gate off": {}, "old daemon": nil} {
		t.Run(name, func(t *testing.T) {
			d := newGateDaemon(t)
			d.features = features
			d.status[profileHome.Id] = "Connected"

			res := runCLI(t, d, "profile", "select", profileHome.Name)
			require.NoError(t, res.err, res.out)

			assert.True(t, d.called(t, "Down"), "calls: %v", d.callList(t))
		})
	}
}

func TestProfileList_WithTheGateShowsTheConnectionStatus(t *testing.T) {
	d := newGateDaemon(t)
	d.sessions = []*proto.SessionStatus{
		{ProfileId: profileWork.Id, ProfileName: profileWork.Name, Status: "Connected", Focused: true},
		{ProfileId: profileHome.Id, ProfileName: profileHome.Name, Status: "Connecting"},
	}

	res := runCLI(t, d, "profile", "list")
	require.NoError(t, res.err, res.out)

	assert.Regexp(t, `NAME\s+ACTIVE\s+STATUS`, res.out)
	assert.Regexp(t, `prace\s+✓\s+Connected`, res.out)
	assert.Regexp(t, `doma\s+Connecting`, res.out)
}

func TestProfileList_ProfileWithoutSessionIsIdle(t *testing.T) {
	d := newGateDaemon(t)
	d.sessions = []*proto.SessionStatus{
		{ProfileId: profileWork.Id, ProfileName: profileWork.Name, Status: "Connected", Focused: true},
	}

	res := runCLI(t, d, "profile", "list")
	require.NoError(t, res.err, res.out)

	assert.Regexp(t, `doma\s+Idle`, res.out)
}

func TestProfileList_WithoutTheGateIsWhatItWasToday(t *testing.T) {
	for name, features := range map[string]*proto.GetFeaturesResponse{"gate off": {}, "old daemon": nil} {
		t.Run(name, func(t *testing.T) {
			isolateProfiles(t)
			d := &fakeDaemon{features: features, profiles: []*proto.Profile{profileWork, profileHome}, focused: profileWork.Id}

			res := runCLI(t, d, "profile", "list")
			require.NoError(t, res.err, res.out)

			assert.Equal(t, "NAME   ACTIVE\nprace  ✓\ndoma   \n", res.out)
		})
	}
}

func TestProfileRemoveAndLogout_RunningSessionTellsWhatToDo(t *testing.T) {
	running := gstatus.Errorf(codes.FailedPrecondition, "profile %q is running, bring the connection down first", profileHome.Name)

	t.Run("remove", func(t *testing.T) {
		d := newGateDaemon(t)
		d.failures = map[string]error{"RemoveProfile": running}

		res := runCLI(t, d, "profile", "remove", profileHome.Name)

		require.Error(t, res.err)
		assert.Contains(t, res.err.Error(), "running")
		assert.Contains(t, res.err.Error(), "netbird down --profile "+profileHome.Name)
		assert.NotContains(t, res.err.Error(), "rpc error")
	})

	t.Run("logout", func(t *testing.T) {
		d := newGateDaemon(t)
		d.failures = map[string]error{"Logout": running}

		res := runCLI(t, d, "deregister", "--profile", profileHome.Name)

		require.Error(t, res.err)
		assert.Contains(t, res.err.Error(), "netbird down --profile "+profileHome.Name)
	})

	t.Run("logout of the focused profile", func(t *testing.T) {
		d := newGateDaemon(t)
		d.failures = map[string]error{"Logout": running}

		res := runCLI(t, d, "deregister")

		require.Error(t, res.err)
		assert.Contains(t, res.err.Error(), "netbird down")
	})
}

// Without the gate the error is the one of today.
func TestProfileRemove_WithoutTheGateKeepsItsError(t *testing.T) {
	d := newGateDaemon(t)
	d.features = &proto.GetFeaturesResponse{}
	d.failures = map[string]error{"RemoveProfile": gstatus.Error(codes.FailedPrecondition, "profile is running, bring the connection down first")}

	res := runCLI(t, d, "profile", "remove", profileHome.Name)

	require.Error(t, res.err)
	assert.Equal(t, d.failures["RemoveProfile"].Error(), res.err.Error())
}

func TestSessionFlag_ReachesTheRequest(t *testing.T) {
	selector := func(t *testing.T) *proto.SessionSelector { return selectorOf(t, profileHome.Id) }

	t.Run("networks list", func(t *testing.T) {
		d := newGateDaemon(t)
		res := runCLI(t, d, "networks", "list", "--profile", profileHome.Name)
		require.NoError(t, res.err, res.out)
		assert.True(t, gproto.Equal(selector(t), requestOf[proto.ListNetworksRequest](t, d, "ListNetworks").GetSession()))
	})

	t.Run("networks select", func(t *testing.T) {
		d := newGateDaemon(t)
		res := runCLI(t, d, "networks", "select", "route1", "--profile", profileHome.Name)
		require.NoError(t, res.err, res.out)
		assert.True(t, gproto.Equal(selector(t), requestOf[proto.SelectNetworksRequest](t, d, "SelectNetworks").GetSession()))
	})

	t.Run("networks deselect", func(t *testing.T) {
		d := newGateDaemon(t)
		res := runCLI(t, d, "networks", "deselect", "route1", "--profile", profileHome.Name)
		require.NoError(t, res.err, res.out)
		assert.True(t, gproto.Equal(selector(t), requestOf[proto.SelectNetworksRequest](t, d, "DeselectNetworks").GetSession()))
	})

	t.Run("debug bundle", func(t *testing.T) {
		d := newGateDaemon(t)
		res := runCLI(t, d, "debug", "bundle", "--profile", profileHome.Name)
		require.NoError(t, res.err, res.out)
		assert.True(t, gproto.Equal(selector(t), requestOf[proto.DebugBundleRequest](t, d, "DebugBundle").GetSession()))
	})

	t.Run("debug sync-response", func(t *testing.T) {
		d := newGateDaemon(t)
		res := runCLI(t, d, "debug", "persistence", "on", "--profile", profileHome.Name)
		require.NoError(t, res.err, res.out)
		assert.True(t, gproto.Equal(selector(t), requestOf[proto.SetSyncResponsePersistenceRequest](t, d, "SetSyncResponsePersistence").GetSession()))
	})

	t.Run("debug config", func(t *testing.T) {
		d := newGateDaemon(t)
		res := runCLI(t, d, "debug", "config", "--profile", profileHome.Name)
		require.NoError(t, res.err, res.out)
		assert.Equal(t, profileHome.Id, requestOf[proto.GetConfigRequest](t, d, "GetConfig").GetProfileName())
	})

	t.Run("expose", func(t *testing.T) {
		d := newGateDaemon(t)
		res := runCLI(t, d, "expose", "8080", "--profile", profileHome.Name)
		require.Error(t, res.err, "the fake daemon does not expose")
		assert.True(t, gproto.Equal(selector(t), requestOf[proto.ExposeServiceRequest](t, d, "ExposeService").GetSession()))
	})
}

func TestSessionFlag_WithoutItTheFocusedSessionIsMeant(t *testing.T) {
	t.Run("networks", func(t *testing.T) {
		d := newGateDaemon(t)
		res := runCLI(t, d, "networks", "list")
		require.NoError(t, res.err, res.out)
		assert.Nil(t, requestOf[proto.ListNetworksRequest](t, d, "ListNetworks").GetSession())
		requireNoCall(t, d, "GetFeatures", "ListProfiles")
	})

	t.Run("debug bundle", func(t *testing.T) {
		d := newGateDaemon(t)
		res := runCLI(t, d, "debug", "bundle")
		require.NoError(t, res.err, res.out)
		assert.Nil(t, requestOf[proto.DebugBundleRequest](t, d, "DebugBundle").GetSession())
		requireNoCall(t, d, "GetFeatures")
	})
}

// A daemon that would ignore the selector must not get the request: the command would act on the
// focused session, which is not the one the user named.
func TestSessionFlag_WithoutTheGateIsRefused(t *testing.T) {
	commands := map[string][]string{
		"networks list":  {"networks", "list", "--profile", "doma"},
		"networks sel":   {"networks", "select", "route1", "--profile", "doma"},
		"debug bundle":   {"debug", "bundle", "--profile", "doma"},
		"debug config":   {"debug", "config", "--profile", "doma"},
		"debug sync":     {"debug", "persistence", "on", "--profile", "doma"},
		"expose":         {"expose", "8080", "--profile", "doma"},
		"status profile": {"status", "--profile", "doma"},
	}
	for name, args := range commands {
		for fname, features := range map[string]*proto.GetFeaturesResponse{"gate off": {}, "old daemon": nil} {
			t.Run(name+" "+fname, func(t *testing.T) {
				d := newGateDaemon(t)
				d.features = features

				res := runCLI(t, d, args...)

				require.Error(t, res.err)
				assert.Contains(t, res.err.Error(), "concurrent profiles")
				requireNoCall(t, d, "ListNetworks", "SelectNetworks", "DebugBundle", "GetConfig",
					"SetSyncResponsePersistence", "ExposeService", "Status")
			})
		}
	}
}

func TestSessionFlag_UnknownProfile(t *testing.T) {
	d := newGateDaemon(t)

	res := runCLI(t, d, "networks", "list", "--profile", "nikdo")

	require.Error(t, res.err)
	assert.Contains(t, res.err.Error(), `profile "nikdo" not found`)
	requireNoCall(t, d, "ListNetworks")
}

func TestSessionFlag_AmbiguousProfile(t *testing.T) {
	d := newGateDaemon(t)
	d.profiles = append(d.profiles, &proto.Profile{Id: "ffff0000", Name: "prace"})

	res := runCLI(t, d, "networks", "list", "--profile", "prace")

	require.Error(t, res.err)
	assert.Contains(t, res.err.Error(), "ambiguous")
	assert.Contains(t, res.err.Error(), "--show-id")
	requireNoCall(t, d, "ListNetworks")
}

func TestSessionFlag_IDPrefix(t *testing.T) {
	d := newGateDaemon(t)

	res := runCLI(t, d, "networks", "list", "--profile", profileHome.Id[:3])
	require.NoError(t, res.err, res.out)

	assert.Equal(t, profileHome.Id, requestOf[proto.ListNetworksRequest](t, d, "ListNetworks").GetSession().GetProfile(),
		"the selector carries the full ID the prefix resolved to")
}

func TestStatus_ProfileSelectsItsSession(t *testing.T) {
	d := newGateDaemon(t)
	d.status[profileHome.Id] = "Connected"
	d.fullStatus = true
	d.sessions = []*proto.SessionStatus{
		{ProfileId: profileWork.Id, ProfileName: profileWork.Name, Status: "Idle", Focused: true},
		{ProfileId: profileHome.Id, ProfileName: profileHome.Name, Status: "Connected", InterfaceName: "wt1", OverlayIp: "100.72.0.5/16"},
	}

	res := runCLI(t, d, "status", "--profile", profileHome.Name)
	require.NoError(t, res.err, res.out)

	statuses := requestsOf[proto.StatusRequest](t, d, "Status")
	require.NotEmpty(t, statuses)
	last := statuses[len(statuses)-1]
	assert.True(t, gproto.Equal(selectorOf(t, profileHome.Id), last.GetSession()), "got %v", last.GetSession())
	assert.Contains(t, res.out, "Profile: doma", "the summary is the one of the named session")
}

func TestStatus_WithTheGateSummarizesEverySession(t *testing.T) {
	d := newGateDaemon(t)
	d.status[profileWork.Id] = "Connected"
	d.fullStatus = true
	d.sessions = []*proto.SessionStatus{
		{ProfileId: profileWork.Id, ProfileName: profileWork.Name, Status: "Connected", InterfaceName: "wt0", OverlayIp: "100.71.0.5/16", Focused: true},
		{ProfileId: profileHome.Id, ProfileName: profileHome.Name, Status: "Connecting", InterfaceName: "wt1", OverlayIp: "100.72.0.5/16", Conflict: gproto.String("exit_node")},
	}

	res := runCLI(t, d, "status")
	require.NoError(t, res.err, res.out)

	assert.Contains(t, res.out, "Sessions:")
	assert.Regexp(t, `prace\s+Connected\s+wt0\s+100\.71\.0\.5/16\s+focused`, res.out)
	assert.Regexp(t, `doma\s+Connecting\s+wt1\s+100\.72\.0\.5/16\s+conflict: exit_node`, res.out)
	assert.Contains(t, res.out, "NetBird IP: 100.71.0.5/16", "the summary of the focused session is still there")
}

func TestStatus_JSONGainsSessionsAndKeepsTheRest(t *testing.T) {
	d := newGateDaemon(t)
	d.status[profileWork.Id] = "Connected"
	d.fullStatus = true
	d.sessions = []*proto.SessionStatus{
		{ProfileId: profileWork.Id, ProfileName: profileWork.Name, Status: "Connected", InterfaceName: "wt0", OverlayIp: "100.71.0.5/16", Focused: true},
		{ProfileId: profileHome.Id, ProfileName: profileHome.Name, Status: "Idle"},
	}

	res := runCLI(t, d, "status", "--json")
	require.NoError(t, res.err, res.out)

	var got map[string]json.RawMessage
	require.NoError(t, json.Unmarshal([]byte(res.out), &got), res.out)
	for _, key := range statusJSONKeys {
		assert.Contains(t, got, key, "the existing field %s stays", key)
	}
	require.Contains(t, got, "sessions")

	var sessions []map[string]any
	require.NoError(t, json.Unmarshal(got["sessions"], &sessions))
	require.Len(t, sessions, 2)
	assert.Equal(t, "prace", sessions[0]["profileName"])
	assert.Equal(t, "wt0", sessions[0]["interfaceName"])
	assert.Equal(t, true, sessions[0]["focused"])
	assert.Equal(t, "Idle", sessions[1]["status"])
}

// statusJSONKeys are the fields of `netbird status --json` before sessions existed.
var statusJSONKeys = []string{
	"peers", "cliVersion", "daemonVersion", "daemonStatus", "management", "signal", "relays", "netbirdIp",
	"publicKey", "usesKernelInterface", "wireguardPort", "fqdn", "quantumResistance", "quantumResistancePermissive",
	"networks", "dnsServers", "events", "lazyConnectionEnabled", "profileName", "sshServer",
}

func TestStatus_WithoutTheGateIsWhatItWasToday(t *testing.T) {
	for name, features := range map[string]*proto.GetFeaturesResponse{"gate off": {}, "old daemon": nil} {
		t.Run(name, func(t *testing.T) {
			d := newGateDaemon(t)
			d.features = features
			d.status[profileWork.Id] = "Connected"
			d.fullStatus = true

			res := runCLI(t, d, "status")
			require.NoError(t, res.err, res.out)
			assert.Equal(t, statusSummaryToday, res.out)
			requireNoCall(t, d, "GetFeatures", "ListProfiles")

			res = runCLI(t, d, "status", "--json")
			require.NoError(t, res.err, res.out)
			var got map[string]json.RawMessage
			require.NoError(t, json.Unmarshal([]byte(res.out), &got), res.out)
			assert.NotContains(t, got, "sessions")
			for _, key := range statusJSONKeys {
				assert.Contains(t, got, key)
			}

			res = runCLI(t, d, "status", "--yaml")
			require.NoError(t, res.err, res.out)
			assert.NotRegexp(t, `(?m)^sessions:`, res.out, "the sessions of the daemon, not those of the SSH server")
		})
	}
}

// statusSummaryToday is the text of `netbird status` for testFullStatus as it was before sessions.
var statusSummaryToday = fmt.Sprintf("OS: %s/%s\nDaemon version: 0.0.0-test\nCLI version: development\nProfile: prace\n"+
	"Management: Connected\nSignal: Connected\nRelays: 0/0 Available\nNameservers: 0/0 Available\n"+
	"FQDN: laptop.netbird.selfhosted\nNetBird IP: 100.71.0.5/16\nInterface type: Kernel\nWireguard port: 51820\n"+
	"Quantum resistance: false\nLazy connection: false\nSSH Server: Disabled\nNetworks: -\nPeers count: 0/0 Connected\n",
	runtime.GOOS, runtime.GOARCH)

func TestSSH_ProfileFlagIsParsed(t *testing.T) {
	resetSSHGlobals()
	t.Cleanup(resetSSHGlobals)

	require.NoError(t, validateSSHArgsWithoutFlagParsing(nil, []string{"--profile", "prace", "peer"}))
	assert.Equal(t, "prace", sshProfile)
	assert.Equal(t, "peer", host)

	require.NoError(t, validateSSHArgsWithoutFlagParsing(nil, []string{"peer"}))
	assert.Empty(t, sshProfile, "a command without the flag must not keep the one of the previous")
}

func TestSSH_SessionOfTheFlag(t *testing.T) {
	t.Cleanup(func() { sshProfile = "" })

	t.Run("without the flag the daemon is not asked", func(t *testing.T) {
		d := newGateDaemon(t)
		daemonAddr = d.start(t)
		sshProfile = ""

		target, err := sshSession(t.Context())

		require.NoError(t, err)
		assert.Nil(t, target.selector)
		assert.Empty(t, d.callList(t))
	})

	t.Run("with the gate", func(t *testing.T) {
		d := newGateDaemon(t)
		daemonAddr = d.start(t)
		sshProfile = profileHome.Name

		target, err := sshSession(t.Context())

		require.NoError(t, err)
		assert.True(t, gproto.Equal(selectorOf(t, profileHome.Id), target.selector), "got %v", target.selector)
	})

	t.Run("without the gate", func(t *testing.T) {
		for name, features := range map[string]*proto.GetFeaturesResponse{"gate off": {}, "old daemon": nil} {
			d := newGateDaemon(t)
			d.features = features
			daemonAddr = d.start(t)
			sshProfile = profileHome.Name

			target, err := sshSession(t.Context())

			require.Errorf(t, err, name)
			assert.Nil(t, target.selector)
			assert.Contains(t, err.Error(), "concurrent profiles", name)
		}
	})
}

// A TCP socket carries no identity, and the sessions of different users are told apart by who asks.
func TestConcurrentProfilesRefuseASocketWithoutIdentity(t *testing.T) {
	unixSocket := func(t *testing.T, name string) string {
		t.Helper()
		// t.TempDir would be too long for the path of a unix socket.
		dir, err := os.MkdirTemp("", "nb-gate")
		require.NoError(t, err)
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		return "unix://" + filepath.Join(dir, name)
	}

	for _, tc := range []struct {
		name       string
		daemon     func(t *testing.T) string
		jsonSocket func(t *testing.T) string
		wantFlag   string
	}{
		{
			name:       "the control socket on TCP",
			daemon:     func(*testing.T) string { return "tcp://127.0.0.1:0" },
			jsonSocket: func(*testing.T) string { return "" },
			wantFlag:   "--daemon-addr",
		},
		{
			name:       "the JSON socket on TCP",
			daemon:     func(t *testing.T) string { return unixSocket(t, "daemon.sock") },
			jsonSocket: func(*testing.T) string { return "tcp://127.0.0.1:0" },
			wantFlag:   "--json-socket",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			json := tc.jsonSocket(t)
			useServiceSockets(t, true, tc.daemon(t), json, json != "")

			// Through Start, as a check it does not call protects nothing.
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			p := newProgram(ctx, cancel)
			err := p.Start(nil)
			if err == nil {
				t.Cleanup(func() { p.serv.Stop() })
			}

			require.Error(t, err, "a service with the gate must not start on a socket without identity")
			assert.Contains(t, err.Error(), "unix", "the operator should be told what to change")
			assert.Contains(t, err.Error(), tc.wantFlag, "the operator should be told which socket it is")
			assert.Nil(t, p.serv, "a refused start must not have set up the server")
		})
	}
}

func TestConcurrentProfilesAcceptSocketsWithIdentity(t *testing.T) {
	const unix, tcp = "unix:///var/run/netbird.sock", "tcp://127.0.0.1:0"

	for _, tc := range []struct {
		name        string
		gate        bool
		daemon      string
		json        string
		jsonEnabled bool
		wantErr     bool
	}{
		{name: "the gate on unix sockets", gate: true, daemon: unix, json: unix, jsonEnabled: true},
		{name: "a JSON socket that stays closed does not count", gate: true, daemon: unix, json: tcp, jsonEnabled: false},
		{name: "a JSON socket with an unreadable address is refused", gate: true, daemon: unix, json: "nonsense", jsonEnabled: true, wantErr: true},
		{name: "without the gate the sockets stay what they are", gate: false, daemon: tcp, json: tcp, jsonEnabled: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			useServiceSockets(t, tc.gate, tc.daemon, tc.json, tc.jsonEnabled)

			err := checkConcurrentProfilesSockets()
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
		})
	}
}

// useServiceSockets sets what the service reads its sockets and the gate from.
func useServiceSockets(t *testing.T, gate bool, daemon, json string, jsonEnabled bool) {
	t.Helper()
	originalGate, originalDaemon, originalJSON, originalEnabled := concurrentProfiles, daemonAddr, jsonSocket, enableJSONSocket
	t.Cleanup(func() {
		concurrentProfiles, daemonAddr, jsonSocket, enableJSONSocket = originalGate, originalDaemon, originalJSON, originalEnabled
	})
	concurrentProfiles, daemonAddr, jsonSocket, enableJSONSocket = gate, daemon, json, jsonEnabled
}
