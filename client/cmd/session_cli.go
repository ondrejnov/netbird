package cmd

import (
	"context"
	"fmt"
	"strings"

	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
)

const (
	sessionProfileFlag = "profile"
	sessionProfileDesc = "profile whose session the command acts on, the focused one if not set (needs a daemon with concurrent profiles)"

	downAllFlag = "all"
	downAllDesc = "disconnect every session (needs a daemon with concurrent profiles)"
)

var (
	// sessionProfile is the --profile of the commands that act on one session.
	sessionProfile string
	downAll        bool
)

const (
	msgGateOff = "--%s needs concurrent profiles: reinstall the service with " +
		"`netbird service install --enable-concurrent-profiles` and restart it"
	msgGateLegacy = "--%s needs concurrent profiles, which this daemon is too old to offer: update the daemon"
)

// gateState tells how the daemon stands to concurrent profiles.
type gateState int

const (
	// gateLegacy is a daemon that does not know the feature at all.
	gateLegacy gateState = iota
	// gateDisabled is a daemon that knows it and runs without it.
	gateDisabled
	// gateEnabled is a daemon with the feature gate on.
	gateEnabled
)

// daemonConcurrentProfiles asks the daemon for its feature gate. A daemon that predates
// GetFeatures is one without the feature. Any other failure is returned: a command that
// would treat an unknown answer as "off" could take a connection down that it should leave.
func daemonConcurrentProfiles(ctx context.Context, client proto.DaemonServiceClient) (gateState, error) {
	resp, err := client.GetFeatures(ctx, &proto.GetFeaturesRequest{})
	if err != nil {
		if gstatus.Code(err) == codes.Unimplemented {
			return gateLegacy, nil
		}
		return gateDisabled, fmt.Errorf("read the daemon features: %w", err)
	}
	if resp.GetConcurrentProfilesEnabled() {
		return gateEnabled, nil
	}
	return gateDisabled, nil
}

// requireConcurrentProfiles fails with the reason when the daemon cannot act on a named
// session. flag names the option that needs it. An older daemon would ignore the selector
// and act on its one connection, which is not the session the user named.
func requireConcurrentProfiles(ctx context.Context, client proto.DaemonServiceClient, flag string) error {
	state, err := daemonConcurrentProfiles(ctx, client)
	if err != nil {
		return err
	}
	switch state {
	case gateEnabled:
		return nil
	case gateLegacy:
		return fmt.Errorf(msgGateLegacy, flag)
	default:
		return fmt.Errorf(msgGateOff, flag)
	}
}

// sessionTarget is a session the user named on the command line. The zero value is no session
// named, which means the focused one.
type sessionTarget struct {
	selector *proto.SessionSelector
	// name is the display name of the profile, ID its ID.
	name string
	id   string
}

// resolveSessionFlag turns the --profile of a command into the session it names. It returns the
// zero target when the flag is not set, which makes the command act on the focused session as it
// always did.
func resolveSessionFlag(ctx context.Context, client proto.DaemonServiceClient, handle string) (sessionTarget, error) {
	if handle == "" {
		return sessionTarget{}, nil
	}
	if err := requireConcurrentProfiles(ctx, client, sessionProfileFlag); err != nil {
		return sessionTarget{}, err
	}

	currUser, err := profilemanager.InvokingUser()
	if err != nil {
		return sessionTarget{}, fmt.Errorf("get current user: %w", err)
	}
	resp, err := client.ListProfiles(ctx, &proto.ListProfilesRequest{Username: currUser.Username})
	if err != nil {
		return sessionTarget{}, fmt.Errorf("list profiles: %w", err)
	}
	profile, err := matchProfile(resp.GetProfiles(), handle)
	if err != nil {
		return sessionTarget{}, err
	}

	return sessionTarget{
		selector: &proto.SessionSelector{Profile: profile.GetId(), Username: currUser.Username},
		name:     profile.GetName(),
		id:       profile.GetId(),
	}, nil
}

// sessionSelectorOf is the selector of target, nil for the focused session.
func sessionSelectorOf(target sessionTarget) *proto.SessionSelector {
	return target.selector
}

// sessionFromFlag resolves the --profile of a command on an open daemon connection.
func sessionFromFlag(ctx context.Context, client proto.DaemonServiceClient) (*proto.SessionSelector, error) {
	target, err := resolveSessionFlag(ctx, client, sessionProfile)
	if err != nil {
		return nil, err
	}
	return target.selector, nil
}

// matchProfile finds the profile a handle names the way the daemon does: by exact ID, by a unique
// name, then by a unique ID prefix.
func matchProfile(profiles []*proto.Profile, handle string) (*proto.Profile, error) {
	for _, p := range profiles {
		if p.GetId() == handle {
			return p, nil
		}
	}

	byName := func(p *proto.Profile) bool { return p.GetName() == handle }
	byPrefix := func(p *proto.Profile) bool { return strings.HasPrefix(p.GetId(), handle) }
	for _, matches := range []func(*proto.Profile) bool{byName, byPrefix} {
		found := filterProfiles(profiles, matches)
		switch len(found) {
		case 0:
			continue
		case 1:
			return found[0], nil
		default:
			return nil, ambiguousProfileError(handle, len(found))
		}
	}
	return nil, fmt.Errorf("profile %q not found", handle)
}

func filterProfiles(profiles []*proto.Profile, matches func(*proto.Profile) bool) []*proto.Profile {
	var found []*proto.Profile
	for _, p := range profiles {
		if matches(p) {
			found = append(found, p)
		}
	}
	return found
}

func ambiguousProfileError(handle string, count int) error {
	return fmt.Errorf("profile %q is ambiguous, it matches %d profiles\n"+
		"Run `netbird profile list --show-id` to see IDs, then name the profile by ID prefix", handle, count)
}

// upRequestFor is the Up request for the session of target, the focused one for nil.
func upRequestFor(target sessionTarget) *proto.UpRequest {
	if target.selector == nil {
		return &proto.UpRequest{}
	}
	id, username := target.id, target.selector.GetUsername()
	return &proto.UpRequest{ProfileName: &id, Username: &username}
}

// runningElsewhere picks the sessions that are connected or connecting apart from the focused
// one. A session that waits for a login is not running, and neither is an idle one.
func runningElsewhere(sessions []*proto.SessionStatus) []*proto.SessionStatus {
	var running []*proto.SessionStatus
	for _, s := range sessions {
		if s.GetFocused() {
			continue
		}
		if status := s.GetStatus(); strings.EqualFold(status, "connected") || strings.EqualFold(status, "connecting") {
			running = append(running, s)
		}
	}
	return running
}

// describeSessions lists sessions as `name (status, interface)` for a message to the user.
func describeSessions(sessions []*proto.SessionStatus) string {
	parts := make([]string, 0, len(sessions))
	for _, s := range sessions {
		detail := s.GetStatus()
		if s.GetInterfaceName() != "" {
			detail += ", " + s.GetInterfaceName()
		}
		parts = append(parts, fmt.Sprintf("%s (%s)", profilemanager.StripCtrlChars(s.GetProfileName()), detail))
	}
	return strings.Join(parts, ", ")
}

// stillRunningHint says which sessions keep running after a command that took one down, and
// how to take them down. It is empty when nothing else runs.
func stillRunningHint(sessions []*proto.SessionStatus) string {
	running := runningElsewhere(sessions)
	if len(running) == 0 {
		return ""
	}
	return fmt.Sprintf("Still running: %s\nTake them down with `netbird down --profile <name>` or `netbird down --all`.\n",
		describeSessions(running))
}

// runningSessionError explains a refusal to touch a running session, and the command that
// ends the run. handle is what the user named, empty for the focused session. A daemon
// that refuses for another reason keeps its own words.
func runningSessionError(err error, handle string) error {
	st, ok := gstatus.FromError(err)
	if !ok || st.Code() != codes.FailedPrecondition || !strings.Contains(st.Message(), "bring") {
		return err
	}
	down := "netbird down"
	if handle != "" {
		down += " --profile " + handle
	}
	return fmt.Errorf("%s\nRun `%s` first", st.Message(), down)
}
