package cmd

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
)

const focusReturnTimeout = 10 * time.Second

// focusReturn is where the focus was before `up --profile` moved it on a daemon with concurrent
// profiles. The switch and the Up are separate RPCs, so only the command knows that the switch was
// part of an up and is to be undone when the session does not come up.
type focusReturn struct {
	id       string
	username string
	// mirror is the local active profile before the switch, empty when it could not be read.
	mirror profilemanager.ID
}

// focusBeforeSwitch reads the focus ahead of the switch of `up --profile`. It returns nil without
// the gate, where the switch is meant to stay, and when the focus cannot be read, such as the focus
// of another user: the up then goes on without giving anything back.
func focusBeforeSwitch(ctx context.Context, pm *profilemanager.ProfileManager) *focusReturn {
	conn, err := DialClientGRPCServer(ctx, daemonAddr)
	if err != nil {
		log.Debugf("failed to connect to the daemon to read its focus: %v", err)
		return nil
	}
	defer conn.Close()
	client := proto.NewDaemonServiceClient(conn)

	if gate, err := daemonConcurrentProfiles(ctx, client); err != nil || gate != gateEnabled {
		return nil
	}
	active, err := client.GetActiveProfile(ctx, &proto.GetActiveProfileRequest{})
	if err != nil || active.GetId() == "" {
		log.Debugf("failed to read the focus of the daemon: %v", err)
		return nil
	}

	f := &focusReturn{id: active.GetId(), username: active.GetUsername()}
	if mirror, err := pm.GetActiveProfile(); err == nil {
		f.mirror = mirror.ID
	}
	return f
}

// giveBack moves the focus back after an up of target failed. It leaves the focus on target when
// the session runs after all, as a plain down is then to end it, and when someone else has moved
// the focus since. Profiles are compared by ID: the username the daemon reports for the focus is
// the legacy directory of the profile, not the user who switched to it.
func (f *focusReturn) giveBack(ctx context.Context, pm *profilemanager.ProfileManager, target profilemanager.ID) {
	if f == nil || f.id == target.String() {
		return
	}

	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), focusReturnTimeout)
	defer cancel()

	conn, err := DialClientGRPCServer(ctx, daemonAddr)
	if err != nil {
		log.Warnf("failed to connect to the daemon to give the focus back: %v", err)
		return
	}
	defer conn.Close()
	client := proto.NewDaemonServiceClient(conn)

	if !focusStillOn(ctx, client, target) {
		return
	}

	if _, err := client.SwitchProfile(ctx, &proto.SwitchProfileRequest{ProfileName: &f.id, Username: &f.username}); err != nil {
		log.Warnf("failed to give the focus back to profile %s: %v", f.id, err)
		return
	}
	if f.mirror == "" {
		return
	}
	if err := pm.SwitchProfile(f.mirror); err != nil {
		log.Warnf("failed to restore the local active profile: %v", err)
	}
}

// focusStillOn reports whether the focus is on the session of target and that session does not run.
func focusStillOn(ctx context.Context, client proto.DaemonServiceClient, target profilemanager.ID) bool {
	active, err := client.GetActiveProfile(ctx, &proto.GetActiveProfileRequest{})
	if err != nil {
		log.Warnf("failed to read the focus of the daemon: %v", err)
		return false
	}
	if active.GetId() != target.String() {
		return false
	}

	status, err := client.Status(ctx, &proto.StatusRequest{
		Session: &proto.SessionSelector{Profile: target.String(), Username: active.GetUsername()},
	})
	if err != nil {
		log.Warnf("failed to read the status of profile %s: %v", target, err)
		return false
	}
	switch internal.StatusType(status.GetStatus()) {
	case internal.StatusConnected, internal.StatusConnecting:
		return false
	default:
		return true
	}
}
