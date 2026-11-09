//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/client/proto"
)

// listDaemon answers ListProfiles with fixed rows and GetConfig with the default
// profile's management URL, or with configErr when it is set.
type listDaemon struct {
	proto.DaemonServiceClient
	profiles      []*proto.Profile
	managementURL string
	configErr     error
	configAsked   []string
}

func (d *listDaemon) ListProfiles(context.Context, *proto.ListProfilesRequest, ...grpc.CallOption) (*proto.ListProfilesResponse, error) {
	return &proto.ListProfilesResponse{Profiles: d.profiles}, nil
}

func (d *listDaemon) GetConfig(_ context.Context, in *proto.GetConfigRequest, _ ...grpc.CallOption) (*proto.GetConfigResponse, error) {
	d.configAsked = append(d.configAsked, in.GetProfileName())
	if d.configErr != nil {
		return nil, d.configErr
	}
	return &proto.GetConfigResponse{ManagementUrl: d.managementURL}, nil
}

func listedIDs(t *testing.T, d *listDaemon) []string {
	t.Helper()

	profiles, err := NewProfiles(stubConn{client: d}, nil, nil).List(context.Background(), "alice")
	require.NoError(t, err)
	ids := make([]string, 0, len(profiles))
	for _, p := range profiles {
		ids = append(ids, p.ID)
	}
	return ids
}

func TestProfilesList_DefaultVisibility(t *testing.T) {
	defaultRow := func(active bool) *proto.Profile {
		return &proto.Profile{Id: "default", Name: "default", IsActive: active}
	}
	work := &proto.Profile{Id: "work-1a2b", Name: "work", IsActive: true}
	home := &proto.Profile{Id: "home-3c4d", Name: "home"}

	tests := []struct {
		name   string
		daemon *listDaemon
		want   []string
	}{
		{
			name:   "unused default is hidden next to other profiles",
			daemon: &listDaemon{profiles: []*proto.Profile{defaultRow(false), work, home}, managementURL: "https://api.netbird.io:443"},
			want:   []string{"work-1a2b", "home-3c4d"},
		},
		{
			name:   "default with no management URL is hidden",
			daemon: &listDaemon{profiles: []*proto.Profile{defaultRow(false), work}},
			want:   []string{"work-1a2b"},
		},
		{
			name:   "default on a self-hosted management stays",
			daemon: &listDaemon{profiles: []*proto.Profile{defaultRow(false), work}, managementURL: "https://vpn.example.com:443"},
			want:   []string{"default", "work-1a2b"},
		},
		{
			name:   "active default stays",
			daemon: &listDaemon{profiles: []*proto.Profile{defaultRow(true), home}},
			want:   []string{"default", "home-3c4d"},
		},
		{
			name:   "default as the only profile stays",
			daemon: &listDaemon{profiles: []*proto.Profile{defaultRow(false)}},
			want:   []string{"default"},
		},
		{
			name:   "unreadable default config keeps the default listed",
			daemon: &listDaemon{profiles: []*proto.Profile{defaultRow(false), work}, configErr: errors.New("unavailable")},
			want:   []string{"default", "work-1a2b"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, listedIDs(t, tt.daemon), "listed profile IDs")
		})
	}
}

func TestProfilesList_AsksForTheDefaultConfig(t *testing.T) {
	d := &listDaemon{profiles: []*proto.Profile{{Id: "default"}, {Id: "work-1a2b", IsActive: true}}}
	listedIDs(t, d)
	assert.Equal(t, []string{"default"}, d.configAsked, "GetConfig must read the default profile, not the active one")
}
