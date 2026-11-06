package proto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	protobuf "google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

// firstSessionField is the lowest field number the concurrent profiles design
// uses for fields added to existing messages. Upstream keeps adding fields in
// sequence, so staying far above it avoids a clash after a merge.
const firstSessionField = 1000

// oldSchema builds the daemon schema as a client built before the session
// fields would know it: no SessionSelector, no SessionStatus and no field
// numbered firstSessionField or above.
func oldSchema(t *testing.T) protoreflect.FileDescriptor {
	t.Helper()

	fdp := protodesc.ToFileDescriptorProto(File_daemon_proto)
	var kept []*descriptorpb.DescriptorProto
	for _, m := range fdp.GetMessageType() {
		if m.GetName() == "SessionSelector" || m.GetName() == "SessionStatus" {
			continue
		}
		stripSessionFields(m)
		kept = append(kept, m)
	}
	fdp.MessageType = kept

	fd, err := protodesc.NewFile(fdp, protoregistry.GlobalFiles)
	require.NoError(t, err, "old schema must build")
	return fd
}

func stripSessionFields(m *descriptorpb.DescriptorProto) {
	var fields []*descriptorpb.FieldDescriptorProto
	for _, f := range m.GetField() {
		if f.GetNumber() >= firstSessionField {
			continue
		}
		fields = append(fields, f)
	}
	m.Field = fields

	// A synthetic oneof of a stripped proto3 optional field would be left empty.
	var oneofs []*descriptorpb.OneofDescriptorProto
	var remap = map[int32]int32{}
	for i, o := range m.GetOneofDecl() {
		used := false
		for _, f := range fields {
			if f.OneofIndex != nil && f.GetOneofIndex() == int32(i) {
				used = true
				break
			}
		}
		if !used {
			continue
		}
		remap[int32(i)] = int32(len(oneofs))
		oneofs = append(oneofs, o)
	}
	m.OneofDecl = oneofs
	for _, f := range fields {
		if f.OneofIndex != nil {
			idx := remap[f.GetOneofIndex()]
			f.OneofIndex = &idx
		}
	}

	for _, n := range m.GetNestedType() {
		stripSessionFields(n)
	}
}

func newOldMessage(t *testing.T, fd protoreflect.FileDescriptor, name protoreflect.Name) *dynamicpb.Message {
	t.Helper()
	md := fd.Messages().ByName(name)
	require.NotNil(t, md, "old schema has message %s", name)
	return dynamicpb.NewMessage(md)
}

func session(profile, username string) *SessionSelector {
	return &SessionSelector{Profile: profile, Username: username}
}

// messagesWithSessionFields lists every existing message that gains fields,
// each populated in all of its old and new fields.
func messagesWithSessionFields() map[protoreflect.Name]protobuf.Message {
	sel := func() *SessionSelector { return session("work", "alice") }
	conflict := "overlay"

	return map[protoreflect.Name]protobuf.Message{
		"DownRequest": &DownRequest{Session: sel(), All: true},
		"StatusRequest": &StatusRequest{
			GetFullPeerStatus: true, ShouldRunProbes: true, WaitForReady: protobuf.Bool(true), Session: sel(),
		},
		"StatusResponse": &StatusResponse{
			Status:        "Connected",
			DaemonVersion: "0.0.0",
			Sessions: []*SessionStatus{
				{
					ProfileId: "p1", ProfileName: "work", Status: "Connected", InterfaceName: "wt1",
					OverlayIp: "100.64.0.1/16", Focused: true, FullStatus: &FullStatus{NetworksRevision: 7},
				},
				{ProfileId: "p2", ProfileName: "home", Status: "Connecting", Conflict: &conflict},
			},
		},
		"Profile":             &Profile{Name: "work", IsActive: true, Id: "p1", ConnectionStatus: "Connected"},
		"SystemEvent":         &SystemEvent{Id: "e1", Message: "m", ProfileId: "p1"},
		"GetFeaturesResponse": &GetFeaturesResponse{DisableProfiles: true, ConcurrentProfilesEnabled: true, MaxSessions: 4},

		"WaitSSOLoginRequest":               &WaitSSOLoginRequest{UserCode: "u", Session: sel()},
		"ListNetworksRequest":               &ListNetworksRequest{Session: sel()},
		"SelectNetworksRequest":             &SelectNetworksRequest{NetworkIDs: []string{"n"}, All: true, Session: sel()},
		"TracePacketRequest":                &TracePacketRequest{SourceIp: "1.1.1.1", Session: sel()},
		"StartCaptureRequest":               &StartCaptureRequest{SnapLen: 96, Session: sel()},
		"StartBundleCaptureRequest":         &StartBundleCaptureRequest{Session: sel()},
		"StopBundleCaptureRequest":          &StopBundleCaptureRequest{Session: sel()},
		"GetPeerSSHHostKeyRequest":          &GetPeerSSHHostKeyRequest{PeerAddress: "peer", Session: sel()},
		"RequestJWTAuthRequest":             &RequestJWTAuthRequest{HasGraphicalSession: true, Session: sel()},
		"WaitJWTTokenRequest":               &WaitJWTTokenRequest{DeviceCode: "d", Session: sel()},
		"RequestExtendAuthSessionRequest":   &RequestExtendAuthSessionRequest{HasGraphicalSession: true, Session: sel()},
		"WaitExtendAuthSessionRequest":      &WaitExtendAuthSessionRequest{DeviceCode: "d", Session: sel()},
		"DismissSessionWarningRequest":      &DismissSessionWarningRequest{Session: sel()},
		"ExposeServiceRequest":              &ExposeServiceRequest{Port: 80, Session: sel()},
		"ListStatesRequest":                 &ListStatesRequest{Session: sel()},
		"CleanStateRequest":                 &CleanStateRequest{StateName: "s", All: true, Session: sel()},
		"DeleteStateRequest":                &DeleteStateRequest{StateName: "s", All: true, Session: sel()},
		"DebugBundleRequest":                &DebugBundleRequest{Anonymize: true, Session: sel()},
		"SetSyncResponsePersistenceRequest": &SetSyncResponsePersistenceRequest{Enabled: true, Session: sel()},
		"SubscribeRequest":                  &SubscribeRequest{Session: sel()},
	}
}

// TestOldClientReadsNewMessages checks I10 in one direction: a message carrying
// the session fields reaches a client that does not know them with every old
// field intact, and passes through it back to a new reader without losing the
// new fields (unknown fields are kept on the wire).
func TestOldClientReadsNewMessages(t *testing.T) {
	old := oldSchema(t)

	for name, msg := range messagesWithSessionFields() {
		t.Run(string(name), func(t *testing.T) {
			wire, err := protobuf.Marshal(msg)
			require.NoError(t, err)

			oldMsg := newOldMessage(t, old, name)
			require.NoError(t, protobuf.Unmarshal(wire, oldMsg), "old client must accept the new message")

			// The fields the old client knows keep their values.
			msg.ProtoReflect().Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
				if fd.Number() >= firstSessionField {
					assert.Nil(t, oldMsg.Descriptor().Fields().ByNumber(fd.Number()),
						"old schema must not know field %d", fd.Number())
					return true
				}
				ofd := oldMsg.Descriptor().Fields().ByNumber(fd.Number())
				require.NotNil(t, ofd, "old schema lost field %d", fd.Number())
				assert.True(t, oldMsg.Has(ofd), "old client must see field %d", fd.Number())
				return true
			})
			assert.NotEmpty(t, oldMsg.GetUnknown(), "fields from %d up must stay as unknown fields", firstSessionField)

			// An old client that forwards or re-serialises the message keeps them.
			rewire, err := protobuf.Marshal(oldMsg)
			require.NoError(t, err)
			back := msg.ProtoReflect().New().Interface()
			require.NoError(t, protobuf.Unmarshal(rewire, back))
			assert.True(t, protobuf.Equal(msg, back), "new fields lost on the way through an old client:\nwant %v\ngot  %v", msg, back)
		})
	}
}

// TestNewClientReadsOldMessages checks I10 in the other direction: messages an
// old client sends parse into the new types with the session fields unset, so a
// request without a selector keeps meaning "the focused session".
func TestNewClientReadsOldMessages(t *testing.T) {
	old := oldSchema(t)

	t.Run("DownRequest", func(t *testing.T) {
		wire, err := protobuf.Marshal(newOldMessage(t, old, "DownRequest"))
		require.NoError(t, err)

		var got DownRequest
		require.NoError(t, protobuf.Unmarshal(wire, &got))
		assert.Nil(t, got.GetSession(), "an old Down has no selector")
		assert.False(t, got.GetAll(), "an old Down does not mean all sessions")
	})

	t.Run("StatusRequest", func(t *testing.T) {
		m := newOldMessage(t, old, "StatusRequest")
		fields := m.Descriptor().Fields()
		m.Set(fields.ByName("getFullPeerStatus"), protoreflect.ValueOfBool(true))
		m.Set(fields.ByName("waitForReady"), protoreflect.ValueOfBool(true))
		wire, err := protobuf.Marshal(m)
		require.NoError(t, err)

		var got StatusRequest
		require.NoError(t, protobuf.Unmarshal(wire, &got))
		assert.True(t, got.GetGetFullPeerStatus())
		assert.True(t, got.GetWaitForReady())
		assert.Nil(t, got.GetSession(), "an old Status has no selector")
	})

	t.Run("StatusResponse", func(t *testing.T) {
		m := newOldMessage(t, old, "StatusResponse")
		m.Set(m.Descriptor().Fields().ByName("status"), protoreflect.ValueOfString("Connected"))
		wire, err := protobuf.Marshal(m)
		require.NoError(t, err)

		var got StatusResponse
		require.NoError(t, protobuf.Unmarshal(wire, &got))
		assert.Equal(t, "Connected", got.GetStatus())
		assert.Empty(t, got.GetSessions(), "an old daemon reports no session list")
	})

	t.Run("Profile", func(t *testing.T) {
		m := newOldMessage(t, old, "Profile")
		fields := m.Descriptor().Fields()
		m.Set(fields.ByName("name"), protoreflect.ValueOfString("work"))
		m.Set(fields.ByName("is_active"), protoreflect.ValueOfBool(true))
		wire, err := protobuf.Marshal(m)
		require.NoError(t, err)

		var got Profile
		require.NoError(t, protobuf.Unmarshal(wire, &got))
		assert.True(t, got.GetIsActive())
		assert.Empty(t, got.GetConnectionStatus(), "an old daemon reports no connection status")
	})

	t.Run("GetFeaturesResponse", func(t *testing.T) {
		m := newOldMessage(t, old, "GetFeaturesResponse")
		m.Set(m.Descriptor().Fields().ByName("disable_profiles"), protoreflect.ValueOfBool(true))
		wire, err := protobuf.Marshal(m)
		require.NoError(t, err)

		var got GetFeaturesResponse
		require.NoError(t, protobuf.Unmarshal(wire, &got))
		assert.True(t, got.GetDisableProfiles())
		assert.False(t, got.GetConcurrentProfilesEnabled(), "an old daemon has no concurrent profiles")
		assert.Zero(t, got.GetMaxSessions())
	})

	t.Run("SystemEvent", func(t *testing.T) {
		m := newOldMessage(t, old, "SystemEvent")
		m.Set(m.Descriptor().Fields().ByName("id"), protoreflect.ValueOfString("e1"))
		wire, err := protobuf.Marshal(m)
		require.NoError(t, err)

		var got SystemEvent
		require.NoError(t, protobuf.Unmarshal(wire, &got))
		assert.Equal(t, "e1", got.GetId())
		assert.Empty(t, got.GetProfileId(), "an old daemon does not tag events with a profile")
	})
}

// TestSessionFieldNumbers pins the wire numbers the design assigns, so a later
// edit cannot silently move a field the released clients already rely on.
func TestSessionFieldNumbers(t *testing.T) {
	md := func(name protoreflect.Name) protoreflect.MessageDescriptor {
		d := File_daemon_proto.Messages().ByName(name)
		require.NotNil(t, d, name)
		return d
	}
	number := func(m, f protoreflect.Name) protoreflect.FieldNumber {
		fd := md(m).Fields().ByName(f)
		require.NotNil(t, fd, "%s.%s", m, f)
		return fd.Number()
	}

	assert.Equal(t, protoreflect.FieldNumber(1000), number("DownRequest", "session"))
	assert.Equal(t, protoreflect.FieldNumber(1001), number("DownRequest", "all"))
	assert.Equal(t, protoreflect.FieldNumber(1000), number("StatusRequest", "session"))
	assert.Equal(t, protoreflect.FieldNumber(1000), number("StatusResponse", "sessions"))
	assert.Equal(t, protoreflect.FieldNumber(1000), number("Profile", "connection_status"))
	assert.Equal(t, protoreflect.FieldNumber(1000), number("SystemEvent", "profile_id"))
	assert.Equal(t, protoreflect.FieldNumber(1000), number("GetFeaturesResponse", "concurrent_profiles_enabled"))
	assert.Equal(t, protoreflect.FieldNumber(1001), number("GetFeaturesResponse", "max_sessions"))

	for i, f := range []protoreflect.Name{"profile", "username"} {
		assert.Equal(t, protoreflect.FieldNumber(i+1), number("SessionSelector", f))
	}
	for i, f := range []protoreflect.Name{
		"profile_id", "profile_name", "status", "interface_name", "overlay_ip", "focused", "conflict", "full_status",
	} {
		assert.Equal(t, protoreflect.FieldNumber(i+1), number("SessionStatus", f))
	}

	// Every selector added to an existing request uses the first new number.
	for name := range messagesWithSessionFields() {
		fd := md(name).Fields().ByName("session")
		if fd == nil {
			continue
		}
		assert.Equal(t, protoreflect.FieldNumber(firstSessionField), fd.Number(), "%s.session", name)
		assert.True(t, fd.HasPresence(), "%s.session must be optional so absent means focused", name)
	}
}
