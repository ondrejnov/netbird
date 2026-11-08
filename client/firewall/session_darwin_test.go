//go:build darwin && !ios

package firewall

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/firewall/uspfilter/common"
	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/iface/wgbackend"
)

type sessionTestIface struct {
	name      string
	userspace bool
}

func (i sessionTestIface) Name() string { return i.name }

func (sessionTestIface) Address() wgaddr.Address {
	return wgaddr.MustParseWGAddress("100.81.0.1/16")
}

func (i sessionTestIface) IsUserspaceBind() bool { return i.userspace }

func (sessionTestIface) SetFilter(device.PacketFilter) error { return nil }

func (sessionTestIface) GetDevice() *device.FilteredDevice { return nil }

func (sessionTestIface) GetWGDevice() *wgbackend.Device { return nil }

type noOtherSessions struct{}

func (noOtherSessions) OtherSessions() (common.IsolationSnapshot, error) {
	return common.IsolationSnapshot{}, nil
}

// macOS has no per-interface switch for forwarding or the weak host model, so a session without
// its userspace firewall must never count as isolated.
func TestSessionIsolation_AddNeverClaimsKernelIsolationOnMacOS(t *testing.T) {
	iso := NewSessionIsolation()
	result, err := iso.Add("utun101", wgaddr.MustParseWGAddress("100.81.0.1/16"))
	require.NoError(t, err)
	assert.False(t, result.Kernel, "the kernel isolates nothing, a session without firewall is refused")
	assert.False(t, result.IPv6Disabled, "the userspace firewall covers IPv6 as well")
	assert.NoError(t, iso.Verify(), "an added session verifies")
}

func TestSessionIsolation_VerifyWithoutASessionFailsOnMacOS(t *testing.T) {
	assert.Error(t, NewSessionIsolation().Verify())
}

func TestNewSessionFirewall_RefusalsOnMacOS(t *testing.T) {
	iso := NewSessionIsolation()
	_, err := iso.Add("utun101", wgaddr.Address{})
	require.NoError(t, err)
	userspace := sessionTestIface{name: "utun101", userspace: true}

	tests := []struct {
		name                string
		iface               IFaceMapper
		disableServerRoutes bool
		session             SessionConfig
	}{
		{"no isolation", userspace, false, SessionConfig{Slot: 1, Source: noOtherSessions{}}},
		{"no isolation source", userspace, false, SessionConfig{Slot: 1, Isolation: iso}},
		{"no userspace bind", sessionTestIface{name: "utun101"}, false, SessionConfig{Slot: 1, Isolation: iso, Source: noOtherSessions{}}},
		{"server routes disabled", userspace, true, SessionConfig{Slot: 1, Isolation: iso, Source: noOtherSessions{}}},
		{"not in the isolation", sessionTestIface{name: "utun109", userspace: true}, false, SessionConfig{Slot: 9, Isolation: iso, Source: noOtherSessions{}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fm, err := NewSessionFirewall(t.Context(), tt.iface, nil, nil, tt.disableServerRoutes, 1280, tt.session)
			assert.ErrorIs(t, err, ErrSessionNotIsolated)
			assert.Nil(t, fm, "a refused session gets no firewall")
		})
	}
}

func TestSessionIsolation_RemovedSessionIsRefusedOnMacOS(t *testing.T) {
	iso := NewSessionIsolation()
	_, err := iso.Add("utun101", wgaddr.Address{})
	require.NoError(t, err)
	require.NoError(t, iso.Remove("utun101"))

	fm, err := NewSessionFirewall(t.Context(), sessionTestIface{name: "utun101", userspace: true}, nil, nil, false, 1280,
		SessionConfig{Slot: 1, Isolation: iso, Source: noOtherSessions{}})
	assert.ErrorIs(t, err, ErrSessionNotIsolated, "a session that left the isolation gets no firewall")
	assert.Nil(t, fm)
}
