//go:build !android

package firewall

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/firewall/uspfilter/common"
	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/iface/wgbackend"
)

type sessionTestIface struct {
	name string
}

func (i sessionTestIface) Name() string { return i.name }

func (i sessionTestIface) Address() wgaddr.Address {
	return wgaddr.MustParseWGAddress("100.64.0.1/16")
}

func (sessionTestIface) IsUserspaceBind() bool { return true }

func (sessionTestIface) SetFilter(device.PacketFilter) error { return nil }

func (sessionTestIface) GetDevice() *device.FilteredDevice { return nil }

func (sessionTestIface) GetWGDevice() *wgbackend.Device { return nil }

type noOtherSessions struct{}

func (noOtherSessions) OtherSessions() (common.IsolationSnapshot, error) {
	return common.IsolationSnapshot{Overlays: []netip.Prefix{}}, nil
}

func isolationWithBackend(t *testing.T, backend FWType) *SessionIsolation {
	t.Helper()
	isolation := NewSessionIsolation()
	isolation.detect = func() FWType { return backend }
	_, err := isolation.decidedBackend()
	require.NoError(t, err)
	return isolation
}

// Each of these would leave a session running with nothing to stop its peers (I6). Nothing here
// reaches a backend: the refusal comes first.
func TestNewSessionFirewallRefusesWhatWouldNotIsolate(t *testing.T) {
	iface := sessionTestIface{name: "wt1"}

	t.Run("no isolation", func(t *testing.T) {
		_, err := NewSessionFirewall(iface, nil, nil, false, 1280, SessionConfig{Source: noOtherSessions{}})
		assert.ErrorIs(t, err, ErrSessionNotIsolated)
	})

	t.Run("no isolation source", func(t *testing.T) {
		isolation := isolationWithBackend(t, UNKNOWN)
		_, err := NewSessionFirewall(iface, nil, nil, false, 1280, SessionConfig{Isolation: isolation})
		assert.ErrorIs(t, err, ErrSessionNotIsolated)
	})

	for _, backend := range []FWType{NFTABLES, IPTABLES} {
		t.Run("native backend without the session in the kernel isolation", func(t *testing.T) {
			isolation := isolationWithBackend(t, backend)
			_, err := NewSessionFirewall(iface, nil, nil, false, 1280, SessionConfig{Isolation: isolation, Source: noOtherSessions{}})
			assert.ErrorIs(t, err, ErrSessionNotIsolated, "a native backend makes the kernel isolation mandatory, also with a userspace bind")
		})
	}
}

// The discovery runs once. Its answer depends on the tables the first session creates, and two
// sessions on different backends would not share one isolation.
func TestSessionIsolationDecidesTheBackendOnce(t *testing.T) {
	calls := 0
	isolation := NewSessionIsolation()
	isolation.detect = func() FWType {
		calls++
		return UNKNOWN
	}

	result, err := isolation.Add("wt0", wgaddr.MustParseWGAddress("100.64.0.1/16"))
	require.NoError(t, err)
	assert.False(t, result.Kernel, "without a native backend the kernel enforces nothing")

	_, err = isolation.Add("wt1", wgaddr.MustParseWGAddress("100.65.0.1/16"))
	require.NoError(t, err)
	assert.Equal(t, 1, calls, "the discovery should run once")

	assert.NoError(t, isolation.Verify(), "there is nothing in the kernel to compare")
	assert.NoError(t, isolation.Remove("wt0"))
}

func TestSessionIsolationVerifyWithoutASessionFails(t *testing.T) {
	err := NewSessionIsolation().Verify()
	assert.Error(t, err, "a verify before any Add has nothing to vouch for")
	assert.False(t, errors.Is(err, ErrSessionNotIsolated))
}
