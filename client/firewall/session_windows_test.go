//go:build windows

package firewall

import (
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/firewall/uspfilter/common"
	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/iface/wgbackend"
)

// fakeFlags is the adapter state of the slots: true means a flag that lets packets cross is on.
type fakeFlags struct {
	mu         sync.Mutex
	open       map[uint32]bool
	absent     map[uint32]bool
	failSet    error
	isolations int
}

func newFakeFlags() *fakeFlags {
	return &fakeFlags{open: map[uint32]bool{}, absent: map[uint32]bool{}}
}

func (f *fakeFlags) isolate(slot uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.absent[slot] {
		return errAdapterAbsent
	}
	if f.failSet != nil {
		return f.failSet
	}
	f.isolations++
	f.open[slot] = false
	return nil
}

func (f *fakeFlags) check(slot uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.absent[slot] && f.open[slot] {
		return errors.New("forwarding is on")
	}
	return nil
}

func (f *fakeFlags) setOpen(slot uint32) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.open[slot] = true
}

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

func TestSessionIsolation_AddNeverClaimsKernelIsolation(t *testing.T) {
	iso := newSessionIsolation(newFakeFlags())
	result, err := iso.Add("wt1", wgaddr.MustParseWGAddress("100.81.0.1/16"))
	require.NoError(t, err)
	assert.False(t, result.Kernel, "adapter flags do not count as kernel isolation, a session without firewall is refused")
	assert.False(t, result.IPv6Disabled, "the flags cover IPv6 as well")
}

func TestSessionIsolation_VerifyWithoutASessionFails(t *testing.T) {
	assert.Error(t, newSessionIsolation(newFakeFlags()).Verify())
}

func TestSessionIsolation_AttachRequiresAdd(t *testing.T) {
	flags := newFakeFlags()
	iso := newSessionIsolation(flags)
	assert.Error(t, iso.attach("wt1", 1), "an adapter of a session the isolation does not know is refused")
	assert.Zero(t, flags.isolations, "and nothing is changed on the host")
}

func TestSessionIsolation_VerifyAndRestore(t *testing.T) {
	flags := newFakeFlags()
	iso := newSessionIsolation(flags)
	for _, name := range []string{"wt1", "wt2"} {
		_, err := iso.Add(name, wgaddr.Address{})
		require.NoError(t, err)
	}
	require.NoError(t, iso.attach("wt1", 1))
	assert.NoError(t, iso.Verify(), "wt2 has no adapter yet, which is not a loss")

	// Something on the host, ICS for instance, turns forwarding on for the adapter of slot 1.
	flags.setOpen(1)
	err := iso.Verify()
	require.Error(t, err, "a flag turned on is a lost isolation")
	assert.Contains(t, err.Error(), "wt1", "the error names the session")

	require.NoError(t, iso.Restore())
	assert.NoError(t, iso.Verify(), "Restore turns the flag off again")
}

func TestSessionIsolation_AbsentAdapterIsNoLoss(t *testing.T) {
	flags := newFakeFlags()
	iso := newSessionIsolation(flags)
	_, err := iso.Add("wt1", wgaddr.Address{})
	require.NoError(t, err)
	require.NoError(t, iso.attach("wt1", 1))

	// The engine closed the adapter, and the session has not left the isolation yet.
	flags.mu.Lock()
	flags.absent[1] = true
	flags.mu.Unlock()
	assert.NoError(t, iso.Verify(), "an adapter that is gone delivers nothing")
	assert.NoError(t, iso.Restore(), "and there is nothing to restore on it")
}

func TestSessionIsolation_RemoveStopsChecking(t *testing.T) {
	flags := newFakeFlags()
	iso := newSessionIsolation(flags)
	_, err := iso.Add("wt1", wgaddr.Address{})
	require.NoError(t, err)
	require.NoError(t, iso.attach("wt1", 1))
	require.NoError(t, iso.Remove("wt1"))

	flags.setOpen(1)
	assert.NoError(t, iso.Verify(), "a session that left is not checked")
	assert.Error(t, iso.attach("wt1", 1), "and cannot attach without being added again")
}

func TestNewSessionFirewall_Refusals(t *testing.T) {
	flags := newFakeFlags()
	iso := newSessionIsolation(flags)
	_, err := iso.Add("wt1", wgaddr.Address{})
	require.NoError(t, err)
	userspace := sessionTestIface{name: "wt1", userspace: true}

	tests := []struct {
		name                string
		iface               IFaceMapper
		disableServerRoutes bool
		session             SessionConfig
	}{
		{"no isolation", userspace, false, SessionConfig{Slot: 1, Source: noOtherSessions{}}},
		{"no isolation source", userspace, false, SessionConfig{Slot: 1, Isolation: iso}},
		{"no userspace bind", sessionTestIface{name: "wt1"}, false, SessionConfig{Slot: 1, Isolation: iso, Source: noOtherSessions{}}},
		{"server routes disabled", userspace, true, SessionConfig{Slot: 1, Isolation: iso, Source: noOtherSessions{}}},
		{"not in the isolation", sessionTestIface{name: "wt9", userspace: true}, false, SessionConfig{Slot: 9, Isolation: iso, Source: noOtherSessions{}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fm, err := NewSessionFirewall(t.Context(), tt.iface, nil, nil, tt.disableServerRoutes, 1280, tt.session)
			assert.ErrorIs(t, err, ErrSessionNotIsolated)
			assert.Nil(t, fm, "a refused session gets no firewall")
		})
	}
	assert.Zero(t, flags.isolations, "a refusal changes nothing on the host")
}

func TestNewSessionFirewall_FailedFlagsRefuse(t *testing.T) {
	flags := newFakeFlags()
	flags.failSet = errors.New("access denied")
	iso := newSessionIsolation(flags)
	_, err := iso.Add("wt1", wgaddr.Address{})
	require.NoError(t, err)

	fm, err := NewSessionFirewall(t.Context(), sessionTestIface{name: "wt1", userspace: true}, nil, nil, false, 1280,
		SessionConfig{Slot: 1, Isolation: iso, Source: noOtherSessions{}})
	assert.ErrorIs(t, err, ErrSessionNotIsolated, "a session whose adapter cannot be isolated does not run")
	assert.Nil(t, fm)
}
