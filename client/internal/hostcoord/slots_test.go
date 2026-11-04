package hostcoord

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/iface"
)

const (
	autoIface = iface.WgInterfaceDefault
	autoPort  = iface.DefaultWgPort
)

var autoRequest = ResourceRequest{WgIface: autoIface, WgPort: autoPort}

// fakePorts answers port probes without touching the network: listed ports are busy,
// and a request for any port returns the next value of a counter.
type fakePorts struct {
	mu   sync.Mutex
	busy map[int]struct{}
	next atomic.Int64
}

func (f *fakePorts) probe(port int) (int, io.Closer, error) {
	if port == 0 {
		return int(f.next.Add(1)), io.NopCloser(nil), nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, busy := f.busy[port]; busy {
		return 0, nil, errors.New("address already in use")
	}
	return port, io.NopCloser(nil), nil
}

func (f *fakePorts) setBusy(ports ...int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.busy = make(map[int]struct{}, len(ports))
	for _, p := range ports {
		f.busy[p] = struct{}{}
	}
}

func newFakeSlots(t *testing.T, base string) *Slots {
	t.Helper()
	s, _ := newFakeSlotsAndPorts(t, base)
	return s
}

func newFakeSlotsAndPorts(t *testing.T, base string) (*Slots, *fakePorts) {
	t.Helper()
	return newFakeSlotsWith(t, base)
}

func newFakeSlotsWith(t *testing.T, base string, opts ...SlotsOption) (*Slots, *fakePorts) {
	t.Helper()
	s, err := NewSlots(base, opts...)
	require.NoError(t, err)
	t.Cleanup(func() { closeSlots(t, s) })
	ports := &fakePorts{}
	ports.next.Store(30000)
	s.probe = ports.probe
	return s, ports
}

// closeSlots stands in for the end of a process: the file lock goes away with it.
func closeSlots(t *testing.T, s *Slots) {
	t.Helper()
	require.NoError(t, s.Close())
}

func TestSlots_FirstSessionGetsSlotZeroAndTodaysNames(t *testing.T) {
	// A missing sessions.json with no legacy owner is a fresh installation: the first
	// session takes slot 0 and must look exactly like a session does today.
	s := newFakeSlots(t, t.TempDir())

	res, err := s.Reserve(sessionKey("a"), autoRequest)
	require.NoError(t, err)

	assert.Equal(t, Slot(0), res.Slot, "the first session takes slot 0")
	assert.Equal(t, iface.WgInterfaceDefault, res.Interface, "slot 0 keeps the default name")
	if runtime.GOOS == "linux" {
		assert.Equal(t, "wt0", res.Interface, "slot 0 is wt0 on Linux")
	}
	assert.Equal(t, uint16(51820), res.Port, "slot 0 keeps the default port")
}

func TestSlots_LowestFreeIncludingHolesAndBeyondSessionLimit(t *testing.T) {
	base := t.TempDir()
	// Slots 0 to 7 taken except 1 and 5, with numbers past the default session limit of 4.
	writeSessionsFile(t, base, `{"version":1,"sessions":[
		{"profile":"s0","username":"u","slot":0,"desired":"up"},
		{"profile":"s2","username":"u","slot":2,"desired":"up"},
		{"profile":"s3","username":"u","slot":3,"desired":"down"},
		{"profile":"s4","username":"u","slot":4,"desired":"down"},
		{"profile":"s6","username":"u","slot":6,"desired":"down"},
		{"profile":"s7","username":"u","slot":7,"desired":"down"}
	]}`)
	s := newFakeSlots(t, base)

	for _, want := range []struct {
		profile string
		slot    Slot
		name    string
		port    uint16
	}{
		{"new1", 1, "wt1", 51821},
		{"new2", 5, "wt5", 51825},
		{"new3", 8, "wt8", 51828},
		{"new4", 9, "wt9", 51829},
		{"new5", 10, "wt10", 51830},
	} {
		res, err := s.Reserve(sessionKey(want.profile), autoRequest)
		require.NoError(t, err)
		assert.Equal(t, want.slot, res.Slot, "lowest free slot for %s", want.profile)
		assert.Equal(t, want.name, res.Interface, "interface of %s", want.profile)
		assert.Equal(t, want.port, res.Port, "port of %s", want.profile)
	}

	// A session on an existing high slot runs even though five others hold lower ones.
	res, err := s.Reserve(sessionKey("s7"), autoRequest)
	require.NoError(t, err)
	assert.Equal(t, Slot(7), res.Slot, "a stored slot past the session limit stays valid")
	assert.Equal(t, "wt7", res.Interface, "the name follows the slot number, not the session count")
}

func TestSlots_UsernameIsPartOfTheKey(t *testing.T) {
	s := newFakeSlots(t, t.TempDir())

	a, err := s.Reserve(SessionKey{Profile: "same", Username: "alice"}, autoRequest)
	require.NoError(t, err)
	b, err := s.Reserve(SessionKey{Profile: "same", Username: "bob"}, autoRequest)
	require.NoError(t, err)

	assert.NotEqual(t, a.Slot, b.Slot, "legacy profile IDs are not unique across users")
}

func TestSlots_StableAcrossRestart(t *testing.T) {
	base := t.TempDir()
	first := newFakeSlots(t, base)
	leases := make(map[string]Lease)
	for _, p := range []string{"a", "b", "c"} {
		res, err := first.Reserve(sessionKey(p), autoRequest)
		require.NoError(t, err)
		leases[p] = res.Lease
	}
	require.NoError(t, first.SetDesired(sessionKey("b"), DesiredUp))
	first.Release(leases["a"])
	require.NoError(t, first.Remove(sessionKey("a")))
	closeSlots(t, first)

	// A new instance reads the state only from the file.
	second := newFakeSlots(t, base)

	assert.ElementsMatch(t, []SlotRecord{
		{Key: sessionKey("b"), Slot: 1, Desired: DesiredUp},
		{Key: sessionKey("c"), Slot: 2, Desired: DesiredDown},
	}, second.Records(), "slots and desired state survive a restart")

	res, err := second.Reserve(sessionKey("c"), autoRequest)
	require.NoError(t, err)
	assert.Equal(t, Slot(2), res.Slot, "a known session keeps its slot even when a lower one is free")
	assert.Equal(t, "wt2", res.Interface, "the interface stays stable")

	res, err = second.Reserve(sessionKey("d"), autoRequest)
	require.NoError(t, err)
	assert.Equal(t, Slot(0), res.Slot, "the removed profile's slot is free after a restart too")
}

func TestSlots_ReleasedOnlyByRemovingTheProfile(t *testing.T) {
	s := newFakeSlots(t, t.TempDir())
	first, err := s.Reserve(sessionKey("a"), autoRequest)
	require.NoError(t, err)

	// Stopping a session gives back the running resources, not the slot.
	s.Release(first.Lease)
	res, err := s.Reserve(sessionKey("b"), autoRequest)
	require.NoError(t, err)
	assert.Equal(t, Slot(1), res.Slot, "a stopped session keeps its slot")

	restarted, err := s.Reserve(sessionKey("a"), autoRequest)
	require.NoError(t, err)
	assert.Equal(t, Slot(0), restarted.Slot, "a restarted session gets its slot back")

	require.ErrorIs(t, s.Remove(sessionKey("a")), ErrSessionRunning)
	assert.Len(t, s.Records(), 2, "a running session keeps its slot")

	s.Release(restarted.Lease)
	require.NoError(t, s.Remove(sessionKey("a")))
	assert.Len(t, s.Records(), 1, "removal drops the record")

	res, err = s.Reserve(sessionKey("c"), autoRequest)
	require.NoError(t, err)
	assert.Equal(t, Slot(0), res.Slot, "the slot of a removed profile is free again")

	require.NoError(t, s.Remove(sessionKey("never-seen")), "a profile that never ran has no slot to free")
}

func TestSlots_AutoValuesAreNotWrittenAnywhere(t *testing.T) {
	base := t.TempDir()
	s := newFakeSlots(t, base)
	req := autoRequest
	for _, p := range []string{"a", "b"} {
		_, err := s.Reserve(sessionKey(p), req)
		require.NoError(t, err)
	}
	assert.Equal(t, autoRequest, req, "the request from the profile config stays unchanged")

	data, err := os.ReadFile(filepath.Join(base, sessionsFileName))
	require.NoError(t, err)
	assert.NotContains(t, string(data), "wt1", "the slot name is derived, never stored")
	assert.NotContains(t, string(data), "51821", "the slot port is derived, never stored")
}

func TestSlots_ExplicitInterfaceIsRespected(t *testing.T) {
	s := newFakeSlots(t, t.TempDir())
	_, err := s.Reserve(sessionKey("a"), autoRequest)
	require.NoError(t, err)

	res, err := s.Reserve(sessionKey("b"), ResourceRequest{WgIface: "office", WgPort: autoPort})
	require.NoError(t, err)
	assert.Equal(t, "office", res.Interface, "an explicit name is kept")
	assert.Equal(t, Slot(1), res.Slot, "the session still gets its own slot")
	assert.Equal(t, uint16(51821), res.Port, "an automatic port still follows the slot")
}

func TestSlots_ExplicitInterfaceCollisionIsRefused(t *testing.T) {
	s := newFakeSlots(t, t.TempDir())
	first, err := s.Reserve(sessionKey("a"), ResourceRequest{WgIface: "office", WgPort: autoPort})
	require.NoError(t, err)
	_, err = s.Reserve(sessionKey("b"), autoRequest)
	require.NoError(t, err)

	tests := map[string]string{
		"same explicit name":   "office",
		"name of an auto slot": "wt1",
	}
	for name, wanted := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := s.Reserve(sessionKey("late"), ResourceRequest{WgIface: wanted, WgPort: autoPort})
			require.ErrorIs(t, err, ErrInterfaceConflict)
		})
	}
	assert.Len(t, s.Records(), 2, "a refused session gets no slot")

	// The running session keeps what it has, and the name opens up once it stops.
	again, err := s.Reserve(sessionKey("a"), ResourceRequest{WgIface: "office", WgPort: autoPort})
	require.NoError(t, err, "a session does not collide with itself on a retry")
	assert.Equal(t, first.Slot, again.Slot, "a retry keeps the slot")
	assert.Equal(t, first.Interface, again.Interface, "a retry keeps the interface")
	assert.Equal(t, first.Port, again.Port, "a retry keeps the port")

	s.Release(again.Lease)
	res, err := s.Reserve(sessionKey("late"), ResourceRequest{WgIface: "office", WgPort: autoPort})
	require.NoError(t, err, "only a running session holds a name")
	assert.Equal(t, "office", res.Interface, "the name is free after the stop")
}

func TestSlots_AutoNameTakenByExplicitSessionIsRefused(t *testing.T) {
	s := newFakeSlots(t, t.TempDir())
	// Session a sits on slot 0 and claims the name slot 1 would derive.
	_, err := s.Reserve(sessionKey("a"), ResourceRequest{WgIface: "wt1", WgPort: autoPort})
	require.NoError(t, err)

	_, err = s.Reserve(sessionKey("b"), autoRequest)
	assert.ErrorIs(t, err, ErrInterfaceConflict, "bringing up the same name would delete the running link")
}

func TestSlots_FailedRetryKeepsTheRunningReservation(t *testing.T) {
	s := newFakeSlots(t, t.TempDir())
	_, err := s.Reserve(sessionKey("a"), ResourceRequest{WgIface: "office", WgPort: autoPort})
	require.NoError(t, err)

	_, err = s.Reserve(sessionKey("a"), ResourceRequest{WgIface: "bad/name", WgPort: autoPort})
	require.ErrorIs(t, err, ErrInvalidInterfaceName)

	_, err = s.Reserve(sessionKey("b"), ResourceRequest{WgIface: "office", WgPort: autoPort})
	assert.ErrorIs(t, err, ErrInterfaceConflict, "a rejected retry must not give up what is running")
}

func TestSlots_InterfaceNameValidation(t *testing.T) {
	tests := map[string]string{
		"empty":             "",
		"dot":               ".",
		"two dots":          "..",
		"too long":          strings.Repeat("x", 16),
		"slash":             "wt/0",
		"colon":             "wt:0",
		"space":             "wt 0",
		"tab":               "wt\t0",
		"newline":           "wt\n0",
		"vertical tab":      "wt\v0",
		"form feed":         "wt\f0",
		"carriage return":   "wt\r0",
		"nul cuts the name": "wt0\x00x",
		"latin-1 nbsp byte": "wt\xa00",
		"utf-8 nbsp":        "wt 0",
	}
	for name, value := range tests {
		t.Run(name, func(t *testing.T) {
			s := newFakeSlots(t, t.TempDir())
			_, err := s.Reserve(sessionKey("a"), ResourceRequest{WgIface: value, WgPort: autoPort})
			require.ErrorIs(t, err, ErrInvalidInterfaceName)
			assert.Empty(t, s.Records(), "a rejected session gets no slot")
		})
	}

	s := newFakeSlots(t, t.TempDir())
	longest := strings.Repeat("x", 15)
	res, err := s.Reserve(sessionKey("a"), ResourceRequest{WgIface: longest, WgPort: autoPort})
	require.NoError(t, err, "15 bytes fit the kernel limit")
	assert.Equal(t, longest, res.Interface, "the longest name stays whole")
}

func TestSlots_PortValidation(t *testing.T) {
	for _, port := range []int{-1, 65536, 1 << 20} {
		t.Run(fmt.Sprint(port), func(t *testing.T) {
			s := newFakeSlots(t, t.TempDir())
			_, err := s.Reserve(sessionKey("a"), ResourceRequest{WgIface: autoIface, WgPort: port})
			require.ErrorIs(t, err, ErrInvalidPort)
			assert.Empty(t, s.Records(), "a rejected session gets no slot")
		})
	}
}

func TestSlots_ExplicitPortIsRespected(t *testing.T) {
	s := newFakeSlots(t, t.TempDir())
	res, err := s.Reserve(sessionKey("a"), ResourceRequest{WgIface: autoIface, WgPort: 40000})
	require.NoError(t, err)
	assert.Equal(t, uint16(40000), res.Port, "an explicit port is kept")
	assert.Equal(t, iface.WgInterfaceDefault, res.Interface, "an automatic name still follows the slot")
}

func TestSlots_ExplicitPortCollisionIsRefused(t *testing.T) {
	s := newFakeSlots(t, t.TempDir())
	_, err := s.Reserve(sessionKey("a"), ResourceRequest{WgIface: autoIface, WgPort: 40000})
	require.NoError(t, err)
	auto, err := s.Reserve(sessionKey("b"), autoRequest)
	require.NoError(t, err)

	_, err = s.Reserve(sessionKey("c"), ResourceRequest{WgIface: autoIface, WgPort: 40000})
	require.ErrorIs(t, err, ErrPortConflict)
	_, err = s.Reserve(sessionKey("c"), ResourceRequest{WgIface: autoIface, WgPort: int(auto.Port)})
	require.ErrorIs(t, err, ErrPortConflict)
	assert.Len(t, s.Records(), 2, "a refused session gets no slot")
}

func TestSlots_AutoPortMovesAwayFromAnotherSession(t *testing.T) {
	s := newFakeSlots(t, t.TempDir())
	// Session a on slot 0 claims the port slot 1 would derive, and has not bound it yet.
	_, err := s.Reserve(sessionKey("a"), ResourceRequest{WgIface: autoIface, WgPort: 51821})
	require.NoError(t, err)

	res, err := s.Reserve(sessionKey("b"), autoRequest)
	require.NoError(t, err)
	assert.NotEqual(t, uint16(51821), res.Port, "the reservation counts as occupied before anything binds")
	assert.Equal(t, uint16(30001), res.Port, "the port comes from the allocator")
}

func TestSlots_PortZeroAsksTheAllocator(t *testing.T) {
	s := newFakeSlots(t, t.TempDir())
	res, err := s.Reserve(sessionKey("a"), ResourceRequest{WgIface: autoIface, WgPort: 0})
	require.NoError(t, err)
	assert.Equal(t, uint16(30001), res.Port, "port 0 means any free port, as it does today")
}

func TestSlots_PortBeyondRangeUsesAllocator(t *testing.T) {
	base := t.TempDir()
	// 51820 + 13715 is the last usable port, 13716 and later must not wrap or truncate.
	writeSessionsFile(t, base, `{"version":1,"sessions":[
		{"profile":"last","username":"u","slot":13715,"desired":"down"},
		{"profile":"over","username":"u","slot":13716,"desired":"down"},
		{"profile":"far","username":"u","slot":4294967295,"desired":"down"}
	]}`)
	s := newFakeSlots(t, base)

	res, err := s.Reserve(sessionKey("last"), autoRequest)
	require.NoError(t, err)
	assert.Equal(t, uint16(65535), res.Port, "the last port of the range is still derived")
	assert.Equal(t, "wt13715", res.Interface, "the name has no digit limit")

	res, err = s.Reserve(sessionKey("over"), autoRequest)
	require.NoError(t, err)
	assert.Equal(t, uint16(30001), res.Port, "past the range the port comes from the allocator")

	res, err = s.Reserve(sessionKey("far"), autoRequest)
	require.NoError(t, err)
	assert.Equal(t, uint16(30002), res.Port, "the largest slot does not overflow")
	assert.Equal(t, "wt4294967295", res.Interface, "the largest slot still fits the name limit")
}

func TestSlots_AllocatorSkipsReservedPorts(t *testing.T) {
	s, ports := newFakeSlotsAndPorts(t, t.TempDir())
	_, err := s.Reserve(sessionKey("a"), ResourceRequest{WgIface: autoIface, WgPort: 30001})
	require.NoError(t, err)

	// Session a reserved the next value of the allocator but has not bound it.
	ports.setBusy(51821)
	res, err := s.Reserve(sessionKey("b"), autoRequest)
	require.NoError(t, err)
	assert.Equal(t, uint16(30002), res.Port, "the allocator must not hand out a reserved port")
}

func TestSlots_AllocatorRejectsPortOutOfRange(t *testing.T) {
	s := newFakeSlots(t, t.TempDir())
	s.probe = func(int) (int, io.Closer, error) {
		return 70000, io.NopCloser(nil), nil
	}

	_, err := s.Reserve(sessionKey("a"), ResourceRequest{WgIface: autoIface, WgPort: 0})
	require.ErrorIs(t, err, ErrNoFreePort)
	assert.Empty(t, s.Records(), "a session without a port gets no slot")
}

func TestSlots_AllocatorFailureIsReturned(t *testing.T) {
	s := newFakeSlots(t, t.TempDir())
	probeErr := errors.New("no sockets left")
	s.probe = func(int) (int, io.Closer, error) {
		return 0, nil, probeErr
	}

	_, err := s.Reserve(sessionKey("a"), autoRequest)
	require.ErrorIs(t, err, probeErr)
	assert.Empty(t, s.Records(), "a session without a port gets no slot")
}

func TestSlots_PortHeldByAnotherProcess(t *testing.T) {
	// A real socket on loopback stands in for the other process, and the real probe
	// bound to loopback must see it.
	occupant, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = occupant.Close() })
	busy := occupant.LocalAddr().(*net.UDPAddr).Port
	require.Greater(t, busy, 1, "the system returned a usable port")

	s, err := NewSlots(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { closeSlots(t, s) })
	s.probe = listenUDPProbe(net.IPv4(127, 0, 0, 1))
	s.basePort = busy - 1

	first, err := s.Reserve(sessionKey("a"), ResourceRequest{WgIface: autoIface, WgPort: 0})
	require.NoError(t, err)
	require.NotEqual(t, uint16(busy), first.Port, "the allocator must skip the occupied port")

	res, err := s.Reserve(sessionKey("b"), autoRequest)
	require.NoError(t, err)
	assert.Equal(t, Slot(1), res.Slot, "the second session takes slot 1")
	assert.NotEqual(t, uint16(busy), res.Port, "slot 1 would derive the occupied port")
	assert.NotZero(t, res.Port, "the allocator returned a real port")
	assert.NotEqual(t, first.Port, res.Port, "two sessions never share a port")

	explicit, err := s.Reserve(sessionKey("c"), ResourceRequest{WgIface: autoIface, WgPort: busy})
	require.NoError(t, err, "an explicit port taken outside the daemon falls back as it does today")
	assert.NotEqual(t, uint16(busy), explicit.Port, "the occupied port is not handed out")

	s.Release(res.Lease)
	require.NoError(t, occupant.Close())
	res, err = s.Reserve(sessionKey("b"), autoRequest)
	require.NoError(t, err)
	assert.Equal(t, uint16(busy), res.Port, "the derived port returns once it is free")
	assert.Equal(t, Slot(1), res.Slot, "the fallback did not change the slot")
}

func TestSlots_ReleaseFreesPortAndName(t *testing.T) {
	s := newFakeSlots(t, t.TempDir())
	first, err := s.Reserve(sessionKey("a"), ResourceRequest{WgIface: "office", WgPort: 40000})
	require.NoError(t, err)

	s.Release(first.Lease)
	s.Release(first.Lease)

	res, err := s.Reserve(sessionKey("b"), ResourceRequest{WgIface: "office", WgPort: 40000})
	require.NoError(t, err, "a stopped session holds neither name nor port")
	assert.Equal(t, uint16(40000), res.Port, "the port is free again")
}

func TestSlots_StaleReleaseKeepsTheNewReservation(t *testing.T) {
	s := newFakeSlots(t, t.TempDir())
	office := ResourceRequest{WgIface: "office", WgPort: 40000}

	// A session restarts: the new start reserves before the old engine has cleaned up.
	old, err := s.Reserve(sessionKey("a"), office)
	require.NoError(t, err)
	current, err := s.Reserve(sessionKey("a"), office)
	require.NoError(t, err)
	assert.NotEqual(t, old.Lease, current.Lease, "every reservation has its own lease")

	s.Release(old.Lease)

	_, err = s.Reserve(sessionKey("b"), ResourceRequest{WgIface: "office", WgPort: autoPort})
	assert.ErrorIs(t, err, ErrInterfaceConflict, "the late release must not free the running interface")
	_, err = s.Reserve(sessionKey("b"), ResourceRequest{WgIface: "other", WgPort: 40000})
	assert.ErrorIs(t, err, ErrPortConflict, "the late release must not free the running port")
	assert.ErrorIs(t, s.Remove(sessionKey("a")), ErrSessionRunning, "the session is still running")

	s.Release(current.Lease)
	_, err = s.Reserve(sessionKey("b"), office)
	assert.NoError(t, err, "the newest lease frees the resources")
}

func TestSlots_LeaseOfAFailedRetryStaysValid(t *testing.T) {
	s := newFakeSlots(t, t.TempDir())
	first, err := s.Reserve(sessionKey("a"), ResourceRequest{WgIface: "office", WgPort: autoPort})
	require.NoError(t, err)

	_, err = s.Reserve(sessionKey("a"), ResourceRequest{WgIface: "bad/name", WgPort: autoPort})
	require.ErrorIs(t, err, ErrInvalidInterfaceName)

	s.Release(first.Lease)
	_, err = s.Reserve(sessionKey("b"), ResourceRequest{WgIface: "office", WgPort: autoPort})
	assert.NoError(t, err, "a refused retry did not replace the lease that holds the resources")
}

func TestSlots_LeaseOnlyFreesItsOwnSession(t *testing.T) {
	s := newFakeSlots(t, t.TempDir())
	_, err := s.Reserve(sessionKey("a"), ResourceRequest{WgIface: "office", WgPort: autoPort})
	require.NoError(t, err)

	s.Release(Lease{})

	_, err = s.Reserve(sessionKey("b"), ResourceRequest{WgIface: "office", WgPort: autoPort})
	assert.ErrorIs(t, err, ErrInterfaceConflict, "the zero lease holds nothing and frees nothing")
}

func TestSlots_SlotZeroOwnerOnMissingFile(t *testing.T) {
	// An upgrade: the state file of "legacy" belongs to slot 0 although sessions.json does
	// not exist yet. Another profile starting first must not take wt0 from it.
	base := t.TempDir()
	s, _ := newFakeSlotsWith(t, base, WithSlotZeroOwner(sessionKey("legacy")))

	assert.Equal(t, []SlotRecord{{Key: sessionKey("legacy"), Slot: 0, Desired: DesiredDown}}, s.Records(),
		"the owner has slot 0 before any session starts")

	stored, err := os.ReadFile(filepath.Join(base, sessionsFileName))
	require.NoError(t, err, "the migration is stored right away, not with the first session")
	assert.Contains(t, string(stored), `"legacy"`, "the file names the owner of slot 0")

	other, err := s.Reserve(sessionKey("work"), autoRequest)
	require.NoError(t, err)
	assert.Equal(t, Slot(1), other.Slot, "another profile starting first gets slot 1")
	assert.Equal(t, "wt1", other.Interface, "and stays away from the interface of the owner")

	legacy, err := s.Reserve(sessionKey("legacy"), autoRequest)
	require.NoError(t, err)
	assert.Equal(t, Slot(0), legacy.Slot, "the owner lands on the slot of its state file")
	assert.Equal(t, iface.WgInterfaceDefault, legacy.Interface, "with today's interface name")
}

func TestSlots_SlotZeroOwnerSurvivesARestartWithoutTheOption(t *testing.T) {
	base := t.TempDir()
	first, _ := newFakeSlotsWith(t, base, WithSlotZeroOwner(sessionKey("legacy")))
	closeSlots(t, first)

	second := newFakeSlots(t, base)
	res, err := second.Reserve(sessionKey("work"), autoRequest)
	require.NoError(t, err)
	assert.Equal(t, Slot(1), res.Slot, "the crash between migration and first session loses nothing")
}

func TestSlots_SlotZeroOwnerIgnoredWhenTheFileExists(t *testing.T) {
	stored := map[string]string{
		"other owner": `{"version":1,"sessions":[{"profile":"work","username":"u","slot":0,"desired":"up"}]}`,
		"no sessions": `{"version":1,"sessions":[]}`,
	}
	for name, content := range stored {
		t.Run(name, func(t *testing.T) {
			base := t.TempDir()
			path := writeSessionsFile(t, base, content)

			s, _ := newFakeSlotsWith(t, base, WithSlotZeroOwner(sessionKey("legacy")))

			got, err := os.ReadFile(path)
			require.NoError(t, err)
			assert.Equal(t, content, string(got), "the migration only runs without a file")
			assert.NotContains(t, s.Records(), SlotRecord{Key: sessionKey("legacy"), Slot: 0, Desired: DesiredDown},
				"a stored state wins over the option")
		})
	}
}

func TestSlots_SlotZeroOwnerInvalidIsRefused(t *testing.T) {
	base := t.TempDir()

	_, err := NewSlots(base, WithSlotZeroOwner(SessionKey{Profile: "../x", Username: "u"}))
	require.Error(t, err, "the next start would refuse a file holding this key")
	assert.NoFileExists(t, filepath.Join(base, sessionsFileName), "nothing is stored for a refused owner")

	_ = newFakeSlots(t, base) // a refused migration must not leave the lock taken
}

func TestSlots_ClosedInstanceRefusesEverything(t *testing.T) {
	// The lock is gone after Close, so a successor may already own the file.
	base := t.TempDir()
	s := newFakeSlots(t, base)
	res, err := s.Reserve(sessionKey("a"), autoRequest)
	require.NoError(t, err)
	closeSlots(t, s)
	require.NoError(t, s.Close(), "Close is idempotent")

	successor := newFakeSlots(t, base)
	require.NoError(t, successor.SetDesired(sessionKey("a"), DesiredUp))
	path := filepath.Join(base, sessionsFileName)
	before, err := os.ReadFile(path)
	require.NoError(t, err)

	_, err = s.Reserve(sessionKey("b"), autoRequest)
	assert.ErrorIs(t, err, ErrSlotsClosed)
	assert.ErrorIs(t, s.SetDesired(sessionKey("a"), DesiredDown), ErrSlotsClosed)
	assert.ErrorIs(t, s.Remove(sessionKey("a")), ErrSlotsClosed)
	s.Release(res.Lease)
	assert.Empty(t, s.Records(), "a closed instance knows nothing anymore")

	after, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, string(before), string(after), "a closed instance must not touch the file of its successor")
}

func TestSlots_SetDesired(t *testing.T) {
	base := t.TempDir()
	s := newFakeSlots(t, base)
	_, err := s.Reserve(sessionKey("a"), autoRequest)
	require.NoError(t, err)
	assert.Equal(t, DesiredDown, s.Records()[0].Desired, "a reservation alone does not ask for a reconnect")

	require.NoError(t, s.SetDesired(sessionKey("a"), DesiredUp))
	closeSlots(t, s)
	reopened := newFakeSlots(t, base)
	assert.Equal(t, DesiredUp, reopened.Records()[0].Desired, "the desired state is stored")

	require.ErrorIs(t, reopened.SetDesired(sessionKey("unknown"), DesiredUp), ErrUnknownSession)
	require.Error(t, reopened.SetDesired(sessionKey("a"), DesiredState("maybe")), "an unknown state is refused")
	assert.Equal(t, DesiredUp, reopened.Records()[0].Desired, "a refused change keeps the old state")
}

func TestSlots_RecordsIsACopy(t *testing.T) {
	s := newFakeSlots(t, t.TempDir())
	_, err := s.Reserve(sessionKey("a"), autoRequest)
	require.NoError(t, err)

	s.Records()[0].Slot = 99

	assert.Equal(t, Slot(0), s.Records()[0].Slot, "callers cannot change the stored slot")
}

func TestSlots_ConcurrentReservations(t *testing.T) {
	// The fake probe never binds, exactly like the gap in freePort between closing the
	// probe and the engine binding the port. Its allocator also walks into the ports
	// that later slots derive, so only the reservation can keep the results apart.
	const sessions = 64
	base := t.TempDir()
	s, ports := newFakeSlotsAndPorts(t, base)
	// A few derived ports are taken, so part of the sessions goes through the allocator.
	ports.setBusy(51823, 51827, 51840)
	ports.next.Store(51830)

	results := make([]SessionResources, sessions)
	errs := make([]error, sessions)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range sessions {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results[i], errs[i] = s.Reserve(sessionKey(fmt.Sprintf("p%d", i)), autoRequest)
			_ = s.Records()
		}()
	}
	close(start)
	wg.Wait()

	slots := make(map[Slot]struct{})
	names := make(map[string]struct{})
	usedPorts := make(map[uint16]struct{})
	for i, res := range results {
		require.NoError(t, errs[i])
		slots[res.Slot] = struct{}{}
		names[res.Interface] = struct{}{}
		usedPorts[res.Port] = struct{}{}
	}
	assert.Len(t, slots, sessions, "every session has its own slot")
	assert.Len(t, names, sessions, "every session has its own interface")
	assert.Len(t, usedPorts, sessions, "every session has its own port")
	for slot := range sessions {
		assert.Contains(t, slots, Slot(slot), "the slots have no holes")
	}

	inMemory := s.Records()
	closeSlots(t, s)
	reopened := newFakeSlots(t, base)
	assert.ElementsMatch(t, inMemory, reopened.Records(), "the file matches memory after the race")
}

func TestSlots_ConcurrentLifecycle(t *testing.T) {
	base := t.TempDir()
	s := newFakeSlots(t, base)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			key := sessionKey(fmt.Sprintf("p%d", i))
			for range 25 {
				res, err := s.Reserve(key, autoRequest)
				assert.NoError(t, err)
				assert.NoError(t, s.SetDesired(key, DesiredUp))
				s.Release(res.Lease)
				assert.NoError(t, s.Remove(key))
			}
		}()
	}
	wg.Wait()

	assert.Empty(t, s.Records(), "every profile was removed")
	closeSlots(t, s)
	_ = newFakeSlots(t, base) // the file stays valid after concurrent writes
}

func TestStoredRecords_ReadsWithoutTouchingAnything(t *testing.T) {
	base := filepath.Join(t.TempDir(), "state")

	records, err := StoredRecords(base)
	require.NoError(t, err)
	assert.Empty(t, records, "a missing file should give no sessions")
	_, err = os.Stat(base)
	assert.ErrorIs(t, err, os.ErrNotExist, "reading must not create the directory")

	require.NoError(t, os.MkdirAll(base, 0o750))
	writeSessionsFile(t, base, `{"version":1,"sessions":[
		{"profile":"second","username":"bob","slot":4,"desired":"up"},
		{"profile":"first","username":"alice","slot":1,"desired":"down"}
	]}`)

	records, err = StoredRecords(base)
	require.NoError(t, err)
	assert.Equal(t, []SlotRecord{
		{Key: SessionKey{Profile: "first", Username: "alice"}, Slot: 1, Desired: DesiredDown},
		{Key: SessionKey{Profile: "second", Username: "bob"}, Slot: 4, Desired: DesiredUp},
	}, records, "records should come ordered by slot")

	entries, err := os.ReadDir(base)
	require.NoError(t, err)
	assert.Len(t, entries, 1, "reading must not add a lock file next to the sessions file")
}

// The daemon reads the file before anyone holds the lock, and must not need it: a foreground
// instance holding the lock would otherwise stop its crash cleanup.
func TestStoredRecords_WorksWhileLocked(t *testing.T) {
	base := t.TempDir()
	slots, err := NewSlots(base, WithSlotZeroOwner(SessionKey{Profile: "owner", Username: "alice"}))
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, slots.Close()) })

	records, err := StoredRecords(base)
	require.NoError(t, err)
	require.Len(t, records, 1, "the owner should be stored")
	assert.Equal(t, Slot(0), records[0].Slot, "the owner should hold slot 0")
}

func TestStoredRecords_RefusesCorruptFile(t *testing.T) {
	base := t.TempDir()
	path := writeSessionsFile(t, base, `{"version":1,"sessions":[{"profile":"a","slot":0}]}`)

	_, err := StoredRecords(base)
	assert.ErrorIs(t, err, ErrCorruptSessions)

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"profile":"a"`, "a corrupt file should stay in place")
}

// A session has to be on record before its desired state can be stored, and that must not
// take its resources: the resources of a session that does not run stay free.
func TestSlots_EnsureStoresASlotWithoutReserving(t *testing.T) {
	base := t.TempDir()
	first := SessionKey{Profile: "first", Username: "u"}
	second := SessionKey{Profile: "second", Username: "u"}

	s, err := NewSlots(base)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Close()) })

	slot, err := s.Ensure(first)
	require.NoError(t, err)
	assert.Equal(t, Slot(0), slot, "the first session gets the lowest slot")

	slot, err = s.Ensure(second)
	require.NoError(t, err)
	assert.Equal(t, Slot(1), slot, "the next session gets the next slot")

	slot, err = s.Ensure(first)
	require.NoError(t, err)
	assert.Equal(t, Slot(0), slot, "a known session keeps its slot")

	require.NoError(t, s.SetDesired(second, DesiredUp))

	stored, err := StoredRecords(base)
	require.NoError(t, err)
	assert.Equal(t, []SlotRecord{
		{Key: first, Slot: 0, Desired: DesiredDown},
		{Key: second, Slot: 1, Desired: DesiredUp},
	}, stored, "the records must reach the disk")

	assert.NoError(t, s.Remove(first), "a session that was only ensured holds no resources")
}

func TestSlots_EnsureAfterCloseIsRefused(t *testing.T) {
	s, err := NewSlots(t.TempDir())
	require.NoError(t, err)
	require.NoError(t, s.Close())

	_, err = s.Ensure(SessionKey{Profile: "p"})
	assert.ErrorIs(t, err, ErrSlotsClosed)
}
