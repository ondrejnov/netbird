package hostcoord

import (
	"cmp"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/iface"
)

const (
	slotInterfacePrefix = "wt"
	maxPort             = 65535
	// anyFreePort asks the allocator directly, which is what freePort does with 0.
	anyFreePort = 0
)

var (
	// ErrInterfaceConflict reports an interface name held by a running session.
	// Bringing the session up anyway would delete the link of the other session.
	ErrInterfaceConflict = errors.New("interface name is used by a running session")
	// ErrForeignLink reports an interface under the name of a session that no session created.
	ErrForeignLink = errors.New("interface name is used by something else on this host")
	// ErrInvalidInterfaceName reports a name the kernel would refuse.
	ErrInvalidInterfaceName = errors.New("invalid interface name")
	// ErrPortConflict reports an explicit port reserved by a running session.
	ErrPortConflict = errors.New("port is used by a running session")
	// ErrInvalidPort reports a port outside the UDP range.
	ErrInvalidPort = errors.New("invalid port")
	// ErrNoFreePort reports that the allocator found no usable port.
	ErrNoFreePort = errors.New("no free port")
	// ErrSessionRunning reports an operation that needs the session stopped first.
	ErrSessionRunning = errors.New("session is running")
	// ErrUnknownSession reports a session without a stored slot.
	ErrUnknownSession = errors.New("unknown session")
	// ErrSlotsClosed reports use of an instance after Close. It no longer holds the lock,
	// so another instance may own the sessions file by now.
	ErrSlotsClosed = errors.New("slots are closed")
)

// Slot is the permanent number of a session. It is not tied to the session limit, and
// its width keeps every derived interface name within the kernel limit.
type Slot uint32

// DesiredState says whether a session should run after a daemon restart.
type DesiredState string

const (
	// DesiredUp means the session should be connected.
	DesiredUp DesiredState = "up"
	// DesiredDown means the session should stay disconnected.
	DesiredDown DesiredState = "down"
)

func (d DesiredState) valid() bool {
	return d == DesiredUp || d == DesiredDown
}

// SlotRecord is the stored state of one session.
type SlotRecord struct {
	Key     SessionKey
	Slot    Slot
	Desired DesiredState
}

// ResourceRequest carries the interface and port values of a profile config as they
// are. The default values mean "follow the slot", anything else is explicit.
type ResourceRequest struct {
	WgIface string
	WgPort  int
}

// SessionResources are the host resources a session runs with.
type SessionResources struct {
	Slot      Slot
	Interface string
	Port      uint16
	// Lease is what Release needs to give these resources back.
	Lease Lease
}

// Lease identifies one successful Reserve. Only the newest lease of a session holds its
// resources, so a late Release from an old instance cannot free those of its successor.
// The zero value holds nothing.
type Lease struct {
	key        SessionKey
	generation uint64
}

// portProbe binds a UDP port, or any free one for 0, and returns the bound port.
type portProbe func(port int) (int, io.Closer, error)

// Slots assigns permanent slots and the interface and port of running sessions.
type Slots struct {
	// bringUpMu serializes allocation only and must not be held across login or
	// network waits. Under it a port is either free or reserved, which closes the gap
	// between probing a port and the engine binding it.
	bringUpMu sync.Mutex
	store     *sessionStore
	lock      io.Closer
	closed    bool
	records   map[SessionKey]slotState
	running   map[SessionKey]SessionResources
	// generation numbers the leases of this instance. The first one is 1, so the zero
	// Lease never matches.
	generation uint64

	probe    portProbe
	basePort int
}

// SlotsOption configures NewSlots.
type SlotsOption func(*slotsOptions)

type slotsOptions struct {
	slotZeroOwner *SessionKey
}

// WithSlotZeroOwner names the session whose state file predates slots, because such a
// file belongs to slot 0. It only applies when the sessions file does not exist.
func WithSlotZeroOwner(owner SessionKey) SlotsOption {
	return func(o *slotsOptions) {
		o.slotZeroOwner = &owner
	}
}

// NewSlots takes the lock of base and loads the slots stored there, until Close. A second
// instance on the same base gets ErrSessionsLocked, a corrupt file an error, and neither
// changes any state on disk. A missing file gives an empty state, or with
// WithSlotZeroOwner a state holding that owner on slot 0, stored before NewSlots returns.
func NewSlots(base string, opts ...SlotsOption) (*Slots, error) {
	var options slotsOptions
	for _, opt := range opts {
		opt(&options)
	}

	lock, err := lockSessions(base)
	if err != nil {
		return nil, err
	}

	store := newSessionStore(base)
	records, err := loadOrMigrate(store, options.slotZeroOwner)
	if err != nil {
		closeSessionsLock(lock)
		return nil, err
	}
	return &Slots{
		store:    store,
		lock:     lock,
		records:  records,
		running:  make(map[SessionKey]SessionResources),
		probe:    listenUDPProbe(nil),
		basePort: iface.DefaultWgPort,
	}, nil
}

// loadOrMigrate stores the owner right away: if the first session only stored it, a
// crash before that session would hand slot 0 to whichever profile starts next.
func loadOrMigrate(store *sessionStore, slotZeroOwner *SessionKey) (map[SessionKey]slotState, error) {
	records, found, err := store.load()
	if err != nil {
		return nil, err
	}
	if found || slotZeroOwner == nil {
		return records, nil
	}

	records[*slotZeroOwner] = slotState{slot: 0, desired: DesiredDown}
	if err := store.save(records); err != nil {
		return nil, fmt.Errorf("store owner of slot 0: %w", err)
	}
	return records, nil
}

// Close gives up the lock and forgets the state. Everything but Release and Records is
// refused afterwards, because writing from memory could undo a successor.
func (s *Slots) Close() error {
	s.bringUpMu.Lock()
	defer s.bringUpMu.Unlock()

	if s.closed {
		return nil
	}
	s.closed = true
	s.records = nil
	s.running = nil
	if err := s.lock.Close(); err != nil {
		return fmt.Errorf("close sessions lock: %w", err)
	}
	return nil
}

// Reserve returns the resources of key and holds them until Release of the returned
// lease. A session seen for the first time gets the lowest free slot, stored before
// Reserve returns. Calling it for a running session replaces its reservation and its
// lease, and a failure keeps the old ones.
func (s *Slots) Reserve(key SessionKey, req ResourceRequest) (SessionResources, error) {
	if req.WgPort < anyFreePort || req.WgPort > maxPort {
		return SessionResources{}, fmt.Errorf("%w: %d", ErrInvalidPort, req.WgPort)
	}

	s.bringUpMu.Lock()
	defer s.bringUpMu.Unlock()

	if s.closed {
		return SessionResources{}, ErrSlotsClosed
	}

	state, known := s.records[key]
	if !known {
		state = slotState{slot: s.lowestFreeSlot(), desired: DesiredDown}
	}

	name, err := s.resolveInterface(key, state.slot, req.WgIface)
	if err != nil {
		return SessionResources{}, err
	}
	port, err := s.resolvePort(key, state.slot, req.WgPort)
	if err != nil {
		return SessionResources{}, err
	}

	if !known {
		next := maps.Clone(s.records)
		next[key] = state
		if err := s.commit(next); err != nil {
			return SessionResources{}, err
		}
	}

	s.generation++
	res := SessionResources{
		Slot:      state.slot,
		Interface: name,
		Port:      port,
		Lease:     Lease{key: key, generation: s.generation},
	}
	s.running[key] = res
	return res, nil
}

// Release gives back the interface and port held by lease, and reports whether the lease still
// held them. The slot stays with the session. A lease replaced by a later Reserve holds nothing, so
// releasing it does nothing either, and whoever holds it has no say about the session anymore. After
// Close there is no successor to protect, as nothing can be reserved.
func (s *Slots) Release(lease Lease) bool {
	s.bringUpMu.Lock()
	defer s.bringUpMu.Unlock()
	if s.closed {
		return true
	}
	held, running := s.running[lease.key]
	if !running || held.Lease != lease {
		return false
	}
	delete(s.running, lease.key)
	return true
}

// Running returns the resources key holds at the moment, if any.
func (s *Slots) Running(key SessionKey) (SessionResources, bool) {
	s.bringUpMu.Lock()
	defer s.bringUpMu.Unlock()
	res, running := s.running[key]
	return res, running
}

// Remove frees the slot of a removed profile, the only way a slot becomes free. A
// profile without a slot is not an error, a running session is.
func (s *Slots) Remove(key SessionKey) error {
	s.bringUpMu.Lock()
	defer s.bringUpMu.Unlock()

	if s.closed {
		return ErrSlotsClosed
	}
	if _, running := s.running[key]; running {
		return ErrSessionRunning
	}
	if _, known := s.records[key]; !known {
		return nil
	}

	next := maps.Clone(s.records)
	delete(next, key)
	return s.commit(next)
}

// Ensure returns the stored slot of key, storing the lowest free one for a session seen
// for the first time. Unlike Reserve it holds no interface or port.
func (s *Slots) Ensure(key SessionKey) (Slot, error) {
	s.bringUpMu.Lock()
	defer s.bringUpMu.Unlock()

	if s.closed {
		return 0, ErrSlotsClosed
	}
	if state, known := s.records[key]; known {
		return state.slot, nil
	}

	state := slotState{slot: s.lowestFreeSlot(), desired: DesiredDown}
	next := maps.Clone(s.records)
	next[key] = state
	if err := s.commit(next); err != nil {
		return 0, err
	}
	return state.slot, nil
}

// SetDesired stores whether the session of key should run after a daemon restart.
func (s *Slots) SetDesired(key SessionKey, desired DesiredState) error {
	if !desired.valid() {
		return fmt.Errorf("unknown desired state %q", desired)
	}

	s.bringUpMu.Lock()
	defer s.bringUpMu.Unlock()

	if s.closed {
		return ErrSlotsClosed
	}
	state, known := s.records[key]
	if !known {
		return ErrUnknownSession
	}
	if state.desired == desired {
		return nil
	}

	state.desired = desired
	next := maps.Clone(s.records)
	next[key] = state
	return s.commit(next)
}

// Records returns a copy of the stored sessions ordered by slot.
func (s *Slots) Records() []SlotRecord {
	s.bringUpMu.Lock()
	defer s.bringUpMu.Unlock()

	return sortedRecords(s.records)
}

// StoredRecords returns the sessions stored in base ordered by slot, for a reader that
// does not own the file. It takes no lock and creates nothing, so an installation that
// has no sessions file keeps having none. A missing file gives no sessions.
func StoredRecords(base string) ([]SlotRecord, error) {
	records, _, err := newSessionStore(base).load()
	if err != nil {
		return nil, err
	}
	return sortedRecords(records), nil
}

func sortedRecords(records map[SessionKey]slotState) []SlotRecord {
	out := make([]SlotRecord, 0, len(records))
	for key, state := range records {
		out = append(out, SlotRecord{Key: key, Slot: state.slot, Desired: state.desired})
	}
	slices.SortFunc(out, func(a, b SlotRecord) int {
		return cmp.Compare(a.Slot, b.Slot)
	})
	return out
}

// commit publishes next only after it reached the disk, so memory never promises a
// slot that a restart would lose.
func (s *Slots) commit(next map[SessionKey]slotState) error {
	if err := s.store.save(next); err != nil {
		return err
	}
	s.records = next
	return nil
}

func (s *Slots) lowestFreeSlot() Slot {
	used := make(map[Slot]struct{}, len(s.records))
	for _, state := range s.records {
		used[state.slot] = struct{}{}
	}
	var slot Slot
	for {
		if _, taken := used[slot]; !taken {
			return slot
		}
		slot++
	}
}

func (s *Slots) resolveInterface(key SessionKey, slot Slot, requested string) (string, error) {
	name := requested
	if requested == iface.WgInterfaceDefault {
		name = slotInterfaceName(slot)
	}
	if err := validateSlotInterfaceName(name); err != nil {
		return "", err
	}

	for other, res := range s.running {
		if other != key && res.Interface == name {
			return "", fmt.Errorf("%w: %s", ErrInterfaceConflict, name)
		}
	}
	return name, nil
}

func slotInterfaceName(slot Slot) string {
	if slot == 0 {
		return iface.WgInterfaceDefault
	}
	return slotInterfacePrefix + strconv.FormatUint(uint64(slot), 10)
}

// validateSlotInterfaceName adds what the kernel's dev_valid_name refuses on top of
// validateDevName: its isspace also matches byte 0xA0, and a NUL would cut the name so
// it could mean the interface of another session.
func validateSlotInterfaceName(name string) error {
	if validateDevName(name) != nil || strings.IndexByte(name, 0x00) >= 0 || strings.IndexByte(name, 0xA0) >= 0 {
		return fmt.Errorf("%w: %q", ErrInvalidInterfaceName, name)
	}
	return nil
}

func (s *Slots) resolvePort(key SessionKey, slot Slot, wgPort int) (uint16, error) {
	taken := s.reservedPorts(key)

	wanted := wgPort
	switch wgPort {
	case iface.DefaultWgPort:
		wanted = s.slotPort(slot)
	case anyFreePort:
	default:
		if _, reserved := taken[uint16(wgPort)]; reserved {
			return 0, fmt.Errorf("%w: %d", ErrPortConflict, wgPort)
		}
	}

	if wanted != anyFreePort && s.portAvailable(wanted, taken) {
		return uint16(wanted), nil
	}

	port, err := s.allocatePort(taken)
	if err != nil {
		return 0, err
	}
	if wanted != anyFreePort {
		log.Infof("using %d as port of slot %d: %d is in use", port, slot, wanted)
	}
	return port, nil
}

func (s *Slots) reservedPorts(except SessionKey) map[uint16]struct{} {
	taken := make(map[uint16]struct{}, len(s.running))
	for other, res := range s.running {
		if other != except {
			taken[res.Port] = struct{}{}
		}
	}
	return taken
}

// slotPort returns the port derived from slot, or anyFreePort past the end of the range.
func (s *Slots) slotPort(slot Slot) int {
	port := uint64(s.basePort) + uint64(slot)
	if port > maxPort {
		return anyFreePort
	}
	return int(port)
}

func (s *Slots) portAvailable(port int, taken map[uint16]struct{}) bool {
	if _, reserved := taken[uint16(port)]; reserved {
		return false
	}
	_, closer, err := s.probe(port)
	if err != nil {
		return false
	}
	closeProbe(closer)
	return true
}

// allocatePort asks the system for a port. The probes stay open until it returns, so
// the system cannot repeat a port and the reservations bound the number of attempts.
func (s *Slots) allocatePort(taken map[uint16]struct{}) (uint16, error) {
	for attempt := 0; attempt <= len(taken); attempt++ {
		port, closer, err := s.probe(anyFreePort)
		if err != nil {
			return 0, fmt.Errorf("ask the system for a free port: %w", err)
		}
		defer closeProbe(closer)

		if port < 1 || port > maxPort {
			continue
		}
		if _, reserved := taken[uint16(port)]; !reserved {
			return uint16(port), nil
		}
	}
	return 0, ErrNoFreePort
}

func closeProbe(closer io.Closer) {
	if err := closer.Close(); err != nil {
		log.Debugf("failed to close port probe: %v", err)
	}
}

// listenUDPProbe binds on ip like the engine does, a nil ip meaning all addresses.
func listenUDPProbe(ip net.IP) portProbe {
	return func(port int) (int, io.Closer, error) {
		conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip, Port: port})
		if err != nil {
			return 0, nil, err
		}
		addr, ok := conn.LocalAddr().(*net.UDPAddr)
		if !ok {
			closeProbe(conn)
			return 0, nil, errors.New("wrong address type of the probe socket")
		}
		return addr.Port, conn, nil
	}
}
