//go:build !android

package nftables

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"sync"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/netbirdio/netbird/client/iface/wgaddr"
)

const (
	isoChainForward = "forward"
	isoChainInput   = "input"

	isoSetIfaces    = "ifaces"
	isoSetHairpin   = "hairpin"
	isoSetOverlays  = "overlays"
	isoSetOverlays6 = "overlays6"
	isoSetOwn       = "own"
	isoSetOwn6      = "own6"

	ipv4DaddrOffset = 16
	ipv4AddrLen     = 4
	ipv6DaddrOffset = 24
	ipv6AddrLen     = 16

	// A meta ifname fills the first register completely, the next field starts in the second.
	isoFirstRegister  = 1
	isoSecondRegister = 2
)

// ErrOverlayOverlap reports that the IPv4 overlay of a session overlaps another session's.
var ErrOverlayOverlap = errors.New("overlay overlaps another session")

// IfaceName is the name of the overlay interface of a session.
type IfaceName string

// validate rejects what the kernel would never accept as an interface name, and "+", which
// iptables reads as a wildcard, so both backends take the same names.
func (n IfaceName) validate() error {
	if n == "" || len(n) >= unix.IFNAMSIZ || n == "." || n == ".." {
		return fmt.Errorf("invalid interface name %q", string(n))
	}
	if strings.ContainsAny(string(n), "/:+\x00") || strings.ContainsFunc(string(n), func(r rune) bool { return r <= ' ' || r == 0x7f }) {
		return fmt.Errorf("invalid interface name %q", string(n))
	}
	return nil
}

// AddResult is what a session has to honor after a successful Add.
type AddResult struct {
	// IPv6Disabled means the session is isolated without the IPv6 overlay it asked for: it
	// overlaps the one of another session, or the kernel refused it. The session must not put
	// the IPv6 address on its interface: the rules go by address, so a peer of the other session
	// would reach it there.
	IPv6Disabled bool
}

// isolationMember holds the overlay prefixes of a session. An invalid overlay6 means the
// session has no IPv6 overlay on this host.
type isolationMember struct {
	overlay  netip.Prefix
	overlay6 netip.Prefix
}

func newIsolationMember(addr wgaddr.Address) (isolationMember, error) {
	overlay := addr.Network
	if !overlay.IsValid() || !overlay.Addr().Unmap().Is4() || overlay.Bits() < 1 || overlay.Bits() > 32 {
		return isolationMember{}, errors.New("session has no valid IPv4 overlay")
	}
	member := isolationMember{overlay: netip.PrefixFrom(overlay.Addr().Unmap(), overlay.Bits()).Masked()}

	overlay6 := addr.IPv6Net
	if addr.HasIPv6() && overlay6.IsValid() && overlay6.Addr().Is6() && overlay6.Bits() > 0 {
		member.overlay6 = overlay6.Masked()
	}
	return member, nil
}

// Isolation keeps sessions from reaching each other's networks through this host. It owns one
// table with one rule set: sessions only ever change the content of its sets. A drop in any
// table is final, so this holds whatever the order of the tables, and an accept in a session's
// own table cannot lift it. One daemon has one Isolation.
type Isolation struct {
	mu      sync.Mutex
	members map[IfaceName]isolationMember
}

// NewIsolation returns an Isolation without sessions. It installs nothing until the first Add.
func NewIsolation() *Isolation {
	return &Isolation{members: make(map[IfaceName]isolationMember)}
}

// Add isolates the session on the given interface from all others, or updates its overlays
// when it is already known. A session must not run when Add fails: nothing is changed then.
// An overlapping IPv4 overlay fails with ErrOverlayOverlap. An overlapping IPv6 overlay, and a
// kernel that refuses the IPv6 part, make the session continue without the new v6 overlay,
// which the result reports. A known session keeps the one it had.
func (i *Isolation) Add(name IfaceName, addr wgaddr.Address) (AddResult, error) {
	if err := name.validate(); err != nil {
		return AddResult{}, err
	}
	requested, err := newIsolationMember(addr)
	if err != nil {
		return AddResult{}, fmt.Errorf("add %s to isolation: %w", name, err)
	}

	i.mu.Lock()
	defer i.mu.Unlock()

	member, err := i.resolveOverlaps(name, requested)
	if err != nil {
		return AddResult{}, fmt.Errorf("add %s to isolation: %w", name, err)
	}

	previous, known := i.members[name]
	if known && previous == member {
		return ipv6Result(requested, member), nil
	}

	if err := i.applyMember(name, previous, member, known); err != nil {
		// Only a v6 overlay that changes can be what the kernel refused. A known session keeps
		// the one it has: its elements are in the sets, and a transient error must not take them.
		if !member.overlay6.IsValid() || member.overlay6 == previous.overlay6 {
			return AddResult{}, fmt.Errorf("add %s to isolation: %w", name, err)
		}
		log.Warnf("session %s continues without its new IPv6 isolation: %v", name, err)
		member.overlay6 = previous.overlay6
		if previous == member {
			return ipv6Result(requested, member), nil
		}
		if err := i.applyMember(name, previous, member, known); err != nil {
			return AddResult{}, fmt.Errorf("add %s to isolation: %w", name, err)
		}
	}
	return ipv6Result(requested, member), nil
}

func ipv6Result(requested, stored isolationMember) AddResult {
	return AddResult{IPv6Disabled: requested.overlay6.IsValid() && stored.overlay6 != requested.overlay6}
}

// applyMember writes the member in one batch, which the kernel takes whole or not at all, and
// records it when it did.
func (i *Isolation) applyMember(name IfaceName, previous, member isolationMember, known bool) error {
	conn := &nftables.Conn{}
	sets := newIsolationSets()
	if len(i.members) == 0 {
		// Whatever a crashed daemon left behind must not count as isolation of this one.
		if err := queueIsolationInstall(conn, sets); err != nil {
			return fmt.Errorf("install isolation: %w", err)
		}
	}
	if err := sets.queueMemberChange(conn, name, previous, member, known); err != nil {
		return err
	}
	if err := conn.Flush(); err != nil {
		return err
	}

	i.members[name] = member
	return nil
}

func (i *Isolation) resolveOverlaps(name IfaceName, member isolationMember) (isolationMember, error) {
	for other, existing := range i.members {
		if other == name {
			continue
		}
		if existing.overlay.Overlaps(member.overlay) {
			return isolationMember{}, fmt.Errorf("%w %s", ErrOverlayOverlap, other)
		}
		if member.overlay6.IsValid() && existing.overlay6.IsValid() && existing.overlay6.Overlaps(member.overlay6) {
			log.Warnf("IPv6 overlay of %s overlaps session %s, isolating it without IPv6", name, other)
			member.overlay6 = netip.Prefix{}
		}
	}
	return member, nil
}

// Remove takes the session out of the isolation, which keeps holding for all others. The last
// session removes the whole table. Removing an unknown session does nothing.
func (i *Isolation) Remove(name IfaceName) error {
	i.mu.Lock()
	defer i.mu.Unlock()

	member, known := i.members[name]
	if !known {
		return nil
	}

	conn := &nftables.Conn{}
	if len(i.members) == 1 {
		queueIsolationDelete(conn)
	} else if err := newIsolationSets().queueMemberRemoval(conn, name, member); err != nil {
		return fmt.Errorf("remove %s from isolation: %w", name, err)
	}
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("remove %s from isolation: %w", name, err)
	}

	delete(i.members, name)
	return nil
}

// RemoveAll drops all sessions and the table, including one a crashed daemon left behind.
func (i *Isolation) RemoveAll() error {
	i.mu.Lock()
	defer i.mu.Unlock()

	conn := &nftables.Conn{}
	queueIsolationDelete(conn)
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("remove isolation: %w", err)
	}
	clear(i.members)
	return nil
}

// Verify compares the kernel state with what the isolation should be and reports any
// difference, including additions: a single accept in front of a drop in these chains opens
// the host between sessions. Sessions must not keep running when it fails.
func (i *Isolation) Verify() error {
	i.mu.Lock()
	defer i.mu.Unlock()

	conn := &nftables.Conn{}
	table, err := conn.ListTableOfFamily(IsolationTableName, nftables.TableFamilyINet)
	if err != nil && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("verify isolation: list table: %w", err)
	}
	if err != nil {
		if len(i.members) == 0 {
			return nil
		}
		return errors.New("verify isolation: table is missing")
	}
	if len(i.members) == 0 {
		return errors.New("verify isolation: table exists without sessions")
	}
	if table.Flags != 0 {
		return fmt.Errorf("verify isolation: table has flags %#x", table.Flags)
	}

	sets := newIsolationSets()
	if err := verifyIsolationChains(conn, sets); err != nil {
		return fmt.Errorf("verify isolation: %w", err)
	}
	if err := sets.verify(conn, i.members); err != nil {
		return fmt.Errorf("verify isolation: %w", err)
	}
	return nil
}

func isolationTable() *nftables.Table {
	return &nftables.Table{Name: IsolationTableName, Family: nftables.TableFamilyINet}
}

// queueIsolationDelete deletes the table whether it exists or not: a table added earlier in
// the batch is always there to delete.
func queueIsolationDelete(conn *nftables.Conn) {
	conn.AddTable(isolationTable())
	conn.DelTable(isolationTable())
}

func queueIsolationInstall(conn *nftables.Conn, sets isolationSets) error {
	queueIsolationDelete(conn)
	conn.AddTable(isolationTable())

	for _, set := range sets.all() {
		if err := addSet(conn, set, nil); err != nil {
			return fmt.Errorf("add set %s: %w", set.Name, err)
		}
	}
	for _, spec := range isolationChainSpecs(sets) {
		chain := conn.AddChain(&nftables.Chain{
			Name:     spec.name,
			Table:    isolationTable(),
			Hooknum:  spec.hook,
			Priority: nftables.ChainPriorityFilter,
			Type:     nftables.ChainTypeFilter,
			Policy:   policyAccept(),
		})
		for _, rule := range spec.rules {
			conn.AddRule(&nftables.Rule{Table: isolationTable(), Chain: chain, Exprs: rule})
		}
	}
	return nil
}

func policyAccept() *nftables.ChainPolicy {
	policy := nftables.ChainPolicyAccept
	return &policy
}

type isolationChainSpec struct {
	name  string
	hook  *nftables.ChainHook
	rules [][]expr.Any
}

func isolationChainSpecs(sets isolationSets) []isolationChainSpec {
	return []isolationChainSpec{
		{
			name:  isoChainForward,
			hook:  nftables.ChainHookForward,
			rules: [][]expr.Any{isolationForwardRule(sets)},
		},
		{
			name: isoChainInput,
			hook: nftables.ChainHookInput,
			rules: [][]expr.Any{
				isolationInputRule(sets, unix.NFPROTO_IPV4, sets.overlays, sets.own, ipv4DaddrOffset, ipv4AddrLen),
				isolationInputRule(sets, unix.NFPROTO_IPV6, sets.overlays6, sets.own6, ipv6DaddrOffset, ipv6AddrLen),
			},
		},
	}
}

func metaToRegister(key expr.MetaKey, register uint32) *expr.Meta {
	return &expr.Meta{Key: key, Register: register}
}

func lookupSet(set *nftables.Set, invert bool) *expr.Lookup {
	return &expr.Lookup{SourceRegister: isoFirstRegister, SetName: set.Name, SetID: set.ID, Invert: invert}
}

// isolationForwardRule is I3. Netfilter compares a register only with a constant, so "the
// interfaces differ" is a lookup of the pair in a set of the pairs that are the same.
func isolationForwardRule(sets isolationSets) []expr.Any {
	return []expr.Any{
		metaToRegister(expr.MetaKeyIIFNAME, isoFirstRegister),
		lookupSet(sets.ifaces, false),
		metaToRegister(expr.MetaKeyOIFNAME, isoFirstRegister),
		lookupSet(sets.ifaces, false),
		metaToRegister(expr.MetaKeyIIFNAME, isoFirstRegister),
		metaToRegister(expr.MetaKeyOIFNAME, isoSecondRegister),
		lookupSet(sets.hairpin, true),
		&expr.Verdict{Kind: expr.VerdictDrop},
	}
}

// isolationInputRule is I4 for one address family: traffic from a session to the overlay of
// any session, unless the pair of interface and address is the session's own.
func isolationInputRule(sets isolationSets, proto byte, overlays, own *nftables.Set, offset, length uint32) []expr.Any {
	daddr := func(register uint32) *expr.Payload {
		return &expr.Payload{DestRegister: register, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: length}
	}
	return []expr.Any{
		metaToRegister(expr.MetaKeyNFPROTO, isoFirstRegister),
		&expr.Cmp{Op: expr.CmpOpEq, Register: isoFirstRegister, Data: []byte{proto}},
		metaToRegister(expr.MetaKeyIIFNAME, isoFirstRegister),
		lookupSet(sets.ifaces, false),
		daddr(isoFirstRegister),
		lookupSet(overlays, false),
		metaToRegister(expr.MetaKeyIIFNAME, isoFirstRegister),
		daddr(isoSecondRegister),
		lookupSet(own, true),
		&expr.Verdict{Kind: expr.VerdictDrop},
	}
}

// isolationSets are the sets of the table. All content of the isolation lives here.
type isolationSets struct {
	ifaces    *nftables.Set
	hairpin   *nftables.Set
	overlays  *nftables.Set
	overlays6 *nftables.Set
	own       *nftables.Set
	own6      *nftables.Set
}

func newIsolationSets() isolationSets {
	table := isolationTable()
	return isolationSets{
		ifaces: &nftables.Set{Table: table, Name: isoSetIfaces, KeyType: nftables.TypeIFName},
		hairpin: &nftables.Set{
			Table: table, Name: isoSetHairpin, Concatenation: true,
			KeyType: nftables.MustConcatSetType(nftables.TypeIFName, nftables.TypeIFName),
		},
		overlays:  &nftables.Set{Table: table, Name: isoSetOverlays, Interval: true, KeyType: nftables.TypeIPAddr},
		overlays6: &nftables.Set{Table: table, Name: isoSetOverlays6, Interval: true, KeyType: nftables.TypeIP6Addr},
		own: &nftables.Set{
			Table: table, Name: isoSetOwn, Interval: true, Concatenation: true,
			KeyType: nftables.MustConcatSetType(nftables.TypeIFName, nftables.TypeIPAddr),
		},
		own6: &nftables.Set{
			Table: table, Name: isoSetOwn6, Interval: true, Concatenation: true,
			KeyType: nftables.MustConcatSetType(nftables.TypeIFName, nftables.TypeIP6Addr),
		},
	}
}

func (s isolationSets) all() []*nftables.Set {
	return []*nftables.Set{s.ifaces, s.hairpin, s.overlays, s.overlays6, s.own, s.own6}
}

type isolationElements struct {
	set      *nftables.Set
	elements []nftables.SetElement
}

func (s isolationSets) ifaceElements(name IfaceName) []isolationElements {
	key := ifname(string(name))
	return []isolationElements{
		{s.ifaces, []nftables.SetElement{{Key: key}}},
		{s.hairpin, []nftables.SetElement{{Key: slices.Concat(key, key)}}},
	}
}

func (s isolationSets) overlayElements(name IfaceName, overlay netip.Prefix) []isolationElements {
	if !overlay.IsValid() {
		return nil
	}
	overlays, own := s.overlays, s.own
	if overlay.Addr().Is6() {
		overlays, own = s.overlays6, s.own6
	}

	key := ifname(string(name))
	first := overlay.Addr().AsSlice()
	last := calculateLastIP(overlay)
	return []isolationElements{
		{overlays, []nftables.SetElement{{Key: first}, {Key: intervalEndKey(last), IntervalEnd: true}}},
		{own, []nftables.SetElement{{Key: slices.Concat(key, first), KeyEnd: slices.Concat(key, last.AsSlice())}}},
	}
}

// intervalEndKey is the exclusive end of an interval. Past the last address it wraps to zero,
// which nftables reads as the open end of the range.
func intervalEndKey(last netip.Addr) []byte {
	if next := last.Next(); next.IsValid() {
		return next.AsSlice()
	}
	return make([]byte, last.BitLen()/8)
}

func (s isolationSets) memberElements(name IfaceName, member isolationMember) []isolationElements {
	return slices.Concat(
		s.ifaceElements(name),
		s.overlayElements(name, member.overlay),
		s.overlayElements(name, member.overlay6),
	)
}

func queueElements(conn *nftables.Conn, batches []isolationElements, queue func(*nftables.Conn, *nftables.Set, []nftables.SetElement) error) error {
	for _, batch := range batches {
		if err := queue(conn, batch.set, batch.elements); err != nil {
			return fmt.Errorf("queue elements of set %s: %w", batch.set.Name, err)
		}
	}
	return nil
}

func queueAdd(conn *nftables.Conn, set *nftables.Set, elements []nftables.SetElement) error {
	return conn.SetAddElements(set, elements)
}

func queueDelete(conn *nftables.Conn, set *nftables.Set, elements []nftables.SetElement) error {
	return conn.SetDeleteElements(set, elements)
}

// queueMemberChange queues a new member, or only the overlays that differ for a known one, in
// the single batch that keeps the session isolated throughout.
func (s isolationSets) queueMemberChange(conn *nftables.Conn, name IfaceName, previous, member isolationMember, known bool) error {
	if !known {
		return queueElements(conn, s.memberElements(name, member), queueAdd)
	}
	for _, change := range []struct{ from, to netip.Prefix }{
		{previous.overlay, member.overlay},
		{previous.overlay6, member.overlay6},
	} {
		if change.from == change.to {
			continue
		}
		if err := queueElements(conn, s.overlayElements(name, change.from), queueDelete); err != nil {
			return err
		}
		if err := queueElements(conn, s.overlayElements(name, change.to), queueAdd); err != nil {
			return err
		}
	}
	return nil
}

func (s isolationSets) queueMemberRemoval(conn *nftables.Conn, name IfaceName, member isolationMember) error {
	return queueElements(conn, s.memberElements(name, member), queueDelete)
}

func verifyIsolationChains(conn *nftables.Conn, sets isolationSets) error {
	specs := isolationChainSpecs(sets)
	listed, err := conn.ListChainsOfTableFamily(nftables.TableFamilyINet)
	if err != nil {
		return fmt.Errorf("list chains: %w", err)
	}
	chains := slices.DeleteFunc(listed, func(c *nftables.Chain) bool { return c.Table.Name != IsolationTableName })
	if len(chains) != len(specs) {
		return fmt.Errorf("table has %d chains, want %d", len(chains), len(specs))
	}
	for _, spec := range specs {
		idx := slices.IndexFunc(chains, func(c *nftables.Chain) bool { return c.Name == spec.name })
		if idx < 0 {
			return fmt.Errorf("chain %s is missing", spec.name)
		}
		if err := verifyIsolationChain(conn, chains[idx], spec); err != nil {
			return fmt.Errorf("chain %s: %w", spec.name, err)
		}
	}
	return nil
}

func verifyIsolationChain(conn *nftables.Conn, chain *nftables.Chain, spec isolationChainSpec) error {
	if chain.Hooknum == nil || *chain.Hooknum != *spec.hook {
		return errors.New("wrong hook")
	}
	if chain.Type != nftables.ChainTypeFilter {
		return fmt.Errorf("wrong type %q", chain.Type)
	}
	if chain.Policy != nil && *chain.Policy != nftables.ChainPolicyAccept {
		return errors.New("wrong policy")
	}

	rules, err := conn.GetRules(isolationTable(), chain)
	if err != nil {
		return fmt.Errorf("list rules: %w", err)
	}
	if len(rules) != len(spec.rules) {
		return fmt.Errorf("has %d rules, want %d", len(rules), len(spec.rules))
	}
	for idx, rule := range rules {
		if !sameIsolationExprs(rule.Exprs, spec.rules[idx]) {
			return fmt.Errorf("rule %d differs", idx)
		}
	}
	return nil
}

// sameIsolationExprs compares a rule read from the kernel with the expected one. The set ID
// only links objects inside one batch, so it does not count.
func sameIsolationExprs(got, want []expr.Any) bool {
	return reflect.DeepEqual(withoutSetIDs(got), withoutSetIDs(want))
}

func withoutSetIDs(exprs []expr.Any) []expr.Any {
	out := make([]expr.Any, 0, len(exprs))
	for _, e := range exprs {
		if lookup, ok := e.(*expr.Lookup); ok {
			stripped := *lookup
			stripped.SetID = 0
			e = &stripped
		}
		out = append(out, e)
	}
	return out
}

func (s isolationSets) verify(conn *nftables.Conn, members map[IfaceName]isolationMember) error {
	listed, err := conn.GetSets(isolationTable())
	if err != nil {
		return fmt.Errorf("list sets: %w", err)
	}
	if len(listed) != len(s.all()) {
		return fmt.Errorf("table has %d sets, want %d", len(listed), len(s.all()))
	}

	expected := make(map[string][]string)
	for name, member := range members {
		for _, batch := range s.memberElements(name, member) {
			for _, element := range batch.elements {
				expected[batch.set.Name] = append(expected[batch.set.Name], elementIdentity(element))
			}
		}
	}

	for _, set := range s.all() {
		elements, err := conn.GetSetElements(set)
		if err != nil {
			return fmt.Errorf("list elements of set %s: %w", set.Name, err)
		}
		got := make([]string, 0, len(elements))
		for _, element := range elements {
			got = append(got, elementIdentity(element))
		}
		slices.Sort(got)
		want := expected[set.Name]
		slices.Sort(want)
		if !slices.Equal(got, want) {
			return fmt.Errorf("set %s has %d elements that differ from the %d expected", set.Name, len(got), len(want))
		}
	}
	return nil
}

func elementIdentity(element nftables.SetElement) string {
	return fmt.Sprintf("%s-%s-%t", hex.EncodeToString(element.Key), hex.EncodeToString(element.KeyEnd), element.IntervalEnd)
}
