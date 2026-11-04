//go:build !android

package iptables

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/lrh3321/ipset-go"
	"golang.org/x/sys/unix"
)

const (
	isoChainForward = "NETBIRD-ISO-FWD"
	isoChainInput   = "NETBIRD-ISO-IN"

	isoSetPrefix   = "nb-iso-"
	isoSetIfaces   = isoSetPrefix + "ifaces"
	isoSetOverlays = isoSetPrefix + "overlays"
	isoSetOwn      = isoSetPrefix + "own"
	isoSetV6Suffix = "-v6"

	// isoIfaceSetsPerList sizes the list that joins the interface sets: the kernel does not
	// allow growing it. Its entries take no memory until used.
	isoIfaceSetsPerList = 1024

	isoDestroyRetries       = 40
	isoDestroyRetryInterval = 50 * time.Millisecond
)

// errIPSetHashFull is the kernel's IPSET_ERR_HASH_FULL. The library has a constant of that name
// one number off: the kernel starts its hash errors at IPSET_ERR_TYPE_SPECIFIC itself.
const errIPSetHashFull = ipset.IPSetError(ipset.IPSET_ERR_TYPE_SPECIFIC)

// isolationPlane is the isolation of one address family.
type isolationPlane struct {
	client    *iptables.IPTables
	v6        bool
	installed bool
	// ifaceSets holds the interfaces in each set of the list, the index is the set's number.
	ifaceSets []map[IfaceName]struct{}
}

func newIsolationPlane(client *iptables.IPTables, v6 bool) *isolationPlane {
	return &isolationPlane{client: client, v6: v6}
}

func (p *isolationPlane) setName(base string) string {
	if p.v6 {
		return base + isoSetV6Suffix
	}
	return base
}

func (p *isolationPlane) ifaceSetName(index int) string {
	return p.setName(isoSetIfaces) + "-" + strconv.Itoa(index)
}

func (p *isolationPlane) ownsSet(name string) bool {
	return strings.HasPrefix(name, isoSetPrefix) && strings.Contains(name, isoSetV6Suffix) == p.v6
}

func (p *isolationPlane) createOptions() ipset.CreateOptions {
	var opts ipset.CreateOptions
	if p.v6 {
		opts.Family = ipset.FamilyIPV6
	}
	return opts
}

func jumpTo(chain string) []string {
	return []string{"-j", chain}
}

func (p *isolationPlane) inputRule() []string {
	return []string{
		"-m", "set", "--match-set", p.setName(isoSetIfaces), "src,src",
		"-m", "set", "--match-set", p.setName(isoSetOverlays), "dst",
		"-m", "set", "!", "--match-set", p.setName(isoSetOwn), "dst,src",
		"-j", "DROP",
	}
}

// forwardRule needs an interface of its own for one reason: iptables cannot compare the
// incoming with the outgoing interface. The rest of the match is the set, so it stays one
// rule per session.
func (p *isolationPlane) forwardRule(name IfaceName) []string {
	return []string{
		"-i", string(name), "!", "-o", string(name),
		"-m", "set", "--match-set", p.setName(isoSetIfaces), "dst,dst",
		"-j", "DROP",
	}
}

// install starts from nothing, since whatever a crashed daemon left must not count as isolation
// of this one. Failing leaves nothing behind.
func (p *isolationPlane) install() error {
	if err := p.teardown(); err != nil {
		return fmt.Errorf("remove previous isolation: %w", err)
	}
	if err := p.createObjects(); err != nil {
		if terr := p.teardown(); terr != nil {
			return fmt.Errorf("%w; rollback: %v", err, terr)
		}
		return err
	}
	p.installed = true
	return nil
}

func (p *isolationPlane) createObjects() error {
	opts := p.createOptions()
	if err := ipset.Create(p.setName(isoSetOverlays), ipset.TypeHashNet, opts); err != nil {
		return fmt.Errorf("create ipset %s: %w", p.setName(isoSetOverlays), err)
	}
	if err := ipset.Create(p.setName(isoSetOwn), ipset.TypeHashNetIface, opts); err != nil {
		return fmt.Errorf("create ipset %s: %w", p.setName(isoSetOwn), err)
	}
	listOpts := ipset.CreateOptions{Size: isoIfaceSetsPerList}
	if err := ipset.Create(p.setName(isoSetIfaces), ipset.TypeListSet, listOpts); err != nil {
		return fmt.Errorf("create ipset %s: %w", p.setName(isoSetIfaces), err)
	}

	for _, chain := range []string{isoChainForward, isoChainInput} {
		if err := p.client.NewChain(tableMangle, chain); err != nil {
			return fmt.Errorf("create chain %s: %w", chain, err)
		}
	}
	if err := p.client.Append(tableMangle, isoChainInput, p.inputRule()...); err != nil {
		return fmt.Errorf("add input rule: %w", err)
	}

	for _, jump := range []struct{ from, to string }{
		{chainForward, isoChainForward},
		{chainInput, isoChainInput},
	} {
		if err := p.client.Insert(tableMangle, jump.from, 1, jumpTo(jump.to)...); err != nil {
			return fmt.Errorf("add jump from %s: %w", jump.from, err)
		}
	}
	return nil
}

// teardown removes the chains and sets of this plane whether they exist or not.
func (p *isolationPlane) teardown() error {
	var errs []error
	for _, jump := range []struct{ from, to string }{
		{chainForward, isoChainForward},
		{chainInput, isoChainInput},
	} {
		// iptables cannot even look for a jump to a chain that does not exist.
		exists, err := p.client.ChainExists(tableMangle, jump.to)
		if err != nil {
			errs = append(errs, fmt.Errorf("check chain %s: %w", jump.to, err))
			continue
		}
		if !exists {
			continue
		}
		if err := p.client.DeleteIfExists(tableMangle, jump.from, jumpTo(jump.to)...); err != nil {
			errs = append(errs, fmt.Errorf("delete jump from %s: %w", jump.from, err))
		}
		if err := p.client.ClearAndDeleteChain(tableMangle, jump.to); err != nil {
			errs = append(errs, fmt.Errorf("delete chain %s: %w", jump.to, err))
		}
	}
	errs = append(errs, p.destroySets())

	if err := errors.Join(errs...); err != nil {
		return err
	}
	p.installed = false
	p.ifaceSets = nil
	return nil
}

func (p *isolationPlane) existingSets() ([]string, error) {
	all, err := ipset.ListAll()
	if err != nil {
		return nil, fmt.Errorf("list ipsets: %w", err)
	}
	names := []string{}
	for _, set := range all {
		if p.ownsSet(set.SetName) {
			names = append(names, set.SetName)
		}
	}
	return names, nil
}

func (p *isolationPlane) destroySets() error {
	names, err := p.existingSets()
	if err != nil {
		return err
	}
	// The list holds references to the interface sets, so it goes first.
	slices.SortFunc(names, func(a, b string) int { return len(a) - len(b) })

	var errs []error
	for _, name := range names {
		if err := destroySetWhenUnused(name); err != nil {
			errs = append(errs, fmt.Errorf("destroy ipset %s: %w", name, err))
		}
	}
	return errors.Join(errs...)
}

// destroySetWhenUnused waits out the reference a just deleted rule keeps: iptables-nft
// releases it after the commit, in a work queue of the kernel.
func destroySetWhenUnused(name string) error {
	var err error
	for range isoDestroyRetries {
		err = ipset.Destroy(name)
		if !errors.Is(err, unix.EBUSY) && !errors.Is(err, ipset.ErrBusy) {
			return err
		}
		time.Sleep(isoDestroyRetryInterval)
	}
	return err
}

func halfSpaces(v6 bool) []netip.Prefix {
	if v6 {
		return []netip.Prefix{netip.MustParsePrefix("::/1"), netip.MustParsePrefix("8000::/1")}
	}
	return []netip.Prefix{netip.MustParsePrefix("0.0.0.0/1"), netip.MustParsePrefix("128.0.0.0/1")}
}

func prefixEntry(prefix netip.Prefix, name IfaceName) *ipset.Entry {
	return &ipset.Entry{
		IP:    prefix.Addr().AsSlice(),
		CIDR:  uint8(prefix.Bits()),
		IFace: string(name),
		// Adding what exists and deleting what is gone both stay no errors, which keeps
		// rollback and a repeated Remove simple.
		Replace: true,
	}
}

// addMember adds a session. The prefix may be invalid: without an overlay in this family the
// interface still counts, since traffic must not be forwarded to it. Own comes before
// overlays so the session is never cut off its own address. Failing leaves the member out.
func (p *isolationPlane) addMember(name IfaceName, overlay netip.Prefix) error {
	if err := p.addMemberObjects(name, overlay); err != nil {
		if rerr := p.removeMember(name, overlay); rerr != nil {
			return fmt.Errorf("%w; rollback: %v", err, rerr)
		}
		return err
	}
	return nil
}

func (p *isolationPlane) addMemberObjects(name IfaceName, overlay netip.Prefix) error {
	if err := p.placeInterface(name); err != nil {
		return err
	}
	if err := p.addOverlay(name, overlay); err != nil {
		return err
	}
	// A rule a failed rollback left must not be added twice by the next attempt.
	if err := p.client.AppendUnique(tableMangle, isoChainForward, p.forwardRule(name)...); err != nil {
		return fmt.Errorf("add forward rule: %w", err)
	}
	return nil
}

// placeInterface adds the interface to an interface set. The kernel hashes hash:net,iface
// without the interface, so a prefix with all its interfaces shares one bucket of limited
// size, and every interface needs the same prefixes here. A full set is therefore normal: the
// next one takes over, and the first set the interface fits in is where it stays.
func (p *isolationPlane) placeInterface(name IfaceName) error {
	for index, members := range p.ifaceSets {
		err := p.addToIfaceSet(index, name)
		if err == nil {
			members[name] = struct{}{}
			return nil
		}
		if !errors.Is(err, errIPSetHashFull) {
			return err
		}
		if rerr := p.removeFromIfaceSet(index, name); rerr != nil {
			return fmt.Errorf("%w; rollback: %v", err, rerr)
		}
	}

	index := len(p.ifaceSets)
	setName := p.ifaceSetName(index)
	if err := ipset.Create(setName, ipset.TypeHashNetIface, p.createOptions()); err != nil {
		return fmt.Errorf("create ipset %s: %w", setName, err)
	}
	if err := ipset.Add(p.setName(isoSetIfaces), &ipset.Entry{Name: setName, Replace: true}); err != nil {
		return fmt.Errorf("add ipset %s to list: %w", setName, err)
	}
	p.ifaceSets = append(p.ifaceSets, map[IfaceName]struct{}{})
	if err := p.addToIfaceSet(index, name); err != nil {
		return err
	}
	p.ifaceSets[index][name] = struct{}{}
	return nil
}

func (p *isolationPlane) addToIfaceSet(index int, name IfaceName) error {
	for _, half := range halfSpaces(p.v6) {
		if err := ipset.Add(p.ifaceSetName(index), prefixEntry(half, name)); err != nil {
			return fmt.Errorf("add interface to ipset %s: %w", p.ifaceSetName(index), err)
		}
	}
	return nil
}

func (p *isolationPlane) addOverlay(name IfaceName, overlay netip.Prefix) error {
	if !overlay.IsValid() {
		return nil
	}
	if err := ipset.Add(p.setName(isoSetOwn), prefixEntry(overlay, name)); err != nil {
		return fmt.Errorf("add to ipset %s: %w", p.setName(isoSetOwn), err)
	}
	if err := ipset.Add(p.setName(isoSetOverlays), prefixEntry(overlay, "")); err != nil {
		return fmt.Errorf("add to ipset %s: %w", p.setName(isoSetOverlays), err)
	}
	return nil
}

// removeOverlay tries both sets even after one failed, so a rollback undoes all it can.
func (p *isolationPlane) removeOverlay(name IfaceName, overlay netip.Prefix) error {
	if !overlay.IsValid() {
		return nil
	}
	var errs []error
	if err := ipset.Del(p.setName(isoSetOverlays), prefixEntry(overlay, "")); err != nil {
		errs = append(errs, fmt.Errorf("delete from ipset %s: %w", p.setName(isoSetOverlays), err))
	}
	if err := ipset.Del(p.setName(isoSetOwn), prefixEntry(overlay, name)); err != nil {
		errs = append(errs, fmt.Errorf("delete from ipset %s: %w", p.setName(isoSetOwn), err))
	}
	return errors.Join(errs...)
}

// replaceOverlay adds before it removes: for a moment the session owns both, never neither. When
// it fails the caller undoes it with restoreOverlay, whichever step it got to.
func (p *isolationPlane) replaceOverlay(name IfaceName, previous, overlay netip.Prefix) error {
	if previous == overlay {
		return nil
	}
	if err := p.addOverlay(name, overlay); err != nil {
		return err
	}
	return p.removeOverlay(name, previous)
}

// restoreOverlay undoes a replaceOverlay, in the same order so the session is never without one.
func (p *isolationPlane) restoreOverlay(name IfaceName, previous, overlay netip.Prefix) error {
	if previous == overlay {
		return nil
	}
	return errors.Join(p.addOverlay(name, previous), p.removeOverlay(name, overlay))
}

// removeMember undoes addMember in the reverse order. All steps tolerate what is already gone
// and run even after one failed, so a broken chain does not keep an interface in the sets.
func (p *isolationPlane) removeMember(name IfaceName, overlay netip.Prefix) error {
	var errs []error
	if err := p.client.DeleteIfExists(tableMangle, isoChainForward, p.forwardRule(name)...); err != nil {
		errs = append(errs, fmt.Errorf("delete forward rule: %w", err))
	}
	if err := p.removeOverlay(name, overlay); err != nil {
		errs = append(errs, err)
	}
	for index, members := range p.ifaceSets {
		if _, ok := members[name]; !ok {
			continue
		}
		if err := p.removeFromIfaceSet(index, name); err != nil {
			errs = append(errs, err)
			continue
		}
		delete(members, name)
	}
	return errors.Join(errs...)
}

func (p *isolationPlane) removeFromIfaceSet(index int, name IfaceName) error {
	for _, half := range halfSpaces(p.v6) {
		if err := ipset.Del(p.ifaceSetName(index), prefixEntry(half, name)); err != nil {
			return fmt.Errorf("delete interface from ipset %s: %w", p.ifaceSetName(index), err)
		}
	}
	return nil
}

func (p *isolationPlane) verifyAbsent() error {
	for _, chain := range []string{isoChainForward, isoChainInput} {
		exists, err := p.client.ChainExists(tableMangle, chain)
		if err != nil {
			return fmt.Errorf("check chain %s: %w", chain, err)
		}
		if exists {
			return fmt.Errorf("chain %s exists without sessions", chain)
		}
	}
	names, err := p.existingSets()
	if err != nil {
		return err
	}
	if len(names) > 0 {
		return fmt.Errorf("%d ipsets exist without sessions", len(names))
	}
	return nil
}

func (p *isolationPlane) verify(overlays map[IfaceName]netip.Prefix) error {
	if !p.installed {
		return errors.New("not installed")
	}
	for _, jump := range []struct{ from, to string }{
		{chainForward, isoChainForward},
		{chainInput, isoChainInput},
	} {
		if err := p.verifyJumpFirst(jump.from, jump.to); err != nil {
			return err
		}
	}
	if err := p.verifyChain(isoChainInput, [][]string{p.inputRule()}); err != nil {
		return err
	}

	forward := make([][]string, 0, len(overlays))
	for name := range overlays {
		forward = append(forward, p.forwardRule(name))
	}
	if err := p.verifyChain(isoChainForward, forward); err != nil {
		return err
	}
	return p.verifySets(overlays)
}

// verifyJumpFirst accepts only one kind of rule above the jump: the jump to the MSS clamping
// chain of a manager, which that manager puts at the top and which holds no verdict.
func (p *isolationPlane) verifyJumpFirst(from, to string) error {
	lines, err := p.client.List(tableMangle, from)
	if err != nil {
		return fmt.Errorf("list %s: %w", from, err)
	}
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "-A" {
			continue
		}
		if len(fields) != 4 || fields[2] != "-j" {
			return fmt.Errorf("a rule precedes the jump in %s", from)
		}
		if fields[3] == to {
			return nil
		}
		if !strings.HasPrefix(fields[3], chainRTMSSClamp) {
			return fmt.Errorf("a jump to %s precedes the jump in %s", fields[3], from)
		}
	}
	return fmt.Errorf("the jump to %s is missing from %s", to, from)
}

func (p *isolationPlane) verifyChain(chain string, rules [][]string) error {
	lines, err := p.client.List(tableMangle, chain)
	if err != nil {
		return fmt.Errorf("list %s: %w", chain, err)
	}
	count := 0
	for _, line := range lines {
		if strings.HasPrefix(line, "-A ") {
			count++
		}
	}
	if count != len(rules) {
		return fmt.Errorf("chain %s has %d rules, want %d", chain, count, len(rules))
	}
	for _, rule := range rules {
		exists, err := p.client.Exists(tableMangle, chain, rule...)
		if err != nil {
			return fmt.Errorf("check rule in %s: %w", chain, err)
		}
		if !exists {
			return fmt.Errorf("a rule is missing from %s", chain)
		}
	}
	return nil
}

func (p *isolationPlane) verifySets(overlays map[IfaceName]netip.Prefix) error {
	wantOverlays, wantOwn := []string{}, []string{}
	for name, overlay := range overlays {
		if overlay.IsValid() {
			wantOverlays = append(wantOverlays, entryIdentity(net.IP(overlay.Addr().AsSlice()), overlay.Bits(), ""))
			wantOwn = append(wantOwn, entryIdentity(net.IP(overlay.Addr().AsSlice()), overlay.Bits(), string(name)))
		}
	}
	if err := verifySetEntries(p.setName(isoSetOverlays), wantOverlays); err != nil {
		return err
	}
	if err := verifySetEntries(p.setName(isoSetOwn), wantOwn); err != nil {
		return err
	}

	wantList := make([]string, 0, len(p.ifaceSets))
	for index, members := range p.ifaceSets {
		wantList = append(wantList, p.ifaceSetName(index))
		wantEntries := make([]string, 0, len(members)*2)
		for name := range members {
			if _, ok := overlays[name]; !ok {
				return fmt.Errorf("interface set %d holds an unknown session", index)
			}
			for _, half := range halfSpaces(p.v6) {
				wantEntries = append(wantEntries, entryIdentity(net.IP(half.Addr().AsSlice()), half.Bits(), string(name)))
			}
		}
		if err := verifySetEntries(p.ifaceSetName(index), wantEntries); err != nil {
			return err
		}
	}
	return verifySetEntries(p.setName(isoSetIfaces), wantList)
}

func verifySetEntries(setName string, want []string) error {
	listed, err := ipset.List(setName)
	if err != nil {
		return fmt.Errorf("list ipset %s: %w", setName, err)
	}
	got := make([]string, 0, len(listed.Entries))
	for _, entry := range listed.Entries {
		if entry.Name != "" {
			got = append(got, entry.Name)
			continue
		}
		got = append(got, entryIdentity(entry.IP, int(entry.CIDR), entry.IFace))
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		return fmt.Errorf("ipset %s has %d entries that differ from the %d expected", setName, len(got), len(want))
	}
	return nil
}

func entryIdentity(ip net.IP, bits int, name string) string {
	return fmt.Sprintf("%s/%d,%s", ip, bits, name)
}
