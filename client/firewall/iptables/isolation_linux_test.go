//go:build privileged

package iptables

import (
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"testing"

	"github.com/coreos/go-iptables/iptables"
	"github.com/lrh3321/ipset-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	fw "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
)

type isoSession struct {
	net     *isoNetwork
	manager *Manager
}

// startIsoManager runs a real session manager with route ACLs that allow forwarding from its
// overlay to every destination given, and an input ACL that opens the host to its overlay. Any
// isolation the test sees is therefore not the work of a missing accept.
func startIsoManager(t *testing.T, n *isoNetwork, destinations ...netip.Prefix) *isoSession {
	t.Helper()
	manager, err := Create(n.ifaceMock(), iface.DefaultMTU, WithSlot(n.slot))
	require.NoError(t, err)
	require.NoError(t, manager.Init(nil))

	session := &isoSession{net: n, manager: manager}
	t.Cleanup(func() { session.stop(t) })

	require.NoError(t, manager.EnableRouting())
	for _, source := range []netip.Prefix{n.addr.Network, n.addr.IPv6Net} {
		_, err := manager.AddFilterRule(nil, []netip.Prefix{source}, fw.Network{}, fw.ProtocolALL, nil, nil, fw.ActionAccept)
		require.NoError(t, err)
	}
	for _, destination := range destinations {
		source := n.addr.Network
		if destination.Addr().Is6() {
			source = n.addr.IPv6Net
		}
		_, err := manager.AddFilterRule(nil, []netip.Prefix{source}, fw.Network{Prefix: destination}, fw.ProtocolALL, nil, nil, fw.ActionAccept)
		require.NoError(t, err)
	}
	require.NoError(t, manager.Flush())
	return session
}

func (s *isoSession) stop(t *testing.T) {
	t.Helper()
	if s.manager == nil {
		return
	}
	manager := s.manager
	s.manager = nil
	require.NoError(t, manager.Close(nil))
}

func routedDestinations(networks ...*isoNetwork) []netip.Prefix {
	destinations := []netip.Prefix{}
	for _, n := range networks {
		destinations = append(destinations, n.addr.Network, n.addr.IPv6Net, n.behind.Masked())
	}
	return destinations
}

func isoIfaceName(n *isoNetwork) IfaceName {
	return IfaceName(n.name)
}

// newTestIsolation skips only when the host cannot run this backend at all. A probe, not NewIsolation
// itself, decides: a broken NewIsolation must fail the test instead of skipping it.
func newTestIsolation(t *testing.T) *Isolation {
	t.Helper()
	if _, err := exec.LookPath("iptables"); err != nil {
		t.Skipf("no iptables: %v", err)
	}
	const probe = "nb-isotest-probe"
	if err := ipset.Create(probe, ipset.TypeHashNetIface, ipset.CreateOptions{}); err != nil {
		t.Skipf("no hash:net,iface ipset: %v", err)
	}
	require.NoError(t, ipset.Destroy(probe))

	isolation, err := NewIsolation()
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, isolation.RemoveAll()) })
	return isolation
}

// isolationObjects lists what the isolation has in the kernel, for both address families.
func isolationObjects(t *testing.T) []string {
	t.Helper()
	objects := []string{}
	for _, protocol := range []iptables.Protocol{iptables.ProtocolIPv4, iptables.ProtocolIPv6} {
		client, err := iptables.NewWithProtocol(protocol)
		require.NoError(t, err)
		for _, chain := range []string{isoChainForward, isoChainInput} {
			exists, err := client.ChainExists(tableMangle, chain)
			require.NoError(t, err)
			if exists {
				objects = append(objects, fmt.Sprintf("chain %s (protocol %d)", chain, protocol))
			}
		}
		for _, parent := range []string{chainForward, chainInput} {
			lines, err := client.List(tableMangle, parent)
			require.NoError(t, err)
			for _, line := range lines {
				if strings.Contains(line, "NETBIRD-ISO") {
					objects = append(objects, line)
				}
			}
		}
	}
	sets, err := ipset.ListAll()
	require.NoError(t, err)
	for _, set := range sets {
		if strings.HasPrefix(set.SetName, isoSetPrefix) {
			objects = append(objects, "ipset "+set.SetName)
		}
	}
	return objects
}

// assertSeparated sends real packets across the boundary between two networks, in the three
// ways a session must not cross it, for both address families.
func assertSeparated(t *testing.T, context string, from, to *isoNetwork) {
	t.Helper()
	assert.False(t, reaches(t, from.ns, from.peer4, to.ns, to.peer4),
		"%s: peer of %s must not reach the overlay of %s", context, from.name, to.name)
	assert.False(t, reaches(t, from.ns, from.peer4, to.ns, to.behind.Addr()),
		"%s: peer of %s must not reach the routed network behind %s", context, from.name, to.name)
	assert.False(t, reaches(t, from.ns, from.peer4, nil, to.addr.IP),
		"%s: peer of %s must not reach a local service on the IP of %s", context, from.name, to.name)
	assert.False(t, reaches(t, from.ns, from.peer6, to.ns, to.peer6),
		"%s: peer of %s must not reach the v6 overlay of %s", context, from.name, to.name)
	assert.False(t, reaches(t, from.ns, from.peer6, nil, to.addr.IPv6),
		"%s: peer of %s must not reach a local service on the v6 IP of %s", context, from.name, to.name)
}

func assertOwnServiceWorks(t *testing.T, context string, n *isoNetwork) {
	t.Helper()
	assert.True(t, reaches(t, n.ns, n.peer4, nil, n.addr.IP),
		"%s: peer of %s must reach a local service on its own overlay IP", context, n.name)
	assert.True(t, reaches(t, n.ns, n.peer6, nil, n.addr.IPv6),
		"%s: peer of %s must reach a local service on its own v6 overlay IP", context, n.name)
}

func assertNotSeparated(t *testing.T, context string, from, to *isoNetwork) {
	t.Helper()
	assert.True(t, reaches(t, from.ns, from.peer4, to.ns, to.peer4),
		"%s: route ACL must let the peer of %s reach the overlay of %s", context, from.name, to.name)
	assert.True(t, reaches(t, from.ns, from.peer4, to.ns, to.behind.Addr()),
		"%s: route ACL must let the peer of %s reach the routed network behind %s", context, from.name, to.name)
	assert.True(t, reaches(t, from.ns, from.peer4, nil, to.addr.IP),
		"%s: input ACL must let the peer of %s reach a local service on the IP of %s", context, from.name, to.name)
	assert.True(t, reaches(t, from.ns, from.peer6, to.ns, to.peer6),
		"%s: route ACL must let the peer of %s reach the v6 overlay of %s", context, from.name, to.name)
	assert.True(t, reaches(t, from.ns, from.peer6, nil, to.addr.IPv6),
		"%s: input ACL must let the peer of %s reach a local service on the v6 IP of %s", context, from.name, to.name)
}

// TestIsolationSeparatesSessionsWithRealPackets is the I3 and I4 scenario on a routing peer: the
// route ACLs of real managers allow the destination in the other network and only the isolation
// stands in the way. Both creation orders run because no order between tables may matter.
func TestIsolationSeparatesSessionsWithRealPackets(t *testing.T) {
	for _, tc := range []struct {
		name            string
		isolationIsLast bool
	}{
		{name: "isolation installed after the managers", isolationIsLast: true},
		{name: "isolation installed before the managers", isolationIsLast: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			enableHostForwarding(t)
			a, b, c := newIsoNetwork(t, 1), newIsoNetwork(t, 2), newIsoNetwork(t, 3)
			isolation := newTestIsolation(t)

			add := func() {
				for _, n := range []*isoNetwork{a, b, c} {
					require.NoError(t, addToIsolation(isolation, isoIfaceName(n), n.addr))
				}
				require.NoError(t, isolation.Verify())
			}
			if !tc.isolationIsLast {
				add()
			}

			sessionA := startIsoManager(t, a, routedDestinations(b, c)...)
			sessionB := startIsoManager(t, b, routedDestinations(a, c)...)
			sessionC := startIsoManager(t, c, routedDestinations(a, b)...)

			// Only a flow that exists before the isolation can show established traffic is cut.
			established := newIsoFlow(t, a.ns, a.peer4, b.ns, b.peer4, nextIsoPort())
			if tc.isolationIsLast {
				assertNotSeparated(t, "without isolation", a, b)
				assertOwnServiceWorks(t, "without isolation", a)
				require.True(t, established.forward(), "established flow setup, forward")
				require.True(t, established.reply(), "established flow setup, reply")
				add()
			}

			assert.NoError(t, isolation.Verify(), "managers must leave the isolation intact")
			assertSeparated(t, "all sessions up", a, b)
			assertSeparated(t, "all sessions up", b, a)
			assertSeparated(t, "all sessions up", a, c)
			assertOwnServiceWorks(t, "all sessions up", a)
			assertOwnServiceWorks(t, "all sessions up", b)
			assert.False(t, established.forward(), "an established flow must not cross either")

			for _, session := range []*isoSession{sessionA, sessionB} {
				_, err := session.manager.AddFilterRule(nil, []netip.Prefix{session.net.addr.Network},
					fw.Network{Prefix: netip.MustParsePrefix("198.51.100.0/24")}, fw.ProtocolALL, nil, nil, fw.ActionAccept)
				require.NoError(t, err)
				require.NoError(t, session.manager.Flush())
			}
			assert.NoError(t, isolation.Verify(), "a later rule of a session must leave the isolation intact")

			sessionC.stop(t)
			require.NoError(t, isolation.Remove(isoIfaceName(c)))
			assert.NoError(t, isolation.Verify(), "removing a session must leave a valid isolation")
			assertSeparated(t, "after session C left", a, b)
			assertSeparated(t, "after session C left", b, a)
			assertOwnServiceWorks(t, "after session C left", a)
			assertOwnServiceWorks(t, "after session C left", b)

			require.NoError(t, isolation.Remove(isoIfaceName(b)))
			assert.NotEmpty(t, isolationObjects(t), "one session left, the isolation must stay")
			assert.NoError(t, isolation.Verify())
			assertOwnServiceWorks(t, "with one session left", a)
			assertNotSeparated(t, "B is no longer isolated", a, b)

			require.NoError(t, isolation.Remove(isoIfaceName(a)))
			assert.Empty(t, isolationObjects(t), "the last Remove must remove the isolation completely")
			assert.NoError(t, isolation.Verify(), "no session and nothing installed is a valid state")
			assertNotSeparated(t, "no isolation left", a, b)
		})
	}
}

// bridgedIsoNetwork makes a session interface with two peers behind it, so traffic between them
// is forwarded in and out of that same interface.
func bridgedIsoNetwork(t *testing.T, slot uint) (string, wgaddr.Address, [2]*isoNS, [2]netip.Addr) {
	t.Helper()
	addr := isoAddress(slot)
	addr.IPv6 = netip.Addr{}
	addr.IPv6Net = netip.Prefix{}
	name := fmt.Sprintf("wt%d", slot)

	bridge := &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: name}}
	require.NoError(t, netlink.LinkAdd(bridge))
	t.Cleanup(func() { _ = netlink.LinkDel(bridge) })
	link, err := netlink.LinkByName(name)
	require.NoError(t, err)
	require.NoError(t, allowAsymmetricTraffic(name))
	require.NoError(t, addNodadAddr(link, addr.IP, addr.Network.Bits()))
	require.NoError(t, netlink.LinkSetUp(link))

	namespaces := [2]*isoNS{newIsoNS(t), newIsoNS(t)}
	peers := [2]netip.Addr{addr.IP.Next(), addr.IP.Next().Next()}
	for i, ns := range namespaces {
		port := fmt.Sprintf("%sp%d", name, i)
		veth := &netlink.Veth{
			LinkAttrs:     netlink.LinkAttrs{Name: port, MasterIndex: link.Attrs().Index},
			PeerName:      "peer0",
			PeerNamespace: netlink.NsFd(int(ns.file.Fd())),
		}
		require.NoError(t, netlink.LinkAdd(veth))
		t.Cleanup(func() { _ = netlink.LinkDel(veth) })
		portLink, err := netlink.LinkByName(port)
		require.NoError(t, err)
		require.NoError(t, netlink.LinkSetUp(portLink))

		peer := peers[i]
		ns.run(t, func() error {
			peerLink, err := netlink.LinkByName("peer0")
			if err != nil {
				return fmt.Errorf("find peer link: %w", err)
			}
			if err := allowAsymmetricTraffic("peer0"); err != nil {
				return err
			}
			// A /32 sends even the other peer through the host, as a tunnel would.
			if err := addNodadAddr(peerLink, peer, 32); err != nil {
				return fmt.Errorf("add peer address: %w", err)
			}
			if err := netlink.LinkSetUp(peerLink); err != nil {
				return fmt.Errorf("bring up peer: %w", err)
			}
			gateway := &netlink.Route{LinkIndex: peerLink.Attrs().Index, Dst: hostIPNet(addr.IP), Scope: netlink.SCOPE_LINK}
			if err := netlink.RouteAdd(gateway); err != nil {
				return fmt.Errorf("add gateway route: %w", err)
			}
			return addRoute(peerLink, netip.MustParsePrefix("0.0.0.0/0"), addr.IP)
		})
	}
	return name, addr, namespaces, peers
}

// TestIsolationKeepsForwardingInsideOneNetwork runs without managers because they have a hairpin
// rule of their own: the point is that the isolation does not add one.
func TestIsolationKeepsForwardingInsideOneNetwork(t *testing.T) {
	enableHostForwarding(t)
	name, addr, namespaces, peers := bridgedIsoNetwork(t, 5)
	other := newIsoNetwork(t, 6)

	require.True(t, reaches(t, namespaces[0], peers[0], namespaces[1], peers[1]), "peers must reach each other through the host")
	require.True(t, reaches(t, namespaces[0], peers[0], other.ns, other.peer4), "the other network must be reachable before isolation")

	isolation := newTestIsolation(t)
	require.NoError(t, addToIsolation(isolation, IfaceName(name), addr))
	require.NoError(t, addToIsolation(isolation, isoIfaceName(other), other.addr))

	assert.True(t, reaches(t, namespaces[0], peers[0], namespaces[1], peers[1]), "forwarding inside one network must keep working")
	assert.True(t, reaches(t, namespaces[1], peers[1], namespaces[0], peers[0]), "forwarding inside one network must keep working both ways")
	assert.False(t, reaches(t, namespaces[0], peers[0], other.ns, other.peer4), "forwarding to the other network must stop")
}

// TestIsolationLeavesOtherInterfacesAlone covers the LAN a routing peer serves: a route to it does
// not cross a session boundary.
func TestIsolationLeavesOtherInterfacesAlone(t *testing.T) {
	enableHostForwarding(t)
	a, b := newIsoNetwork(t, 1), newIsoNetwork(t, 2)

	lan := wgaddr.Address{IP: netip.MustParseAddr("192.168.77.1"), Network: netip.MustParsePrefix("192.168.77.0/24")}
	lanNS := newIsoNS(t)
	lanPeer := netip.MustParseAddr("192.168.77.2")
	connectIsoPeer(t, "lan0", lanNS, lan, lanPeer, netip.Addr{})

	isolation := newTestIsolation(t)
	require.NoError(t, addToIsolation(isolation, isoIfaceName(a), a.addr))
	require.NoError(t, addToIsolation(isolation, isoIfaceName(b), b.addr))

	assert.True(t, reaches(t, a.ns, a.peer4, lanNS, lanPeer), "a peer must reach a LAN that is not a session")
	assert.True(t, reaches(t, lanNS, lanPeer, a.ns, a.peer4), "the LAN must reach a peer")
	assert.True(t, reaches(t, lanNS, lanPeer, nil, a.addr.IP), "the LAN is not limited by I4")
}

func isoFakeAddress(index int) wgaddr.Address {
	return wgaddr.Address{
		IP:      netip.AddrFrom4([4]byte{100, 64, byte(index), 1}),
		Network: netip.PrefixFrom(netip.AddrFrom4([4]byte{100, 64, byte(index), 0}), 24),
	}
}

func isoRuleCount(t *testing.T, chain string) int {
	t.Helper()
	client, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	require.NoError(t, err)
	lines, err := client.List(tableMangle, chain)
	require.NoError(t, err)
	count := 0
	for _, line := range lines {
		if strings.HasPrefix(line, "-A ") {
			count++
		}
	}
	return count
}

func isoEntryCount(t *testing.T, setName string) int {
	t.Helper()
	listed, err := ipset.List(setName)
	require.NoError(t, err)
	return len(listed.Entries)
}

// TestIsolationScalesBeyondOneInterfaceSet goes past the few dozen interfaces the kernel keeps per
// prefix in a hash:net,iface set, because 5.8 allows no limit. The rules stay at one per session and the
// sessions on both sides of that border are isolated from each other with real packets.
func TestIsolationScalesBeyondOneInterfaceSet(t *testing.T) {
	const fakes = 140
	enableHostForwarding(t)
	isolation := newTestIsolation(t)

	early := newIsoNetworkV4Only(t, 1)
	require.NoError(t, addToIsolation(isolation, isoIfaceName(early), early.addr))
	for i := range fakes {
		require.NoError(t, addToIsolation(isolation, IfaceName(fmt.Sprintf("wt%d", 100+i)), isoFakeAddress(i)), "session %d", i)
	}
	late := newIsoNetworkV4Only(t, 2)
	require.NoError(t, addToIsolation(isolation, isoIfaceName(late), late.addr))

	sessions := fakes + 2
	assert.Equal(t, sessions, isoRuleCount(t, isoChainForward), "forwarding must take one rule per session")
	assert.Equal(t, 1, isoRuleCount(t, isoChainInput), "input must take one rule whatever the number of sessions")
	assert.GreaterOrEqual(t, isoEntryCount(t, isoSetIfaces), 2, "the interfaces must take more than one set")
	assert.NoError(t, isolation.Verify())

	assert.False(t, reaches(t, early.ns, early.peer4, late.ns, late.peer4), "the first must not reach the last")
	assert.False(t, reaches(t, late.ns, late.peer4, early.ns, early.peer4), "the last must not reach the first")
	assert.False(t, reaches(t, early.ns, early.peer4, nil, late.addr.IP), "the first must not reach the host through the last")
	assert.False(t, reaches(t, late.ns, late.peer4, nil, early.addr.IP), "the last must not reach the host through the first")
	assert.True(t, reaches(t, late.ns, late.peer4, nil, late.addr.IP), "the last must reach its own overlay")
	assert.True(t, reaches(t, early.ns, early.peer4, nil, early.addr.IP), "the first must reach its own overlay")

	require.NoError(t, isolation.Remove(IfaceName("wt100")))
	assert.Equal(t, sessions-1, isoRuleCount(t, isoChainForward), "leaving must take the rule along")
	assert.NoError(t, isolation.Verify())
	require.NoError(t, addToIsolation(isolation, IfaceName("wt100"), isoFakeAddress(0)), "the freed place must be usable")
	assert.NoError(t, isolation.Verify())
}

// TestIsolationVerifyFindsDamage changes the installed state the ways something outside the
// isolation could, and shows each one is an error (I6).
func TestIsolationVerifyFindsDamage(t *testing.T) {
	const name IfaceName = "wt1"

	for _, tc := range []struct {
		name   string
		damage func(t *testing.T, client *iptables.IPTables)
	}{
		{
			name: "jump removed from forward",
			damage: func(t *testing.T, client *iptables.IPTables) {
				require.NoError(t, client.Delete(tableMangle, chainForward, "-j", isoChainForward))
			},
		},
		{
			name: "jump removed from input",
			damage: func(t *testing.T, client *iptables.IPTables) {
				require.NoError(t, client.Delete(tableMangle, chainInput, "-j", isoChainInput))
			},
		},
		{
			name: "accept above the jump",
			damage: func(t *testing.T, client *iptables.IPTables) {
				require.NoError(t, client.Insert(tableMangle, chainForward, 1, "-i", string(name), "-j", "ACCEPT"))
				t.Cleanup(func() { _ = client.Delete(tableMangle, chainForward, "-i", string(name), "-j", "ACCEPT") })
			},
		},
		{
			name: "accept in the input chain",
			damage: func(t *testing.T, client *iptables.IPTables) {
				require.NoError(t, client.Insert(tableMangle, isoChainInput, 1, "-j", "ACCEPT"))
			},
		},
		{
			name: "forward rule removed",
			damage: func(t *testing.T, client *iptables.IPTables) {
				require.NoError(t, client.ClearChain(tableMangle, isoChainForward))
			},
		},
		{
			name: "interface removed from its set",
			damage: func(t *testing.T, _ *iptables.IPTables) {
				require.NoError(t, ipset.Flush(isoSetIfaces+"-0"))
			},
		},
		{
			name: "pair added to own",
			damage: func(t *testing.T, _ *iptables.IPTables) {
				require.NoError(t, ipset.Add(isoSetOwn, &ipset.Entry{
					IP: netip.MustParseAddr("100.64.9.0").AsSlice(), CIDR: 24, IFace: string(name), Replace: true,
				}))
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolation := newTestIsolation(t)
			require.NoError(t, addToIsolation(isolation, name, isoFakeAddress(1)))
			require.NoError(t, isolation.Verify(), "the intact isolation must verify")

			client, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
			require.NoError(t, err)
			tc.damage(t, client)

			assert.Error(t, isolation.Verify(), "damage must be reported")
		})
	}
}

// TestIsolationStaysAboveAcceptsOfLaterManagers: a manager started after the isolation adds its
// established accept to mangle FORWARD and its MSS clamping jump on top of the chain. The accept
// has to stay below the isolation, and the clamping jump must not count as damage.
func TestIsolationStaysAboveAcceptsOfLaterManagers(t *testing.T) {
	enableHostForwarding(t)
	isolation := newTestIsolation(t)
	a := newIsoNetworkV4Only(t, 1)
	require.NoError(t, addToIsolation(isolation, isoIfaceName(a), a.addr))

	manager, err := Create(a.ifaceMock(), iface.DefaultMTU, WithSlot(a.slot))
	require.NoError(t, err)
	require.NoError(t, manager.Init(nil))
	t.Cleanup(func() { assert.NoError(t, manager.Close(nil)) })
	_, err = manager.AddFilterRule(nil, []netip.Prefix{a.addr.Network},
		fw.Network{Prefix: netip.MustParsePrefix("198.51.100.0/24")}, fw.ProtocolALL, nil, nil, fw.ActionAccept)
	require.NoError(t, err)
	require.NoError(t, manager.Flush())

	assert.NoError(t, isolation.Verify(), "what a manager adds to mangle must not count as damage")
}

// TestIsolationStaysClosedWithoutSlot is the counterpart of the nftables bypass: a manager without a
// slot and the allower of the userspace mode must not get past the isolation chains in mangle.
func TestIsolationStaysClosedWithoutSlot(t *testing.T) {
	openers := []struct {
		name string
		open func(t *testing.T, n *isoNetwork)
	}{
		{
			name: "manager from Create",
			open: func(t *testing.T, n *isoNetwork) {
				t.Helper()
				manager, err := Create(n.ifaceMock(), iface.DefaultMTU)
				require.NoError(t, err)
				require.NoError(t, manager.Init(nil))
				t.Cleanup(func() { assert.NoError(t, manager.Close(nil)) })
				_, err = manager.AddFilterRule(nil, []netip.Prefix{n.addr.Network}, fw.Network{}, fw.ProtocolALL, nil, nil, fw.ActionAccept)
				require.NoError(t, err)
				require.NoError(t, manager.Flush())
			},
		},
		{
			name: "allower from NewInterfaceAllower",
			open: func(t *testing.T, n *isoNetwork) {
				t.Helper()
				allower, err := NewInterfaceAllower(n.ifaceMock())
				require.NoError(t, err)
				require.NoError(t, allower.Apply())
				t.Cleanup(func() { assert.NoError(t, allower.Close()) })
			},
		},
	}

	for _, opener := range openers {
		for _, isolationFirst := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s, isolation first %t", opener.name, isolationFirst), func(t *testing.T) {
				enableHostForwarding(t)
				a, b := newIsoNetwork(t, 1), newIsoNetwork(t, 2)
				isolation := newTestIsolation(t)
				add := func() {
					require.NoError(t, addToIsolation(isolation, isoIfaceName(a), a.addr))
					require.NoError(t, addToIsolation(isolation, isoIfaceName(b), b.addr))
				}

				if isolationFirst {
					add()
					opener.open(t, a)
				} else {
					opener.open(t, a)
					add()
				}

				assert.NoError(t, isolation.Verify(), "nothing may have changed the isolation")
				assert.False(t, reaches(t, a.ns, a.peer4, nil, b.addr.IP), "A must not reach a local service on the IP of B")
				assert.False(t, reaches(t, a.ns, a.peer6, nil, b.addr.IPv6), "A must not reach a local service on the v6 IP of B")
				assert.True(t, reaches(t, a.ns, a.peer4, nil, a.addr.IP), "A must keep its own local service")
			})
		}
	}
}

// TestIsolationAddFailsClosed covers the paths where a session must not start: nothing may look
// installed afterwards.
func TestIsolationAddFailsClosed(t *testing.T) {
	t.Run("kernel refuses a step", func(t *testing.T) {
		isolation := newTestIsolation(t)
		require.NoError(t, addToIsolation(isolation, "wt1", isoFakeAddress(1)))

		client, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
		require.NoError(t, err)
		require.NoError(t, client.Delete(tableMangle, chainForward, "-j", isoChainForward))
		require.NoError(t, client.ClearAndDeleteChain(tableMangle, isoChainForward))

		assert.Error(t, addToIsolation(isolation, "wt2", isoFakeAddress(2)), "the chain to add to is gone")
		assert.Equal(t, 2, isoEntryCount(t, isoSetIfaces+"-0"), "only the running session may stay in the set")
		assert.Error(t, isolation.Verify(), "the isolation is still broken")
	})

	t.Run("install fails on the first session", func(t *testing.T) {
		isolation := newTestIsolation(t)
		const blocking = "nb-iso-own"
		// A set of the same name that is in use cannot be replaced, so the install stops midway.
		require.NoError(t, ipset.Create(blocking, ipset.TypeHashNet, ipset.CreateOptions{}))
		client, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
		require.NoError(t, err)
		rule := []string{"-m", "set", "--match-set", blocking, "dst", "-j", "ACCEPT"}
		require.NoError(t, client.Append(tableFilter, chainOutput, rule...))
		t.Cleanup(func() { _ = client.Delete(tableFilter, chainOutput, rule...) })

		assert.Error(t, addToIsolation(isolation, "wt1", isoFakeAddress(1)), "the install must fail")

		require.NoError(t, client.Delete(tableFilter, chainOutput, rule...))
		require.NoError(t, isolation.RemoveAll(), "cleanup must work once the blocker is gone")
		assert.Empty(t, isolationObjects(t), "nothing may stay behind")
		assert.NoError(t, addToIsolation(isolation, "wt1", isoFakeAddress(1)), "a later attempt must work")
		assert.NoError(t, isolation.Verify())
	})

	t.Run("invalid input", func(t *testing.T) {
		isolation := newTestIsolation(t)
		for _, name := range []IfaceName{"", "this-name-is-too-long", "wt/1", "wt 1", "wt+", ".."} {
			assert.Error(t, addToIsolation(isolation, name, isoFakeAddress(1)), "name %q must be refused", name)
		}
		for _, addr := range []wgaddr.Address{
			{},
			{Network: netip.MustParsePrefix("0.0.0.0/0")},
			{Network: netip.MustParsePrefix("fd00::/64")},
		} {
			assert.Error(t, addToIsolation(isolation, "wt1", addr), "overlay %v must be refused", addr.Network)
		}
		assert.Empty(t, isolationObjects(t), "refused input must not install anything")
	})

	t.Run("overlapping IPv4 overlay", func(t *testing.T) {
		isolation := newTestIsolation(t)
		require.NoError(t, addToIsolation(isolation, "wt1", isoFakeAddress(1)))

		overlapping := wgaddr.Address{Network: netip.MustParsePrefix("100.64.0.0/16")}
		assert.ErrorIs(t, addToIsolation(isolation, "wt2", overlapping), ErrOverlayOverlap)
		assert.Equal(t, 1, isoRuleCount(t, isoChainForward), "the refused session must not have a rule")
		assert.NoError(t, isolation.Verify())
	})
}

// TestIsolationIPv6IsSoft shows a session without IPv6, or one whose v6 cannot be used, keeps the
// isolation of v4 working.
func TestIsolationIPv6IsSoft(t *testing.T) {
	t.Run("no v6 at all", func(t *testing.T) {
		enableHostForwarding(t)
		isolation := newTestIsolation(t)
		a, b := newIsoNetworkV4Only(t, 1), newIsoNetworkV4Only(t, 2)
		require.NoError(t, addToIsolation(isolation, isoIfaceName(a), a.addr))
		require.NoError(t, addToIsolation(isolation, isoIfaceName(b), b.addr))
		assert.NoError(t, isolation.Verify())
		assert.Zero(t, isoEntryCount(t, isoSetOwn+isoSetV6Suffix), "no session has a v6 overlay")

		assert.False(t, reaches(t, a.ns, a.peer4, b.ns, b.peer4), "v4 must stay isolated")
		assert.False(t, reaches(t, a.ns, a.peer4, nil, b.addr.IP), "v4 must stay isolated")
		assert.True(t, reaches(t, a.ns, a.peer4, nil, a.addr.IP), "the own overlay must stay reachable")
	})

	t.Run("host without ip6tables", func(t *testing.T) {
		isolation := newTestIsolation(t)
		plane6 := isolation.plane6
		isolation.plane6 = nil
		t.Cleanup(func() { isolation.plane6 = plane6 })

		require.NoError(t, addToIsolation(isolation, "wt1", isoFakeAddress(1)), "a session without v6 must not need ip6tables")
		assert.NoError(t, isolation.Verify())

		withV6 := isoFakeAddress(2)
		withV6.IPv6, withV6.IPv6Net = netip.MustParseAddr("fd00::1"), netip.MustParsePrefix("fd00::/64")
		assert.Error(t, addToIsolation(isolation, "wt2", withV6), "a session with v6 cannot be isolated without ip6tables")
		assert.NoError(t, isolation.Verify(), "the running session must stay isolated")
	})

	t.Run("v6 installed late covers running sessions", func(t *testing.T) {
		isolation := newTestIsolation(t)
		require.NoError(t, isolation.plane6.teardown())
		plane6 := isolation.plane6
		isolation.plane6 = nil
		require.NoError(t, addToIsolation(isolation, "wt1", isoFakeAddress(1)))
		isolation.plane6 = plane6

		withV6 := isoFakeAddress(2)
		withV6.IPv6, withV6.IPv6Net = netip.MustParseAddr("fd00::1"), netip.MustParsePrefix("fd00::/64")
		require.NoError(t, addToIsolation(isolation, "wt2", withV6))
		assert.NoError(t, isolation.Verify())
		assert.Equal(t, 4, isoEntryCount(t, isoSetIfaces+isoSetV6Suffix+"-0"), "both interfaces must be in the v6 set")
	})

	t.Run("overlapping v6 overlay is skipped", func(t *testing.T) {
		isolation := newTestIsolation(t)
		first, second := isoFakeAddress(1), isoFakeAddress(2)
		first.IPv6, first.IPv6Net = netip.MustParseAddr("fd00::1"), netip.MustParsePrefix("fd00::/64")
		second.IPv6, second.IPv6Net = netip.MustParseAddr("fd00::2"), netip.MustParsePrefix("fd00::/64")
		require.NoError(t, addToIsolation(isolation, "wt1", first))
		require.NoError(t, addToIsolation(isolation, "wt2", second), "a v6 overlap must not stop the session")

		assert.Equal(t, 1, isoEntryCount(t, isoSetOwn+isoSetV6Suffix), "only the first session owns the v6 overlay")
		assert.Equal(t, 2, isoEntryCount(t, isoSetOwn), "both sessions keep their v4 overlay")
		assert.NoError(t, isolation.Verify())
	})
}

// TestIsolationAddUpdatesKnownSession covers the overlay changing while the session runs. The old
// overlay must not stay in the sets, and Add with the same values must not touch anything.
func TestIsolationAddUpdatesKnownSession(t *testing.T) {
	isolation := newTestIsolation(t)
	require.NoError(t, addToIsolation(isolation, "wt1", isoFakeAddress(1)))
	require.NoError(t, addToIsolation(isolation, "wt2", isoFakeAddress(2)))
	require.NoError(t, addToIsolation(isolation, "wt1", isoFakeAddress(1)), "the same values must be accepted")
	assert.Equal(t, 2, isoRuleCount(t, isoChainForward), "the same values must not add a rule")

	require.NoError(t, addToIsolation(isolation, "wt1", isoFakeAddress(3)))
	assert.NoError(t, isolation.Verify(), "the sets must hold exactly the new overlay")
	assert.Equal(t, 2, isoRuleCount(t, isoChainForward), "an update must not add a rule")

	assert.ErrorIs(t, addToIsolation(isolation, "wt2", isoFakeAddress(3)), ErrOverlayOverlap)
	require.NoError(t, addToIsolation(isolation, "wt2", isoFakeAddress(1)), "the freed overlay must be usable")
	assert.NoError(t, isolation.Verify())
}

func prefixEntries(name IfaceName, prefixes ...netip.Prefix) []string {
	entries := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		entries = append(entries, entryIdentity(net.IP(prefix.Addr().AsSlice()), prefix.Bits(), string(name)))
	}
	return entries
}

// removeIsolationSet makes the kernel refuse every change of a set. The input rule is the only one
// holding on to the overlay sets.
func removeIsolationSet(t *testing.T, plane *isolationPlane, base string) {
	t.Helper()
	require.NoError(t, plane.client.ClearChain(tableMangle, isoChainInput))
	require.NoError(t, destroySetWhenUnused(plane.setName(base)))
}

// restoreIsolationSet undoes removeIsolationSet, the entries show what the isolation should hold.
func restoreIsolationSet(t *testing.T, plane *isolationPlane, base string, setType string, entries ...*ipset.Entry) {
	t.Helper()
	require.NoError(t, ipset.Create(plane.setName(base), setType, plane.createOptions()))
	for _, entry := range entries {
		require.NoError(t, ipset.Add(plane.setName(base), entry))
	}
	require.NoError(t, plane.client.Append(tableMangle, isoChainInput, plane.inputRule()...))
}

// TestIsolationFailedUpdateKeepsState: ipsets have no batch, so an update of the overlays is several
// steps. When one fails the kernel and what Remove and Verify work from must still agree, or Verify
// keeps failing for all other sessions long after the session is gone (I2).
func TestIsolationFailedUpdateKeepsState(t *testing.T) {
	t.Run("host without ip6tables for the new v6 overlay", func(t *testing.T) {
		isolation := newTestIsolation(t)
		plane6 := isolation.plane6
		isolation.plane6 = nil
		t.Cleanup(func() { isolation.plane6 = plane6 })
		require.NoError(t, addToIsolation(isolation, "wt1", isoFakeAddress(1)))
		require.NoError(t, addToIsolation(isolation, "wt2", isoFakeAddress(2)))

		next := isoFakeAddress(3)
		next.IPv6, next.IPv6Net = netip.MustParseAddr("fd00:3::1"), netip.MustParsePrefix("fd00:3::/64")
		assert.Error(t, addToIsolation(isolation, "wt1", next), "a session with v6 cannot be isolated without ip6tables")
		assert.NoError(t, isolation.Verify(), "the running session must keep its overlay")

		require.NoError(t, isolation.Remove("wt1"))
		assert.NoError(t, isolation.Verify(), "the other session must not pay for the failed update")
	})

	t.Run("v6 half refuses after the v4 half moved", func(t *testing.T) {
		isolation := newTestIsolation(t)
		withV6 := func(index int) wgaddr.Address {
			addr := isoFakeAddress(index)
			addr.IPv6 = netip.AddrFrom16([16]byte{0xfd, 0, 0, byte(index), 15: 1})
			addr.IPv6Net = netip.PrefixFrom(netip.AddrFrom16([16]byte{0xfd, 0, 0, byte(index)}), 64)
			return addr
		}
		first, second := withV6(1), withV6(2)
		require.NoError(t, addToIsolation(isolation, "wt1", first))
		require.NoError(t, addToIsolation(isolation, "wt2", second))

		removeIsolationSet(t, isolation.plane6, isoSetOwn)
		assert.Error(t, addToIsolation(isolation, "wt1", withV6(3)), "the v6 set to change is gone")

		wantOwn := append(prefixEntries("wt1", first.Network), prefixEntries("wt2", second.Network)...)
		assert.NoError(t, verifySetEntries(isoSetOwn, wantOwn), "v4 must be back on the old overlay")
		assert.NoError(t, verifySetEntries(isoSetOverlays, prefixEntries("", first.Network, second.Network)),
			"v4 must be back on the old overlay")
		assert.Equal(t, first.Network, isolation.members["wt1"].overlay, "the session keeps its old overlay")

		restoreIsolationSet(t, isolation.plane6, isoSetOwn, ipset.TypeHashNetIface,
			prefixEntry(first.IPv6Net, "wt1"), prefixEntry(second.IPv6Net, "wt2"))
		assert.NoError(t, isolation.Verify(), "kernel and members must agree once the host is repaired")

		require.NoError(t, isolation.Remove("wt1"))
		assert.NoError(t, isolation.Verify(), "the other session must not pay for the failed update")
	})

	// The set is gone for the rollback too. What it could not undo must stay known: other sessions
	// must not get the prefix, and Remove has to take it along.
	failRollback := func(t *testing.T) (*Isolation, wgaddr.Address, wgaddr.Address, wgaddr.Address) {
		t.Helper()
		isolation := newTestIsolation(t)
		first, second, next := isoFakeAddress(1), isoFakeAddress(2), isoFakeAddress(3)
		require.NoError(t, addToIsolation(isolation, "wt1", first))
		require.NoError(t, addToIsolation(isolation, "wt2", second))

		removeIsolationSet(t, isolation.plane4, isoSetOverlays)
		assert.Error(t, addToIsolation(isolation, "wt1", next), "the set to change is gone")
		assert.NoError(t, verifySetEntries(isoSetOwn, append(prefixEntries("wt1", first.Network), prefixEntries("wt2", second.Network)...)),
			"the new overlay must not stay in the set that was still there")
		assert.ErrorIs(t, addToIsolation(isolation, "wt2", next), ErrOverlayOverlap, "the prefix may still be in the kernel")

		restoreIsolationSet(t, isolation.plane4, isoSetOverlays, ipset.TypeHashNet,
			prefixEntry(first.Network, ""), prefixEntry(second.Network, ""))
		require.NoError(t, isolation.Verify(), "kernel and members must agree once the host is repaired")
		return isolation, first, second, next
	}

	t.Run("failed rollback, Remove takes what is left along", func(t *testing.T) {
		isolation, _, second, next := failRollback(t)

		require.NoError(t, isolation.plane4.addOverlay("wt1", next.Network))
		require.Error(t, isolation.Verify(), "a prefix left in the kernel must be reported")

		require.NoError(t, isolation.Remove("wt1"))
		assert.NoError(t, isolation.Verify(), "nothing of the session may stay")
		assert.NoError(t, verifySetEntries(isoSetOwn, prefixEntries("wt2", second.Network)), "only the other session may stay")
		assert.NoError(t, addToIsolation(isolation, "wt2", next), "the prefix is free again")
		assert.NoError(t, isolation.Verify())
	})

	t.Run("failed rollback, a repeated update finishes the job", func(t *testing.T) {
		isolation, first, _, next := failRollback(t)

		require.NoError(t, isolation.plane4.addOverlay("wt1", next.Network))
		assert.NoError(t, addToIsolation(isolation, "wt1", first), "the same overlay must still clean up")
		assert.NoError(t, isolation.Verify(), "nothing may be left of the failed update")

		assert.NoError(t, addToIsolation(isolation, "wt1", next))
		assert.NoError(t, isolation.Verify())
	})
}

// TestRestoreOverlayFromAnyStep starts from what a failure midway leaves. Removing the previous
// overlay only fails on a kernel error that cannot be caused from outside, so the state is set up
// by hand: the new overlay is in, the previous one half gone.
func TestRestoreOverlayFromAnyStep(t *testing.T) {
	isolation := newTestIsolation(t)
	previous, next := isoFakeAddress(1).Network, isoFakeAddress(2).Network
	require.NoError(t, addToIsolation(isolation, "wt1", isoFakeAddress(1)))

	require.NoError(t, isolation.plane4.addOverlay("wt1", next))
	require.NoError(t, ipset.Del(isoSetOverlays, prefixEntry(previous, "")))
	require.Error(t, isolation.Verify(), "the state must differ for this to mean anything")

	assert.NoError(t, isolation.plane4.restoreOverlay("wt1", previous, next))
	assert.NoError(t, isolation.Verify(), "exactly the previous overlay must be back")
}

// TestIsolationCleansUpAfterCrash leaves the state of a dead daemon behind and shows both ways out
// of it: the next daemon's first session starts from a clean state, and without any session all
// of it goes away (I7).
func TestIsolationCleansUpAfterCrash(t *testing.T) {
	crashed := newTestIsolation(t)
	require.NoError(t, addToIsolation(crashed, "wt1", isoFakeAddress(1)))
	require.NoError(t, addToIsolation(crashed, "wt2", isoFakeAddress(2)))

	next, err := NewIsolation()
	require.NoError(t, err)
	assert.Error(t, next.Verify(), "state no session stands behind must be reported")
	require.NoError(t, addToIsolation(next, "wt3", isoFakeAddress(3)))
	assert.NoError(t, next.Verify(), "the first session must replace what the crash left")
	assert.Equal(t, 1, isoRuleCount(t, isoChainForward), "nothing of the dead sessions may stay")
	require.NoError(t, next.Remove("wt3"))
	assert.Empty(t, isolationObjects(t), "the last Remove must remove everything")

	crashedAgain, err := NewIsolation()
	require.NoError(t, err)
	require.NoError(t, addToIsolation(crashedAgain, "wt1", isoFakeAddress(1)))
	fresh, err := NewIsolation()
	require.NoError(t, err)
	require.NoError(t, fresh.RemoveAll())
	assert.Empty(t, isolationObjects(t), "RemoveAll must remove what a crash left")
	assert.NoError(t, fresh.RemoveAll(), "RemoveAll must work with nothing installed")
	assert.NoError(t, fresh.Remove("wt1"), "Remove of an unknown session must do nothing")
}

// TestIsolationOverlappingIPv6WithRealPackets is the conflict of spec section 6. The rules go by
// address, so they can only hold when the session whose v6 was disabled does what Add tells it:
// the address must not stay on its interface. The test plays that caller. Once it has, peers of A
// reach nothing of B over v6, and traffic from the interface of B is dropped.
func TestIsolationOverlappingIPv6WithRealPackets(t *testing.T) {
	for _, tc := range isoV6Overlaps() {
		t.Run(tc.name, func(t *testing.T) {
			enableHostForwarding(t)
			a := newIsoNetworkWithAddress(t, 1, tc.first)
			b := newIsoNetworkWithAddress(t, 2, tc.second)
			connectOverlappingPeers(t, a, b)

			// Without these, a probe that fails later would prove nothing.
			require.True(t, reachesHost(t, a.ns, a.peer6, b.addr.IPv6), "without isolation A reaches the v6 address of B")
			require.True(t, reachesHost(t, b.ns, b.peer6, a.addr.IPv6), "without isolation B reaches the v6 address of A")
			require.True(t, reaches(t, a.ns, a.peer6, b.ns, b.peer6), "without isolation A reaches the v6 peer of B")
			require.True(t, reaches(t, b.ns, b.peer6, a.ns, a.peer6), "without isolation B reaches the v6 peer of A")

			isolation := newTestIsolation(t)
			disabled, err := addReportingIPv6(isolation, isoIfaceName(a), a.addr)
			require.NoError(t, err)
			assert.False(t, disabled, "the first session keeps its v6")
			disabled, err = addReportingIPv6(isolation, isoIfaceName(b), b.addr)
			require.NoError(t, err, "a v6 overlap must not stop the session")
			assert.True(t, disabled, "the second session must be told its v6 is disabled")
			assert.NoError(t, isolation.Verify())

			// The condition on the caller: this is what stays open if it ignores the result.
			assert.True(t, reachesHost(t, a.ns, a.peer6, b.addr.IPv6),
				"the rules cannot tell an address left on the interface from the range of A")

			if disabled {
				dropOwnIPv6(t, b)
			}

			assert.False(t, reachesHost(t, a.ns, a.peer6, b.addr.IPv6), "A must not reach the v6 address of B (I4)")
			assert.False(t, reachesHost(t, b.ns, b.peer6, a.addr.IPv6), "traffic from B to the v6 address of A must be dropped (I4)")
			assert.False(t, reaches(t, a.ns, a.peer6, b.ns, b.peer6), "A must not reach the v6 peer of B (I3)")
			assert.False(t, reaches(t, b.ns, b.peer6, a.ns, a.peer6), "B must not reach the v6 peer of A (I3)")
			assert.True(t, reachesHost(t, a.ns, a.peer6, a.addr.IPv6), "A keeps its own v6 service")

			assert.False(t, reaches(t, a.ns, a.peer4, b.ns, b.peer4), "v4 must stay isolated")
			assert.False(t, reaches(t, a.ns, a.peer4, nil, b.addr.IP), "v4 must stay isolated")
			assert.True(t, reaches(t, b.ns, b.peer4, nil, b.addr.IP), "B keeps its v4")
		})
	}
}

func addToIsolation(isolation *Isolation, name IfaceName, addr wgaddr.Address) error {
	_, err := isolation.Add(name, addr)
	return err
}

func addReportingIPv6(isolation *Isolation, name IfaceName, addr wgaddr.Address) (bool, error) {
	result, err := isolation.Add(name, addr)
	return result.IPv6Disabled, err
}

// TestIsolationAddReportsDisabledIPv6 covers all the ways to the result. It has to hold for the
// call that changes nothing too: a session restarting its setup must get the same answer.
func TestIsolationAddReportsDisabledIPv6(t *testing.T) {
	withV6 := func(index int, overlay6 string) wgaddr.Address {
		prefix := netip.MustParsePrefix(overlay6)
		addr := isoFakeAddress(index)
		addr.IPv6, addr.IPv6Net = prefix.Addr(), prefix.Masked()
		return addr
	}
	first, overlapping := withV6(1, "fd00:aa::1/64"), withV6(2, "fd00:aa::2/64")

	t.Run("no overlap", func(t *testing.T) {
		isolation := newTestIsolation(t)
		for name, addr := range map[IfaceName]wgaddr.Address{
			"wt1": first,
			"wt2": withV6(2, "fd00:bb::1/64"),
			"wt3": isoFakeAddress(3),
		} {
			disabled, err := addReportingIPv6(isolation, name, addr)
			require.NoError(t, err)
			assert.False(t, disabled, "%s must keep what it asked for", name)
		}
		assert.Equal(t, 2, isoEntryCount(t, isoSetOwn+isoSetV6Suffix), "both sessions with v6 own it")
	})

	t.Run("repeated, and after the other session left", func(t *testing.T) {
		isolation := newTestIsolation(t)
		require.NoError(t, addToIsolation(isolation, "wt1", first))

		for range 2 {
			disabled, err := addReportingIPv6(isolation, "wt2", overlapping)
			require.NoError(t, err)
			assert.True(t, disabled, "the overlap still exists")
		}
		assert.Equal(t, 1, isoEntryCount(t, isoSetOwn+isoSetV6Suffix), "only the first session owns the v6 overlay")

		require.NoError(t, isolation.Remove("wt1"))
		disabled, err := addReportingIPv6(isolation, "wt2", overlapping)
		require.NoError(t, err)
		assert.False(t, disabled, "the overlap is gone")
		assert.Equal(t, 1, isoEntryCount(t, isoSetOwn+isoSetV6Suffix), "the session now owns its v6 overlay")
		assert.NoError(t, isolation.Verify())
	})

	t.Run("a running session moving onto another overlay", func(t *testing.T) {
		isolation := newTestIsolation(t)
		require.NoError(t, addToIsolation(isolation, "wt1", first))
		require.NoError(t, addToIsolation(isolation, "wt2", withV6(2, "fd00:bb::1/64")))
		require.Equal(t, 2, isoEntryCount(t, isoSetOwn+isoSetV6Suffix), "both sessions own their v6 overlay")

		disabled, err := addReportingIPv6(isolation, "wt2", overlapping)
		require.NoError(t, err)
		assert.True(t, disabled, "the running session must learn it lost its v6")
		assert.Equal(t, 1, isoEntryCount(t, isoSetOwn+isoSetV6Suffix), "its old v6 overlay must leave")
		assert.NoError(t, isolation.Verify())
	})

	t.Run("a refused session gets no result", func(t *testing.T) {
		isolation := newTestIsolation(t)
		require.NoError(t, addToIsolation(isolation, "wt1", first))

		disabled, err := addReportingIPv6(isolation, "wt2", withV6(1, "fd00:aa::2/64"))
		assert.ErrorIs(t, err, ErrOverlayOverlap)
		assert.False(t, disabled, "a session that must not run has nothing to honor")
	})
}
