//go:build privileged

package nftables

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

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
	names, err := NamesForSlot(n.slot)
	require.NoError(t, err)
	manager, err := CreateForSession(n.ifaceMock(), iface.DefaultMTU, names)
	require.NoError(t, err)
	return runIsoManager(t, n, manager, destinations...)
}

func runIsoManager(t *testing.T, n *isoNetwork, manager *Manager, destinations ...netip.Prefix) *isoSession {
	t.Helper()
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

func hasIsolationTable(t *testing.T) bool {
	t.Helper()
	return len(tableFamilies(t, IsolationTableName)) > 0
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
			isolation := NewIsolation()
			t.Cleanup(func() { assert.NoError(t, isolation.RemoveAll()) })

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

			for _, session := range []*isoSession{sessionA, sessionB, sessionC} {
				require.NoError(t, session.manager.reconcileExternalChains())
			}
			assert.NoError(t, isolation.Verify(), "a reconcile must not open the isolation chains")

			sessionC.stop(t)
			require.NoError(t, isolation.Remove(isoIfaceName(c)))
			assert.NoError(t, isolation.Verify(), "removing a session must leave a valid isolation")
			assertSeparated(t, "after session C left", a, b)
			assertSeparated(t, "after session C left", b, a)
			assertOwnServiceWorks(t, "after session C left", a)
			assertOwnServiceWorks(t, "after session C left", b)

			require.NoError(t, isolation.Remove(isoIfaceName(b)))
			assert.True(t, hasIsolationTable(t), "one session left, the isolation must stay")
			assert.NoError(t, isolation.Verify())
			assertOwnServiceWorks(t, "with one session left", a)
			assertNotSeparated(t, "B is no longer isolated", a, b)

			require.NoError(t, isolation.Remove(isoIfaceName(a)))
			assert.False(t, hasIsolationTable(t), "the last Remove must remove the isolation completely")
			assert.NoError(t, isolation.Verify(), "no session and no table is a valid state")
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

	isolation := NewIsolation()
	t.Cleanup(func() { assert.NoError(t, isolation.RemoveAll()) })
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

	isolation := NewIsolation()
	t.Cleanup(func() { assert.NoError(t, isolation.RemoveAll()) })
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

func isoElementCount(t *testing.T, setName string) int {
	t.Helper()
	elements, err := (&nftables.Conn{}).GetSetElements(&nftables.Set{Table: isolationTable(), Name: setName})
	require.NoError(t, err)
	return len(elements)
}

func isoRuleHandles(t *testing.T) []ruleIdentity {
	t.Helper()
	return snapshotTableRules(t, IsolationTableName)
}

// TestIsolationSessionsOnlyChangeSets pins the design of 5.8: the number of rules does not grow
// with the sessions. The handles show the rules were not even replaced.
func TestIsolationSessionsOnlyChangeSets(t *testing.T) {
	isolation := NewIsolation()
	t.Cleanup(func() { assert.NoError(t, isolation.RemoveAll()) })

	require.NoError(t, addToIsolation(isolation, "wt1", isoFakeAddress(1)))
	rules := isoRuleHandles(t)
	require.NotEmpty(t, rules)

	const sessions = 70
	for i := 2; i <= sessions; i++ {
		require.NoError(t, addToIsolation(isolation, IfaceName(fmt.Sprintf("wt%d", i)), isoFakeAddress(i)))
	}
	assert.Equal(t, rules, isoRuleHandles(t), "sessions must not change the rules")
	assert.Equal(t, sessions, isoElementCount(t, isoSetIfaces), "every interface must be in the set")
	assert.Equal(t, sessions, isoElementCount(t, isoSetOwn), "every session must own its overlay")
	assert.NoError(t, isolation.Verify())

	require.NoError(t, isolation.Remove("wt35"))
	assert.Equal(t, rules, isoRuleHandles(t), "a departing session must not change the rules")
	assert.Equal(t, sessions-1, isoElementCount(t, isoSetIfaces), "the interface must leave the set")
	assert.NoError(t, isolation.Verify())
}

// TestIsolationVerifyFindsDamage changes the installed state the ways something outside the
// isolation could, and shows each one is an error (I6).
func TestIsolationVerifyFindsDamage(t *testing.T) {
	const name IfaceName = "wt1"
	sets := newIsolationSets()

	for _, tc := range []struct {
		name   string
		damage func(t *testing.T, conn *nftables.Conn)
	}{
		{
			name:   "table removed",
			damage: func(_ *testing.T, conn *nftables.Conn) { conn.DelTable(isolationTable()) },
		},
		{
			name: "table dormant",
			damage: func(t *testing.T, _ *nftables.Conn) {
				makeIsolationTableDormant(t)
				table, err := (&nftables.Conn{}).ListTableOfFamily(IsolationTableName, nftables.TableFamilyINet)
				require.NoError(t, err)
				require.NotZero(t, table.Flags, "the table must be dormant for this case to mean anything")
			},
		},
		{
			name: "accept inserted in front of the forward drop",
			damage: func(_ *testing.T, conn *nftables.Conn) {
				conn.InsertRule(&nftables.Rule{
					Table: isolationTable(),
					Chain: &nftables.Chain{Name: isoChainForward, Table: isolationTable()},
					Exprs: []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}},
				})
			},
		},
		{
			name: "input chain flushed",
			damage: func(_ *testing.T, conn *nftables.Conn) {
				conn.FlushChain(&nftables.Chain{Name: isoChainInput, Table: isolationTable()})
			},
		},
		{
			name: "chain added",
			damage: func(_ *testing.T, conn *nftables.Conn) {
				conn.AddChain(&nftables.Chain{Name: "extra", Table: isolationTable()})
			},
		},
		{
			name: "interface removed from its set",
			damage: func(t *testing.T, conn *nftables.Conn) {
				require.NoError(t, conn.SetDeleteElements(sets.ifaces, []nftables.SetElement{{Key: ifname(string(name))}}))
			},
		},
		{
			name: "pair added to own",
			damage: func(t *testing.T, conn *nftables.Conn) {
				other := isoFakeAddress(9).Network
				for _, batch := range sets.overlayElements("wt9", other) {
					if batch.set == sets.own {
						require.NoError(t, conn.SetAddElements(batch.set, batch.elements))
					}
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolation := NewIsolation()
			t.Cleanup(func() { assert.NoError(t, isolation.RemoveAll()) })
			require.NoError(t, addToIsolation(isolation, name, isoFakeAddress(1)))
			require.NoError(t, isolation.Verify(), "the intact isolation must verify")

			conn := &nftables.Conn{}
			tc.damage(t, conn)
			require.NoError(t, conn.Flush())

			assert.Error(t, isolation.Verify(), "damage must be reported")
		})
	}
}

// makeIsolationTableDormant sends the message by hand, the library always clears table flags.
func makeIsolationTableDormant(t *testing.T) {
	t.Helper()
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_NETFILTER)
	require.NoError(t, err)
	t.Cleanup(func() { _ = unix.Close(fd) })

	message := func(msgType, flags uint16, family byte, resID uint16, attrs []byte) []byte {
		out := binary.NativeEndian.AppendUint32(nil, uint32(unix.SizeofNlMsghdr+4+len(attrs)))
		out = binary.NativeEndian.AppendUint16(out, msgType)
		out = binary.NativeEndian.AppendUint16(out, flags)
		out = binary.NativeEndian.AppendUint32(out, 0)
		out = binary.NativeEndian.AppendUint32(out, 0)
		out = append(out, family, 0)
		out = binary.BigEndian.AppendUint16(out, resID)
		return append(out, attrs...)
	}
	attr := func(attrType uint16, value []byte) []byte {
		out := binary.NativeEndian.AppendUint16(nil, uint16(unix.SizeofNlAttr+len(value)))
		out = binary.NativeEndian.AppendUint16(out, attrType)
		out = append(out, value...)
		for len(out)%unix.NLA_ALIGNTO != 0 {
			out = append(out, 0)
		}
		return out
	}

	attrs := attr(unix.NFTA_TABLE_NAME, append([]byte(IsolationTableName), 0))
	attrs = append(attrs, attr(unix.NFTA_TABLE_FLAGS, binary.BigEndian.AppendUint32(nil, unix.NFT_TABLE_F_DORMANT))...)

	batch := message(unix.NFNL_MSG_BATCH_BEGIN, unix.NLM_F_REQUEST, unix.AF_UNSPEC, unix.NFNL_SUBSYS_NFTABLES, nil)
	batch = append(batch, message(unix.NFNL_SUBSYS_NFTABLES<<8|unix.NFT_MSG_NEWTABLE, unix.NLM_F_REQUEST, unix.NFPROTO_INET, 0, attrs)...)
	batch = append(batch, message(unix.NFNL_MSG_BATCH_END, unix.NLM_F_REQUEST, unix.AF_UNSPEC, unix.NFNL_SUBSYS_NFTABLES, nil)...)
	require.NoError(t, unix.Sendto(fd, batch, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}))
}

// TestIsolationStaysClosedWithoutSessionScope is the bypass of F0 Q1. The manager and allower of
// the plain constructors open every chain they do not recognize, and they run in slot 0, so the
// isolation chains must not be among those. Verify runs once, after the engine came up: the
// accept must not appear through the monitor later either, whichever came first.
func TestIsolationStaysClosedWithoutSessionScope(t *testing.T) {
	openers := []struct {
		name string
		open func(t *testing.T, n *isoNetwork) func() error
	}{
		{
			name: "manager from Create",
			open: func(t *testing.T, n *isoNetwork) func() error {
				t.Helper()
				manager, err := Create(n.ifaceMock(), iface.DefaultMTU)
				require.NoError(t, err)
				return runIsoManager(t, n, manager).manager.reconcileExternalChains
			},
		},
		{
			name: "allower from NewInterfaceAllower",
			open: func(t *testing.T, n *isoNetwork) func() error {
				t.Helper()
				allower, err := NewInterfaceAllower(n.ifaceMock(), iface.DefaultMTU)
				require.NoError(t, err)
				require.NoError(t, allower.Apply())
				t.Cleanup(func() { assert.NoError(t, allower.Close()) })
				return allower.reconcileExternalChains
			},
		},
	}

	for _, opener := range openers {
		for _, isolationFirst := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s, isolation first %t", opener.name, isolationFirst), func(t *testing.T) {
				enableHostForwarding(t)
				a, b := newIsoNetwork(t, 1), newIsoNetwork(t, 2)
				isolation := NewIsolation()
				t.Cleanup(func() { assert.NoError(t, isolation.RemoveAll()) })
				add := func() {
					require.NoError(t, addToIsolation(isolation, isoIfaceName(a), a.addr))
					require.NoError(t, addToIsolation(isolation, isoIfaceName(b), b.addr))
				}

				var reconcile func() error
				if isolationFirst {
					add()
					reconcile = opener.open(t, a)
				} else {
					reconcile = opener.open(t, a)
					add()
				}

				// The tag in a table created last shows the monitor ran with the isolation visible.
				foreign := addHookedTable(t, "nbtest_foreign_late")
				require.Eventually(t, func() bool { return len(foreign.tags(t)) > 0 },
					5*time.Second, 50*time.Millisecond, "the monitor must open a table that appears later")
				require.NoError(t, reconcile())

				assertNoAcceptTags(t, IsolationTableName, "isolation table")
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
	t.Run("kernel refuses the batch", func(t *testing.T) {
		isolation := NewIsolation()
		t.Cleanup(func() { assert.NoError(t, isolation.RemoveAll()) })
		require.NoError(t, addToIsolation(isolation, "wt1", isoFakeAddress(1)))

		conn := &nftables.Conn{}
		conn.DelTable(isolationTable())
		require.NoError(t, conn.Flush())

		assert.Error(t, addToIsolation(isolation, "wt2", isoFakeAddress(2)), "the sets to change are gone")
		assert.Error(t, isolation.Verify(), "the isolation is still broken")
		assert.Empty(t, tableFamilies(t, IsolationTableName), "a failed Add must not leave anything behind")
	})

	t.Run("invalid input", func(t *testing.T) {
		isolation := NewIsolation()
		t.Cleanup(func() { assert.NoError(t, isolation.RemoveAll()) })

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
		assert.Empty(t, tableFamilies(t, IsolationTableName), "refused input must not install anything")
	})

	t.Run("overlapping IPv4 overlay", func(t *testing.T) {
		isolation := NewIsolation()
		t.Cleanup(func() { assert.NoError(t, isolation.RemoveAll()) })
		require.NoError(t, addToIsolation(isolation, "wt1", isoFakeAddress(1)))
		before := isoElementCount(t, isoSetIfaces)

		overlapping := wgaddr.Address{Network: netip.MustParsePrefix("100.64.0.0/16")}
		assert.ErrorIs(t, addToIsolation(isolation, "wt2", overlapping), ErrOverlayOverlap)
		assert.Equal(t, before, isoElementCount(t, isoSetIfaces), "the refused session must not be in the sets")
		assert.NoError(t, isolation.Verify())
	})
}

// TestIsolationIPv6IsSoft shows a session without IPv6, or one whose v6 cannot be used, keeps the
// isolation of v4 working.
func TestIsolationIPv6IsSoft(t *testing.T) {
	t.Run("no v6 at all", func(t *testing.T) {
		enableHostForwarding(t)
		isolation := NewIsolation()
		t.Cleanup(func() { assert.NoError(t, isolation.RemoveAll()) })

		a, b := newIsoNetworkV4Only(t, 1), newIsoNetworkV4Only(t, 2)
		require.NoError(t, addToIsolation(isolation, isoIfaceName(a), a.addr))
		require.NoError(t, addToIsolation(isolation, isoIfaceName(b), b.addr))
		assert.NoError(t, isolation.Verify())
		assert.Zero(t, isoElementCount(t, isoSetOverlays6), "no session has a v6 overlay")
		assert.Zero(t, isoElementCount(t, isoSetOwn6), "no session has a v6 overlay")

		assert.False(t, reaches(t, a.ns, a.peer4, b.ns, b.peer4), "v4 must stay isolated")
		assert.False(t, reaches(t, a.ns, a.peer4, nil, b.addr.IP), "v4 must stay isolated")
		assert.True(t, reaches(t, a.ns, a.peer4, nil, a.addr.IP), "the own overlay must stay reachable")
	})

	t.Run("v6 address without a prefix", func(t *testing.T) {
		isolation := NewIsolation()
		t.Cleanup(func() { assert.NoError(t, isolation.RemoveAll()) })
		addr := isoFakeAddress(1)
		addr.IPv6 = netip.MustParseAddr("fd00::1")
		require.NoError(t, addToIsolation(isolation, "wt1", addr))
		assert.Zero(t, isoElementCount(t, isoSetOwn6), "an unusable v6 overlay counts as none")
		assert.NoError(t, isolation.Verify())
	})

	t.Run("kernel refuses the v6 elements of a new session", func(t *testing.T) {
		isolation := NewIsolation()
		t.Cleanup(func() { assert.NoError(t, isolation.RemoveAll()) })
		require.NoError(t, addToIsolation(isolation, "wt1", isoFakeAddress(1)))

		withV6 := isoFakeAddress(2)
		withV6.IPv6, withV6.IPv6Net = netip.MustParseAddr("fd00:bb::1"), netip.MustParsePrefix("fd00:bb::/64")
		blocker := blockIsolationOwn6(t, "wt2", netip.MustParsePrefix("fd00:bb::/65"))

		disabled, err := addReportingIPv6(isolation, "wt2", withV6)
		require.NoError(t, err, "a v6 failure must not stop the session")
		assert.True(t, disabled, "the session must be told to leave v6 alone")
		assert.Equal(t, 2, isoElementCount(t, isoSetOwn), "v4 of the session must be isolated")
		assert.Equal(t, 1, isoElementCount(t, isoSetOwn6), "only the foreign element may be in the v6 set")
		assert.False(t, isolation.members["wt2"].overlay6.IsValid(), "v6 must not be in the isolation")

		blocker()
		assert.NoError(t, isolation.Verify(), "kernel and members must agree once the host is repaired")
		disabled, err = addReportingIPv6(isolation, "wt2", withV6)
		require.NoError(t, err)
		assert.False(t, disabled, "the session gets its v6 once the kernel takes it")
		assert.Equal(t, 1, isoElementCount(t, isoSetOwn6))
		assert.NoError(t, isolation.Verify())
	})

	t.Run("kernel refuses the new v6 elements of a running session", func(t *testing.T) {
		isolation := NewIsolation()
		t.Cleanup(func() { assert.NoError(t, isolation.RemoveAll()) })
		first := isoFakeAddress(1)
		first.IPv6, first.IPv6Net = netip.MustParseAddr("fd00:aa::1"), netip.MustParsePrefix("fd00:aa::/64")
		require.NoError(t, addToIsolation(isolation, "wt1", first))

		next := isoFakeAddress(3)
		next.IPv6, next.IPv6Net = netip.MustParseAddr("fd00:bb::1"), netip.MustParsePrefix("fd00:bb::/64")
		blocker := blockIsolationOwn6(t, "wt1", netip.MustParsePrefix("fd00:bb::/65"))

		disabled, err := addReportingIPv6(isolation, "wt1", next)
		require.NoError(t, err, "a v6 failure must not stop the update")
		assert.True(t, disabled)
		assert.Equal(t, next.Network, isolation.members["wt1"].overlay, "v4 must move")
		assert.False(t, isolation.members["wt1"].overlay6.IsValid(), "the old v6 overlay must leave")

		blocker()
		assert.NoError(t, isolation.Verify(), "the old v6 overlay must not stay in the sets")
	})

	t.Run("overlapping v6 overlay is skipped", func(t *testing.T) {
		isolation := NewIsolation()
		t.Cleanup(func() { assert.NoError(t, isolation.RemoveAll()) })

		first, second := isoFakeAddress(1), isoFakeAddress(2)
		first.IPv6, first.IPv6Net = netip.MustParseAddr("fd00::1"), netip.MustParsePrefix("fd00::/64")
		second.IPv6, second.IPv6Net = netip.MustParseAddr("fd00::2"), netip.MustParsePrefix("fd00::/64")
		require.NoError(t, addToIsolation(isolation, "wt1", first))
		require.NoError(t, addToIsolation(isolation, "wt2", second), "a v6 overlap must not stop the session")

		assert.Equal(t, 1, isoElementCount(t, isoSetOwn6), "only the first session owns the v6 overlay")
		assert.Equal(t, 2, isoElementCount(t, isoSetOwn), "both sessions keep their v4 overlay")
		assert.NoError(t, isolation.Verify())
	})
}

// TestIsolationAddUpdatesKnownSession covers the overlay changing while the session runs. The old
// overlay must not stay in the sets, and Add with the same values must not touch anything.
func TestIsolationAddUpdatesKnownSession(t *testing.T) {
	isolation := NewIsolation()
	t.Cleanup(func() { assert.NoError(t, isolation.RemoveAll()) })

	require.NoError(t, addToIsolation(isolation, "wt1", isoFakeAddress(1)))
	require.NoError(t, addToIsolation(isolation, "wt2", isoFakeAddress(2)))
	require.NoError(t, addToIsolation(isolation, "wt1", isoFakeAddress(1)), "the same values must be accepted")

	require.NoError(t, addToIsolation(isolation, "wt1", isoFakeAddress(3)))
	assert.NoError(t, isolation.Verify(), "the sets must hold exactly the new overlay")
	assert.Equal(t, 2, isoElementCount(t, isoSetIfaces), "the interface must not be duplicated")
	assert.Equal(t, 2, isoElementCount(t, isoSetOwn), "the old overlay must leave")

	assert.ErrorIs(t, addToIsolation(isolation, "wt2", isoFakeAddress(3)), ErrOverlayOverlap)
	require.NoError(t, addToIsolation(isolation, "wt2", isoFakeAddress(1)), "the freed overlay must be usable")
	assert.NoError(t, isolation.Verify())
}

// TestIsolationCleansUpAfterCrash leaves the state of a dead daemon behind and shows both ways out
// of it: the next daemon's first session starts from a clean table, and without any session the
// table goes away (I7).
func TestIsolationCleansUpAfterCrash(t *testing.T) {
	crashed := NewIsolation()
	require.NoError(t, addToIsolation(crashed, "wt1", isoFakeAddress(1)))
	require.NoError(t, addToIsolation(crashed, "wt2", isoFakeAddress(2)))

	next := NewIsolation()
	assert.Error(t, next.Verify(), "a table no session stands behind must be reported")
	require.NoError(t, addToIsolation(next, "wt3", isoFakeAddress(3)))
	assert.NoError(t, next.Verify(), "the first session must replace what the crash left")
	assert.Equal(t, 1, isoElementCount(t, isoSetIfaces), "nothing of the dead sessions may stay")
	require.NoError(t, next.Remove("wt3"))
	assert.Empty(t, tableFamilies(t, IsolationTableName), "the last Remove must remove the table")

	crashedAgain := NewIsolation()
	require.NoError(t, addToIsolation(crashedAgain, "wt1", isoFakeAddress(1)))
	require.NoError(t, NewIsolation().RemoveAll())
	assert.Empty(t, tableFamilies(t, IsolationTableName), "RemoveAll must remove what a crash left")
	assert.NoError(t, NewIsolation().RemoveAll(), "RemoveAll must work without a table")
	assert.NoError(t, NewIsolation().Remove("wt1"), "Remove of an unknown session must do nothing")
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

			isolation := NewIsolation()
			t.Cleanup(func() { assert.NoError(t, isolation.RemoveAll()) })
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

// blockIsolationOwn6 puts an element of a session in front of the v6 set that overlaps the overlay
// a test is going to add, which the kernel refuses. The result removes it.
func blockIsolationOwn6(t *testing.T, name IfaceName, overlay netip.Prefix) (remove func()) {
	t.Helper()
	sets := newIsolationSets()
	var own isolationElements
	for _, batch := range sets.overlayElements(name, overlay) {
		if batch.set.Name == isoSetOwn6 {
			own = batch
		}
	}
	require.NotNil(t, own.set)
	conn := &nftables.Conn{}
	require.NoError(t, conn.SetAddElements(own.set, own.elements))
	require.NoError(t, conn.Flush())
	return func() {
		conn := &nftables.Conn{}
		require.NoError(t, conn.SetDeleteElements(own.set, own.elements))
		require.NoError(t, conn.Flush())
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
		isolation := NewIsolation()
		t.Cleanup(func() { assert.NoError(t, isolation.RemoveAll()) })
		for name, addr := range map[IfaceName]wgaddr.Address{
			"wt1": first,
			"wt2": withV6(2, "fd00:bb::1/64"),
			"wt3": isoFakeAddress(3),
		} {
			disabled, err := addReportingIPv6(isolation, name, addr)
			require.NoError(t, err)
			assert.False(t, disabled, "%s must keep what it asked for", name)
		}
		assert.Equal(t, 2, isoElementCount(t, isoSetOwn6), "both sessions with v6 own it")
	})

	t.Run("repeated, and after the other session left", func(t *testing.T) {
		isolation := NewIsolation()
		t.Cleanup(func() { assert.NoError(t, isolation.RemoveAll()) })
		require.NoError(t, addToIsolation(isolation, "wt1", first))

		for range 2 {
			disabled, err := addReportingIPv6(isolation, "wt2", overlapping)
			require.NoError(t, err)
			assert.True(t, disabled, "the overlap still exists")
		}
		assert.Equal(t, 1, isoElementCount(t, isoSetOwn6), "only the first session owns the v6 overlay")

		require.NoError(t, isolation.Remove("wt1"))
		disabled, err := addReportingIPv6(isolation, "wt2", overlapping)
		require.NoError(t, err)
		assert.False(t, disabled, "the overlap is gone")
		assert.Equal(t, 1, isoElementCount(t, isoSetOwn6), "the session now owns its v6 overlay")
		assert.NoError(t, isolation.Verify())
	})

	t.Run("a running session moving onto another overlay", func(t *testing.T) {
		isolation := NewIsolation()
		t.Cleanup(func() { assert.NoError(t, isolation.RemoveAll()) })
		require.NoError(t, addToIsolation(isolation, "wt1", first))
		require.NoError(t, addToIsolation(isolation, "wt2", withV6(2, "fd00:bb::1/64")))
		require.Equal(t, 2, isoElementCount(t, isoSetOwn6), "both sessions own their v6 overlay")

		disabled, err := addReportingIPv6(isolation, "wt2", overlapping)
		require.NoError(t, err)
		assert.True(t, disabled, "the running session must learn it lost its v6")
		assert.Equal(t, 1, isoElementCount(t, isoSetOwn6), "its old v6 overlay must leave")
		assert.NoError(t, isolation.Verify())
	})

	t.Run("a refused session gets no result", func(t *testing.T) {
		isolation := NewIsolation()
		t.Cleanup(func() { assert.NoError(t, isolation.RemoveAll()) })
		require.NoError(t, addToIsolation(isolation, "wt1", first))

		disabled, err := addReportingIPv6(isolation, "wt2", withV6(1, "fd00:aa::2/64"))
		assert.ErrorIs(t, err, ErrOverlayOverlap)
		assert.False(t, disabled, "a session that must not run has nothing to honor")
	})
}
