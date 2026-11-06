package dns

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/internal/peer"
	nbdns "github.com/netbirdio/netbird/dns"
)

// mtuIface is the interface of a session with the given MTU.
type mtuIface struct {
	mocWGIface
	mtu uint16
}

func (i *mtuIface) MTU() uint16 { return i.mtu }

// mtuService listens somewhere other than the upstream of the test, which would read as a loop.
type mtuService struct {
	mockService
}

func (s *mtuService) RuntimeIP() netip.Addr { return netip.MustParseAddr("192.0.2.53") }

// startEDNSRecorder is an upstream that answers and remembers the EDNS0 size of the last query.
func startEDNSRecorder(t *testing.T) (netip.AddrPort, *atomic.Uint32) {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)

	var size atomic.Uint32
	server := &dns.Server{PacketConn: conn, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		if opt := r.IsEdns0(); opt != nil {
			size.Store(uint32(opt.UDPSize()))
		}
		reply := new(dns.Msg).SetReply(r)
		_ = w.WriteMsg(reply)
	})}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })

	addr, err := netip.ParseAddrPort(conn.LocalAddr().String())
	require.NoError(t, err)
	return addr, &size
}

// resolverOfSession builds the resolver the way a session does, from the interface of the session.
func resolverOfSession(t *testing.T, mtu uint16, upstream netip.AddrPort) *handlerWrapper {
	t.Helper()
	server := newDefaultServer(context.Background(), &mtuIface{mtu: mtu}, &mtuService{}, peer.NewRecorder("test"), nil, true)
	t.Cleanup(server.ctxCancel)

	group := nsGroupsByDomain{
		domain: "example.com",
		groups: []*nbdns.NameServerGroup{{
			NameServers: []nbdns.NameServer{{IP: upstream.Addr(), NSType: nbdns.UDPNameServerType, Port: int(upstream.Port())}},
			Domains:     []string{"example.com"},
		}},
	}
	handler, err := server.buildMergedDomainHandler(group, PriorityUpstream)
	require.NoError(t, err)
	return handler
}

func queryThroughResolver(t *testing.T, handler *handlerWrapper) {
	t.Helper()
	writer := &mtuTestWriter{}
	handler.handler.ServeDNS(writer, new(dns.Msg).SetQuestion("host.example.com.", dns.TypeA))
	assert.NotNil(t, writer.msg(), "the resolver should answer")
}

// mtuTestWriter keeps what the resolver answers.
type mtuTestWriter struct {
	mu    sync.Mutex
	reply *dns.Msg
}

func (w *mtuTestWriter) msg() *dns.Msg {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.reply
}

func (w *mtuTestWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}
}
func (w *mtuTestWriter) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5353}
}
func (w *mtuTestWriter) Write([]byte) (int, error) { return 0, nil }
func (w *mtuTestWriter) Close() error              { return nil }
func (w *mtuTestWriter) TsigStatus() error         { return nil }
func (w *mtuTestWriter) TsigTimersOnly(bool)       {}
func (w *mtuTestWriter) Hijack()                   {}
func (w *mtuTestWriter) WriteMsg(m *dns.Msg) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.reply = m
	return nil
}

// Two sessions with different MTUs on one daemon: what each advertises to its upstream follows its
// own config, whichever of them started last. A size above the tunnel MTU loses the answer of a
// large response, a size below it costs a needless retry over TCP.
func TestResolverAdvertisesTheMTUOfItsSession(t *testing.T) {
	upstreamA, sizeA := startEDNSRecorder(t)
	upstreamB, sizeB := startEDNSRecorder(t)

	resolverA := resolverOfSession(t, 1280, upstreamA)
	resolverB := resolverOfSession(t, 1400, upstreamB)

	queryThroughResolver(t, resolverA)
	queryThroughResolver(t, resolverB)
	assert.EqualValues(t, 1280-ipUDPHeaderSize, sizeA.Load(), "the first session advertises its own MTU")
	assert.EqualValues(t, 1400-ipUDPHeaderSize, sizeB.Load(), "the second session advertises its own MTU")

	// Side by side, as sessions run: -race hears any state the two still share.
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(2)
		go func() { defer wg.Done(); queryThroughResolver(t, resolverA) }()
		go func() { defer wg.Done(); queryThroughResolver(t, resolverB) }()
	}
	wg.Wait()
	assert.EqualValues(t, 1280-ipUDPHeaderSize, sizeA.Load(), "the first session keeps its own MTU next to the other")
	assert.EqualValues(t, 1400-ipUDPHeaderSize, sizeB.Load(), "the second session keeps its own MTU next to the other")
}

// The EDNS0 cap of a query that already carries a larger buffer follows the MTU it is given.
func TestExchangeCapsToTheGivenMTU(t *testing.T) {
	upstream, size := startEDNSRecorder(t)
	for _, mtu := range []uint16{1280, 1400} {
		query := new(dns.Msg).SetQuestion("host.example.com.", dns.TypeA)
		query.SetEdns0(4096, false)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, _, err := ExchangeWithFallback(ctx, &dns.Client{Timeout: time.Second}, query, upstream.String(), mtu)
		cancel()
		require.NoError(t, err)
		assert.EqualValues(t, mtu-ipUDPHeaderSize, size.Load(), "the cap should follow the MTU of the caller")
	}
}

// A resolver built without an MTU, on an interface that reports none, has the default of the tunnel.
func TestResolverWithoutAnMTUUsesTheDefault(t *testing.T) {
	upstream, size := startEDNSRecorder(t)
	queryThroughResolver(t, resolverOfSession(t, 0, upstream))
	assert.EqualValues(t, iface.DefaultMTU-ipUDPHeaderSize, size.Load())
}
