//go:build e2e

// Package concurrentprofiles runs the acceptance scenario of concurrent profiles on real
// containers: two Management servers, a peer in each network, and a daemon with the feature
// gate on, driven only through its CLI. See docs/specs/concurrent-profiles.md, section 1.
package concurrentprofiles

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/netbirdio/netbird/e2e/harness"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

// daemonSocket keeps every container of the suite off the default address of the agent.
const daemonSocket = "unix:///var/run/nb-e2e.sock"

// overlayNetwork is one self-hosted network: its Management and a peer in it.
type overlayNetwork struct {
	profile string
	overlay netip.Prefix
	// overlayV6 is the range Management gave the network, read once the network is up.
	overlayV6 netip.Prefix
	dnsDomain string
	// routed is a network behind the peer, so that the host of the daemon has a route of this
	// network to lose. routedHost is an address there that answers.
	routed     netip.Prefix
	routedHost netip.Addr
	server     *harness.Combined
	setupKey   string
	peer       *harness.Client
	peerFQDN   string
}

var (
	work = &overlayNetwork{
		profile:    "prace",
		overlay:    netip.MustParsePrefix("100.71.0.0/16"),
		dnsDomain:  "prace.internal",
		routed:     netip.MustParsePrefix("10.71.1.0/24"),
		routedHost: netip.MustParseAddr("10.71.1.1"),
	}
	home = &overlayNetwork{
		profile:    "doma",
		overlay:    netip.MustParsePrefix("100.72.0.0/16"),
		dnsDomain:  "doma.internal",
		routed:     netip.MustParsePrefix("10.72.1.0/24"),
		routedHost: netip.MustParseAddr("10.72.1.1"),
	}
)

func TestMain(m *testing.M) {
	os.Exit(run(m))
}

func run(m *testing.M) int {
	// Generous timeout to cover a cold build of the images on the first run.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	for _, network := range []*overlayNetwork{work, home} {
		cleanup, err := network.start(ctx)
		defer cleanup()
		if err != nil {
			fmt.Fprintf(os.Stderr, "e2e: network %s: %v\n", network.profile, err)
			return 1
		}
	}
	return m.Run()
}

// start brings up the Management of the network with its own domain, overlay and DNS domain,
// joins the peer and gives the network a route through it. The cleanup is safe at any stage.
func (n *overlayNetwork) start(ctx context.Context) (func(), error) {
	var cleanups []func()
	cleanup := func() {
		for i := len(cleanups) - 1; i >= 0; i-- {
			cleanups[i]()
		}
	}

	server, err := harness.StartCombined(ctx, harness.WithDomain("netbird-"+n.profile+".local"))
	if err != nil {
		return cleanup, fmt.Errorf("start management: %w", err)
	}
	cleanups = append(cleanups, func() { _ = server.Terminate(context.Background()) })
	n.server = server

	if _, err := server.Bootstrap(ctx); err != nil {
		return cleanup, fmt.Errorf("bootstrap admin PAT: %w", err)
	}
	if err := n.setOverlay(ctx, n.overlay); err != nil {
		return cleanup, err
	}

	key, err := server.API().SetupKeys.Create(ctx, api.PostApiSetupKeysJSONRequestBody{
		Name:       "e2e-" + n.profile,
		Type:       "reusable",
		ExpiresIn:  86400,
		AutoGroups: []string{},
	})
	if err != nil {
		return cleanup, fmt.Errorf("mint setup key: %w", err)
	}
	n.setupKey = key.Key

	peerName := "peer-" + n.profile
	peer, err := harness.StartClient(ctx, server, key.Key,
		harness.WithClientName(peerName),
		harness.WithClientEnv(map[string]string{"NB_DAEMON_ADDR": daemonSocket}))
	if err != nil {
		return cleanup, fmt.Errorf("start peer: %w", err)
	}
	cleanups = append(cleanups, func() { _ = peer.Terminate(context.Background()) })
	n.peer = peer
	n.peerFQDN = peerName + "." + n.dnsDomain

	if err := peer.WaitConnected(ctx, 90*time.Second); err != nil {
		return cleanup, fmt.Errorf("peer does not connect: %w\n%s", err, peer.Logs(ctx))
	}
	return cleanup, n.routeThroughPeer(ctx, peerName)
}

// setOverlay sets the network range of the account of this Management, the same call an
// administrator makes to get out of an overlap.
func (n *overlayNetwork) setOverlay(ctx context.Context, overlay netip.Prefix) error {
	accounts, err := n.server.API().Accounts.List(ctx)
	if err != nil {
		return fmt.Errorf("list accounts: %w", err)
	}
	if len(accounts) != 1 {
		return fmt.Errorf("expected one account, got %d", len(accounts))
	}

	settings := accounts[0].Settings
	networkRange := overlay.String()
	settings.NetworkRange = &networkRange
	settings.DnsDomain = &n.dnsDomain
	if _, err := n.server.API().Accounts.Update(ctx, accounts[0].Id, api.PutApiAccountsAccountIdJSONRequestBody{Settings: settings}); err != nil {
		return fmt.Errorf("set network range %s: %w", overlay, err)
	}
	return n.readOverlayV6(ctx)
}

// readOverlayV6 keeps the range the account has now, so that the addresses of this network can
// be told apart from the ones of the other network.
func (n *overlayNetwork) readOverlayV6(ctx context.Context) error {
	accounts, err := n.server.API().Accounts.List(ctx)
	if err != nil {
		return fmt.Errorf("list accounts: %w", err)
	}
	if len(accounts) != 1 || accounts[0].Settings.NetworkRangeV6 == nil {
		return fmt.Errorf("expected one account with an IPv6 range, got %+v", accounts)
	}
	overlayV6, err := netip.ParsePrefix(*accounts[0].Settings.NetworkRangeV6)
	if err != nil {
		return fmt.Errorf("parse IPv6 range: %w", err)
	}
	n.overlayV6 = overlayV6
	return nil
}

// routeThroughPeer makes the peer the routing peer of the routed network, with an address there
// that answers a ping.
func (n *overlayNetwork) routeThroughPeer(ctx context.Context, peerName string) error {
	code, out, err := n.peer.Exec(ctx, "ip", "addr", "add", netip.PrefixFrom(n.routedHost, n.routed.Bits()).String(), "dev", "lo")
	if err != nil || code != 0 {
		return fmt.Errorf("add the routed address on the peer (exit %d): %v: %s", code, err, out)
	}

	peers, err := n.server.API().Peers.List(ctx)
	if err != nil {
		return fmt.Errorf("list peers: %w", err)
	}
	var peerID string
	for _, p := range peers {
		if p.Hostname == peerName {
			peerID = p.Id
		}
	}
	if peerID == "" {
		return fmt.Errorf("peer %s is not registered", peerName)
	}

	all, err := n.server.API().Groups.GetByName(ctx, "All")
	if err != nil {
		return fmt.Errorf("find the group of all peers: %w", err)
	}
	routed := n.routed.String()
	if _, err := n.server.API().Routes.Create(ctx, api.PostApiRoutesJSONRequestBody{
		Description: "e2e " + n.profile,
		Enabled:     true,
		Groups:      []string{all.Id},
		Masquerade:  true,
		Metric:      100,
		Network:     &routed,
		NetworkId:   "e2e-" + n.profile,
		Peer:        &peerID,
	}); err != nil {
		return fmt.Errorf("create route: %w", err)
	}
	return nil
}
