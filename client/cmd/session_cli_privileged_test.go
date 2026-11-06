//go:build privileged && linux

package cmd

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/client/iface/netstack"
	"github.com/netbirdio/netbird/client/internal/ipcauth"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	clientProto "github.com/netbirdio/netbird/client/proto"
	client "github.com/netbirdio/netbird/client/server"
	"github.com/netbirdio/netbird/management/internals/server/config"
	"github.com/netbirdio/netbird/util"
)

const cliSetupKey = "A2C8E62B-38F5-4553-B31E-DD66C696CEBB"

// startTwoNetworks runs a Signal and a Management for each of two networks with their own overlay,
// and returns the addresses of the Managements. They are servers of the daemon process, see
// TestCLIGateDaemon.
func startTwoNetworks(t *testing.T) (work, home string) {
	t.Helper()

	cfg := &config.Config{}
	_, err := util.ReadJson("../testdata/management.json", cfg)
	require.NoError(t, err)
	_, signalLis := startSignal(t)
	cfg.Signal.URI = signalLis.Addr().String()

	raw, err := os.ReadFile("../testdata/store.sql")
	require.NoError(t, err)
	const overlay = `{"IP":"100.64.0.0","Mask":"//8AAA=="}`
	require.Contains(t, string(raw), overlay, "the store has the overlay this test replaces")
	homeStore := filepath.Join(t.TempDir(), "store.sql")
	require.NoError(t, os.WriteFile(homeStore, []byte(strings.ReplaceAll(string(raw), overlay, `{"IP":"100.72.0.0","Mask":"//8AAA=="}`)), 0o600))

	_, workLis := startManagement(t, cfg, "../testdata/store.sql")
	_, homeLis := startManagement(t, cfg, homeStore)
	return workLis.Addr().String(), homeLis.Addr().String()
}

const cliDaemonDirEnv = "NB_TEST_CLI_DAEMON_DIR"

// TestCLIGateDaemon is the daemon the CLI tests talk to, together with the Managements of its two
// networks. It runs in a process of its own: the CLI sets up the logging of the process on every
// command, and doing that next to a running gRPC server is a data race of the logging library.
// The daemon serves a Unix socket with the credentials the service has, so that it knows who
// calls, and ends the sessions when it is told to stop.
func TestCLIGateDaemon(t *testing.T) {
	dir := os.Getenv(cliDaemonDirEnv)
	if dir == "" {
		t.Skip("runs only as the daemon of the CLI tests")
	}

	profilemanager.ConfigDirOverride = dir
	profilemanager.DefaultConfigPathDir = dir
	profilemanager.ActiveProfileStatePath = filepath.Join(dir, "active_profile.json")
	profilemanager.DefaultConfigPath = filepath.Join(dir, "default.json")

	workMgmt, homeMgmt := startTwoNetworks(t)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "work-management"), []byte(workMgmt), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "home-management"), []byte(homeMgmt), 0o600))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	daemon := client.New(ctx, "console", "", false, false, false, false, true)
	require.NoError(t, daemon.Start())

	lis, err := net.Listen("unix", filepath.Join(dir, "daemon.sock"))
	require.NoError(t, err)
	srv := grpc.NewServer(grpc.Creds(ipcauth.NewTransportCredentials()))
	clientProto.RegisterDaemonServiceServer(srv, daemon)
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "daemon-ready"), nil, 0o600))
	<-stop
	require.NoError(t, daemon.StopSessions(context.Background()))
}

// startGateDaemon runs a real daemon with the gate on in a process of its own and returns the
// address of its socket and the addresses of the Managements of its two networks. The daemon is
// stopped, and its sessions with it, when the test ends.
func startGateDaemon(t *testing.T) (addr, workMgmt, homeMgmt string) {
	t.Helper()

	t.Setenv("NB_DNS_STATE_FILE", "")
	t.Setenv("NB_WG_KERNEL_DISABLED", "true")
	t.Setenv(netstack.EnvUseNetstackMode, "false")
	isolateProfiles(t)

	dir, err := os.MkdirTemp("", "cli-daemon")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	require.NoError(t, os.Chmod(dir, 0o755))

	logFile, err := os.Create(filepath.Join(t.TempDir(), "daemon.log"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = logFile.Close() })

	daemon := exec.Command(os.Args[0], "-test.run=^TestCLIGateDaemon$", "-test.timeout=10m")
	daemon.Env = append(os.Environ(), cliDaemonDirEnv+"="+dir)
	daemon.Stdout = logFile
	daemon.Stderr = logFile
	require.NoError(t, daemon.Start())

	exited := make(chan struct{})
	go func() {
		defer close(exited)
		_ = daemon.Wait()
	}()
	t.Cleanup(func() {
		_ = daemon.Process.Signal(syscall.SIGTERM)
		select {
		case <-exited:
		case <-time.After(time.Minute):
			_ = daemon.Process.Kill()
			<-exited
		}
		if t.Failed() {
			raw, _ := os.ReadFile(logFile.Name())
			t.Logf("log of the daemon:\n%s", tail(raw, 20000))
		}
	})

	ready := filepath.Join(dir, "daemon-ready")
	deadline := time.After(2 * time.Minute)
	for {
		if _, err := os.Stat(ready); err == nil {
			work, err := os.ReadFile(filepath.Join(dir, "work-management"))
			require.NoError(t, err)
			home, err := os.ReadFile(filepath.Join(dir, "home-management"))
			require.NoError(t, err)
			return "unix://" + filepath.Join(dir, "daemon.sock"), string(work), string(home)
		}
		select {
		case <-exited:
			raw, _ := os.ReadFile(logFile.Name())
			t.Fatalf("the daemon ended early\n%s", tail(raw, 20000))
		case <-deadline:
			t.Fatal("the daemon did not start")
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func tail(raw []byte, n int) string {
	if len(raw) > n {
		raw = raw[len(raw)-n:]
	}
	return string(raw)
}

type statusJSON struct {
	DaemonStatus string `json:"daemonStatus"`
	ProfileName  string `json:"profileName"`
	Sessions     []struct {
		ProfileName   string `json:"profileName"`
		Status        string `json:"status"`
		InterfaceName string `json:"interfaceName"`
		OverlayIP     string `json:"overlayIp"`
		Focused       bool   `json:"focused"`
	} `json:"sessions"`
}

func cliStatus(t *testing.T, addr string, args ...string) statusJSON {
	t.Helper()
	res := runCLIAt(t, addr, append([]string{"status", "--json"}, args...)...)
	require.NoError(t, res.err, res.out)
	var got statusJSON
	require.NoError(t, json.Unmarshal([]byte(res.out), &got), res.out)
	return got
}

// The acceptance scenario of the spec, through the commands of the CLI on a real daemon with real
// engines: two sessions next to each other, each with an interface of its own, and the commands
// that end, select, remove and list act on the session they name.
func TestCLI_TwoSessionsOnARealDaemon(t *testing.T) {
	addr, workMgmt, homeMgmt := startGateDaemon(t)

	res := runCLIAt(t, addr, "up", "--profile", "prace", "--management-url", "http://"+workMgmt, "--setup-key", cliSetupKey)
	require.NoError(t, res.err, res.out)
	res = runCLIAt(t, addr, "up", "--profile", "doma", "--management-url", "http://"+homeMgmt, "--setup-key", cliSetupKey)
	require.NoError(t, res.err, res.out)

	// Both sessions are connected, each with an interface of its own.
	st := cliStatus(t, addr)
	byName := map[string]int{}
	for i, s := range st.Sessions {
		byName[s.ProfileName] = i
	}
	require.Contains(t, byName, "prace", "status lists the first session")
	require.Contains(t, byName, "doma", "status lists the second session")
	work, home := st.Sessions[byName["prace"]], st.Sessions[byName["doma"]]
	assert.Equal(t, "Connected", work.Status)
	assert.Equal(t, "Connected", home.Status)
	assert.NotEmpty(t, work.InterfaceName)
	assert.NotEmpty(t, home.InterfaceName)
	assert.NotEqual(t, work.InterfaceName, home.InterfaceName, "each session has its own interface")
	assert.True(t, strings.HasPrefix(work.OverlayIP, "100.64."), "work overlay: %s", work.OverlayIP)
	assert.True(t, strings.HasPrefix(home.OverlayIP, "100.72."), "home overlay: %s", home.OverlayIP)
	assert.True(t, home.Focused, "the profile of the last `up` is the focused one")
	assert.Equal(t, "doma", st.ProfileName)

	res = runCLIAt(t, addr, "status")
	require.NoError(t, res.err, res.out)
	assert.Contains(t, res.out, "Sessions:")
	assert.Contains(t, res.out, "prace")

	other := cliStatus(t, addr, "--profile", "prace")
	assert.Equal(t, "prace", other.ProfileName, "the summary is the one of the named session")

	// The list names the connection of each profile.
	res = runCLIAt(t, addr, "profile", "list")
	require.NoError(t, res.err, res.out)
	assert.Regexp(t, `prace\s+Connected`, res.out)
	assert.Regexp(t, `doma\s+✓\s+Connected`, res.out)

	// A selection moves the focus and leaves the connections as they are.
	res = runCLIAt(t, addr, "profile", "select", "prace")
	require.NoError(t, res.err, res.out)
	st = cliStatus(t, addr)
	assert.Equal(t, "prace", st.ProfileName)
	for _, s := range st.Sessions {
		if s.ProfileName == "prace" || s.ProfileName == "doma" {
			assert.Equal(t, "Connected", s.Status, "select must not touch the connection of %s", s.ProfileName)
		}
	}

	// A running session can be neither removed nor logged out.
	res = runCLIAt(t, addr, "profile", "remove", "doma")
	require.Error(t, res.err)
	assert.Contains(t, res.err.Error(), "netbird down --profile doma")
	res = runCLIAt(t, addr, "deregister", "--profile", "doma")
	require.Error(t, res.err)
	assert.Contains(t, res.err.Error(), "netbird down --profile doma")
	assert.Equal(t, "Connected", cliStatus(t, addr, "--profile", "doma").DaemonStatus, "a refused command leaves the session")

	res = runCLIAt(t, addr, "networks", "list", "--profile", "doma")
	require.NoError(t, res.err, res.out)

	// A plain down ends the focused session and says what keeps running.
	res = runCLIAt(t, addr, "down")
	require.NoError(t, res.err, res.out)
	assert.Contains(t, res.out, "Still running: doma")
	assert.NotContains(t, res.out, "default", "a session that waits for a login is not running")
	assert.Equal(t, "Idle", cliStatus(t, addr).DaemonStatus)
	assert.Equal(t, "Connected", cliStatus(t, addr, "--profile", "doma").DaemonStatus, "the other session runs on")

	// Bring the first back and take down the second by name.
	res = runCLIAt(t, addr, "up", "--profile", "prace")
	require.NoError(t, res.err, res.out)
	res = runCLIAt(t, addr, "down", "--profile", "doma")
	require.NoError(t, res.err, res.out)
	assert.Equal(t, "Idle", cliStatus(t, addr, "--profile", "doma").DaemonStatus)
	assert.Equal(t, "Connected", cliStatus(t, addr, "--profile", "prace").DaemonStatus, "the named session is the one that went down")

	// The removal of a profile that is down goes through.
	res = runCLIAt(t, addr, "profile", "remove", "doma")
	require.NoError(t, res.err, res.out)

	res = runCLIAt(t, addr, "down", "--all")
	require.NoError(t, res.err, res.out)
	assert.Equal(t, "Idle", cliStatus(t, addr).DaemonStatus)
}

// A refused `up --profile` gives the focus back on a real daemon: the second profile of the same
// network overlaps the first, and a plain down that follows ends the session that runs.
func TestCLI_RefusedUpGivesTheFocusBack(t *testing.T) {
	addr, workMgmt, _ := startGateDaemon(t)

	res := runCLIAt(t, addr, "up", "--profile", "prace", "--management-url", "http://"+workMgmt, "--setup-key", cliSetupKey)
	require.NoError(t, res.err, res.out)

	res = runCLIAt(t, addr, "up", "--profile", "treti", "--management-url", "http://"+workMgmt, "--setup-key", cliSetupKey)
	require.Error(t, res.err, res.out)
	require.Contains(t, res.err.Error(), "overlaps", "the up is refused for the overlay")

	st := cliStatus(t, addr)
	assert.Equal(t, "prace", st.ProfileName, "the focus is back on the session that had it")
	assert.Equal(t, "Connected", st.DaemonStatus)

	res = runCLIAt(t, addr, "down")
	require.NoError(t, res.err, res.out)
	assert.Equal(t, "Idle", cliStatus(t, addr, "--profile", "prace").DaemonStatus, "a plain down ends the session that had the focus")
}
