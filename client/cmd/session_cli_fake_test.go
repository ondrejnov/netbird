package cmd

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	gproto "google.golang.org/protobuf/proto"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
)

// fakeDaemon is what a test sets up of the daemon the commands talk to: the features it reports,
// its profiles, their status and the failures of its RPCs. The daemon itself, fakeServer, runs in
// a process of its own and records every request, so that a test sees exactly which calls a
// command makes and in which order. The tests that need the real behaviour of the daemon run
// against a real one.
//
// The process is the point: the CLI sets up the logging library on every command, and doing that
// in the process of a running gRPC server is a data race under -race, the one TestLogin has.
type fakeDaemon struct {
	// features is what GetFeatures answers. Nil makes the RPC Unimplemented, as in a daemon that
	// predates it.
	features *proto.GetFeaturesResponse
	// featuresErr makes GetFeatures fail with this error.
	featuresErr error

	profiles []*proto.Profile
	// focused is the ID of the profile the calls without a selector act on.
	focused string
	// status is the status by profile ID, Idle for a profile that is not in it.
	status map[string]string
	// sessions is what Status lists with the gate.
	sessions []*proto.SessionStatus
	// fullStatus makes Status answer with testFullStatus when the full status is asked.
	fullStatus bool
	// failures makes the named RPC fail.
	failures map[string]error

	dir  string
	addr string
}

// fakeConfig is fakeDaemon as the process of the daemon reads it.
type fakeConfig struct {
	Features    json.RawMessage        `json:"features,omitempty"`
	FeaturesErr *fakeFailure           `json:"featuresErr,omitempty"`
	Profiles    []fakeProfile          `json:"profiles"`
	Focused     string                 `json:"focused"`
	FocusedUser string                 `json:"focusedUser"`
	Status      map[string]string      `json:"status"`
	Sessions    []json.RawMessage      `json:"sessions"`
	FullStatus  bool                   `json:"fullStatus"`
	Failures    map[string]fakeFailure `json:"failures"`
}

type fakeProfile struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type fakeFailure struct {
	Code    uint32 `json:"code"`
	Message string `json:"message"`
}

func failureOf(err error) fakeFailure {
	st := gstatus.Convert(err)
	return fakeFailure{Code: uint32(st.Code()), Message: st.Message()}
}

func (d *fakeDaemon) config(t *testing.T) []byte {
	t.Helper()

	// The focus is the one of the user the CLI runs for, which under sudo is not the user of the
	// process: the daemon answers with the user of the session, not with its own.
	cfg := fakeConfig{Focused: d.focused, FocusedUser: currentUsername(t), Status: d.status, FullStatus: d.fullStatus, Failures: map[string]fakeFailure{}}
	if d.features != nil {
		raw, err := protojson.Marshal(d.features)
		require.NoError(t, err)
		cfg.Features = raw
	}
	if d.featuresErr != nil {
		failure := failureOf(d.featuresErr)
		cfg.FeaturesErr = &failure
	}
	for _, p := range d.profiles {
		cfg.Profiles = append(cfg.Profiles, fakeProfile{ID: p.Id, Name: p.Name})
	}
	for _, s := range d.sessions {
		raw, err := protojson.Marshal(s)
		require.NoError(t, err)
		cfg.Sessions = append(cfg.Sessions, raw)
	}
	for name, err := range d.failures {
		cfg.Failures[name] = failureOf(err)
	}

	raw, err := json.Marshal(cfg)
	require.NoError(t, err)
	return raw
}

const fakeDaemonDirEnv = "NB_TEST_FAKE_DAEMON_DIR"

// start runs the daemon with what the test has set up so far and returns its address. A second
// call returns the address of the daemon that runs.
func (d *fakeDaemon) start(t *testing.T) string {
	t.Helper()
	if d.addr != "" {
		return d.addr
	}

	d.dir = t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(d.dir, "config.json"), d.config(t), 0o600))

	logFile, err := os.Create(filepath.Join(d.dir, "process.log"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = logFile.Close() })

	proc := exec.Command(os.Args[0], "-test.run=^TestFakeDaemonProcess$", "-test.timeout=10m")
	proc.Env = append(os.Environ(), fakeDaemonDirEnv+"="+d.dir)
	proc.Stdout = logFile
	proc.Stderr = logFile
	require.NoError(t, proc.Start())

	exited := make(chan struct{})
	go func() {
		defer close(exited)
		_ = proc.Wait()
	}()
	t.Cleanup(func() {
		_ = proc.Process.Kill()
		<-exited
	})

	deadline := time.After(time.Minute)
	for {
		if raw, err := os.ReadFile(filepath.Join(d.dir, "address")); err == nil && len(raw) > 0 {
			d.addr = "tcp://" + string(raw)
			return d.addr
		}
		select {
		case <-exited:
			raw, _ := os.ReadFile(logFile.Name())
			t.Fatalf("the fake daemon ended early\n%s", raw)
		case <-deadline:
			t.Fatal("the fake daemon did not start")
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// fakeCall is a request the daemon got: the name of the RPC and the request as protojson.
type fakeCall struct {
	name string
	raw  []byte
}

func (d *fakeDaemon) log(t *testing.T) []fakeCall {
	t.Helper()
	if d.dir == "" {
		return nil
	}

	f, err := os.Open(filepath.Join(d.dir, "calls.log"))
	if os.IsNotExist(err) {
		return nil
	}
	require.NoError(t, err)
	defer f.Close()

	var calls []fakeCall
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		name, raw, _ := strings.Cut(scanner.Text(), " ")
		calls = append(calls, fakeCall{name: name, raw: []byte(raw)})
	}
	require.NoError(t, scanner.Err())
	return calls
}

func (d *fakeDaemon) callList(t *testing.T) []string {
	t.Helper()
	var names []string
	for _, c := range d.log(t) {
		names = append(names, c.name)
	}
	return names
}

func (d *fakeDaemon) called(t *testing.T, name string) bool {
	t.Helper()
	for _, c := range d.callList(t) {
		if c == name {
			return true
		}
	}
	return false
}

// requestsOf are the requests of the RPC name that the daemon got.
func requestsOf[T any, P interface {
	*T
	gproto.Message
}](t *testing.T, d *fakeDaemon, name string) []P {
	t.Helper()
	var out []P
	for _, c := range d.log(t) {
		if c.name != name {
			continue
		}
		var msg T
		require.NoError(t, protojson.Unmarshal(c.raw, P(&msg)), "request of %s", name)
		out = append(out, P(&msg))
	}
	return out
}

// requestOf is the single request of the RPC name that the daemon got.
func requestOf[T any, P interface {
	*T
	gproto.Message
}](t *testing.T, d *fakeDaemon, name string) P {
	t.Helper()
	got := requestsOf[T, P](t, d, name)
	require.Lenf(t, got, 1, "%s should have been called once, calls: %v", name, d.callList(t))
	return got[0]
}

// TestFakeDaemonProcess is the daemon of fakeDaemon.
func TestFakeDaemonProcess(t *testing.T) {
	dir := os.Getenv(fakeDaemonDirEnv)
	if dir == "" {
		t.Skip("runs only as the daemon of the CLI tests")
	}

	raw, err := os.ReadFile(filepath.Join(dir, "config.json"))
	require.NoError(t, err)
	srv := &fakeServer{callLog: filepath.Join(dir, "calls.log")}
	require.NoError(t, json.Unmarshal(raw, &srv.cfg))
	srv.focused = srv.cfg.Focused
	srv.focusedUser = srv.cfg.FocusedUser

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	grpcServer := grpc.NewServer()
	proto.RegisterDaemonServiceServer(grpcServer, srv)
	// The address appears only when the daemon can be dialled.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "address"), []byte(lis.Addr().String()), 0o600))
	require.NoError(t, grpcServer.Serve(lis))
}

// fakeServer is the daemon of the CLI tests, see fakeDaemon.
type fakeServer struct {
	proto.UnimplementedDaemonServiceServer

	mu          sync.Mutex
	callLog     string
	cfg         fakeConfig
	focused     string
	focusedUser string
}

func (d *fakeServer) record(name string, req gproto.Message) error {
	raw, err := protojson.Marshal(req)
	if err != nil {
		return err
	}
	// protojson may put a space or a line break in its output, a call is one line.
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil {
		return err
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	f, err := os.OpenFile(d.callLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := fmt.Fprintf(f, "%s %s\n", name, compact.String()); err != nil {
		return err
	}
	if failure, ok := d.cfg.Failures[name]; ok {
		return gstatus.Error(codes.Code(failure.Code), failure.Message)
	}
	return nil
}

func (d *fakeServer) profileByHandle(handle string) *fakeProfile {
	for i := range d.cfg.Profiles {
		if p := &d.cfg.Profiles[i]; p.ID == handle || p.Name == handle {
			return p
		}
	}
	return nil
}

func (d *fakeServer) gateOn() bool {
	if len(d.cfg.Features) == 0 {
		return false
	}
	var features proto.GetFeaturesResponse
	return protojson.Unmarshal(d.cfg.Features, &features) == nil && features.GetConcurrentProfilesEnabled()
}

func (d *fakeServer) GetFeatures(_ context.Context, req *proto.GetFeaturesRequest) (*proto.GetFeaturesResponse, error) {
	if err := d.record("GetFeatures", req); err != nil {
		return nil, err
	}
	if f := d.cfg.FeaturesErr; f != nil {
		return nil, gstatus.Error(codes.Code(f.Code), f.Message)
	}
	if len(d.cfg.Features) == 0 {
		return nil, gstatus.Error(codes.Unimplemented, "method GetFeatures not implemented")
	}
	var features proto.GetFeaturesResponse
	if err := protojson.Unmarshal(d.cfg.Features, &features); err != nil {
		return nil, err
	}
	return &features, nil
}

func (d *fakeServer) ListProfiles(_ context.Context, req *proto.ListProfilesRequest) (*proto.ListProfilesResponse, error) {
	if err := d.record("ListProfiles", req); err != nil {
		return nil, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	out := &proto.ListProfilesResponse{}
	for _, p := range d.cfg.Profiles {
		out.Profiles = append(out.Profiles, &proto.Profile{Id: p.ID, Name: p.Name, IsActive: p.ID == d.focused})
	}
	return out, nil
}

func (d *fakeServer) SwitchProfile(_ context.Context, req *proto.SwitchProfileRequest) (*proto.SwitchProfileResponse, error) {
	if err := d.record("SwitchProfile", req); err != nil {
		return nil, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	p := d.profileByHandle(req.GetProfileName())
	if p == nil {
		return nil, gstatus.Error(codes.NotFound, "profile not found")
	}
	d.focused = p.ID
	if req.GetUsername() != "" {
		d.focusedUser = req.GetUsername()
	}
	return &proto.SwitchProfileResponse{Id: p.ID}, nil
}

func (d *fakeServer) GetActiveProfile(_ context.Context, req *proto.GetActiveProfileRequest) (*proto.GetActiveProfileResponse, error) {
	if err := d.record("GetActiveProfile", req); err != nil {
		return nil, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	p := d.profileByHandle(d.focused)
	if p == nil {
		return nil, gstatus.Error(codes.NotFound, "no active profile")
	}
	return &proto.GetActiveProfileResponse{Id: p.ID, ProfileName: p.Name, Username: d.focusedUser}, nil
}

func (d *fakeServer) Status(_ context.Context, req *proto.StatusRequest) (*proto.StatusResponse, error) {
	if err := d.record("Status", req); err != nil {
		return nil, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	id := d.focused
	if sel := req.GetSession(); sel != nil {
		id = sel.GetProfile()
	}
	status := d.cfg.Status[id]
	if status == "" {
		status = "Idle"
	}
	resp := &proto.StatusResponse{Status: status, DaemonVersion: "0.0.0-test"}
	if req.GetFullPeerStatus && d.cfg.FullStatus {
		resp.FullStatus = testFullStatus()
	}
	if d.gateOn() {
		for _, raw := range d.cfg.Sessions {
			var s proto.SessionStatus
			if err := protojson.Unmarshal(raw, &s); err != nil {
				return nil, err
			}
			resp.Sessions = append(resp.Sessions, &s)
		}
	}
	return resp, nil
}

func (d *fakeServer) SetConfig(_ context.Context, req *proto.SetConfigRequest) (*proto.SetConfigResponse, error) {
	if err := d.record("SetConfig", req); err != nil {
		return nil, err
	}
	return &proto.SetConfigResponse{}, nil
}

func (d *fakeServer) Login(_ context.Context, req *proto.LoginRequest) (*proto.LoginResponse, error) {
	if err := d.record("Login", req); err != nil {
		return nil, err
	}
	return &proto.LoginResponse{}, nil
}

func (d *fakeServer) Up(_ context.Context, req *proto.UpRequest) (*proto.UpResponse, error) {
	if err := d.record("Up", req); err != nil {
		return nil, err
	}
	return &proto.UpResponse{}, nil
}

func (d *fakeServer) Down(_ context.Context, req *proto.DownRequest) (*proto.DownResponse, error) {
	if err := d.record("Down", req); err != nil {
		return nil, err
	}
	return &proto.DownResponse{}, nil
}

func (d *fakeServer) RemoveProfile(_ context.Context, req *proto.RemoveProfileRequest) (*proto.RemoveProfileResponse, error) {
	if err := d.record("RemoveProfile", req); err != nil {
		return nil, err
	}
	return &proto.RemoveProfileResponse{Id: req.GetProfileName()}, nil
}

func (d *fakeServer) Logout(_ context.Context, req *proto.LogoutRequest) (*proto.LogoutResponse, error) {
	if err := d.record("Logout", req); err != nil {
		return nil, err
	}
	return &proto.LogoutResponse{}, nil
}

func (d *fakeServer) ListNetworks(_ context.Context, req *proto.ListNetworksRequest) (*proto.ListNetworksResponse, error) {
	if err := d.record("ListNetworks", req); err != nil {
		return nil, err
	}
	return &proto.ListNetworksResponse{Routes: []*proto.Network{{ID: "route1", Range: "10.0.0.0/24"}}}, nil
}

func (d *fakeServer) SelectNetworks(_ context.Context, req *proto.SelectNetworksRequest) (*proto.SelectNetworksResponse, error) {
	if err := d.record("SelectNetworks", req); err != nil {
		return nil, err
	}
	return &proto.SelectNetworksResponse{}, nil
}

func (d *fakeServer) DeselectNetworks(_ context.Context, req *proto.SelectNetworksRequest) (*proto.SelectNetworksResponse, error) {
	if err := d.record("DeselectNetworks", req); err != nil {
		return nil, err
	}
	return &proto.SelectNetworksResponse{}, nil
}

func (d *fakeServer) DebugBundle(_ context.Context, req *proto.DebugBundleRequest) (*proto.DebugBundleResponse, error) {
	if err := d.record("DebugBundle", req); err != nil {
		return nil, err
	}
	return &proto.DebugBundleResponse{Path: "/tmp/bundle.zip"}, nil
}

func (d *fakeServer) GetConfig(_ context.Context, req *proto.GetConfigRequest) (*proto.GetConfigResponse, error) {
	if err := d.record("GetConfig", req); err != nil {
		return nil, err
	}
	return &proto.GetConfigResponse{}, nil
}

func (d *fakeServer) SetSyncResponsePersistence(_ context.Context, req *proto.SetSyncResponsePersistenceRequest) (*proto.SetSyncResponsePersistenceResponse, error) {
	if err := d.record("SetSyncResponsePersistence", req); err != nil {
		return nil, err
	}
	return &proto.SetSyncResponsePersistenceResponse{}, nil
}

func (d *fakeServer) ExposeService(req *proto.ExposeServiceRequest, _ proto.DaemonService_ExposeServiceServer) error {
	if err := d.record("ExposeService", req); err != nil {
		return err
	}
	return gstatus.Error(codes.Unavailable, "fake daemon does not expose")
}

// isolateProfiles points the profile files of the command at a directory of the test.
func isolateProfiles(t *testing.T) {
	t.Helper()

	dir := t.TempDir()
	origDir, origState, origDefault := profilemanager.DefaultConfigPathDir, profilemanager.ActiveProfileStatePath, profilemanager.DefaultConfigPath
	profilemanager.DefaultConfigPathDir = dir
	profilemanager.ActiveProfileStatePath = dir + "/active_profile.json"
	profilemanager.DefaultConfigPath = dir + "/default.json"
	profilemanager.ConfigDirOverride = dir
	t.Cleanup(func() {
		profilemanager.DefaultConfigPathDir = origDir
		profilemanager.ActiveProfileStatePath = origState
		profilemanager.DefaultConfigPath = origDefault
		profilemanager.ConfigDirOverride = ""
	})
}

// cliResult is what a command wrote and returned.
type cliResult struct {
	out string
	err error
}

// runCLI runs the command line against the daemon d and returns what it printed. The daemon
// starts with the first command.
func runCLI(t *testing.T, d *fakeDaemon, args ...string) cliResult {
	t.Helper()

	return runCLIAt(t, d.start(t), args...)
}

// runCLIAt runs the command line against the daemon at addr.
func runCLIAt(t *testing.T, addr string, args ...string) cliResult {
	t.Helper()

	resetFlags(rootCmd)
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	t.Cleanup(func() {
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		rootCmd.SetArgs(nil)
		resetFlags(rootCmd)
	})

	full := append(append([]string{}, args...), "--daemon-addr", addr, "--log-file", "")
	rootCmd.SetArgs(full)
	err := rootCmd.Execute()
	return cliResult{out: buf.String(), err: err}
}

// The two profiles of the tests, with the display names of the acceptance scenario.
var (
	profileWork = &proto.Profile{Id: "a1b2c3d4", Name: "prace"}
	profileHome = &proto.Profile{Id: "e5f6a7b8", Name: "doma"}
)

func gateOn() *proto.GetFeaturesResponse {
	return &proto.GetFeaturesResponse{ConcurrentProfilesEnabled: true, MaxSessions: 4}
}

func currentUsername(t *testing.T) string {
	t.Helper()
	u, err := profilemanager.InvokingUser()
	require.NoError(t, err)
	return u.Username
}

func requireNoCall(t *testing.T, d *fakeDaemon, names ...string) {
	t.Helper()
	for _, name := range names {
		require.Falsef(t, d.called(t, name), "%s must not be called, calls: %s", name, strings.Join(d.callList(t), ", "))
	}
}

// testFullStatus is the full status the fake daemon answers for the session whose status is asked.
func testFullStatus() *proto.FullStatus {
	return &proto.FullStatus{
		ManagementState: &proto.ManagementState{URL: "https://mgmt.example.test:443", Connected: true},
		SignalState:     &proto.SignalState{URL: "https://signal.example.test:443", Connected: true},
		LocalPeerState: &proto.LocalPeerState{
			IP:              "100.71.0.5/16",
			PubKey:          "cHVibGljLWtleS1mb3ItdGhlLXRlc3Q=",
			Fqdn:            "laptop.netbird.selfhosted",
			KernelInterface: true,
			WgPort:          51820,
		},
	}
}
