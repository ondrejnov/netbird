//go:build privileged && linux

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal/ipcauth"
	"github.com/netbirdio/netbird/client/proto"
)

const (
	accessClientSocketEnv = "NB_TEST_ACCESS_SOCKET"
	accessReportPrefix    = "ACCESS_REPORT "

	// Two unprivileged accounts of the harness image, which the kernel and the account database
	// know for real.
	accessOwnUser   = "nobody"
	accessOtherUser = "daemon"
	accessOwnProf   = "second-profile"
	accessOtherProf = "third-profile"
)

// accessReport is what a client process running as its own account got from the daemon.
type accessReport struct {
	Codes    map[string]string `json:"codes"`
	Sessions []string          `json:"sessions"`
}

func accessCode(err error) string {
	return gstatus.Code(err).String()
}

// TestAccessClient runs as the client of TestSessionAccessOverTheRealSocket, in a process of its own
// and under the account the kernel will report to the daemon.
func TestAccessClient(t *testing.T) {
	socket := os.Getenv(accessClientSocketEnv)
	if socket == "" {
		t.Skip("runs only as the client of TestSessionAccessOverTheRealSocket")
	}

	conn, err := grpc.NewClient("unix://"+socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	client := proto.NewDaemonServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	own := &proto.SessionSelector{Profile: accessOwnProf, Username: accessOwnUser}
	other := &proto.SessionSelector{Profile: accessOtherProf, Username: accessOtherUser}
	report := accessReport{Codes: map[string]string{}}

	_, err = client.Status(ctx, &proto.StatusRequest{Session: own})
	report.Codes["status of the own session"] = accessCode(err)
	_, err = client.Status(ctx, &proto.StatusRequest{Session: other})
	report.Codes["status of the other session"] = accessCode(err)
	_, err = client.Down(ctx, &proto.DownRequest{Session: other})
	report.Codes["down of the other session"] = accessCode(err)

	// A client cannot talk itself into being someone else with what it sends.
	forged := metadata.NewOutgoingContext(ctx, metadata.Pairs("x-netbird-fwd", "1", "x-netbird-fwd-uid", "0", "x-netbird-fwd-gid", "0"))
	_, err = client.Down(forged, &proto.DownRequest{Session: other})
	report.Codes["down of the other session with forged metadata"] = accessCode(err)

	profile, username := accessOtherProf, accessOtherUser
	_, err = client.Up(ctx, &proto.UpRequest{ProfileName: &profile, Username: &username, Async: true})
	report.Codes["up with the username of the other"] = accessCode(err)

	status, err := client.Status(ctx, &proto.StatusRequest{GetFullPeerStatus: true})
	report.Codes["status"] = accessCode(err)
	for _, entry := range status.GetSessions() {
		report.Sessions = append(report.Sessions, entry.GetProfileId())
	}

	_, err = client.Down(ctx, &proto.DownRequest{All: true})
	report.Codes["down of all"] = accessCode(err)

	raw, err := json.Marshal(report)
	require.NoError(t, err)
	fmt.Println(accessReportPrefix + string(raw))
}

// runAccessClient copies the test binary where any account can run it and runs TestAccessClient
// under account, the current one when it is nil.
func runAccessClient(t *testing.T, socket string, account *user.User) accessReport {
	t.Helper()

	dir, err := os.MkdirTemp("", "access-client")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	require.NoError(t, os.Chmod(dir, 0o755))
	binary := filepath.Join(dir, "client.test")
	copyExecutable(t, os.Args[0], binary)

	cmd := exec.Command(binary, "-test.run=^TestAccessClient$", "-test.timeout=2m", "-test.v")
	cmd.Dir = dir
	cmd.Env = []string{accessClientSocketEnv + "=" + socket}
	if account != nil {
		uid, err := strconv.ParseUint(account.Uid, 10, 32)
		require.NoError(t, err)
		gid, err := strconv.ParseUint(account.Gid, 10, 32)
		require.NoError(t, err)
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
	}
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))

	for _, line := range strings.Split(string(out), "\n") {
		if raw, found := strings.CutPrefix(line, accessReportPrefix); found {
			var report accessReport
			require.NoError(t, json.Unmarshal([]byte(raw), &report))
			return report
		}
	}
	require.FailNow(t, "the client did not report", string(out))
	return accessReport{}
}

func copyExecutable(t *testing.T, from, to string) {
	t.Helper()
	source, err := os.Open(from)
	require.NoError(t, err)
	defer func() { _ = source.Close() }()
	target, err := os.OpenFile(to, os.O_CREATE|os.O_WRONLY, 0o755)
	require.NoError(t, err)
	_, err = io.Copy(target, source)
	require.NoError(t, err)
	require.NoError(t, target.Close())
}

// The whole way a request takes: the kernel says who connected, and the account database says whose
// session that is. Nothing in the request can change either.
func TestSessionAccessOverTheRealSocket(t *testing.T) {
	ownAccount, err := user.Lookup(accessOwnUser)
	require.NoError(t, err, "the harness image has the account")
	_, err = user.Lookup(accessOtherUser)
	require.NoError(t, err, "the harness image has the account")

	f := newGateFixture(t)
	// The account database of the host, not a stand-in.
	f.s.lookupUIDFn = nil

	dir, err := os.MkdirTemp("", "access-socket")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	require.NoError(t, os.Chmod(dir, 0o755))
	socket := filepath.Join(dir, "daemon.sock")
	listener, err := net.Listen("unix", socket)
	require.NoError(t, err)
	require.NoError(t, os.Chmod(socket, 0o666))

	server := grpc.NewServer(grpc.Creds(ipcauth.NewTransportCredentials()))
	proto.RegisterDaemonServiceServer(server, f.s)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)

	own := sessionKeyOf(accessOwnProf, accessOwnUser)
	other := sessionKeyOf(accessOtherProf, accessOtherUser)
	require.NoError(t, f.up(own))
	require.NoError(t, f.up(other))
	require.NoError(t, f.up(f.first))

	report := runAccessClient(t, socket, ownAccount)

	assert.Equal(t, map[string]string{
		"status of the own session":                      "OK",
		"status of the other session":                    "PermissionDenied",
		"down of the other session":                      "PermissionDenied",
		"down of the other session with forged metadata": "PermissionDenied",
		"up with the username of the other":              "PermissionDenied",
		"status":                                         "OK",
		"down of all":                                    "OK",
	}, report.Codes)
	assert.Equal(t, []string{accessOwnProf}, report.Sessions, "the client may read only its own session")

	assert.False(t, f.session(own).isClientRunning(), "down of all takes down the session of the caller")
	assert.True(t, f.session(other).isClientRunning(), "the session of the other account must stay up")
	assert.True(t, f.session(f.first).isClientRunning(), "the session of root must stay up")

	// The same requests from root reach everything.
	require.NoError(t, f.up(own))
	report = runAccessClient(t, socket, nil)
	assert.Equal(t, "OK", report.Codes["status of the other session"])
	assert.ElementsMatch(t, []string{accessOwnProf, accessOtherProf, string(f.first.Profile)}, report.Sessions)
	assert.False(t, f.session(other).isClientRunning(), "root takes down any session")
	assert.False(t, f.session(f.first).isClientRunning(), "root takes down any session")
}
