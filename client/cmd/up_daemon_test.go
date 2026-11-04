package cmd

import (
	"context"
	"os"
	"os/user"
	"testing"
	"time"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
)

var cliAddr string

func TestUpDaemon(t *testing.T) {

	tempDir := t.TempDir()
	origDefaultProfileDir := profilemanager.DefaultConfigPathDir
	origActiveProfileStatePath := profilemanager.ActiveProfileStatePath
	profilemanager.DefaultConfigPathDir = tempDir
	profilemanager.ActiveProfileStatePath = tempDir + "/active_profile.json"
	profilemanager.ConfigDirOverride = tempDir

	currUser, err := user.Current()
	if err != nil {
		t.Fatalf("failed to get current user: %v", err)
		return
	}

	sm := profilemanager.ServiceManager{}
	created, err := sm.AddProfile("test1", currUser.Username)
	if err != nil {
		t.Fatalf("failed to add profile: %v", err)
		return
	}

	err = sm.SetActiveProfileState(&profilemanager.ActiveProfileState{
		ID:       created.ID,
		Username: currUser.Username,
	})
	if err != nil {
		t.Fatalf("failed to set active profile state: %v", err)
		return
	}

	t.Cleanup(func() {
		profilemanager.DefaultConfigPathDir = origDefaultProfileDir
		profilemanager.ActiveProfileStatePath = origActiveProfileStatePath
		profilemanager.ConfigDirOverride = ""
	})

	mgmAddr := startTestingServices(t)

	confPath := tempDir + "/config.json"

	_, cliLis := startClientDaemon(t, context.Background(), "http://"+mgmAddr, confPath)

	cliAddr = cliLis.Addr().String()

	daemonAddr = "tcp://" + cliAddr
	rootCmd.SetArgs([]string{
		"login",
		"--daemon-addr", "tcp://" + cliAddr,
		"--setup-key", "A2C8E62B-38F5-4553-B31E-DD66C696CEBB",
		"--log-file", "",
	})
	if err := rootCmd.Execute(); err != nil {
		t.Errorf("expected no error while running up command, got %v", err)
		return
	}
	time.Sleep(time.Second * 3)
	if status := daemonStatus(t, cliAddr); status == internal.StatusLoginFailed {
		t.Errorf("wrong status after login: %s", status)
		return
	}

	// Test the setup-key-file flag.
	tempFile, err := os.CreateTemp("", "setup-key")
	if err != nil {
		t.Errorf("could not create temp file, got error %v", err)
		return
	}
	defer os.Remove(tempFile.Name())
	if _, err := tempFile.Write([]byte("A2C8E62B-38F5-4553-B31E-DD66C696CEBB")); err != nil {
		t.Errorf("could not write to temp file, got error %v", err)
		return
	}
	if err := tempFile.Close(); err != nil {
		t.Errorf("unable to close file, got error %v", err)
	}
	rootCmd.SetArgs([]string{
		"login",
		"--daemon-addr", "tcp://" + cliAddr,
		"--setup-key-file", tempFile.Name(),
		"--log-file", "",
	})
	if err := rootCmd.Execute(); err != nil {
		t.Errorf("expected no error while running up command, got %v", err)
		return
	}
	time.Sleep(time.Second * 3)
	if status := daemonStatus(t, cliAddr); status == internal.StatusLoginFailed {
		t.Errorf("wrong status after login: %s", status)
		return
	}

	rootCmd.SetArgs([]string{
		"up",
		"--daemon-addr", "tcp://" + cliAddr,
		"--log-file", "",
	})
	if err := rootCmd.Execute(); err != nil {
		t.Errorf("expected no error while running up command, got %v", err)
		return
	}
	time.Sleep(time.Second * 3)
	if status := daemonStatus(t, cliAddr); status == internal.StatusLoginFailed {
		t.Errorf("wrong status after connect: %s", status)
		return
	}

	rootCmd.SetArgs([]string{
		"status",
		"--daemon-addr", "tcp://" + cliAddr,
	})
	if err := rootCmd.Execute(); err != nil {
		t.Errorf("expected no error while running up command, got %v", err)
		return
	}
	time.Sleep(time.Second * 3)

	rootCmd.SetErr(nil)
	rootCmd.SetArgs([]string{"down", "--daemon-addr", "tcp://" + cliAddr})
	if err := rootCmd.Execute(); err != nil {
		t.Errorf("expected no error while running up command, got %v", err)
		return
	}
	// we can't check status here, because context already canceled
}

// daemonStatus asks the daemon, since the status lives on its session. The daemon of this
// test talks to its default Management, so it stays at NeedsLogin whatever the CLI does.
func daemonStatus(t *testing.T, addr string) internal.StatusType {
	t.Helper()

	conn, err := DialClientGRPCServer(context.Background(), "tcp://"+addr)
	if err != nil {
		t.Fatalf("dial the daemon: %v", err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			t.Logf("close the daemon connection: %v", err)
		}
	}()

	resp, err := proto.NewDaemonServiceClient(conn).Status(context.Background(), &proto.StatusRequest{})
	if err != nil {
		t.Fatalf("read the daemon status: %v", err)
	}
	return internal.StatusType(resp.GetStatus())
}
