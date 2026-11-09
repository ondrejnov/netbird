package cmd

import (
	"context"
	"os"
	"os/user"
	"path/filepath"
	"testing"
	"time"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/ipcauth"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
)

var cliAddr string

func TestUpDaemon(t *testing.T) {

	tempDir := t.TempDir()
	origDefaultProfileDir := profilemanager.DefaultConfigPathDir
	origActiveProfileStatePath := profilemanager.ActiveProfileStatePath
	origDefaultConfigPath := profilemanager.DefaultConfigPath
	profilemanager.DefaultConfigPathDir = tempDir
	profilemanager.DefaultConfigPath = tempDir + "/default.json"
	profilemanager.ActiveProfileStatePath = tempDir + "/active_profile.json"
	// Without this the loader reads the real /var/lib/netbird/default.json.
	profilemanager.DefaultConfigPath = filepath.Join(tempDir, "default.json")
	profilemanager.ConfigDirOverride = tempDir

	currUser, err := user.Current()
	if err != nil {
		t.Fatalf("failed to get current user: %v", err)
		return
	}

	identity, err := ipcauth.CurrentProcessIdentity()
	if err != nil {
		t.Fatalf("failed to read this process's identity: %v", err)
		return
	}

	sm := profilemanager.ServiceManager{}
	created, err := sm.AddProfile("test1", &identity)
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
		profilemanager.DefaultConfigPath = origDefaultConfigPath
		profilemanager.ConfigDirOverride = ""
	})

	// A foreground login reads the Management URL from the config of the profile the CLI runs on, the
	// default one, and from nowhere else. The daemon reads it from the config of its active profile.
	// Without them the setup key of this test goes to the default Management, which calls it invalid.
	mgmtURL := "http://" + startTestingServices(t)
	activeConfigPath, err := created.FilePath()
	if err != nil {
		t.Fatalf("failed to get the path of the profile: %v", err)
	}
	for _, path := range []string{profilemanager.DefaultConfigPath, activeConfigPath} {
		if _, err := profilemanager.UpdateOrCreateConfig(profilemanager.ConfigInput{ConfigPath: path, ManagementURL: mgmtURL}); err != nil {
			t.Fatalf("failed to write the profile config: %v", err)
		}
	}

	confPath := tempDir + "/config.json"

	_, cliLis := startClientDaemon(t, context.Background(), mgmtURL, confPath)

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
	// The flags of rootCmd stay set between executions, and these two exclude each other.
	setupKey = ""
	rootCmd.PersistentFlags().Lookup("setup-key").Changed = false
	t.Cleanup(func() {
		setupKeyPath = ""
		rootCmd.PersistentFlags().Lookup("setup-key-file").Changed = false
	})
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

// daemonStatus asks the daemon, since the status lives on its session.
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
