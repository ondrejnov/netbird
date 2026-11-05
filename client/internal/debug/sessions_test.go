package debug

import (
	"archive/zip"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
)

type fakeExporter struct{ content string }

func (f fakeExporter) Export(w io.Writer) error {
	_, err := io.WriteString(w, f.content)
	return err
}

func readBundle(t *testing.T, path string) map[string]string {
	t.Helper()
	reader, err := zip.OpenReader(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = reader.Close() })

	entries := make(map[string]string, len(reader.File))
	for _, file := range reader.File {
		opened, err := file.Open()
		require.NoError(t, err)
		raw, err := io.ReadAll(opened)
		require.NoError(t, err)
		require.NoError(t, opened.Close())
		entries[file.Name] = string(raw)
	}
	return entries
}

func recorderOf(t *testing.T, management, overlayIP string) *peer.Status {
	t.Helper()
	recorder := peer.NewRecorder(management)
	recorder.UpdateManagementAddress(management)
	recorder.UpdateLocalPeerState(peer.LocalPeerState{IP: overlayIP})
	return recorder
}

func configOf(t *testing.T, management string) *profilemanager.Config {
	t.Helper()
	parsed, err := url.Parse(management)
	require.NoError(t, err)
	return &profilemanager.Config{ManagementURL: parsed}
}

func stateFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

// The files of each session stay apart and name their own profile, and nothing of the second
// session reaches the top of the bundle, which old readers take for the whole of it.
func TestBundle_KeepsEverySessionApart(t *testing.T) {
	dir := t.TempDir()

	generator := NewBundleGenerator(GeneratorDependencies{
		TempDir:        dir,
		ProfileName:    "work-profile",
		InternalConfig: configOf(t, "https://mgmt.work.example:443"),
		StatusRecorder: recorderOf(t, "https://mgmt.work.example:443", "100.71.0.1/16"),
		StatePath:      stateFile(t, dir, "work.state.json", `{"owner":"work"}`),
		ClientMetrics:  fakeExporter{"metric work"},
		OtherSessions: []SessionBundle{{
			Dir:            "home-id",
			ProfileName:    "home-profile",
			InternalConfig: configOf(t, "https://mgmt.home.example:443"),
			StatusRecorder: recorderOf(t, "https://mgmt.home.example:443", "100.72.0.1/16"),
			StatePath:      stateFile(t, dir, "home.state.json", `{"owner":"home"}`),
			ClientMetrics:  fakeExporter{"metric home"},
		}},
	}, BundleConfig{})

	path, err := generator.Generate()
	require.NoError(t, err)
	entries := readBundle(t, path)

	assert.Contains(t, entries["status.txt"], "Profile: work-profile", "the top of the bundle is about its own session")
	assert.Contains(t, entries["status.txt"], "100.71.0.1", "status.txt has the address of its session")
	assert.NotContains(t, entries["status.txt"], "100.72.0.1", "status.txt has no address of another session")
	assert.Contains(t, entries["config.txt"], "mgmt.work.example")
	assert.Equal(t, `{"owner":"work"}`, entries["state.json"])
	assert.Equal(t, "metric work", entries["metrics.txt"])

	const home = "sessions/home-id/"
	assert.Contains(t, entries[home+"status.txt"], "Profile: home-profile", "status.txt names the profile of its session")
	assert.Contains(t, entries[home+"status.txt"], "100.72.0.1", "status.txt has the address of its session")
	assert.NotContains(t, entries[home+"status.txt"], "100.71.0.1", "status.txt has no address of another session")
	assert.Contains(t, entries[home+"config.txt"], "mgmt.home.example")
	assert.Equal(t, `{"owner":"home"}`, entries[home+"state.json"])
	assert.Equal(t, "metric home", entries[home+"metrics.txt"], "the metrics are those of its session")

	for name := range entries {
		if !strings.HasPrefix(name, "sessions/") {
			continue
		}
		assert.True(t, strings.HasPrefix(name, home), "%s should belong to a session", name)
	}
	assert.NotContains(t, entries, home+"goroutine.prof", "what describes the daemon appears once")
	assert.Contains(t, entries["README.txt"], "sessions/", "the reader should learn what the directory is")
}

// Without sessions, the bundle is what it has always been.
func TestBundle_WithoutSessionsHasNoTraceOfThem(t *testing.T) {
	dir := t.TempDir()
	generator := NewBundleGenerator(GeneratorDependencies{
		TempDir:        dir,
		InternalConfig: configOf(t, "https://mgmt.work.example:443"),
		StatusRecorder: recorderOf(t, "https://mgmt.work.example:443", "100.71.0.1/16"),
		StatePath:      stateFile(t, dir, "work.state.json", `{"owner":"work"}`),
	}, BundleConfig{})

	path, err := generator.Generate()
	require.NoError(t, err)
	entries := readBundle(t, path)

	for name := range entries {
		assert.False(t, strings.HasPrefix(name, "sessions/"), "%s should not exist without sessions", name)
	}
	assert.NotContains(t, entries["README.txt"], "sessions/")
	assert.Equal(t, `{"owner":"work"}`, entries["state.json"])
}

// What describes the whole host also describes sessions the requester may not read.
func TestBundle_OmitHostWideLeavesOutLogsAndSystemInfo(t *testing.T) {
	dir := t.TempDir()
	logFile := stateFile(t, dir, "client.log", "a line about another session\n")

	build := func(omit bool) map[string]string {
		generator := NewBundleGenerator(GeneratorDependencies{
			TempDir:        dir,
			LogPath:        logFile,
			StatusRecorder: recorderOf(t, "https://mgmt.work.example:443", "100.71.0.1/16"),
			StatePath:      stateFile(t, dir, "work.state.json", `{}`),
			OmitHostWide:   omit,
		}, BundleConfig{IncludeSystemInfo: true})
		path, err := generator.Generate()
		require.NoError(t, err)
		return readBundle(t, path)
	}

	// The control: the same bundle with the files, so their absence below means something.
	full := build(false)
	require.Contains(t, full, "client.log", "the control should carry the log of the daemon")
	require.Contains(t, full, "routes.txt", "the control should carry the system information")

	omitted := build(true)
	assert.NotContains(t, omitted, "client.log", "the log of the daemon names other sessions")
	assert.NotContains(t, omitted, "routes.txt", "the routes of the host name other sessions")
	assert.NotContains(t, omitted, "interfaces.txt", "the interfaces of the host name other sessions")
	assert.Contains(t, omitted, "status.txt", "what is about the session stays")
	assert.Contains(t, omitted["README.txt"], "left out", "the reader should learn why the logs are missing")
}
