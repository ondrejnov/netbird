package version

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

type forkRelease struct {
	Builds []struct {
		ID     string   `yaml:"id"`
		Goos   []string `yaml:"goos"`
		Tags   []string `yaml:"tags"`
		Binary string   `yaml:"binary"`
	} `yaml:"builds"`
	Nfpms []struct {
		PackageName string   `yaml:"package_name"`
		Conflicts   []string `yaml:"conflicts"`
		Replaces    []string `yaml:"replaces"`
		Formats     []string `yaml:"formats"`
	} `yaml:"nfpms"`
	Release struct {
		Disable bool `yaml:"disable"`
	} `yaml:"release"`
	Uploads    []any `yaml:"uploads"`
	Publishers []any `yaml:"publishers"`
	Brews      []any `yaml:"brews"`
	Blobs      []any `yaml:"blobs"`
	Dockers    []any `yaml:"dockers_v2"`
}

// The fork ships from its own goreleaser file, so the upstream release stays as
// it is and the fork packages cannot be installed next to the upstream ones.
// goreleaser itself publishes nothing; the workflow creates the release.
func TestForkReleaseConfig(t *testing.T) {
	raw, err := os.ReadFile("../.goreleaser_multiprofile.yaml")
	require.NoError(t, err, "the fork needs its own goreleaser configuration")

	var cfg forkRelease
	require.NoError(t, yaml.Unmarshal(raw, &cfg))

	require.NotEmpty(t, cfg.Builds, "the fork configuration must define a build")
	targets := map[string]bool{}
	for _, b := range cfg.Builds {
		for _, goos := range b.Goos {
			targets[goos] = true
		}
		assert.Contains(t, b.Tags, forkTag, "build %s must carry the fork tag", b.ID)
	}
	assert.Equal(t, map[string]bool{"linux": true, "windows": true}, targets, "the fork ships Linux and Windows only")

	upstreamOf := map[string]string{
		"netbird-multiprofile":    "netbird",
		"netbird-ui-multiprofile": "netbird-ui",
	}
	require.NotEmpty(t, cfg.Nfpms, "the fork must define its packages")
	for _, pkg := range cfg.Nfpms {
		upstream, ok := upstreamOf[pkg.PackageName]
		require.True(t, ok, "package %s must not reuse an upstream name", pkg.PackageName)
		assert.Contains(t, pkg.Conflicts, upstream, "%s must conflict with %s", pkg.PackageName, upstream)
		assert.Contains(t, pkg.Replaces, upstream, "%s must replace %s", pkg.PackageName, upstream)
	}

	assert.True(t, cfg.Release.Disable, "goreleaser must not publish, the workflow does")
	assert.Empty(t, cfg.Uploads, "the fork configuration must not upload packages")
	assert.Empty(t, cfg.Publishers, "the fork configuration must not publish packages")
	assert.Empty(t, cfg.Brews, "the fork configuration must not publish a Homebrew formula")
	assert.Empty(t, cfg.Blobs, "the fork configuration must not upload to a bucket")
	assert.Empty(t, cfg.Dockers, "the fork configuration must not push images")

	assert.False(t, strings.Contains(string(raw), "pkgs.netbird.io"), "the fork configuration must not refer to the official repository")
}

// The release is created only in the fork, and only after the installer test.
func TestForkReleaseWorkflowPublishesToTheFork(t *testing.T) {
	raw, err := os.ReadFile("../.github/workflows/release-multiprofile.yml")
	require.NoError(t, err)

	var wf struct {
		Jobs map[string]struct {
			If    string   `yaml:"if"`
			Needs []string `yaml:"needs"`
			Steps []struct {
				Run string `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	require.NoError(t, yaml.Unmarshal(raw, &wf))

	publish, ok := wf.Jobs["publish"]
	require.True(t, ok, "the workflow must have a publish job")
	assert.Contains(t, publish.If, "github.repository == 'ondrejnov/netbird'", "publishing must be limited to the fork")
	assert.Contains(t, publish.Needs, "test_windows_installer", "publishing must wait for the installer test")

	var creates []string
	for _, job := range wf.Jobs {
		for _, step := range job.Steps {
			if strings.Contains(step.Run, "gh release") {
				creates = append(creates, step.Run)
			}
		}
	}
	require.Len(t, creates, 1, "exactly one step may touch GitHub releases")
	assert.Contains(t, creates[0], "--repo ondrejnov/netbird", "the release must go to the fork, never to upstream")
}

// The upstream release must not build the fork: the tag belongs to the fork file only.
func TestUpstreamReleaseConfigHasNoForkTag(t *testing.T) {
	raw, err := os.ReadFile("../.goreleaser.yaml")
	require.NoError(t, err)
	assert.NotContains(t, string(raw), forkTag, "the upstream release must not build with the fork tag")
}

const forkTag = "multiprofile"
