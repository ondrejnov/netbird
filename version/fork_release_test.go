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
		GitHub  struct {
			Owner string `yaml:"owner"`
			Name  string `yaml:"name"`
		} `yaml:"github"`
	} `yaml:"release"`
	Publishers []any `yaml:"publishers"`
	Brews      []any `yaml:"brews"`
	Blobs      []any `yaml:"blobs"`
	Dockers    []any `yaml:"dockers_v2"`
}

// The fork ships from its own goreleaser file, so the upstream release stays as
// it is, the fork package cannot be installed next to the upstream one and a
// release lands only in the fork's GitHub releases.
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

	require.Len(t, cfg.Nfpms, 1, "the fork ships one package definition")
	pkg := cfg.Nfpms[0]
	assert.Equal(t, "netbird-multiprofile", pkg.PackageName, "the fork package must not reuse the upstream name")
	assert.Contains(t, pkg.Conflicts, "netbird", "the fork package must conflict with the upstream package")
	assert.Contains(t, pkg.Replaces, "netbird", "the fork package must replace the upstream package")

	assert.False(t, cfg.Release.Disable, "a fork tag publishes a GitHub release")
	assert.Equal(t, "ondrejnov", cfg.Release.GitHub.Owner, "the release must go to the fork, never to upstream")
	assert.Equal(t, "netbird", cfg.Release.GitHub.Name, "the release must go to the fork repository")
	assert.Empty(t, cfg.Publishers, "the fork configuration must not publish packages")
	assert.Empty(t, cfg.Brews, "the fork configuration must not publish a Homebrew formula")
	assert.Empty(t, cfg.Blobs, "the fork configuration must not upload to a bucket")
	assert.Empty(t, cfg.Dockers, "the fork configuration must not push images")

	assert.False(t, strings.Contains(string(raw), "pkgs.netbird.io"), "the fork configuration must not refer to the official repository")
}

// The upstream release must not build the fork: the tag belongs to the fork file only.
func TestUpstreamReleaseConfigHasNoForkTag(t *testing.T) {
	raw, err := os.ReadFile("../.goreleaser.yaml")
	require.NoError(t, err)
	assert.NotContains(t, string(raw), forkTag, "the upstream release must not build with the fork tag")
}

const forkTag = "multiprofile"
