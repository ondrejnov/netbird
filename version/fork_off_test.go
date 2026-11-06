//go:build !multiprofile

package version

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The upstream build must behave exactly as before: no marker on the version
// and the periodic lookup of the latest release stays on.
func TestUpstreamBuildIsUnchanged(t *testing.T) {
	assert.False(t, ForkBuild(), "an untagged build must not report itself as the fork")

	old := version
	t.Cleanup(func() { version = old })
	version = "0.70.1"
	assert.Equal(t, "0.70.1", NetbirdVersion(), "the upstream version must carry no marker")
}

func TestUpstreamBuildStillFetchesLatestVersion(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("9.9.9"))
	}))
	t.Cleanup(srv.Close)

	old := versionURL
	t.Cleanup(func() { versionURL = old })
	versionURL = srv.URL

	u := NewUpdate("test")
	require.True(t, u.fetchVersion(), "the upstream build must read the latest version")
	assert.Equal(t, int32(1), hits.Load(), "the upstream build must query the release endpoint")
}
