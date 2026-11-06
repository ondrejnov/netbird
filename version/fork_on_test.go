//go:build multiprofile

package version

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestForkBuildCarriesMarker(t *testing.T) {
	assert.True(t, ForkBuild(), "a tagged build must report itself as the fork")

	old := version
	t.Cleanup(func() { version = old })

	version = "0.70.1"
	assert.Equal(t, "0.70.1+multiprofile", NetbirdVersion(), "a release version must carry the marker")

	version = "0.70.1+multiprofile"
	assert.Equal(t, "0.70.1+multiprofile", NetbirdVersion(), "a version stamped with the marker must not get it twice")

	version = DevelopmentVersion
	assert.Equal(t, "development+multiprofile", NetbirdVersion(), "a development build must carry the marker too")
	assert.True(t, IsDevelopmentVersion(NetbirdVersion()), "the marker must not hide a development build")
}

// Peers and Management compare the version a client reports; the marker must
// not change how a fork client ranks against a minimum version.
func TestForkVersionStaysComparable(t *testing.T) {
	old := version
	t.Cleanup(func() { version = old })
	version = "0.70.1"

	ok, err := MeetsMinVersion("0.70.0", NetbirdVersion())
	require.NoError(t, err)
	assert.True(t, ok, "a marked version must meet a lower minimum")

	ok, err = MeetsMinVersion("0.71.0", NetbirdVersion())
	require.NoError(t, err)
	assert.False(t, ok, "a marked version must not meet a higher minimum")

	assert.True(t, VersionRegexp.MatchString(NetbirdVersion()), "the marked version must stay a valid version")
}

// The fork is not published to pkgs.netbird.io, so asking it for the latest
// release would offer the upstream build to a fork client.
func TestForkBuildDoesNotQueryReleaseEndpoint(t *testing.T) {
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
	assert.False(t, u.fetchVersion(), "the fork must not read a latest version")

	done := make(chan struct{})
	go func() {
		u.StartFetcher()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("StartFetcher must return at once in the fork build")
	}

	assert.Zero(t, hits.Load(), "the fork must not send any request to the release endpoint")
	assert.Nil(t, u.LatestVersion(), "the fork must not learn a latest version")
}
