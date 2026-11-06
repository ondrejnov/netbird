package version

import "strings"

// ForkBuild reports whether this binary is the multi-profile fork rather than
// the upstream client. The fork is selected at build time by the multiprofile tag.
func ForkBuild() bool {
	return forkMarker != ""
}

// markFork appends the fork marker as semver build metadata. Build metadata
// does not take part in version comparison, so peers and Management rank a
// fork client like the upstream release it is based on.
func markFork(v string) string {
	if forkMarker == "" || strings.HasSuffix(v, "+"+forkMarker) {
		return v
	}
	return v + "+" + forkMarker
}
