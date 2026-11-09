//go:build !android && !ios && !freebsd && !js

package services

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStatusFocusedProfileID(t *testing.T) {
	// Without the concurrent profiles gate the daemon reports no sessions.
	assert.Empty(t, Status{}.FocusedProfileID(), "no sessions means no focused profile")

	st := Status{Sessions: []SessionStatus{
		{ProfileID: "work", Status: StatusConnected},
		{ProfileID: "home", Status: StatusConnected, Focused: true},
	}}
	assert.Equal(t, "home", st.FocusedProfileID(), "focused session's profile should be returned")
}
