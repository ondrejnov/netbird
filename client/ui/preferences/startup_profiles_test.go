//go:build !android && !ios && !freebsd && !js

package preferences

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStore_SetStartupProfilePersists(t *testing.T) {
	withTempConfigDir(t)
	emitter := &recordingEmitter{}
	s, err := NewStore(nil, emitter)
	require.NoError(t, err)

	require.NoError(t, s.SetStartupProfile("prace", true))
	require.NoError(t, s.SetStartupProfile("doma", true))
	// A second enable of the same profile must not list it twice.
	require.NoError(t, s.SetStartupProfile("prace", true))
	assert.Equal(t, []string{"prace", "doma"}, s.Get().StartupProfiles)

	before := s.Get().StartupProfiles
	require.NoError(t, s.SetStartupProfile("prace", false))
	assert.Equal(t, []string{"doma"}, s.Get().StartupProfiles)
	assert.Equal(t, []string{"prace", "doma"}, before, "a copy handed out earlier must not change underneath")
	assert.Len(t, emitter.calledWith(EventPreferencesChanged), 3, "only real changes should broadcast")

	reloaded, err := NewStore(nil, nil)
	require.NoError(t, err)
	assert.Equal(t, []string{"doma"}, reloaded.Get().StartupProfiles, "the choice should survive a restart")

	assert.Error(t, s.SetStartupProfile("", true))
}
