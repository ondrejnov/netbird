package profilemanager

// SessionKey identifies the profile a session runs. It includes the user because
// legacy profile IDs are not unique across users.
type SessionKey struct {
	Profile  ID
	Username string
}

// SessionKey returns the identity of the profile the state points at, captured by
// value so that a later profile switch cannot change it.
func (a *ActiveProfileState) SessionKey() SessionKey {
	return SessionKey{Profile: a.ID, Username: a.Username}
}

// SanitizedUsername returns the name of the directory that holds the profiles of username. Different
// usernames can end up with the same directory.
func SanitizedUsername(username string) string {
	return sanitizeProfileName(username)
}
