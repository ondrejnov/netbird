package server

import (
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
)

// windowsAccount is a local account of a Windows host.
type windowsAccount struct {
	// name is the account as DOMAIN\name, the domain being the computer.
	name string
	sid  string
}

// holdsWindowsAccount reports whether username names the caller. The name of the caller's SID is
// compared, and never the SID of the name: a name without a domain resolves by a search order, so
// it could name an account other than the one the CLI of the caller sent.
func (c sessionCaller) holdsWindowsAccount(username string) bool {
	if c.id.SID == "" {
		return false
	}
	name, err := c.accountName(c.id.SID)
	if err != nil {
		log.Warnf("failed to look up the account of a caller: %v", err)
		return false
	}
	return strings.EqualFold(name, username)
}

// aloneInWindowsDirectory is aloneInDirectory for DOMAIN\name. The directory drops the backslash
// and every other character the sanitizer does not keep, so another local account may land on
// the same one. Domain accounts cannot be listed, so a domain account has its directory only
// when its name loses nothing but the backslash.
func (c sessionCaller) aloneInWindowsDirectory(username string) bool {
	domain, account, ok := strings.Cut(username, `\`)
	if !ok || domain == "" || account == "" || strings.Contains(account, `\`) {
		log.Debugf("denying access to the profiles of %s for an unprivileged caller: not a DOMAIN\\name account", username)
		return false
	}
	directory := profilemanager.SanitizedUsername(username)
	if directory == "" {
		return false
	}

	accounts, err := c.windowsAccounts()
	if err != nil {
		log.Warnf("failed to read the accounts of this host: %v", err)
		return false
	}

	local := false
	for _, other := range accounts {
		if strings.EqualFold(other.sid, c.id.SID) {
			local = true
			continue
		}
		if strings.EqualFold(profilemanager.SanitizedUsername(other.name), directory) {
			log.Debugf("denying access to the profiles of %s for an unprivileged caller: the account %s shares their directory", username, other.name)
			return false
		}
	}
	if !local && !losslessWindowsName(domain, account) {
		log.Debugf("denying access to the profiles of %s for an unprivileged caller: the domain account loses characters in the name of its directory", username)
		return false
	}
	return true
}

func losslessWindowsName(domain, account string) bool {
	return profilemanager.SanitizedUsername(domain) == domain && profilemanager.SanitizedUsername(account) == account
}
