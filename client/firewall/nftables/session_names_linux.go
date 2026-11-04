//go:build !android

package nftables

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// IsolationTableName is the table holding the rules that separate sessions from each
// other. It is not derived from NB_NFTABLES_TABLE: no session may ever own it or open it.
const IsolationTableName = "netbird-iso"

const (
	slotSeparator = "-"

	// The kernel counts the terminating NUL of a table name, opaque user data has none.
	maxTableNameLen = unix.NFT_TABLE_MAXNAMELEN - 1
	maxRuleTagLen   = unix.NFT_USERDATA_MAXLEN
)

// SessionNames holds the nftables identifiers one session owns on the host. Use
// NamesForSlot to derive them; slot 0 has the same names as a manager built with Create.
type SessionNames struct {
	// Table is the exact name of the session's work table.
	Table string
	// TagSuffix is appended to the tags of the session's accept rules in foreign chains.
	TagSuffix string
}

// NamesForSlot returns the names of the session in the given slot. NB_NFTABLES_TABLE
// provides only the base of the table name. A name over the kernel limit is an error,
// never truncated.
func NamesForSlot(slot uint) (SessionNames, error) {
	names := SessionNames{Table: getTableName()}
	if slot > 0 {
		names.TagSuffix = slotSeparator + strconv.FormatUint(uint64(slot), 10)
		names.Table += names.TagSuffix
	}
	if err := names.validate(); err != nil {
		return SessionNames{}, fmt.Errorf("names for slot %d: %w", slot, err)
	}
	return names, nil
}

func (n SessionNames) validate() error {
	if err := validateTableName(n.Table); err != nil {
		return err
	}

	// An unsuffixed tag is the one of slot 0, so only the base table may use it.
	if n.TagSuffix == "" {
		if n.Table != getTableName() {
			return fmt.Errorf("table %q needs a tag suffix", n.Table)
		}
		return nil
	}

	number, ok := strings.CutPrefix(n.TagSuffix, slotSeparator)
	if !ok || !isDecimal(number) {
		return fmt.Errorf("invalid tag suffix %q", n.TagSuffix)
	}
	// Closing a manager deletes its table, so the table must be the configured base and
	// nothing else with this suffix.
	if n.Table != getTableName()+n.TagSuffix {
		return fmt.Errorf("table %q does not match base table and tag suffix %q", n.Table, n.TagSuffix)
	}
	if len(userDataAcceptForwardRuleIif)+len(n.TagSuffix) > maxRuleTagLen {
		return fmt.Errorf("tag suffix of %d bytes exceeds the kernel limit", len(n.TagSuffix))
	}
	return nil
}

func validateTableName(name string) error {
	switch {
	case name == "":
		return errors.New("empty table name")
	case len(name) > maxTableNameLen:
		return fmt.Errorf("table name of %d bytes exceeds the kernel limit of %d", len(name), maxTableNameLen)
	case strings.ContainsRune(name, 0):
		return errors.New("table name contains a NUL byte")
	case name == IsolationTableName, name == firewalldTableName, isIptablesTable(name):
		// Closing a manager deletes its table, so it must never own one of these.
		return fmt.Errorf("table name %q is reserved", name)
	}
	return nil
}

func isDecimal(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range []byte(s) {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// sessionScope is what distinguishes a manager built for a session. A nil scope means one
// built without it: the historic tags, and every other table counts as foreign.
type sessionScope struct {
	names SessionNames
	base  string
}

func newSessionScope(names SessionNames) (*sessionScope, error) {
	if err := names.validate(); err != nil {
		return nil, fmt.Errorf("validate session names: %w", err)
	}
	return &sessionScope{names: names, base: getTableName()}, nil
}

// ownsTable reports whether the table belongs to NetBird itself. Opening such a table for
// an interface would let it past another session's drop or past the isolation rules.
func (s *sessionScope) ownsTable(name string) bool {
	if s == nil {
		return false
	}
	if name == IsolationTableName || name == s.base {
		return true
	}
	number, ok := strings.CutPrefix(name, s.base+slotSeparator)
	return ok && isDecimal(number)
}

// acceptTags are the user data tags of one session's accept rules in foreign chains.
type acceptTags struct {
	forwardIif string
	forwardOif string
	input      string
}

func newAcceptTags(suffix string) acceptTags {
	return acceptTags{
		forwardIif: userDataAcceptForwardRuleIif + suffix,
		forwardOif: userDataAcceptForwardRuleOif + suffix,
		input:      userDataAcceptInputRule + suffix,
	}
}

func (t acceptTags) contains(userData []byte) bool {
	switch string(userData) {
	case t.forwardIif, t.forwardOif, t.input:
		return true
	}
	return false
}

// bindSession limits the family to the names of the scope. It runs before first use.
func (r *family) bindSession(scope *sessionScope) {
	if scope == nil {
		return
	}
	r.scope = scope
	r.tags = newAcceptTags(scope.names.TagSuffix)
}
