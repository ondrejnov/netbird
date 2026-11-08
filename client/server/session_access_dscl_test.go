package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseDsclAccounts(t *testing.T) {
	out := "_amavisd                 83\n" +
		"daemon                   1\n" +
		"ondrej                   501\n" +
		"john.doe                 502\n" +
		"broken\n" +
		"nouid                    abc\n" +
		"\n"

	assert.Equal(t, []hostAccount{
		{name: "_amavisd", uid: 83},
		{name: "daemon", uid: 1},
		{name: "ondrej", uid: 501},
		{name: "john.doe", uid: 502},
	}, parseDsclAccounts(out), "every line with a name and a numeric UID is an account")
}
