package server

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal/ipcauth"
	"github.com/netbirdio/netbird/client/proto"
)

// SIDs of no real account, so neither is the user the tests run as.
const (
	winAliceSID = "S-1-5-21-1000000001-1000000002-1000000003-5001"
	winBobSID   = "S-1-5-21-1000000001-1000000002-1000000003-5002"
	winCorpSID  = "S-1-5-21-2000000001-2000000002-2000000003-7001"
)

// A Windows caller owns the profiles of the account its SID names, written as DOMAIN\name, and a
// directory no other account of the host lands on.
func TestSessionAccess_WindowsOwnerBySID(t *testing.T) {
	names := map[string]string{
		winAliceSID: `PC\alice`,
		winBobSID:   `PC\bob`,
		winCorpSID:  `CORP\carol`,
	}
	localAccounts := []windowsAccount{{name: `PC\alice`, sid: winAliceSID}, {name: `PC\bob`, sid: winBobSID}}

	setup := func(t *testing.T, accounts []windowsAccount, accountsErr, nameErr error) *accessFixture {
		t.Helper()
		f := newAccessFixture(t)
		f.s.accountNameFn = func(sid string) (string, error) {
			if nameErr != nil {
				return "", nameErr
			}
			name, ok := names[sid]
			if !ok {
				return "", errors.New("no such account")
			}
			return name, nil
		}
		f.s.windowsAccountsFn = func() ([]windowsAccount, error) { return accounts, accountsErr }
		return f
	}
	caller := func(sid string) context.Context {
		return ctxWithIdentity(ipcauth.Identity{SID: sid})
	}
	list := func(f *accessFixture, ctx context.Context, username string) error {
		_, err := f.s.ListProfiles(ctx, &proto.ListProfilesRequest{Username: username})
		return err
	}

	t.Run("the own account reaches its profiles", func(t *testing.T) {
		f := setup(t, localAccounts, nil, nil)
		assert.NoError(t, list(f, caller(winAliceSID), `PC\alice`))
		assert.NoError(t, list(f, caller(winAliceSID), `pc\ALICE`), "account names do not depend on case")
	})

	t.Run("another account is refused", func(t *testing.T) {
		f := setup(t, localAccounts, nil, nil)
		requireRefusedAsForeign(t, list(f, caller(winAliceSID), `PC\bob`))
		requireRefusedAsForeign(t, list(f, caller(winBobSID), `PC\alice`))
		// A domain account is in no local list, so only the name of the SID tells it apart.
		requireRefusedAsForeign(t, list(f, caller(winAliceSID), `CORP\carol`))
	})

	t.Run("a name without its domain is not the account", func(t *testing.T) {
		f := setup(t, localAccounts, nil, nil)
		requireRefusedAsForeign(t, list(f, caller(winAliceSID), `alice`), "only the name the SID resolves to counts")
	})

	t.Run("an unknown SID reaches nothing", func(t *testing.T) {
		f := setup(t, localAccounts, nil, errors.New("the domain controller is unreachable"))
		requireRefusedAsForeign(t, list(f, caller(winAliceSID), `PC\alice`), "not knowing who calls means it is not their session (I6)")
	})

	t.Run("a local account on the same directory reaches nothing", func(t *testing.T) {
		accounts := append([]windowsAccount{{name: `PC\al.ice`, sid: winBobSID}}, localAccounts[:1]...)
		f := setup(t, accounts, nil, nil)
		requireRefusedAsForeign(t, list(f, caller(winAliceSID), `PC\alice`), `PC\al.ice and PC\alice share the directory PCalice`)
	})

	t.Run("the accounts cannot be read", func(t *testing.T) {
		f := setup(t, nil, errors.New("access denied"), nil)
		requireRefusedAsForeign(t, list(f, caller(winAliceSID), `PC\alice`))
	})

	t.Run("a domain account with a clean name reaches its profiles", func(t *testing.T) {
		f := setup(t, localAccounts, nil, nil)
		assert.NoError(t, list(f, caller(winCorpSID), `CORP\carol`))
	})

	t.Run("a domain account whose name loses characters reaches nothing", func(t *testing.T) {
		names[winCorpSID] = `CORP\carol.smith`
		t.Cleanup(func() { names[winCorpSID] = `CORP\carol` })
		f := setup(t, localAccounts, nil, nil)
		requireRefusedAsForeign(t, list(f, caller(winCorpSID), `CORP\carol.smith`), "the domain accounts it could share a directory with cannot be listed")
	})

	t.Run("a local account may lose characters, its neighbours are known", func(t *testing.T) {
		names[winBobSID] = `PC\bob smith`
		t.Cleanup(func() { names[winBobSID] = `PC\bob` })
		f := setup(t, []windowsAccount{localAccounts[0], {name: `PC\bob smith`, sid: winBobSID}}, nil, nil)
		assert.NoError(t, list(f, caller(winBobSID), `PC\bob smith`))
	})

	t.Run("the default profile is shared as before", func(t *testing.T) {
		f := setup(t, nil, errors.New("access denied"), errors.New("unknown"))
		// The cancelled context stops the call right after the authorization.
		_, err := f.s.GetConfig(cancelledCopy(caller(winAliceSID)), &proto.GetConfigRequest{ProfileName: "default", Username: `PC\alice`})
		assert.NotEqual(t, codes.PermissionDenied, gstatus.Code(err), "the default profile needs no account: %v", err)
	})
}
