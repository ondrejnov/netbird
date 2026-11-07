package server

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// windowsAccountName returns the account of sid as DOMAIN\name.
func windowsAccountName(sidString string) (string, error) {
	sid, err := windows.StringToSid(sidString)
	if err != nil {
		return "", fmt.Errorf("parse SID: %w", err)
	}
	account, domain, _, err := sid.LookupAccount("")
	if err != nil {
		return "", fmt.Errorf("look up account of SID: %w", err)
	}
	if domain == "" {
		return account, nil
	}
	return domain + `\` + account, nil
}

// userInfo0 is USER_INFO_0 of NetUserEnum.
type userInfo0 struct {
	name *uint16
}

const (
	filterNormalAccount = 0x0002
	maxPreferredLength  = 0xFFFFFFFF
)

// localWindowsAccounts lists the local user accounts of the host, with their SIDs. A failure to
// list them, or to resolve one of them, is an error: a missing account could share a directory.
func localWindowsAccounts() ([]windowsAccount, error) {
	computer, err := windows.ComputerName()
	if err != nil {
		return nil, fmt.Errorf("get computer name: %w", err)
	}
	var accounts []windowsAccount
	var resume uint32
	for {
		var buf *byte
		var read, total uint32
		enumErr := windows.NetUserEnum(nil, 0, filterNormalAccount, &buf, maxPreferredLength, &read, &total, &resume)
		if enumErr != nil && !errors.Is(enumErr, windows.ERROR_MORE_DATA) {
			return nil, fmt.Errorf("enumerate local accounts: %w", enumErr)
		}
		page, pageErr := readUserInfo0(computer, buf, read)
		if buf != nil {
			_ = windows.NetApiBufferFree(buf)
		}
		if pageErr != nil {
			return nil, pageErr
		}
		accounts = append(accounts, page...)
		if !errors.Is(enumErr, windows.ERROR_MORE_DATA) {
			return accounts, nil
		}
	}
}

// readUserInfo0 resolves each name within the computer, which a bare name would only reach by the
// search order of LookupAccountName.
func readUserInfo0(computer string, buf *byte, read uint32) ([]windowsAccount, error) {
	if buf == nil || read == 0 {
		return nil, nil
	}
	entries := unsafe.Slice((*userInfo0)(unsafe.Pointer(buf)), read)
	accounts := make([]windowsAccount, 0, len(entries))
	for _, entry := range entries {
		name := windows.UTF16PtrToString(entry.name)
		sid, domain, _, err := windows.LookupSID("", computer+`\`+name)
		if err != nil {
			return nil, fmt.Errorf("look up local account %s: %w", name, err)
		}
		accounts = append(accounts, windowsAccount{name: domain + `\` + name, sid: sid.String()})
	}
	return accounts, nil
}
