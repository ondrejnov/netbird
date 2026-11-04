//go:build linux && !android

package hostcoord

import (
	"errors"
	"fmt"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	nberrors "github.com/netbirdio/netbird/client/errors"
)

const wireguardLinkType = "wireguard"

// RemoveSessionLinks deletes the kernel interfaces stored sessions left behind. They outlive the
// process with their peers on them, and a session that does not come back would leave its
// interface outside the isolation of the next daemon. It may only run before the first session
// starts. A link that is not WireGuard is not ours, whatever its name, and stays.
func RemoveSessionLinks(records []SlotRecord) error {
	var merr *multierror.Error
	for _, record := range records {
		name := slotInterfaceName(record.Slot)
		link, found, err := sessionLink(name)
		if err != nil {
			merr = multierror.Append(merr, err)
			continue
		}
		if !found {
			continue
		}
		if err := netlink.LinkDel(link); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("delete link %s: %w", name, err))
		}
	}
	return nberrors.FormatErrorOrNil(merr)
}

// VerifyNoSessionLinks reports a link RemoveSessionLinks would delete, or one it cannot tell apart.
func VerifyNoSessionLinks(records []SlotRecord) error {
	var merr *multierror.Error
	for _, record := range records {
		name := slotInterfaceName(record.Slot)
		_, found, err := sessionLink(name)
		if err != nil {
			merr = multierror.Append(merr, err)
			continue
		}
		if found {
			merr = multierror.Append(merr, fmt.Errorf("link %s of a stored session is still there", name))
		}
	}
	return nberrors.FormatErrorOrNil(merr)
}

// sessionLink returns the link called name and whether it can be the one of a session.
func sessionLink(name string) (netlink.Link, bool, error) {
	link, err := netlink.LinkByName(name)
	if err != nil {
		var notFound netlink.LinkNotFoundError
		if errors.As(err, &notFound) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("find link %s: %w", name, err)
	}
	if link.Type() != wireguardLinkType {
		log.Warnf("leaving interface %s of type %s: a session link would be WireGuard", name, link.Type())
		return nil, false, nil
	}
	return link, true, nil
}
