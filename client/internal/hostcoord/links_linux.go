//go:build linux && !android

package hostcoord

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	nberrors "github.com/netbirdio/netbird/client/errors"
)

const (
	wireguardLinkType = "wireguard"
	// tunLinkType is the interface of a userspace session, as netlink.Tuntap names it. One that is
	// closing can still be there when the next attempt starts, and it goes away by itself.
	tunLinkType = "tuntap"

	// closingTunWait is how long a closing TUN gets to go away. It is the kernel taking the interface
	// down after the last descriptor closed, and the descriptors close before an attempt ends.
	closingTunWait = 5 * time.Second
	closingTunPoll = 50 * time.Millisecond
)

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

// RefuseForeignLink refuses a link called name that cannot be the one of a session. Bringing a session
// up deletes whatever has its name, so a session must not start on top of such a link. A TUN gets
// closingTunWait to go away: the one of a previous attempt does, and nobody else's may be deleted.
// Any lookup failure counts as well, as nobody can tell what is there.
func RefuseForeignLink(ctx context.Context, name string) error {
	timeout := time.NewTimer(closingTunWait)
	defer timeout.Stop()
	poll := time.NewTicker(closingTunPoll)
	defer poll.Stop()

	for {
		link, err := netlink.LinkByName(name)
		if err != nil {
			var notFound netlink.LinkNotFoundError
			if errors.As(err, &notFound) {
				return nil
			}
			return fmt.Errorf("find link %s: %w", name, err)
		}

		switch linkType := link.Type(); linkType {
		case wireguardLinkType:
			return nil
		case tunLinkType:
		default:
			return fmt.Errorf("%w: %s has type %s", ErrForeignLink, name, linkType)
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for link %s to go away: %w", name, ctx.Err())
		case <-timeout.C:
			return fmt.Errorf("%w: %s is a TUN that stays", ErrForeignLink, name)
		case <-poll.C:
		}
	}
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
