package internal

import (
	"errors"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/internal/dns"
	"github.com/netbirdio/netbird/client/internal/hostcoord"
	cProto "github.com/netbirdio/netbird/client/proto"
)

// SessionConflict is the value of SessionStatus.conflict.
type SessionConflict string

const (
	// ConflictOverlay means the IPv4 overlay overlaps another session, which refuses the session.
	ConflictOverlay SessionConflict = "overlay"
	// ConflictInterface means another session uses the interface name or the port, which refuses the session.
	ConflictInterface SessionConflict = "interface"
	// ConflictExitNode means the session asked for an exit node while another session holds the only one.
	ConflictExitNode SessionConflict = "exit_node"
	// ConflictDNS means another session limits the DNS of the session.
	ConflictDNS SessionConflict = "dns"
)

const (
	// EventSessionRefused is the kind of the event about a refused session.
	EventSessionRefused = "session_refused"

	eventIPv6Skipped = "ipv6_overlay_skipped"

	msgOverlayRefused = "This session was not started: its overlay range overlaps another running session. " +
		"Change network_range in the Management of one of the networks, or bring the other session down"
	msgIsolationLost = "This session was stopped: something on this host changed the rules that keep the networks of this daemon apart, " +
		"and they could not be put back. Find out what changes the firewall, then bring the session up again"
	msgExplicitInterface = "This session was not started: with concurrent profiles the interface name comes from the session. " +
		"Set the interface name of this profile back to " + iface.WgInterfaceDefault
	msgForeignLink = "This session was not started: something else on this host uses the name of its interface. " +
		"Rename or remove that interface"
	msgInterfaceRefused = "This session was not started: its interface name is used by another running session. " +
		"Change the interface name of one of the profiles, or bring the other session down"
	msgPortRefused = "This session was not started: its port is used by another running session. " +
		"Change the port of one of the profiles, or bring the other session down"
)

// SessionRefusal is what a user gets to see about a refused session.
type SessionRefusal struct {
	// Conflict is empty for a refusal another session has no part in, such as a failed isolation.
	Conflict SessionConflict
	Message  string
}

// RefusalOf describes an error that carries ErrSessionRefused. The text of a conflict stays free of
// addresses and of the name of the other session, which can belong to another user.
func RefusalOf(err error) SessionRefusal {
	switch {
	case errors.Is(err, ErrIsolationLost):
		return SessionRefusal{Message: msgIsolationLost}
	case errors.Is(err, ErrOverlayOverlap):
		return SessionRefusal{Conflict: ConflictOverlay, Message: msgOverlayRefused}
	case errors.Is(err, ErrExplicitInterface):
		return SessionRefusal{Conflict: ConflictInterface, Message: msgExplicitInterface}
	case errors.Is(err, hostcoord.ErrForeignLink):
		return SessionRefusal{Conflict: ConflictInterface, Message: msgForeignLink}
	case errors.Is(err, hostcoord.ErrInterfaceConflict):
		return SessionRefusal{Conflict: ConflictInterface, Message: msgInterfaceRefused}
	case errors.Is(err, hostcoord.ErrPortConflict):
		return SessionRefusal{Conflict: ConflictInterface, Message: msgPortRefused}
	}
	return SessionRefusal{Message: fmt.Sprintf("This session was not started: %v", err)}
}

// Conflict returns what another session limits about the running session key, empty when nothing does.
func (d *DaemonHost) Conflict(key hostcoord.SessionKey) SessionConflict {
	switch {
	case d == nil:
		return ""
	case d.coordinator.Routes().WaitsForExitNode(key):
		return ConflictExitNode
	case d.coordinator.DNSOwners().InConflict(key):
		return ConflictDNS
	}
	return ""
}

// ExitNodeHeldByOther reports whether a session other than key holds the exit node of the host.
func (d *DaemonHost) ExitNodeHeldByOther(key hostcoord.SessionKey) bool {
	owner, held := d.coordinator.Routes().ExitNodeOwner()
	return held && owner != key
}

// routeEventMessages holds what a session is told, %s being the route. All of them are warnings, the
// handover included: the routing changes without the user having asked.
var routeEventMessages = map[hostcoord.RouteEventKind]string{
	hostcoord.RouteEventShadowed:         "Another session routes %s, this session takes over when that one leaves",
	hostcoord.RouteEventAcquired:         "The session that routed %s left, this session routes it now",
	hostcoord.RouteEventHandoverFailed:   "This session could not take over the route %s from the session that left, it will try again",
	hostcoord.RouteEventExitNodeHeld:     "Another session holds the exit node of this host, the exit node %s of this session is skipped",
	hostcoord.RouteEventExitNodeReleased: "The session holding the exit node of this host left. Traffic takes the physical default, and the exit node %s of this session has to be selected again",
	hostcoord.RouteEventOverlayRefused:   "The route %s overlaps the overlay of another session and was refused",
}

// routeEvent runs on the goroutine of whichever session caused the change, possibly with that session
// holding its locks. It only touches the recorder of this session, which does not wait for anyone.
func (h *SessionHost) routeEvent(event hostcoord.RouteEvent) {
	log.Warnf("route of profile %s: %s", event.Session.Profile, event.Kind)
	log.Debugf("route of profile %s: %s for %s: %v", event.Session.Profile, event.Kind, event.Prefix, event.Err)

	h.warn(cProto.SystemEvent_NETWORK, string(event.Kind), fmt.Sprintf(routeEventMessages[event.Kind], event.Prefix),
		map[string]string{cProto.MetadataPrefixKey: event.Prefix.String()})
}

// dnsWarning has the same constraints as routeEvent, and the DNS server calls it with its lock held.
func (h *SessionHost) dnsWarning(warning dns.HostDNSWarning) {
	log.Warnf("DNS of profile %s: %s", h.key.Profile, warning.Kind)

	var message string
	metadata := map[string]string{}
	switch warning.Kind {
	case dns.HostDNSCatchAllHeld:
		message = "Another session routes all DNS of this host, this session keeps only its own domains"
	case dns.HostDNSHeld:
		message = "Another session holds the DNS of this host, names of this network do not resolve here, its addresses work"
	case dns.HostDNSDomainShared:
		domains := strings.Join(warning.Domains, ", ")
		message = fmt.Sprintf("Another session serves the same DNS domain %s, a name in both networks is answered by either one", domains)
		metadata[cProto.MetadataDomainsKey] = domains
	case dns.HostDNSDomainHeld:
		domains := strings.Join(warning.Domains, ", ")
		message = fmt.Sprintf("Another session serves the DNS domain %s on this host, names in it resolve through that session only", domains)
		metadata[cProto.MetadataDomainsKey] = domains
	default:
		message = string(warning.Kind)
	}
	h.warn(cProto.SystemEvent_DNS, string(warning.Kind), message, metadata)
}

func (h *SessionHost) warn(category cProto.SystemEvent_Category, kind, message string, metadata map[string]string) {
	if h.recorder == nil {
		return
	}
	if metadata == nil {
		metadata = map[string]string{}
	}
	metadata[cProto.MetadataKindKey] = kind
	h.recorder.PublishEvent(cProto.SystemEvent_WARNING, category, message, message, metadata)
	// The conflict in the status follows from the same change, for whoever watches the status.
	h.recorder.NotifyStateChange()
}
