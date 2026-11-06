package status

import (
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/netbirdio/netbird/client/proto"
)

// SessionOutput is one session of a daemon with concurrent profiles.
type SessionOutput struct {
	ProfileID     string `json:"profileId" yaml:"profileId"`
	ProfileName   string `json:"profileName" yaml:"profileName"`
	Status        string `json:"status" yaml:"status"`
	InterfaceName string `json:"interfaceName,omitempty" yaml:"interfaceName,omitempty"`
	OverlayIP     string `json:"overlayIp,omitempty" yaml:"overlayIp,omitempty"`
	Focused       bool   `json:"focused" yaml:"focused"`
	// Conflict names the resource that keeps the session from running: overlay, exit_node, dns
	// or interface.
	Conflict string `json:"conflict,omitempty" yaml:"conflict,omitempty"`
}

func mapSessions(sessions []*proto.SessionStatus) []SessionOutput {
	if len(sessions) == 0 {
		return nil
	}
	out := make([]SessionOutput, 0, len(sessions))
	for _, s := range sessions {
		out = append(out, SessionOutput{
			ProfileID:     s.GetProfileId(),
			ProfileName:   s.GetProfileName(),
			Status:        s.GetStatus(),
			InterfaceName: s.GetInterfaceName(),
			OverlayIP:     s.GetOverlayIp(),
			Focused:       s.GetFocused(),
			Conflict:      s.GetConflict(),
		})
	}
	return out
}

// SessionsSummary is the table of the sessions, empty when there are none. It follows the summary
// of the session the status was asked for.
func (o *OutputOverview) SessionsSummary() string {
	return renderSessions(o.Sessions)
}

// SessionsSummaryOf is SessionsSummary for the sessions as the daemon reported them.
func SessionsSummaryOf(sessions []*proto.SessionStatus) string {
	return renderSessions(mapSessions(sessions))
}

func renderSessions(sessions []SessionOutput) string {
	if len(sessions) == 0 {
		return ""
	}

	var b strings.Builder
	b.WriteString("Sessions:\n")
	tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	for _, s := range sessions {
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\n", sanitizeCell(s.ProfileName), s.Status, dash(s.InterfaceName),
			dash(s.OverlayIP), sessionNotes(s))
	}
	_ = tw.Flush()
	return b.String()
}

func sessionNotes(s SessionOutput) string {
	var notes []string
	if s.Focused {
		notes = append(notes, "focused")
	}
	if s.Conflict != "" {
		notes = append(notes, "conflict: "+s.Conflict)
	}
	return strings.Join(notes, ", ")
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// sanitizeCell drops the control characters of a profile name, which the user chose.
func sanitizeCell(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}
