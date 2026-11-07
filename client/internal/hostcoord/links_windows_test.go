//go:build windows

package hostcoord

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/windows"
)

func TestJudgeAdapters(t *testing.T) {
	slotGUID := windows.GUID{Data1: 1}
	otherGUID := windows.GUID{Data1: 2}

	tests := []struct {
		name     string
		adapters []presentAdapter
		want     linkVerdict
	}{
		{"no adapters", nil, linkFree},
		{"only unrelated adapters", []presentAdapter{{"Ethernet", otherGUID}, {"wt2", windows.GUID{Data1: 3}}}, linkFree},
		{"another adapter has the name", []presentAdapter{{"wt1", otherGUID}}, linkForeign},
		{"the slot's adapter is still there", []presentAdapter{{"wt1", slotGUID}}, linkClosing},
		// Another program created an adapter under the slot's name, and Wintun renamed ours.
		{"the slot's adapter under another name", []presentAdapter{{"wt1 1", slotGUID}}, linkClosing},
		{"the slot's adapter and a foreign one with the name", []presentAdapter{{"wt1 1", slotGUID}, {"wt1", otherGUID}}, linkForeign},
		{"a foreign adapter listed after the slot's", []presentAdapter{{"wt1", slotGUID}, {"wt1", otherGUID}}, linkForeign},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, detail := judgeAdapters(tt.adapters, "wt1", slotGUID)
			assert.Equal(t, tt.want, got, "verdict, detail %q", detail)
			if tt.want != linkFree {
				assert.NotEmpty(t, detail, "a refusal or a wait says what it is about")
			}
		})
	}
}
