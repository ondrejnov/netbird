package nftables

import (
	"errors"
	"fmt"

	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
)

type InterfaceState struct {
	NameStr   string         `json:"name"`
	WGAddress wgaddr.Address `json:"wg_address"`
	MTU       uint16         `json:"mtu"`
}

func (i *InterfaceState) Name() string {
	return i.NameStr
}

func (i *InterfaceState) Address() wgaddr.Address {
	return i.WGAddress
}

type ShutdownState struct {
	InterfaceState *InterfaceState `json:"interface_state,omitempty"`
	// TableName and TagSuffix stay empty unless the session has a suffix, so a state file
	// of slot 0 keeps its format and one without them still means the default names.
	TableName string `json:"table_name,omitempty"`
	TagSuffix string `json:"tag_suffix,omitempty"`
}

func (s *ShutdownState) Name() string {
	return "nftables_state"
}

func (s *ShutdownState) Cleanup() error {
	if s.InterfaceState == nil {
		return errors.New("state has no interface state")
	}
	mtu := s.InterfaceState.MTU
	if mtu == 0 {
		mtu = iface.DefaultMTU
	}
	nft, err := s.createManager(mtu)
	if err != nil {
		return fmt.Errorf("create nftables manager: %w", err)
	}

	if err := nft.Close(nil); err != nil {
		return fmt.Errorf("reset nftables manager: %w", err)
	}

	return nil
}

func (s *ShutdownState) createManager(mtu uint16) (*Manager, error) {
	if s.TagSuffix == "" {
		// Only a session with a suffix writes its names, so a table name alone is damage.
		if s.TableName != "" {
			return nil, fmt.Errorf("table %q has no tag suffix", s.TableName)
		}
		return Create(s.InterfaceState, mtu)
	}
	return CreateForSession(s.InterfaceState, mtu, SessionNames{Table: s.TableName, TagSuffix: s.TagSuffix})
}
