//go:build !linux || android

package conntrack

import nftypes "github.com/netbirdio/netbird/client/internal/netflow/types"

// Option configures a connection tracker, which this platform does not have.
type Option func()

// Accounting shares nf_conntrack_acct between holders, which this platform does not have.
type Accounting struct{}

// NewAccounting returns an Accounting with no holders.
func NewAccounting() *Accounting {
	return &Accounting{}
}

// WithAccounting does nothing on this platform.
func WithAccounting(*Accounting) Option {
	return func() {}
}

func New(flowLogger nftypes.FlowLogger, iface nftypes.IFaceMapper, _ ...Option) nftypes.ConnTracker {
	return nil
}
