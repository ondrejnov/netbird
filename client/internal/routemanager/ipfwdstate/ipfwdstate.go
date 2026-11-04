package ipfwdstate

import (
	"errors"
	"fmt"
	"sync"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"

	nberrors "github.com/netbirdio/netbird/client/errors"
)

// IPForwardingState tracks v4 and v6 IP-forwarding sysctl enables with
// independent refcounts so a v4-only routing setup doesn't flip v6 sysctls.
// Without WithHostState the refcounts are private to the instance.
type IPForwardingState struct {
	mu sync.Mutex

	host *HostState

	// routingV4/routingV6 track whether the routing path currently holds a
	// reference, so repeated EnableRouting calls (one per network-map update)
	// hold at most one reference per family.
	routingV4 bool
	routingV6 bool
	closed    bool

	wgIfaceName string
}

// Option configures an IPForwardingState.
type Option func(*IPForwardingState)

// WithHostState makes the instance share the refcounts and the stored
// originals with every other instance given the same HostState.
func WithHostState(host *HostState) Option {
	return func(f *IPForwardingState) {
		if host != nil {
			f.host = host
		}
	}
}

// NewIPForwardingState returns a state tracker for the IP-forwarding sysctls.
// wgIfaceName is excluded from the per-interface accept_ra handling, as is the
// interface of every other instance sharing the same HostState.
func NewIPForwardingState(wgIfaceName string, opts ...Option) *IPForwardingState {
	f := &IPForwardingState{wgIfaceName: wgIfaceName}
	for _, opt := range opts {
		opt(f)
	}
	if f.host == nil {
		f.host = newHostState(false)
	}
	f.host.attach(wgIfaceName)
	return f
}

// Counts returns the current v4 and v6 refcounts. Intended for diagnostics
// and tests.
func (f *IPForwardingState) Counts() (v4, v6 int) {
	return f.host.counts()
}

// RequestRouting takes the forwarding references for the routing path. It is
// idempotent: while routing already holds a reference, further calls don't
// increment the refcounts, and a v4-only request releases a previously held v6
// reference. A v6 sysctl failure is logged and not returned so it can't take
// down v4 routing (the sysctl may be unwritable, e.g. read-only /proc/sys or
// IPv6 disabled on the kernel command line); v6 is retried on the next call.
func (f *IPForwardingState) RequestRouting(v6 bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.closed {
		return errors.New("IP forwarding state is closed")
	}

	if !f.routingV4 {
		if err := f.host.requestV4(); err != nil {
			return err
		}
		f.routingV4 = true
	}

	if !v6 {
		if !f.routingV6 {
			return nil
		}
		f.routingV6 = false
		return f.host.releaseV6()
	}

	if f.routingV6 {
		return nil
	}
	if err := f.host.requestV6(f.wgIfaceName); err != nil {
		log.Warnf("enable IPv6 forwarding for routing: %v", err)
		return nil
	}
	f.routingV6 = true
	return nil
}

// ReleaseRouting releases the references RequestRouting holds. Calls without a
// held reference are no-ops.
func (f *IPForwardingState) ReleaseRouting() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.releaseRoutingLocked()
}

func (f *IPForwardingState) releaseRoutingLocked() error {
	var result *multierror.Error
	if f.routingV4 {
		f.routingV4 = false
		if err := f.host.releaseV4(); err != nil {
			result = multierror.Append(result, err)
		}
	}
	if f.routingV6 {
		f.routingV6 = false
		if err := f.host.releaseV6(); err != nil {
			result = multierror.Append(result, err)
		}
	}
	return nberrors.FormatErrorOrNil(result)
}

// Close releases the held references and detaches the instance's interface
// from the shared state. Further requests are rejected. It is idempotent.
func (f *IPForwardingState) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.closed {
		return nil
	}
	f.closed = true
	f.host.detach(f.wgIfaceName)
	if err := f.releaseRoutingLocked(); err != nil {
		return fmt.Errorf("release routing: %w", err)
	}
	return nil
}
