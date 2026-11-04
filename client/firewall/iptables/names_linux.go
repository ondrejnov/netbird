//go:build !android

package iptables

import (
	"fmt"
	"strconv"
)

const (
	// maxChainNameLen is the longest iptables chain name the kernel accepts
	// (XT_EXTENSION_MAXNAMELEN is 29 including the terminator).
	maxChainNameLen = 28
	// maxIPSetNameLen is the longest ipset name the kernel accepts
	// (IPSET_MAXNAMELEN is 32 including the terminator).
	maxIPSetNameLen = 31
)

// Option configures an iptables Manager.
type Option func(*config)

type config struct {
	slot uint
}

// WithSlot makes the manager own the chains and ipsets of the given slot.
// Slot 0 keeps the names used without any option; slot N appends the suffix
// "-N" to every chain and ipset the manager creates.
func WithSlot(slot uint) Option {
	return func(c *config) {
		c.slot = slot
	}
}

func newConfig(opts ...Option) config {
	var cfg config
	for _, opt := range opts {
		opt(&cfg)
	}
	return cfg
}

// chainNames holds the chain names and the ipset suffix of one slot.
type chainNames struct {
	slot   uint
	suffix string

	aclInput   string
	rtNAT      string
	rtFwdIn    string
	rtFwdOut   string
	rtPre      string
	rtRdr      string
	natOutput  string
	rtMSSClamp string
}

// newChainNames derives the chain names of a slot and rejects the slot when a
// name would exceed the kernel limit, because a truncated name could collide
// with the chain of another slot.
func newChainNames(slot uint) (chainNames, error) {
	n := chainNames{slot: slot}
	if slot != 0 {
		n.suffix = "-" + strconv.FormatUint(uint64(slot), 10)
	}

	for _, c := range []struct {
		dst  *string
		base string
	}{
		{&n.aclInput, chainACLInput},
		{&n.rtNAT, chainRTNAT},
		{&n.rtFwdIn, chainRTFwdIn},
		{&n.rtFwdOut, chainRTFwdOut},
		{&n.rtPre, chainRTPre},
		{&n.rtRdr, chainRTRdr},
		{&n.natOutput, chainNATOutput},
		{&n.rtMSSClamp, chainRTMSSClamp},
	} {
		name := c.base + n.suffix
		if len(name) > maxChainNameLen {
			return chainNames{}, fmt.Errorf("chain name %q is %d characters, the kernel allows %d", name, len(name), maxChainNameLen)
		}
		*c.dst = name
	}

	return n, nil
}

// ipsetName returns the kernel name of the set whose content hash is name.
// The hash identifies the content only, so the slot suffix is what keeps two
// slots with the same set from sharing one kernel object.
func (n chainNames) ipsetName(name string, v6 bool) (string, error) {
	if v6 {
		name += "-v6"
	}
	name += n.suffix
	if len(name) > maxIPSetNameLen {
		return "", fmt.Errorf("ipset name %q is %d characters, the kernel allows %d", name, len(name), maxIPSetNameLen)
	}
	return name, nil
}

// acceptTag marks the accept rules this slot installs in chains it shares with
// other slots. Slot 0 stays untagged so its rules are the ones installed
// without a slot.
func (n chainNames) acceptTag() string {
	if n.slot == 0 {
		return ""
	}
	return "netbird" + n.suffix
}
