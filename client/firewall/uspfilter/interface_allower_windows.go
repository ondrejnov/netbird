package uspfilter

import (
	"fmt"
	"os/exec"
	"strconv"
	"syscall"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"

	nberrors "github.com/netbirdio/netbird/client/errors"
	"github.com/netbirdio/netbird/client/internal/wincmd"
)

type action string

const (
	addRule          action = "add"
	deleteRule       action = "delete"
	firewallRuleName        = "Netbird"
)

// WindowsInterfaceAllower opens the NetBird interface in the Windows firewall
// via netsh advfirewall rules. It implements InterfaceAllower for the userspace
// firewall on Windows.
type WindowsInterfaceAllower struct {
	iface Iface
	// ruleName names the IPv4 rule; the IPv6 rule has the suffix -v6.
	ruleName string
	// replaceStale makes Apply replace a rule of that name instead of keeping it. A rule of a
	// session can be left by a crash with the address the slot had then.
	replaceStale bool
}

// NewWindowsInterfaceAllower builds the Windows netsh-based interface allower.
func NewWindowsInterfaceAllower(iface Iface) *WindowsInterfaceAllower {
	return &WindowsInterfaceAllower{iface: iface, ruleName: firewallRuleName}
}

// NewWindowsInterfaceAllowerForSlot builds the allower of the session on slot. Slot 0 keeps the
// rules of a client without sessions; any other slot owns rules with the suffix -N.
func NewWindowsInterfaceAllowerForSlot(iface Iface, slot uint32) *WindowsInterfaceAllower {
	if slot == 0 {
		return NewWindowsInterfaceAllower(iface)
	}
	return &WindowsInterfaceAllower{
		iface:        iface,
		ruleName:     SlotFirewallRuleName(slot),
		replaceStale: true,
	}
}

// SlotFirewallRuleName returns the name of the IPv4 rule of slot.
func SlotFirewallRuleName(slot uint32) string {
	if slot == 0 {
		return firewallRuleName
	}
	return firewallRuleName + "-" + strconv.FormatUint(uint64(slot), 10)
}

// Apply adds inbound-allow netsh rules for the interface's addresses.
func (a *WindowsInterfaceAllower) Apply() error {
	if !isWindowsFirewallReachable() {
		return nil
	}

	if err := a.applyRule(a.ruleName, a.iface.Address().IP.String()); err != nil {
		return err
	}
	if v6 := a.iface.Address().IPv6; v6.IsValid() {
		if err := a.applyRule(a.ruleName+"-v6", v6.String()); err != nil {
			return err
		}
	}
	return nil
}

func (a *WindowsInterfaceAllower) applyRule(name, localIP string) error {
	if isFirewallRuleActive(name) {
		if !a.replaceStale {
			return nil
		}
		if err := manageFirewallRule(name, deleteRule); err != nil {
			return fmt.Errorf("remove stale windows firewall rule %s: %w", name, err)
		}
	}
	return manageFirewallRule(name,
		addRule,
		"dir=in",
		"enable=yes",
		"action=allow",
		"profile=any",
		"localip="+localIP,
	)
}

// Close removes the netsh rules added by Apply.
func (a *WindowsInterfaceAllower) Close() error {
	if !isWindowsFirewallReachable() {
		return nil
	}

	var merr *multierror.Error
	if isFirewallRuleActive(a.ruleName) {
		if err := manageFirewallRule(a.ruleName, deleteRule); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("remove windows firewall rule: %w", err))
		}
	}
	if isFirewallRuleActive(a.ruleName + "-v6") {
		if err := manageFirewallRule(a.ruleName+"-v6", deleteRule); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("remove windows v6 firewall rule: %w", err))
		}
	}
	return nberrors.FormatErrorOrNil(merr)
}

func manageFirewallRule(ruleName string, action action, extraArgs ...string) error {
	args := []string{"advfirewall", "firewall", string(action), "rule", "name=" + ruleName}
	if action == addRule {
		args = append(args, extraArgs...)
	}
	netshCmd := wincmd.System32("netsh")
	cmd := exec.Command(netshCmd, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Run()
}

func isWindowsFirewallReachable() bool {
	args := []string{"advfirewall", "show", "allprofiles", "state"}

	netshCmd := wincmd.System32("netsh")

	cmd := exec.Command(netshCmd, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	_, err := cmd.Output()
	if err != nil {
		log.Infof("Windows firewall is not reachable, skipping default rule management. Using only user space rules. Error: %s", err)
		return false
	}

	return true
}

func isFirewallRuleActive(ruleName string) bool {
	args := []string{"advfirewall", "firewall", "show", "rule", "name=" + ruleName}

	netshCmd := wincmd.System32("netsh")

	cmd := exec.Command(netshCmd, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_, err := cmd.Output()
	return err == nil
}
