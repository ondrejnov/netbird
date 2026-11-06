//go:build linux

// Package isolatedhost runs a privileged test binary in network and mount namespaces of its own,
// so that its tests neither see nor change the firewall, routes, interfaces, sysctls, /etc and
// system bus of the machine. The tests then find the same host on a CI runner with Docker,
// systemd-resolved and a D-Bus system bus as in the container of the privileged harness.
package isolatedhost

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// envInside marks the copy of the test binary that runs in the namespaces of its own.
const envInside = "NB_TEST_ISOLATED_HOST"

// etcLayerPrefix names the dir of the layer over /etc, by which a process knows the namespaces.
const etcLayerPrefix = "nb-isolated-etc-"

// The host the tests were written against: the container of the privileged harness, whose
// resolv.conf has a search list of "." and whose rp_filter the host passes on as 2.
const (
	resolvConf = "nameserver 192.0.2.53\nsearch .\n"
	rpFilter   = "2"
)

// systemBusDirs hold the socket of the D-Bus system bus. A test that wants a bus starts its own.
var systemBusDirs = []string{"/run/dbus", "/var/run/dbus"}

// iptablesProbeChain is created and deleted again to make iptables create a table.
const iptablesProbeChain = "NB-ISOLATED-PROBE"

type host struct {
	iptablesTables bool
}

// Option changes the host the tests get.
type Option func(*host)

// WithIptablesTables gives the host the filter, nat and mangle tables of iptables and ip6tables
// with their built-in chains, as a host has them once anything used iptables. A fresh namespace
// has none.
func WithIptablesTables() Option {
	return func(h *host) { h.iptablesTables = true }
}

// Run runs the tests of m in a fresh network and mount namespace and returns the exit code for
// os.Exit. The first call starts the test binary again in the namespaces with the same arguments,
// so flags such as -test.run, -test.v and -test.coverprofile apply to the copy, and returns its
// code. In the copy it prepares the namespaces and runs the tests.
func Run(m *testing.M, opts ...Option) int {
	var h host
	for _, opt := range opts {
		opt(&h)
	}

	prepared, err := isPrepared()
	if err != nil {
		fmt.Fprintf(os.Stderr, "isolated host: %v\n", err)
		return 1
	}
	// A process a test starts from the binary, whatever its environment and account, inherits
	// the namespaces and runs in them as they are.
	if prepared {
		return m.Run()
	}

	inside, err := isInside()
	if err != nil {
		fmt.Fprintf(os.Stderr, "isolated host: %v\n", err)
		return 1
	}
	if !inside {
		return runInNamespaces()
	}

	cleanup, err := prepare(h)
	if err != nil {
		fmt.Fprintf(os.Stderr, "isolated host: prepare the namespaces: %v\n", err)
		return 1
	}
	code := m.Run()
	cleanup()
	return code
}

// isPrepared reports whether the process runs in namespaces prepare set up, which it tells by
// the layer over /etc.
func isPrepared() (bool, error) {
	raw, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return false, fmt.Errorf("read the mounts: %w", err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 4 && fields[4] == "/etc" && strings.Contains(line, etcLayerPrefix) {
			return true, nil
		}
	}
	return false, nil
}

func isInside() (bool, error) {
	val := os.Getenv(envInside)
	if val == "" {
		return false, nil
	}
	inside, err := strconv.ParseBool(val)
	if err != nil {
		return false, fmt.Errorf("parse %s: %w", envInside, err)
	}
	return inside, nil
}

func runInNamespaces() int {
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "isolated host: find the test binary: %v\n", err)
		return 1
	}

	// Pdeathsig follows the thread that started the copy, so that thread has to stay.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), envInside+"=true")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: unix.CLONE_NEWNET | unix.CLONE_NEWNS,
		Pdeathsig:  syscall.SIGKILL,
	}
	err = cmd.Run()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "isolated host: run the tests in their own namespaces: %v\n", err)
		return 1
	}
	return 0
}

// prepare sets up the fresh namespaces.
func prepare(h host) (func(), error) {
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		return nil, fmt.Errorf("find the loopback: %w", err)
	}
	// Only a network namespace that was just created has its loopback down. Anything else could
	// be the host, whose mounts must stay as they are.
	if lo.Attrs().Flags&net.FlagUp != 0 {
		return nil, fmt.Errorf("%s is set outside a fresh network namespace", envInside)
	}

	// Mounts must not reach the namespace of the host, which may share them.
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return nil, fmt.Errorf("make the mounts private: %w", err)
	}
	cleanup, err := mountOwnEtc()
	if err != nil {
		return nil, err
	}
	if err := hideSystemBus(); err != nil {
		cleanup()
		return nil, err
	}
	if err := os.WriteFile("/proc/sys/net/ipv4/conf/all/rp_filter", []byte(rpFilter), 0o600); err != nil {
		cleanup()
		return nil, fmt.Errorf("set rp_filter: %w", err)
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		cleanup()
		return nil, fmt.Errorf("bring up the loopback: %w", err)
	}
	if h.iptablesTables {
		if err := createIptablesTables(); err != nil {
			cleanup()
			return nil, err
		}
	}
	return cleanup, nil
}

func createIptablesTables() error {
	if err := createTables("iptables"); err != nil {
		return err
	}
	// A host without IPv6 has no ip6tables tables either.
	if err := createTables("ip6tables"); err != nil {
		fmt.Fprintf(os.Stderr, "isolated host: no ip6tables tables: %v\n", err)
	}
	return nil
}

func createTables(tool string) error {
	for _, table := range []string{"filter", "nat", "mangle"} {
		for _, action := range []string{"-N", "-X"} {
			out, err := exec.Command(tool, "-w", "-t", table, action, iptablesProbeChain).CombinedOutput()
			if err != nil {
				return fmt.Errorf("%s -t %s %s: %w: %s", tool, table, action, err, out)
			}
		}
	}
	return nil
}

// mountOwnEtc puts a writable layer over /etc, so what the tests write there, such as resolv.conf
// and its backup, stays in the namespace, and gives it a resolv.conf of its own.
func mountOwnEtc() (func(), error) {
	files, err := etcFileMounts()
	if err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp("", etcLayerPrefix)
	if err != nil {
		return nil, fmt.Errorf("create the dir of the /etc layer: %w", err)
	}
	removeDir := func() {
		if err := os.Remove(dir); err != nil {
			fmt.Fprintf(os.Stderr, "isolated host: remove %s: %v\n", dir, err)
		}
	}
	// An overlay cannot have its upper dir on an overlay, which the root of a container is.
	if err := unix.Mount("tmpfs", dir, "tmpfs", 0, "mode=0700"); err != nil {
		removeDir()
		return nil, fmt.Errorf("mount the tmpfs of the /etc layer: %w", err)
	}
	cleanup := func() {
		if err := unix.Unmount("/etc", unix.MNT_DETACH); err != nil {
			fmt.Fprintf(os.Stderr, "isolated host: unmount /etc: %v\n", err)
		}
		if err := unix.Unmount(dir, unix.MNT_DETACH); err != nil {
			fmt.Fprintf(os.Stderr, "isolated host: unmount %s: %v\n", dir, err)
		}
		removeDir()
	}

	upper, work := filepath.Join(dir, "upper"), filepath.Join(dir, "work")
	for _, d := range []string{upper, work} {
		if err := os.Mkdir(d, 0o755); err != nil {
			unmountDir(dir)
			removeDir()
			return nil, fmt.Errorf("create %s: %w", d, err)
		}
	}
	options := fmt.Sprintf("lowerdir=/etc,upperdir=%s,workdir=%s", upper, work)
	if err := unix.Mount("overlay", "/etc", "overlay", 0, options); err != nil {
		unmountDir(dir)
		removeDir()
		return nil, fmt.Errorf("mount the /etc layer: %w", err)
	}

	// The resolv.conf of a host with systemd-resolved is a link into /run, which is not layered.
	if err := os.Remove("/etc/resolv.conf"); err != nil && !errors.Is(err, os.ErrNotExist) {
		cleanup()
		return nil, fmt.Errorf("remove the resolv.conf of the host: %w", err)
	}
	files["/etc/resolv.conf"] = []byte(resolvConf)
	for path, content := range files {
		// Every account reads these, including the one a test drops its child process to.
		if err := os.WriteFile(path, content, 0o644); err != nil { //nolint:gosec
			cleanup()
			return nil, fmt.Errorf("write %s: %w", path, err)
		}
	}
	return cleanup, nil
}

// etcFileMounts reads the files mounted into /etc, such as the hosts file of a container, which the
// layer would hide.
func etcFileMounts() (map[string][]byte, error) {
	raw, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return nil, fmt.Errorf("read the mounts: %w", err)
	}
	files := make(map[string][]byte)
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 || !strings.HasPrefix(fields[4], "/etc/") {
			continue
		}
		path := fields[4]
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		files[path] = content
	}
	return files, nil
}

func unmountDir(dir string) {
	if err := unix.Unmount(dir, unix.MNT_DETACH); err != nil {
		fmt.Fprintf(os.Stderr, "isolated host: unmount %s: %v\n", dir, err)
	}
}

// hideSystemBus covers the socket of the system bus, so no test reaches systemd-resolved,
// NetworkManager or firewalld of the host.
func hideSystemBus() error {
	for _, dir := range systemBusDirs {
		info, err := os.Stat(dir)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("stat %s: %w", dir, err)
		}
		if !info.IsDir() {
			continue
		}
		if err := unix.Mount("tmpfs", dir, "tmpfs", 0, "mode=0755"); err != nil {
			return fmt.Errorf("cover %s: %w", dir, err)
		}
	}
	return nil
}
