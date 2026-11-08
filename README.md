<div align="center">

<img width="234" src="docs/media/logo-full.png" alt="NetBird logo"/>

# NetBird with concurrent profiles

**One machine, one daemon, several NetBird networks connected at the same time.**

[Features](#features) · [Requirements](#requirements) · [Getting started](#getting-started) · [Usage](#usage) · [Conflicts](#conflicts) · [Limitations](#known-limitations)

</div>

This is a fork of [netbirdio/netbird](https://github.com/netbirdio/netbird) that lets the
NetBird client keep **multiple profiles connected concurrently**. Upstream NetBird connects one
profile at a time, and switching profiles drops the previous connection. In this fork, each
profile runs as its own session with its own identity, interface, ACLs, routes, and DNS, and
bringing one session up or down leaves the others untouched.

> [!IMPORTANT]
> This fork targets **self-hosted Management only**. NetBird Cloud is neither supported nor
> tested. Management, Signal, and Relay are unchanged; all the work is in the client.

> [!NOTE]
> The feature sits behind a gate that is **off by default**. With the gate off, the client
> behaves exactly like upstream, with the same interface names, firewall rules, and files.

## Features

- **Concurrent sessions**: connect to work, home, and lab networks at once, each on its own
  interface (`wt0`, `wt1`, ...).
- **Isolation between networks**: traffic cannot transit from one overlay to another, and each
  session owns only its own firewall table, routes, and DNS records.
- **Stable slots**: a profile gets a persistent slot on first start, so its interface name and
  port stay the same across restarts.
- **Focus model**: commands without `--profile` act on the *focused* session, so existing
  scripts and older UIs keep working.
- **Per-user access**: unprivileged users control and read only their own sessions plus the
  shared `default` profile.
- **Explicit conflict handling**: overlapping overlay ranges, duplicate DNS domains, competing
  exit nodes, and shared route prefixes are detected and reported instead of silently breaking
  connectivity.
- **Desktop UI support**: the profile dropdown and tray show the state of every session and can
  disconnect each one separately.
- **Byte-for-byte compatible slot 0**: the first session uses the same names as upstream, so
  upgrading with the gate off changes nothing.

## Platform support

| Platform | Status |
| --- | --- |
| Linux | Supported (CLI and desktop UI) |
| Windows | Supported behind the gate, manual build only |
| macOS, FreeBSD | Builds and behaves like upstream; the gate is refused |
| Android, iOS, WASM, embedded client | Out of scope, unchanged |

## Requirements

On Linux, a session refuses to start with the gate on when any of these holds:

| Condition | Fix |
| --- | --- |
| Netstack mode (`NB_USE_NETSTACK_MODE`) | Disable netstack |
| Legacy routing (no fwmark rule support) | Use a kernel with fwmark rules, then restart the service |
| `NB_DNS_STATE_FILE` is set | Unset it; all sessions would share one state file |
| Kernel older than 5.6 | Upgrade the kernel |
| iptables without ipset modules | Install the ipset modules |
| Explicit `interface_name` in the profile | `netbird up --profile X --interface-name wt0` (`wt0` means "use the slot name") |
| No native firewall and the session firewall is disabled | Install nftables or iptables, or keep the session firewall on |

## Getting started

### Build and install (Linux)

The fork is built and installed separately and never published to the official package
repository:

```bash
goreleaser release --snapshot --clean --config .goreleaser_multiprofile.yaml
sudo apt install ./dist/*.deb          # or the .rpm
netbird version                        # e.g. 0.70.1+multiprofile
```

The `netbird-multiprofile` package conflicts with and replaces `netbird`, installs the same
binary and service, and keeps `/var/lib/netbird`. Auto-update and the lookup on
`pkgs.netbird.io` are disabled in this build so an official release cannot overwrite it.

<details>
<summary>Windows (manual build, test VM)</summary>

```powershell
cd client; go build -tags multiprofile -o netbird.exe .   # put wintun.dll next to the binary
# elevated terminal
.\netbird.exe service install --enable-concurrent-profiles; .\netbird.exe service start
```

</details>

### Enable the gate

New service installation:

```bash
sudo netbird service install --enable-concurrent-profiles
sudo netbird service start
```

Existing service (reinstalls and restarts it, so all connections drop):

```bash
sudo netbird service reconfigure --enable-concurrent-profiles
```

The setting is stored in `service.json` and takes effect after a service restart.

> [!WARNING]
> The client rewrites routing, firewall, and DNS on the host. Try the fork in a VM or another
> disposable environment first.

## Usage

```bash
netbird up --profile work --management-url https://mgmt.work.example --setup-key <key>
netbird up --profile home --management-url https://mgmt.home.example --setup-key <key>
netbird status
ping <work-peer>                       # goes through wt0
ping <home-peer>                       # goes through wt1
netbird down --profile home            # routes, firewall, and DNS of "work" stay untouched
```

`netbird status` adds a table of sessions:

```text
Sessions:
  default  NeedsLogin  -    -
  home     Connected   wt1  100.72.253.109/16  focused, conflict: dns
  work     Connected   wt0  100.71.231.76/16
```

| Command | Behavior with the gate on |
| --- | --- |
| `netbird up --profile X` | Starts session X and moves focus to it; other sessions keep running. Creates the profile if missing |
| `netbird down` | Disconnects the focused session and lists what is still running |
| `netbird down --profile X` / `--all` | Disconnects the named session, or all sessions the caller can reach |
| `netbird status [--profile X]` | Summary of all sessions or of X; JSON output adds a `sessions` field |
| `netbird profile select X` | Moves focus only, disconnects nothing |
| `netbird profile list` | Includes the connection state |
| `netbird profile remove X`, `deregister` | Refused for a running session; run `netbird down --profile X` first |
| `networks`, `debug`, `ssh`, `expose` | Accept `--profile`, default is the focused session |

The default limit is **4 sessions**; above it, `up` returns `ResourceExhausted`.

## Conflicts

| Conflict | Behavior |
| --- | --- |
| Overlapping IPv4 overlay | The new session does not start (`conflict: overlay`) |
| Overlapping IPv6 overlay | The new session skips IPv6 and runs on IPv4 |
| Same route prefix | The first session owns it; it moves to the next one when the owner leaves |
| Route covering another session's overlay | The route is refused |
| Exit node | One per machine, first wins (`conflict: exit_node`) |
| Same DNS domain | systemd-resolved: non-colliding names work in both networks. Other backends: the first session owns the domain (`conflict: dns`), IPs still work |
| Session limit | `up` returns `ResourceExhausted` |

> [!TIP]
> Self-hosted networks pick a random `/16` from `100.64.0.0/10`, so two independent networks
> collide with a probability of 1/64. Change `network_range` (and `dns_domain`, since older
> installations all default to `netbird.selfhosted`) in the account settings of one of the
> networks to resolve it. Changing the range renumbers every peer in that network.

## Known limitations

- A panic in one session takes down the daemon and all networks; sessions that were up are
  restored after the service restarts.
- The SSH client config of every session (`/etc/ssh/ssh_config.d/99-netbird-N.conf`) is
  world-readable, as in upstream, so local users can see peer IPs and names of other sessions.
- Older desktop UIs only see the focused session; switching profiles there leaves the previous
  session running and visible only in `netbird status`.
- Foreground mode (`netbird up --foreground-mode`) stays single-profile.
- Only the `file` DNS backend has been verified on a real host so far.

## Disable the gate

```bash
sudo netbird service reconfigure --enable-concurrent-profiles=false
```

After the restart, leftovers of all sessions are cleaned up and only the focused profile
reconnects, under its upstream names. Disable the gate before going back to an upstream package,
since upstream does not know `sessions.json` and would not clean up the extra slots.

## Documentation

- [User guide](docs/concurrent-profiles.md) (Czech): gate, usage, conflicts, upgrade, and rollback.
- [Specification](docs/specs/concurrent-profiles.md) (Czech): design, invariants, and phase plan.
- [Upstream documentation](https://docs.netbird.io/) for everything else NetBird does.

## Upstream

This fork tracks [netbirdio/netbird](https://github.com/netbirdio/netbird) and merges it
regularly. Do not report problems with concurrent profiles upstream, they exist only in
[this fork](https://github.com/ondrejnov/netbird). The licensing of the
upstream project applies unchanged; see [LICENSE](LICENSE) and the license files in
`management/`, `signal/`, and `relay/`.

_WireGuard_ and the _WireGuard_ logo are [registered trademarks](https://www.wireguard.com/trademark-policy/) of Jason A. Donenfeld.
