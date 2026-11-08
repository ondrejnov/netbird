# Concurrent profiles: technical design

This document explains how the fork lets one NetBird daemon keep several profiles connected at
the same time. The user-facing behavior is described in the [README](../README.md); the binding
design with all decisions, findings, and the phase plan is the
[specification](specs/concurrent-profiles.md) (Czech).

## Contents

- [The problem](#the-problem)
- [Architecture: one daemon, N sessions](#architecture-one-daemon-n-sessions)
- [Session layer in the daemon](#session-layer-in-the-daemon)
- [Slots and resource naming](#slots-and-resource-naming)
- [Host coordinator](#host-coordinator)
- [Isolation between networks](#isolation-between-networks)
- [DNS](#dns)
- [Daemon IPC and authorization](#daemon-ipc-and-authorization)
- [Lifecycle, persistence, and crash recovery](#lifecycle-persistence-and-crash-recovery)
- [Feature gate and compatibility](#feature-gate-and-compatibility)
- [Windows](#windows)
- [Scaling](#scaling)
- [Invariants and tests](#invariants-and-tests)

## The problem

Upstream NetBird assumes exactly one connection per host. Running a second engine next to the
first one does not just fail, it damages the first one:

| Area | What happens with two engines |
| --- | --- |
| Daemon state | `Server` has a single `actCancel`, `clientRunning`, and `connectClient`. `Up` with a running connection returns before it even reads the requested profile |
| Interface | Every profile stores `wt0`, and creating the link deletes an existing link of the same name |
| Routing (Linux) | Start or stop of any engine flushes the whole routing table `0x1BD0` and deletes the ip rules 105 and 110. The other engine's refcounter does not notice and never restores its routes |
| Sysctl, IP forwarding | Global "original value" variables are overwritten, so the second engine saves already changed values as the originals |
| nftables, iptables | Same table `netbird`, same chain and ipset names. Init and close of one engine delete the other engine's rules, including its accept tags in foreign chains |
| DNS | One `resolv.conf` and one backup, Windows NRPT keys removed by prefix, macOS scutil keys without an owner |
| Port | `freePort` checks and closes a socket, so concurrent starts race for the same port |
| SSH config | One `99-netbird.conf` file |

Some properties that are harmless with one network become security problems with two, and the
design turns them into invariants:

- **Transit**: a routing peer has `ip_forward=1`, so a peer of network A could send packets into
  network B through this host.
- **Weak host model**: Linux delivers a packet that arrives on `wt0` locally even when it is
  addressed to the IP of `wt1`.
- **Metadata leaks**: the system info sent to Management excludes only the session's own
  overlay address, so the address of the other network would leak to the first Management.
- **ICE candidates**: the interface blacklist matches by prefix, so a custom interface name
  could end up in ICE candidates of a foreign network.

## Architecture: one daemon, N sessions

The community proposal in [netbirdio/netbird#446](https://github.com/netbirdio/netbird/issues/446)
was to run N independent daemons. The fork runs **one daemon with N sessions** instead, because
several host resources cannot be shared correctly between processes:

| Problem | N daemons | One daemon |
| --- | --- | --- |
| Exit node in A, specific route in B | Each daemon has its own table, and `ip rule` order beats longest-prefix match: `0.0.0.0/0` in the first table shadows the specific route in the second | One shared table `0x1BD0`, LPM works across sessions |
| Control traffic | Different fwmark bases per process, so packets of A can be captured by B's table (tunnel in tunnel) | One shared `ControlPlaneMark`, all control traffic bypasses the table |
| Host coordination (exit node, DNS catch-all, overlay conflicts) | Needs an inter-process protocol and locks | A mutex and refcounts in one process |
| Profiles and UX | A state dir per instance breaks the profile model; UI and CLI talk to several sockets | Profiles stay as they are, one socket |
| Process crash | Isolated | Shared fate (the weak spot of this design) |

```text
Server (daemon)
├── sessions map[SessionKey]*session     key = profile + OS user
├── focused SessionKey                   target of RPCs without a selector
├── host *hostcoord.Coordinator          shared host resources
├── isolation *firewall.SessionIsolation separation between sessions
└── daemon-global: logs, MDM, updater, sleep handler, IPC

session
├── config, ConnectClient, peer.Status, context state
├── lifecycle lock, actCancel, run channels
├── OAuth / JWT / extend-auth flows, capture
└── slot (interface name, port, firewall names)
```

`SessionKey` contains the OS user as well as the profile, because legacy profile IDs are not
unique across users.

## Session layer in the daemon

Code: `client/server/session*.go`, `client/internal/session_host.go`.

- **Identity is passed down, never re-read.** Upstream `connect()` and `run()` re-read the
  active profile, so a retry after a profile switch could combine the old config with the new
  profile's state file. Under a session, nothing reads the active profile; the state path is
  derived from the session key.
- **Each session owns its run state**: cancel function, running and give-up channels, auth
  flows, JWT cache, packet capture. Secrets and tokens are never shared (invariant I9).
- **Lock order** is `guardedConfigMu` → `session.lifecycle` → `Server.mutex` → `session.mu`.
  `session.mu` is a leaf. A start or stop holds the session's `lifecycle` lock, so it can release
  `Server.mutex` around slow steps (login, network waits) without blocking other sessions. The
  order is enforced by `lock_order_test.go`.
- **Focus.** `focused` is persisted as `active_profile.json`. Every RPC without a session
  selector targets the focused session, so old clients see one network exactly as before.
- **Daemon-wide subsystems** walk all sessions: the sleep handler suspends and wakes every
  session, an MDM restart restarts all of them. The auto-update manager is only given to the
  focused session.
- **Failure scope.** A normal session failure (login, retry, conflict) never affects the others.
  A panic cannot be contained, since `recover` only catches its own goroutine and the engine
  starts many; the daemon dies and restores the sessions from `sessions.json` after restart.

## Slots and resource naming

Code: `client/internal/hostcoord/slots.go`, `client/firewall/nftables/session_names_linux.go`.

On first start a session gets a **persistent slot**: the lowest free non-negative number. The
slot is stored in `sessions.json` and released only when the profile is removed, so a profile
keeps its interface and port across restarts. The slot number is not tied to the session limit:
slot 7 can run under a limit of 4.

| Resource | Slot 0 | Slot N |
| --- | --- | --- |
| Interface | `wt0` | `wtN` |
| Port | `51820` | `51820+N` when free and ≤ 65535, otherwise from the allocator |
| nftables table | `netbird` | `netbird-N` (passed to the constructor, not the process-wide env var) |
| Accept tag in a foreign chain | unchanged | suffix `-N`; start and stop delete only their exact tag |
| iptables chains, ipsets | unchanged | suffix `-N` |
| SSH client config | `99-netbird.conf` | `99-netbird-N.conf` |

**Slot 0 is byte-for-byte identical to upstream.** Backward compatibility depends on it.
`wt0` in a profile config means "automatic", resolves to the slot name, and is never written
back, so profile config files keep their format. An explicit custom interface name is refused
with the gate on (`conflict=interface`): a collision with a running session would otherwise
mean deleting its link. Port and slot allocation runs under a short lock (`bringUpMu`) that
covers only the allocation, which removes the `freePort` race without serializing whole starts.

## Host coordinator

Code: `client/internal/hostcoord/`. A daemon-wide object passed as a dependency, not a global;
tests and foreground mode create their own instance.

### Routing base

The parts of routing that every session shares (ip rules 105 and 110, sysctls, IP forwarding,
`nf_conntrack_acct`) are reference-counted in `AcquireRoutingBase` / `ReleaseRoutingBase`:
they are set up on the 0→1 transition and torn down on 1→0. Engine `Init` and `Stop` no longer
call the blanket `CleanupRouting` while another session runs. `nbnet.Init` runs once at daemon
start, so a probe in one session cannot switch the whole process to legacy routing.

### Routes

All sessions share table `0x1BD0`; routes are told apart by `dev`. `Routes` tracks claims per
prefix:

- The first session that claims a prefix **owns** it and installs it. Others queue as waiters.
- When the owner leaves, the next waiter is **promoted** and its route installed immediately,
  instead of relying on a refcounter that only calls add on 0→1. A failed handover stays queued
  and is retried on the next operation.
- A route that covers another session's overlay is refused (`route_overlay_refused`); the
  self-check `isOwnAddress` knows all overlay prefixes, not only its own.
- **Exit node**: one per machine, first wins. The owner also owns `unreachable ::/0` in the
  shared table. Default prefixes are not handed over when the owner leaves; traffic falls back
  to the physical default route.

### Sessions registry

`Sessions` holds the interface and overlay prefixes of every running session. It feeds:

- the overlay conflict check (`OverlayPrefixesExcept`),
- the ICE interface blacklist and the system info sent to Management, which exclude **all**
  NetBird interfaces and overlay addresses (invariant I5),
- the network monitor, whose next-hop lookup skips all NetBird interfaces, so a change in one
  session cannot restart another (I8),
- the userspace firewall through `IsolationSource`, an immutable snapshot rebuilt on change so
  the per-packet path takes no lock and allocates nothing.

### Overlay conflicts

After login and before the engine is created, the session's IPv4 overlay is checked against all
running sessions. An overlap is a permanent refusal (`conflict=overlay`); the check runs again
when Management changes the address. An overlapping IPv6 overlay only drops the session's v6,
since IPv6 is a soft feature and must never break v4.

## Isolation between networks

Code: `client/firewall/session_linux.go`, `client/firewall/nftables/isolation_linux.go`,
`client/firewall/iptables/isolation*_linux.go`, `client/firewall/uspfilter/`.

Two rules keep networks apart:

- **I3, no transit**: forwarding between two different NetBird interfaces is dropped, also on a
  routing peer and also when a route ACL would allow the destination in the other network.
- **I4, no weak host**: a packet arriving on a session interface and addressed to any session
  overlay is dropped, unless the pair (interface, address) is that session's own.

### nftables

One dedicated table `inet netbird-iso` with a fixed rule set. Sessions never change rules, only
the content of sets:

| Set | Content |
| --- | --- |
| `ifaces` | interface names of all sessions |
| `hairpin` | `(iif, oif)` pairs that are the same interface |
| `overlays`, `overlays6` | overlay prefixes of all sessions |
| `own`, `own6` | `(ifname . prefix)` pairs each session owns |

```text
forward: iif ∈ ifaces, oif ∈ ifaces, (iif . oif) ∉ hairpin           → drop   (I3)
input:   iif ∈ ifaces, daddr ∈ overlays, (iif . daddr) ∉ own          → drop   (I4)
```

Netfilter compares a register only with a constant, which is why "the interfaces differ" is
expressed as a lookup in a set of identical pairs. A drop in any table is final, so the
isolation holds whatever the table order, and an accept in a session's own table cannot lift
it. The rule count stays constant as sessions come and go, and all NetBird tables are excluded
when the firewall looks for foreign chains to insert its accept rules into.

### Other backends

- **iptables** builds the same rules with ipsets. Missing ipset modules mean the session does
  not start; there is no fallback path.
- **No native firewall**: the userspace filter (`uspfilter`) and the forwarder consult the
  `IsolationSource` snapshot per packet. An error or a snapshot that does not validate denies.
- **Netstack and legacy routing** are refused with the gate on.

### Fail closed

The isolation is installed **before** the session gets any peers. If it cannot be installed,
the session does not start (I6). The kernel state is verified every 5 seconds: a difference is
restored and reported as `isolation_restored`; a failed restore stops all sessions.

## DNS

Code: `client/internal/hostcoord/dns.go`, `client/internal/dns/`.

`DNSOwners` arbitrates three things: the catch-all (`RouteAll`), the host DNS on backends that
cannot be merged, and match domains.

| Backend | Match domains | Catch-all |
| --- | --- | --- |
| systemd-resolved | Per link. Queries go to every link with the domain; a positive answer wins, a name in both networks is a race | One owner |
| NetworkManager | Per link | One owner |
| resolvconf (openresolv) | Behaves like `file` because of `-x`: one session owns host DNS | One owner |
| `/etc/resolv.conf` (file) | Cannot be merged: one session owns host DNS | One owner |

- Capturing the "original" nameservers skips **all** NetBird interfaces, so one session never
  records another session's resolver as the upstream.
- A session without host DNS keeps working by IP and reports `conflict=dns`.
- Sessions sharing a DNS domain get the `dns_domain_shared` warning; domains served by more than
  one session are tracked per session and released when it leaves.
- Per-session state that upstream kept global (DNS MTU, the firewalld context, the certificate
  proof slot) is moved into the session.

## Daemon IPC and authorization

Code: `client/proto/daemon.proto`, `client/server/session_access*.go`.

The proto is only extended. New fields in existing messages start at **1000**, so they cannot
collide with fields upstream adds after a merge.

```proto
message SessionSelector {
  string profile = 1;   // ID, unique ID prefix, or name
  string username = 2;
}

message DownRequest   { optional SessionSelector session = 1000; bool all = 1001; }
message StatusRequest { optional SessionSelector session = 1000; }
message StatusResponse {
  // fields 1-4 still describe the focused session
  repeated SessionStatus sessions = 1000;
}
```

A selector was added to every RPC that acts on a connection (networks, SSO and JWT flows,
packet trace and capture, SSH host keys, expose, state management). `GetFeaturesResponse`
reports `concurrent_profiles_enabled` and `max_sessions`, so a new client can tell whether the
daemon supports sessions and an old client keeps working (I10).

Authorization happens **in the handler**, never in the client:

- The caller identity comes from the kernel via `ipcauth.CallerIdentity` (`SO_PEERCRED` on
  Linux, the named-pipe token on Windows), never from the `username` field.
- An unprivileged caller controls and reads only its own sessions and the shared `default`.
  `Status.sessions` and `Down{all}` are filtered the same way.
- An unknown identity is denied. With the gate on, the daemon refuses to start on a TCP socket,
  where there is no caller identity.
- `Down` and `Status` without a selector keep the upstream behavior and act on the focused
  session.

`SubscribeStatus` with the gate on watches the recorder of every session the caller can reach
and pushes a snapshot when any of them changes, which is what the desktop UI uses.

## Lifecycle, persistence, and crash recovery

`<config>/sessions.json` stores, per session, the profile, OS user, slot, and desired state. It
holds no secrets. Unknown fields or a corrupt file refuse the service start and the file stays
in place for repair. Access is serialized with `flock` (`LockFileEx` on Windows).

On daemon start with the gate on:

1. Residual cleanup runs for **all** profiles in `sessions.json` before the first session is
   created: state files, leftover links of the slots, leftover isolation.
2. Sessions whose desired state is up are restored, then the focused one.
3. A residual cleanup triggered by `Up` handles only that session's own state file and never
   flushes marked routes while another session runs.

`netbird up --profile X` creates the session if needed, allocates the slot, stores the desired
state, and moves the focus. If the session is refused (limit, conflict), the focus goes back to
the session that had it before. `down` stops only the selected sessions; when the last one
leaves, the routing base is torn down and the host returns to its original state (I7).

## Feature gate and compatibility

`netbird service install|reconfigure --enable-concurrent-profiles`, stored in `service.json` and
applied on service restart. Off by default.

| | Gate off | Gate on |
| --- | --- | --- |
| `Up(profile)` | Switches the profile like upstream | Starts another session |
| `SwitchProfile` | Like upstream | Moves the focus only |
| RPC selecting a non-active profile | `FailedPrecondition` | Targets that session |

With the gate off, nothing changes (I1): same names, same rules, same file formats. Turning the
gate off cleans up the leftovers of every slot on the next start and reconnects only the focused
profile under its slot 0 names; `sessions.json` is kept read-only for a later re-enable.

The fork build (tag `multiprofile`) is versioned distinctly (`+multiprofile`), disables
auto-update and the lookup of the official package repository, and ships as the
`netbird-multiprofile` package, so an official release cannot silently replace it.

## Windows

Windows reuses the same design with platform-specific naming:

| Resource | Slot 0 | Slot N |
| --- | --- | --- |
| Wintun adapter | `wt0`, today's GUID | `wtN`, GUID `uuid.NewSHA1(<slot 0 GUID>, "slot-N")` |
| Firewall rules (netsh) | `Netbird`, `Netbird-v6` | `Netbird-N`, `Netbird-N-v6` |
| NRPT keys | `NetBird-Match-*` | `NetBirdS<N>-Match-*` |

Deriving the adapter GUID from the slot lets crash cleanup work from `sessions.json` alone. The
NRPT prefix deliberately does not start with `NetBird-`, so slot 0's prefix-based cleanup cannot
delete it. Each NRPT domain and each route prefix has one owning session, because Windows applies
only the alphabetically first NRPT key for a namespace. Isolation uses the userspace filter plus
kernel adapter flags (`Forwarding`, `WeakHostReceive`, and `WeakHostSend` disabled), and a foreign
adapter with a slot's name is refused rather than deleted.

## Scaling

The default limit of 4 sessions is the only thing that bounds the count: one check in `Server`,
a constructor parameter where 0 means unlimited. Nothing else may assume a maximum: no
fixed-size arrays, no single-digit suffixes, and no per-session host resource unless necessary.
Fwmarks, the routing table, and rules 105/110 stay shared.

| Resource | Capacity |
| --- | --- |
| Interface name | `wt` + number, 15 characters on Linux, always validated |
| iptables chain | longest `NETBIRD-RT-MSSCLAMP` is 19 of 28 characters; the generator checks the suffix |
| Isolation | constant rule set, only sets grow |
| nftables hooks | measured: 16 sessions add 3–6 µs RTT locally and 6–8 µs when forwarding |
| Restart on network change | 16 sessions with a local Management come up within 2.7 s |

## Invariants and tests

Every invariant has a test; the privileged ones run in their own network namespace through
`make test-privileged`.

| ID | Invariant |
| --- | --- |
| I1 | Gate off: same behavior, names, rules, and file formats as upstream |
| I2 | Start, stop, restart, or crash of a session does not change another session's routes, firewall, or DNS |
| I3 | A peer of A cannot reach B through this host, even on a routing peer (tested with real engines and packets) |
| I4 | A peer of A cannot reach a local service through B's IP |
| I5 | Addresses and flows of another session never go to Management, Signal, Flow, or ICE candidates |
| I6 | A failing security check refuses; a session without isolation never starts |
| I7 | After the last session ends, or after a crash, the host returns to its original state |
| I8 | A change in one session does not restart another through the network monitor |
| I9 | Secrets, tokens, JWT cache, and SSO flows belong to one session |
| I10 | An old client works with the new daemon and a new client with the old daemon |
