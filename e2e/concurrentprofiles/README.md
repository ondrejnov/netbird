# Concurrent profiles E2E test

The acceptance scenario of [the specification](../../docs/specs/concurrent-profiles.md#akceptační-scénář-linux-cli-v1)
on real containers: two Management servers, a peer in each network and a daemon with
the feature gate on, driven only through the CLI in its container.

The test runs in four modes, kernel and userspace interface with nftables and iptables:

- `netbird up --profile` of both profiles, the same CLI a user runs.
- `netbird status` with both sessions, their interfaces and addresses.
- Ping to each peer, to a host behind a route of each network and back from each peer,
  with the route and the packet counter showing the interface it went through.
- `netbird down --profile doma`, after which the routes, rules, nftables, iptables,
  ipsets, sysctls, `resolv.conf` and the DNS answers of the other session are compared
  with what they were, and the interface of the other session is the same link.
- A network moved over the range of the other one is refused with `conflict=overlay`
  and without a change on the host, and comes back after the range is moved away.
- After `netbird down --all` the namespace is what it was before the first `up`.

The containers keep to themselves: every daemon serves its own socket path, and the
network namespace of the container is what the daemon changes.

On a machine you can rebuild, with Docker and Go available:

```bash
go test -tags e2e -timeout 25m -v ./e2e/concurrentprofiles/...
```

On a host whose networking matters, keep the test process in a container as well, see
[testing-privileged.md](../../docs/testing-privileged.md#running-an-e2e-suite-in-the-same-container).

The DNS backend in the container is the `file` one: there is no systemd-resolved or
NetworkManager in the image.
