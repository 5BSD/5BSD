# serviced

`serviced(8)` is 5BSD's system service manager. `authorityd(8)` starts one
supervised instance and supplies descriptor-based authority for service
launches. `serviced` owns bundle discovery, explicit boot and IPC activation,
readiness, restart policy, storage leases, and the administrative control
socket. The authoritative pre-v1 target is the dependency-free demand model in
`docs/service-architecture-plan.md`.
Any remaining internal startup-edge graph is implementation debt, not manifest
ABI or a supported dependency facility.

## Boot and registry model

At startup `serviced` runs the transitional `/etc/rc autoboot` oneshot, scans
root-owned bundles in `/Capabilities/System` and `/Capabilities`, validates the
complete graph, starts units declaring `activation.boot=true`, then reports
boot convergence to `authorityd`. Units that declare only `activation.ipc` start
on the first lookup of one of their reserved names.

Installed versions are immutable directories named
`<bundle-id>@<20-digit-sequence>.cap`. The registry selects the highest
sequence for each identity regardless of directory enumeration order. Equal
sequences, user/system identity collisions, duplicate unit labels, duplicate
IPC names, unknown descriptor providers, and dependency cycles fail the
replacement scan today. The startup-edge and cycle checks are scheduled for
removal as local factories become ordinary IPC-activated providers. A failed
reload leaves the previous registry running.

See [Capability bundle manifests](manifests.md) for the complete two-level
`Bundle.ucl` and `Units/<name>.unit/Unit.ucl` format.

## Launch and lifecycle

Each native unit is launched with `pdfork(2)`. Before releasing the child,
`serviced` mints every declared capability, creates a
coalition, installs a versioned bootstrap envfd, and applies the requested
credentials. This *launch-time* capability minting is
fail-closed: partial construction is rolled back and the program never receives
an incomplete authority set.

Distinct from launch minting is **session minting** — handing an authenticated
login a scoped session lookup channel. `serviced` no longer honors
`SVC_OP_MINT_DOMAIN` on an ambient lookup channel; that path is retired. The
only minter of session channels is the [auth-agent](../security/session-mint.md)
(`system.authagent`), itself an ordinary serviced-managed unit, which mints over
its own bootstrap channel. `login`/`su`/`sshd` ask the agent rather than minting
for themselves.

```text
STOPPED -> STARTING -> RUNNING -> STOPPING -> STOPPED
                    \-> DONE (oneshot)
```

`RUNNING` requires both the service protocol check-in and independently
observed capability-mode entry. Restart policies are `never`, `always`, and
`on-failure`. Rapid failures use bounded backoff and the `max_failures` circuit
breaker. Shutdown drains manager-visible demands and owned sessions and
escalates from graceful termination to `SIGKILL` after `stop_timeout`; there
is no dependency graph to reverse.

Storage lifetimes are `persistent`, `cache`, `boot`, and `lease`. Shared lease
storage is destroyed only when its last launched holder exits. Manager-session
and boot-generation reconciliation recover abandoned lease/boot datasets after
a crash or reboot without treating a `tzfsd` restart as a reboot.

## Capability services and global IPC

A unit needs no manifest declaration to use a capability service. It links the
matching typed library and reaches the service lazily, on first use, over
`service_connect()`:

| Library | Service |
| --- | --- |
| `liblogcmp` | `system.Log` |
| `libnotify` | `system.Notify` |
| `libtracecmp` | `system.Trace` |
| `libnetworkcmp` | `system.Network` (bounded DNS plus connected, rights-limited sockets) |
| `libcryptocmp` | `system.Crypto` |

Each provider is an ordinary supervised bundle that publishes its
reverse-domain name in `activation.ipc` and answers with
`service_provider_expose()`. Every successful connect yields a fresh, direct,
transfer-confined session; the supervisor is not a data-plane proxy. Publishing
a name does not imply boot activation — a provider stays stopped until its first
lookup.

Storage is not delivered by the manifest. A unit opens the `system.Filesystem`
service (`tzfsd`) at runtime and receives its own dataset — scoped to its
unforgeable channel label — as a rights-limited `zfshandle`, which it mounts
lazily with `service_storage_open()` and holds for its lifetime (the handle
anchors the mount).

### Private helpers

A bundle may ship a *private helper*: a unit marked
`activation { helper = true }` that publishes no `system.*` name and is launched
only on request by a sibling unit in the same bundle, through
`service_helper_open("<unit>")`. `serviced` resolves it under a synthetic
bundle-local name that ordinary global lookup cannot reach, activates it on
demand, and returns a confined channel. The helper joins its parent's coalition
and so shares its lifetime — an XPC-style privilege-separation boundary that
stays inside the bundle.

## Administration and installation

```sh
servicectl verify /path/to/App.cap
servicectl install /path/to/App.cap
servicectl reload
servicectl status
servicectl services
servicectl bundles
servicectl start org.example.app/worker
servicectl stop org.example.app/worker
```

`verify` is side-effect free. `install` requires root, copies without following
symlinks, accepts only directories and regular files, enforces bundle tree
limits, normalizes ownership and writable bits, syncs every staged object,
verifies the staged bytes, and atomically renames them to the canonical version
path. Existing sequences are never overwritten. `reload` activates the
highest valid sequence. Older immutable directories may remain while pinned by
a running process or until garbage collection, but serviced has no rollback or
historical-version selection interface.

The control socket is `/var/run/serviced.sock`. Mutating operations require
root. Requests and replies are fixed-size and bounded. Descriptor headroom is
reserved before each launch so `EMFILE` cannot leave a partial launch.

## Program API

Managed programs use `libservice(3)`. Providers explicitly authorize minted
capabilities, install capprotect restrictions, expose IPC listeners, enter
capability mode, and report readiness. Consumers reach a service through its
typed library — `liblogcmp`, `libnotify`, `libtracecmp`, `libnetworkcmp`,
`libcryptocmp` — which connects lazily on first use.

Socket, timer, path, calendar (`schedule`), `queue_directory`, and `on_mount`
activation are all implemented demand sources; only user-domain schedules
remain future work. Dependency targets are not planned. The only current
compatibility boundary is the deliberately isolated `/etc/rc` bootstrap needed
to boot the existing base system.
