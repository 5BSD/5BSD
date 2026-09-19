# switchboard

`switchboard(8)` is 5BSD's system service manager. `capsule(8)` starts one
supervised instance and supplies descriptor-based authority for service
launches; `switchboard` owns bundle discovery, boot and demand activation,
readiness, restart policy, and the administrative control socket. It holds no
capabilities of its own — it is a pure launcher and naming switchboard. The
demand model is deliberately dependency-free: there is no dependency graph.

## Boot and registry

At startup `switchboard` runs the transitional `/etc/rc autoboot` oneshot (see
[Coexistence with rc](capsule.md#coexistence-with-rc)), scans root-owned
bundles in `/Capabilities/System` and `/Capabilities`, validates the registry,
starts units declaring `activation.boot=true`, then reports convergence to
`capsule`. Units that declare only `activation.ipc` start on the first
lookup of one of their reserved names.

Installed versions are immutable directories named
`<bundle-id>@<sequence>.cap`; the registry selects the highest sequence per
identity, and a failed reload leaves the previous registry running. See
[Capability bundle manifests](manifests.md) for the format.

## The /Capabilities hierarchy

The capability plane is laid out **by capability, not by type** — no
`/Capabilities/run`, `db`, or `log`. Every capability is a static half and a
dynamic half:

```text
/Capabilities/
├── System/            shipped bundle definitions      static, read-only, at boot
│   └── <Name>.cap         binary, manifest, config defaults
├── Config/            minimal pre-storage config      static, admin-mutable
│   ├── BSDFilesystem.ucl          storage pool + layout
│   ├── principal-policy.ucl  what a login session holds (auth agent)
│   └── switchboard/disabled  operator disable list
└── <Name>/            per-capability runtime home     BSDFilesystem-provisioned, at runtime
    ├── control.sock / state/ / cache/ / log/
```

Runtime homes are provisioned by [`BSDFilesystem`](../storage/trustedzfs.md) as distinct
handles, so capabilities cannot see into one another's state — the isolation
is structural. `Config/` is the one static exception: `BSDFilesystem` and `switchboard`
run *before* the storage plane exists, so their bootstrap config (plus
`principal-policy.ucl`, read by the
[auth-agent](../security/authority-model.md); an absent policy falls back to
root-or-`wheel` holds everything) lives on the root dataset. The bootstrap itself
rides inherited capability descriptors, never a named socket, so it can never
block on an unmounted directory. Classic UNIX programs keep `/etc`, `/var`,
and `/usr` unchanged; only the rc hand-off crosses the boundary.

## Launch and lifecycle

Each native unit is launched with `pdfork(2)`: `switchboard` sets up activation
tokens, creates a coalition, installs a versioned bootstrap envfd, and applies
the requested credentials before releasing the child. A unit declares no
capabilities in its manifest — it acquires what it needs at runtime, by name,
each grant scoped to its unforgeable channel label. Bootstrap construction is
fail-closed: partial construction is rolled back.

```text
STOPPED -> STARTING -> RUNNING -> STOPPING -> STOPPED
                    \-> DONE (oneshot)
```

`RUNNING` requires both the service protocol check-in and independently
observed capability-mode entry. Restart policies are `never`, `always`, and
`on-failure`, with bounded backoff and a `max_failures` circuit breaker.

Distinct from launch is **session minting** — handing an authenticated login a
scoped session lookup channel. The only minter of session channels is the
[auth-agent](../security/authority-model.md) (`system.auth`), itself an
ordinary switchboard-managed unit; `login`/`su`/`sshd` ask the agent rather than
minting for themselves. The minted channel carries the principal's anointment
set from `principal-policy.ucl`, and the same agent extends a session by one
name for one command through `anoint(1)`
([IPC Anointments](../security/ipc-anointments.md)).

## Capability services and global IPC

A unit needs no manifest declaration to use a capability service: it links
the matching typed client library and reaches the service lazily on first
use over `service_connect()`. Each
provider is an ordinary supervised bundle that publishes its name in
`activation.ipc`; it stays stopped until its first lookup. An `ipc` entry may
gate its endpoint on anointments the caller must hold; `switchboard` matches at
lookup and refuses a miss as `ENOENT` before any on-demand launch (see
[IPC Anointments](../security/ipc-anointments.md)). Every successful
connect yields a fresh, direct, transfer-confined session — the supervisor is
not a data-plane proxy. Writing a provider is covered in
[The Hybrid Model](../development/hybrid-model.md) and
[Writing a Service Provider](../development/writing-components.md).

Storage follows the same rule: a unit opens `system.Filesystem`
([`BSDFilesystem`](../storage/trustedzfs.md)) at runtime and receives its own dataset —
scoped to its channel label — as a rights-limited `zfshandle` it mounts with
`service_storage_open()`. `switchboard` holds no storage capability; it only
requests destruction of shared `lease` datasets when their last launched
holder exits, and reconciles abandoned datasets after a crash or reboot.

A bundle may also ship a **private helper**: a unit marked
`activation { helper = true }` that publishes no global name and is launched
only on request by a sibling unit via `service_helper_open("<unit>")`. It
joins its parent's coalition and shares its lifetime — an XPC-style
privilege-separation boundary inside the bundle.

## Administration

`switchboardctl(8)` is the operator tool: side-effect-free verification, staged
atomic installs, reload, status, and per-unit start/stop. Mutating
operations go through the control endpoints `system.switchboard` and
`system.lifecycle`, gated on the `system.switchboard.admin` anointment; the
shipped principal policy gives it to root and `wheel`, and an operator can
hold it from login or `anoint` it per command. `switchboardctl graph` draws
the anointment reach graph from the registry on disk, with `--lint` for
unreachable endpoints and dead declarations. Existing sequences are never
overwritten; there is no rollback or historical-version selection interface.

Reference: `switchboard(8)`, `switchboard(5)`, `switchboardctl(8)`.
