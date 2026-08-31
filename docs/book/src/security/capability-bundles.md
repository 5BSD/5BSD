# Capability bundles

A `.cap` bundle is 5BSD's install, configuration, resource, execution, and
authority boundary. It contains one `Bundle.ucl`, an exact inventory of one or
more `.unit` directories, their executables and resources, and optional shared
content. Mutable state is supplied separately as named storage descriptors.

The complete format and a fully populated example are in
[Capability bundle manifests](../system/manifests.md).

## Security properties

- Bundle metadata is declared once. Unit manifests cannot change bundle id,
  publisher, version, sequence, or the unit inventory.
- Activation is explicit (`boot`, `ipc`, or both); it is never inferred from a
  field with a second meaning.
- Programs are one regular executable below their unit's `bin` directory.
  Absolute paths, traversal, symlinks, and undeclared units are rejected.
- UCL is literal: includes, macros, file variables, duplicate keys, implicit
  arrays, and unknown fields fail closed.
- The loaded tree is root-owned and not group/world writable.
- Kernel authority is minted before execution and delivered by descriptor.
  Storage uses logical roles such as `storage:data`; applications never choose
  ZFS dataset paths.
- A unit's runtime identity is `<bundle-id>/<unit-name>`, independent of any
  IPC name it publishes.

## The `/Capabilities` tree

`/Capabilities` is a top-level directory whose skeleton is shipped by the base
system. The distribution `mtree` (`etc/mtree/BSD.root.dist`) creates the tree
with fixed ownership and mode on a fresh install, before `serviced` first runs;
the layout is verified by `mtree`/pkgbase rather than synthesised at runtime.

```text
/Capabilities/            0755 root:wheel  capability tree root
  System/                 0755 root:wheel  base-system bundles (pkgbase-installed *.cap)
  State/                  0700 root:wheel  durable mutable state
    serviced/             0700 root:wheel  serviced registry and unit state (versioned UCL)
  Run/                    0700 root:wheel  per-instance runtime container directories
```

`State/` and `Run/` are mode `0700 root:wheel`: only a process with that
authority — `serviced` — may traverse them. Site and administrator bundles may
also be placed directly under `/Capabilities/`.

`Run/` holds one **runtime container directory** per launched instance,
`Run/<unit-instance>/`, created before the process starts and removed when it
stops (and during crash reconciliation). A launched program cannot open its
container by pathname — it is confined to capability mode and the directory is
not world-reachable — so `serviced` passes an `O_DIRECTORY` descriptor into the
child's bootstrap and the program uses `*at(2)` calls relative to it. The
container is runtime state, never a source of authority, and is safe to delete
and recreate. It is distinct from provisioned storage leases, which are minted
TrustedZFS datasets delivered as `zfshandle` descriptors.

## Naming

A capability is identified by a hierarchical name in the `system.` namespace —
`system.Log`, `system.Network`, `system.Storage`, `system.Bluetooth`, and so on.
This name is what a program looks up to reach the capability and what a bundle
claims in order to provide it; it is declared once as the bundle's `bundle_id`
and on the listener the unit activates (`activation { ipc = ["system.Log"]; }`).

**The name is the contract.** A capability *is* its claimed name, not the daemon
behind it. To replace a provider — swap the storage broker, ship an alternate
logger — you publish a bundle that claims the same `system.<Capability>` name;
consumers are unaffected because they resolve the name, never the binary. This is
the decoupling launchd draws between a service label and its executable.

The `system.` prefix is reserved for base-system capabilities (it is also the
namespace casper uses — `system.pwd`, `system.syslog`). Third-party or
out-of-tree capabilities use a reverse-DNS namespace (`org.example.Thing`) so
they never collide with the base set.

### Process names

Each capability's launched executable is named for the capability in title case
— `Log`, `Network`, `Storage`, `Bluetooth`, plus `Authority` (PID 1) and
`Serviced` for the plane's spine. Because base daemons are conventionally
lowercase (`sshd`, `cron`, `syslogd`), the plane stands out at a glance in
`ps(1)` and `top(1)`:

```text
  PID COMMAND
    1 Authority
   18 Serviced
 1408 Audit
 1430 Filesystem
 1432 Network
  ... Storage
  952 syslogd
  971 cron
```

The name shown in `top` is the same identity a program resolves. Components get
it from their bundle's `bin/<Capability>` executable (serviced sets `argv[0]` to
the basename); the spine daemons set it with `setproctitle(3)`. Brackets —
`[name]` — are deliberately *not* used: `ps`/`top` reserve those for kernel and
`P_SYSTEM` processes, which the plane daemons are not.

## Layout and installation

Base provider Makefiles install `Bundle.ucl`, `Unit.ucl`, executables, and
configuration into this same layout. Configuration for `logd` and `bsdnotify`,
for example, lives in the provider unit's `Config` directory rather than
`/etc`. `serviced` supplies the selected unit location as the reserved
`CAPABILITY_UNIT_DIR` environment entry, so versioned site bundles do not
depend on a fixed `/Capabilities/System` path.

`servicectl verify` is side-effect free. `serviced` builds a replacement
registry transactionally: malformed additions, duplicate bundle identities,
duplicate IPC names, unknown startup providers, or dependency cycles leave
the previous running registry in place.

## Runtime delivery

Direct file, socket, jail, vsock, and system authority arrives through
rights-limited kernel descriptors or activation tokens. Named capability
services and storage occupy a separate named-descriptor bootstrap table. The
role and type are validated independently. Storage is delivered as a
rights-limited `zfshandle`: the consumer mounts a mount-rights claim itself
with `service_storage_open(3)` and holds the handle for its lifetime (the
handle anchors the mount), so the service manager never mounts on its behalf —
`tzfsd` sets the dataset root's owner at mint so the service can write. Because
the consumer mounts and hardens the directory itself, granting itself
`CAP_MMAP_R` there is all that is needed to `mmap(2)` its own storage — no
manifest opt-in.

A unit may also declare files and directories it needs as descriptors rather
than paths, under `capabilities.open`:

```
capabilities {
    open = [
        { path = "/Capabilities/Config/principal-policy.ucl";
          name = "principal-policy"; type = "file"; rights = "r"; },
        { path = "/Capabilities/Config";
          name = "config"; type = "dir"; rights = "rl"; },
    ]
}
```

The service manager resolves each path once, opens it, and attenuates the
descriptor to exactly the rights the unit asked for — `r` read, `w` write, `x`
execute, `l` lookup, always with `fstat` — then delivers it as a named entry in
the same bootstrap descriptor table as capability services and storage. The
program never opens a path; it retrieves the descriptor by name with
`service_capability_open(3)` (`ucl_parser_add_fd` for a config file, `openat`
under a delivered directory). This is the capsicum-clean replacement for the
old habit of opening a config path before `cap_enter`. Acquisition is a launch
prerequisite: if the manager cannot open a declared resource with the requested
rights it refuses to launch the unit, exactly like a missing dependency — never
a half-provisioned service. `capabilities.open` is distinct from
`capabilities.files`, which is a MAC path-access grant (see below), not a
delivered descriptor.

Providers claim only IPC names declared under `activation.ipc`. A provider is
not ready until its complete declared set is claimed and capability-mode entry
is independently observed. Simultaneous lookups cannot create duplicate
provider processes.

## Exclusive and non-exclusive holds

Capability classes divide into two kinds, and the distinction is a system
invariant, not a stylistic one:

- **Non-exclusive holds** — `paths`, `files`, and delivered `open` descriptors.
  A file or path grant is a *reference-counted share*: any number of units may
  hold an overlapping grant on the same path at the same time, each narrowed to
  its own `FI_FS_*` action mask. Holding read on `/Capabilities/Config` does not
  exclude another unit from holding it too. A delivered `open` descriptor is the
  most non-exclusive of all — it is simply an opened file, not even a claim.

- **Exclusive isolations** — `network` endpoints, `jails`, and `vsock` CIDs.
  An isolation is owned by exactly one holder *across the whole system*. The
  authority mints an isolation token only after `mac_capability_isolation`
  confirms no foreign owner already holds an overlapping claim; a conflicting
  request is rejected. The same owner re-claiming its own isolation is a
  refcount, not a conflict. This is what makes an isolation an isolation: two
  units cannot both own TCP :443, jail `web`, or vsock CID 42.

A unit author reads this as: ask for files and `open` descriptors freely — they
compose — but an isolation you declare is yours alone, and a second unit that
declares the same one will fail to launch until the first releases it.

Storage lifecycle is supervised. `lease` storage is reference-counted across
all units sharing it and is destroyed only after the last holder; crash and
reboot reconciliation use service-manager and kernel-boot generations without
mistaking a `tzfsd` restart for a reboot.

## Process protection

A unit manifest may declare a `protect` policy that the service manager applies
to the launched process **by its process descriptor, immediately after
`pdfork(2)`** — before the program image runs and regardless of what that image
does:

```
protect = ["ptrace", "signal", "visible", "wait", "noprivs", "nofork"];
```

Each entry names a protection flag; the group aliases `protect` (outward guards
against ptrace, signalling, visibility, and wait), `restrict` (self restrictions
such as no-fork, no-exec, no-new-sockets, no-privileges), and `all` expand to
their sets. Unknown names are ignored with a warning, so a manifest written for
a newer flag set still loads on an older system. Because protection is keyed to
the process and dropped when it exits, a fork is born unprotected and a reused
PID is never falsely shielded. `servicectl verify` prints the parsed mask.

The policy is per-service by necessity: a capability provider that forks a
per-connection worker cannot itself carry `nofork`, while each worker it
launches can — and since the launcher holds the worker's descriptor, it applies
the worker's policy without the worker needing any protection authority of its
own.

## No compatibility format

This is a pre-v1 clean break. The former `etc/*.ucl` format, repeated schema
metadata in each process manifest, inferred `provides` activation,
`capabilities.storage`, `components=[...]`, and the eager `descriptors {}`
factory block are rejected. They are not silently translated. A unit reaches a
capability service at runtime through its typed library and `service_connect()`,
not through a manifest declaration.
