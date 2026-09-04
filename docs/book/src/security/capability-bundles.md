# Capability Bundles

A `.cap` bundle is 5BSD's install, configuration, resource, execution, and
authority boundary. It contains one `Bundle.ucl`, an exact inventory of one or
more `.unit` directories, their executables and resources, and optional shared
content. Mutable state is not part of the bundle; a unit obtains it at runtime
from `tzfsd`, scoped to its own unforgeable channel label. This chapter covers
the bundle *security model*; the complete manifest format and the
on-disk layout of the `/Capabilities` tree are covered in the
[System Services section](../system/manifests.md), not repeated here.

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
- Kernel authority is acquired at runtime, by name, over the unit's unforgeable
  channel — never minted before execution or declared in the manifest.
  Applications never choose ZFS dataset paths; `tzfsd` derives each dataset
  from the channel label.
- A unit's runtime identity is `<bundle-id>/<unit-name>`, independent of any
  IPC name it publishes.

There is deliberately no compatibility path for older manifest formats: legacy
`capabilities {}` blocks, inferred activation, and eager descriptor factories
are rejected, never silently translated.

## Naming

A capability is identified by a hierarchical name in the `system.` namespace —
`system.Log`, `system.Network`, `system.Filesystem` — declared once as the
bundle's `bundle_id` and on the listener the unit activates.

**The name is the contract.** A capability *is* its claimed name, not the
daemon behind it. To replace a provider you publish a bundle that claims the
same name; consumers are unaffected because they resolve the name, never the
binary. The `system.` prefix is reserved for base-system capabilities;
third-party bundles use a reverse-DNS namespace (`org.example.Thing`) so they
never collide with the base set. Each capability's launched executable is named
for the capability in title case (`Log`, `Filesystem`, ...), so the plane
stands out at a glance in `ps(1)` next to conventional lowercase daemons.

`servicectl verify` is side-effect free, and `serviced` builds a replacement
registry transactionally: malformed additions, duplicate identities, duplicate
IPC names, or dependency cycles leave the previous running registry in place.

## Runtime delivery

Direct file, socket, and system authority arrives through rights-limited kernel
descriptors or activation tokens, acquired at runtime by name over the unit's
unforgeable channel — not from a launch-time bootstrap table. A unit that needs
an existing file or directory calls `service_open_isolated(3)`: the filesystem
daemon (`tzfsd`) opens the path under its own per-label policy and returns a
rights-limited, capsicum-clean descriptor — the grant lives in `tzfsd`'s
policy, not in the unit's manifest. Storage is delivered as a rights-limited
`zfshandle` the consumer mounts and holds itself (`service_storage_open(3)`),
so the service manager never mounts on its behalf.

Providers claim only the IPC names declared under `activation.ipc`, and a
provider is not ready until its complete declared set is claimed and
capability-mode entry is independently observed. Simultaneous lookups cannot
create duplicate provider processes.

## Exclusive and non-exclusive holds

The runtime grants a unit acquires divide into two kinds, and the distinction
is a system invariant:

- **Non-exclusive holds** — filesystem paths. A path grant is a
  reference-counted share: any number of units may hold an overlapping grant on
  the same path, each narrowed to its own action mask.
- **Exclusive isolations** — network endpoints. An isolation is owned by
  exactly one holder across the whole system: the kernel `mac_capability`
  isolation service confirms no foreign owner already holds an overlapping
  claim before a token is minted, and a conflicting request is rejected. This
  is what makes an isolation an isolation: two units cannot both own TCP :443.

A unit author reads this as: acquire paths freely — they compose — but a
network isolation is yours alone until you release it. Storage lifecycle is
likewise supervised: leases are reference-counted across sharing units and
reconciled across crashes and reboots without mistaking a `tzfsd` restart for a
reboot.

## Process protection

A unit manifest may declare a `protect` policy that `serviced` applies to the
launched process **by its process descriptor, immediately after `pdfork(2)`** —
before the program image runs and regardless of what that image does:

```
protect = ["ptrace", "signal", "visible", "wait", "noprivs", "nofork"];
```

Entries name [capprotect shield flags](process-protections.md); the aliases
`protect`, `restrict`, and `all` expand to their sets, and unknown names are
ignored with a warning so a newer manifest still loads on an older system.
Because protection is keyed to the process and dropped when it exits, a fork is
born unprotected and a reused PID is never falsely shielded. The policy is
per-service by necessity: a provider that forks per-connection workers cannot
itself carry `nofork`, while each worker it launches can — and since the
launcher holds the worker's descriptor, it applies the worker's policy without
the worker needing any protection authority of its own.
