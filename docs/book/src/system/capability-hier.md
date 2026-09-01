# Capability filesystem hierarchy

Capability programs do not scatter their files across the classic UNIX
directories, and they do not clone them either. Classic UNIX lays out `/etc`,
`/var/run`, `/var/db`, and `/var/log` *by type* because classic programs share
global namespaces — every daemon's config piles into one `/etc`, every socket
into one `/var/run`. Capability programs don't share those namespaces: each one
ships as a self-contained bundle and each active one is handed its own
storage by `tzfsd`. So the capability plane is laid out **by capability, not by
type**. Everything lives under `/Capabilities`, and each capability owns a
self-contained subtree there.

## The two halves of a capability

Every capability is a **static half** and a **dynamic half**:

- **Static half — the bundle.** `/Capabilities/System/<Name>.cap` ships
  everything fixed about the capability: its binary, its manifest, and its
  configuration defaults. It is installed read-only by pkgbase and is present
  the instant the root dataset mounts. This is the capability's definition.
- **Dynamic half — the runtime home.** `/Capabilities/<Name>/` is the
  capability's own directory, provisioned by `tzfsd` when the capability
  activates. Its control socket, persistent state, cache, and logs all live
  here — in *its* home, not in any shared global directory. Because each home
  is a distinct `tzfsd` handle, capabilities cannot see into one another's
  runtime state; the isolation is structural, not conventional.

```text
/Capabilities/
├── System/            shipped bundle definitions        static, read-only, at boot
│   ├── Log.cap
│   ├── Notify.cap
│   └── Filesystem.cap
├── Config/            minimal pre-storage plane config   static, admin-mutable, at boot
│   ├── tzfsd.ucl          storage pool + layout
│   ├── tzfsd.d/           drop-ins
│   ├── principal-policy.ucl  admin policy (auth-agent; optional)
│   └── serviced/disabled  operator disable list
└── <Name>/            per-capability runtime home        tzfsd-provisioned, at runtime
    ├── control.sock       the capability's own endpoint      (ephemeral)
    ├── state/             persistent state                   (tzfsd persistent)
    ├── cache/             discardable working data           (tzfsd ephemeral)
    └── log/               the capability's logs              (tzfsd persistent)
```

There is deliberately **no `/Capabilities/run`, no `/Capabilities/db`, no
`/Capabilities/log`.** A socket, a state file, and a log for the `Log`
capability all live under `/Capabilities/Log/`; the same for every other
capability. The plane reads as a list of capabilities, each with its own home —
the way the security model already thinks about them.

## The one static exception: `Config/`

Two core daemons run *before* the storage plane they depend on exists, so they
cannot read their configuration from a `tzfsd`-provisioned home — that home
doesn't exist yet:

- **`tzfsd`** must know its pool and layout before it can mount anything.
- **`serviced`** consults the operator disable list while building its bundle
  registry, before it activates (and therefore before any runtime home exists).

Their bootstrap configuration is the *only* thing kept in a shared static
directory, `/Capabilities/Config/`, on the root dataset and present at boot. It
is kept deliberately minimal — genuine pre-storage bootstrap config, nothing
that could instead live in a capability's own home. Everything a capability
needs *after* the storage plane is up belongs in its runtime home, not here.

## Why the split is safe — the bootstrap ordering

1. **`authorityd` (PID 1)** starts. The `authorityd → serviced → tzfsd` handshake
   rides **inherited capability descriptors**, never a named socket or path, so
   the bootstrap can never block on a directory that is not mounted yet. This is
   the invariant the whole layout rests on.
2. The **root dataset mounts**, so `/Capabilities/System` (definitions) and
   `/Capabilities/Config` (bootstrap config) are present.
3. **`serviced`** reads `/Capabilities/Config/serviced/disabled`, scans
   `/Capabilities/System` for bundles, and builds its registry.
4. **`tzfsd`** reads `/Capabilities/Config/tzfsd.ucl`, brings up the storage
   plane, and begins handing out per-capability runtime homes.
5. Each activated capability — `serviced` and the core daemons included — gets
   its `/Capabilities/<Name>/` home and creates its control socket, state, and
   logs there.

The rule that keeps it sound: **the only things needed before `tzfsd` is up are
the read-only definitions in `System/` and the minimal `Config/`; everything
else is a per-capability runtime home that arrives with the storage plane.**

## What stays in the classic hierarchy

Classic UNIX programs keep `/etc`, `/var`, and `/usr` unchanged; the capability
plane adds nothing to them. The one deliberate bridge is the legacy `rc`
bootstrap: `authorityd` still executes `/etc/rc` to converge a classic multi-user
system, because rc and the programs it starts are classic UNIX software. That is
the boundary — capability programs own `/Capabilities`, each with its own home;
classic programs own the classic tree; only the rc hand-off crosses it.
