# Capability filesystem hierarchy

Capability programs — `oracled`, `serviced`, `tzfsd`, the descriptor factories,
and the component providers — do not scatter their files across the classic
UNIX directories. Those (`/etc`, `/var`, `/usr/local`, `/var/run`, `/var/db`,
`/var/log`) remain the home of classic UNIX software. Everything the capability
plane owns lives under a single, self-describing tree at **`/Capabilities`**.

`/Capabilities` is a directory on the root dataset — not a separate mount — so
its static children exist from early boot, before the storage daemon runs. Its
storage subtrees are individually provisioned by `tzfsd` at runtime. This is the
same hybrid FreeBSD itself uses: `/` and `/etc` are present the instant the root
mounts, while `/usr`, `/home`, and the `tmpfs` on `/var/run` arrive as the boot
proceeds.

## The tree

```text
/Capabilities/
├── System/        installed capability bundles (*.cap)   static, read-only
├── etc/           capability-daemon configuration        static, early, mutable by admin
├── run/           control sockets, pid files             tmpfs, early, ephemeral
├── db/            persistent daemon state                on root, early, survives reboot
├── persistent/    unit/shared persistent storage         tzfsd dataset, runtime
├── ephemeral/     boot- and lease-lifetime storage       tzfsd dataset, runtime
└── .templates/    flavor clone origins (<flavor>@ready)   tzfsd dataset, runtime
```

| Subtree | Analogous to | Backing | Available |
|---|---|---|---|
| `System/` | `/usr` (shipped, immutable) | root dataset | at boot |
| `etc/` | `/etc` | root dataset | at boot |
| `run/` | `/var/run` | tmpfs | very early (before any daemon binds) |
| `db/` | `/var/db` | root dataset | at boot |
| `persistent/`, `ephemeral/`, `.templates/` | separately mounted `/home`, `/usr` | `tzfsd`-owned ZFS datasets / anonymous mounts | runtime, once `tzfsd` is up |

## Why the split — the bootstrap ordering

The capability daemons come up in a fixed order and the tree matches it:

1. **`oracled` (PID 1)** starts. It needs *no* filesystem rendezvous: the
   `oracled → serviced → tzfsd` handshake is carried on **inherited capability
   descriptors**, never on named sockets or paths. This is the invariant that
   makes the whole scheme safe — the bootstrap can never deadlock on a
   directory that is not mounted yet.
2. The **root dataset is mounted** (ZFS root), so `/Capabilities/System`,
   `/Capabilities/etc`, and `/Capabilities/db` are already present. `run/` is a
   small `tmpfs` mounted here as well, so control sockets have a home before any
   daemon binds one.
3. **`serviced`** reads `/Capabilities/etc`, scans `/Capabilities/System` for
   bundles, consults `/Capabilities/db` for operator state, and binds its
   control socket under `/Capabilities/run`.
4. **`tzfsd`** provisions and owns the storage subtrees, handing
   `/Capabilities/{persistent,ephemeral}` out as rights-limited handles and
   anonymous mounts. Nothing earlier in the sequence depends on these, so it is
   safe for them to arrive last.

The rule that keeps this sound: **anything needed before `tzfsd` is up must live
on a subtree that is static (root dataset) or a `tmpfs` (`run/`); only the
storage subtrees may be `tzfsd`-mounted.** A capability daemon must never place
a file it needs at startup on a subtree that only exists once the storage plane
is running.

## Placement rules

- **Bundles** → `/Capabilities/System/<Name>.cap`, installed read-only by
  pkgbase. Immutable, versioned; never write daemon state here.
- **Configuration** → `/Capabilities/etc/` (for example the storage broker's
  `tzfsd.ucl` and its `tzfsd.d/` drop-ins). Admin-editable, read at startup.
- **Control sockets and pid files** → `/Capabilities/run/`. Ephemeral; recreated
  each boot; never carry state across a reboot here.
- **Persistent daemon state** → `/Capabilities/db/<daemon>/` (for example the
  operator disable list at `/Capabilities/db/serviced/disabled`). Survives
  reboot; small and daemon-private.
- **Application storage** → `/Capabilities/{persistent,ephemeral}` only, and
  only via `tzfsd` handles — a daemon never reaches into these datasets by path.

## What stays in the classic hierarchy

Classic UNIX programs keep using `/etc`, `/var`, `/usr`, and friends unchanged;
the capability plane simply does not add to them. The one deliberate bridge is
the legacy `rc` bootstrap: `oracled` still executes `/etc/rc` to converge a
classic multi-user system alongside the capability plane, because rc and the
programs it starts are classic UNIX software. That is the boundary — capability
programs own `/Capabilities`, classic programs own the classic tree, and only
the rc hand-off crosses it.
