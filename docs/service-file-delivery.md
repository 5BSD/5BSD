# Service file/directory capability delivery

Status: **implemented and clean-VM verified** (2026-08-31). A general serviced
mechanism (not auth-agent-specific):
a service declares the files and directories it needs, with the rights it needs
on each, and serviced **opens them and hands over the descriptors** — already
`cap_rights_limit`ed to those rights — in the launch bootstrap. The service never
opens a path.

## Exclusivity

An `open` descriptor is a **non-exclusive hold**, in the same category as
`capabilities.files` and `capabilities.paths`: any number of units may be
delivered a descriptor for the same file or directory at once — opening a file
excludes no one. This is the opposite of an **isolation** (`network`, `jails`,
`vsock`), which is exclusive across the whole system: the authority mints an
isolation token only when no foreign owner holds an overlapping claim. `open`
is not even an authority claim — the service manager opens the path directly and
hands over the fd — so it never conflicts and never needs the isolation
conflict machinery. See the book's *Exclusive and non-exclusive holds*.

## Why

Authority in this OS is a held capability; a **path is ambient authority**. Worse,
a capsicum-mode service (`cap_enter`) cannot `open()` a path at all, regardless of
any MAC grant. Today services that need config (tzfsd, logd) work around this by
opening their config directory **by path before `cap_enter`** — the exact smell
this removes. `capabilities.files` (`{path, FI_FS_* actions}`) is a *MAC grant*,
not a delivered fd, and does not help in capsicum.

The fix: serviced (the launcher — not itself in capsicum) resolves the paths once,
opens them, attenuates each fd to the declared rights, and delivers them as named
descriptors on the existing bootstrap named-fd rail. The service retrieves them by
name and uses them (`ucl_parser_add_fd` for config, `openat` under a delivered dir
fd). Capsicum-clean, least-privilege, and reusable by every daemon.

## Manifest

A new `open` array in a unit manifest (distinct from the MAC-grant
`capabilities.files`):

```
open = [
    { path = "/Capabilities/Config/principal-policy.ucl";
      name = "principal-policy"; type = "file"; rights = "r"; },
    { path = "/var/db/whatever";
      name = "state";            type = "file"; rights = "rw"; },
    { path = "/Capabilities/Config";
      name = "config";           type = "dir";  rights = "rl"; },
];
```

- `path` — absolute path serviced resolves at launch.
- `name` — the bootstrap name the service retrieves it by (unique per unit).
- `type` — `file` or `dir` (`dir` implies `O_DIRECTORY`).
- `rights` — the rights the consumer needs, **consumer-specified, not fixed
  read-only**: `r` read, `w` write, `x` execute, `l` lookup (dirs, for `openat`).
  Mapped to `cap_rights`: r→CAP_READ, w→CAP_WRITE, x→CAP_FEXECVE, l→CAP_LOOKUP,
  always +CAP_FSTAT. A dir delivered with `rl` lets the service `openat` files
  read-only within it (the openat'd fd inherits <= the dir's rights).

## serviced delivery (execute.c)

At launch, before exec, for each `open` entry:

1. `open(path, O_RDONLY|O_RDWR per rights [| O_DIRECTORY])`.
2. `cap_rights_limit(fd, <mapped rights>)`.
3. Assign it an fd number in the bootstrap struct (after the existing
   capability/token fds) and record `{fd, name, type}` in the bootstrap
   named-fd table.
4. `dup2` it to that number in the child's fd setup (the same path the existing
   `capabilities[]` fds take), close-on-exec cleared as the rail requires.

**Fail-closed (the key semantic):** a **required** file/dir acquisition is a
launch prerequisite. If serviced cannot open a declared resource (missing,
denied, wrong type), it **refuses to launch the service** — logs
`open <name> (<path>): <errno>` and fails the launch exactly like a missing
dependency, applying the unit's restart policy. Never a half-provisioned
service.

**Optional entries:** an entry may set `optional = true`. Such an entry is
delivered when it can be opened and **silently skipped** (logged at `NOTICE`,
not delivered) when it cannot — the launch proceeds, and the service checks
whether `service_capability_open` finds the name. This preserves the fail-closed
default while letting a genuinely optional resource — e.g. an absent admin
policy that should fall back to a built-in default — not block a boot-critical
service. The launch barrier counts only the entries actually delivered.

## Retrieval (libservice)

The bootstrap named-fd rail is what `service_capability_open(ctx, name, type,
&fd)` already reads; delivered `open` entries appear there with their `name` and
`type`. So the consumer:

```c
int fd;
if (service_capability_open(ctx, "principal-policy", "file", &fd) == 0) {
    /* ucl_parser_add_fd(p, fd); ... */
}
```

For a `dir` entry the consumer `openat`s within the delivered fd. No new
retrieval API is required if delivered entries reuse the capability-fd table;
otherwise add a thin `service_file_open(ctx, name, type, &fd)` sibling.

As implemented, delivered entries **do** reuse the capability-fd table, so
`service_capability_open` retrieves them directly with the unit-chosen `name`
and type `"file"`/`"dir"` — no new API. This required loosening
`service_capability_name_valid` to accept a general `[a-z0-9-]` token (it
previously accepted only a fixed name set); the manifest
parser enforces the same charset/length at parse time so a bad `open` name is
a config error, not a silent retrieval miss.

### Where it lives

- Manifest: `struct serviced_open_cap {path, name, rights, is_dir}` +
  `SVC_OPEN_{READ,WRITE,EXEC,LOOKUP}` in `lib/libcapbundle/serviced_manifest.h`;
  parsed/validated in `libcapbundle_parse.c` (key `open`), copied in
  `libcapbundle.c`, change-compared in `serviced/manifest_compare.c`.
- Delivery: `serviced/execute.c`, in the pre-fork acquire block beside the
  token/container capabilities — opens, `cap_rights_limit`s,
  `cap_xfer_limit(CAP_XFER_NONE)`s, and appends as a named bootstrap capability;
  any failure takes the existing `fail_tokens` path (fail-closed). The
  all-or-nothing barrier counts `m->ncap_open`.
- Retrieval: `service_capability_open` in `lib/libservice`. The child-side
  bootstrap validator (`parse_service_bootstrap`) gained a `file`/`dir` arm:
  these are raw kernel descriptors whose authority is their own cap_rights
  (like a `zfshandle`), not mac_capability tokens, so it validates liveness +
  vnode kind instead of calling `capability_get_info()`. Without this the child
  rejected the delivered fd and `service_acquire` failed.

## Verified

Clean image built from source (`installworld` + `installkernel KERNCONF=VBSD`),
booted under qemu/TCG with a probe unit that declares three `open` resources.
Running as the unprivileged `capability` service (uid 976), after `cap_enter`:
reads a **root-owned** config file it could never open by path; a write to that
read-only fd is denied ("Capabilities insufficient"); `cap_rights_get` shows
`read=1 write=0` exactly matching `rights="r"`; `openat` within the delivered
directory fd succeeds; and an ambient path `open()` is denied in capability
mode. All other system services boot normally with the change in place.

## Reuse

Any daemon adopts it by declaring `open` and dropping its pre-`cap_enter`
path-opening: tzfsd's `confd` directory and logd's store directory become
`open`-delivered dir fds. The auth-agent (P1c) declares
`principal-policy.ucl` as an `open` file fd and parses it with
`ucl_parser_add_fd`, removing its last path dependency in cap mode.

## Not covered here

Passwd/group lookups (`getpwuid`, wheel membership) are a separate ambient
dependency; the auth-agent avoids them by having the login caller pass the
already-resolved principal attributes (it authenticated the principal and holds
the reach-capability). See docs/auth-agent-design.md.
