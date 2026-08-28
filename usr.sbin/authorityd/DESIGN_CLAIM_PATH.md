# FI_OP_CLAIM_PATH: kernel-side path claim (DESIGN PROPOSAL — NOT IMPLEMENTED)

> **Note:** This document describes a proposed kernel interface extension.
> The live protocol uses fd-based FI_OP_CLAIM / FI_OP_RELEASE.
> Op codes and struct names here are proposals, not current API.

## Problem

The isolation service claims vnodes by fd.  Userspace opens the path,
gets an fd, passes it via `MAC_CAPABILITY_CALL` ioctl.  This breaks for
several kernel object types where `open()` either blocks, fails, or
returns the wrong vnode.

## Affected kernel object types

### 1. Network filesystem mount points (NFS, FUSE, smbfs)

`open("/mnt/nfs")` crosses the mount boundary and resolves to the
NFS root vnode.  If the server is unreachable, name resolution blocks
indefinitely in the kernel.  `O_NONBLOCK` does not help — the block
is in `namei()`, not the device open routine.

**What we want to claim:** The covered vnode (the local directory
underneath the mount), so that `mac_vnode_check_lookup` blocks
traversal into the mounted filesystem.

**Current workaround:** Claim the parent directory (`/mnt` instead
of `/mnt/nfs`).  Too broad — blocks siblings.

### 2. Automounter mount points (autofs, amd)

`open()` on an autofs trigger directory causes the automounter to
mount the real filesystem.  This may block waiting for NFS/LDAP,
or create a mount that wasn't intended to exist at claim time.

**What we want:** Claim the trigger vnode without triggering the
mount.  Same NOCROSSMOUNT approach as NFS.

### 3. Device nodes that block on open

Some device drivers block in their `d_open` routine regardless of
`O_NONBLOCK`:

- `/dev/tty*` — may wait for carrier detect (modem lines)
- `/dev/sa*` — tape drives may rewind on open
- Custom drivers with initialization sequences

`O_NONBLOCK` is a hint that most drivers honor, but there's no
guarantee.  The only safe approach for arbitrary device nodes is
to not call `open()` at all.

**What we want:** Claim the device vnode by path without calling
the device's `d_open`.  `NOCROSSMOUNT` alone doesn't help here —
we also need to skip the device open.  A `namei()` lookup returns
the vnode without opening it, which is exactly what we need.

### 4. Unix domain socket nodes

`open()` on a socket vnode returns `EOPNOTSUPP`.  The socket file
cannot be opened, so it cannot be claimed via the current fd-based
interface.

**What we want:** Claim the socket vnode so that
`mac_vnode_check_uipc_connect` blocks unauthorized connections.
The vnode exists in the filesystem — we just can't `open()` it.

**Current workaround:** Claim the parent directory.

### 5. Paths that don't exist yet

A service manifest may reference a path that doesn't exist at boot
(e.g., a log file, pid file, or socket that the service creates at
runtime).  `open()` fails with `ENOENT`.

**What we want:** Claim the parent directory so that
`mac_vnode_check_create` blocks unauthorized creation.  This already
works — claim the parent.  But it might be useful to claim a
not-yet-existing path by name so the claim activates when the file
is created.  This is a separate feature (deferred claims) and out
of scope for `FI_OP_CLAIM_PATH`.

### 6. Layered mounts (nullfs, unionfs)

`open()` on a nullfs mount traverses into the lower layer.  The
vnode returned is the lower-layer vnode, not the nullfs vnode.
Claiming it protects the file via the lower path too, which may
be the correct behavior.  But if the intent is to protect the
nullfs namespace specifically, we'd need the upper vnode.

`NOCROSSMOUNT` stops at the nullfs mount boundary and returns the
covered vnode — same behavior as NFS.  This is correct for the
"block access through this mount" use case.

## Proposed kernel interface

```c
#define FI_OP_CLAIM_PATH    14  /* claim vnode by path */
#define FI_OP_RELEASE_PATH  15  /* release vnode by path */
#define FI_OP_MINT_PATH     16  /* mint token by path */

/* Path resolution flags */
#define FI_PF_NOCROSSMOUNT  0x01  /* stop at mount boundaries */
#define FI_PF_NOFOLLOW      0x02  /* don't follow final symlink */

struct fi_path_request {
    uint32_t    op;
    uint32_t    flags;          /* FI_PF_* */
    uint64_t    actions;        /* FI_FS_* mask (for mint/query) */
    char        path[PATH_MAX];
} __packed;
```

### Kernel implementation

The `FI_OP_CLAIM_PATH` handler in `mac_capability_isolation.c`:

1. Copy path from the request payload
2. Set up a `struct nameidata` with:
   - `LOCKLEAF` — lock the target vnode
   - `NOCROSSMOUNT` — if `FI_PF_NOCROSSMOUNT` is set
   - `NOFOLLOW` — if `FI_PF_NOFOLLOW` is set
3. Call `kern_namei()` to resolve the path
4. The result is a locked vnode reference — the same thing
   `open()` would produce, but without calling `VOP_OPEN`
5. Insert the vnode into the isolation hash table (same as
   existing `FI_OP_CLAIM`)
6. `vput()` the vnode (unlock + drop reference; the hash
   table holds its own `vref`)

Key difference from `open()`: `namei()` returns the vnode without
calling `VOP_OPEN`.  This means:
- No device `d_open` — no driver blocking
- No FIFO open semantics — no waiting for peer
- No `EOPNOTSUPP` on sockets — just gets the vnode
- `NOCROSSMOUNT` stops at mount points

### Security considerations

- The path is resolved using the calling process's credentials
  (authorityd runs as root, so all paths are accessible)
- Path resolution is subject to symlink races, but claiming is
  idempotent — re-claiming the same vnode is a no-op
- The path string comes from authorityd's config, not from untrusted
  input

## Manifest changes proposed by this document

When this proposal was written, its path example was:

```ucl
capabilities {
    paths = ["/var/www"];
}
```

The current manifest also supports fine-grained files, network endpoints,
jails, VSOCK endpoints, and system gates; see `serviced(5)` for that
authoritative schema.  Neither `mountpoints` nor object-valued `paths` below
is currently accepted.  They remain possible extensions if the proposed
kernel operation is implemented.

This proposal would add a `mountpoints` key:

```ucl
capabilities {
    paths = ["/var/www"];
    mountpoints = ["/mnt/nfs"];
}
```

Or use a richer object form in `paths`:

```ucl
capabilities {
    paths = [
        "/var/www",
        { path = "/mnt/nfs"; nocrossmount = true; },
        { path = "/dev/custom"; noopen = true; },
        { path = "/var/run/app.sock"; type = "socket"; },
    ];
}
```

The object form maps to `FI_PF_*` flags in the kernel request.

For `authorityd.conf` claims, the same syntax applies:

```ucl
claims {
    paths = [
        "/dev/mem",
        { path = "/mnt/nfs"; nocrossmount = true; },
    ];
}
```

## Implementation order

1. Add `FI_OP_CLAIM_PATH` / `FI_OP_RELEASE_PATH` / `FI_OP_MINT_PATH`
   to `mac_capability_isolation_proto.h` and implement in `mac_capability_isolation.c`
2. Add `mac_capability_claim_path_str()` to authorityd's `mac_capability_claims.c` that
   uses the new op instead of open+ioctl
3. Update config.c and manifest.c to parse the object form
4. Update authority_proto.c mint handler to use path-based claim when
   `nocrossmount` is set
5. Add `AUTHORITY_OP_MINT_PATH_STR` to the channel protocol so serviced
   can request path-based mints
6. Update man pages and tests
