# tzfsd and tzfsctl

`tzfsd(8)` is the `[TZFS]` storage daemon: the system component that owns
the storage plane. It holds the root-pool TrustedZFS handles, provisions
the `/Capabilities` dataset layout, maintains the flavor templates, and
mints rights-limited dataset handles on request, passing them back over
`SCM_RIGHTS`. It mints and manages only — it never proxies I/O; everything
a consumer does after receiving a handle is the `libtrustedzfs` verb
surface. The daemon lives in `usr.sbin/tzfsd/`; the operator CLI is
`usr.sbin/tzfsctl/`.

ZFS is a required subsystem for 5BSD (UFS remains bootable, but the
capability storage plane assumes a ZFS pool); `tzfsd` refuses to start
without one.

## Why a dedicated daemon

Storage granting was originally inline in oracled
(`handle_mint_storage()` opening `/dev/zfs` per request). Moving it into
`tzfsd` gives storage its own configuration, its own audit identity, and
the flavor/template system, without fracturing the mint path: serviced
still mints every capability class over its one oracle channel, and
oracled's `ORACLE_OP_MINT_STORAGE` is now a thin forwarder that calls
`tzfsd_request`/`tzfsd_release` via `libtzfsd`. oracled no longer opens
`/dev/zfs` at all, and starts `tzfsd` on demand the first time a service
needs storage. The manifest `capabilities.storage` stanza was unchanged by
the move — only who mints changed.

## The `[TZFS]` tag

Every system daemon in the capability stack carries a distinguishable
bracket tag — `[ORACLE]` (oracled/oracle-init), `[SERVICE]` (serviced),
`[TZFS]` (tzfsd) — so `ps`, `procstat`, and capability inspectors can tell
the authority holders apart. `tzfsd` sets it via
`setproctitle("[TZFS] storage daemon")`.

## Startup and capability confinement

All name-based work happens up front, then the daemon seals itself:

1. Load `/etc/capability/tzfsd.ucl` (optional; built-in defaults apply),
   then layer flavor-catalog drop-ins from `/etc/capability/tzfsd.d/`.
2. Verify ZFS is available; provision the `/Capabilities` layout
   idempotently (persistent, ephemeral, and `.templates` roots), retaining
   full-rights subtree handles on each.
3. Prepare flavor templates (see [Flavors](flavors.md)); a flavor that
   cannot be materialized is simply not offered.
4. Open the `SOCK_SEQPACKET` listener at `/var/run/tzfsd.sock`
   (root-owned, mode 0600), daemonize, write the `tzfsd.ready` file.
5. `cap_enter()` — the entire request loop runs in capability mode,
   minting every grant by derive/openat/create/clone from the retained
   handles. No request can reach a dataset outside the configured roots.

## Layout

```
zroot/Capabilities                      (mountpoint /Capabilities)
├─ persistent/<bundle-id>/<claim>       survives reboot, materialized once
├─ ephemeral/<bundle-id>/<claim>        cloned/created at service start,
│                                       destroyed at stop
└─ .templates/<flavor>@ready            clone origins, not app-visible
```

Ephemeral datasets default to `sync=disabled` for scratch throughput. All
roots and the pool are configurable in `tzfsd.ucl` (see `tzfs.conf(5)`);
the defaults above are the shipped opinion, applied with zero operator
configuration.

## Protocol and client library

`lib/libtzfsd/` is the client (prefix `tzfsd_`), distinct from
`libtrustedzfs` (prefix `tzfs_`, the handle verbs) because consumers link
both. The wire protocol (`tzfsd_proto.h`, alongside the other capability
protocols in `lib/liboraclert/`) is a reply-with-fds RPC with four ops:
`TZFSD_OP_REQUEST` (returns the handle fd via `SCM_RIGHTS` plus the
resolved dataset name for audit), `TZFSD_OP_RELEASE` (idempotent ephemeral
teardown), `TZFSD_OP_LIST_FLAVORS`, and `TZFSD_OP_PING`.

A service declares storage in its manifest like any other capability:

```ucl
capabilities {
    storage = [{
        name     = "rootfs";
        flavor   = "linux";       # "" = bare dataset, no template
        rights   = ["mount", "snapshot"];
        lifetime = "ephemeral";
    }];
}
```

serviced mints the handle over its oracle channel at exec and delivers it
in the token-bootstrap fd range; ephemeral claims are destroyed at stop
using the handle's own `DESTROY` rights.

## tzfsctl

`tzfsctl(8)` is the operator/inspector CLI:

```sh
tzfsctl ping                    # daemon liveness
tzfsctl list-flavors            # available flavors (default marked)
tzfsctl request -f linux -l ephemeral -r mount,props_read -m scratch
tzfsctl release scratch         # destroy an ephemeral claim
```

`request` drives the same path a service does: it asks for a handle,
prints the resolved dataset, and with `-m` mounts it and prints the dirfd
before exiting (which unmounts and closes it — `request` is a
demonstration/health tool, not a way to hold storage open). Rights are
named (`props_read`, `props_write`, `snapshot`, `snap_destroy`,
`clone_src`, `create`, `destroy`, `mount`, or `all`).

## Operations

- Config: `/etc/capability/tzfsd.ucl` plus `*.ucl` drop-ins in
  `/etc/capability/tzfsd.d/`. Every key is optional.
- Run `tzfsd -f` for foreground with stderr logging; `-c` for an alternate
  config. Logging goes to syslog facility `daemon`.
- Readiness: the socket at `/var/run/tzfsd.sock` and the ready file; a
  startup summary logs `N/M flavors available`.
- Manpages: `tzfsd(8)`, `tzfs.conf(5)`, `tzfsctl(8)`, `libtzfsd(3)`.
- Tests: `tests/sys/tzfs/` (ATF, request/clone/mount/release, rights
  attenuation, ephemeral teardown, negative paths).

**Status.** A boot-time `tzfsd.ready` ordering gate for services that need
storage before the first on-demand mint is a designed Phase 4 refinement;
today oracled's spawn-and-wait covers the on-demand case. The design
document (`docs/tzfsd-design.md`) also sketches a
`tzfsctl flavor destroy` runtime-reclaim subcommand that is not in the
shipped CLI — flavor removal today is config (`enabled = false`) or
removing the `tzfs-flavors` package.

Sources: `docs/tzfsd-design.md`, `usr.sbin/tzfsd/`, `usr.sbin/tzfsctl/`,
`lib/libtzfsd/`.
