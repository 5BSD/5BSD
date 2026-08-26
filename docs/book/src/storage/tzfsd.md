# tzfsd and capability storage

`tzfsd(8)` owns the storage plane. It retains TrustedZFS parent handles,
creates or opens application datasets, attenuates each returned handle to the
declared rights, and passes that handle with `SCM_RIGHTS`. It never proxies
application I/O.

`oracled` starts it on demand and forwards storage requests. `serviced`
converts mount-only storage into a rights-limited directory named
`storage:<logical-name>`. A filesystem descriptor consumes its backing handle
privately. Only a unit requesting advanced ZFS operations receives a named
`zfshandle`. The logical name is not a dataset name.

## Dataset layout

```text
<pool>/Capabilities/
├── persistent/
│   ├── u-<192-bit-key>          unit persistent/cache storage
│   └── s-<192-bit-key>          shared persistent/cache storage
├── ephemeral/
│   ├── boot-<kern.boottime>/
│   │   └── <stable-key>         current-boot storage
│   └── lease-<manager-session>/
│       └── <stable-key>         last-holder lease storage
└── .templates/
    └── <flavor>@ready
```

The key is the first 192 bits of a domain-separated SHA-256 digest over bundle
id, scope, unit id when applicable, and descriptor name. It is stable for
persistent identity and has 192-bit collision resistance. Scope prefixes make
unit and shared keys visibly disjoint.

## Lifetimes

| Lifetime | Stop | `serviced` restart | `tzfsd` restart | Reboot |
|---|---|---|---|---|
| `persistent` | keep | keep | keep | keep |
| `cache` | keep | keep | keep | keep, but reclaimable by policy |
| `boot` | keep | keep | keep | reclaim old boot generation |
| `lease` | delete after last holder | reclaim abandoned session | resume current session | reclaim old session |

Shared lease accounting occurs in `serviced`: every successful mint adds a
holder and all failure/stop paths release exactly the subset actually minted.
Only the transition from one holder to zero sends a destroy request.

`tzfsd` does not erase the ephemeral root when it starts. Doing so would turn a
storage-daemon crash into application data loss. Instead, boot generations are
derived from `kern.boottime`; lease generations are selected by `oracled` for
each new `serviced` instance. Reconnecting after a `tzfsd` crash resumes the
same lease session. A new manager instance selects a new session after the old
supervised process tree is gone and reclaims older ordinary lease trees.
Retained snapshots make reconciliation fail visibly and leave the tree intact.

## Bundle declarations

Shared definition in `Bundle.ucl`:

```ucl
shared {
    storage = [{
        name = "database";
        flavor = "native";
        lifetime = "persistent";
    }];
}
```

Per-unit grants in `Unit.ucl`:

```ucl
storage = [
    {
        name = "database";
        scope = "shared";
        rights = ["mount", "props_read", "snapshot"];
    },
    {
        name = "scratch";
        scope = "unit";
        lifetime = "lease";
        rights = ["mount", "props_read", "props_write"];
    }
];
```

A shared reference cannot override the bundle declaration's lifetime or
flavor. Rights remain per unit. Accepted rights include property read/write,
snapshot lifecycle, rollback, clone source, child create/destroy, send/receive,
mount, hold, and release operations.

## Confinement and protocol

Before `cap_enter()`, `tzfsd` loads its UCL configuration and flavor drop-ins,
ensures ZFS is available, provisions roots, reconciles stale boot generations,
and retains subtree handles. After that point every operation derives from
those handles.

The versioned `SOCK_SEQPACKET` protocol has request, release, flavor-list,
ping, and begin-session operations. Messages are fixed-size and reject unknown
flags, non-zero reserved bytes, unterminated fields, unsafe dataset components,
wrong descriptor counts, truncation, and descriptor smuggling. Release is
idempotent and applies only to the selected lease generation.

Tests under `tests/sys/tzfs` exercise all lifetimes, daemon restart, session
rollover, last-holder behavior, malformed sessions/messages, rights
attenuation, clone/mount behavior, and conservative retained-snapshot failure
in a disposable ZFS VM.
