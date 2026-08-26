# Capability bundle manifests

`serviced` loads applications from self-contained `.cap` directories. The
format has two levels: one bundle manifest owns identity and shared resources;
each unit has a smaller process manifest. There is no legacy `etc/*.ucl`
format.

## Directory contract

```text
Mail.cap/
├── Bundle.ucl
├── Shared/
│   ├── Config/
│   ├── Resources/
│   ├── Libraries/
│   └── Executables/
└── Units/
    ├── smtpd.unit/
    │   ├── Unit.ucl
    │   ├── bin/smtpd
    │   ├── Config/
    │   └── Resources/
    └── indexer.unit/
        ├── Unit.ucl
        └── bin/indexer
```

At the bundle root only `Bundle.ucl`, `Shared`, and `Units` are accepted.
Every name in `Bundle.ucl`'s `units` array must have exactly one
`Units/<name>.unit` directory; undeclared entries below `Units` are errors.
The default executable is `bin/<unit-name>`. A `program` override is still one
filename below that unit's `bin` directory, never a path.

Configuration and static resources belong inside the `.cap` tree, not in
`/etc`. Bundle-wide data goes below `Shared`; process-specific data goes below
the corresponding unit. Mutable application data is storage, described below,
and is not written into the installed bundle.

At launch, `CAPABILITY_UNIT_DIR` is set by `serviced` to the selected
`Units/<name>.unit` directory. This makes `Config` and `Resources` work for
both fixed base-system bundles and sequence-versioned site installations.
The name is reserved and cannot be overridden by a unit manifest. It conveys
a location, not new authority; a process that enters capability mode must open
the files it needs first or request a filesystem descriptor.

## Complete bundle example

`Bundle.ucl` contains only bundle identity, version ordering, the exact unit
inventory, and declarations genuinely shared by units:

```ucl
schema = "org.5bsd.capability-bundle";
schema_version = 1;

bundle_id = "org.example.mail";
version = "2.4.1";
sequence = 17;
author = "Example Project";
publisher = "org.example";

units = ["smtpd", "indexer"];

shared {
    storage = [{
        name = "maildata";
        flavor = "native";
        lifetime = "persistent";
    }];
}
```

`sequence` is the monotonic update order. `version` is display metadata and
does not need to be numerically sortable. Unit names use lower-case ASCII
letters, digits, and interior dashes.

## Complete unit example

`Units/smtpd.unit/Unit.ucl` contains process behavior and authority:

```ucl
# program = "smtpd" is the default for smtpd.unit
arguments = ["--foreground"];
environment = {
    MODE = "production";
};
user = "capability";
group = "capability";

activation {
    boot = true;
    ipc = ["org.example.mail.smtp"];
}

restart = "on-failure";
stop_timeout = 10;
max_failures = 10;
kmod_requires = ["zfs"];

storage = [
    {
        name = "maildata";
        scope = "shared";
        rights = ["mount", "props_read", "snapshot"];
    },
    {
        name = "queue";
        scope = "unit";
        flavor = "native";
        lifetime = "lease";
        rights = ["mount", "props_read", "props_write"];
    }
];

capabilities {
    files = [{
        path = "/etc/ssl/cert.pem";
        actions = ["read", "stat"];
    }];
    network = [{
        domain = "inet";
        protocol = "tcp";
        port = 25;
        direction = "bind";
        address = "0.0.0.0";
    }];
    system = [];
}

descriptors {
    filesystem { storage = "queue"; }
    network {}
    crypto {}
}
```

Activation is always explicit. `boot=true` starts the unit during convergence.
Each `ipc` name reserves a reverse-domain endpoint and permits launch on first
lookup. At least one activation mode is required. `provides`, `on_demand`,
`requires`, and `components` are not aliases and are rejected.

## Storage descriptors

Storage is a top-level unit descriptor declaration, not a member of
`capabilities`. A direct mount-only entry becomes a rights-limited directory
available as `storage:<name>`. Storage used to back a `filesystem` descriptor
is private to that descriptor factory and is not also exposed to the client.
Only claims requesting advanced ZFS operations receive a `zfshandle`.

- `scope="unit"` creates storage private to the bundle/unit/name tuple. Flavor
  and lifetime may be declared here.
- `scope="shared"` references a declaration in `Bundle.ucl`. The unit supplies
  only its own rights; it cannot override shared flavor or lifetime.
- `persistent` survives process, manager, and machine restarts.
- `cache` also survives restarts but is explicitly reclaimable cache; it must
  never be the only copy of data.
- `boot` is shared only within the current kernel boot generation.
- `lease` exists while at least one launched holder remains. Shared leases are
  destroyed after the last holder, not the first unit to stop.

The visible name is never used as a ZFS path. `libcapbundle` derives a
domain-separated 192-bit SHA-256 key from bundle id, scope, unit id (for unit
scope), and logical name. This prevents cross-bundle collisions and keeps
filesystem-safe implementation names out of application policy.

Abandoned leases are grouped under a random service-manager session. A new
manager session reclaims older lease generations after the old supervised
process tree has been stopped. Restarting only `tzfsd` resumes the same
session. Boot storage uses `kern.boottime`, so a daemon restart preserves it
while a machine reboot selects a new generation. Reconciliation is
conservative: storage containing retained snapshots is reported and left
intact rather than silently discarding it.

## Closed schemas and limits

Unknown keys, duplicate keys, UCL directives/includes, macros, file variables,
implicit arrays, symlinked manifests, and over-1-MiB manifests fail closed.
Important limits are:

| Item | Maximum |
|---|---:|
| units per bundle | 32 |
| services loaded system-wide | 256 |
| arguments / environment entries | 32 / 32 |
| IPC names per unit | 8 |
| storage declarations per unit | 8 |
| shared storage declarations | 8 |
| paths / files / network / jails / vsock | 16 each |
| direct capability services | 4 |
| kernel modules | 8 |
| stop timeout | 300 seconds |
| bundle tree entries | 4096 |
| one bundle file | 512 MiB |
| total bundle bytes | 2 GiB |

Capability entry fields and accepted action names are documented in
`serviced(5)`. Network claims cover IPv4, IPv6, and Bluetooth. System gates
are a closed set. Reserved bootstrap environment names cannot be supplied by
the manifest.

## Discovery and trust

Base-system bundles are installed in `/Capabilities/System`; site bundles are
installed in `/Capabilities`. Registry directories and every loaded object
must be root-owned and not writable by group or other. Symlinks and special
files are rejected. `servicectl verify path.cap` prints the effective unit
configuration, including activation, storage scope/lifetime, and opaque
dataset key, without activating the bundle.

The same strict parser is used by `servicectl` and `serviced`, so validation
and runtime loading do not have separate interpretations.
