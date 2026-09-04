# Capability bundle manifests

`serviced` loads applications from self-contained `.cap` directories. The
format has two levels: one bundle manifest owns identity and the unit
inventory; each unit has a smaller process manifest.

## Directory contract

```text
Mail.cap/
├── Bundle.ucl
├── Shared/                      bundle-wide Config/ Resources/ Libraries/
└── Units/
    ├── smtpd.unit/
    │   ├── Unit.ucl
    │   ├── bin/smtpd            default executable: bin/<unit-name>
    │   └── Config/
    └── indexer.unit/
        ├── Unit.ucl
        └── bin/indexer
```

At the bundle root only `Bundle.ucl`, `Shared`, and `Units` are accepted;
every name in `Bundle.ucl`'s `units` array must have exactly one
`Units/<name>.unit` directory. Configuration and static resources belong
inside the `.cap` tree, not in `/etc`; at launch `serviced` sets
`CAPABILITY_UNIT_DIR` to the selected unit directory (a location, not new
authority). Mutable data is storage, obtained from
[`tzfsd`](../storage/trustedzfs.md) at runtime, never written into the installed
bundle.

## Example

`Bundle.ucl` — identity, version ordering, unit inventory:

```ucl
schema = "org.5bsd.capability-bundle";
schema_version = 1;

bundle_id = "org.example.mail";
version = "2.4.1";       # display metadata
sequence = 17;           # monotonic update order
publisher = "org.example";
units = ["smtpd", "indexer"];
```

`Units/smtpd.unit/Unit.ucl` — how to run the program:

```ucl
arguments = ["--foreground"];
user = "capability";
group = "capability";

activation {
    boot = true;
    ipc = ["org.example.mail.smtp"];   # launch on first lookup
}

restart = "on-failure";
stop_timeout = 10;
limits { memory = "512M"; nproc = 64; nofile = 1024; }
umask = "0077";
band  = "standard";      # background | standard | interactive
```

## No capabilities block

A unit declares **no** capabilities — there is no `capabilities {}` block, and
eager grant syntax (`provides`, `requires`, `descriptors {}`, …) is rejected.
The manifest says only how to launch the program; the program acquires
whatever it needs at runtime, by name, every grant scoped to its own
unforgeable channel label: files and devices, mutable storage (`tzfsd`),
jails (`warden`), kernel modules (`sysextd`), and vsock endpoints (`vmd`),
each through its `service_*(3)` call in `libservice(3)`. Brokered outbound
networking is its own chapter: [localnetwork](localnetwork.md).

## Activation and process policy

Activation is always explicit and at least one mode is required. Demand
sources inside `activation` (details in `serviced(5)`):

- `boot = true` — start during convergence.
- `ipc = ["name", …]` — reserve reverse-domain endpoints; launch on first lookup.
- `socket` — socket activation.
- `timer { interval = N; }` — every `N` monotonic seconds.
- `schedule = "…"` — wall-clock calendar (five-field cron string or
  `hourly`/`daily`/…); `persistent = true` adds anacron-style catch-up. The
  plane's cron replacement; mutually exclusive with `timer`.
- `path { path = "/abs"; }`, `queue_directory = "/abs"`, `on_mount = true`.

`limits`, `umask`, and `band` are policy applied in the child after
`pdfork(2)` and before `exec`, so they bind the image from its first
instruction: `limits` become `setrlimit(2)` ceilings (`core` defaults to 0),
`umask` defaults to `0077`, and `band` maps to scheduling priority. The MAC
integrity shield (`protect`) separately covers no-new-privileges, W^X, and
ptrace/signal isolation.

## Validation and limits

Unknown keys, duplicate keys, UCL directives, symlinked manifests, and
oversized manifests fail closed, and bundle counts and sizes are bounded
(the ceilings are in `serviced(5)`). Base bundles install in
`/Capabilities/System`, site bundles in `/Capabilities`; every loaded object
must be root-owned and not group/other-writable, and symlinks and special
files are rejected. `servicectl verify` and `serviced` share the same strict
parser, so validation and runtime loading cannot diverge.

Reference: `serviced(5)`.
