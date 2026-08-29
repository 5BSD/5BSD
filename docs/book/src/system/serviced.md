# serviced

`serviced(8)` is 5BSD's system service manager. `authorityd(8)` starts one
supervised instance and supplies descriptor-based authority for service
launches. `serviced` owns bundle discovery, explicit boot and IPC activation,
readiness, restart policy, storage leases, and the administrative control
socket. The authoritative pre-v1 target is the dependency-free demand model in
`docs/service-architecture-plan.md`.
Any remaining internal startup-edge graph is implementation debt, not manifest
ABI or a supported dependency facility.

## Boot and registry model

At startup `serviced` runs the transitional `/etc/rc autoboot` oneshot, scans
root-owned bundles in `/Capabilities/System` and `/Capabilities`, validates the
complete graph, starts units declaring `activation.boot=true`, then reports
boot convergence to `authorityd`. Units that declare only `activation.ipc` start
on the first lookup of one of their reserved names.

Installed versions are immutable directories named
`<bundle-id>@<20-digit-sequence>.cap`. The registry selects the highest
sequence for each identity regardless of directory enumeration order. Equal
sequences, user/system identity collisions, duplicate unit labels, duplicate
IPC names, unknown descriptor providers, and dependency cycles fail the
replacement scan today. The startup-edge and cycle checks are scheduled for
removal as local factories become ordinary IPC-activated providers. A failed
reload leaves the previous registry running.

See [Capability bundle manifests](manifests.md) for the complete two-level
`Bundle.ucl` and `Units/<name>.unit/Unit.ucl` format.

## Launch and lifecycle

Each native unit is launched with `pdfork(2)`. Before releasing the child,
`serviced` mints every declared capability, provisions storage, constructs
local descriptors, creates a coalition, installs a versioned bootstrap envfd,
and applies the requested credentials and optional jail. Partial construction
is rolled back; the program never receives an incomplete authority set.

```text
STOPPED -> STARTING -> RUNNING -> STOPPING -> STOPPED
                    \-> DONE (oneshot)
```

`RUNNING` requires both the service protocol check-in and independently
observed capability-mode entry. Restart policies are `never`, `always`, and
`on-failure`. Rapid failures use bounded backoff and the `max_failures` circuit
breaker. Shutdown drains manager-visible demands and owned sessions and
escalates from graceful termination to `SIGKILL` after `stop_timeout`; there
is no dependency graph to reverse.

Storage lifetimes are `persistent`, `cache`, `boot`, and `lease`. Shared lease
storage is destroyed only when its last launched holder exits. Manager-session
and boot-generation reconciliation recover abandoned lease/boot datasets after
a crash or reboot without treating a `tzfsd` restart as a reboot.

## Local descriptors and global IPC

Local descriptors replace ambient authority for one consumer process:

```ucl
storage = [{
    name = "data";
    scope = "unit";
    lifetime = "persistent";
    rights = "mount";
}];

descriptors {
    filesystem { storage = "data"; }
    network {}
    crypto {}
}
```

The filesystem descriptor must name storage with mount rights. `serviced`
mounts that dataset anonymously, passes its directory and the immutable bundle
root to `localfilesystem`, and injects only the confined session endpoint into
the consumer. Network and crypto descriptors have no manifest-selectable
provider or policy escape hatch.

Global services instead publish reverse-domain names in `activation.ipc` and
use `service_provider_expose()`. Providers are ordinary supervised bundles;
examples include `system.Log`, `system.Notify`, and `system.Trace`.
Consumers discover these names through typed libraries. Publishing a name does
not imply boot activation.

## Administration and installation

```sh
servicectl verify /path/to/App.cap
servicectl install /path/to/App.cap
servicectl reload
servicectl status
servicectl services
servicectl bundles
servicectl start org.example.app/worker
servicectl stop org.example.app/worker
```

`verify` is side-effect free. `install` requires root, copies without following
symlinks, accepts only directories and regular files, enforces bundle tree
limits, normalizes ownership and writable bits, syncs every staged object,
verifies the staged bytes, and atomically renames them to the canonical version
path. Existing sequences are never overwritten. `reload` activates the
highest valid sequence. Older immutable directories may remain while pinned by
a running process or until garbage collection, but serviced has no rollback or
historical-version selection interface.

The control socket is `/var/run/serviced.sock`. Mutating operations require
root. Requests and replies are fixed-size and bounded. Descriptor headroom is
reserved before launches and IPC brokerage so `EMFILE` cannot leave a partial
launch.

## Program API

Managed programs use `libservice(3)`. Providers explicitly authorize minted
capabilities, install capprotect restrictions, expose IPC listeners, enter
capability mode, and report readiness. Consumers use typed global-service
libraries or local descriptor libraries such as `libfilesystemcmp`,
`libnetworkcmp`, and `libcryptocmp`.

Socket, timer, path, calendar (`schedule`), `queue_directory`, and `on_mount`
activation are all implemented demand sources; only user-domain schedules
remain future work. Dependency targets are not planned. The only current
compatibility boundary is the deliberately isolated `/etc/rc` bootstrap needed
to boot the existing base system.
