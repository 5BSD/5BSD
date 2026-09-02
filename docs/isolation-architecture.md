# Isolation architecture

How 5BSD isolates one Component (a launched program) from another and from the
system, after the manifest `capabilities {}` block was removed and capabilities
became on-demand, label-scoped services.

The guiding rule: **authority is a held, kernel-attested channel credential
(the unforgeable label), not a manifest declaration.** A Component declares
nothing to isolate; it *asks* the owning authority for what it needs, on demand,
and the authority scopes the grant by the Component's label.

## Layers

Isolation is provided by several cooperating layers, not one mechanism. Each
layer is independent; together they are defence-in-depth.

### 1. Capsicum (the baseline)

Every Component enters capability mode (`cap_enter(2)`). In capability mode a
process **cannot open any path by name** (no global namei), cannot create
arbitrary sockets, and every descriptor it holds is limited to explicit
`cap_rights`. This alone isolates the vast majority of Components from the
filesystem and network namespaces: they can only act through descriptors they
were explicitly handed. A Component that needs a resource it cannot name asks a
provider for it (below).

### 2. The filesystem daemon (tzfsd) — `system.Filesystem`

tzfsd brokers everything file-shaped, scoped by the caller's unforgeable label:

- **Storage** — `service_storage_open(3)`: a per-Component ZFS dataset under
  `persistent/u<hash-of-label>/…`. A Component can only ever reach its own
  subtree.
- **Config area** — `service_open_config(3)`: a writable `config/` area under the
  same per-label home, for configuration files outside the shared UNIX tree.
- **Isolated descriptors** — `service_open_isolated(3)`: tzfsd opens an existing
  path (a device node, a shared directory, a config file) on the Component's
  behalf and hands back a Capsicum-rights-limited descriptor. **Default-deny**:
  tzfsd consults its own per-label `open_paths` policy and opens only the exact
  paths (or prefixes, for device units like `/dev/vhidN`) that label is granted,
  with only the requested rights. This is how a sandboxed Component reaches a
  device it cannot open by path itself (e.g. blued and `/dev/vhid*`).

Because Components are in capability mode, tzfsd is the *only* way most of them
reach a path at all, and its per-label policy decides which Component gets which
descriptor. Capsicum + tzfsd delivery is therefore a complete path/device
isolation story without a separate per-service kernel lock.

### 3. warden (jails) — `system.Namespace`

`service_enter_namespace(3)`: a Component confines itself to a jail scoped to its
label. Persistent or ephemeral (lifetime bound to the Component). warden is the
namespace authority; jails self-scope by label, so nothing is declared.

### 4. The kernel `mac_capability` isolation service (the backbone)

`sys/dev/mac_capability/mac_capability_isolation.c` provides kernel-enforced,
nonce-scoped restriction of network endpoints, vsock endpoints, filesystem
paths, and jails: a *claim* locks a resource (default-open otherwise), a *token*
grants a specific holder access, and the holder *authorizes* its own nonce. This
is the enforcement backbone. It is owned by **authorityd** (the one authority):
authorityd holds the standing claims and mints tokens. It always claims
`/dev/mac_capability` (its own device).

Today the isolation service is the authority for **vsock** (see vmd, below) and
**network**. Per-service *path* tokens are retired — path isolation moved to
capsicum + tzfsd (layer 1 + 2), which is complete and avoids scattering claims.
Network endpoint restriction is currently relaxed to default-open (a deliberate
choice — most Components need no port restriction); the authority remains and can
re-restrict without touching Components.

### 5. The VM daemon (vmd) — `system.VM`

vmd is the VM authority. Its eventual role is to run virtual machines (bhyve);
today it brokers the **vsock** (VM socket) transport, taking that out of serviced
and the manifest. A Component in capability mode cannot bind a vsock address
itself (it names a global namespace), so it asks vmd via its library
(`service_vsock_listen(3)`); vmd binds a host-local (`VMADDR_CID_LOCAL`)
`AF_VSOCK` listening socket on the Component's behalf and hands back the
descriptor. This is the same broker-holds-a-capability, re-delivers-per-label
shape as tzfsd for paths and warden for jails.

vmd scopes each Component to a **port window** derived from a hash of its
unforgeable channel label (`VMD_PORT_BASE + offset*VMD_PORTS_PER_LABEL`); the
wire request names only an index within that window, so one Component can never
name or bind another's port. When vmd grows the full VM lifecycle it will own the
`/dev/vsock` provider authority for a running guest's CID (a guest is isolated by
its own CID) via authorityd's kept vsock machinery — the `ort_vsock_claim` /
`mint_vsock_token` primitives were deliberately preserved for exactly this. vmd
runs as a root, non-capmode privileged provider (the vsock transport and bhyve
management need device access and a global-namespace `loadat`/`openat`).

## Who is an authority vs. a broker

- **authorityd** is the *one* isolation authority: it owns kernel claims and
  mints tokens. It is deliberately single-caller (it trusts serviced) and is not
  a general per-Component mint service.
- **tzfsd, warden, vmd** are **brokers**, not authorities. They *hold* a
  capability (a dataset handle, the jail authority, a vsock provider grant) and
  re-deliver rights-limited access to Components by label. They do not mint new
  isolation claims — they hand out descriptors. This keeps the isolation
  authority centralized in authorityd and prevents it from scattering across
  daemons.
- **serviced** holds no isolation authority at all. It launches Components and
  resolves names on demand; it is a launcher + naming switchboard.

## Why not a per-service kernel path-lock too

Locking each restricted device to a single owner in the kernel would add a third
redundant layer on top of capsicum (which already stops every Component from
opening paths) and tzfsd's per-label delivery policy. The only processes it would
additionally constrain are the trusted non-capmode base daemons — a
compromised-TCB threat that is already game-over. The marginal benefit does not
justify scattering claims across daemons or expanding PID 1. Capsicum + tzfsd is
the right amount of mechanism.
