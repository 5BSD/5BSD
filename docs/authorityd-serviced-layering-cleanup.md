# Layering cleanup: get leaf-daemon work out of authorityd and serviced

## Principle

Two programs are the most privileged and hardest-to-change in the system:
`authorityd` (runs as PID 1) and `serviced` (the service manager). Neither
should contain code, wire types, or library links that are specific to any
*leaf* capability daemon. Their jobs are narrow:

- **authorityd** mints the capabilities it creates **through the kernel**
  (`mac_capability` isolation tokens, channels, coalitions), is the boot mint
  boundary, and is the lifecycle/control root. That is all.
- **serviced** launches children, delivers descriptors, supervises them via
  the coalition, routes discovery, and applies launch policy (limits, band,
  umask, calendar, activation). That is all.

Everything a *specific daemon* needs (tzfsd storage, a jail broker, a module
broker, netd, …) must reach those two programs **blind**: as an opaque,
domain-tagged request they forward without interpreting, or — better — as a
held channel to the owning daemon that serviced simply *delivers*.

## What's wrong today (evidence)

### Kernel-backed mints — legitimate, keep as-is

These go through `usr.sbin/authorityd/mac_capability_mint.c` to the
`mac_capability` isolation fd (`FI_OP_MINT*`). authorityd owns that device;
this is its actual role. Not a violation.

| Op | Handler | Backing |
|----|---------|---------|
| `MINT_PATH` / `MINT_FILE` | `handle_mint_path/file` | `mac_capability_mint_{path,file}_token` (kernel ioctl) |
| `MINT_NET` | `handle_mint_net` | `mac_capability_mint_net_token` (kernel ioctl) |
| `MINT_JAIL` (token) | `handle_mint_jail` | `mac_capability_mint_jail_token` (kernel ioctl) |
| `MINT_VSOCK` | `handle_mint_vsock` | kernel ioctl |
| `MINT_SYSTEM`, `CREATE_CHANNEL`, `CREATE_COALITION` | — | kernel `mac_capability` |

### The three real violations

| # | What | Where | Why it's misplaced |
|---|------|-------|--------------------|
| **V1** | **Storage brokering** — the only userland-*daemon* client inside PID 1 | `authority_proto.c:47` `#include "tzfsd.h"`; `:400-455` persistent tzfsd channel + session; `MINT_STORAGE`/`DESTROY_STORAGE` forward. `Makefile:55,58` `-I.../libtzfsd`, `LIBADD=… tzfsd` | PID 1 is a tzfsd client; a storage-daemon stall can reach init. |
| **V2** | **Module loading** — raw privileged syscall as policy | `authority_proto.c:891-893` `modfind()`/`kldload()` in `handle_ensure_kmod`; `serviced/kldmgr_client.c` + `execute.c:1214` decide *which* modules | The deleted `kldmgrd`'s job, resurrected across PID 1 + serviced. `control.c:10` already admits "kldload … here temporarily". |
| **V3** | **Jail construction** — raw privileged syscall | `authority_proto.c:682` `jail_set(iov, niov)` in `handle_create_jail`; serviced carries inline `jail_name/hostname/ip4/path` in `svc_manifest` | PID 1 assembles jailparams and creates jails — that's a jail broker's job. |

### serviced's mirror-image coupling

- **Links leaf clients:** `Makefile:35,37` `-I.../libtzfsd`, `LIBADD=… tzfsd jail`.
- **One typed path per daemon:** `authority_client.c` has a `fill_<domain>_req`
  + `authority_mint_<domain>` pair for net (`:215`), jail (`:233`),
  vsock (`:258`), storage (`:390`).
- **Typed claim arrays in the manifest:** `serviced_manifest.h` `struct
  svc_manifest` carries `cap_net[]`, `cap_jail[]`, `cap_vsock[]`,
  `cap_storage[]` (+ inline jail fields), each an `ort_*`/`serviced_*` wire type.

Net effect: **adding a daemon means editing both programs.** That is the
anti-pattern to remove.

## Prior art: launchd

Darwin's `launchd` (also PID 1 + service manager) never accumulates per-daemon
knowledge, and the reason is a single design choice: **it brokers named
capabilities, never typed requests.** It is a *rendezvous* service, not a
request forwarder.

- A job's plist declares `MachServices = { "com.apple.foo" = true }`. launchd
  owns the receive right for that name before the daemon exists. A client calls
  `bootstrap_look_up("com.apple.foo")` and gets a **send right** — a Mach port,
  i.e. an unforgeable capability. launchd knows the **name** (opaque) and
  brokers the **port** (a capability); it never parses, validates, or forwards
  the *content* sent over it. The two endpoints speak whatever they like.
- Sockets work the same way: the `Sockets` plist key makes launchd create and
  listen on the fd, then pass the pre-made descriptor to the job on connection
  (`launch_activate_socket(3)`). It delivers the fd; it doesn't speak the
  protocol on it.
- Launch conditions (`StartCalendarInterval`, `LaunchEvents`, path/IOKit
  triggers) are **generic mechanisms**, declared per job, with zero per-daemon
  code.

Adding a daemon on macOS = **adding a plist**; it never means editing launchd.

Equally instructive is what Apple kept *out* of launchd — the same jobs that
are our V2/V3:

- Kext loading is **not** in launchd (`kernelmanagerd`/`kmutil`). PID 1 does
  not `kldload`. → our **V2**.
- Sandbox/container construction is **not** in launchd (`sandboxd`,
  `containermanagerd`, per-process Seatbelt profiles). PID 1 does not build the
  confinement. → our **V3**.

Caveat worth heeding: launchd is also criticized as a monolith — it absorbed
`init`, `mach_init`, `inetd`, and much of `cron`/`at`. The discipline that
keeps that sane is exactly the line this plan draws: **absorb generic
mechanisms, never per-daemon logic.** `StartCalendarInterval` is generic
scheduling, not code that knows any particular job. The moment launchd grew a
`fill_storage_request()`, it would have our problem.

Where we are *ahead* of launchd: our capabilities are kernel-enforced
descriptors carrying rights and transfer limits, not bare Mach send rights — so
"deliver the channel" can also carry fine-grained, pre-attenuated authority
that launchd would have to approximate with entitlements.

## Per-daemon architectural audit

A full audit of the capability-plane daemons (2026-09-01). Ranked by daemon;
"clean" = a socketless `service_provider` with per-client channels and no
leaf-coupling. Citations are in the tracking notes; summarized here.

| Daemon | Socket-free? | Key architectural issues |
|--------|-------------|--------------------------|
| **authorityd** (PID 1) | **No** | ① live AF_UNIX `getpeereid` control listener **in PID 1** (`control.c` — not vestigial; a fatal Phase-5 startup step) — flagship violation; ② `kldload`/`modfind` run in PID 1 (`handle_ensure_kmod`); ③ `jail_set()` in PID 1 (`handle_create_jail`); ④ hardcoded serviced fd-map + restart policy (`bootstrap.c`) |
| **serviced** | Yes | storage coupling **REMOVED** (`5583478`): links no libtzfsd, no storage code (`cap_storage` is declaration-only). Remaining typed scaffolding is net/jail/vsock — **kernel** isolation mints via authorityd, not leaf-daemon clients (Phase 4 generalizes them; still links libjail). Plane-conformant otherwise |
| **tzfsd** | **Yes** | **DONE** (`5583478`): socket-free `system.Storage` provider; identity-scoped nested datasets `persistent/u<hash-of-label>/<claim>`; consumers self-mint via libservice |
| **authagentd** | Yes | no per-client worker isolation — the mint authority + SYSTEM bootstrap channel are shared across all login clients (no `pdfork`/`service_worker_protect`) |
| **localcrypto** | Yes | policy hardcoded in C (dead `crypto_policy.conf`); parent/listener not hardened with `service_provider_protect` |
| **localnetwork** | Yes | session policy hardcoded in C, ignores `client_label` (contradicts its own header comment) |
| **bsdnotify** | Yes | clean; single router worker (intentional); `auditcmp` coupling is via channel (fine) |
| **auditbrokerd** | Yes | clean; provider→audit-event-class table hardcoded in C (`auditcmp_policy.c`) → manifest |
| **traced** | Yes | ① bypasses the audit broker with raw `audit_submit`/libbsm → use libauditcmp; ② operator allowlist from hardcoded `/etc/traced.allow` → manifest |
| **logd** | Yes | clean; fixed pool worker (intentional); `auditcmp` coupling via channel (fine) |
| **blued** | **No** | dual/shadow control plane: exposes `system.Bluetooth` but the *live* IPC is a hand-rolled `/var/run/blued.sock` with `getpeereid` tiers (the provider listener is dormant). BT **radio** sockets + the SCM_RIGHTS L2CAP fd broker are legitimate — leave |
| **meshd** | **No** | entirely hand-rolled `/var/run/meshd.sock` + `getpeereid`, **no** provider, **no** capability sandbox, **no** manifest; also couples into blued's source tree and speaks blued's wire protocol over a path socket |

**Cross-cutting themes** (fix system-wide, not per-daemon):
- **Socket-free**: tzfsd storage **done** (`5583478`). Remaining: authorityd
  control (`control.c` — the last core plane socket + `getpeereid`) and the
  blued/meshd control planes, all still on UNIX sockets + `getpeereid`.
- **Policy-in-code vs manifest**: localcrypto, localnetwork, auditbrokerd, and
  traced hardcode operator policy in C; authagentd's `principal-policy`
  descriptor is the pattern to copy (deliver policy as a manifest descriptor via
  `service_capability_open`).
- **Per-client worker isolation**: authagentd (mint authority) shares state
  across clients; bsdnotify/logd use single-worker models by design (fine, but
  call it out). localcrypto/localnetwork/auditbrokerd/traced do it right
  (`pdfork` + `service_worker_protect`).
- **Audit-broker bypass**: traced submits audit directly instead of via
  auditbrokerd.
- **Privileged work misplaced in PID 1**: `kldload` and `jail_set` → dedicated
  brokers (already tracked as the kmod/jail phases).

## Socket-free (launchd-style) — a standing mandate

The capability plane is **socket-free**: a service is reached over a held
`mac_capability` **channel** obtained **by name**, never a UNIX-domain socket,
a filesystem path, or a `getpeereid(3)` peer check. This is the launchd model
(a Mach port brokered by name) with kernel-enforced attenuation on top. Authority
is the *held channel*, so scoping is intrinsic to the capability rather than
bolted on with socket permissions.

Any capability-plane daemon that still listens on a UNIX socket is to be
**rewritten as a `service_provider`** (libservice: `service_provider_expose(name)`
+ per-client worker channels; clients use `service_open(name)`), matching
`localcrypto`/`bsdnotify`/`localnetwork`/etc. which are already socketless.

**Socket-free hit list (capability-plane IPC only):**

| Daemon | Socket | Status |
|--------|--------|--------|
| `tzfsd` | ~~`/var/run/tzfsd.sock` storage IPC~~ | **DONE** (`5583478`) — `system.Storage` provider; consumers self-mint; serviced links no libtzfsd |
| `authorityd` (`control.c`) | lifecycle control socket (`getpeereid`) | **to convert — the last capability-plane socket + `getpeereid` in the core** |
| `blued`/`meshd` (`ctl.c`) | control sockets | to convert |

Explicitly **out of scope** (legitimate non-plane sockets): the Bluetooth
**radio** sockets (HCI/L2CAP hardware transport), and stock network/base
daemons (`nfsd`, `mountd`, `inetd`, `ppp`, `route6d`, `iscsid`, bhyve backends)
— these speak real wire protocols, not capability-plane IPC.

## Target architecture

The end-state is launchd's model, made stronger by capability attenuation:
**serviced delivers the consumer a held channel to the owning daemon,
pre-attenuated to the bounds the manifest declares, and the consumer mints for
itself over that channel.** serviced and authorityd never see a
storage/jail/net request — only a domain name and a bounds tuple.

```
manifest (declares BOUNDS: domain, rights ceiling, lifetime)
   │
   ▼
serviced ── launch · deliver fds/channels · supervise · discovery · launch policy
   │            └── "give me a <domain> channel bounded by {rights, lifetime}"
   ▼
authorityd ── kernel mints only (mac_capability) + generic delegate ROUTE
   │
   ├── (kernel) isolation tokens, channels, coalitions            ← stays
   └── DELEGATE(domain, bounds) ──► owning daemon returns an
                                     ATTENUATED channel  ──► delivered to consumer
                                     (tzfsd, jaild, kmodd)
```

This reconciles the two forces that first looked opposed:

- **Manifest-as-policy is preserved** — the manifest still declares the bounds
  (rights ceiling, lifetime). It just stops declaring daemon-specific *fields*.
- **The consumer self-serves at runtime** (launchd's decoupling) — but it can
  only ever mint *within* the delivered channel's attenuation, because the
  capability itself enforces the ceiling. Policy is enforced by the shape of
  the handed-out capability, not by serviced interpreting a request.

So the currency of both core programs becomes exactly launchd's — **names and
capabilities** — plus a bounds tuple they pass through opaquely.

**Target = (B) deliver-channel.** (A) broker-forward — serviced/authorityd
relay an opaque domain-tagged *request* and return the resulting fd — is the
**transitional half-measure** we pass through in Phases 1–3: it already deletes
all *typed* per-daemon code from the two programs, without yet flipping every
consumer to self-serve. Phase 4 completes the move to (B).

## Phases

Each phase ends with a clean-VM validation loop (the `~/vm` ZFS-root rig:
refresh bundle-private binaries + libs, rebuild image, boot under qemu-TCG,
assert the service comes up and 0 launch failures).

### Phase 0 — Scaffolding + baseline (no behavior change)
- Add `AUTHORITY_OP_DELEGATE` to `authorityd_svc_proto.h`: `{uint32_t domain;
  uint32_t blob_len; uint8_t blob[]; }`, reply carries status + one optional fd.
- authorityd gains a `domain → owning-daemon socket` route table (data, not
  per-op code). Start empty.
- serviced gains one `authority_delegate(domain, blob)` client that returns
  `{status, fd}`. Start unused.
- Capture a golden boot transcript + `zfs list` / service inventory as the
  regression baseline.

### Phase 1 — Storage out of PID 1, then socketless  *(in progress)*

Progress (committed, VM-verified):
- **Storage out of PID 1** (`9c4d931`): authorityd links no libtzfsd, no storage
  ops; serviced brokered tzfsd directly (transitional step A).
- **tzfsd leases concurrent-safe** (`a601a7c`): `session_begin` create-or-open,
  never reaps a sibling; orphan GC at daemon startup.

Remaining — the **socketless rewrite** (supersedes step A; per the socket-free
mandate): convert tzfsd to a `system.Storage` `service_provider`, rewrite
`libtzfsd`/`tzfsctl` as `service_open` channel clients, then serviced delivers a
scoped `system.Storage` channel by name and libservice self-mints — deleting
`storage_client.c` + `libtzfsd` from serviced. Attenuation is intrinsic to the
delivered channel (no `AUTHORIZE` op, no peer-uid, no socket).

Original transitional framing (retained for reference):
- Route `MINT_STORAGE`/`DESTROY_STORAGE` through `DELEGATE(domain=STORAGE)`
  (blob = the existing `authority_storage_req` body), OR — simpler — have
  **serviced talk to tzfsd directly** (it already links libtzfsd and holds the
  claim), deleting the authorityd hop entirely.
- **Delete from authorityd:** `#include "tzfsd.h"`, the `authority_tzfsd_*`
  channel/session state, both storage handlers, and `libtzfsd`/`-Ilibtzfsd`
  from the Makefile. PID 1 no longer links a leaf daemon.
- Validate: logd/consumers still get `persistent/u-…` + `ephemeral/lease-…`
  bare datasets; `tzfsctl ping` ok; 0 launch failures.

### Phase 2 — Module loading out of PID 1
- Introduce a minimal **module broker** (or fold into an existing low daemon)
  that owns `modfind`/`kldload`; expose it via `DELEGATE(domain=KMOD)`.
- Prefer making a service's kernel-module prerequisite a **loader/bundle
  declaration** resolved before launch, so most cases need no runtime kldload
  at all.
- **Delete from authorityd:** `handle_ensure_kmod` + `modfind`/`kldload`.
  **Delete from serviced:** `kldmgr_client.c`, the `execute.c:1214` call, and
  `kmod_requires[]` handling. Remove the `control.c` "temporarily" comment.
- Validate: a service that needs a module (e.g. a filesystem/linux consumer)
  still launches.

### Phase 3 — Jail construction out of PID 1
- Move `jail_set()` into a **jail broker** daemon; expose via
  `DELEGATE(domain=JAIL_CREATE)`. authorityd keeps only the kernel jail-*token*
  mint (`MINT_JAIL`), which is a real capability mint.
- **Delete from authorityd:** `handle_create_jail` + `jail_set`, and
  `libjail`/`-Ijail` if now unused. **Delete from serviced:** inline
  `has_jail/jail_name/jail_hostname/jail_ip4/jail_path` handling +
  `authority_create_jail`; the manifest expresses "attach to jail X" as an
  opaque JAIL_CREATE claim.
- Validate: a jailed service still starts and is confined.

### Phase 4 — Generalize the manifest + complete the move to (B)  *(structural)*
Once V1–V3 prove the pattern, finish the launchd model: serviced stops
relaying requests and instead **delivers pre-attenuated channels**.
- Replace the typed `cap_net[]`/`cap_jail[]`/`cap_vsock[]`/`cap_storage[]`
  arrays with **one uniform delegated-claim list**: `{domain, rights ceiling,
  lifetime}` — a bounds tuple, no daemon-specific fields. `libcapbundle` parses
  each domain's declaration; the two core programs never see the fields.
- For each claim, serviced obtains from the owning daemon (via `DELEGATE`, or
  via discovery) a **channel attenuated to the declared bounds** and delivers
  *that* to the consumer — instead of minting the concrete resource itself.
  The consumer mints within the bounds over its held channel (the tzfsd/jail/…
  protocol now lives only between consumer and owning daemon).
- Replace serviced's `fill_<domain>_req`/`authority_mint_<domain>` family with a
  single loop that requests+delivers channels by domain.
- **Delete from serviced:** `libtzfsd`, `libjail` links; every per-domain fill
  function. serviced now knows only: fds/channels, coalition, discovery, launch
  policy — launchd's currency, plus attenuation.
- Validate: full boot + every capability service up, each self-serving its
  resource within manifest-declared bounds.

> Transitional note: Phases 1–3 may land as **(A)** (serviced/authorityd relay
> an opaque request, return the fd) to minimize churn; they still delete all
> typed per-daemon code. Phase 4 flips consumers to **(B)** self-serve over a
> delivered attenuated channel — the end-state. A domain can be migrated A→B
> one at a time.

### Phase 5 — (optional) collapse kernel-mint ops
authorityd's per-domain **kernel** mints (`MINT_PATH/FILE/NET/VSOCK/JAIL`)
could fold behind a single generic isolation-mint. Low priority: they pull in
no daemon dependencies and are authorityd's genuine role. Defer unless the
op-count itself becomes a maintenance cost.

## Sequencing & risk

- Order is deliberate: **Storage → Kmod → Jail → Generalize.** Each phase is
  independently shippable and independently revertible.
- Phases 1–3 are *deletions from the privileged core* with the logic moving to
  (or already living in) less-privileged places — each strictly reduces PID 1's
  surface. Phase 4 is the larger structural change; do it last, on proven
  patterns.
- Every phase gates on the clean-VM loop. The known rig traps apply: refresh
  the **bundle-private** daemon copies (`/Capabilities/System/*.cap/Units/*/bin`),
  keep libs/binaries ABI-consistent, and do a **clean** kernel-module relink
  (not `-DKERNFAST`) when kernel objects change.

## Definition of done

- `grep -rl 'tzfsd\|libjail\|jail_set\|kldload\|modfind' usr.sbin/authorityd`
  returns nothing.
- serviced's `LIBADD` contains no leaf-daemon client lib (`tzfsd`, `jail`).
- `svc_manifest` carries no daemon-specific typed claim struct — only the
  uniform delegated-claim (bounds) list plus fds/coalition/launch-policy.
- Each leaf protocol (tzfsd storage, jail-create, kmod) is spoken **only**
  between the consumer and the owning daemon over a delivered, pre-attenuated
  channel — never relayed through serviced or authorityd (end-state **B**).
- serviced/authorityd's currency is **names + capabilities + a bounds tuple**,
  exactly launchd's model — they interpret no per-daemon request content.
- Adding a new capability daemon touches **neither** authorityd nor serviced.
