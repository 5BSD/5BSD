# Capability resource lifecycle & cleanup

Status: **APPROVED — package trigger implemented; durable acknowledgement/replay
work remains.**
Author: 2026-09-06.

## 0. Locked decisions (review outcome)

- **Home:** fold into Capsule/switchboard — **no new daemon** (no `system.Lifecycle`).
- **Granularity:** **bundle-label only.** A retirement fires when a bundle is
  uninstalled from `/Capabilities`; the retired label is that bundle's manifest
  label. Per-principal (decommissioned-user) retirement is out of scope for now.
- **Timing:** **immediate reclaim** — no grace window. (Upgrades that reinstall
  the same bundle re-create their own resources; we do not preserve orphaned
  state across an uninstall.)
- **Reconciliation:** deferred until the installed-on-disk registry can
  distinguish disabled bundles from removed bundles without ambiguity.
- **Push transport:** because switchboard already holds a **control channel to
  every provider it launches**, the push is a `reclaim(label)` control-channel
  message from switchboard — NOT a bsdnotify topic. This is the literal "fold into
  switchboard": no switchboard→Notify publish dependency, no per-topic publisher ACL,
  and providers need not subscribe to Notify. The bsdnotify idea was the seed;
  the control channel is the fold. The `label_is_live` query remains dormant;
  current cleanup is push-only. Sections below
  that describe a `system.label.retired` Notify topic are **superseded** by this
  control-channel transport.

## 1. Problem

Capability providers accumulate **persistent per-label state** — resources they
created on behalf of a consumer, keyed by the consumer's unforgeable channel
label, that outlive the consumer's process:

| Provider | Persistent per-label state |
|---|---|
| tzfsd (system.Filesystem) | persistent/cache dataset claims |
| localcrypto (system.Crypto) | named keys in the kernel keystore |
| warden (system.Namespace) | persistent (non-ephemeral) jails |
| waspnest (system.Waspnest) | assigned vsock port windows |
| logd (system.Log) | the per-label log store |

Providers with only session/fd-scoped state self-clean and are **out of scope**:
localdevice, localnetwork, localsysctl, traced, auditbrokerd, and sysextd (its
allow-list is global, not per-label).

Two cleanup cases:

1. **Voluntary** — a *live* consumer reclaims its own resources. **Already
   solved** by the W14 API work: `LIST` (enumerate what I own) + `DESTROY` /
   `NAMED_DELETE` (reclaim one). No further work.
2. **Involuntary** — the owning label is *gone* (its bundle was uninstalled, or
   the principal was decommissioned) and can never call `DESTROY`. Its
   resources are **orphaned and leak forever**. This is the gap this design
   closes.

## 1a. Do you need a delete hook? (program-author guidance)

If you write a capability program (a bundle/provider), decide which of two cases
you are in — it determines whether uninstall needs a delete hook:

**Case A — ephemeral / held-resource programs: NO delete hook needed.**
Everything you hold is bound to your running process or an open descriptor and
is released by the kernel/Capsule when your service stops:

- an fd you opened, a channel/token delivered to you, a `SYS_OP_CLAIM` /
  isolation claim bound to a held instance fd, a vsock listener, etc.

When your unit stops (including because its bundle was uninstalled and switchboard
tore it down), those go away on their own. Example: **`localsysctl`'s sysctl
isolation** — the Capsule daemon owns the scoped `SYS_GATE_SYSCTL` claim and
reference-counts it against the delivering service; when `localsysctl` stops,
switchboard releases that auto-claim (refcount → 0) and the delivered token fd
closes, so the isolation lifts automatically. No pkg hook, no reclaim handler.
(Requirement: the auto-claim **must** be refcount-released on service teardown —
verify this is wired; a leaked Capsule claim would isolate an OID with no
writer.)

**Case B — persistent-state programs: you need BOTH of two things.**
If you create state that OUTLIVES your process — a zfs dataset, a file, a jail,
a named kernel key, or a per-label log store — the kernel
won't reclaim it when you stop, so uninstall must drive it explicitly. You need:

1. a **provider-side reclaim handler** — `service_set_reclaim_handler(3)` — that
   destroys your persistent per-label state when told a label is being
   reclaimed; **and**
2. a **pkg delete hook** that invokes `/usr/libexec/switchboard-pkg-reclaim
   <label>` in the base package's UCL descriptor, so uninstalling the package
   triggers bounded retries over the root-gated bridge (see §5b).

Neither alone suffices: (1) without (2) is never triggered on uninstall; (2)
without (1) reaches your provider but it does nothing. The providers in §1's
table are all Case B.

If in doubt: hold nothing persistent (Case A) and you owe nothing at uninstall.

## 2. Why not UNIX as the management plane

These resources deliberately live **outside** the UNIX namespace: tzfsd datasets
are anonymous mounts invisible to `find /`; named keys live in the kernel
keystore, not files; vsock windows and jails are not
paths, uids, or PIDs. `rm`, `pkg`, and a UNIX admin cannot see or reclaim them,
and making them UNIX-visible would contradict the "authority = held capability,
not path/uid" model. **Cleanup must be a first-class capability-plane mechanism
keyed on labels, not delegated to UNIX.**

## 3. Target design: authoritative lifecycle plus reconciliation

This section records the intended end state.  It is not the shipping
completeness guarantee: the unsafe pull sweeps were removed as described in
§5b, so current providers use the push path only.

A **hybrid push + pull** model. Push gives low-latency reclamation; pull
guarantees eventual completeness even across missed events and restarts (a pure
pub/sub broadcast is lossy — bsdnotify drops on a full queue and never replays
after a restart, so a provider that is down when the event fires would leak
forever).

### 3.1 Source of truth — Capsule/switchboard

switchboard owns the installed-bundle set and Capsule mints the labels, so
**Capsule/switchboard is the sole truth for "is label L still valid?"** A label
is *retired* when its owning bundle is uninstalled from `/Capabilities` or its
principal is permanently decommissioned. Nothing else may assert a retirement —
a consumer must never be able to retire another label.

New Capsule/switchboard surface (privileged, over the control channel):

- **event** `label-retired(L)` — emitted when a label is retired.
- **query** `label_is_live(L) -> bool` and `label_list_live() -> [labels]` —
  for provider reconciliation.

### 3.2 Push — prompt reclamation via system.Notify

Capsule publishes `label-retired(L)` on a well-known Notify topic
**`system.label.retired`**. bsdnotify's per-topic policy restricts **publish to
the Capsule label only** (consumers may subscribe, never publish). Each
stateful provider subscribes and, on receipt, invokes its own `reclaim(L)`.

This is the low-latency path. It is explicitly **best-effort**: a provider that
missed the event (down, restarting, dropped from a full queue) is caught by the
pull path.

### 3.3 Pull — reconciliation sweep (the completeness guarantee)

Each stateful provider, **on startup and on a slow periodic timer**
(e.g. hourly, jittered), performs a mark-and-sweep:

```
for label in (my own resources, via the internal equivalent of LIST):
    if capsule.label_is_live(label) == false:
        reclaim(label)
```

Because the provider already stores its resources keyed by label (that is what
made the W14 `LIST` ops possible), the enumeration is free. The sweep converges
regardless of any missed event.

### 3.4 Per-provider `reclaim(label)` — privileged, built from LIST + DESTROY

Each stateful provider grows one **privileged** entry point, `reclaim(label)`,
distinct from the consumer's self-service `DESTROY`:

- Authorization: the caller must present the **Capsule** capability (the same
  trust root that emits retirements). A consumer cannot invoke reclaim for any
  label, including its own-via-this-path (it uses `DESTROY` for that).
- Implementation: internally it is exactly `LIST(label)` → `DESTROY(each)` — the
  W14 primitives are the building blocks. It must be **idempotent** (reclaiming
  an already-clean label is a no-op success) because push and pull can both fire
  for the same label.

Per-provider specifics:

| Provider | reclaim(L) does |
|---|---|
| tzfsd | destroy every dataset claim under `derive_ns(L)` |
| localcrypto | delete every named key owned by L (kernel keystore, owner-scoped) |
| warden | destroy every persistent jail owned by L |
| waspnest | free L's vsock window slot |
| logd | drop L's log store segments |

bsdnotify is not in this table: topic state lasts only for the router epoch and
is deleted when the label's final session disconnects; it is not durable
provider-owned state.

### 3.5 A bonus: waspnest window reclamation becomes safe

Earlier analysis (see the born-in-capmode notes) correctly rejected reclaiming a
vsock window **on disconnect** — that would reintroduce the squatting vuln (a
reconnecting label could be reassigned, or its slot handed to an attacker). This
design supplies the *safe* trigger: reclaim on **authoritative retirement**, when
Capsule confirms the label is truly gone — not on a mere disconnect. So the
deliberate 4096-window bound becomes reclaimable without weakening the
anti-squat invariant.

## 4. Trust & security model

- Only **Capsule** may emit `label-retired` (Notify topic publish-gated to the
  Capsule label) and only Capsule may invoke a provider's `reclaim`.
- A consumer can **subscribe** to retirements (useful for its own bookkeeping)
  but can neither publish them nor trigger another label's reclamation.
- `reclaim` is idempotent and fail-closed: an unknown/already-clean label is a
  no-op; a partial failure is retried on the next sweep.
- Reclamation is **destructive** — it must key strictly on the retired label and
  never touch a live label's resources (the same owner-scoping invariant the
  LIST/DESTROY ops already enforce).

## 5. What ships (implementation plan, after this review)

1. Capsule/switchboard: retirement detection on bundle uninstall; the
   `label-retired` publish; the `label_is_live` / `label_list_live` queries.
2. bsdnotify: the `system.label.retired` topic with Capsule-only publish
   policy (a per-topic publisher ACL — small extension to the notify policy).
3. Each of the five stateful providers: a privileged `reclaim(label)` op
   (LIST+DESTROY internally) + the startup/periodic reconciliation sweep + a
   Capsule verification on the reclaim caller.
4. USDT probes: `label-retired` (Capsule), `reclaim` (per provider: label,
   resources reclaimed, reason push|sweep).
5. Tests: pure (reclaim idempotency, owner-scoping — never touch a live label)
   + plane (retire a label, assert push reclaims it; simulate a missed event,
   assert the sweep reclaims it) + VM fleet verification.

## 5b. The pkg trigger + third-party extensibility (2026-09-06)

**Mechanism status:** the reclaim mechanism is BUILT + VM-verified + committed —
`switchboardctl reclaim <label>` (admin-gated `SCTL_OP_RECLAIM`) → switchboard broadcasts
`SVC_OP_RECLAIM_LABEL` to every running provider → each provider's registered
handler self-decides and reclaims that label's resources (tzfsd namespace destroy,
warden jails, localcrypto keys, waspnest window, logd records). Owner-scoped,
idempotent, DTrace-probed, per-provider tested; live broadcast to all 11 providers
confirmed on the plane, fleet green.

**Reclaim is PUSH-ONLY (updated after the 2026-09-06 security review).** The
adversarial review found a HIGH data-safety bug in the pull/reconcile *sweeps*
(warden/waspnest): they treated an operator-*disabled* (still-installed) bundle
as not-live and destroyed its jail/window, because `bundle_registry_label_installed`
conflates "disabled" with "uninstalled". Fix (commit f19cdb4008b): the warden and
waspnest reconcile sweeps were REMOVED — all providers are now push-only, matching
tzfsd/localcrypto/logd. The `label_is_live` query and `service_label_is_live(3)`
remain as dormant API. Consequence: a provider that is *down* during the push
leaks its share (recoverable — re-run `switchboardctl reclaim`), rather than risking
destruction of a live bundle's data. A SAFE backstop can be re-added later, but it
MUST use an *installed-on-disk*, fail-safe-to-live liveness source (return "live"
for a disabled-but-present bundle and for an empty/suspect registry), NOT the
active-registry check that caused the HIGH. The §3.3 pull-path text below is
retained as design rationale but is not the current implementation.

The cross-label isolation invariant and the reclaim trust boundary (admin-gating,
switchboard-sole-originator, validated fail-closed dispatch, pure-read label_is_live,
fail-soft client) were reviewed and confirmed correct. One MEDIUM remains open in
logd: its reclaimed-labels tombstone set is capped/monotonic, so after many
lifetime retirements reclaims fail and a *reused* label name could read the prior
owner's records — fix direction is a durable/larger tombstone or a physical
per-label prune.

**The pkg trigger (implemented):** a capability bundle is a pkgbase package; `pkg
delete` removes its static files. The runtime, daemon-owned resources it left
behind are reclaimed by a **post-deinstall hook** in the package manifest that
runs `/usr/libexec/switchboard-pkg-reclaim <label>...` for the package's
capability labels.  Hooks are attached only to each base package, not its
debug/development/manual subpackages:

```
scripts { post-deinstall = "/usr/libexec/switchboard-pkg-reclaim <label>..." }
```

**The deinstall reach path — the problem.** `pkg` runs deinstall scripts in a
plain root context with **no plane login session**, so it has no ambient
discovery channel. The everyday `switchboardctl reclaim` reaches
`SWITCHBOARD_CONTROL_NAME` only over that ambient channel (the old getpeereid
control socket was retired), and a `pkg` deinstall fork does not have one: `pkg`
preserves the `SERVICE_LOOKUP_FD` *environment variable* but **closes the
inherited descriptor** (verified). So `switchboardctl reclaim` driven purely over
the ambient plane cannot reach switchboard from a bare `pkg` script.

**DECIDED (owner's explicit call): a single dedicated, root-gated UNIX socket —
the reclaim bridge.** switchboard binds ONE AF_UNIX `SOCK_STREAM` listener at
`SWITCHBOARD_RECLAIM_SOCK` = `/var/run/switchboard-reclaim.sock` whose ONLY function
is to let a UNIX (pkg) context trigger a label reclaim. It is documented as the
**sole deliberate UNIX→plane bridge** on the system. This supersedes the earlier
"boot-provisioned SYSTEM ambient channel / carry fd 3 into pkg" plan: no Capsule
ambient-carry change is needed.

Why it is safe / grants no new authority:
  - Root can *already* drive `switchboardctl reclaim` via the ambient ADMIN control
    channel from an admin login session (`SCTL_OP_RECLAIM`, ADMIN-gated). The
    socket adds no capability root does not already hold.
  - It is **root-gated**: on each connection switchboard calls `getpeereid(2)` and
    requires `euid == 0`; any other peer is refused (`EPERM`) and the connection
    closed. The worst case it enables is a **root-only DoS** that reclaims a
    still-live label.
  - It does **reclaim and nothing else**: one fixed request in
    (`struct switchboard_reclaim_req` = `{ uint32_t version; char label[64]; }`),
    one fixed reply out
    (`struct switchboard_reclaim_reply` = `{ int32_t status; uint32_t
    providers_notified; }`), connection closed. There is no other op.
  - **Ownership/permissions:** switchboard runs as uid 976
    (capability:capability), so the socket node is owned by 976 and chmod'd
    `0600`. root (pkg) still connects — DAC bits never restrict a uid-0 process
    — while any other uid is refused at `connect(2)` by the mode AND, decisively,
    by the `getpeereid` euid == 0 gate. The mode is defense in depth; the
    getpeereid gate is the authority.
  - It reuses the existing authorized broadcast: a valid, authorized request
    calls `svc_retire_label()` (the same `SVC_OP_RECLAIM_LABEL` fan-out the
    ambient `SCTL_OP_RECLAIM` path uses), which runs in switchboard's own context.
  - Fail-soft: if the socket cannot be created at startup, switchboard logs a
    warning and runs normally (reclaim stays reachable over the ambient ADMIN
    plane); the listener is brought up after `/etc/rc` so `/var/run` exists.

Where it lives: path + wire structs in `lib/libcapsulert/switchboard_ctl.h`;
listener + accept/getpeereid/serve in `usr.sbin/switchboard/reclaim_bridge.c`
(pure predicates `reclaim_peer_is_authorized()`/`reclaim_req_valid()` in
`reclaim_bridge.h`, unit-tested in `tests/reclaim_bridge_test.c`); the CLI verb
`switchboardctl reclaim <label>` connects the socket (the ambient `SCTL_OP_RECLAIM`
handler is retained unchanged as a second path for admin-login callers).

Current safety behavior:

1. Alternate-root and chroot package operations never contact the host daemon.
2. Upgrades preserve state.
3. All labels in a multi-bundle package are attempted on every retry.
4. Failure is visible and names the manual recovery command; it is not hidden
   behind `|| true`.

Remaining robustness work:

1. Add per-provider completion acknowledgements.  The current reply confirms
   that a notification was queued, not that cleanup succeeded.
2. Add durable replay for a provider that is down for all three attempts or
   when SwitchBoard is unavailable throughout post-deinstall.
3. Bind retirement to an install generation.  Reusing a textual bundle label
   before delayed cleanup completes could otherwise target the new generation.
4. Move potentially slow provider cleanup off libservice's control-dispatch
   thread without introducing races in provider state.
5. VM end-to-end: create dataset+jail+key+log state, delete its package, verify
   each provider, repeat with a provider restart, an upgrade, and an offline
   root.

**Third-party extensibility (both directions work):**
- Third-party **providers**: participate automatically. switchboard broadcasts to
  EVERY running provider — a new `system.Foo` that holds per-label state just
  links libservice, calls `service_set_reclaim_handler()`, and implements its
  reclaim (optionally the `label_is_live` reconcile). No switchboard/CLI change. Safe:
  the broadcast only names the retired label; each provider acts solely on its own
  state, so it can never touch another provider's resources.
- Third-party **consumers**: get their provider-held resources reclaimed via the
  same post-deinstall hook (the reusable pattern documented above), AND their own
  `pkg` deinstall script still runs for any app-specific cleanup (stock pkg
  behavior, untouched).

## 6. Open questions for review

1. **Retirement granularity** — retire at the *bundle* label only, or also
   per-principal (a decommissioned user)? Bundle-uninstall is the concrete,
   switchboard-observable event; principal decommission needs a defined trigger.
2. **Sweep cadence** — hourly is a starting point; too frequent wastes work,
   too rare leaves orphans occupying space/quota longer. Tunable per provider?
3. **A dedicated lifecycle facility vs. folding into switchboard/Capsule** — the
   publish + liveness query could be a small new `system.Lifecycle` provider, or
   just methods on the existing Capsule/switchboard control surface. Leaning
   toward the latter (no new daemon; Capsule already is the truth).
4. **Grace period** — reclaim immediately on retirement, or after a grace window
   (in case a bundle is reinstalled)? A grace window avoids destroying data on a
   quick uninstall/reinstall or upgrade.
