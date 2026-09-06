# Capability resource lifecycle & cleanup

Status: **APPROVED — decisions locked 2026-09-06; implementation in progress.**
Author: 2026-09-06.

## 0. Locked decisions (review outcome)

- **Home:** fold into authority/serviced — **no new daemon** (no `system.Lifecycle`).
- **Granularity:** **bundle-label only.** A retirement fires when a bundle is
  uninstalled from `/Capabilities`; the retired label is that bundle's manifest
  label. Per-principal (decommissioned-user) retirement is out of scope for now.
- **Timing:** **immediate reclaim** — no grace window. (Upgrades that reinstall
  the same bundle re-create their own resources; we do not preserve orphaned
  state across an uninstall.)
- **Sweep cadence (the one item left to the implementer):** startup + an
  hourly, jittered periodic reconciliation.
- **Push transport:** because serviced already holds a **control channel to
  every provider it launches**, the push is a `reclaim(label)` control-channel
  message from serviced — NOT a bsdnotify topic. This is the literal "fold into
  serviced": no serviced→Notify publish dependency, no per-topic publisher ACL,
  and providers need not subscribe to Notify. The bsdnotify idea was the seed;
  the control channel is the fold. The pull path (serviced `label_is_live`
  query) covers providers that were down when the push fired. Sections below
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
| bsdnotify (system.Notify) | retained per-topic state |

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

## 2. Why not UNIX as the management plane

These resources deliberately live **outside** the UNIX namespace: tzfsd datasets
are anonymous mounts invisible to `find /`; named keys live in the kernel
keystore, not files; vsock windows, jails, and retained notify state are not
paths, uids, or PIDs. `rm`, `pkg`, and a UNIX admin cannot see or reclaim them,
and making them UNIX-visible would contradict the "authority = held capability,
not path/uid" model. **Cleanup must be a first-class capability-plane mechanism
keyed on labels, not delegated to UNIX.**

## 3. Design: authoritative label-lifecycle, reclaimed via the W14 primitives

A **hybrid push + pull** model. Push gives low-latency reclamation; pull
guarantees eventual completeness even across missed events and restarts (a pure
pub/sub broadcast is lossy — bsdnotify drops on a full queue and never replays
after a restart, so a provider that is down when the event fires would leak
forever).

### 3.1 Source of truth — authority/serviced

serviced owns the installed-bundle set and authority mints the labels, so
**authority/serviced is the sole truth for "is label L still valid?"** A label
is *retired* when its owning bundle is uninstalled from `/Capabilities` or its
principal is permanently decommissioned. Nothing else may assert a retirement —
a consumer must never be able to retire another label.

New authority/serviced surface (privileged, over the control channel):

- **event** `label-retired(L)` — emitted when a label is retired.
- **query** `label_is_live(L) -> bool` and `label_list_live() -> [labels]` —
  for provider reconciliation.

### 3.2 Push — prompt reclamation via system.Notify

Authority publishes `label-retired(L)` on a well-known Notify topic
**`system.label.retired`**. bsdnotify's per-topic policy restricts **publish to
the authority label only** (consumers may subscribe, never publish). Each
stateful provider subscribes and, on receipt, invokes its own `reclaim(L)`.

This is the low-latency path. It is explicitly **best-effort**: a provider that
missed the event (down, restarting, dropped from a full queue) is caught by the
pull path.

### 3.3 Pull — reconciliation sweep (the completeness guarantee)

Each stateful provider, **on startup and on a slow periodic timer**
(e.g. hourly, jittered), performs a mark-and-sweep:

```
for label in (my own resources, via the internal equivalent of LIST):
    if authority.label_is_live(label) == false:
        reclaim(label)
```

Because the provider already stores its resources keyed by label (that is what
made the W14 `LIST` ops possible), the enumeration is free. The sweep converges
regardless of any missed event.

### 3.4 Per-provider `reclaim(label)` — privileged, built from LIST + DESTROY

Each stateful provider grows one **privileged** entry point, `reclaim(label)`,
distinct from the consumer's self-service `DESTROY`:

- Authorization: the caller must present the **authority** capability (the same
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
| bsdnotify | drop L's retained topic state (subscriptions/timers die with the session already) |

### 3.5 A bonus: waspnest window reclamation becomes safe

Earlier analysis (see the born-in-capmode notes) correctly rejected reclaiming a
vsock window **on disconnect** — that would reintroduce the squatting vuln (a
reconnecting label could be reassigned, or its slot handed to an attacker). This
design supplies the *safe* trigger: reclaim on **authoritative retirement**, when
authority confirms the label is truly gone — not on a mere disconnect. So the
deliberate 4096-window bound becomes reclaimable without weakening the
anti-squat invariant.

## 4. Trust & security model

- Only **authority** may emit `label-retired` (Notify topic publish-gated to the
  authority label) and only authority may invoke a provider's `reclaim`.
- A consumer can **subscribe** to retirements (useful for its own bookkeeping)
  but can neither publish them nor trigger another label's reclamation.
- `reclaim` is idempotent and fail-closed: an unknown/already-clean label is a
  no-op; a partial failure is retried on the next sweep.
- Reclamation is **destructive** — it must key strictly on the retired label and
  never touch a live label's resources (the same owner-scoping invariant the
  LIST/DESTROY ops already enforce).

## 5. What ships (implementation plan, after this review)

1. authority/serviced: retirement detection on bundle uninstall; the
   `label-retired` publish; the `label_is_live` / `label_list_live` queries.
2. bsdnotify: the `system.label.retired` topic with authority-only publish
   policy (a per-topic publisher ACL — small extension to the notify policy).
3. Each of the six stateful providers: a privileged `reclaim(label)` op
   (LIST+DESTROY internally) + the startup/periodic reconciliation sweep + an
   authority-verify on the reclaim caller.
4. USDT probes: `label-retired` (authority), `reclaim` (per provider: label,
   resources reclaimed, reason push|sweep).
5. Tests: pure (reclaim idempotency, owner-scoping — never touch a live label)
   + plane (retire a label, assert push reclaims it; simulate a missed event,
   assert the sweep reclaims it) + VM fleet verification.

## 6. Open questions for review

1. **Retirement granularity** — retire at the *bundle* label only, or also
   per-principal (a decommissioned user)? Bundle-uninstall is the concrete,
   serviced-observable event; principal decommission needs a defined trigger.
2. **Sweep cadence** — hourly is a starting point; too frequent wastes work,
   too rare leaves orphans occupying space/quota longer. Tunable per provider?
3. **A dedicated lifecycle facility vs. folding into serviced/authority** — the
   publish + liveness query could be a small new `system.Lifecycle` provider, or
   just methods on the existing authority/serviced control surface. Leaning
   toward the latter (no new daemon; authority already is the truth).
4. **Grace period** — reclaim immediately on retirement, or after a grace window
   (in case a bundle is reinstalled)? A grace window avoids destroying data on a
   quick uninstall/reinstall or upgrade.
