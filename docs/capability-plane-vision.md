# The 5BSD Capability Plane — a comprehensive vision

Status: vision / architecture north-star. Descriptive of where we are and
prescriptive of where we are going. 2026-09-06.

---

## 1. One idea

**Authority is a held capability, never an ambient identity.**

Not a uid, not a path, not a PID, not "root." A program may act only through
capabilities it was *given*, each one an unforgeable, narrowable, revocable
handle to exactly one thing. Everything else in this document is a consequence
of taking that single rule seriously and pushing it all the way down.

Traditional UNIX answers "may I?" by asking *who are you* (uid) and *what path*.
The capability plane answers "may I?" by asking *what do you hold*. The two
coexist: the plane sits **beside** BSD, not on top of a rewrite — stock UNIX
still runs, but the security-relevant surface migrates onto held capabilities.

---

## 2. The shape of the world

```
            Capsule (PID 1)          the trusted root: brings the plane up
               │
        ┌──────┴───────┐
     authority       serviced        mint authority  +  launcher/switchboard
        │               │                              & bundle-lifecycle owner
        │        ┌──────┴────────────────────────┐
        │     system.* providers  ...........  consumers (apps/components)
        │     (Filesystem, Crypto,             each an unforgeable label,
        │      Network, Log, Device,           reaching services by NAME
        │      Namespace, Sysctl, ...)         over its own channel
        └── unforgeable mac_capability channels everywhere ──┘
```

- **Capsule** is PID 1 — the minimal trusted root that claims the plane and
  hands off. Smallest possible TCB at the base.
- **authority** mints labels and capabilities; it is the source of truth for
  *who is who* and *what is granted*.
- **serviced** launches every component, brokers name lookups, supervises, and
  owns **bundle lifecycle** (install/uninstall of `/Capabilities` bundles). It is
  the capability plane's package/lifecycle manager.
- **Providers** (`system.Filesystem`, `system.Crypto`, `system.Network`,
  `system.Log`, `system.Device`, `system.Namespace`, `system.Sysctl`,
  `system.SystemExtension`, `system.Waspnest`, `system.Audit`, `system.Notify`,
  `system.Trace`, `system.AuthAgent`) each broker exactly one kernel or system
  facility, handing back Capsicum-narrowed descriptors. They are socket-free
  `service_provider`s reached by name, never by a global socket.
- **Consumers** are components with unforgeable labels that reach services by
  name over a channel and receive narrowed capabilities.

Names are the only global namespace. Everything reachable is reached by asking
serviced to resolve a name into a channel; the channel's label is unforgeable.

---

## 3. Born sandboxed

A daemon must not have a window in which it runs un-sandboxed. So capability
providers are **born in capability mode**: serviced `cap_enter()`s the child
*before* `fexecve`, delivering pre-opened resources (its config, its `/dev`
directory descriptor, its storage) so the daemon never names a global path.
From instruction one it can only touch what it was handed.

The exceptions are explicit and few: a small set of providers that must perform
a genuine root+global-namespace kernel op (kldload, jail_set, ZFS mount, gated
sysctl writes) run privileged by documented necessity, not by accident. Casper —
the fork-before-sandbox zygote — is fully retired from the plane.

The corollary: authority is *carried in*, not *acquired*. A provider begins with
exactly its grant and can only narrow from there.

---

## 4. Every service is complete, self-describing, and observable

A capability service is not useful if you can only guess at it. So each provider
converges on the same shape:

- **A full verb surface**, not a subset — read/write/introspect/enumerate for its
  domain (system.Sysctl needs get/set/oidfmt/descr/next, not just get/set).
- **`LIST`** — enumerate what *you* own, scoped to your own label. The plane is
  self-describing: a holder can always ask "what do I have?"
- **`DESTROY`/`DELETE`** — reclaim what you own. The plane is self-cleaning at
  the holder's own initiative.
- **A client library** — the contract is code, not folklore.
- **USDT DTrace probes** — every operation is observable; the plane explains
  itself at runtime.
- **Tests at two altitudes** — pure logic tests and live-plane provider tests.
- **Man page + book** — the contract is documented.

`LIST` + `DESTROY` are not incidental features. They are the primitives that make
the plane *manageable*: everything else about lifecycle is built from "enumerate
what a label owns" and "reclaim it."

---

## 5. The per-app home — one app, one directory, one delete

This is the organizing principle for persistent state and the key to cleanup.

**Each app (each consumer label) has exactly one capability home: a per-label
namespace under `system.Filesystem` (tzfsd).** It is anon-mounted, invisible to
the UNIX namespace, keyed by the unforgeable label — a capability-plane
directory, not a UNIX path. All of an app's file-backed persistent state lives
under it, and providers that persist bytes on an app's behalf store them there
(logd already delegates its store to a tzfsd-delivered directory).

This is deliberately the same shape the rest of the industry converged on —
iOS/macOS app containers, Android per-app data, Flatpak/Snap per-app dirs — and
it is also the pragmatic form of the seL4/Genode ideal: the home *is* the grant,
and destroying it reclaims everything derived, in a single revoke.

Consequences:

- **Isolation** is spatial and obvious: an app's persistent world is one subtree
  it alone can reach.
- **Accounting** has a natural home: a quota on the namespace bounds the app's
  total persistent footprint (the endgame — see §7).
- **Cleanup** is one operation: destroy the namespace.

The honest edge: some per-label state is a **kernel object**, not a file —
localcrypto named keys, persistent warden jails, waspnest port windows. These
cannot literally live in a directory today. So the model is two tiers:

1. **Tier 1 — the per-app namespace** is the home for all file-backed state and
   the dominant cleanup unit. Destroying it covers the vast majority.
2. **Tier 2 — a minimal per-provider `reclaim(label)`** for the few kernel-object
   holdouts, built from the same `LIST`+`DESTROY` primitives.

The direction of travel (§7) is to shrink tier 2 toward zero by re-homing even
kernel-object state as sealed material under the namespace, until the invariant
is pure: **one app = one directory = one delete.**

---

## 6. Resource lifecycle — how things are born and reclaimed

Two lifetimes, two mechanisms, both modeled on what mature systems proved works:

**Session-scoped state dies with the channel.** A worker, an open descriptor, a
live session — its lifetime is the channel's. When the unforgeable channel
closes (the client exited, was killed, lost its grant), the provider's per-session
state goes with it. This is the Mach dead-name / QNX connection-close / Genode
session-close pattern: reclamation is driven by a reliable, OS-mediated signal
tied to the holder's death, not by polling and not by trust.

**Persistent state is reclaimed at decommission.** State designed to outlive the
process (the app's namespace, its named keys) is reclaimed when the *owner
itself* is decommissioned — its bundle uninstalled. That is a management event,
and serviced — the plane's bundle-lifecycle owner — is exactly the right and
authoritative place to trigger it. On uninstall, serviced retires the label and:

- destroys the app's per-app namespace (tier 1 — the bulk), and
- pushes `reclaim(label)` to the kernel-object providers over the **control
  channel it already holds to each of them** — a reliable notification (the Mach
  dead-name analog), *not* a lossy broadcast —
- with a **reconciliation query** (`label_is_live`) providers run on
  startup and periodically as the completeness backstop for anything a
  down provider missed.

Push for latency, pull for completeness, revoke-the-home for the bulk. No
in-kernel GC, no ambient sweeper; reclamation is authority-driven and structural.

**We do not delegate this to UNIX.** `rm`, `pkg`, an admin — none can see anon
mounts or kernel keystore objects. Cleanup is a first-class capability-plane
operation keyed on labels, driven by the plane's own lifecycle authority.

---

## 7. The endgame — leaks impossible by construction

seL4 and Genode point at the destination: resources *derived* from an explicit,
quota-bounded grant, reclaimed by revoking the grant. Applied here:

- Every app's persistent footprint is **quota-accounted against its per-app
  namespace**. A provider persisting on the app's behalf spends the app's quota,
  under its namespace. A component cannot leak beyond what it was granted,
  because there is nowhere else for its state to live.
- **Decommission = revoke the namespace.** Everything derived collapses in one
  operation. Tier-2 reclaim shrinks toward zero as kernel-object state is
  re-homed as sealed material under the namespace.
- The result is the strongest possible invariant: an app's entire persistent
  existence is one revocable grant, and the system cannot accumulate orphans.

This is the same place seL4/Genode arrived at from the memory side; we arrive at
it from the storage/namespace side, which is the natural fit for a system whose
persistent substrate is TrustedZFS.

---

## 8. Assurance — the plane must be trustworthy end to end

- **The TCB is small and gets the deepest scrutiny.** Capsule (PID 1), serviced,
  and authority are the root of trust; they warrant the most testing, tracing,
  and adversarial security review — more than any single provider.
- **Everything is traced.** USDT probes on every operation mean the running plane
  can be observed, audited, and explained without guesswork; the observability
  substrate (dtrace, traced, instruments) is itself a first-class provider.
- **Everything is tested at two altitudes** — pure logic and live-plane — and
  security-relevant invariants (owner-scoping, fail-closed, single-transfer
  descriptors, no privilege widening) are regression-guarded.
- **Audit is a capability too.** Security-relevant actions commit to the audit
  trail from within capability mode via system.Audit.

---

## 9. Where we are, where we are going

**Standing today:** the authority model is in force; Capsule is PID 1; serviced
launches the fleet; 8 of 13 providers are born-in-capmode and the other 5 are
documented, legitimate privileged exceptions; Casper is fully retired; every
provider has a complete verb surface plus `LIST`/`DESTROY`, USDT probes, tests,
and docs; tzfsd already gives each label a per-namespace home and logd already
stores under a tzfsd-delivered directory.

**Next:**
1. Make the **per-app tzfsd namespace the canonical persistent home**, and route
   providers' persistent state under it.
2. **Cleanup**: serviced retires a label on bundle uninstall → destroy the app's
   namespace (tier 1) + minimal `reclaim(label)` to the kernel-object providers
   (tier 2), with `label_is_live` reconciliation as the backstop.
3. **Deep-audit the TCB** — Capsule, serviced, authority — for testing, tracing,
   security, and API completeness, since they were never in the per-provider
   audit and carry the most trust.
4. **Quota-account the per-app namespace** and begin re-homing kernel-object
   state under it, walking toward "one app = one directory = one delete" and
   leaks impossible by construction.

**The line that holds all of it together:** a program is exactly what it holds;
its whole persistent existence is one revocable grant; and when it is gone, one
revoke reclaims it — with nothing ambient, nothing trusted-by-default, and
nothing left behind.
