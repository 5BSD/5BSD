# System lifecycle as a capability — design options

Status: **decided** (P4b of the capability-authority migration). Companion
to [capability-authority-model.md](capability-authority-model.md). This chose
*the* architecture for how a principal asks the system to change run state
(reboot / halt / poweroff / powercycle / reroot / rescan / catatonia /
single-user) in the object-capability model, before any boot-critical code moves.

## 0. Decision (2026-08-30): capability *beside* BSD

The guiding principle is that the capability world sits **next to** the BSD
world, not carved through it. `authority_init` (PID 1) is already the bridge — it
is BSD `init(8)` (signals, getty, rc, `reboot(2)`) *and* the capability spine.
BSD tools reach it the BSD way; capability tools reach it the capability way,
because it is both. So for lifecycle:

- **Stock `reboot`/`halt`/`shutdown` stay BSD.** They signal init, and init *is*
  `authority_init`, which already handles those signals. We **revert** the
  authorityd-socket code we added to `reboot.c`/`shutdown.c` — this *shrinks* our
  stock-BSD footprint rather than growing it, and puts no capability/`/usr`
  dependency in `/sbin`.
- **The capability path is a new capability-world tool, `authorityctl`**, living
  in `/usr` — the capability-native control CLI for the authority/spine, the
  exact parallel of `servicectl` for serviced. It covers the *whole* authorityd
  control surface (`authorityctl reboot|halt|poweroff|…`, `authorityctl status`,
  `authorityctl reload`), which is what lets the getpeereid socket be deleted
  outright. Routing is R1 (serviced self-serves the name, ADMIN-gated, and relays
  to authorityd over the existing authority channel).
- **The signal-to-init path stays.** It is how BSD tools reach init;
  `authority_init` handles it; it is already root- and MAC-gated. This
  deliberately **revises** the earlier P4b goal of deleting `kill(1,SIG*)`:
  coexistence keeps it as the BSD tools' legacy door, with the capability door
  (`authorityctl` → `system.lifecycle`/`system.authority`) beside it.
- **The authorityd getpeereid *socket* is still deleted** (§7): its ops are now
  reached by signal (BSD tools) or by `authorityctl` (capability plane).

The sections below (§3–§4) record the option analysis that led here; the client
question they weigh (inline vs static vs new tool) is now moot — the answer is a
new `/usr` tool and *no* change to `/sbin`.

## 1. The problem

Today a lifecycle transition reaches PID 1 two ways, both of which the migration
must retire:

1. **A getpeereid socket** — `reboot(8)` connects `AUTHORITYD_CTL_SOCK`, sends
   `CTL_OP_REBOOT`/etc.; authorityd authorizes by the peer euid, records the op,
   and PID 1's state machine (`oi_lifecycle_apply` → death transition →
   `reboot(2)`) applies it.
2. **A signal to init** — `reboot(8)` falls back to `kill(1, SIG*)`; PID 1's
   `transition_handler` maps the signal to the same transition. This path is
   MAC-gated: the signal shield (`CP_SF_SIGNAL`) is deliberately *withheld* while
   PID 1 has no listening control socket, and raised once the socket is up, so
   `kill(1,…)` is denied precisely when the socket is the sanctioned path.

The end state (capability-authority-model.md §11): **authority is a held
capability, not a uid, a PID, or the ability to signal init.** A principal
allowed to change run state holds a `lifecycle` capability and *presents* it to
the spine. `reboot(2)` remains only as the kernel escape hatch.

## 2. Constraints that shape the answer

- **C1 — `/sbin` tools must stay exec-able without `/usr`.** `reboot`/`halt`/
  `shutdown` live in `/sbin` and the source deliberately avoids `/usr` library
  dependencies (the inline socket client in `reboot.c` exists for this reason).
  A *dynamic* link to libservice (`/usr/lib`) would make `reboot` fail to even
  `exec` when `/usr` is not mounted (single-user, early boot, separate-`/usr`).
- **C2 — the capability plane only exists in multi-user.** Presenting
  `system.lifecycle` needs libservice, a running serviced, and an inherited
  ambient lookup channel. In single-user / early boot none of that is up.
- **C3 — `reboot(2)` is the floor.** When the plane is down, the tool must still
  bring the machine down; `reboot(2)` (with `sync`) is the guaranteed mechanism.
- **C4 — delete the socket *and* the signal path.** Success means neither
  `AUTHORITYD_CTL_SOCK` nor `kill(1,SIG*)` remains a lifecycle channel.
- **C5 — keep the PID-1-side change minimal.** PID 1 is the least forgiving
  place to be wrong; prefer reusing proven plumbing over new PID-1 machinery.

## 3. Two orthogonal questions

### 3a. Routing: how does a presented op reach PID 1?

| Option | Shape | PID-1 cost | Verdict |
|---|---|---|---|
| **R1 — serviced relay** | tool → serviced serves `system.lifecycle` (ADMIN-gated, exactly like the P3 `system.serviced` self-serve) → serviced relays the op to authorityd over the **existing** authority channel via a new `AUTHORITY_OP_LIFECYCLE` → authorityd calls `oi_lifecycle_apply` | tiny: one op + a wrapper over the existing static function; `oi_dispatch` already invokes `authority_proto_dispatch()` in the same PID-1 context | **chosen** |
| R2 — authorityd serves directly | authorityd registers `system.lifecycle` with serviced and accepts brokered channels itself (service-provider machinery inside PID 1) | large: new listener/registration/accept path inside PID 1 | rejected (violates C5) |

**R1 wins.** serviced already relays authority ops to authorityd (mint, storage,
ambient-lookup); lifecycle is one more. The capability's ADMIN gate is the same
mint P2/P3 already produce for admin login sessions, so authorization is
*identical* to the rest of the plane, and the PID-1 delta is a handful of lines.

### 3b. Client: what binary presents the capability, given C1?

This is the real question the `/usr` constraint forces.

| Option | `/sbin` stays `/usr`-free? | Code cost | Notes |
|---|---|---|---|
| A — inline capability client in `/sbin/reboot` | yes | high (~150 lines reimplementing the ambient lookup + one channel round-trip in raw `mac_capability` ioctls, and it must track the wire protocol) | duplicates libservice in the most fragile binary |
| B — static-link libservice into `/sbin/reboot` | yes | medium | pulls the whole lib chain (service+channel+capability+ucl) in static; unusual for base, bloats the escape tool |
| C — dynamic-link libservice into `/sbin/reboot` | **no** | low | simplest, but breaks C1 outright — reboot won't `exec` without `/usr` |
| **D — new `/usr` capability tool; `/sbin` delegates** | **yes** | low | `/sbin/reboot` stays minimal and `exec`s the `/usr` tool for a clean shutdown, falling back to `reboot(2)` if the `exec` fails (no `/usr` / plane down). Capability logic lives once, in `/usr`, linking libservice like `servicectl` already does. |
| E — invert: `/usr/sbin/reboot` is the capability tool, `/sbin/reboot` a tiny static `reboot(2)` escape | yes | medium | familiar name = capability path, but two binaries named `reboot`, PATH-order-dependent, and still needs the static escape |

## 4. Recommendation

**R1 + D.** A new `/usr` capability tool presents `system.lifecycle`; serviced
self-serves that name (ADMIN-gated) and relays to authorityd; `/sbin/reboot`/
`halt`/`shutdown` map their `howto` to an op and **`exec` the tool**, falling
back to `reboot(2)` when the tool is unavailable.

Why D over A/B/C/E:

- **C1 is preserved for free.** `/sbin/reboot` gains no library dependency and no
  protocol code — it just `exec`s a path and, on `ENOENT`/failure, calls
  `reboot(2)`. It is *more* robust than today (no socket/signal logic at all).
- **One implementation of the capability client.** The `/usr` tool reuses the
  exact `service_open()` + request/reply pattern P3 already shipped in
  `servicectl`. No new protocol surface in a fragile binary.
- **It is what lets C4 happen.** With clean shutdown flowing tool →
  `system.lifecycle` → serviced → authorityd, and degraded shutdown flowing
  through `reboot(2)`, nothing needs the authorityd socket or `kill(1,SIG*)` —
  both can be deleted, and the MAC signal-shield deferral in
  `mac_capability_claims.c` becomes an unconditional shield.
- **Delegation beats inversion (E).** Keeping the primary binary at its
  canonical `/sbin` path avoids two same-named tools and PATH ambiguity; the
  capability path is reached *through* the familiar command, and the escape lives
  in the same binary that already owns `reboot(2)` (`reboot -q`).

### Sub-choice: dedicated tool vs. a `servicectl` subcommand

- **Dedicated tool (recommended for clarity).** `system.lifecycle` is a distinct
  authority from serviced control (`system.serviced`); a distinct tool keeps that
  boundary legible and lets the lifecycle capability be delegated/attenuated
  independently. Naming follows the `*ctl` convention already in the tree
  (`servicectl`, `tzfsctl`, `notifyctl`, `meshctl`) — a candidate is
  `lifecyclectl`. Verbs cover the full op set (reboot/halt/poweroff/powercycle/
  reroot/rescan/catatonia/single).
- **`servicectl reboot` subcommand (lower effort).** Zero new binary — servicectl
  already links libservice and speaks the plane. But it conflates "control the
  service manager" with "change system run state," and couples the two
  authorities. Acceptable as an expedient; not the clean end state.

The routing and the `/sbin` delegation are identical either way, so this can be
deferred without reworking anything else.

## 5. Concrete architecture (R1 + D)

```
  admin shell (holds ambient lookup channel)
        │  runs `reboot` (or the tool directly)
        ▼
  /sbin/reboot  ── maps howto→op ──► exec /usr/sbin/<tool> <op>
        │                                   │  (inherits ambient channel)
        │ exec fails / plane down           ▼
        ▼                            <tool>: service_open("system.lifecycle")
   reboot(2)  (kernel escape)               │  send {op}; await ack
        (single-user, early boot)           ▼
                                     serviced: self-serves system.lifecycle
                                       (ADMIN-gated, P3 self-serve pattern)
                                       relays AUTHORITY_OP_LIFECYCLE ──► authorityd
                                                                            │
                                                          authority_init_lifecycle(op)
                                                                            ▼
                                                          oi_lifecycle_apply(op)
                                                          → death transition → reboot(2)
```

Components:

- **`<tool>` (`/usr/sbin`)** — capability client; links libservice; `service_open`
  + one request/reply carrying the op; prints the spine's ack/errno.
- **serviced** — self-serves `system.lifecycle` alongside `system.serviced`
  (same `naming_lookup` fork + adopt-channel machinery, ADMIN-gated); its handler
  relays the op to authorityd via a new `authority_lifecycle(op)` wrapper in
  `authority_client.c` (`AUTHORITY_OP_LIFECYCLE`).
- **authorityd** — `authority_proto.c` gains one `case AUTHORITY_OP_LIFECYCLE`
  that reads the op and calls a new public `authority_init_lifecycle(int op)`,
  which is a thin wrapper over the existing static `oi_lifecycle_apply`. No state
  machine changes: this is the same call the control-socket path makes at
  `oi_dispatch`.
- **`/sbin/reboot`/`halt`/`shutdown`** — replace the socket+signal block with:
  `exec` the tool; on failure, `reboot(2)`. `reboot -q` (direct `reboot(2)`)
  is unchanged.

## 6. Degraded-mode behavior (explicit)

- **Single-user / early boot / no `/usr`:** the `exec` fails; `/sbin/reboot`
  calls `reboot(2)` (with `sync`). No `rc.shutdown` runs — this is a deliberate,
  documented consequence: the clean, service-ordered shutdown requires the plane,
  and maintenance mode gets the guaranteed kernel path. (If service-ordered
  single-user shutdown is later deemed necessary, PID 1 can run `rc.shutdown`
  itself on a `reboot(2)` request; out of scope here.)
- **Plane up but authorityd wedged:** the tool times out; `/sbin/reboot` still
  falls back to `reboot(2)`.

## 7. What this deletes (C4)

- `AUTHORITYD_CTL_SOCK` and all of `usr.sbin/authorityd/control.c`'s lifecycle
  handling (the STATUS/RELOAD admin ops re-home separately or move to a
  `system.authority` capability; SHUTDOWN is meaningless when authorityd is PID 1).
- `reboot(8)`'s socket client and its `kill(1,SIG*)` fallback.
- The signal-shield deferral in `mac_capability_claims.c` (`if getpid()==1 …
  &= ~CP_SF_SIGNAL`) — the shield becomes unconditional, closing the
  `kill(1,SIG*)` path for good; init's `transition_handler` lifecycle arms retire.

## 8. Migration (dual-path, verify each on the ZFS image)

1. Land the plane: `AUTHORITY_OP_LIFECYCLE` + authorityd wrapper; serviced
   `system.lifecycle` self-serve + relay; the `/usr` tool. Verify a **real
   reboot** driven by the tool on a fresh ZFS image, with the socket/signal still
   present.
2. Point `/sbin/reboot`/`halt`/`shutdown` at the tool (exec-then-`reboot(2)`),
   keeping the socket as a temporary fallback. Verify clean reboot via `reboot`.
3. Delete the authorityd socket + signal path + the shield deferral; make the
   shield unconditional. Verify clean reboot, single-user `reboot(2)`, and that
   `kill(1,SIGINT)` is denied.
```
