# Capability sysctl isolation

Status: design + Phase 1. Author: Kory Heard. 2026-09-06.

## Problem

`sysctl` is a single global namespace of kernel tunables. On the capability
plane we want the **secure realm** to control a **configurable subset** of it —
not all of it — and to have the UNIX side reach the controlled OIDs **through
the `system.Sysctl` daemon (`localsysctl`)** rather than by direct `__sysctl(2)`.

Two mechanisms exist today and neither meets that goal on its own:

- **The kernel gate `SYS_GATE_SYSCTL`** (`mac_capability_system`) is
  *all-or-nothing*: whoever claims it makes *every* privileged sysctl write by a
  foreign nonce fail. Too coarse — it can't isolate "just these OIDs," and
  claiming it would force *all* privileged writes through one path.
- **`localsysctl`'s per-label `sysctl.conf` ACL** is a good policy layer, but it
  is only consulted by callers that *choose* to go through the daemon. Nothing
  makes a privileged process go through it; it can `__sysctl` directly. So the
  ACL is advisory, not enforced.

## Goal

Make the kernel gate **per-OID and config-driven**, mirroring
`mac_capability_isolation` (which already does config-driven, per-resource
claims for vnodes / net endpoints / jails):

- The secure realm isolates a **named, configured set of OIDs**. Only those are
  gated; every other sysctl stays directly writable (subject to the normal
  `PRIV_SYSCTL_WRITE` check).
- For an isolated OID, a foreign nonce's direct write is **denied** — the only
  way to write it is to ask **`localsysctl`**, which holds the claim and brokers
  the write per its per-label `sysctl.conf`.
- Policy (which OIDs, and per-label allow/deny) lives entirely in userland
  (`localsysctl`'s config). The kernel only enforces the claimed set.

This keeps three properties the request called for: **not all** (only the
claimed subset), **config-driven** (localsysctl supplies the set), and
**daemon-brokered** (localsysctl is the sole writer of the isolated OIDs).

## Non-goals / preserved invariants

- **Reads are never gated.** Unchanged. `newptr == NULL` returns early.
- **`sysctl` name resolution is never gated.** The `CTLFLAG_ANYBODY` exemption
  (the `CTL_SYSCTL` `NAME2OID`/`NEXT`/... magic nodes, and `kern.proc.args`)
  stays — an isolated OID is matched by identity, not by treating name lookups
  as writes. (See the fix in `mac_capability_system.c`.)
- **Owner-scoping (crown jewel).** An isolation decision keys only on the
  unforgeable channel nonce (claim owner) and the accessed OID identity, never a
  wire-supplied caller identity.
- **Back-compat.** A `SYS_GATE_SYSCTL` claim that carries *no* OID set keeps the
  current coarse behavior (gate all privileged writes). New claimers pass an OID
  set to get the scoped behavior. No existing claimer changes meaning.

## OID identity

An isolated OID is named by its **MIB** (the `int[]` array, e.g. the mib for
`kern.maxfiles`), bounded by `CTL_MAXNAME`. `localsysctl` already resolves names
to MIBs via the `CTL_SYSCTL` magic nodes, so it sends MIBs in the claim. The
kernel compares the accessed OID's MIB (reconstructed by walking
`SYSCTL_PARENT` from the leaf `oidp`, bounded depth) against the claimed set.
MIBs, not `struct sysctl_oid *` pointers, are the stored identity so there is no
dynamic-oid lifetime hazard; isolated OIDs are static tunables in practice, so
the per-write comparison cost (small set × shallow depth) is negligible and only
paid for genuinely privileged (non-`ANYBODY`) writes.

## Wire format (Phase 1)

The fixed request header is unchanged and remains the compatibility floor:

```c
struct sys_request { uint32_t op; uint32_t gates; } __packed;   /* unchanged */
```

A `SYS_OP_CLAIM` whose `gates` includes `SYS_GATE_SYSCTL` MAY carry a trailing
OID-set payload; the kernel detects it by `req_len > sizeof(struct sys_request)`
(no payload => coarse mode, exactly as today):

```c
#define SYS_OID_MAXDEPTH  CTL_MAXNAME   /* 24 */
#define SYS_SYSCTL_MAXOIDS 64           /* per-claim isolated-OID cap */

struct sys_sysctl_oid {
        uint32_t depth;                 /* 1..SYS_OID_MAXDEPTH */
        int      mib[SYS_OID_MAXDEPTH];
} __packed;

struct sys_sysctl_oidset {
        uint32_t noids;                 /* 1..SYS_SYSCTL_MAXOIDS */
        struct sys_sysctl_oid oids[];   /* noids entries */
} __packed;
/* Full CLAIM payload with OIDs: sys_request followed by sys_sysctl_oidset. */
```

Validation (fail-closed): `noids` in range, each `depth` in range, total length
matches `req_len`, `gates` a subset of `SYS_GATE_ALL`. A malformed payload is
`EINVAL`; the claim is not created.

## Kernel storage (Phase 1)

`struct sys_claim` gains an optional isolated-OID set for the SYSCTL gate:

```c
struct sys_claim {
        ...
        uint32_t         sc_gates;
        u_int            sc_gate_refs[32];
        /* SYSCTL per-OID isolation (NULL/0 => coarse: gate all writes) */
        struct sys_sysctl_oid *sc_sysctl_oids;
        u_int            sc_nsysctl_oids;
};
```

Allocated with the claim, freed on `sys_revoke`. `sc_nsysctl_oids == 0` means
coarse mode for this claim (current behavior).

## Hook algorithm (Phase 1)

`sys_mac_system_check_sysctl` (unchanged prefix: read/`ANYBODY` exemptions
first), then:

1. Reconstruct the accessed OID's MIB from `oidp`.
2. `sys_sysctl_oid_is_isolated(mib, depth)` under `sys_lock`: scan claims that
   cover `SYS_GATE_SYSCTL`. A claim with `sc_nsysctl_oids == 0` isolates **every**
   OID (coarse, back-compat). A claim with an OID set isolates an OID iff its MIB
   is in the set. Returns whether isolated (and lets `sys_check_gate` do the
   owner/authorization decision exactly as for any other gate).
3. If **not** isolated by any claim → `return 0` (pass; normal privilege checks
   already ran). If isolated → `sys_check_gate(cred, SYS_GATE_SYSCTL, ...)` —
   same owner/token/authorize logic as every other gate, so `localsysctl` (the
   claim owner) writes freely and foreign nonces are denied unless token-
   authorized.

This reuses the existing claim/mint/authorize/revoke machinery unchanged; only
the "does this gate apply to this OID" test becomes set-aware.

## Phases

- **Phase 1 (this change): kernel + wire.** Extend the proto, claim storage, and
  the hook to consult a per-claim OID set; keep empty-set = coarse. Kernel ATF
  tests (`mac_capability_system_test`, CAPLANE_OFF VM): a claim listing only OID
  X denies a foreign write to X but allows a foreign write to a different
  privileged OID Y; empty-set claim still gates all; name resolution unaffected;
  token-authorized foreign write to X allowed.
- **Phase 2: `localsysctl` claims the configured set.** `localsysctl` loads the
  isolated-OID list from its config (`sysctl.conf` / an `isolate` stanza),
  resolves names to MIBs, and issues the OID-set `SYS_OP_CLAIM` at startup so it
  becomes the broker for exactly those OIDs. (Requires `privileged = true` in its
  Unit.ucl — it already is, for capmode sysctl.)
- **Phase 3: broker path + wiring.** Ensure the `localsysctl` SET path performs
  the write on behalf of an authorized client per the per-label ACL; wire the
  isolated-set config into the provider bundle; end-to-end VM test (client
  denied direct write to an isolated OID, succeeds via the daemon).

## Security review checklist (per phase)

- Owner-scoping: isolation keyed on claim nonce + OID identity only.
- Fail-closed parsing of the OID-set payload; bounded sizes; no OOB.
- Back-compat: empty-set claim identical to today; existing claimers unchanged.
- Reads and name resolution never gated (regression tests stay green).
- Revoke frees the OID set; no leak; counter/state consistent under `sys_lock`.
