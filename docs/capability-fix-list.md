# Capability plane — fix list

Tracked backlog of maturity work raised during the naming/hardening review.
Grouped by theme; each item is meant to be independently buildable and
VM-validated.

## New providers (net-new capabilities)

Each is a TCB component and should get its own focused build (design → provider
+ manifest with `protect` + ambient/policy → DTrace provider → tests → man →
docs), the way BSDExtension/BSDNamespace were done — not rushed as a batch.

- **BSDTime** (`system.Time`) — broker clock set / `adjtime` / RTC. Ambient
  (needs `PRIV_SETTIMEOFDAY`); default-deny writes, per-label policy. Reads stay
  unbrokered (any process may read the clock).
- **BSDPower** (`system.Power`) — suspend/resume, ACPI, thermal/battery.
  Boundary: capsule keeps reboot/halt; BSDPower owns the rest. Ambient.
- **BSDFirewall** (`system.Firewall`) — a pf wrapper brokering `/dev/pf` ioctls
  with a whitelist + per-label policy, on the BSDDevice model (delivered
  `/dev/pf` fd, cap_rights + ioctl allow-list).

## Testing hardening (target: privileged/ambient providers ≥ ~1.0 test:src with negative/adversarial/policy cases)

- **BSDFilesystem** (tzfsd) — 0.45, fleet minimum, storage TCB. The
  request/mount broker path (provisioning, anon-mount anchors, quota) is thin.
  Highest-value lift.
- **BSDVM** (waspnest) — 11 cases, ambient VM/bhyve+vsock broker.
- **BSDSysctl** — DONE: policy-boundary adversarial suite added (config_test
  5 → 10).
- BSDTrace looked thin by ratio but its session_test already covers the
  security-critical paths (one-shot auth, unauthorized-open denied,
  poison-session); left as-is intentionally.

## Remove unnecessary hardcoding (a "magic string" sweep of the TCB)

The mint authority and admin anchors are hardcoded in `switchboard.h`:

- `SVC_MINT_PRINCIPAL_LABEL "system.Auth/authagentd"` — switchboard identifies
  the identity-mint authority by an exact `strcmp` (svc_proto.c). The *decision*
  (which single bundle may mint identities) is a trust anchor and MUST stay in
  the TCB, not runtime config — otherwise editing config forges identities. But
  the *mechanism* (a magic label string) is brittle: switchboard should
  recognize the mint authority by a **manifest-declared role** it validates
  (like `ambient`/`protect`), so the identity is not a hardcoded string.
- `SVC_ANOINT_SWITCHBOARD_ADMIN "system.switchboard.admin"` — same shape;
  same treatment.
- Legit defaults (keep, but confirm each is override-able where it should be):
  `CAPSULE_DEFAULT_CONFFILE`, `SWITCHBOARD_BUNDLE_DIR_SYSTEM/USER_DEFAULT`,
  `SWITCHBOARD_RUN_DIR_DEFAULT`, `SWITCHBOARD_DISABLED_PATH`.

Sweep goal: no TCB *identity/authority* decision keyed on a hardcoded string;
paths remain compile-time defaults but overridable via config where sensible.

## Boot ordering: legacy rc vs the capability plane

Verified ordering is **plane-first**: capsule (PID 1) → switchboard (installs
the ambient lookup channel) → `/etc/rc` as a blocking oneshot (startup.c).
rc and all its descendants — getty, login, su, sshd — inherit that ambient
channel (domain.c), which is why **root login works and root's channels are
delivered** (validated by the boot-check's `ROOT_CHANNEL` + `SYSCTL_DISCOVERY`
assertions, run as root over the console after the login mint).

So rc does NOT start before the capability world. The real debt underneath:
`/etc/rc` still starts the **full legacy rc.d world** (networking, syslogd, …)
as un-sandboxed ambient-authority processes; only a curated allow-list
(`rc_adopt.c`, currently just `cron`) is absorbed as capability units. Direction
of travel: incrementally migrate rc.d services into the plane so the
un-capability-governed legacy surface shrinks.

## Documentation

- **Book rework, dev-first** — restructure the mdBook around how a developer
  works with the capability model (write a provider, client APIs,
  born-in-capmode, protect/anoint/DTrace, cap_xfer/coalitions/env-descriptors),
  not reference prose. Per-daemon reference under the final `BSD*` names.

## Naming loose ends (minor)

- Package names still old (`PACKAGE=localcrypto`, `packages/authagentd/`, …) —
  cosmetic; renaming cascades into release/packages ucl manifests.
- Internal source filenames still old inside renamed dirs (e.g.
  `BSDSysctl/localsysctl.c`) — dev-facing but low-value churn.
