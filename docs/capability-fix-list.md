# Capability plane — fix list

Tracked backlog of maturity work raised during the naming/hardening review.
Grouped by theme; each item is meant to be independently buildable and
VM-validated.

## New providers (net-new capabilities)

Each is a TCB component and should get its own focused build (design → provider
+ manifest with `protect` + ambient/policy → DTrace provider → tests → man →
docs), the way BSDExtension/BSDNamespace were done — not rushed as a batch.

- **BSDTime** (`system.Time`) — DONE: clock set/slew broker (libtimecmp +
  BSDTime + BSDTimectl), ambient, default-deny per-label time.conf; protocol_test
  6/6, config_test 8/8, DTrace probes. VM boot validation with the next from-scratch run.
- **BSDPower** (`system.Power`) — suspend/resume, ACPI, thermal/battery.
  Boundary: capsule keeps reboot/halt; BSDPower owns the rest. Ambient.
- **BSDFirewall** (`system.Firewall`) — a pf wrapper brokering `/dev/pf` ioctls
  with a whitelist + per-label policy, on the BSDDevice model (delivered
  `/dev/pf` fd, cap_rights + ioctl allow-list).

## Testing hardening — DONE (the LOC-ratio was a misleading proxy)

Re-audited each flagged provider by *security-boundary coverage*, not LOC ratio:

- **BSDSysctl** — the one genuine gap (policy had 5 cases). FIXED: adversarial
  policy suite added (config_test 5 → 10: read/write separation, exact-label,
  default-deny, null/empty, dot-boundary).
- **BSDFilesystem** (tzfsd, 0.45) — the ratio is low only because request.c /
  layout.c are large with ZFS/mount plumbing. Its 28 cases DO cover the
  security invariants: `list_scopes_to_caller_ns`, `destroy_resolves_under_caller_ns`,
  `isolated_open_does_not_require_pool`, `dotdot_is_component_wise`,
  `namespaces_isolate_tenants`, `readonly_view_is_enforced_by_rights`. Adequate.
- **BSDVM** (11 cases) — covers window-isolation (`distinct_labels_never_share_a_window`,
  `list_reports_only_callers_window`), wire contracts, malformed rejection. Adequate.
- **BSDTrace** — session_test covers one-shot auth, unauthorized-open denied,
  poison-session. Adequate.

Lesson: test:src LOC is a poor maturity signal for providers with heavy
non-security plumbing; judge by whether the security boundary is exercised.

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

## Broader sweep: AI drift + pre-1.0 self-compat removal

The plane is pre-1.0: there is **no released version to stay compatible with**,
so any code that supports an *earlier iteration of our own work* is dead weight.
Sweep capsule, the changed kernel modules (mac_capability, ng_hci_virt/vhci,
OES), and the daemons for:

**Remove — pre-1.0 self-compat (we owe no backward compatibility to ourselves):**
- **Pre-capmode / non-plane launch fallbacks** — daemons carry a "fall back to
  the $CAPABILITY_UNIT_DIR path for a legacy launch" branch (BSDDevice
  `localdevice.c`, BSDNetwork `networkcmp.c`, BSDLog `logcmp.c`, BSDNotify,
  BSDBluetooth), backed by `service_config_open`'s path fallback in libservice.
  BLOCKED, not dead: the provider **test fixture** (`capd_service_fixture.c`)
  launches daemons standalone via `SERVICE_UNIT_DIR_ENV` (no plane delivering
  fds), so removing the fallback breaks every provider test first. Prereq:
  rework the fixture to deliver `CONFIG_FD`/dir-fds like switchboard does, THEN
  drop the fallback. Production is already born-in-capmode (switchboard always
  delivers `CONFIG_FD`), so this is test-harness debt, not a runtime path.
- **Transitional uid/euid gates** in capsule (`commands.c`, `capsule_proto.c`:
  "the euid==0 gates below are transitional") — remove once the held-capability
  end state is in place; don't keep both.
- **Legacy init(8) signal / SIGHUP compatibility handlers** in capsule
  (`capsule.c` legacy-lifecycle-signal ignore, `commands.c` "legacy SIGHUP
  compatibility path") — keep ONLY what the stock-init handoff genuinely needs.
- **Stale transitional symlinks / man-links** — the vmd→waspnest→bhyve chain
  (waspnest is now BSDVM); any `/usr/sbin/waspnest`→bhyve symlink is doubly dead.
- **`legacy_global_mount`** path in BSDFilesystem `layout.c` — confirm whether
  any live config still produces a non-anon global mount; if not, delete it.
- Version-negotiation / N-1 fallbacks for our own on-disk formats and wire
  protocols. (The libcapreclaim `struct_size` guard is NOT this — it is
  forward-skew safety for a partial upgrade, keep it.)

**KEEP — genuinely not self-compat:**
- "legacy Unix service world" / rc / rc.d references — that is the real
  traditional UNIX world we host (see the rc→plane item), not our own old code.

**AI drift to hunt (artifacts of iterative generation, not features):**
- Dead/unreachable code, unused fields/flags never read, functions defined and
  never wired.
- Duplicate/near-duplicate implementations of the same thing across daemons.
- Speculative generality: interfaces with a single impl, config knobs nothing
  sets, abstraction layers with one caller.
- Stale/aspirational comments that describe behavior the code does not have
  (e.g. the `trustedzfs:::anon-mount` probe the docs claimed but no provider
  defined — already fixed; sweep for more).
- Copy-paste leftovers and inconsistent patterns across the (now BSD*) daemons.

Each removal is its own reviewed+VM-validated change — this is a scalpel pass on
the TCB, not a blind delete.

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
