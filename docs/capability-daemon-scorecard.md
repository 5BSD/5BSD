# Capability daemon scorecard

> **Reconciled against the unit files on 2026-09-25.** The `launch`, `user`
> and `gates` columns below, and the prose that follows the table, were
> re-derived from each provider's manifest (`usr.sbin/BSD*/capbundle/*.ucl`,
> `usr.sbin/bluetooth/BSDBluetooth/blued.ucl`) and `lib/libcapbundle`'s
> defaults (`ambient` absent => false, `user` absent => `capability`,
> `SWITCHBOARD_DEFAULT_USER`). The earlier claim that five providers were
> ambient was wrong: only BSDVM declares `ambient = true`. Daemon names were
> updated to the current `BSD*` binaries (BSDTrace, BSDVM, BSDBluetooth), and
> the two providers the table had omitted (BSDPower, BSDTime) were added with
> counts taken on 2026-09-25 (`src` = daemon `*.c` outside `tests/`, `tst` =
> `tests/*.c`, ATF = `ATF_TP_ADD_TC` entries). The other columns (LOC, ATF,
> anoint, DTrace, xfer, reclaim, man, book) were spot-checked, not re-surveyed:
> protect and DTrace hold for all 16 (every unit declares `protect`, every
> daemon ships a `*_provider.d`); `xfer` matches `grep cap_xfer_limit` and
> `reclaim` matches `LIBADD capreclaim` in each daemon's Makefile.

A measurable baseline for the capability provider daemons: source size, test
depth, and integration with the plane's protection primitives. Re-run the
survey in `tools/` (or by hand) and update this table to track progress.

Columns: **src/tst LOC** (C source vs. its test tree), **ATF** (test cases),
**ratio** (test:src LOC), **launch** (`capmode` = born in capability mode,
the manifest default; `ambient` = manifest `ambient = true`), **user**
(manifest `user`; default `capability`), **gates** (manifest
`capabilities { system = [...] }`, the Capsule-minted "system" gate tokens the
unit holds), **protect** (manifest `protect` shield flags), **anoint**
(endpoint gated on an anointment), **DTrace** (ships a USDT provider),
**xfer** (attenuates delivered fds with `cap_xfer_limit`), **reclaim** (a
`libcapreclaim` client), **man/book** (man page / dev-book chapter).

| daemon | wire name | src | tst | ATF | ratio | launch | user | gates | protect | anoint | DTrace | xfer | reclaim | man | book |
|---|---|--:|--:|--:|--:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| BSDFilesystem | system.Filesystem | 3350 | 1516 | 28 | 0.45 | capmode | root | – | Y | – | Y | – | Y | Y | – |
| BSDLog | system.Log | 5986 | 4425 | 88 | 0.74 | capmode | capability | – | Y | – | Y | Y | Y | Y | Y |
| BSDCrypto | system.Crypto | 1199 | 1433 | 18 | 1.20 | capmode | root | – | Y | – | Y | Y | Y | Y | – |
| BSDNetwork | system.Network | 2740 | 1708 | 35 | 0.62 | capmode | capability | – | Y | – | Y | Y | – | Y | Y |
| BSDSysctl | system.Sysctl | 793 | 555 | 10 | 0.70 | capmode | capability | sysctl (+ `isolate = ["kern.maxfiles"]`) | Y | – | Y | – | – | Y | Y |
| BSDDevice | system.Device | 740 | 1066 | 15 | 1.44 | capmode | capability | – | Y | – | Y | – | – | Y | Y |
| BSDAudit | system.Audit | 815 | 829 | 18 | 1.02 | capmode | root | – | Y | – | Y | – | – | Y | Y |
| BSDTrace | system.Trace | 934 | 618 | 16 | 0.66 | capmode | root | – | Y | Y | Y | Y | – | Y | – |
| BSDNotify | system.Notify | 2805 | 3714 | 62 | 1.32 | capmode | capability | – | Y | Y | Y | – | – | Y | Y |
| BSDAuth | system.Auth | 1813 | 5034 | 139 | 2.78 | capmode | root | – | Y | Y | Y | Y | – | Y | – |
| BSDExtension | system.SystemExtension | 1479 | 1332 | 36 | 0.90 | capmode | capability | kldload, kldunload | Y | – | Y | – | Y | Y | – |
| BSDNamespace | system.Namespace | 1518 | 1329 | 26 | 0.88 | capmode | capability | jail | Y | – | Y | – | Y | Y | – |
| BSDPower | system.Power | 644 | 836 | 27 | 1.30 | capmode | capability | – | Y | – | Y | – | – | Y | Y |
| BSDTime | system.Time | 634 | 680 | 18 | 1.07 | capmode | capability | settime | Y | – | Y | – | – | Y | Y |
| BSDBluetooth | system.Bluetooth | 54968 | 224865 | 3746 | 4.09 | capmode | capability | – | Y | – | Y | Y | Y | Y | – |
| BSDVM | system.VM | 654 | 837 | 11 | 1.28 | **ambient** | root | – | Y | – | Y | Y | – | Y | – |

Other manifest facts, uniform across all 16 units: `restart = "on-failure"`
(no unit uses another policy); no unit declares a `watchdog { interval }`
heartbeat deadline; `protect` is the same eight-flag set everywhere
(`ptrace`, `signal`, `wait`, `sigkill`, `sigcont`, `sched`, `core`,
`ktrace`). BSDBluetooth's unit adds `stop_timeout = 10` and
`max_failures = 10` and takes both `user` and `ambient` from the defaults.
BSDAuth is the single `mint_authority = true` unit. The four units that hold
Capsule gates (BSDSysctl, BSDExtension, BSDNamespace, BSDTime) are the only
ones with a `capabilities {}` block; the capmode providers that need a
device or a tree reach it through delivered `directories` instead
(BSDCrypto, BSDDevice, BSDPower, BSDTrace: `/dev`; BSDFilesystem: `/dev` and
`/`; BSDLog, BSDExtension, BSDNamespace, BSDCrypto, BSDBluetooth: the
`/Capabilities` trees).

## Uniform (good)

`protect` 16/16, DTrace 16/16, man page 16/16. `anoint` is scoped to the three
privileged-surface endpoints (BSDTrace, BSDNotify, BSDAuth) by design. The
providers marked `xfer` attenuate the descriptors they deliver non-forwardable
(`cap_xfer_limit`) and rights-narrow them (`cap_rights_limit`); BSDDevice
rights-narrows and ioctl-whitelists but does not call `cap_xfer_limit`
directly. Fifteen of the
sixteen providers are born in capability mode; the privileged operations they
still need run through Capsule-minted "system" gate tokens (sysctl, kldload/
kldunload, jail, settime) or through delivered directory descriptors, with the
per-label policy file as the authorization boundary on top. BSDVM is the one
`ambient = true` provider: it relies on drop-inherited-authority + per-label
policy instead of a Capsicum sandbox.

## Testing gaps (target: ambient/privileged-surface providers ≥ ~1.0 ratio, with negative + adversarial + policy cases)

Ranked by criticality × under-testing:

1. **BSDFilesystem** — 0.45, the fleet minimum, on the storage TCB (ZFS mounts,
   the anon-mount anchor machinery, provisioning, quota). Reclaim is now
   hardened; the request/mount broker path is the thin part. Two of its
   tests under `tests/sys/tzfs` are still disabled pending a fake-service
   harness.
2. **BSDTrace** — 16 cases; anoint-gated because it reads arbitrary
   kernel/process state, so it warrants adversarial depth it lacks.
3. **BSDSysctl** — 10 cases (fleet minimum); born in capmode but holds the
   sysctl gate — the per-label policy ACL is the only boundary and needs heavy
   negative tests.
4. **BSDVM** — 11 cases; the only ambient provider (vsock broker; bhyve VM
   lifecycle unbuilt).

Adequate-but-low-ratio: BSDNetwork (0.62), switchboard (0.68 but 168 cases).
Well-tested: BSDAuth, BSDBluetooth, BSDNotify, BSDDevice, BSDCrypto,
BSDAudit, BSDExtension, BSDPower (provider_test added 2026-09-25), BSDTime.

## Naming

Daemon binaries are unified under the `BSD*` scheme (the userspace daemon that
abstracts a system facility); the `system.X` capability labels are unchanged.
Retired names (traced, waspnest as a daemon, blued, sysextd, vmd) must not be
reintroduced in docs; the only remaining references are "renamed from" notes.
