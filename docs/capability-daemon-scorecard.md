# Capability daemon scorecard

A measurable baseline for the capability provider daemons: source size, test
depth, and integration with the plane's protection primitives. Re-run the
survey in `tools/` (or by hand) and update this table to track progress.

Columns: **src/tst LOC** (C source vs. its test tree), **ATF** (test cases),
**ratio** (test:src LOC), **protect** (manifest `protect` shield flags),
**anoint** (endpoint gated on an anointment), **DTrace** (ships a USDT
provider), **xfer** (attenuates delivered fds with `cap_xfer_limit`),
**reclaim** (a `libcapreclaim` client), **man/book** (man page / dev-book
chapter).

| daemon | src | tst | ATF | ratio | protect | anoint | DTrace | xfer | reclaim | man | book |
|---|--:|--:|--:|--:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| tzfsd | 3350 | 1516 | 28 | 0.45 | Y | – | Y | – | Y | Y | – |
| logd | 5986 | 4425 | 88 | 0.74 | Y | – | Y | Y | Y | Y | Y |
| localcrypto | 1199 | 1433 | 18 | 1.20 | Y | – | Y | Y | Y | Y | – |
| localnetwork | 2740 | 1708 | 35 | 0.62 | Y | – | Y | Y | – | Y | Y |
| localsysctl | 793 | 555 | 10 | 0.70 | Y | – | Y | – | – | Y | Y |
| localdevice | 740 | 1066 | 15 | 1.44 | Y | – | Y | – | – | Y | Y |
| auditbrokerd | 815 | 829 | 18 | 1.02 | Y | – | Y | – | – | Y | Y |
| traced | 934 | 618 | 16 | 0.66 | Y | Y | Y | Y | – | Y | – |
| bsdnotify | 2805 | 3714 | 62 | 1.32 | Y | Y | Y | – | – | Y | Y |
| authagentd | 1813 | 5034 | 139 | 2.78 | Y | Y | Y | Y | – | Y | – |
| bsdextension | 1479 | 1332 | 36 | 0.90 | Y | – | Y | – | Y | Y | – |
| warden | 1518 | 1329 | 26 | 0.88 | Y | – | Y | – | Y | Y | – |
| blued | 54968 | 224865 | 3746 | 4.09 | Y | – | Y | Y | Y | Y | – |
| waspnest | 654 | 837 | 11 | 1.28 | Y | – | Y | Y | – | Y | – |

## Uniform (good)

`protect` 14/14, DTrace 14/14, man page 14/14. `anoint` is scoped to the three
privileged-surface endpoints (traced, bsdnotify, authagentd) by design. Every
sandboxed provider that delivers a descriptor attenuates it non-forwardable
(`cap_xfer_limit`) and rights-narrows it (`cap_rights_limit`); the ambient
providers (tzfsd, localsysctl, warden, bsdextension, waspnest) rely on
drop-inherited-authority + per-label policy instead of a Capsicum sandbox.

## Testing gaps (target: ambient/privileged-surface providers ≥ ~1.0 ratio, with negative + adversarial + policy cases)

Ranked by criticality × under-testing:

1. **tzfsd** — 0.45, the fleet minimum, on the storage TCB (ZFS mounts, the
   anon-mount anchor machinery, provisioning, quota). Reclaim is now hardened;
   the request/mount broker path is the thin part.
2. **traced** — 16 cases; anoint-gated because it reads arbitrary kernel/process
   state, so it warrants adversarial depth it lacks.
3. **localsysctl** — 10 cases (fleet minimum); ambient, unrestricted sysctl —
   the per-label policy ACL is the only boundary and needs heavy negative tests.
4. **waspnest** — 11 cases; ambient VM/bhyve+vsock broker.

Adequate-but-low-ratio: localnetwork (0.62), switchboard (0.68 but 168 cases).
Well-tested: authagentd, blued, bsdnotify, localdevice, localcrypto,
auditbrokerd, bsdextension.

## Naming (in progress)

Daemon binaries are being unified under a `BSD*` scheme (the userspace daemon
that abstracts a system facility); the `system.X` capability labels are
unchanged. New providers land already named this way.
