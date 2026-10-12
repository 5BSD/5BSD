# Capability daemons on FIDL: handoff (2026-10-12)

Plan and contract: `DAEMONS.md`; evidence: `VALIDATION.json` `fidl_daemons`.

## State

Branch `fidl/daemons` (worktree `/usr/obj/5BSD-fidl-daemons`, objdir
`/usr/obj/usr/obj/5BSD-fidl-daemons`), on `9fd613e6335`, nothing
uncommitted:

| Commit | |
|---|---|
| `cfc7ce79cec` | libfidl: rebuild generated objects when their binding set is regenerated (in dev as `4481bcfaecd`) |
| `4735f8a0c3f` | libfidl: rebuild generated objects when a runtime header (`lib/libfidl/include/fidl/bsd/*.h`) changes (standalone, for dev) |
| `8ff582d727e` .. `f0ef3020715` | BSDPower, BSDDevice, BSDTrace, BSDSysctl, BSDCrypto, BSDAudit, BSDNetwork, BSDNotify, BSDLog on FIDL |
| `b5ca7a8eb4f` | validation record |
| `07da857a6f0` | libfidl: encode and decode the C bindings directly on the wire (performance pass) |
| `779d28c87d7` | libservice: move the Filesystem, SystemExtension, Namespace and VM clients into libfilesystemcmp, libextensioncmp, libnamespacecmp, libvmcmp; libservice SHLIB_MAJOR 2 (`libservice.so.1` in ObsoleteFiles), UPDATING |

Branch `fidl/conversions-wip` (worktree `/usr/obj/5BSD-fidl-port`), on
`779d28c87d7`: five `WIP:` commits, **not yet compiled**: shared plumbing,
BSDVM (`bsd.vm.v1`), BSDNamespace (`bsd.namespace.v1`), BSDExtension
(`bsd.extension.v1`), BSDFilesystem + OES (`bsd.filesystem.v1`,
`bsd.oes.v1`).  Each has its schema, server, client, provider tests,
evolution test (`tests/evolution/*_next.fidl`, next_peer), latency bench,
build-daemon-bench.sh case, manual pages and book page.  The original
drafting tree `/usr/obj/5BSD-fidl-scratch` (detached) can be discarded.

## Decisions

- Library layout (b): the four libservice-embedded clients are their own
  lib*cmp libraries; libservice stays C-only (no libfidl).
- The Extension borrowed-session API (`service_session_extension_*` on a
  `struct service_session`) becomes `extensioncmp_session_open/create/close`
  plus `extensioncmp_load/stat/list/reload/manage/info` on a
  `struct extensioncmp_session` (accepted; UPDATING entry and
  libextensioncmp(3) on the WIP branch).
- system.Network.PF stays on the record protocol.
- Daemon conversions land in dev only when the coordinator says so.

## Validation

VM7 (perf build before the empty-string fix; 2 vCPUs, plane-on, all daemon
suites, legacy benches from `4e87e953034` interleaved, median of 3
rounds), p50 µs record protocol -> FIDL:

| Service | Op | Before | FIDL | Ratio |
|---|---|---|---|---|
| Audit | Submit | 131 | 146 | 1.11 |
| Crypto | Random | 127 | 124 | 0.98 |
| Device | List | 171 | 138 | 0.81 |
| Log | GetStats | 137 | 144 | 1.05 |
| Network | GetLimits | 132 | 147 | 1.11 |
| Notify | GetStats | 140 | 130 | 0.93 |
| Power | States | 120 | 127 | 1.06 |
| Sysctl | Get | 153 | 172 | 1.12 |
| Trace | Open | 3159 | 3959 | 1.25 (noisy: 1.13 in VM6, p99 in seconds) |

Before the performance pass the ratios were 1.04-2.54x.  ktrace: 6.1 vs
7.3 system calls per call.

VM8 and VM9 (perf + split, plus libservice, sysextctl, BSDNamespace,
BSDExtension, BSDFilesystem, BSDVM, libbsdfilesystem, liboes suites):
1091/1199, 3 failed: c_binding_test (a stale generated object, below) and
logctl's two pre-existing cases (`unavailable`, `severity_names`, which
expect system.Log to be absent).

VM10 (the same suites on the current branch, after `4735f8a0c3f`):
**1092/1199 passed, 0 broken, 105 skipped, 2 failed** (logctl's two
pre-existing cases); c_binding_test and c_wire_test pass; Power, Sysctl
and BSDTime lifecycle gates pass.  VM11 repeats one latency round with
legacy benches rebuilt for libservice.so.2 (`legacy11`; the VM7 ones
needed libservice.so.1).  Its FIDL p50 (µs) match VM7's within noise:
Audit 148 (VM7 146), Crypto 127 (124), Device 130 (138), Log 133 (144),
Network 141 (147), Notify 123 (130), Power 126 (127), Sysctl 164 (172).
Its record-protocol round ran under heavy host load (four agents; p99 up to
100 ms, p50 1.1-6.6x VM7's for unchanged code) and is not a valid
comparison; VM7's table stands, the encoder change having left the FIDL
side unchanged.

## c_binding_test

Fixed and VM-verified (VM10).  Three causes, all fixed:

- Hang (alarm): incremental builds kept stale generated objects (the
  generator keeps unchanged files' times), so the test ran an old encoder
  without its cycle guard.  Fixed by `cfc7ce79cec`.
- `Collections.Echo` refused a valid Collection with EINVAL: a present
  label with NULL and size 0 failed `utfutils_is_valid_utf8()` (probe run
  vm8b).  `ValidUtf8()` in `<fidl/bsd/c_wire.h>` accepts size 0
  (`07da857a6f0`); c_wire_test covers a NULL empty string.
- VM8/VM9 still failed because the generated objects were not rebuilt when
  `c_wire.h` changed (bmake discarded stale .depend files).  Fixed by
  `4735f8a0c3f`: every generated object depends on the runtime headers.

## Work directories and scripts

`/usr/obj/5bsd-fidl-daemons-work`:

- `run-vmN.sh`: stage (`installworld distribution` + `installkernel
  GENERIC-NODEBUG`, NO_ROOT) into `stageN`, then `vm-provider.sh` with
  `CPUS=2`, `LOADER_EXTRA='dtraceall_load="YES"'`, `EXTRA_SCRIPT=vm-daemons.sh`
  and the legacy benches in `legacyN-bin` (copied from `legacy4`).  Output:
  `vmN.out`, `vmN/serial.log`, `vmN/results/kyua-results`.
- `cbind-extra.sh`: an EXTRA_SCRIPT that runs c_binding_test with output.
- `*-world*.log`: build logs.

Host rules: `make -j6`, one 2-vCPU VM at a time, tests only in VMs.

## Resume

1. Legacy benches now link libservice.so.2: rebuild them with the
   `legacy11/build-*.sh` scripts (they add -lfilesystemcmp -lextensioncmp).
2. In `/usr/obj/5BSD-fidl-port` (fidl/conversions-wip): incremental
   `make -j6 buildworld WITHOUT_CLEAN=yes` with
   `MAKEOBJDIRPREFIX` for that worktree (first build there is a full one),
   or cherry-pick the WIP commits onto fidl/daemons and build in its objdir.
   Fix compile errors per provider, amend each WIP commit (drop "WIP:").
3. Build legacy benches for vm, namespace, extension and filesystem with
   `tools/build/fuchsia/build-daemon-bench.sh SRC 779d28c87d7 <daemon> OUT`
   (BASE_REV is the split commit, the last record-protocol state) and add
   them to the VM's EXTRA_DIR.
4. VM-verify (add the converted suites and `lib/libfidl`), record latency
   in DAEMONS.md and VALIDATION.json, update DAEMONS.md's progress rows.
5. Rebase onto dev: `git rebase --onto 4481bcfaecd cfc7ce79cec fidl/daemons`
   (cfc7ce79cec is patch-identical to 4481bcfaecd; once `4735f8a0c3f` is in
   dev too, rebase past it the same way), rebuild, report to the coordinator
   to land.
