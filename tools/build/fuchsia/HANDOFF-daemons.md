# Capability daemons on FIDL: handoff (2026-10-12)

Plan and contract: `DAEMONS.md`; evidence: `VALIDATION.json` `fidl_daemons`.

## State

Branch `fidl/daemons` (worktree `/usr/obj/5BSD-fidl-daemons`, objdir
`/usr/obj/usr/obj/5BSD-fidl-daemons`), on `9fd613e6335`, nothing
uncommitted:

| Commit | |
|---|---|
| `cfc7ce79cec` | libfidl: rebuild generated objects when their binding set is regenerated (in dev as `4481bcfaecd`) |
| `a206a5a0a5c` .. `f33cf2c0af4` | BSDPower, BSDDevice, BSDTrace, BSDSysctl, BSDCrypto, BSDAudit, BSDNetwork, BSDNotify, BSDLog on FIDL |
| `a03b0095684` | validation record |
| `a1e7dd47a2e` | libfidl: encode and decode the C bindings directly on the wire (performance pass) |
| `15233acb9e4` | libservice: move the Filesystem, SystemExtension, Namespace and VM clients into libfilesystemcmp, libextensioncmp, libnamespacecmp, libvmcmp; libservice SHLIB_MAJOR 2 (`libservice.so.1` in ObsoleteFiles), UPDATING |

Branch `fidl/conversions-wip` (worktree `/usr/obj/5BSD-fidl-port`), on
`15233acb9e4`: five `WIP:` commits, **not yet compiled**: shared plumbing,
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

VM8 (perf + split, plus libservice, sysextctl, BSDNamespace, BSDExtension,
BSDFilesystem, BSDVM, libbsdfilesystem, liboes suites): 1091/1199 passed,
105 skipped, 3 failed: `lib/libfidl/c_binding_test` (below) and logctl's
two pre-existing cases (`unavailable`, `severity_names`, which expect
system.Log to be absent).

## c_binding_test

Two problems found and fixed in `a1e7dd47a2e`/`cfc7ce79cec`:

- Hang (alarm): incremental builds kept stale generated objects (the
  generator keeps unchanged files' times), so the test ran an old encoder
  without its cycle guard.  Fixed by `cfc7ce79cec`.
- `Collections.Echo` refused a valid Collection with EINVAL: a present
  label with NULL and size 0 failed `utfutils_is_valid_utf8()`.  Probe run
  (vm8b) confirmed only the label mattered.  `ValidUtf8()` in
  `<fidl/bsd/c_wire.h>` now accepts size 0; c_wire_test covers a NULL
  empty string.

**Open:** the VM run of the fixed build (VM9:
`/usr/obj/5bsd-fidl-daemons-work/vm9`, `run-vm9.sh`, `vm9.out`) was still
running at handoff.  Check that c_binding_test and c_wire_test pass and
that nothing else regressed against VM8.

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

1. Read VM9 (see above).
2. In `/usr/obj/5BSD-fidl-port` (fidl/conversions-wip): incremental
   `make -j6 buildworld WITHOUT_CLEAN=yes` with
   `MAKEOBJDIRPREFIX` for that worktree (first build there is a full one),
   or cherry-pick the WIP commits onto fidl/daemons and build in its objdir.
   Fix compile errors per provider, amend each WIP commit (drop "WIP:").
3. Build legacy benches for vm, namespace, extension and filesystem with
   `tools/build/fuchsia/build-daemon-bench.sh SRC 15233acb9e4 <daemon> OUT`
   (BASE_REV is the split commit, the last record-protocol state) and add
   them to the VM's EXTRA_DIR.
4. VM-verify (add the converted suites and `lib/libfidl`), record latency
   in DAEMONS.md and VALIDATION.json, update DAEMONS.md's progress rows.
5. Rebase onto dev `4481bcfaecd`:
   `git rebase --onto 4481bcfaecd cfc7ce79cec fidl/daemons` (cfc7ce79cec is
   patch-identical to 4481bcfaecd), rebuild, report to the coordinator to
   land.
