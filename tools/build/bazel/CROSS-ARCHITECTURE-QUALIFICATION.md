# Cross-architecture kernel build foundations

2026-11-01. Required system targets are amd64, ARM64 (`arm64` / `aarch64`) and
RISC-V (`riscv` / `riscv64`). This record qualifies configuration generation and
inventory tooling. It does not establish cross-compiled world, kernel or module
products. Make remains the production backend.

## Real ARM64 and RISC-V configuration generation

Native targets now exist for both architectures:

- `//sys/arm64/conf:generic_config` and `:generic_debug_config`;
- `//sys/riscv/conf:generic_config` and `:generic_debug_config`;
- corresponding `generic_identity` and `generic_debug_identity` labels.

They use the maintained `bsd_kernel_config` action, the original GENERIC and
included configuration files, shared `sys/conf` metadata and the typed ZSTDIO
option. The RISC-V package also declares SoC files metadata referenced by its
maintained configurations. Required files metadata stays nonempty; currently
absent optional SoC options metadata is allowed to be empty. The host config
program runs in the execution configuration. ARM/RISC-V target binaries are
not executed on the amd64 host.

`/usr/obj/usr/src/bazel-cross-kernel-config-qualification-r3-20261101/receipt.json`
passes the maintained format-5 frontend. A fresh independent Make build of
config is at
`/usr/obj/usr/src/bazel-cross-kernel-config-make-reference-20261101/`; its receipt
rechecks inputs. That tool independently generated the reference trees under
`/usr/obj/usr/src/bazel-cross-kernel-config-reference-20261101/`, recording exact
commands, parsed machine/architecture identities and source/output hashes.
The reference uses the same declared ZSTDIO override and logical source-root
argument; no generated file is rewritten to make the comparison pass.

The complete comparison is
`/usr/obj/usr/src/bazel-cross-kernel-config-parity-20261101/parity.json`:

| Configuration | Regular generated files | Exact filename/content parity |
| --- | ---: | --- |
| ARM64 GENERIC | 184 | yes |
| ARM64 GENERIC with config -g | 184 | yes |
| RISC-V GENERIC | 183 | yes |
| RISC-V GENERIC with config -g | 183 | yes |

All 734 generated files, including empty headers, match byte for byte. All four
identity records match. Generated Makefiles are captured comparison outputs;
Bazel does not execute them. Bazel's read-only output modes are not compared to
ordinary writable reference modes. The first failed native run exposed missing
RISC-V SoC input declarations; it remains retained, along with the subsequent
optional-glob analysis failure.

## Architecture-checked module inventory

`module_inventory.py` now runs independent read-only Make queries with a bounded
worker pool (`--jobs`, defaulting to the logical CPU count). The coordinator
preserves recursive SUBDIR selection, duplicates/cycles, path checks and query
errors. There is no cache of module selections. Output is a diagnostic inventory,
not production graph input and not proof that a Bazel target builds.

Every query explicitly sets both TARGET/TARGET_ARCH and MACHINE/MACHINE_ARCH,
then asks Make to echo MACHINE/MACHINE_ARCH and rejects a mismatch. Direct Make
queries below `/usr/src` do not translate TARGET to MACHINE on their own. The
first ARM64 inventory, which relied on TARGET alone, actually used the amd64
host machine and is invalid. It remains retained with its hash and an explicit
rejection at
`/usr/obj/usr/src/bazel-cross-module-inventory-20261101/arm64-initial-review.json`.
No ARM coverage conclusion may be drawn from that initial report.

Seven unit tests cover parsing, source-versus-partial declarations, safe sibling
resolution, equivalent serial/parallel traversal, duplicate/cycle suppression,
query/path/malformed-output failures and rejection of host-architecture output.
The new traversal regression also exposed a pre-existing Path/string error in
the path-escape diagnostic; this is fixed. These unit fixtures do not substitute
for complete real Make inventories.

## Complete real module selections

The corrected full scans completed without query errors:

| Target machine / architecture | Selected leaf KMODs |
| --- | ---: |
| amd64 / amd64 | 729 |
| arm64 / aarch64 | 615 |
| riscv / riscv64 | 543 |

Reports are `amd64-r2.json`, `arm64-r2.json` and `riscv64.json` under
`/usr/obj/usr/src/bazel-cross-module-inventory-20261101/`. Each query verifies
its actual machine/architecture. The new amd64 selection exactly matches all
(dir, KMOD) pairs in the earlier serial inventory; the fourteen added VirtIO
declarations account for its declaration-count increase. That independent
selection comparison is retained in `amd64-serial-selection-review.json`.
Commands, per-scan resource counters, the audit implementation, a bounded
source stamp and its successful post-run recheck are retained in the same
folder. The scans used sixteen workers and took approximately 57, 54 and 66
seconds for ARM64, RISC-V and amd64 on this host; those are audit timings, not
a controlled compiler/build performance comparison.

The ARM64 and RISC-V reports each find 97 selected directories containing the
existing **amd64-specific** module macro. This is source overlap only. Those
numbers do not establish compatible target declarations or successful module
cross-builds. The current amd64 report finds 106 direct declarations; its 623
other selected leaves still need native descriptions.

`//tools/build/bazel:module_inventory_test` also ran under the maintained
frontend as part of
`/usr/obj/usr/src/bazel-syslogd-qualification-r4-20261101/`. Its captured test.log
confirms all seven unit cases executed and passed, including rejection of host
architecture output. The separately executed constructor regression in that
run is not evidence of ARM/RISC-V runtime behavior.

## Unchanged-input reuse

`/usr/obj/usr/src/bazel-cross-kernel-config-cache-20261101/` repeats the original
eight configured targets. Its captured artifact manifest is byte-identical to
the original (SHA-256 `9cb44b07f3707e193b1da8d1d83dc9504fbaccc27647b2d73413bed62e308091`),
and the external execution log is empty. Bazel reported one internal action.
The retained cache-review.json limits this result to unchanged-input reuse;
source mutation, independent clean bootstrap, remote cache and cross-workspace
portability remain separate gates.

## Frontend review and remaining work

Existing `build-bsd bazel-test` format-5 target selection handles these native
host-executed configuration actions. No new CLI, signing, installation,
publication or manual contract is introduced. The inventory's `--jobs` controls
a read-only diagnostic, not a second build backend.

The current prepared SDK still registers an amd64 toolchain/platform. Completing
cross builds requires registered execution and target toolchains with correct
constraints and target sysroots, target-specific kernel compiler/linker policy,
layout generators, architecture/board source selection and complete native
module dependencies. Existing amd64-only module declarations cannot establish
ARM64 or RISC-V support merely because a shared driver source is portable.

Cross-target compilation/link/install/pkgbase parity, bootstrap independence,
mutation/cache behavior, VM/board boot and device behavior, and controlled CPU,
memory, disk I/O and disk-usage comparisons remain open. No kernel was installed,
module loaded or VM started by this qualification. BIP remains out of scope.
