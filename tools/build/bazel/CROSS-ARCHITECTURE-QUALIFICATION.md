# Cross-architecture kernel build foundations

2026-11-01. Required system targets are amd64, ARM64 (`arm64` / `aarch64`) and
RISC-V (`riscv` / `riscv64`). This record qualifies configuration generation and
inventory tooling, and the first real cross-compiled kernel layout objects. It
does not establish complete world, kernel or module products. Make remains the production backend.

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

## Registered cross-target kernel compiler foundation

Format-5 source input now accepts optional `"target-kind": "kernel"`. The
maintained `build-bsd bazel-test --arch arm64|riscv64 --bazel-inputs FILE`
passes the normalized target architecture to the existing backend. Its execution
SDK/object root remains amd64. Legacy qualification formats and ordinary
userland inputs remain amd64-only; foreign userland and all runnable selections
in the kernel profile are rejected before SDK preparation/output creation.
The current build host must be amd64. This is not a cross-userland SDK.

`tools/build/bazel/kernel_toolchain` declares source-owned platforms and standard
`rules_cc` C++ toolchains with separate execution and target constraints and a
kernel ABI constraint. Compiler actions use declared `File` tools through the
supported `tool(tool=...)` API. They do not wrap Make, synthesize relative paths
that escape a package, embed a builder's absolute compiler location, or rewrite
compiler outputs. The OS/release part of the target triple comes from the
verified SDK identity; architecture selection is ordinary platform metadata.
Host config/grep/sed/sort/nm tools remain in the execution configuration.

Kernel compiler inputs contain the selected compiler and its runtime closure,
without the host SDK's userland headers/sysroot. `-nostdinc -ffreestanding`
and target-owned source header declarations prevent host include lookup. The
captured cross compile actions contain no SDK `sysroot/usr/include` inputs.
Future sources requiring compiler intrinsic headers need explicit declarations.
Kernel link inputs also omit userland startup objects and libraries; complete
kernel links, archive/link/strip actions and every assembly dialect still need
their own actual product qualification.

The first consumers compile the original `sys/kern/genoffset.c` against actual
GENERIC `opt_global.h` extracted from native config output. ARM64 declares its
shared ARM header dependency; this does not restore an ARM32 system port. The
ARM64 GENERIC policy preserves fixed x18, general registers, branch protection,
per-thread stack guard and frame pointers. RISC-V preserves the kernel soft-float
`lp64` ABI, maintained ISA/code model, current LLD no-relax policy, PIE and frame
policy. These are explicit GENERIC targets, not arbitrary board/config coverage.
Common warning and debug/CTF setting expressions are shared with existing amd64
rules; no native amd64 flag value was changed by that extraction.

### Independent actual object and layout parity

| Target | `genoffset.o` bytes | `offset.inc` bytes | Exact Make bytes |
| --- | ---: | ---: | --- |
| ARM64 GENERIC, no debug | 1,400 | 695 | both outputs |
| RISC-V GENERIC, no debug | 1,360 | 695 | both outputs |

Maintained frontend receipts:

- `/usr/obj/usr/src/bazel-cross-layout-arm64-r3-20261101/receipt.json`;
- `/usr/obj/usr/src/bazel-cross-layout-riscv-r1-20261101/receipt.json`.

Fresh independent Make config/object builds, commands, dependency records and
resource counters are retained under
`/usr/obj/usr/src/bazel-cross-layout-make-reference-20261101/`. All 135 recorded
compiler/config/header inputs recheck unchanged. Complete file byte comparison,
ELF machine identity (AArch64 183, RISC-V 243), compiler argv, bounded source
snapshots and input rechecks are recorded in
`/usr/obj/usr/src/bazel-cross-layout-review-20261101/review.json`. Each first
cross build executed three external actions: option extraction, target
compilation and host layout extraction. This object defines layout symbols;
it does not exercise executable kernel routines or a device driver.

Both repeat frontend runs, `bazel-cross-layout-arm64-cache-20261101` and
`bazel-cross-layout-riscv-cache-20261101`, reuse the exact artifact manifests
with zero external spawns. Switching platforms discards Bazel's analysis cache;
this is unchanged-input action reuse, not a claim of free analysis, remote
cache portability, mutation coverage or overall build performance. Captured
`time -l` counters are not total JVM/compiler memory measurements.

The existing amd64 regression at
`/usr/obj/usr/src/bazel-cross-layout-amd64-regression-r1-20261101/receipt.json`
reuses its compiled layout object (no CppCompile spawn) and produces an
`offset.inc` exactly matching fresh Make. Its raw object differs from the
no-debug Make reference because the existing native SDK emits DWARF. That
mismatch is retained; no amd64 raw object parity claim is made. Two native
Bazel test targets execute all eight typed-setting/profile tests and seven
module-inventory tests. The maintained frontend ATF `bazel_plan` also passes,
including both cross-architecture argv/scope checks.

Initial failures remain retained: r1 used a `compiler` label attribute that
collided with a `rules_cc` compiler-string convention; r2 exposed rejection of
cross-repository package-relative `tool_path`. The final rule binds actual
compiler artifacts, with no path-normalization exception or SDK receipt edit.

## Remaining system qualification

Existing amd64-specific module declarations still do not establish ARM64 or
RISC-V module support. Next work must extend real kernel/body and module rules
with proper target selection, generated interfaces, architecture linker scripts,
CTF, debug/install metadata and independent Make comparisons. Complete kernel,
world/sysroot/pkgbase construction, bootstrap independence, source-mutation
behavior, VM/board boot/device tests and controlled CPU/memory/disk-I/O/disk-usage
comparisons remain open. No kernel was installed, module loaded or VM started
by this qualification. Make remains production/default; BIP stays out of scope.

The next real module tranche now qualifies filemon on ARM64 and RISC-V,
including the maintained shared link, CTF/export/debug/install stages. This is
one explicit module per architecture, not portable coverage for the remaining
amd64 declarations. See [shared-module evidence](CROSS-MODULE-QUALIFICATION.md).
