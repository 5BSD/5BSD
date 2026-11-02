# Kernel configuration inventory qualification (2026-11-02)

## Implementation

`config -J` exports format-1 `kernel-inputs.json` directly from the original
parser's resolved file table. It retains selection order, source spelling and
origin, exact object prefix/name, no-object entries, flags, custom compiler text
and dependencies. Custom recipes remain metadata: no Make expressions are
interpreted. The inventory excludes backend startup/system/version objects and
final linker policy; native aggregation must declare and validate these too.

The maintained `bsd_kernel_config` rule always requests this inventory and
provides it as an explicit `.inputs.json` output group. Each supported
architecture exports `generic_input_manifest`. The generated output tree and
identity interface remain available. No production build action invokes Make
or parses a generated Makefile to discover inputs.

## Evidence

- Original Make config utility builds with `make -j16 -C usr.sbin/config all`
  in the standard architecture object directory, without installation.
- Maintained `kernel-config-inventory-test.py` passes 12 cases: amd64, ARM64 and
  RISC-V GENERIC, each with default, ZSTDIO disabled, NFS_ROOT disabled and both
  disabled. For every case, its complete ordered non-null object list equals
  the independent Make `${OBJS}` expansion. Default parser object counts are
  2,455 / 2,028 / 1,187, respectively. These exclude the seven backend additions
  in the current complete configured link-product inventories.
- Ordinary generated file bytes remain identical when enabling `-J`; repeated
  inventory generation preserves both bytes and mtime. Public `files` extension
  testing checks literal quotes, backslashes, tabs, generated source origins,
  a custom object prefix and no-object metadata. An unwritable output staging
  path fails. `-J` with `-i`, `-m` or `-x` fails before those shortcut modes.
- Maintained format-5 frontend runs all three architecture manifest targets on
  the host. All three immutable captured JSON payloads equal their independent
  Make-tool manifests exactly. These are target configuration outputs, not
  ARM64/RISC-V kernel compilation.
- A separately captured native config executable and its three native shared
  libraries pass the same complete matrix. Captures are resolved through the
  hash-verified qualification manifest before making disposable executable
  copies. The host supplies compatible base runtime/loader support; this is
  not static bootstrap parity or VM runtime qualification.

Evidence roots under `/usr/obj/usr/src/`:

- `bazel-kernel-config-inventory-make-r2-20261102`: full Make-tool matrix,
  commands, stdout/stderr, inputs and manifest receipts.
- `bazel-kernel-config-inventory-native-r1-20261102`: three captured manifests,
  byte comparisons and actual config action records.
- `bazel-kernel-config-inventory-tool-native-r3-20261102`: native config/tool
  shared-library captures through the userland toolchain.
- `bazel-kernel-config-inventory-tool-review-r1-20261102`: capture bindings and
  complete native-tool matrix.

An initial standalone test invocation used the wrong object directory and
failed before testing; the corrected run uses Make's actual `.OBJDIR`.
The mixed kernel/userland tool-capture profile r2 was rejected at analysis
because kernel toolchains intentionally lack userland PIC support. The
corrected standalone userland profile r3 passes; no toolchain policy was
weakened. Original failures remain recorded.

## Frontend and remaining scope

The existing `build-bsd bazel-test --bazel-inputs ... --jobs 16` path handles the
new filegroup outputs and the existing typed kernel options. Its backend helper,
rule and config manual changed together; no new frontend C option or alternate
build path is required. Disk budgets remained satisfied. Logged time/RSS is an
observation, not a controlled performance comparison.

This is the prerequisite for fail-closed native kernel aggregate coverage.
The aggregate guard/link/order/debug processing/install are still unfinished;
this commit does not claim a linked native kernel or a complete world/modules/
architectures/packages/bootstrap/runtime/performance migration. Make remains
the production default. BIP remains excluded.
