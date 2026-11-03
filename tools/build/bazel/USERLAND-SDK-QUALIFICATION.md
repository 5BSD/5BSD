# Userland target and execution SDKs (2026-11-03)

The maintained SDK preparation and format-5 source backend now distinguish an
explicit amd64, ARM64 or RISC-V userland target from the native amd64 execution
SDK. The existing native interface and kernel toolchain selection remain the
default. Kernel profiles require a native execution SDK, including cross-kernel
profiles; a foreign userland target SDK is rejected for that role.

## Preparation and input contract

`libmd-plan.py --sdk-only --target-arch ARCH` queries the selected real
`/usr/obj/usr/src/<world>/.src_opts` and build environment. It does not generate
or claim a cross legacy libmd product graph. The recorded compiler command,
including its target option, determines compiler identity and resources.
`libmd-stage-tools.py` then materializes the explicit target sysroot and tools.
For cross preparation its `--execution-workspace` and `--execution-receipt`
name a separately validated native format-1 snapshot. A format-2 composite
receipt binds that origin receipt and copies its complete native toolchain
under `toolchain/host`; no host include fallback or target tag substitution is
used. Conflicting source bindings, changed host dependencies, escaping paths,
incomplete host closure and snapshot inventory changes are rejected.

The format-5 backend selects the actual target platform and separately
registers the copied native host toolchain. Cross tests must have the existing
explicit host-artifact provider and pass configured inventory validation before
execution. Foreign programs are not run. The original native default platform
arguments are preserved. `build-bsd` already forwards the explicit architecture
and format-5 inputs; its C frontend needs no alternative entry point.

RISC-V userland uses the actual original `rv64imafdc/lp64d` ABI and `-mno-relax`
for compilation and executable links. These flags are conditional on the
RISC-V userland toolchain; shared-library links preserve the original recipe's
absence of repeated CFLAGS, and kernel toolchains retain their own policy.

## Evidence and limits

Fresh maintained preparations are retained under
`/usr/obj/usr/src/bazel-userland-{native,aarch64,riscv64}-sdk-r3-20261103`.
The native receipt validates 16,712 source/runtime/snapshot bindings. Compared
with native-r1, the only snapshot byte change is the intentional conditional
RISC-V feature in `toolchain/cc_toolchain_config.bzl`; compiler/sysroot bytes are
unchanged. Stale earlier receipts were not rebound.

The old cross header floors contained 25 dangling retired PF/ALTQ links each.
The original maintained `delete-old-files` and `include/Makefile includes`
recipes, with queried `IMAKE_INSTALL`, refreshed only the private cross
sysroots under `/usr/obj`. NO_ROOT/metadata policy is explicit; no host install
occurred. Original target compiler/linker/libc/libbz2 bytes were protected.
Fresh original cross references were rebuilt because two consumed `stdlib.h`
paths changed. Rejected initial preparation/reference attempts remain retained.

The maintained native policy profile passed both `source_settings_test` and
`source_test_inventory_test`. Direct unit totals are 15 settings methods,
18 inventory methods and 10 reference-option methods; these are not 43 Bazel
test targets. Real three-architecture libbz2/bzip2 production qualification is
recorded separately in BZIP2-THREE-ARCH-QUALIFICATION.md.

The SDK still comes from Make-built compiler/runtime/sysroot floors and depends
on verified matching execution-OS libraries/loader. This is not a complete
bootstrap, execution-OS replacement or hermeticity claim. Other world/rescue
components, foreign runtime execution, full installation/pkgbase/publication,
performance and boot/security behavior remain separate gates.
