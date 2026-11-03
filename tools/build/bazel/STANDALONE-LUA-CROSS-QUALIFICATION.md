# Standalone Lua: architecture qualification (2026-11-03)

## Native declarations and ABI boundaries

`//stand/liblua:static_archive` now selects explicit amd64, ARM64 and RISC-V
compiler/header contexts from the target platform. Unsupported architectures are
incompatible. The same 31 source-owned translation units and ordered archive
contract apply on each supported architecture; this is one interpreter archive
per architecture, not 93 new libraries or executable programs.

ARM64 uses Make's general-register-only code generation, reserved x18 and PIC.
RISC-V uses rv64imac, lp64 soft-float, PIC, no relaxation and the medium code
model. The ordinary userland RISC-V floating-point feature is disabled for these
freestanding compiler groups. The compile-time ABI contract rejects floating
instructions/calling conventions enabled through RISC-V compiler macros.
Architecture header views select only the corresponding machine headers.

`archive_test` is a declared `bsd_host_artifact_test`. Its interpreter and tools
execute on the bound native SDK. It inspects the target archive without executing
foreign code. Its three test methods check member order, loader API/import
isolation, and every member's ELF class/endianness/machine/relocatable type;
RISC-V members must also declare the soft-float ELF ABI. The separate compiler
contract remains outside the production archive.

## Results and original Make comparisons

All evidence paths below are under `/usr/obj/usr/src`.

| Target ABI | Final frontend qualification | Original Make reference | Members with equal allocated sections | Symbolic allocated relocations compared | Test methods |
| --- | --- | --- | --- | --- | --- |
| amd64 | `bazel-stand-lua-amd64-r2-20261103` | `bazel-stand-liblua-make-r1-20261103` | 31/31 | 4,786 | 3 |
| aarch64 | `bazel-stand-lua-aarch64-r3-20261103` | `bazel-stand-lua-aarch64-make-r1-20261103` | 31/31 | 4,551 | 3 |
| riscv64 | `bazel-stand-lua-riscv64-r2-20261103` | `bazel-stand-lua-riscv64-make-r1-20261103` | 31/31 | 7,636 | 3 |

Each comparison checks actual archive order, defined/undefined external symbols,
allocated section bytes/type/flags/size/alignment and relocations resolved to
symbol identity, section, value, size, type, offset and addend. ELF identity and
ABI flags also match Make. All 93 full object byte comparisons differ;
DWARF/source mapping and debugger qualification remain open. Allocated section
and relocation equality is not complete file equality or firmware execution.
Both new Make references use the maintained reference tool with target/profile
identity checks, recipe metadata and all 16 CPUs. The archive is INTERNALLIB;
there are no installed payloads in either component METALOG.

The final architecture-tagged comparison directories are
`bazel-stand-lua-amd64-review-r2-20261103`,
`bazel-stand-lua-aarch64-review-r2-20261103` and
`bazel-stand-lua-riscv64-review-r2-20261103`. They compare the final current-tree
captures directly. Earlier comparison attempts are retained separately.

`bazel-stand-lua-cross-actions-r1-20261103` contains per-architecture action
proofs and `final-summary.json`. All 93 owned member outputs bind to actual,
noncached successful compiler actions and matching actual archive inputs/outputs.
The corresponding standalone configuration/header hashes, critical CPU flags,
ELF machine/ABI flags and final captured archive digests are checked. The action
proof explicitly identifies the earlier qualification where each action ran;
reused steps are not called fresh. Successful RISC-V compiler actions from its
initial failed test attempt remain valid only where their object digests match
the final artifact. The upstream compact execution-log converter and its runtime
bindings were verified before and after reading each log.

`bazel-stand-lua-final-regressions-r1-20261103/commands.json` records the final
ARM64/amd64 frontend runs after the static-only contract correction. All three
final test reports contain three passing inspection methods. Per-member checks
are subtests within those methods, not an extra 93 top-level test cases.

## Issues found and corrected

The initial ARM64 frontend attempt stopped before compilation: its older SDK
receipt depended on a deleted historical DTrace build artifact. That failure is
retained in `bazel-stand-lua-aarch64-r1-20261103-disk.*` and the identified
frontend build-run log. It was not bypassed by weakening origin/hash checks.
An initial preparation attempt also encountered removed historical settings;
it did not produce a replacement SDK.

Fresh composite SDKs are `bazel-stand-lua-aarch64-sdk-r1-20261103` and
`bazel-stand-lua-riscv64-sdk-r1-20261103`. Maintained `libmd-plan.py --sdk-only`
and `libmd-stage-tools.py` use the real target world profiles and the verified
`bazel-userland-native-sdk-r5-20261103` as their explicit execution SDK. The tool
configuration names actual current, hash-bound origins and the selected Python
runtime. `bazel-stand-lua-cross-sdk-preparation-r2-20261103` retains that config,
commands and logs. This is preparation against Make-built worlds, not a Bazel
bootstrap or a complete system build. Referenced immutable SDK inputs must be
retained; dependency-aware cleanup/portable bootstrap-input qualification remains
part of the broader goal.

The initial RISC-V attempt compiled the loader objects but failed while building
the ABI fixture's unintended userland shared library: its soft-float object
conflicted with hard-float userland startup files. The fixture is a compile-only
contract, so its cc_library now has `linkstatic = True`. No ABI flag or linker
check was suppressed. The final configured RISC-V dependency graph has no
CppLink action for the ABI contract; `abi-contract-link-query.json` retains that
query. This also removes the unnecessary fixture DSO from the other architectures.

## Frontend and remaining scope

The normal maintained `build-bsd bazel-test --arch ... --jobs 16 --bazel-inputs
...` interface selects the explicit target/composite SDK and requires declared
host-artifact tests for cross builds. No cross-test gate was relaxed and no C
frontend, security policy, staging/signing/publication or manual interface changed.
Make remains production/default. No installation, upgrade, reboot or VM run was
performed for this archive qualification.

The private 64-bit EFI Lua contexts were subsequently qualified in
EFI-LUA-QUALIFICATION.md. IA32 variants, remaining standalone archives, full EFI
loader links and firmware execution remain open. The shared source
observability review still applies; these host inspections establish neither
probe delivery nor loader diagnostics at runtime. Complete world/kernel/modules,
pkgbase/hardware publication, bootstrap/sandbox/cache configurations and CPU,
memory and disk performance remain separate gates. SDK staging and client-only
timings do not establish whole-build or runtime performance.
