# IA32 freestanding prerequisite (2026-11-04)

The recorded AMD64 world inventory selects 32-bit EFI library/loader contexts,
BIOS loaders and standalone libraries. The existing three 64-bit SDK platforms
cannot represent these as correct target architectures. This change adds the
32-bit compiler/linker prerequisite; those producer graphs still need conversion.

## Maintained implementation

The SDK stager declares standalone_i386 using the x86_32 platform constraint,
i386 FreeBSD Clang triple and native AMD64 execution constraints. Its platform
and C++ toolchain are registered with the other disjoint SDK environments.
The artifact boundary accepts explicit architecture i386; ordinary hosted
consumers and execution tools retain their existing environments. It does not
add an i386 system/world target or a 32-bit hosted sysroot.

The SDK capability advances to schema 2. The normal format-5 source backend
requires snapshot-bound schema-2 declarations before staging or invoking Bazel.
A fresh SDK was produced using the maintained SDK stager and the verified
recorded Make-built SDK/profile/tool inputs under /usr/obj. Receipts were not
retagged. Full before/after SDK verification remains enabled. The C frontend
requires no new option; its backend, tests and manual advance together.

The resource-header fixture now checks both ELF32 and ELF64. All four target
ABIs compile the same freestanding checked-addition source with an explicit
compiler resource header. The fixture also uses the maintained firmware-link
rule, ordered objects and a declared linker script to create static ELF images.
Artifact tests validate ELF class/machine, actual code and entry-point placement,
and absence of an interpreter. Target code is not executed on the host.

## Qualification

`bazel-ia32-abi-r1-20261104` below /usr/obj/usr/src passes all eleven test wrappers,
including ELF32 i386 object/link checks, linked AMD64/ARM64/RISC-V checks,
existing object ABI checks, the generator recipe, native installation validation
and 28 frontend methods. All fifteen previously qualified EFI images retain
identical whole-file bytes under the new SDK. The final review also inspects
load segments, entry points and absence of dynamic-loader segments in all four
static fixture images.

`bazel-ia32-abi-negative-r1-20261104` retains an actual i386 compile failure for an
undeclared hosted stdlib.h. This verifies that the new platform does not fall
back to a hosted include search. `bazel-ia32-old-sdk-rejection-r1-20261104` retains
real frontend rejection of the previous schema-1 SDK with regeneration guidance,
before an output workspace is created. Its first harness assumed backend errors
would be in stderr; build-bsd merges them into stdout. Both streams remain and
the corrected review inspects their combined diagnostic content.

The new SDK is `bazel-standalone-ia32-sdk-r1-20261104`, with 8,331 snapshot files.
The consolidated report and commit binding are in
`bazel-ia32-abi-final-review-r1-20261104`. These records qualify the prerequisite,
not complete BIOS/IA32 EFI programs, their CPU-specific flags, a boot test,
32-bit hosted libraries, a full world/kernel/package build or performance.

## Next work

Convert and qualify the selected 32-bit standalone/EFI/BIOS producer contexts,
then reconcile complete boot/world installation and pkgbase composition. Preserve
source-owned CPU/firmware flags and ordered link inputs; the SDK ABI alone does
not supply those component policies. Full bootstrap, sandbox, cache/relocation,
separate-debug, VM runtime and CPU/memory/disk gates remain open. Make remains
production/default; BIP is excluded. No host installation, upgrade, publication,
reboot or target execution occurred.
