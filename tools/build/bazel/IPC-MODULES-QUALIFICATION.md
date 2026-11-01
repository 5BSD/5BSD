# POSIX and System V IPC modules on three architectures

2026-11-01. Native module/install candidates now cover mqueuefs, sem, sysvmsg,
sysvsem and sysvshm on amd64, ARM64 and RISC-V64. A shared source-owned inventory
selects the five original C sources and their actual target POSIX/SYSVIPC/Capsicum
option headers. Existing native freestanding object/module/CTF/debug/install rules
are reused. mqueuefs preserves the six explicit exported entry points from Make;
System V modules preserve export-all, and sem preserves default export policy.
Original C behavior, MAC authorization and audit calls are unchanged.

## Dependency correction

The first independent Make batch passes eighteen cases and fails twelve: all
three System V modules on both cross architectures, in both CTF/debug modes.
Their existing Make SRCS lists omit vnode_if.h, reached through vnode.h. The
amd64 kernel object directory already contains that generated header and masks
the omission. All three maintained Makefiles now declare vnode_if.h explicitly.
No preseeded header or test-only include path bypasses the failure. Native module
macros already declare the generated vnode interface dependency. The initial
failure logs remain at `/usr/obj/usr/src/bazel-ipc-modules-make-20261101/`.

All thirty fresh independent Make build/install references pass under
`/usr/obj/usr/src/bazel-ipc-modules-make-r2-20261101/`. Commands, queried target
ARCH_FLAGS, generated files, resource counters and NO_ROOT METALOGs are retained.
All six maintained build-bsd native kernel-profile runs pass under
`/usr/obj/usr/src/bazel-ipc-modules-{amd64,arm64,riscv}-{plain,ctf}-r4-20261101/`.
Each selects ten module/install targets. The r4 suffix reuses previous comparison
script naming; there are no earlier native failures in this tranche. Executable
tests are empty in this artifact-only profile.

## Comparison evidence

All fifteen plain modules match Make byte for byte. All fifteen installed CTF
modules match every ELF section except build-ID/debuglink contents, including
code, symbols, relocations and CTF. Both native and Make debuglink CRCs validate
against actual separate debug files. Separate DWARF/build-ID/layout differences
remain recorded; source debugging is not qualified. All forty-five file/debug
install records match destination, type, owner, group, mode and package/debug
tags. Directory metadata and linker.hints are outside this file comparison.

Execution logs establish thirty actual compile actions with the correct target
triples, -nostdinc/-ffreestanding and no SDK include-file inputs. Review,
compiler audit, bounded marker scan, source/input hashes and reproduction scripts
are retained at `/usr/obj/usr/src/bazel-ipc-modules-review-20261101/`.
The bounded five-source scan retains 173 direct audit/tracing marker lines; these
are textual observations, not runtime events or a count of distinct providers.
Existing audit/MAC paths need live argument/denial/credential/namespace tests.

All five directories were previously selected and lacked direct module macros
in each architecture's retained Bluetooth-era inventory. These five additions
bring the component totals to 137 amd64 candidates and 128 ARM64/RISC-V64
candidates, separate from full module/configuration coverage. Full kernels,
world/pkgbase, bootstrap/cache/sandbox, runtime IPC semantics, resource limits,
concurrency, module loading and controlled CPU/RAM/disk-I/O/disk-allocation
comparisons remain open. No host installation or module loading occurred, and
concurrent resource counters are not performance qualification. The maintained
frontend needs no new API, signing or publication helper change for these normal
module/manifest targets; its manual records coverage. Make remains the production
backend; BIP remains excluded.
