# SIMD crypto kernel object qualification

## Scope (2026-11-02)

Five additional amd64 GENERIC link objects now have native declarations: AES-NI
GHASH, CCM and wrappers, plus Intel SHA-1/SHA-256. Six physical prerequisite
contexts preserve source ownership; production C/assembly remains unchanged.
The owning targets declare the original SIMD/AES/PCLMUL/SHA CPU flags and three
cast-qual warning exceptions. Optimized builds select O3; debug configuration
retains the toolchain O0 setting. The existing kernel toolchain/macro is unchanged.

The new bsd_sdk_headers provider derives one compiler-resource directory from
File artifacts in the selected SDK, with no embedded compiler version or host
path. It supplies complete compiler resources and explicitly requested SDK system
headers (SSP availability here), failing on missing/ambiguous resources or invalid
system-header paths. Only selected header files enter CcInfo. Ordinary kernel
compilation keeps its existing header policy.

Make removes nostdinc for these custom crypto recipes so Clang can find its
intrinsics. Native targets keep nostdinc and explicitly search selected-SDK
compiler resources and the declared SDK system-header root, rather than host
include directories. This is an explicit search-policy difference; equivalent
consumed header bytes and final code are independently checked below. Bazel's
normal O2 toolchain flag is followed by target O3 in optimized builds; effective
optimization, not identical raw flag text, is the policy comparison.

The existing build-bsd format-5 target/SDK workflow, CTF and immutable artifact
capture cover these declarations. No frontend C, staging/signing/verification,
publication, SDK-export format or manual option changes are required. Make remains
production/default; BIP remains excluded.

## Retained evidence

Paths below are under /usr/obj/usr/src.

- bazel-kernel-custom-builtins-make-metadata-r1-20261102 records supported
  Make recipes for all eleven then-missing custom products; every reference object
  hash remains unchanged. bazel-kernel-custom-source-bindings-r1-20261102 binds
  nine direct compiler-source identities and external header bytes, retaining the
  two special producer chains explicitly. This is not complete dynamic-input
  discovery or runtime/performance proof.
- bazel-kernel-simd-crypto-amd64-ctf-r1-20261102 passes with all 16 jobs and
  disk-reserve monitoring through the maintained frontend. Five actual compiler
  actions bind through CTF input/output hashes to immutable final captures.
- bazel-kernel-simd-crypto-review-r1-20261102 retains source declarations,
  implementations and exact compiler/artifact reports. Final configured argv
  equals actual executions. Ordered warnings, macros, code-generation options,
  stack/debug/language/forced-header settings agree with Make, with the explicit
  header-search/effective-optimization differences described above.
- Checks verify 316 physical, 8 generated and
  276 external SDK header occurrences. Each external header's
  original Make file, staged SDK file and actual native input digest agree.
  Actual compiler search roots are selected-SDK resources first, declared SDK
  system-header root second, with host default lookup disabled. SSP is only a
  consumed dependency for the sources that query/include it; the retained first
  policy observer incorrectly assumed every source did so. Its correction derives
  the declared SDK root from the content-bound resource root and records actual
  SSP consumption. No production declaration or artifact changed for that correction.
- All five .text/CTF payloads and runtime sections match Make byte-for-byte;
  CTF graphs agree. All 143 non-debug relocations are identical, with no filename
  changes. Full DWARF/string/symbol-table byte equality is not claimed.
- bazel-kernel-simd-crypto-configuration-review-r1-20261102 verifies all
  2,284 previously known groups retain identical configured compiler commands/output paths and
  the five new debug-mode targets have only O0, with their explicit CPU/header
  policy. This is configured analysis, not a debug execution or performance test.
- A bounded source-bound scan finds no matching call-shaped tracing/audit markers
  in these five files; this proves neither absent shared hooks nor runtime coverage.

Closure query r43 passes for 2,289 known groups and
2,464 compilation actions. Reconciliation r36 finds 2,396 source-identity matches,
57 generated-name-only and seven object-name-only matches among 2,466 Make link
products, leaving 6 missing. The old Make source-list inventory omits these
five custom sources, so its graph-only name classification remains conservative;
actual recipe/input/artifact proof above independently resolves those five.
This does not establish complete kernel linking or system completion.

## Remaining gates

The six missing products are the two radix identities, two renamed OpenZFS SHA
assembly objects, VDSO payload and generated final-link addition. Four generated
identities and two other object-name identities still need independent resolution.
Crypto known-answer/error-path, FPU/context lifecycle and live consumer tests,
full linking/post-processing/install, modules, alternate KERNCONF, ARM64/RISC-V64,
world, pkgbase/hardware publication, bootstrap, boot and controlled CPU/memory/disk
I/O/use comparisons remain open. This profile has tests=[] and performs no crypto
device operations. No managed disk cache was enabled. No host install, upgrade
or reboot occurred.
