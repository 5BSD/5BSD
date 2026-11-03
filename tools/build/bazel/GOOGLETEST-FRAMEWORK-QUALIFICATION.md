# Googletest framework installation checkpoint (2026-11-03)

## Source-owned installation and archive corrections

The four framework libraries now have ordinary static archive and installation
candidates. Each component's native BUILD file owns its Make-selected header
inventory. A shared installation macro declares archives, stripped shared
libraries, separate debug files, linker symlinks and private headers. There is
no Make query or filesystem inventory inference during a native Bazel build.

`//lib/googletest:install_manifest` composes the component manifests and selects
self-tests through the existing tests/Googletest settings. Identical package-owned
debug directories merge explicitly. The default aggregate has 101 logical
records: 56 framework records and 45 previously qualified self-test records.
The framework records are 38 headers, four ordinary archives, four shared
libraries, four separate debug files, four linker symlinks and two directories.
Headers, archives and symlinks retain package=googletest,dev; shared libraries
retain package=googletest; symbols/directories retain package=googletest,dbg.

The earlier framework declarations forced `-fPIC` on ordinary objects. That
flag is removed. The maintained `bsd_small_pic` toolchain feature selects
Make's `-fpic -DPIC` for shared-library objects; ordinary archives use ordinary
objects. The archive rule consumes each library's own objects, without copying
transitive dependencies into its installed archive.

Independent shared-library comparison exposed missing explicit math dependencies
and the direct gtest dependency of gmock_main. The declarations now preserve
Make's full framework dependency chain and library order. These are source-built
Bazel dependencies, not raw host library names or arbitrary linker overrides.
The shared link also retains Make's local-symbol and fatal/text-relocation
warning policy. No production C/C++ or Make source was modified.

## Independent Make evidence

All paths below are under `/usr/obj/usr/src`.

- `bazel-googletest-framework-metadata-r1-20261103` captures original framework
  policy through the maintained Make build environment and recorded world SDK.
- `bazel-googletest-framework-make-matrix-r1-20261103` records four sequential
  `install-reference.py --make-meta --jobs 16` builds/stages. Each
  `bazel-googletest-{component}-make-r1-20261103` receipt passes with original
  compiler/profile/include checks, NO_ROOT metadata and private staging.
- `bazel-googletest-framework-r3-20261103` is the final normal frontend native
  candidate. All 40 self-test programs run freshly and pass; the reporting-control
  target is a cached pass. This is 41 outer test cases, with 40 fresh executions.
- `bazel-googletest-framework-review-r2-20261103` compares all 56 unique framework
  records with the original component METALOGs: destinations, types, owners,
  groups, modes, flags, tags and symlink targets. All 38 installed headers are
  byte-identical to the Make payloads.

All four archives match original member order and each member's defined/undefined
symbol contract. All four shared libraries match SONAME, ELF identity, imports,
exports, symbol versions, dependencies and dependency order, with required
hardening and no unexpected search paths. The comparisons use maintained
artifact readers and hash-bound captured qualification payloads. The ELF reader
is explicitly `/usr/bin/llvm-readelf`, with its hash retained; other inspection
utilities are from the frozen SDK. This is not a hermetic-toolchain claim.

Complete archive/shared bytes differ from Make. The shared section-difference
lists are retained. This checkpoint does not establish full code or ABI
equivalence, or explain away differing text/relocation/exception sections.
Independent compiler-context/allocated-code comparison remains required.

The original Make receipts retain their original source hashes. Four subsequent
Bazel BUILD declaration changes are recorded separately with old/current hashes;
those files are absent from the recorded Make input/include closure. The Make
input, compiler/profile and implementation bindings are rechecked unchanged.
The reference receipts are not rewritten to match the candidate.

## Actual action and debug checks

`bazel-googletest-framework-actions-r2-20261103` binds eight actual final native
compiler actions to source hashes and the selected compiler. Four ordinary
objects lack forced PIC/PIE flags; four PIC objects use `-fpic -DPIC`.

The final objects reproduce the bytes consumed by four earlier actual archive
actions in `bazel-googletest-framework-r1-20261103`. Those actions are cached in
the final build. The review checks every owned-object input hash and the final
captured archive hash; it does not claim four fresh final archive executions.
The upstream Bazel compact-log converter and its runtime bindings are retained.

Four native and four original Make stripped-library/debug-file pairs pass the
maintained debuglink checks: matching ELF identity, removed runtime debug/static
symbol sections, nonempty separate debug information and correct filename/CRC.
This does not qualify debugger source lookup or complete debug package behavior.

Thirty-nine raw inner self-test XML reports are retained alongside final logs;
one program produces no inner XML. These reports can contain deliberate inner
failures/disabled tests and are not summed into outer passing-case counts.

## Option and frontend integration

`bazel-googletest-framework-notests-r1-20261103` passes normal frontend build
qualification with tests=false and no test targets. It contains exactly the 56
framework records, excludes all 45 self-test records, and leaves framework
metadata unchanged. `options-and-source.json` compares this with independent
Make MK_TESTS/SUBDIR queries against the unchanged staged SDK. This is component
selection evidence, not a world rebuilt without tests or other-option coverage.

The existing format-5 build-bsd path consumes the native aggregate label and typed
build setting. No C frontend option, manual interface, signing/staging helper or
publication rule changes are required. The source-owned backend definitions,
normal frontend builds, tests and qualification documentation are updated
together. No host installation, upgrade, reboot or package publication occurred.
No signing, verified boot or compromised-root protection is tested.

Earlier failed dependency comparison is retained in
`bazel-googletest-framework-review-r1-20261103`. The first installation candidate
omitted the Make-owned debug directories; those were added before final metadata
comparison. The first action audit expected fresh archive actions and failed;
the final audit explicitly binds cached archive actions to matching final bytes.

## Remaining gates

This establishes selected-default amd64 installation metadata, header payloads,
archive member symbols, shared-library metadata, debuglink integrity and functional
self-tests. Full Make code/compiler-context equivalence, other build options,
ARM64/RISC-V builds/execution, debugger/source packages, installed-suite execution,
actual pkgbase archives, world aggregation and publication remain open. These
frameworks currently have no component install tar target; an installation
manifest is not a completed pkgbase archive.

Disk reserves and client timing/rusage are retained, but aggregate compiler/JVM
CPU, memory, disk I/O and comparative performance remain unmeasured here. Full
world/kernel/modules/bootstrap/sandbox/runtime/package qualification remains
open. Make remains production/default; BIP remains excluded.
