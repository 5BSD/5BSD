# Native private LLDB library qualification (2026-11-02)

## Scope

The source-owned `//lib/clang/liblldb:lldb_shared`, own-object PIC archive,
installation archive and safe API test build through the maintained format-5
`build-bsd bazel-test` frontend. The ordered inventory contains all 756 original
Make sources, including the local Lua wrapper and both distinct `Host.cpp`
files. Existing native Clang/LLVM libraries and declared kvm/C++/math dependencies
supply the actual shared-library link. No runtime Make parsing is introduced.

This qualifies the default amd64 shared/PIC library configuration: LLVM
assertions enabled, ordinary line-table debug policy and full Clang enabled.
The two CLI programs, static/PIE alternatives, cross architectures, full LLDB
upstream tests, debugger initialization/process control, family selection and
final package creation remain open. No host installation or tracing/debugger
activation occurred.

## Immutable native evidence and original Make reference

All roots below are under `/usr/obj/usr/src/`.

- `bazel-lldb-library-native-qualification-r4-20261102`: passed native build and
  one actual `api_smoke_test` wrapper; receipt SHA256
  `70cd822652602082580adb8ac9881775a42cdbc03f360fb2aa06fbb5498e3c71`, artifact
  manifest SHA256
  `60b946cad3aae222b5940654f6a874de83dbef1d84f92cf2b25e1085a255d16a`.
  Explicit target/output capture resolution verifies containment, size and SHA.
- `bazel-lldb-library-make-reference-r1-20261102`: independent original Make
  build/install staging with supported metadata recording, all 756 PIC objects.
  The maintained `install-reference.py --make-meta --jobs 16` path was used;
  the reference retains original flags and filenames.
- `bazel-lldb-library-make-metadata-review-r1-20261102`: 756 actual recipes,
  690,249 consumed-file occurrences and 3,336 unique physical paths. This is a
  post-build physical-input inventory, not a claimed full pre-build snapshot.
- `bazel-lldb-library-action-review-r4-r2-20261102`: 756 successful actual native
  PIC compile records, exact Make warning/effective macro/optimization/debug,
  exception/RTTI/PIC/SSP policies, immutable output bindings, and all 690,249
  prerequisite hashes matched. Source lexical spellings are resolved only when
  they identify the same physical file, then hashed. SDK resource headers are
  bound through the compiler's actual declared `-resource-dir`.

The native receipt uses the historical immutable
`bazel-posthypertrace-sdk-20261102` receipt
`f5efce0dacfcde4956fbe77dff91329dc6be969b290c22dc5960259828745346`.
After a host bsdtar change, the primary prepared
`bazel-posttar-sdk-20261102` for subsequent builds. This result does not silently
rebind the earlier native build to that newer receipt.

## Original filename difference and complete compiler control

The untouched object comparison is retained in
`bazel-lldb-library-object-review-r1-20261102`: 553/756 executable and 197/756
allocated section sets are byte-identical. The original shared metadata check
passes SONAME, ordered NEEDED, imports/exports with versions and hardening, but
its original `.text`, `.rodata` and relocation payload differences remain
recorded. These are not claimed as original whole-file byte identity.

A specific `SBStream::RedirectToFile` difference was traced through unchanged
`LLDB_LOG_ERROR` source to the constant-folded length of `__FILE__`:
`/usr/src/contrib/...` versus `contrib/...`. No source literal or native
production flag was changed to embed `/usr/src`.

The independent original-Make filename-policy control is
`bazel-lldb-library-filename-control-full-r1-20261102`. It builds original `all`
with 16 jobs and adds only `-fmacro-prefix-map=/usr/src/=` to the original
compiler flags. Inner arguments use a literal JSON/direct-exec transport;
Make's target-dependent `DEPEND_CFLAGS` remains evaluated by the inner Make.
The normal reference is untouched. The complete build passed in 318.1 seconds;
the disk guard minimum was 288,094,244,864 bytes, above its 16 GiB floor.

Its `comparison.json` proves every one of the 756 actual compiler recipes
matches the original after removing only that declared mapping. All 756
immutable native objects have exact allocated section type/flags/size/alignment
and bytes against this control, with all 3,336 consumed paths rechecked.
`bazel-lldb-library-canonical-shared-review-r1-20261102/report.json` also proves
**all allocated linked DSO sections exact**, without observer rewriting or
normalization. Debug information and complete file bytes are not claimed equal.

Focused controls r1 through r4 remain rejected: the mapping was absent from the
recipe or outer Make expansion dropped dependency flags. Focused r5 passed
both sampled objects before the full control. Failed native r1/r2/r3 analysis
and missing original/generated-header attempts remain retained as well.

## Generated headers, archive, actual link and installation

- `bazel-lldb-library-generated-header-review-r1-20261102`: all 59 generated
  headers actually consumed from the configured world object tree match native
  captures. The 19 LLDB headers also match the independently generated local
  Make copies. Local copies are not falsely reported as consumed headers.
- `bazel-lldb-library-own-archive-review-r1-20261102`: every one of 756 archive
  member payload hashes matches its captured actual compiler output, in the
  original Make source order. Duplicate basenames are checked by occurrence
  and exact contents, not collapsed.
- `bazel-lldb-library-link-review-r3-20261102`: actual successful DSO link
  parameter SHA and own-archive digest are bound; whole-archive is closed
  immediately afterward. Explicit solib search paths select the captured native
  Clang/LLVM DSOs, distinguished from separately declared SDK tool-runtime and
  sysroot copies. Six explicit link dependencies produce the checked ordered
  seven ELF NEEDED entries: Clang, LLVM, kvm, libc++, libcxxrt, libm, libc.
- `bazel-lldb-library-shared-review-r1-20261102`: unchanged maintained shared ELF
  checker passes SONAME `libprivatelldb.so.21`, ordered NEEDED, imported/exported
  symbols and versions, RELRO/NOW, and absence of RPATH/textrel/writable executable
  segments against the original reference.
- `bazel-lldb-library-install-review-r3-20261102`: all five original Make records
  match native destination/type/root:wheel/mode/link/package tags. Four standard
  structural tar directories are checked separately. Runtime/debug payloads and
  actual debuglink CRC are bound; runtime payload parity follows the complete
  canonical-control comparison above. The additive shared-installation helper
  package argument defaults to `clang`, preserving its existing seven consumers;
  this component uses `lldb` and retains `dev`/`dbg` contexts.

## Runtime and integration limits

The one native C++ test validates the actual loaded native LLDB, Clang and LLVM
DSO paths, version, error copy semantics, string list copy/order and valid/invalid
structured JSON operations. It does not call debugger initialization, launch,
attach or listen. DOF initialization is disabled before process startup.
This does not establish a fully hermetic loader or the upstream LLDB test suite.

The frontend integration review found no new build input or security/staging
API: existing format-5 targets, settings, tests and installation rules apply.
`build-bsd.c`, backend targets and manual need no new interface for this cohort.
The source package boundaries and unchanged source include spellings are
explicit. Continue with CLI generated option headers and programs, safe
pre-initialization tests, actual install/package ownership and the maintained
world parent-selection inventory; the full-system goal remains open.
