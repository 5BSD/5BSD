# Native libxo CSV encoder (2026-11-02)

## Real selected coverage gap

The fresh configured world inventory/metadata covers 2,127 directories. Its
presence survey found lib/libxo/encoder/csv selected with SHLIB_NAME=csv.enc,
SRCS=enc_csv.c and PACKAGE=runtime, without a native producer or install manifest.
The libxo library itself already had a maintained native owner. BUILD presence
is only a review queue; this tranche qualifies the actual missing plugin.

bazel-libxo-csv-parent-context-r2-20261102/report.json records actual Make exports
along root, lib, libxo, encoder and csv. Source, flags, libraries, package and
installation fields equal standalone queries in this configuration; no inherited
export was dropped. The first observation through buildenv encountered its
artificial recursive BUILDENV_SHELL export and was rejected. The accepted direct
Make observation does not generalize to whole-world export-context correctness.

## Maintained ownership and frontend

The native cc_library compiles the original C source with physical source-owned
xo.h, xo_encoder.h and xo_buf.h, original WARNS=5 flags and compiler-owned PIC,
SSP and debug information. cc_shared_library uses the existing native util/xo
libraries. The CSV plugin keeps SONAME csv.enc and is installed under
/usr/lib/libxo/encoder/csv.enc, with its matching debug file and runtime package
metadata. No C implementation, loader search path or host installation changed.

rules_cc rejects a .enc shared build filename with an internal analysis exception.
The retained r1 attempt compiled nothing. The supported native build artifact is
csv.enc.so; its effective SONAME remains csv.enc, verified from the actual ELF,
and declared installation gives it the original csv.enc name. Neither ELF
rewriting nor a private linker implementation is used to bypass that restriction.

Existing build-bsd format-5 targets/settings directly build csv, install_archive
and encoder_test. There are no new CLI, backend, security, signing or staging
inputs. Make stays production/default. This component archive is not final pkg
creation, repository publication or a completed libxo family aggregate.

## Evidence under /usr/obj/usr/src

- bazel-libxo-csv-make-r1-20261102 is an independent -j16 maintained Make build
  and isolated installation. Supported metadata capture in make-meta-r1 confirms
  the original compiled/linked bytes remained unchanged. Actual prerequisites
  and compiler/linker commands are recorded; the world SDK was not substituted
  for the plugin's original source build.
- bazel-libxo-csv-native-qualification-r2-20261102 passes the normal frontend,
  sixteen jobs and unchanged 18 GiB start/16 GiB reserve guard, with compact
  logging. No disk guard fired. Existing JSON remains the frontend default.
- bazel-libxo-csv-audit-r2-20261102/report.json binds the immutable candidate and
  original compile-output digest. The single native PIC object has exact text,
  both constant-data sections and all three raw non-debug relocation sections.
  Ordered warning/macro vectors match; the toolchain's -fPIC versus Make -fpic
  has equal actual code/data here. All 47 Make prerequisites match declared
  input hashes. No broad include tree or host header fallback was introduced.
- The maintained strict shared ELF comparison accepts SONAME csv.enc, ordered
  NEEDED libutil.so.10, libxo.so.0, libc.so.7, imports/exports/versions and hardening.
  All linked sections match except .debug_info, .debug_line and .debug_str.
  Debug bytes and full ABI equivalence are not claimed. Section inspection uses
  read-only bytes or the maintained checker's explicit discard output; inspected
  input hashes remain unchanged.
- All six original installation records match owners, groups, modes and package
  tags; tar metadata and both debug-link CRCs validate. The prior audit-only
  incorrect debug-reference pathname failed visibly and is retained as r1;
  the corrected fresh r2 report is the passing evidence.
- One captured Python wrapper contains five actual passing methods: CSV quote
  escaping, no-header, DOS newline, unknown-option failure and declared native
  loader dependencies. The test driver dlopens the explicit produced artifact,
  calls its original initializer and libxo encoding API, so an installed host
  encoder cannot satisfy the test. Four functional/error paths also pass against
  the fresh Make plugin (make-runtime-r1), using the same digest-bound driver.
- Compact evidence is streamed through Bazel's original converter, checking all
  189 converter bindings before/after; expanded JSON is not written. Action
  runner/cache fields are retained without a general caching/performance claim.

## Remaining gates

Installed default-path discovery is a guest/runtime gate. Explicit plugin API
loading does not claim to exercise libxo's installed directory search. Complete
upstream libxo suites, debug-disabled/custom install configurations, other target
architectures, final pkg creation, full-world composition and system/performance
qualification remain open. No direct SDT/DTrace, FIDL or BSM calls were found in
the single original CSV source; this conversion adds no invented instrumentation.
