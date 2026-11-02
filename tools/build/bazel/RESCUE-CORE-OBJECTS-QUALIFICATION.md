# First real rescue application objects and crunchide tool

November 2, 2026: build-only qualification of the original cat, echo and head
RESCUE variants plus the ordinary crunchide program. This advances the remaining
application stage after [direct stubs](CRUNCHGEN-DIRECT-STUBS-QUALIFICATION.md).
It does not declare or install a complete rescue executable.

## Source-owned products and actual parent context

The existing bin/cat, bin/echo and usr.bin/head owners now expose separate
`rescue_objects` and `rescue_compiler_outputs` targets. Original generated
`cat_make`, `echo_make` and `head_make` targets establish the actual child policy:
`RESCUE`, no PIE/PIC flag, ordinary debug information and strong stack protection.
The rescue parent itself has MK_SSP=no, but its generated child invocations do
not pass that setting: all three actual child compiler recipes contain
-fstack-protector-strong. The native variants retain it. Cat has no enabled
DTrace coverage provider in this variant, and head has no WITH_CASPER define.
The ordinary existing program targets are preserved.

The original global CRUNCH_CFLAGS adds libifconfig/libiscsiutil object-directory
search roots to every application. Neither root contributes a consumed header
for these three programs. Native source-owned closure models actual consumed
headers, and reports these two unused roots explicitly; no full literal include-
argv equality is claimed. The capsicum helper's original installed-header bytes
match the source-owned native virtual include, with the same logical name.

Crunchide's existing native target now has Make's PIC and NLIST defines, actual
ordered warning vector and C17/PIE/SSP/debug policy. Its three compiler outputs
are mandatory direct binary inputs in original Make order, rather than an own
archive subject to lazy extraction. The existing program/install targets remain
normal source-owned products, with no new frontend API or global policy change.

## Build and independent evidence

All roots below are under `/usr/obj/usr/src`:

- `bazel-crunchide-program-make-reference-r1-20261102`: fresh maintained Make
  tool build, supported meta and original installation inventory.
- `bazel-rescue-applications-make-reference-r2-20261102`: successful original
  generated three-program targets, source parent options/exports and actual
  compiler recipes. The first driver omitted -f rescue.mk and failed before
  application compilation; its rejection is retained separately.
- `bazel-rescue-applications-make-reference-r3-20261102`: fresh repeat with all
  discovered physical dependencies bound before compilation, checked afterward,
  and no newly unbound dependencies accepted. There are 113 unique input hashes
  including the tool, source/header files and scoped Makefiles.
- `bazel-rescue-real-objects-matrix-r1-20261102`: sequential guarded original
  three-object and six-target native build, 16 jobs; both pass without reserve
  interruption. The native profile requests build artifacts and no tests.
- `bazel-rescue-real-objects-native-qualification-r1-20261102`: accepted immutable
  six-object/tool/install captures. No real rescue application was executed.
- `bazel-rescue-real-objects-elf-review-r3-20261102`: all six objects have exact
  allocated sections, nondebug relocation bytes and complete symbol records
  versus original Make. Crunchide program allocated contents, ordered NEEDED,
  exports/imports and unchanged ELF metadata/hardening checks pass. Observer
  initialization errors from missing Python imports are retained in r1/r2;
  they are not accepted comparisons or weakened gates.
- `bazel-rescue-real-objects-action-collection-r1-20261102` and
  `bazel-rescue-real-objects-action-review-r1-20261102`: verified compact log
  conversion retains six uncached compiler records. Native dependency outputs
  are copied only after matching actual execution output digests. Their actual
  consumed logical source/header inventories equal Make byte for byte, covering
  391 occurrences. Warning order, macros, optimization, effective PIE, SSP and
  debug flags pass. The actual parameter file proves the original three-object
  tool link order and accepted compiler-to-link-to-program digest bindings.
- `bazel-crunchide-install-review-r1-20261102`: all five original Make records,
  paths/owners/modes/tags, runtime allocated bytes, debuglink CRC and decompressed
  manual bytes pass. Debug-file/archive-envelope byte identity is not claimed.
- `bazel-rescue-real-objects-review-drivers-20261102`: driver/source/evidence hash
  bundle and the exact retained rejected controls.

## Transformation shape and remaining gates

An attempted positive crunchide control on a raw Clang object was rejected by
original crunchide: its combined symbol/section string table is unsupported.
The source's genuine rescue pipeline first links stub and application objects
with ld -r, then runs crunchide on that combined object. No tool or ELF checker
was relaxed. `bazel-crunchide-transform-controls-r1-20261102/FAILED.json` retains
the rejected positive-control design; original and native tools both reject the
same private raw input unchanged with the same diagnostic. Immutable capture
files remain nonexecutable: the native negative check uses a hash-identical
private executable copy. A first permission rejection before startup is retained.
These are negative checks, not successful crunchide transformation qualification.

Next gates are original stub compilation, original relocatable-link arguments,
matching supported combined-object transformation/keep lists and filename-derived
symbol names, then a bounded real static dispatcher/runtime control. All 103
applications, complete static-library order, final executable/aliases/script
installation, packages, options/architectures and guest/runtime qualification
remain open. ELF32 crunchide execution is not claimed. No rescue object/archive
installation is invented, and no host install, account/tracing change, upgrade
or reboot was performed. Make remains the production build. Existing format-5
source-owned targets, declared SDK and immutable captures cover this cohort;
no build-bsd C/backend/manual input API changes are required.
