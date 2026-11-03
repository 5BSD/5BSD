# Standalone Ficl candidate (2026-11-03)

The later [cross/private EFI checkpoint](FICL-CONTEXTS-QUALIFICATION.md) extends
this initial AMD64-only evidence. The scope below describes the initial run.

## Implemented and exercised

`//stand/ficl:static_archive` builds the fifteen members selected by the
maintained standalone Ficl Make recipe, in its original order. Native C++ rules
own compilation, dependency files and source/header inputs; the component archive
owns the ordered archive action. The generated softcore C file is an explicit
producer dependency. No native action invokes Make or consumes its generated C.
The dictionary size remains 30000; standalone ABI, assertions, warning policy,
GELI/disk and existing global verifier selections are retained.

AMD64 is the only archive profile qualified at this checkpoint. ARM64 and RISC-V
source/ABI selections are declared but have not yet been built or compared here.
Private EFI Ficl, IA32, final loader links and firmware execution remain open.
This internal archive has no installation payload: the independent Make
component METALOG is empty. That is not loader/package installation coverage.

## Deterministic softcore generation

The maintained Make recipe concatenates six softword files in explicit order and
runs the original AWK script. Its date stamp appears only in a C comment.
`//stand/ficl:datestamp` is a string build setting, default empty (undated), passed
through the existing format-5 `build-settings` object. It never reads the host
clock. Metadata rejects newlines, NUL, a C comment terminator and backslashes
(which AWK could interpret). The qualification explicitly selected
`Tue Nov 3 2026 (explicit qualification input)`; this is a test input, not a
production timestamp. The default-empty profile remains to be exercised.

The reusable AWK rule now accepts string build-setting labels mapped to variable
names through `variable_settings`. These use `-v` so BEGIN sees the value.
Existing `variables` preserve their operand-assignment semantics; they are not
silently changed to early initialization. Invalid variable names, duplicate
names and non-string settings are rejected at analysis time.

`//stand/ficl:softcore_test` independently concatenates the original six sources
into one input stream, invokes the original script and compares the entire C
output with the native action. It checks newline boundaries and preserved entry
point, and passes through the maintained frontend. Captured source bytes were
also checked separately against the explicitly requested metadata value; the
test alone does not prove configuration propagation. The rule's file operands
are equivalent for this script: it has no per-file state reset, and the six
sources end in newline. Changing that contract fails the recipe test.

## Comparison and provenance

Evidence under `/usr/obj/usr/src/`:

- `bazel-ficl-amd64-make-r1-20261103`: independent maintained Make reference,
  including original compiler metadata, original archive and empty METALOG.
- `bazel-ficl-generator-amd64-r1-20261103`: fresh generator and passing recipe
  test with the declared date setting.
- `bazel-ficl-archive-amd64-r2-20261103`: successful fifteen-member native archive,
  passing recipe test and immutable captured artifacts.
- `bazel-ficl-amd64-review-r1-20261103`: raw allocated-section, symbol, relocation
  and member-order comparison. The generic diagnostic helper retains an older
  Lua scope caption; the recorded target, archive binding and all fifteen Ficl
  member names identify the actual comparison unambiguously.
- `bazel-ficl-amd64-filename-control-r1-20261103`: isolated original compiler
  controls, with macro filename mapping only (and dependency-output flags
  removed to avoid changing the original dependency files). All fifteen match
  native allocated bytes and symbolic relocations. Original artifacts remain
  unchanged; no mapping was added to the native production rules.
- `bazel-ficl-action-review-r1-20261103`: successful actual generator/compiler/
  archive actions, declared source hashes, dependency-file ownership and complete
  output digest chains to the captured archive. Fourteen compilers ran in the
  initial archive attempt; the missing sysdep compiler completed in revision 2.
  This combined provenance is explicit, not a claim that all compiled in r2.

Raw Make comparisons match all symbol contracts and member order, but only three
of fifteen members match allocated bytes and relocations. The remaining twelve
retain different assertion filename strings: absolute Make source paths versus
relative Bazel source paths (and distinct generated-source paths for softcore).
The separate filename controls explain the differences; raw equality is not
claimed. Full object/debug bytes differ. A common diagnostic/debug source-path
policy and source lookup remain system-wide requirements.

The first archive attempt failed on an undeclared `machine/cpufunc.h`; the source
header was then declared, without widening to host includes or disabling sandbox
checks. Failure records are retained. The normal frontend was used with all
sixteen logical CPUs, explicit format-5 SDK/input bindings and selected JDK.
`build-bsd.c` needs no new switch: its maintained backend already handles typed
source settings, native labels and captured results. The manual documents the
new targets and metadata setting. This adds no publication/signing policy.

## Remaining gates

Cross and private EFI archives; IA32; independent runtime execution of Ficl;
complete standalone library and loader links; boot; debug/source lookup;
unchanged and changed-input cache checks; complete world/kernel/modules,
installation/pkgbase/hardware publication; reproducible bootstrap, stronger
sandboxing and broad CPU/memory/disk I/O/disk usage comparisons. No VM, host
installation, upgrade or reboot occurred. Make remains production/default;
BIP remains out of scope.
