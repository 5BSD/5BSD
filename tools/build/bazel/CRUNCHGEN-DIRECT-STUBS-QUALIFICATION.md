# Original crunchgen direct entry stubs

Qualified on November 2, 2026. This extends the bounded dispatcher/tool cohort in
[RESCUE-DISPATCH-QUALIFICATION.md](RESCUE-DISPATCH-QUALIFICATION.md).

## Producer and ordinary workflow

The ordinary `crunchgen -s directory` option writes one `<program>_stub.c` into an
existing output directory. A single C emitter supplies both these files and the
legacy generated Makefile echo recipes. Without `-s`, no stub files are written;
the existing generated main C, cache and Makefile retain their bytes. Invalid
output directories, nonlocal program paths and file write/close failures return
failure. The ordinary crunchgen manual documents the option.

`bsd_crunchgen(emit_stubs = True)` declares each original producer output and
exposes `stubs` plus per-identifier `stub_<identifier>` output groups. The generic
attribute defaults to false; the default dispatcher output remains its main C
file. `//rescue/rescue:entry_stubs` explicitly selects the 103 original C stubs.
No generated Makefile is parsed or executed by the native build. Every program
still requires explicit object metadata; the native action retains empty PATH
and an unusable MAKE path, declared execution tool/runtime inputs and constructor-
time `DTRACE_DOF_INIT_DISABLE=1`.

The fixture now compiles the two generated entry stubs and routes them to its
declared harmless C entries. Its seven unittest methods exercise normal and
alias dispatch, ordered listing, usage/error handling, private hardlinks, and
stub bytes versus the original generated recipe. Fixture entries are not real
rescue application compilation.

## Independent Make and native checks

All roots below are under `/usr/obj/usr/src`:

- `bazel-crunchgen-program-make-reference-r3-20261102`: fresh ordinary Make
  tool/PIE objects/manual and five installation records, supported Make meta.
- `bazel-crunchgen-direct-stubs-matrix-r1-20261102`: sequential guarded Make and
  native builds with 16 jobs. Both pass; the 16 GiB reserve is not reached.
- `bazel-crunchgen-direct-stubs-native-qualification-r1-20261102`: accepted
  format-5 receipt and immutable generated/tool/object/install/test captures.
- `bazel-crunchgen-direct-stubs-controls-r1-20261102`: the original preserved
  Makefile actually produces all 103 stubs in a disposable object directory.
  Every stub equals the new C producer and its immutable native output. The
  main C, cache and Makefile equal both the direct and ordinary new producer
  outputs and their prior qualified captures. Ordinary mode emits no stubs.
  Missing directory, nondirectory and slash-containing program controls fail.
- `bazel-crunchgen-direct-stubs-elf-review-r1-20261102`: dispatcher and two
  normal tool objects match original Make in all allocated sections, runtime
  relocations and symbol records; the tool program matches allocated contents,
  ordered NEEDED entries and the unchanged ELF metadata/hardening checks.
- `bazel-crunchgen-direct-stubs-install-review-r1-20261102`: all five original
  Make install records, runtime allocated bytes, debuglink CRC and decompressed
  manual bytes pass. No whole debug-file/archive-envelope equality is claimed.
- `bazel-crunchgen-direct-stubs-action-collection-r1-20261102` and
  `bazel-crunchgen-direct-stubs-action-review-r1-20261102`: compact records are
  fully drained through the verified upstream converter. Two fresh production
  compiler actions and three unchanged outputs explicitly bound to prior
  uncached compiler records satisfy 166 original dependency occurrences and
  the Make warnings/macros/PIE/SSP policy. Execution-tool `-g0` remains explicit,
  separate from the normal installed debug policy. Both original generators
  execute freshly; all 103 stub output digests bind to the actual action.
  One fresh test setup/XML pair runs seven actual unittest methods; nine
  unchanged analysis-test results are reused, not described as fresh executions.
- `bazel-crunchgen-direct-stubs-link-review-r1-20261102`: actual hash-checked
  parameter file and compiler-output-to-link-input-to-capture bindings prove
  the original two-object tool order.
- `bazel-crunchgen-direct-stubs-review-drivers-20261102`: exact driver, source
  and evidence hash bundle. The earlier dispatcher evidence remains preserved.

`mandoc -T lint` reports the same single preexisting `Tn` style diagnostic before
and after the ordinary manual edit, with its line shifted from 331 to 343. This
is a delta check, not a globally clean lint claim. Existing format-5 target,
SDK, immutable-output and test support covers these new declared outputs; no
build-bsd C/backend or bsd-build manual API change is needed. The source-owned
rule attribute and ordinary producer option are documented together.

## Remaining rescue work

This qualifies direct stub generation, not the 103 application variants or a
complete rescue executable. Original RESCUE/static/no-PIE compile contexts,
source/generated-header closure, actual stub compilation, relocatable links,
crunchide symbol transforms, complete static library order, full executable and
aliases/script installation, package/architecture/options and safe/guest runtime
checks remain open. No rescue archive installation is invented. No host install,
upgrade, tracing activation, account change or reboot was performed; Make stays
the production build.
