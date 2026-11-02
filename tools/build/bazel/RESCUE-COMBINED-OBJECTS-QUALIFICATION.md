# Native rescue combined objects and symbol hiding

November 2, 2026: cat, echo and head now have original generated entry stubs,
ordered relocatable links and original crunchide transformations. This follows
[the actual application objects](RESCUE-CORE-OBJECTS-QUALIFICATION.md). It does
not yet link, execute or install a rescue application or the complete rescue.

## Declared producer contract

The source-owned `//rescue/rescue:core_dispatch` generates the bounded three-
program catalog with executable name rescue_core. Each entry stub is compiled
using the actual generated Make recipe: parent no-SSP/no-debug policy, no PIE,
C17 and the original ordered warnings. Application objects retain their separate
actual child strong-SSP/debug policy. Native compiler outputs feed the original
stub-first, application-second relocatable link directly, without an archive.

`bsd_relocatable_link` uses declared SDK ld.lld and its runtime. The original
compiler driver selects the byte-identical linker with --eh-frame-hdr, -Bstatic,
--allow-multiple-definition, -znow, -zrelro and -r. Its --sysroot and -L roots
perform no lookup in these object-only links; native actions omit those unused
Make staging paths. Literal complete driver-argv identity is not asserted.

The reusable `bsd_crunchide` rule accepts one already combined ET_REL `.o`/`.lo`,
a canonical `program_name` basename and explicit `keep_symbols`. Empty keep
lists deliberately hide all definitions; duplicate or empty individual symbols
and invalid program names fail analysis. It copies the input to an owned
`<target>.generated/<program>.lo`, then runs the original declared cfg=exec
crunchide in that directory with `-k` arguments and only the basename. This
preserves original filename-derived `_$$hide$$ <program>.lo <symbol>` names.
Existing static dtrace_copy_runner and cwd_exec supply copy/chdir/exec; no new
shell, Make subprocess or substitute symbol transformer is introduced.

Only declared libc/libsys runtime aliases are exposed through LD_LIBRARY_PATH=.
Locale is C, PATH is empty, and DTRACE_DOF_INIT_DISABLE=1 is set before startup.
The original input is never modified. DefaultInfo exposes a transparent `.o`
symlink for ordinary C/C++ object consumers; output groups `original_name` and
`execution_tool` expose the `.lo` and actual execution tool for qualification.
`core_metadata` and per-program `_entry_source`, `_entry_compiler_output`,
`_unhidden`, `_crunched` and `_crunched_original` targets retain each stage.

## Actual evidence and limits

The maintained build-bsd format-5 profile accepted 22 targets and all 12 suite
members. Two new negative analysis tests executed uncached with their XML
producer actions; nine previous analysis results and the seven-method runtime
fixture wrapper were local cache hits. These fixture results do not execute the
three production applications. Six fresh sandboxed compiler actions, their 135
consumed input occurrences, three exact ordered links and three private crunchide
actions are hash-bound to immutable captures. Execution-tool compilation matches
original Make source/macros/warnings/SSP/PIE, with the explicit execution-mode -g0
override. Its three mandatory objects retain original link order.

All three generated stub C bodies and stub object whole files equal the original
Make controls. All nine stub/raw/hidden object pairs have exact allocated
sections, runtime relocation bytes and symbol records. The six combined/hidden
files retain different .debug_str/.debug_line and their debug relocations.
Explicit decoded DWARF inspection proves differences only in source/header path
attributes and absolute Make compilation directories versus native `.`; address,
line and column rows are exact. Raw debug bytes are not declared identical, and
no production bytes or diagnostic filenames were rewritten.

A stronger identical-input control uses accepted native stub/application objects
with original Make's selected linker, emitted flags and staging search roots.
It reproduces all three native raw objects byte for byte. Both original normal
crunchide and the captured execution-tool build reproduce all three hidden whole
files, six successful operations. Earlier supported ELF64 controls also verify
both `-k` and `-f` keep interfaces against original outputs. Raw single compiler
objects rejected by original crunchide remain rejected; the valid production
input is the original stub-plus-application ld -r result.

The first native profile rejected an incorrect existing runner target label
before compilation; corrected r2 passed. Observer failures (literal versus
physical double-slash path spelling, argument-count typo and unsupported host
readelf DWARF options) remain preserved separately. Corrected checks do not relax
source, ELF, object order or symbol constraints.

No frontend CLI/backend API change is needed: maintained format-5 target/test/
SDK bindings, compact execution logging and immutable artifact capture carry this
normal graph. No new install product is invented at this intermediate stage.
Full rescue still requires all selected application variants, complete static
library/link closure, genuine dispatcher/application runtime tests, installation,
option/architecture coverage and package integration.

## Retained records

All paths below are under /usr/obj/usr/src:

- bazel-rescue-crunchide-producer-native-qualification-r{1,2}-20261102:
  rejected analysis and accepted receipt/captures/compact log.
- bazel-rescue-combined-make-control-r2-20261102 and
  bazel-rescue-combined-replay-control-r1-20261102: actual original generated
  Make stub/link/hide recipes and raw object replays.
- bazel-crunchide-supported-controls-r1-20261102: six original/native keep controls.
- bazel-rescue-crunchide-producer-action-collection-r2-20261102,
  bazel-rescue-crunchide-producer-action-review-r{1,2}-20261102 and
  bazel-rescue-crunchide-producer-elf-review-r1-20261102: actual execution and ELF
  evidence, including the rejected observer and exact current input bindings.
- bazel-rescue-crunchide-producer-identical-input-control-r1-20261102:
  whole-file linker and original/native crunchide reproductions.
- bazel-rescue-crunchide-producer-debug-review-r{1,2}-20261102 and
  bazel-rescue-crunchide-producer-debug-verify-r1-20261102: raw decoded differences,
  explicit filename mappings and exact decoded line rows.
- bazel-rescue-crunchide-producer-review-drivers-20261102/manifest.json:
  scoped source hashes, copied drivers and accepted/rejected evidence hashes.
