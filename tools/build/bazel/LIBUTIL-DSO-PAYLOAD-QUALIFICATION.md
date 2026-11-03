# libutil DSO payload (November 2, 2026)

## Actual cause and native correction

The preceding static-consumer checkpoint passed shared ELF metadata but retained
DSO payload differences. Its actual PIC archive placed `pw_scan` last among C
objects, whereas original Make selects it before `pw_util`. Native linking also
omitted original `-Wl,-x`. The actual version maps are byte-identical. Compiler
and linker bytes and every declared sysroot input independently match original
Make's staging.

Exact native link replay reproduces the rejected prior ELF byte for byte.
Changing only final PIC object order removes every allocated difference except
`.SUNW_dof`. Adding original local-symbol discard yields the same whole ELF as
the original Make link recipe on those native inputs. The native source list
now preserves original SRCS order, including the source owned by libc; the DSO
retains original local-symbol discard. Only two native declarations change.
Original Make, C sources, generic helpers, toolchain and frontend APIs do not.

A deliberately mixed original provider/native rewritten class fails the strict
hidden FNV path-key association; this rejection is retained. A matched original
provider/class pair with the other native C inputs produces all allocated
sections exactly equal to original Make. That diagnostic uses explicit original
inputs and does not replace or rewrite production native objects.

## Corrected native artifact and original inputs

The actual corrected native ELF is whole-byte identical to the original Make
link recipe on the exact accepted native inputs. This differs from comparing
against untouched independently built original objects.

The captured corrected default DSO matches every allocated section of the
independent original `libutil.so.10.full` except `.SUNW_dof`: code, read-only and
writable data, BSS size/alignment, dynamic tables, relocations, unwind data and
loader-related sections all pass exact section descriptor/content checks
(28 of 29 allocated sections).

All nine DOF section descriptors and payloads are accounted for using actual
PIC object paths, independently verified FNV names, resolved string offsets and
checked padding/extents. The unchanged maintained linked-ELF inventory verifies
original provider/schema/argument mapping, actual function/address and NOP sites.
No general symbol waiver, unresolved-zero equivalence or production artifact
normalization is used. Raw path-derived DOF bytes remain different. The unchanged
shared-library comparator passes SONAME, ordered NEEDED, versioned imports and
exports, version definitions/requirements and hardening.

All 68 real current default compiler actions exactly match the preceding
independently qualified normal/PIC commands, complete input digests, environment
and object/dependency output bytes. Thus its 3,778 original/current consumed
occurrences and original warning/define/codegen/small-PIC proof remain bound.
The first observer also included a separate execution-tool `login_class` action;
its rejection is retained and the corrected comparison explicitly selects the
68 target-configuration actions. Original Make sources remain unchanged; the
reference receipt is not rebound to later native declarations or fixtures.

The explicit experimental profile likewise preserves all 68 actual compiler
commands, complete input digests, environment and output bytes against its own
accepted predecessor. Its 34-member composition retains embedded logincap
metadata only in `login_class`, no separate anchor, the selected original probe
schema and no unrelated metadata in the number-only consumer. Shared ELF
metadata passes. Experimental whole-library/Make payload parity is not claimed.

## Existing tests and unchanged artifacts

Both maintained profiles pass their applicable declared tests. The 56 default
methods (nine archive, four consumer, 43 rescue) and the experimental 43 rescue
methods are explicitly cached accepted results. Current logs and immutable test
reports preserve that provenance; no fresh test execution is invented.

Default component archive, both static consumers and rescue are whole-byte
identical to the previous accepted captures. Both experimental static consumers
and rescue are also whole-byte identical to their accepted captures. All actual
current archives, objects, dependency files and final link parameters are
preserved before any profile switch. Final DSO actions are selected by complete
target/output identity, excluding a repeated execution-tool label. An unchanged
cached provider archive is bound to its prior immutable bytes and the current
link input digest; no fresh archive action is invented.
No credential-changing function, probe
registration or live tracing ran.

## Maintained workflow and remaining gates

Existing build-bsd format-5 targets/tests, validated SDK, compact logging and
immutable artifact capture carry both profiles with 16 jobs and disk guards.
The manual documents the payload scope. No CLI, signing, publication or staging
policy changes; Make remains production/default. No host installation or reboot.

Whole DSO/debug equality, separate DWARF/source lookup, installed libraries and
original ATF tests remain open. The remaining nonallocated section differences
include DWARF and ordinary symbol/string tables. Arbitrary CcInfo extraction,
untraced modes/options/architectures, experimental full-library parity, DTrace
host-provenance/cache hermeticity, full rescue/world/packages/hardware,
bootstrap/publication, live events and performance remain separate gates.

## Retained evidence

All roots below are under `/usr/obj/usr/src/`:

- `bazel-libutil-static-anchor-make-reference-r1-20261102`: independent original
  normal/PIC objects, original final recipe, full DSO and immutable reference.
- `bazel-libutil-dso-payload-review-r1-20261102`: actual input/order/version-map
  diagnosis; current compiler/artifact/test regressions and final hash bindings.
- `bazel-libutil-dso-link-controls-r1-20261102`: rejected mixed-provider attempt
  and four completed controls; untouched outputs and diagnostic inspection.
- `bazel-libutil-dso-link-controls-r2-20261102`: complete input/argv/output
  records for four positive links, strict mixed-provider negative and positive
  matched original provider/class pair. No target execution.
- `bazel-libutil-dso-payload-default-qualification-r1-20261102` and
  `default-action-collection-r1-20261102`: corrected default immutable outputs,
  actual actions/dependencies/archives/parameters and cached test reports.
- `bazel-libutil-dso-payload-section-qualification-r1-20261102` and
  `section-action-collection-r1-20261102`: explicit experimental regression.
- `bazel-libutil-dso-full-dof-review-r1-20261102`: both complete linked-ELF
  inventories, independently verified actual PIC path keys and exact accounting
  for all nine DOF sections.

The later [original test/install qualification](LIBUTIL-TEST-INSTALLATION-QUALIFICATION.md)
supplies the previously missing twelve test programs and selected component
installation metadata/archive. Its separate DWARF/source-lookup and full
library/pkgbase limits remain explicit.
