# Original Heimdal references and native generation tests

## Maintained reference interface

install-reference.py accepts --generator-inputs with --make-meta. Format 1 has
exact top-level keys format and generators. Each generator is keyed by its
source-named uppercase generator command variable and uses receipt, receipt_sha256, artifact (relative to
the receipt directory), and artifact_sha256, as the existing library-input
interface does. Executables must be regular executable original component
object-tree files under /usr/obj. Receipts must be passed native AMD64 Make
references from the selected source tree and bind the same compiler file/content.
Compiler aliases are matched by file identity. Other execution hosts are not yet
qualified. Compiler, target, path/environment and feature-control variable names
are rejected. MAKE_ names and ordinary source tool names such as JEVENTS are
supported. Overrides must be effective and preserve SDK/target/compiler identity.
Hashes are checked before/after commands. Each tool must appear as a direct
command in completed original metadata recipes. No filemon exec observation is
claimed; wrapper commands are rejected rather than inferred.

The helper now first validates the unchanged recorded SDK through its baseline
libmd component, then applies explicit component options and freezes the selected
component's Make include closure. This supports optional components invalid under
the baseline options without disabling original Make dependency checks.
The original MIT profile remains unchanged; references explicitly select
WITHOUT_MITKRB5. The library and generator interfaces compose independently.

## Evidence (all under /usr/obj/usr/src, 2026-11-04)

- bazel-heimdal-roken-make-r3-20261104 and
  bazel-heimdal-vers-make-r1-20261104: fresh original builds/stages using the
  explicitly hash-bound make-roken from bazel-make-roken-make-r1-20261104.
  Both require and audit locally generated/consumed roken.h. Recipe provenance,
  tool binding, compiler/SDK inputs and installation METALOG are retained.
- bazel-compile-et-reference-native-r1-20261104/original-library-review/review.json:
  all 59 regular roken objects and both regular/PIE vers objects are compared
  against immutable captured native archives. Fifty-nine contexts match raw
  allocated code/data, symbolic relocations and external symbols. Two roken
  objects (resolve and snprintf) have original absolute assertion filenames;
  isolated exact original compiler recipes with -fmacro-prefix-map=/usr/src/=
  match native contracts. Raw originals are unchanged. Commands, input hashes,
  controlled objects, diagnostics and native receipt/manifest bindings are saved.
  This excludes debug-only bytes and does not prove roken PIC/shared link parity.
- bazel-compile-et-generation-native-r2-20261104: actual generation_test executes
  three cases: sparse indices/prefix reset/repeated identical generation, invalid
  table names without outputs, and missing input without outputs. Paths to the
  executable, fixture and runtime DSOs come from Bazel rootpath arguments;
  Python embeds no library sonames. The semantic example independently checks the
  AB table base 16896, indices 0/3/4, reserved messages and initialization call.
- bazel-compile-et-generation-native-r3-20261104: six selected targets pass after
  adding compiler-alias and digest-corruption regressions. Generator provenance
  tests execute six unittest methods; other results may be cached. Passing test
  target counts are not counts of all base-system tests.

The initial original reference attempt rejected Heimdal under default MIT
configuration before constructing a reference output. Another rejected the
compiler alias; neither rejection was treated as a passing reference. Generation
r1 rejected a mistaken test soname; its replacement takes actual Bazel artifact
paths as inputs. Failed roots/logs remain available where created.

## Remaining gates

Add original shared-library input binding for the compile_et Make comparison,
then compare generated C/H output and consumer objects, ordered runtime library
requirements, installation and debug handling. Complete roken shared/static/header
installation. No complete Heimdal profile, world/pkgbase/bootstrap/VM/performance
acceptance is claimed. The root Heimdal gate stays in place. Frontend C/backend
format needs no change for these explicit test/reference inputs; the manual is
updated. Make remains default; BIP is excluded.
