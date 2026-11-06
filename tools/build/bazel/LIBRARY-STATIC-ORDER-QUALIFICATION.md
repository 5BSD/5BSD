# Original static archive source order for six libraries

## Correction (2026-11-06)

libfidl, liblogcmp, libnetworkcmp, libnotify, libtimecmp and libtracecmp now declare
their installed static archive member order using the existing component archive
rule. Compilation groups and generated bindings remain independent; their group
concatenation must not move the original internal C member or place a DTrace
provider ahead of generated sources. The source-owned BUILD declarations preserve
the original order in normal traced and untraced modes. The existing section-
archive prototype also receives an explicit source order without a separate
provider member.

The rule requires every selected object exactly once, with unique names. Missing,
extra or duplicate selections fail analysis instead of silently omitting sources.
Native cc_common/toolchain archiving owns the output; no archive extraction,
recomposition, Make invocation or host discovery is added to production actions.
No C/C++/provider source, source compiler flags, shared-library dependencies or
installed test linkage is changed by this correction.

## Qualification

Normal maintained build-bsd format-5 runs pass all six complete installation
parents with DTrace enabled, disabled and the existing section-archive prototype.
Only the source-settings helper executes during these construction runs; original
bodies and live probes do not run. The prototype result establishes construction
only, not equivalence to ordinary Make's provider representation or runtime safety.

Twelve actual installed archive comparisons pass against independent original
Make controls, one per component per normal DTrace mode:

- Original member identity and order match in all twelve comparisons.
- With DTrace disabled, every member's full symbol name/type set matches exactly.
- With DTrace enabled, all ordinary member symbols match. Raw generated DTrace
  alias differences remain recorded. Every changed alias is bound to an actual
  companion object function; the existing inspector validates real relocations,
  function ranges and patched sites independently on both sides.
- The six traced archives have 55 matching probe schemas and 79 ordinary patched
  sites, with zero enabled sites. No alias rewriting or symbol suppression is used.

| Library | Traced members | Probe schemas | Ordinary sites |
| --- | ---: | ---: | ---: |
| libfidl | 21 | 19 | 26 |
| liblogcmp | 6 | 12 | 18 |
| libnetworkcmp | 7 | 9 | 13 |
| libnotify | 7 | 5 | 9 |
| libtimecmp | 6 | 6 | 8 |
| libtracecmp | 6 | 4 | 5 |

## Evidence and remaining gates

All paths below are under /usr/obj/usr/src:

- bazel-library-static-order-builds-r1-20261106: sequential normal frontend driver,
  logs and passed terminal results for all three explicit feature modes.
- bazel-library-static-order-{trace,no-trace,section-trace}-request-r1-20261106:
  declared SDK, flags, selected complete parents and source-owned root bindings.
- bazel-library-static-order-{trace,no-trace,section-trace}-native-r1-20261106:
  immutable artifacts and completed frontend receipts.
- bazel-library-no-dtrace-make-controls-r1-20261106: six independent original
  no-DTrace controls. Existing bazel-directory-<component>-make-r1-20261106 controls
  supply original traced artifacts.
- bazel-library-static-order-review-r1-20261106: all twelve comparisons, actual
  native/original members, complete DOF inventories, unchanged raw symbol
  differences and before/after verified input hashes.

Raw traced archive/symbol byte equality, full code/DWARF/debugger parity, static
consumer extraction, live registration/firing, original test bodies and whole-
system/runtime/performance acceptance remain separate. The known installed test
linkage, dependency and full-library generation/directory gaps remain open.
Neither the full-tests guards nor Make production/default are changed.

Existing frontend configuration/capture, signing and staging contracts suffice;
C/frontend/backend option changes are unnecessary. The manual documents this
bounded qualification and the existing flags. BIP remains excluded.
