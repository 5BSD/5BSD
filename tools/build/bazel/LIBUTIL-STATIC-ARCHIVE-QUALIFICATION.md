# libutil default traced static archive (November 2, 2026)

**Historical checkpoint:** the later [static-consumer qualification](LIBUTIL-STATIC-CONSUMER-QUALIFICATION.md)
corrects original missing-provider and native over-extraction behavior. Its
retained anchor supersedes the unanchored policy below; the original evidence
and its source scope remain preserved.

## Scope and source correction

The independent original Make build produces 34 ordinary members followed by
`logincap_provider.o`, with `pw_scan.o` before `pw_util.o`. The old native
`static_archive` selected `pw_scan` last among C members and added a synthetic
`__bsd_dof_anchor_logincap_provider` symbol to the separate provider. The actual
old archive fails the new order check; an order-only in-memory permutation still
fails the anchor check. Neither old artifact was rewritten.

The source-owned `//lib/libutil:static_archive` now uses the existing unanchored
native DTrace specification, a separate provider and explicit original member
order. Native filenames retain the conventional `.nopic.o` suffix. The strict
existing component archive rule checks every unique selected object exactly
once. Compiler policy, ordinary `:util` CcInfo and shared-library selection are
unchanged. The experimental section-associated composition remains a distinct
opt-in mode, and the untraced archive has not gained an original-order claim.

## Independent reference and actual inputs

The maintained `install-reference.py --make-meta` command built and privately
staged the original component with 16 jobs and supported nofilemon metadata.
It did not execute its tests or install host files. The actual original
`libutil.a.meta` ar recipe and archive both contain the same 35-member order.
All 90 unchanged source-snapshot hashes were rechecked. Only the Make-unread
BUILD file differs from that original snapshot; new native test/fixture files
were added afterward. The original receipt remains immutable.

The actual uncached native DTrace and archive actions bind all 35 member hashes.
The expanded ar response file preserves their exact original order. Its 34 raw
compiler inputs match the earlier actual normal-object records and independent
original compiler-policy audit by digest; they are cached inputs in this run,
not invented fresh compiler spawns. Fresh original normal recipes match the
previously reviewed recipes after only substituting the two explicitly bound
reference object-directory paths; all 1,889 consumed prerequisites match the
actual cached native compiler input digests. All 34 rewritten C members match every
allocated section of the independent original archive members. All 35 members
match their nondebug relocation-section contents.

The provider's sole allocated difference is `.SUNW_dof`. All nine original and
native DOF section descriptors/payloads agree after independently verifying the
actual FNV path-key aliases, resolving their string offsets/lengths and checking
eight-byte padding and final nonloadable extents arithmetically. The unchanged
maintained ET_REL inventory verifies the logincap `setusercontext` schema,
argument mapping, actual object relocation/function and NOP site at offset 560.
No general symbol-name waiver, object rewriting or unresolved-zero equivalence
is used. Native/Make archive envelope, member filenames, DWARF and path-derived
provider bytes therefore are not claimed whole-file identical.

## Tests and unchanged outputs

`//lib/libutil:static_archive_contract_test` executes eight unittest methods:
actual original member contract plus order, duplicate, suffix collision,
missing/embedded DOF, wrong architecture and truncated archive negatives.
Its independent fixture binds the original Make/provider source hashes. The
same test reader passes the independently produced original archive. One Bazel
XML wrapper case represents these eight methods.

The default native profile passes both declared tests (eight archive methods
and the retained 43-method rescue integration log). Default libutil DSO and
rescue ELF are whole-byte identical to the pre-change captures. The explicit
experimental profile passes its applicable rescue test, and its archive and
DSO are whole-byte identical to the prior accepted compiler-policy captures.
The first experimental request deliberately incompatible with the default-only
contract test is retained as a rejected explicit-target request; the corrected
profile requests only applicable targets. No passing exclusion is claimed.
The archive test is a fresh execution; the 43-method rescue test is a cached
accepted result in all three passing profiles. Cached artifact records remain
distinguished from new executions.

## Maintained workflow and remaining gates

Existing build-bsd format-5 targets/tests, selected SDK receipt, compact execution
logs and artifact capture carry this change; no CLI, helper, toolchain,
publication or signing policy changed. The manual documents the target's scope.
Make remains production/default. No host installation or probe registration ran.

**Remaining:** default `:util` CcInfo still uses its existing anchored provider;
independent static-consumer extraction/link semantics are a separate next gate.
Full original DSO payload/debug/installation/tests, untraced and other option/
architecture archive parity, experimental whole-library parity, full rescue,
packages, hardware, runtime probe events and performance remain open.

## Retained evidence

All roots below are under `/usr/obj/usr/src/`:

- `bazel-libutil-archive-make-reference-r1-20261102`: fresh original build,
  object recipes/dependencies, private stage/METALOG and immutable receipt.
- `bazel-libutil-archive-baseline-qualification-r1-20261102` and corresponding
  `baseline-action-collection-r1`: old native archive/DSO/rescue, actual actions.
- `bazel-libutil-archive-native-qualification-r1-20261102` and corresponding
  `native-action-collection-r1`: default accepted captures and producer actions.
- `bazel-libutil-archive-section-qualification-r1-20261102`: explicit
  incompatible-target rejection; `section-qualification-r2` and
  `section-action-collection-r2`: accepted experimental regression.
- `bazel-libutil-archive-review-r1-20261102`: member/actual producer/order,
  raw compiler and unchanged artifact/source bindings, negative controls,
  reviewed drivers and final qualification hash manifest.
- `bazel-libutil-archive-full-dof-review-r1-20261102`: original/native full
  inventories, exact accounted section pair and verified path-key/site report.
