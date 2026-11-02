# Libutil compile-policy correction (November 2, 2026)

This cohort corrects the existing native libutil compiler policy. It does not
establish full archive, DSO payload, world or rescue installation parity.

## Implementation and normal frontend

`//lib/libutil:objects` now declares the original Make `-pipe`, `-fno-common`,
GNU17 and complete ordered warning policy. The selected normal and PIC recipes
also retain O2, debug compression, strong stack protection and the same defines.
A default-disabled toolchain feature, `bsd_small_pic`, selects `-fpic -DPIC`
only for this library's PIC objects. Unselected callers retain `-fPIC -DPIC`;
regular objects do not acquire PIC flags. Both branches use rules_cc's supported
`feature`, `flag_set` and `with_feature_set` contract.

The changed configuration required a new maintained SDK snapshot and receipt;
no old receipt was rebound. Preparation used the original `libmd-plan.py` and
`libmd-stage-tools.py` workflow. SDK and validation are retained under:

- `/usr/obj/usr/src/bazel-small-pic-sdk-20261102/{workspace,toolchain-inputs.json}`
- Receipt SHA256 `2ccb44aeca9f239b8f7db0964152e415907e7b7ca5decda00147c406ade5d0f9`.
- `bazel-small-pic-sdk-validation-r2-20261102.json`: all 16,755 checks pass.

Only the toolchain configuration has a semantic input/snapshot change; compiler,
sysroot and execution-runtime bytes are unchanged. The plan's old/new output-root
relocation is verified explicitly. The first validation observer rejected those
plan metadata/path changes; its original source is retained beside the corrected
observer. Historical posttar SDK and receipts remain intact.

Existing format-5 profiles, declared features, maintained SDK preparation,
artifact capture and test inventory carry the change. No build-bsd C/backend
option, staging, signing or publication policy changes. The manual documents the
source-owned opt-in and SDK requirement. Make remains production/default; BIP is
excluded. No host installation or tracing activation occurred.

## Accepted checks

The guarded native after-profile used all 16 CPUs, an 18 GiB required start and
16 GiB reserve; no reserve interruption. Both test wrappers executed successfully:
four PIC object-inspection methods and eleven real bounded rescue runtime methods.
The latter adds `head -c 1k`, exercising libutil's `expand_number` through the
actual static rescue executable. The executable is whole-byte identical to the
previously accepted core ELF; no full-rescue claim follows.

The PIC fixture inspects actual ELF symbols from regular/default-PIC/regular-
opt-in/small-PIC compiler outputs: values 0/2/0/1. A separate real compiler control
with an incorrect expected PIC level fails at the intended `#error`. Tests do not
execute target objects or substitute flags after compilation.

Representative unchanged normal/PIE/PIC compile actions for echo, libmd and
crunchide compare exactly across SDKs: all 72 actions have identical argv,
environment, dependency path sets, output/configuration/platform fields and
**action keys**. This is a representative default-action regression, not a full
world cache/performance or bootstrap qualification.

Fresh original Make builds libutil and its disposable installation with supported
`.meta` recipe capture. All 68 normal/PIC native actions match the actual original
warning vectors, code-generation policy, source identities and define values.
All 3,778 original and 3,778 actual native `.d` consumed-file occurrences match by
logical identity and physical digest and are declared actual execution inputs.
Sixty-six raw compiler objects have identical allocated sections and nondebug
relocations. The two login_class objects also match all allocated sections and nondebug
relocations in a separate original Make compile-only control. Its actual recipes
are unchanged except the private object directory; the ordinary full-reference
objects had been mutated in place by Make's later dtrace invocation. The selected
original compiler and declared native compiler have identical SHA256 bytes.

Before/after native DSO allocated sections and nondebug relocations are exact;
only .debug_abbrev, .debug_aranges and .debug_info differ. All 34 native archive
members preserve their order, allocated sections and nondebug relocations. These
strict regression checks isolate the compiler correction from existing provider
composition differences.

Strict maintained shared-library checks pass against fresh Make: SONAME
`libutil.so.10`, ordered NEEDED `[libc.so.7]`, imports/exports and symbol versions,
version definitions/requirements, RELRO, immediate binding and absence of unsafe
search paths/text relocations/executable stack or writable-executable segments.
This metadata check reports physical section differences; it is not full ABI or
runtime-provider proof.

## Explicit remaining gates

The pre-existing native section archive has 34 self-contained members versus
Make's 35 members with a separate provider object, and places `pw_scan.o`
differently. The native and Make archive envelopes and DSO payloads are not byte
identical. Comparing native transformed login_class section-archive members to
Make's separately transformed objects also rejects equality: the native partial
link embeds provider/runtime sections and merges string tables. That rejected
comparison is retained; no normalizer or checker waiver is added.

Full libutil archive order/provider/DOF relocation and final DSO payload parity,
original tests/installed-library execution, all options/architectures and full
world/bootstrap remain explicit work. The rescue result still covers only real
cat/echo/head, not the complete selected application set, installation, pkgbase,
hardware, combined publication or boot/upgrade qualification.

## Retained evidence

All paths below are under `/usr/obj/usr/src/`:

- `bazel-libutil-policy-make-reference-r1-20261102` (fresh original component).
- `bazel-libutil-policy-native-{before,after}-qualification-r1-20261102`.
- `bazel-libutil-policy-action-collection-{before,after}-r1-20261102`.
- `bazel-libutil-policy-default-actions-{before,after}-20261102`.
- `bazel-libutil-small-pic-negative-qualification-r1-20261102` (expected failure).
- `bazel-libutil-login-class-make-compile-control-r1-20261102` (two raw objects).
- `bazel-libutil-policy-review-r1-20261102` (hash-bound compiler outputs,
  all consumed input records, objects, archive orders and strict shared report).
- `bazel-libutil-policy-review-drivers-20261102/manifest.json` (15 exact
  preparation/observer sources, including rejected original attempts).

Original upstream compact-log converter streams are fully drained and all 189
converter input bindings verified before/after. Records retain runner/cache-hit
fields: cached results are not invented fresh compiler executions. The before
profile reused compiler outputs; the after log contains 106 actual CppCompile
records across target/exec configurations and PIC fixtures. No unmeasured caching
cause or whole-system performance claim is made.

Observer-only rejected attempts are retained: the first object inspector omitted
its struct import; the initial library inspector incorrectly compared a native
self-contained partial-link result with a separate Make object. The corrected
report records that mismatch rather than accepting it. No production artifact
or maintained checker was rewritten to make these comparisons pass.

During review, upstream merge `1f09beabf46` changed 68 HyperTrace/kernel/bhyve
paths. A separate post-merge validation preserves the original records and
rechecks all 16,755 SDK bindings plus 265 distinct actual libutil consumed-file
and Make-environment bindings: zero mismatches. This does not promote historical
kernel or bhyve artifacts to the new source revision. The reports are
`bazel-libutil-policy-postmerge-sdk-validation-20261102.json` and
`bazel-libutil-policy-review-r1-20261102/postmerge-input-review.json`.
