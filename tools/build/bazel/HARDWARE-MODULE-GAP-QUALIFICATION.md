# AMD ECC injection and watchdog module qualification (2026-11-02)

## Native owners and original policy

The source owners now compile ecc_inject.c and amdsbwd.c through the maintained
amd64 module compiler/CTF pipeline. Their module owners declare the original
empty export list (EXPORT_SYMS=NO), native link/export processing, separate
optional debug files and original installation metadata. The watchdog consumes
its real GENERIC opt_amdsbwd.h producer and existing ISA interface producer;
only the new consumer is added to that interface's visibility. Physical headers
reuse existing providers. No production C code changes or Make-built output
inputs are used by the native graph.

The normal format-5 build-bsd targets/build-settings handle both profiles;
no frontend C/schema, signing, staging backend or manual option changes are
needed. The backend module owner changes and this qualification are committed
together. Make remains production/default; BIP remains excluded.

## Qualified comparisons

Two profiles pass for both modules:

- Plain: complete module files are byte-identical to the matching Make modules.
- CTF/debug: every runtime section payload/metadata matches except GNU build
  identity and debuglink bytes. CTF is exact; native and Make debug pairs each
  pass the maintained module/debuglink checks. Complete DWARF identity is not
  required. Ownership and modes are unchanged, with one plain and two CTF/debug
  installation file records per module matching original Make METALOGs.

Two actual compiler executions bind the source identity, compiler binary,
defines and code-generation policy to original Make recipes. All 200 Make
.depend occurrences are checked against native input digests. Physical source
inputs match exactly. Original KOBJ interface headers differ only in their
single generated source-path comment (absolute schema path versus basename);
both original headers are retained, exact single-comment substitution is
checked, and every other byte must match. No artifact or compiled input is
rewritten by the observer. Make .depend/meta is not a complete dynamic-input
inventory; filemon was disabled.

The final corrected CTF pipeline's section contracts and debug files bind to
the original actual compiler audit. The ECC runtime container layout changes
when the original export transform is enabled, while every named section's
bytes/metadata remains exact; the binding receipt reports this whole-file
difference explicitly. Final comparisons use the corrected export pipeline.

## Corrections and retained failures

The initial declarations incorrectly selected export_all. Original Make's
EXPORT_SYMS=NO requires localization through the default empty list. These
static drivers hid that policy mistake in payload comparisons; the declarations
were corrected before acceptance.

The first plain Make controls explicitly defined DEBUG_FLAGS as empty. Make
uses definedness to select stripping, so those files differ from ordinary
DEBUG_FLAGS-unset output in file symbols and relocation indexing. They remain
retained as that configuration's evidence. Fresh r2 controls leave the variable
genuinely unset, matching the native disabled setting and original Make strip
recipe. No ELF comparator was relaxed to accept the plain mismatch. Arbitrary
user-supplied DEBUG_FLAGS strings are not qualified here.

The existing SDK receipt then rejected a changed /usr/bin/bsdtar digest before
starting another build. Maintained plan/stage helpers prepared a fresh SDK;
old receipts were preserved. Besides generated-plan path identities, bsdtar is
the only changed SDK input. Both module profiles and the registered real package
directory test pass with the fresh SDK. No historical receipt was rebound.

## Evidence under /usr/obj/usr/src

- bazel-next-module-source-facts-r1-20261102: original Make-selected source,
  export and compiler facts for eleven pending module leaves, with parent exports.
- bazel-next-module-make-references-r1-20261102: earlier 22 controls, including
  the explicitly defined-empty plain debug configuration.
- bazel-next-module-make-references-r2-20261102: 22 successful original Make
  controls for eleven modules in ordinary plain and CTF/debug profiles. Only
  these two modules have native qualification in this cohort.
- bazel-hardware-module-gap-review-r1-20261102: actual compiler records,
  200 input checks and retained KOBJ comment differences.
- bazel-posttar-sdk-preparation-20261102 and bazel-posttar-sdk-20261102: new
  maintained SDK preparation and exact input differences.
- bazel-hardware-module-gap-{ctf-debug,plain}-native-r2-20261102: final normal
  frontend builds, original logs and immutable captures using the fresh SDK.
- bazel-hardware-module-gap-review-r3-20261102: final four Make comparisons,
  six matching installation records, debug checks and explicit prior-audit bindings.
- bazel-posttar-package-directories-native-r1-20261102: affected real-tool
  package-directory Bazel regression passes after the SDK refresh.

Original Make compilation used sixteen jobs globally, with isolated object and
installation stages and a disk reserve guard. Native runs used sixteen jobs
and the same guard. Module loading, ECC injection, watchdog arming, hardware
operation, other configurations/architectures, full kernel package closure,
publication, VM behavior and controlled performance are not qualified here.
No host installation, upgrade or reboot occurred.
