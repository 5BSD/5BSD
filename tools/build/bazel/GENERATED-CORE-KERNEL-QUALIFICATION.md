# Generated kernel core qualification

## Implementation (2026-11-02)

The five config/env/hints/vnode/vers built-ins now use the maintained amd64
kernel-object macro for warnings, definitions, debug information and selected CTF
conversion. Original generators and public object labels remain. CTF-off now
forwards raw objects rather than unconditionally converting them. The ordinary
kernel helper also supplies the necessary vnode header dependency; an initial
duplicate declaration was removed after analysis correctly rejected it.

Clock calibration now uses the actual Make common-then-Werror warning policy and
selects its O3 override only in optimized builds, leaving debug O0 intact. Make's
custom recipe permits default compiler headers; native keeps nostdinc and reuses
bsd_sdk_headers for explicit selected-SDK resources and ssp/ssp.h availability.
No compiler version or host header path is embedded in production declarations.
Source C/assembly is unchanged. Only sys/kern/BUILD.bazel changes implementation.

This uses the exercised build-bsd format-5 kernel target/settings/SDK and immutable
capture API. No frontend C, manual/CLI option, SDK-export schema, security policy,
staging/signing/verification or publication change is required. Make remains
production/default; BIP remains excluded.

## A rejected successful build

bazel-kernel-generated-core-amd64-ctf-r1-20261102 exited successfully, yet all five
generated objects lacked both debug_info and SUNW_ctf while Make's objects had
both. The independent output check rejected it. ctfconvert reported missing type
data without returning failure; its established assembly/no-type behavior means
exit status alone cannot prove a typed C object's CTF coverage. The repair routes
these objects through the shared typed policy. The retained initial report and
section listings show the actual failure; no receipt or payload was rewritten.

The second profile rejected the duplicate vnode dependency. The third profile
passed with actual debug and CTF sections, but prerequisite review found clock's
missing SSP-header availability despite equal code. The fourth profile adds that
explicit input and is the final qualified cohort. Earlier runs remain preserved.

## Independent references and retained checks

Paths below are under /usr/obj/usr/src.

- bazel-kernel-generated-core-amd64-ctf-r4-20261102 passes the maintained frontend
  eleven-target build-only profile with 16 jobs and disk monitoring. Its captures
  include six objects and five original generated sources; tests=[] runs no
  runtime tests.
- bazel-kernel-generated-core-review-r2-20261102 retains final declarations,
  source/compiler/action/input/ELF/CTF/relocation reports and implementations.
  The earlier review-r1 directory retains the initial failures/provisional checks.
- env.c, hints.c and vnode_if.c equal the freshly built ordinary Make reference.
  Native config explicitly reapplies declared NFS_ROOT/ZSTDIO settings, moving
  those option lines within embedded configuration text. Replaying the original
  Make config tool with the actual execution-hash-bound override input produces
  byte-identical config.c. The ordinary unoverridden Make reference remains intact;
  no option text, string or symbol was normalized away.
- Version rendering uses identical explicitly declared source revision, compiler
  banner and parser-derived GENERIC identity through the maintained newvers.sh -e
  interface. Its generated C is byte-identical to an independent original-shell
  rendering. The ordinary timestamp/user/host/counter-bearing Make version remains
  untouched. Config/version reference objects use the original Make compiler,
  queried NORMAL_C policy and CTF converter. Their independent compiler -M queries
  provide prerequisites; initial observer assumptions about emitted depfiles are
  retained separately, with no reference object rewritten to fix the observer.
- All six .text and SUNW_ctf payloads and runtime sections are byte-identical to
  the appropriate Make-policy references. The unmodified maintained CTF graph
  comparator agrees for all six. All 5,091 non-debug relocations have identical
  sites, kinds, addends and referenced symbol identities, with no filename/address
  normalization. Full DWARF and symbol/string-table equality is not claimed.
- Actual configured argv matches the selected actual compiler records. Checks bind
  309 physical and 19 generated prerequisite occurrences, plus Make's external
  SSP-header query to identical SDK and actual native input bytes. Source capture
  labels/paths/digests bind directly to compiler inputs; the explicit version
  renderer action binds current script/parameter/copyright/revision/output inputs.
  Clock's declared SDK resource search precedes selected SDK system headers, with
  default host include lookup disabled. This is an explicit search-policy difference.
- Four compiler records are retained from the successful third profile; version
  and clock compiler records are from the fourth. Clock's unchanged CTF result
  binds the original first-profile converter record to current raw compiler/output
  hashes. Other converters bind their matching third/fourth records. Missing
  fresh-spawn records are not presented as executions. The initial observer's
  too-short clock cache history is retained with its corrected explicit provenance.
- Configuration analysis checks optimized/debug CTF-on and two CTF-off debug
  combinations: six compiler actions in each, six converters when enabled and
  zero when disabled; debug clock has O0 without O3. All 2,290 other known groups
  retain configured compiler argv/output paths. This does not establish unchanged
  action inputs/keys or actual debug/CTF-off execution.
- A bounded source-bound scan records 333 call-shaped markers in generated vnode
  code and two timestamp enter/exit markers in clock calibration. Original source
  equality and machine code preserve these hooks; the scan is not live tracing,
  audit completeness or proof of absent shared instrumentation.

## Coverage and remaining gates

Query r47 passes for 2,296 groups and 2,471 compiler actions. Reconciliation r40
accounts for all 2,462 currently selected amd64 Make link products: 2,392 source
inventory identities, nine recipe identities, two special producer artifacts,
five generated-policy artifacts, one clock recipe/artifact and 53 generated-name
matches. The latter have separate 49-KOBJ/four-RPC artifact proofs. No missing or
weak object-name-only identities remain in this configured audit. Older cohort
proofs retain their original source/config context; this is not a fresh execution
or artifact comparison of every selected object after the HyperTrace merge.

Complete native kernel aggregation, exact link order, post-processing/install,
modules/drivers, alternate KERNCONF/features, ARM64/RISC-V64, complete world and
pkgbase/hardware publication, reproducible bootstrap, actual sandbox/VM/runtime
and controlled CPU/memory/disk I/O/use comparisons remain open. The complete
kernel qualification must continue checking actual per-object debug/CTF contracts,
not promote a successful frontend status to a CTF guarantee. No host installation,
upgrade or reboot occurred.
