# Native libc TLS helper and program qualification (2026-11-05)

## Implementation

Both original selected TLS programs now build natively alongside their two helper
DSOs and two regular static archives. Source-owned declarations retain small PIC
for shared helper objects, non-PIE regular archive objects, original SONAMEs and
relative library alias, split debug and package ownership. The original disabled
static TLS program remains disabled; this does not claim it was implemented.
No original C program or helper was modified.

The dlopen helper deliberately imports TLS variables and ATF callbacks from its
exporting main program. It does not acquire an artificial framework dependency to
hide those imports. The dynamic program's original link order places its helper
before ATF and pthread. ABI imports and the existing final-consumer link sequence
preserve that order without moving library producer objects into consumers.
Both programs retain original RUNPATH; the dlopen program retains export-dynamic.

The ELF comparison helper retains its default rejection of runtime search paths.
An explicit expected-search-path input permits legitimate original installation
contracts. Candidate and Make must match both exact values and RPATH/RUNPATH tag
semantics; malformed, extra or divergent tags fail. All existing hardening checks
remain enabled. This is comparison policy, not a change to the system loader.
Ten metadata-boundary regression methods pass through Bazel; their mocked
readelf records are unit tests, not ELF qualification artifacts.

## Evidence

All evidence below is under /usr/obj/usr/src:

- bazel-libc-tls-native-r5-20261105: maintained frontend passes both original
  runtime cases, source settings and the ten-method path-contract target. Captures
  all three installation archives and six actual native runtime libraries with
  receipt/manifest/content bindings. Earlier successful executions and later cache
  hits are retained; no claim of all cases freshly rerunning in r5.
- bazel-libc-tls-review-r1-20261105: all twelve non-directory installed records
  match the independently built original Make component inventory, ownership,
  modes, package/debug tags and library symlink. Exact Kyuafile bytes match.
  Two program ELF contracts, two shared-library contracts and two archive member/
  symbol contracts pass. Native and Make split-debug filenames and CRCs pass.
  Expected runtime path is queried from original Make TESTSDIR, not added to a
  checker allowlist. audit.py and review.json retain inputs and captured bindings.
- bazel-libc-installation-make-r1-20261105: original Make libc parent reference
  with its receipt, component.METALOG, stage and objects. This uses the existing
  prepared SDK, not a new independent whole-world toolchain bootstrap.
- bazel-libc-tls-loader-r1-20261105: both original cases freshly pass against the
  six captured native runtime libraries in private directories. ldd resolves
  native dependencies. Own-child ktrace/kdump records successful opens of the
  native linked helper and the native dlopen helper, with no host TLS helper path
  lookup. Retained traces and hashes bind this observation to captured payloads.

The first native attempt failed on an installation target-name collision; payload
entry names were corrected. A second attempt passed runtime but independent
inspection found wrong NEEDED ordering from dynamic_deps. ABI imports and the
existing ordering boundary corrected the actual link; subsequent independent
comparison passes. These failures remain recorded rather than being relabeled.

## Integration and remaining scope

Existing explicit-input targets/tests, format-5 artifact captures and typed
installation providers express this contribution. The maintained build-bsd C
frontend, schema, backend selection, signing and publication rules need no change.
The manual and completion/observability ledgers are updated with this checkpoint.

This proves selected AMD64 leaf construction/installation contracts and two
original native runtime cases. It does not prove raw ELF/debug byte equality,
full installed test traversal, other architectures/configurations, privileged
loader behavior, live DTrace/audit delivery, full-system packaging or performance.
Full-tests parent guards remain. Make stays production/default; BIP stays excluded.
