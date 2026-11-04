# SDK refresh and bounded verification (2026-11-04)

## Current-input archive qualification

The HyperTrace merge advanced dev to `a914137016e` while the EFI libsa work was
being qualified. An ARM64 repeat correctly refused the changed recorded native
SDK origin `amd64.amd64/tmp/usr/include/sys/hypertrace.h`; the failed build-run
record remains `build-runs/20261104T002510Z-12791`. No old receipt, origin file or
SDK was edited to make this repeat pass.

Maintained `libmd-plan.py --sdk-only` and `libmd-stage-tools.py` prepared new SDKs:

- Native: `bazel-userland-native-sdk-r6-20261104`.
- ARM64: `bazel-libsa-aarch64-sdk-r1-20261104`.
- RISC-V: `bazel-libsa-riscv64-sdk-r1-20261104`.

All paths here are under `/usr/obj/usr/src`. Preparation commands, configuration,
logs and the orchestration source are retained in
`bazel-libsa-sdk-refresh-r1-20261104`. Its `native-sdk-delta.json` binds both native
SDK receipts and actual changed bytes: only the HyperTrace and VMM memory headers
changed in the snapshot; tool/runtime bytes remained identical. Existing SDKs and
their transitive recorded origins remain necessary retained evidence.

The three `bazel-libsa-efi-<arch>-current-r1-20261104` frontend runs passed. Each
has `archive-preservation-review.json` binding its regular and private archives
to the previously qualified captures. All six full archive byte hashes agree,
including after the shared flag factoring. The native run also passed the 35
existing verifier-header checks. This closes the selected current-input repeat
and output-preservation gate; it does not establish complete loader boot,
installation/debug parity, pkgbase or system-wide acceptance.

## Full-content verification with bounded concurrency

The maintained format-5 source backend now verifies all SDK origins, execution
host bindings, original snapshot entries and cached-copy entries with
`sdk_digests.verify`. The existing `--jobs` controls the maximum hash workers.
Submitted batches contain at most twice that many files; open/read concurrency
is bounded by the worker count. Every successful entry is hashed in full on
every invocation. There is no mtime/inode cache or reuse of a previous digest.
Checks retain their manifest order and error prefixes. Unsafe relative snapshot
names are rejected before reads. Cached inventory, offline cache and other
frontend checks remain in place.

`sdk-verification.json` records phase file counts, logical byte counts, workers
and elapsed hashing time. Alias entries are counted separately. These are bytes
hashed, not physical disk I/O, and the timings exclude other preparation work.
The final frontend receipt binds the report hash and phase records. The helper
itself is included in the before/after qualification implementation bindings.
No new frontend C switch or input-format field was needed.

The RISC-V current run exercised the first parallel implementation. It verified
13,551 origin entries, 41 execution-host entries and 16,055 entries in each
snapshot, using 16 workers. Its four hashing phases took approximately 33.7
seconds in that run. The host had other build activity; this is not a controlled
serial/parallel or Make/Bazel performance comparison. That run predates the
added report binding; its exact helper sources are retained in
`recorded-helper-sources`. The final receipt-binding implementation is exercised
by `bazel-sdk-verification-tests-r1-20261104`.

Native Bazel executed 43 methods in that final test run:

- `//tools/build/bazel:sdk_digests_test`: 8 methods, including same-size and
  same-mtime corruption, rereads after a successful verification, missing files,
  unsafe paths, complete serial/parallel reads and actual bounded concurrency.
- `//tools/build/bazel:source_settings_test`: 18 maintained methods.
- `//tools/build/bazel:source_test_inventory_test`: 17 maintained methods.

Both maintained source-graph tests now explicitly declare their sdk_copy and
sdk_digests imports. The result's `verification-review.json` checks the report
hash, all phase inventory counts against the SDK receipt, and test method counts.

The final frontend also refuses the real stale native SDK before invoking Bazel
or creating qualification output. `bazel-sdk-verification-negative-r2-20261104`
retains the exact changed-header diagnostic, exit status, command and helper/input
hashes. The first diagnostic review expected the message on stderr; build-bsd
emits backend diagnostics on stdout. Its records are retained and the corrected
review checks both streams without changing the rejection expectation.

## Compiler-input performance issue remains open

`bazel-libsa-efi-amd64-current-r1-20261104/sdk-invalidation-review.json` binds actual
compiler actions to the native SDK delta: all 191 regular and 260 private
compilations reran, and both changed SDK headers appear in every compiler input
set. Final archives remained byte-identical. This confirms coarse invalidation;
it is not a warm-cache pass or an end-to-end performance result.

The SDK generator currently includes the entire system-header tree in
`compile_inputs`, even for these `-nostdinc` freestanding sources. Bazel treats
compiler files as mandatory inputs in its ordinary dependency-file compilation
path; see the pinned [Bazel 9.3.1 compiler action builder](https://github.com/bazelbuild/bazel/blob/9.3.1/src/main/java/com/google/devtools/build/lib/rules/cpp/CppCompileActionBuilder.java).

Follow-up must qualify a smaller freestanding compiler input context through
normal platform/toolchain selection, preserving ordinary hosted headers and
source-built execution tools. Measure its benefit and complexity before changing
the shared toolchain contract. Preserve real dependency-file discovery and all
input checks. SDK materialization/verification cost, broad link inputs, bootstrap
closure and CPU/memory/physical-disk-I/O/storage comparisons remain required.
Parallel hashing does not close those gates.

Next construction work is actual loader entry sources and final EFI links.
Complete world/rescue/cross kernels/modules, runtime/boot, installation/debug,
bootstrap/sandbox/cache and package/hardware/combined repository qualification
remain open. Make stays production/default; BIP remains excluded. No VM, host
installation, upgrade or reboot occurred.
