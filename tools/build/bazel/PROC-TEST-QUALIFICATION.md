# Original AMD64 libproc tests (2026-11-06)

## Complete selected construction

The original proc_test and both target_prog/target_prog_static helpers build
through native rules and typed installation. A fresh original Make test-component
control builds/stages with sixteen jobs and recipe metadata. All seven installed
records, directory ownership/modes/tags and exact Kyuafile bytes match. The test
and dynamic helper ELF contracts match; the static helper retains fixed EXEC
linkage with no interpreter/dynamic dependencies and passes the explicit static
contract. Native and original split-debug filenames/CRCs and DWARF presence
verify. Raw ELF/DWARF equality and actual debugger source lookup are not claimed.
Original source files and Makefiles are unchanged.

Both helpers retain original per-source -O0. The static helper removes PIE
compilation/link policy and uses fully_static_link, native libc static objects and
native library CcInfo providers. These carry original direct elf/proc/rtld_db/
util/thread dependencies and transitive procstat/cxxrt/kvm/z implementation archives
rather than depending on bare static-archive imports that hide library link edges.
The initial successful construction used bare imports; review refined the graph
before runtime qualification. Both captures and independent comparison reports
remain retained. No SDK fallback libraries or missing-symbol stubs are added.

Original STRIP= is retained for all three installation outputs using the maintained
strip_symbols=False option. Every native and original runtime ELF retains ordinary
symbol tables. Both native and original helpers retain main, foo/_foo weak aliases,
bar/baz local/strong aliases and qux/$qux strong aliases, including original type,
binding, visibility and size contracts and equal addresses within each alias pair.
Absolute symbol addresses are not compared across different final layouts.

## Actual original case execution

Actual native and original Make -l listings match all ten case registrations,
with the original implicit 300-second deadline and no required-user or cleanup
metadata. All ten execute and pass with no skips/expected failures:

- dynamic/static mapping and symbol lookup;
- executable-name aliases and prefixes;
- symbol-lookup failure handling;
- breakpoint placement/verification and continuation;
- signal forwarding;
- local, prefix and underscore symbol ordering.

The native ATF runner uses the actual installation-form proc_test and both
installation-form helper fixtures, retaining symbols and the static contract.
The explicit native libc/libsys/ATF/elf/proc/rtld_db/util/thread/cxxrt/procstat/z/
kvm/nv/unwinder runtime closure is declared. Tests create/debug only their own
children and are external/no-remote because they exercise host process-debug
policy, kernel tracing and the host loader. This is not a hermetic runtime,
normal-system VM boot or cross-kernel/other-ABI proof. A separate source-settings
helper is a valid cached result: eleven passing targets/reported cases total,
not eleven original libproc cases.

Configured action review verifies both registered regular/PIC variants for all
three source consumers, effective helper -O0/test -O2, static versus PIE flags,
and native transitive static archives. These are six registered compile actions,
not six newly executed compiles or mutation/cache invalidation evidence.

## Retained evidence

Under /usr/obj/usr/src:

- bazel-proc-tests-request-r{1,2}-20261106/inputs.json: explicit construction and
  full ten-case runtime requests through maintained build-bsd format 5.
- bazel-proc-tests-native-r1-20261106/receipt.json: first successful construction.
- bazel-proc-tests-native-r2-20261106/receipt.json: transitive native static-link
  provider refinement; completed archive/metadata/directory and DSO capture.
- bazel-proc-tests-make-r1-20261106/receipt.json: independent original Make control.
- bazel-proc-tests-review-r{1,2}-20261106/review.json: first and refined captures'
  complete seven-record and three-program ELF/debug/Kyua/directory comparisons.
- bazel-proc-tests-case-inventory-r1-20261106/review.json: actual original/native
  ten-case metadata listings with explicitly captured native runtime libraries.
- bazel-proc-tests-native-r3-20261106/receipt.json: all ten original cases execute
  and pass; source-settings is a separate valid cached helper result.
- bazel-proc-tests-actions-review-r1-20261106/review.json: effective source/
  optimization/static flag and native direct/transitive archive review.
- bazel-proc-tests-final-review-r1-20261106/review.json: final compared artifact
  bindings remain unchanged; all case log/XML hashes/outcomes verify; original
  and native dynamic/static helper symbol-alias contracts compare.

Each review retains its audit script and input hashes. Historical proof resolves
immutable captures rather than relying solely on mutable bazel-bin paths.

## Frontend and remaining gates

Existing build-bsd format-5 inputs already carry these targets, configuration,
fixtures and tests. No frontend C/schema, stage/signing or publication-policy
change is required; the maintained manual, roadmap and observability ledger are
updated together. Remaining base test parents, full tests-enabled world,
whole-world/kernel/module/debug/pkgbase acceptance, archive order/debugger/
bootstrap/cache/sandbox/reproducibility, normal-service VM boots, CPU/RAM/disk-I/O/
footprint and hardware/combined publication remain open. Other ABIs, CTF-enabled
and other feature profiles are not qualified by this CTF-disabled AMD64 cohort.
Make remains production/default; BIP excluded. No VM launch, host installation,
upgrade, reboot, module load or other-process debugging occurs.
