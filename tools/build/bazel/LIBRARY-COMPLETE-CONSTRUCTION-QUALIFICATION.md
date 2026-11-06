# Selected complete lib hierarchy construction

## Passed construction (2026-11-06)

The maintained build-bsd bazel-test frontend passed the complete selected AMD64
lib hierarchy request: 164 installation child parents, 36 build-only outputs and
the source-settings helper. All 201 requested labels appear in the captured
manifest with no incompatible targets. The receipt binds 683 unique captured
files totaling 2,142,741,312 bytes. The request is derived from the source-owned
root composition and recorded configured selection, including lib/tests; no
selected children are omitted. This is the selected lib/ hierarchy, not all
base libraries outside lib/, all configuration variants or a whole-world build.

Evidence under /usr/obj/usr/src:

- bazel-library-complete-request-r1-20261106: explicit format-5 inputs and selection.
- bazel-library-complete-native-r1-20261106/receipt.json: passed native frontend.
- bazel-library-complete-native-r1-20261106/artifacts/manifest.json:
  f6cbbdab558d24445d19aaa486fcdc59762077167e2df249992617e7dd517e4a.

The only test target in this construction was source_settings_test, whose 28
helper unit methods are reported as one Bazel wrapper case. No original library
program bodies execute in this run. Successful construction and capture do not
establish independent installation or binary equivalence. The public tests-enabled
library aggregate remains guarded; the explicit selected child request does not
qualify or unguard that aggregate.

## Maintained regression validation also passed

The subsequent normal frontend run
bazel-reference-tool-variables-native-r1-20261106 passes all four requested Bazel
test targets. The hash-bound captured logs establish these actual method counts:

| Target | Unit methods |
| --- | ---: |
| source_settings_test | 28 |
| install_reference_generators_test | 8 |
| install_reference_options_test | 20 |
| dtrace_relocatable_inventory_test | 30 |

That is 86 unit methods, reported as four Bazel wrapper cases, with no original
library bodies. The captured test-report manifest SHA-256 is
 d695d721b52ffc2281846b58d60b80482844242798ee38f041f0d5c8391b013f.
This closes the pending maintained regression gates for the source-named generator
interface and multi-object DTrace inspector. The original JEVENTS tool control and
actual four-archive DOF checks remain separate evidence.

## Still active and required

The independent full original Make control
bazel-library-complete-make-r2-20261106 has now passed, including the actual
original JEVENTS recipe check. The complete comparison found recorded installation
gaps; see LIBRARY-COMPLETE-INSTALLATION-GAPS.md and
bazel-library-complete-review-r2-20261106. All six original no-DTrace controls in
bazel-library-no-dtrace-make-controls-r1-20261106 also pass. No full comparison
success is claimed.

Known binary gaps remain as documented in LIBRARY-BINARY-COMPARISON-GAPS.md:
installed test linkage, original build-tree runtime paths, archive source ordering,
extra and ordered dynamic dependencies. Prepared source corrections have not been
applied while the original Make source identity is bound. DTrace metadata validation
does not close raw symbol equality or static-consumer/live-tracing behavior.

Full original library bodies, independent ELF/archive/DWARF/debugger review, full
world/kernel/modules/pkgbase, normal-service VM boot, ARM64/RISC-V, bootstrap,
cache/sandbox/reproducibility, controlled CPU/RAM/disk-I/O/footprint and verified
combined publication remain open. These concurrent builds are not controlled
performance comparisons. Make remains default and BIP is excluded.

Existing format-5 inputs, maintained frontend/backend and immutable capture APIs
suffice for these qualifications; no new C/frontend/security/signing/manual
option is introduced by this construction request. No host installation or reboot
was performed.
