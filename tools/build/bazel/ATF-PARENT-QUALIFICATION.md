# Complete original AMD64 ATF parent (2026-11-06)

## Source-owned traversal and both original profiles

The complete native parent preserves libatf-c, libatf-c++ and original tests/
test-programs traversal. Tests enabled selects eight installation archives,
173 non-directory records and all original C/C++/shell fixtures. Tests disabled
selects only two production library archives and 89 records, with no /usr/tests
payload. Both profiles match separately built sixteen-job original Make parents.
The lib root selects the complete ATF label; its wider full-tests guard remains
until all other library contributions are reconciled. Make stays default.

All selected file/link metadata, modes/owners/groups and package tags match.
Recorded directory path and package-tag claim sets match exactly, including
shared debug ancestors. Manual aliases retain original hardlink inode identities
and tar link targets. Every non-ELF/non-static-archive payload matches exact
bytes, including headers, compressed manuals, all source fixtures and Kyuafiles.
Thirty-six positive-profile and two production-only ELF/split-debug contracts
match independent Make: 34 programs/helpers and two DSOs, plus the same two DSOs
in the disabled profile. This does not establish raw static-archive/DWARF identity
or debugger source lookup; those remain broader qualification gates.

The two nested C/C++ helper programs preserve original WARNS=6, C GNU17/C++
GNU++17 and explicit native ABI library order. They retain no private RPATH.
Original implementations, Makefiles and test bodies are unchanged.

## Exact scripts and original registration policy

The maintained script rule now accepts either its existing single body or a
nonempty ordered list of original fragments, and rejects both/neither forms.
Both use the same declared SDK cat/redirect tools, fixed environment and original
interpreter prefix. sh_helpers exercises the existing single-body form. The five
protocol suites concatenate original common.sh then their original suite body.
All six installed shell programs match original Make bytes; no surrogate driver
or runtime source extraction is used. This is an internal helper API extension,
not a new frontend option or a replacement build workflow.

Make selects the upstream-supplied test-programs/Kyuafile, not generated default
registration. The original file is retained byte-for-byte, including its legacy
syntax and atf suite identity. It registers only five shell suites; c_helpers,
cpp_helpers and sh_helpers remain installed protocol fixtures with deliberate
failure/death/timeout behavior. They are not falsely registered as passing
standalone suites. The initial native assembly generated incorrect registration;
the independent comparison caught it before acceptance.

The parent installs the original filesystem-discovering tests/Kyuafile without
another hand-maintained list of its test children. Actual declared SDK Kyua
metadata discovery matches all 333 unique native/Make case identities and their
per-program order: 214 C, 101 C++ and eighteen nested shell cases. The original
parent does not promise child-directory enumeration order, so filesystem creation
order can put test-programs before or after library suites. The comparison keeps
exact case identities/per-program order and does not patch discovery to force an
artificial global order. The SDK engine and host ATF shell interpreter are still
execution inputs; this is not a fully bootstrapped native-engine qualification.

## Runtime scope

Final parent receipts report the already-qualified sixteen original C++
environment/exception/text passes plus one separate source-settings helper.
The runtime binary hashes match retained strict native-loader/Kyua database
proof from ATF-CXX-TEST-QUALIFICATION.md. Cached successes remain valid receipts,
not claims of new executions. The other 317 registered bodies are not executed
by parent construction/discovery. Compiler/header, filesystem/process/user and
nested death/exit/signal/timeout protocol suites need their proper execution
inputs and runner/guest qualification. Installed helper fixture presence alone
proves none of their intentional outcomes.

## Retained evidence

All paths below are under /usr/obj/usr/src:

- bazel-atf-parent-request-r1-20261106: existing format-5 positive profile.
- bazel-atf-parent-native-r1-20261106: complete first construction; incorrect
  generated upstream-suite replacement retained and rejected by comparison.
- bazel-atf-parent-kyua-review-r1-20261106: explicit original-vs-generated
  Kyuafile mismatch, captured bytes and original/candidate hashes.
- bazel-atf-parent-native-r2-20261106: correct upstream registration and complete
  positive-profile capture, existing runtime/helper results.
- bazel-atf-parent-native-r3-20261106: final single-/multi-body API coverage;
  parent archives/libraries remain byte-identical to r2 compared captures.
- bazel-atf-parent-request-no-tests-r1-20261106 and
  bazel-atf-parent-no-tests-native-r1-20261106: production-only selection proof.
- bazel-atf-parent-make-r1-20261106 and
  bazel-atf-parent-no-tests-make-r1-20261106: independent original parent controls.
- bazel-atf-parent-review-r2-20261106: both complete inventories, directory tag
  claims/hardlinks, all exact data bytes, 38 ELF/debug contracts and 333 actual
  SDK Kyua identities. Retained r1 incorrectly required global filesystem child
  enumeration order; actual identities already matched, and product discovery
  did not change to satisfy the audit.
- bazel-atf-parent-final-review-r1-20261106: final parent/capture identity,
  both script API forms, runtime binary identities and final test-report hashes.

Existing build-bsd format-5 inputs cover these targets and profiles; no frontend
C/schema, SDK-input, signing, stage verification or publication-policy change is
required. The manual and completion plan are updated with this scope. This closes
the last initially missing declaration root, including its nested test-programs;
existing declarations elsewhere still require traversal/inventory qualification.
Full tests-enabled world and independent world/kernel/modules/pkgbase/debug,
normal-service VM acceptance, ARM64/RISC-V, bootstrap/cache/sandbox/reproducibility,
CPU/RAM/disk-I/O/footprint and verified combined publication remain open. No live
DTrace/audit-delivery or root-integrity claim follows. BIP remains excluded;
no host installation/upgrade/reboot or VM launch occurs in this batch.
