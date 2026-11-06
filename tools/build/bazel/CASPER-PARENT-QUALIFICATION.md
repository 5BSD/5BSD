# Native Casper test parent qualification — AMD64

## Implementation and original Make discovery fix

The selected libcasper parent now composes its native production library, all
eight original service contributions, the original service-discovery dispatcher
and its root tests. Optional tests are source-owned Bazel dependencies selected
by the existing tests flag. Production and test archives stay separate, retaining
original package directory claims. This replaces the Casper-specific incomplete
parent guard after positive/negative installation qualification. The full library
root guard remains: other package metadata and whole-payload gates are unfinished.

The original Make installation had a discovery bug: its root Kyuafile registered
only the two cap_main cases, while the independently installed services dispatcher
listed another 63 cases. The source now supplies the root Kyuafile using the
existing `KYUAFILE=yes` mechanism, registering cap_main and including the original
services dispatcher. The dispatcher still discovers installed children; there is
no maintained child-service allowlist or generated filesystem substitute. A new
root test program must be added to this supplied controller, as with other supplied
Kyuafiles. No production or test C bodies were changed.

Six newly qualified service BUILD files use a shared source-owned macro with
native rules_cc compilation, explicit Casper/service/nv/ATF header and ABI inputs,
original GNU17 and warning policy (net uses WARNS=3, the others 6), and original
WITH_CASPER/PIC policy. Owned alwayslink objects preserve direct-source inclusion
before ordered native ABI linkage. The existing fileargs suite remains intact.
Native nv-header visibility is restricted to the Casper subtree. No SDK-library
substitution or compiler discovery fallback was added.

Installed programs retain PIE, ordered dependencies and no RPATH. The two TAP
runtime-only links share their compiled objects with installed programs and add
only the private inherited loader path. Their trace-only checks bind exactly the
native Casper, service, nv, C and sys libraries, plus VDSO. This loader trace is
separate from the Kyua body and does not prove per-body tracing. Original 300s
case deadlines remain. Root cap_main bodies run installed stripped programs.

## Evidence

All paths below are under `/usr/obj/usr/src`, using the maintained build-bsd
bazel-test path, 16 CPUs, recorded format-5 inputs, explicit original offline
cache/SDK receipts, and unsigned development qualification. There is no host
installation, upgrade, verified boot or publication claim.

| Scope | Tests enabled | Tests disabled |
| --- | ---: | ---: |
| Native archives | 18 | 9 |
| Make-matching installed file/link records | 155 | 130 |
| Explicit directory paths/claims | 22/22 | 1/1 |
| Exact non-ELF data files | 112 | 103 |
| Program/DSO ELF and split-debug contracts | 17 | 9 |

- `bazel-casper-parent-before-make-r1-20261106` and
  `bazel-casper-before-discovery-r1-20261106` record the original discovery gap.
- `bazel-casper-parent-make-r1-20261106` and
  `bazel-casper-parent-no-tests-make-r1-20261106` independently build/install the
  corrected complete original parent, without deleting original children.
- `bazel-casper-parent-native-r3-20261106` is the final positive capture;
  `bazel-casper-parent-no-tests-native-r1-20261106` is the negative capture.
  Positive r1 failed analysis on a missing nv-header visibility grant; it remains
  recorded. Positive r2 succeeded; r3 adds the original eleven fileargs bodies.
- `bazel-casper-parent-review-r2-20261106` and
  `bazel-casper-parent-no-tests-review-r1-20261106` bind captured payloads to
  Make METALOG and staged files. These compare all selected file/link sets,
  ownership/group/mode/flags/package tags, symlink/hardlink contracts, all sets of
  directory package claims, exact non-ELF bytes, ordered ELF dependencies/symbols/
  versions/hardening, and debug separation/name/CRC. No static archives are
  installed, matching Make. Raw DWARF/debugger-source equivalence remains open.
- `bazel-casper-discovery-r1-20261106` runs the original Kyua root dispatcher
  against both installations: 65 unique cases across eight programs, identical
  per-program order, and identical actual ATF metadata for 63 ATF cases. Directory
  iteration order between different programs is not a contract. This metadata
  comparison does not run network/root bodies or prove controller isolation.
- `bazel-casper-tap-review-r1-20261106` retains both original Kyua databases,
  stdout, native runtime receipts and program copies, bound to final report hashes.

## Actual execution and remaining scope

Thirteen original ATF cases pass: two cap_main broker connection/churn cases and
all eleven existing fileargs cases. The two original TAP programs pass, checking
199 group and 188 password assertions with no skips. They use actual host account
interfaces, not fabricated account data. The source helper is a separate sixteenth
reported pass; it is not another original suite case. Fifty original cases remain
unexecuted in this qualification: DNS 10, network 34, netdb 1, and sysctl 5. Network
configuration and original root/exclusive metadata remain intact. No privileged
sysctl mutation or fabricated networking success was used.

DOF initialization is disabled for isolated body checks. Live provider firing,
audit delivery, normal Capsule/service/SSH/PAM boot, cross-target installed
runtime, and CPU/RAM/disk-I/O/footprint comparisons remain separate requirements.

The refreshed independent original Make traversal still reaches 326/442 library
directories with tests off/on and adds 116 through 66 entry roots. All 66 now have
configured installation declaration reachability. The negative root still selects
the same 231 archive output paths. See `bazel-casper-graph-review-r1-20261106` and
`bazel-library-test-edges-inventory-r2-20261106`; only the intentional original
Casper tests Makefile changed among recorded Make include inputs. These graph
counts establish neither whole-library installed payloads nor body completeness.

Next reconcile the 25 recorded explicit directory-policy changes against original
Make installation/package claims, then qualify the full selected library/world
payload. Keep the global tests-enabled library guard and Make production default.
Complete world/kernel/modules/pkgbase, current normal-service VM acceptance,
bootstrap/output-query/reproducibility, incremental/cache/sandbox behavior and
verified combined base/hardware publication remain open. BIP is excluded.
Existing frontend format-5 settings already select this work: no C frontend,
configuration schema, signing or backend action change is necessary. The manual
and completion plan are updated with the actual supported scope.
