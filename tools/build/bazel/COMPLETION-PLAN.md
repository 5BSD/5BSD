# Native Bazel completion plan

## Execution reset: finish complete endpoints (2026-11-15)

The six original gates and their acceptance scope are unchanged. Component
porting has become too fragmented: repeated private Make references, SDK refreshes
and per-component narratives do not establish a qualified complete system.
The following execution order supersedes the incremental component queue:

1. Finish and commit the currently running provider-client batch; do not discard
   live work or restart it because an observation times out.
2. Produce one consolidated remaining-work inventory from configured Make
   recursion/component metadata and actual configured Bazel dependencies for
   AMD64 and ARM64. Separate direct incompatible declarations, missing CPU source/
   header selections, generators/execution ABI, link/install metadata and genuine
   unsupported features. An ancestor marked incompatible is not another missing
   program. Resolve omissions in larger related groups through full aggregate
   analysis/builds. Do not repeatedly rediscover the same inventory.
3. Drive the AMD64 end-to-end endpoint through gates 1 and 2: complete provider
   operations in legitimate contexts and whole world/kernel/modules/pkgbase
   comparison, including debug/install contracts and required configurations.
   Preserve the already accepted full upgrade/authentication/rollback/BE-removal
   evidence; rerun that scenario when a relevant change invalidates it. Use one
   complete profile-bound Make world/kernel/stage/package reference for aggregate
   comparisons. Rebuild a component separately only for a concrete mismatch or
   an invalidated source/profile/input boundary.
4. Complete gate 3 using the native package/compiler output as the next SDK seed
   and prove the second-stage build, explicit tool/runtime/input closure,
   invalidation/cache/reproducibility and actual filesystem isolation. The existing
   format-2 explicit SDK boundary and captured compiler/runtime probes are starting
   evidence, not completed native bootstrap. Keep unrelated mutable Make object
   roots from becoming accidental native-build inputs.
5. Use those complete endpoints for the controlled clean/incremental CPU,
   aggregate RAM, disk I/O, retained footprint and cache/compression comparisons
   in gate 4, then qualify the normal frontend, Make ports/hardware and verified
   combined repository publication in gate 5. Do not switch production default
   before these gates pass.
6. Finish ARM64 Tier 1 against the same complete-build acceptance matrix, filling
   its identified implementation gaps in larger groups along the way. RISC-V
   remains nonblocking Tier 2. ARM64 component success is not ARM64 system success.

After this batch, prefer complete aggregate builds with keep-going diagnostics
and one categorized failure report. Keep strict inventory/metadata checks;
reduce repeated setup and redundant testing rather than weakening acceptance.
Add focused tests for concrete regressions and new behavior; use maintained
Bazel tests and full endpoint checks for routine coverage. Source-owned build
metadata stays in Bazel: Make remains the independent reference and ports build
system, never a hidden production action-graph generator or fallback.

Keep the SDK seed stable across the complete endpoint runs. The current full
installed-test candidate uses SDK R15; the earlier full system R15 capture used
SDK R6. Those are different seed generations, so the current compilation is not
an incremental timing comparison. Finish this endpoint and its final source
review before changing the shared Make object profile. Native package-derived
SDK construction in gate 3 must remove that mutable Make-floor dependency;
never edit an old receipt or omit its input checks to reuse it after mutation.

Sandbox setup cost must be measured from the completed profile before tuning.
Bazel 9.3.1 already defaults to directory reuse; its process-wrapper strategy
uses the shared symlinked-sandbox implementation. The optional in-memory stash
can trade extra JVM memory for less directory I/O. Compare it only if profiling
shows a relevant cost, measuring aggregate RAM and disk I/O as well as CPU/time.
No performance flag is changed here, and process-wrapper reuse does not provide
filesystem isolation. Version-bound upstream references:
[SandboxOptions](https://github.com/bazelbuild/bazel/blob/9.3.1/src/main/java/com/google/devtools/build/lib/sandbox/SandboxOptions.java),
[ProcessWrapperSandboxedSpawnRunner](https://github.com/bazelbuild/bazel/blob/9.3.1/src/main/java/com/google/devtools/build/lib/sandbox/ProcessWrapperSandboxedSpawnRunner.java)
and [SymlinkedSandboxedSpawn](https://github.com/bazelbuild/bazel/blob/9.3.1/src/main/java/com/google/devtools/build/lib/sandbox/SymlinkedSandboxedSpawn.java).

Every implementation group must still review build-bsd and its maintained
backend/helpers/tests/manual, retain scope-bound evidence, update this short
current plan and commit incremental changes. Detailed component evidence belongs
in linked reports/history rather than expanding the current gate ledger into a
conversion diary. No new architecture or BIP scope, host installation, upgrade or
reboot is authorized. No completion date or percentage is inferred from counts.

### First consolidated configured inventory

The completed four-query matrix uses the full endpoint's reproducible build
settings and explicit per-architecture SDK/triples/FDT. AMD64 tests-off reports
109,499 configured records and zero incompatible records; this is analysis,
not a new build acceptance. AMD64 tests-on is blocked by 20 incompatible
aggregate/ancestor records, including deliberate incomplete-installed-test guards
in lib, cddl, secure and usr.sbin. Those 20 are not 20 missing programs and the
guards stay until complete installed-test inventory is proved.

ARM64 tests-off reports 2,814 incompatible configured records. Literal direct
AMD64-only restrictions identify 299 declarations across 243 source packages;
these are a review frontier, not 243 missing or necessarily required programs.
Dynamic restrictions and propagated ancestors remain separately unclassified.
Tests-on reports 1,351 incompatible records, with a smaller traversed graph due
to aggregate guards; fewer records do not mean better coverage. The complete
Make source/profile inventory now completes 2,135 AMD64 and 2,094 ARM64
directories without query failures. Its recorded configurations determine the
review queue; they are not a shared Make/Bazel profile or build acceptance. Evidence:
bazel-closeout-consolidated-bazel-inventory-r2-20261115 and
bazel-closeout-consolidated-make-inventory-r2-20261115 under /usr/obj/usr/src.
Earlier missing-loader-input and incorrect metadata CLI diagnostics remain
retained; no failed query is used for complete inventory counts.

### Complete selected package debug pairing

All 1,803 split-debug pairs in the captured 450-package R15 system now pass the
current maintained verifier and independent public-payload/path/policy review.
The original Make reference pairs were rechecked with that verifier, rather
than accepting its older verifier binding. This closes pair binding for the
selected snapshot, not full DWARF semantics, source lookup or current-head
world/package acceptance. See MODULE-DEBUG-QUALIFICATION.md and
`bazel-packaged-debug-pair-audit-r4-20261115` under /usr/obj/usr/src. Failed
diagnostic attempts remain retained; temporary extracted payloads are removed.

### Tests-enabled contribution audit and OS test installation gap

The previously selected installed-test contribution graph completes native R1
and final-graph R2 through `//:world_installation_candidates`. R2 captures 4,230
logical output records (3,633 unique payloads); the capture review verifies them
and the three build-tool test results (38 nested Python cases plus the hardlink
target). Configured boundary checks prove the audit root remains available with
tests on while production guards reject that incomplete profile; with tests off,
both roots expose identical archive paths. These are contribution/build-tool
checks, not complete installed-test, finalized-world or pkgbase acceptance.
Evidence: `bazel-installed-tests-world-native-amd64-r2-20261115`,
`bazel-installed-tests-world-capture-review-r2-20261115` and
`bazel-installed-tests-aggregate-boundaries-r1-20261115` under /usr/obj/usr/src.

The whole-endpoint audit found that this graph omitted the top-level `tests/`
family entirely. A public Bazel loading query joined with the existing completed
Make inventory finds 239 selected test source owners, only ten with any native
rules and three installation archives before the new security suite work. Rule
presence includes partial/non-installed harnesses and is not complete conversion.
Evidence: `bazel-installed-test-loading-inventory-r1-20261115/review.json`.
Connect those source-owned archives through the normal world audit root, convert
missing suites in related groups and compare a matched-profile full Make test
installation. Keep production guards; never substitute a small root Kyuafile
that pretends unconverted directories do not exist.

The first connected security-subtree batch now completes native aggregate R4
through the normal build-bsd format-5 path. All 58 programs are declared: 51 plain
OES C programs, its ATF C program and ATF shell program, plus four MAC ABAC ATF
C programs and its ATF shell program. Included example/logger code and the
reader implementation are explicit dependencies; no source-tree visibility or
Make action fallback was introduced. The parent security Kyuafile includes both
complete children; incomplete tests/sys and tests roots do not manufacture a
complete registration.

The independent review matches all three security Kyuafiles to current original
Make registrations, checks 117 installed file records and explicit package-owned
directory claims, and verifies all 56 compiled binary/debug pairs. It does not
execute integration tests or prove Make/native instruction or DWARF equivalence.
The final aggregate capture verifies all 4,248 output records and the same three
build-tool test targets. Real configured boundary checks retain the tests-on
production rejection and exactly equal 1,284 tests-off archive paths. R3's missing
included logger source and two reviewer diagnostics remain retained; no input or
metadata check was waived. Evidence under /usr/obj/usr/src:
`bazel-installed-tests-world-native-amd64-r4-20261115`,
`bazel-installed-tests-world-capture-review-r4-20261115`,
`bazel-security-test-installation-review-r3-20261115` and
`bazel-installed-tests-aggregate-boundaries-r2-20261115`.

Frontend review: the maintained world backend selects these archives using the
existing tests setting and format-5 labels; no new C option is needed. The manual
now states top-level test coverage remains incomplete and kernel/policy-changing
tests require an isolated VM. Signing/publication helpers are unchanged because
this batch adds native test payloads, not trust policy or publication semantics.
The rest of the 239-owner review queue, a matched full Make installation,
current kernel/modules/image, actual security-suite execution and the six gates
remain open. Continue related test groups through the complete audit endpoint.

The concurrent OpenES merge a7d37e2855a changed kernel and test sources during
R1. R2 incorporated its world dependencies; five archive hashes changed for real
library/header/manual payload changes. Neither run is a controlled incremental
benchmark or a reproducible snapshot of unchanged source. Refresh current-source
kernel/modules/image and VM acceptance; the older VM proof remains evidence for
its recorded snapshot only.

The consolidated AMD64 Make metadata query completes all 2,135 configured
directories without query failures. The maintained native-presence survey binds
those records and reports 1,656 local BUILD owners and 479 ancestor-owned
components. These are directory ownership review counts, not converted program
counts or installation coverage. ARM64 completes all 2,094 directories without
query failures: 1,617 local BUILD owners and 477 ancestor-owned components.
Complete profile-bound Make installation metadata is still required for parity.

The ARM64 literal-constraint frontier is now joined to those completed Make
owners in `aarch64/constraint-frontier-join.json`. Its 299 declarations comprise
109 binaries, 57 C/C++ library rules, 70 shared libraries, 47 component archives
and 16 parent/archive groups across 243 source owners. These are distinct rule
kinds, not 299 missing programs. Four declarations have no exact owner in the
recorded Make configuration (mail/update features differ); they remain explicit
review items, not exclusions. Dynamic constraints and propagated incompatibilities
remain in the original query's separate queue. The next ARM64 work must review
real source/header/define selections as well as compatibility: libssl, for example,
still imports AMD64_DEFINES and cannot be ported by removing its CPU guard alone.

The previous provider-client batch now passes both native builds and all 28
original Make references: fourteen static/shared-library contracts and 344
complete install metadata records per architecture, plus five static DTrace
providers with 36 locations each. Captured reports and output hashes verify.
See CAPABILITY-FIDL-CROSS-QUALIFICATION.md. No additional component campaign is
started; the consolidated inventory and complete endpoints determine next work.

### Execution-host and ARM64 image boundaries confirmed by source review

The current SDK adapter treats AMD64 as the native execution host:
`libmd-stage-tools.py` rejects a separate execution SDK for an AMD64 target and
requires an AMD64 execution receipt for foreign targets; `userland_sdk.py`
validates that same assumption. `source_graph.py` classifies every non-AMD64
target as foreign, and `tools/build/fuchsia/fidlc/BUILD.bazel` restricts the
build-only compiler to AMD64. Thus current ARM64 evidence describes cross builds
from AMD64, not an ARM64-hosted build or self-bootstrap. Keep those existing
cross-build results; do not remove checks or mark foreign binaries executable
to manufacture native-host coverage.

Gate 3/6 must represent the actual execution CPU/SDK separately from the target,
carry that distinction through generators, C/C++ runtime/toolchain selection and
test adapters, and qualify ARM64-hosted execution. The normal frontend and SDK
receipt path must carry it; a private ARM64 wrapper is insufficient. Target and
execution OS/runtime compatibility also needs explicit review when the source
and running host differ, even with the same CPU.

The existing whole-pkgbase image builder `pkg_image.py` additionally requires
BIOS/ZFS policy. Its AMD64 VM evidence cannot qualify ARM64 boot. The maintained
ARM64 EFI image/VM path remains required within Tier 1 completion. This records
existing implementation boundaries; it adds no architecture, BIP or authority
scope and changes no running build inputs.

## Current gate ledger (2026-11-15)

All six gates remain open. Update this ledger when evidence changes; dated
execution notes below retain history and do not override these current rows.
Make remains production/default, BIP is excluded, and host installation/reboot
is not authorized.

| Gate | Current evidence and remaining work |
| --- | --- |
| 1. Runtime and upgrade | Fresh R11 VM R3 passes all 34 checks, normal shutdown, signed 450-package upgrade/new kernel, authentication, rollback, shared-file persistence and unused-BE deletion. It checks 13 manifest-derived boot services and six selected ordinary-session operations; all-provider operation coverage is explicitly false and remains open. The fresh Log-enabled superset VM now passes all 34 checks and normal shutdown, including seven ordinary operations (actual Log emit/flush/query), NetworkControl and SystemExtension in all four phases. Its 147 root-operation outputs, source/serial and phase reports independently verify. Complete-provider coverage stays false; authorized Device, Filesystem, Crypto, Trace and Audit delivery remain open. Earlier timeout failures remain retained. |
| 2. AMD64 parity/configurations | Full R15 passes 32 selected verification tests and captures 450 packages with tests=false and tests_support=yes; it does not qualify the installed OS test suite. The general-helper identity corrections are included. Its 14 general-helper archives match independently Make-qualified focused AMD64 bytes; native static/shared libc smoke probes pass. Focused kernel matches Make's allocated contracts, loader symbols and CTF; native split-debug binding passes. Seven corrected modules match except reported GNU build-ID digests, with exact CTF. All 1,803 packaged split-debug pairs from that capture now pass current-verifier pairing against the complete original Make path/policy inventory (1,079 world, 724 kernel/module), with all 450 package hashes independently reverified. Complete current package/install contracts, DWARF/source lookup and required configuration selections remain open. |
| 3. Bootstrap/dependencies/cache/sandbox | Narrow target/execution compiler roles and actual ABI tests pass. Public target-configuration queries resolve alias ambiguity without ignoring duplicates. Actual configured queries now collapse ordinary/NOSSP consumers to one normal host DTrace bootstrap, preserving all 13 selected ARM64 outputs byte-for-byte. Earlier AMD64 R11 and ARM64 R7 snapshots verified all 8,345/16,682 files and actual target/execution ELF roles before the dev header merge; their current source bindings are stale. Fresh AMD64 R12 and ARM64 R8 materializations pass with direct copy bindings; the fresh AMD64 SDK/loader run passes four selected targets (39 Python checks plus one host ATF case), with hash-verified reports and 82 captured files; the fresh ARM64 run also passes three host-artifact targets (39 Python checks) and captures 75 files. Earlier native R3 runs both host-test scripts (25 cases) and preserves all ten startup objects per architecture against independent Make contracts. These are Make-built seeds; independent native bootstrap, copied-payload/source mutation checks, complete invalidation/reproducibility and filesystem isolation remain required. |
| 4. Resources/performance | A source-owned reaper supervisor now accounts complete private-server descendant CPU/block operations and sampled aggregate RSS; seven real process regressions and maintained AMD64 qualification pass. Normal frontend timings explicitly identify their client-only scope. This qualifies instrumentation, not performance. Command/QEMU observations exist, including R2 staying below its 4 GiB process-RSS and 8 GiB overlay budgets. Controlled clean/incremental CPU, aggregate RAM, disk I/O and retained-footprint comparisons remain required. Full R15 uses an explicit 32 GiB qualification-cache budget; this is not a production default or a performance result. |
| 5. Production frontend/publication | Maintained format-5 qualification works; Make stays the normal backend. Qualified Bazel world/kernel/pkgbase integration, Make ports coverage, separate hardware identity checks and verified combined publication under /usr/obj/usr/src/repo remain required. |
| 6. ARM64 Tier 1 | Current build-host/SDK/FIDL support remains AMD64-only; ARM64 self-hosting and a maintained EFI whole-system image/VM path remain open. Selected libc/CSU/loader, C++/math, portable and capability libraries, locale data, /bin and module-tool contracts pass; detailed dated evidence follows. All 29 FIDL IR consumers now build with the correct execution ABI. The 462 emulated math bodies match Make outcomes (448 passed, 13 expected failures, one skip). Complete ARM64 world/kernel/modules/pkgbase/configuration and VM/runtime qualification remain open. Incompatible configured ancestors are not a remaining-program count. RISC-V stays nonblocking Tier 2. |

Latest full capture: /usr/obj/usr/src/bazel-closeout-system-native-r15-20261114.
Runtime failure: /usr/obj/usr/src/bazel-current-upgrade-vm-r2-20261114/result.json.
Kernel proof: /usr/obj/usr/src/bazel-current-kernel-parity-r5-20261114.
Module diagnostics: /usr/obj/usr/src/bazel-module-source-identity-review-r1-20261114.
ARM64 CSU proof: /usr/obj/usr/src/bazel-arm64-csu-parity-r1-20261114.


### Capability libraries and FIDL execution ABI (2026-11-15)

Nine capability library producers now build for both Tier 1 targets. The first
actual ARM64 Crypto IR generation failed because a raw target-SDK libgcc_s file
entered the host compiler runtime despite cfg=exec. All 29 consumers now share
the compiler-owned execution runtime: configured source-built libmd/C++/math/
unwind DSOs and the existing explicit execution-SDK C runtime alias. Both
maintained qualifications now build every IR. Actual configured ARM64 action
review verifies all 29 host compilers and seven runtime DSOs as AMD64 ELF.
All IRs match across architectures; all nine Crypto generated source/header
files per architecture match original Make bytes. No receipt or artifact is
rewritten to obtain equality. See CAPABILITY-FIDL-CROSS-QUALIFICATION.md.

All 18 original Make references pass. Nine archives/nine shared ELF contracts
and all 344 install metadata records per architecture match. Five static-library
DTrace providers use the existing explicit object-ABI selector before execution
transition; their schemas, 65 symbol-relative locations and target patch
instructions match Make on each platform. Raw compiled payload differences
remain retained, without full code/DWARF or live provider-firing claims.
ARM64 captures 86 files and passes 40 Python checks in three host targets;
AMD64 captures 87 files and adds the passing native wire-format runtime test.
All captured payload and test log/XML hashes independently verify.

Frontend review: existing normal format-5 inputs and maintained backend carry
the shared compiler runtime and all selected producers. No new CLI, signing,
stage verification, hardware identity or publication interface is required.
Complete ARM64 world, provider runtime and other closeout gates remain open;
Make remains production/default and BIP stays excluded.

### Portable library and fresh-account Tier 1 checkpoint (2026-11-15)

Ten additional library producers now admit ARM64 and AMD64, with other CPUs
still explicitly incompatible: libopenbsd, libdiff, libpe, libelftc, libstdbuf,
libkiconv, libdevctl, libkldelf, libmixer and libusbhid. The already portable libc
and libmd installation aggregates also admit ARM64. Original Make recipes have
no CPU-specific source selection for these ten libraries; their normal and
internal PIE variants, private-library names, ABI maps, source order and installed
manual aliases remain intact. The source-owned declarations change compatibility
only. AMD64-only executable tests retain their execution restriction.

All 24 independent original Make component references pass (12 per platform).
Fourteen normal/internal-PIE archives per platform match member order and symbols;
six DSOs match ELF metadata, dependencies and hardening; mixer ABI maps match in
bytes. All 107 archive member ELF machines are correct. Allocated/symbol/relocation
contracts match in 77 objects; the remaining 30 differ only in diagnostic strings
with the canonical /usr/src/ prefix. Raw artifacts, contracts and strings remain
retained; no bytes are rewritten and full DWARF equality is not claimed.

Seven library component archives match all 102 Make install metadata records per
platform; libmd adds 127 matching records. The complete libc installconfig
reference includes three untagged fresh-system files (/etc/passwd, pwd.db and
spwd.db), produced by Make's install-passwd hook. These are already intentionally
separate from package/upgrade payloads in the native world design. Enabling the
existing declared account generator's ARM64 data output, with pwd_mkdb still an
execution-platform tool, allows all 1,508 libc/reference entries to reconcile.
The three generated files match Make bytes, ownership/modes and absence of package
tags. Canonical hardlink chains match actual reference inodes, including regfree
through regexec to regex; a diagnostic that required direct link spelling is
retained. Thus all 1,737 selected install records per platform match. Compiled
archive/DSO/debug byte differences remain recorded.

Final maintained frontend qualification: ARM64 R3 passes three host-artifact test
targets (40 Python cases), with 54 logical outputs / 53 unique payloads; AMD64 R2
passes those checks plus the actual elftc API and stdbuf buffering runtime tests,
with 56 logical outputs / 55 payloads. All captured output and test-log/XML hashes
independently verify. Final ARM64 preserves all 51 earlier selected output records
byte-for-byte while adding separate account state. This is not complete ARM64
world, tests-enabled installation, live device use or independent bootstrap.

Evidence under /usr/obj/usr/src: bazel-portable-libraries-native-aarch64-r3-20261115,
bazel-portable-libraries-native-amd64-r2-20261115, portable-library Make references,
per-platform parity/install-parity/object-contracts/literal-review/capture-review,
libmd-install-parity and libc-install-parity records. The corrected private-library
review filename, rejected nonexistent target and reference reconciliation
failures remain retained. Full ARM64 configured world R4 still rejects incompatible
transitive children; its 3,109 incompatible configured records are not a count of
remaining programs and precede this batch.

Frontend integration review: normal build-bsd format-5 target/test/SDK inputs carry
all producers and the separate fresh-account state. No new CLI, normal backend,
signing/stage verification, hardware identity or publication interface is required.
Account state remains excluded from package upgrade replacements. Make remains
production/default, BIP is excluded, and all six closeout gates remain open.

### Log-enabled full-upgrade acceptance (2026-11-15)

The terminal bazel-provider-log-operator-vm-r1-20261114 result passes all
34 checks and normal QEMU exit. Each of four phases (baseline, inactive install
before activation, new boot and rollback) passes 13 manifest-derived boot units,
seven ordinary-session operations and both installed operators. Log performs an
actual emit, flush and exact-record query. The separate review verifies every
one of the 147 root-output hashes, source and serial hashes, image/helper
captures and phase reports. Signed 450-package upgrade, actual new-kernel boot,
positive/negative authentication, explicit shared-file persistence and unused-BE
deletion pass; that guest reclaims 2,828,566,528 bytes. Application schema rollback,
complete provider operations, Secure Boot and comparative performance are not
proved. Evidence: bazel-provider-log-operator-vm-review-r1-20261115.

Frontend review: existing format-5 targets/image inputs, VM service-policy
format 3 and normal maintained backend carry this case. No frontend, signing,
publication or production-default change is required. Make remains production.

### Installed operator full-upgrade acceptance (2026-11-14)

The complete bazel-provider-operator-vm-r1-20261114 scenario now passes all
34 checks and normal QEMU shutdown. Signed 450-package inactive upgrade, actual
new-kernel boot, positive/negative login/PAM/SSH/su, rollback, explicit shared-file
persistence and unused-boot-environment deletion all pass. The final report binds
147 successful root operations, source/serial hashes and immutable image/helper
captures; the separate review rechecks every root-output hash and all four
service-phase reports. Both added operators pass in every phase; complete
provider operation coverage remains explicitly false. No host installation,
reboot or publication occurred. The fresh Log-enabled superset VM now also passes; see the 2026-11-15
acceptance below.


### Refreshed bin, module-tool and emulated math checkpoint (2026-11-14)

The shared development world selected SYSTEM_COMPILER and debug malloc. Its
final metadata epilogue, then subsequent incremental world updates, invalidated
older SDK source bindings. R13/native R1 and ARM SDK R9/R10 failures remain
retained; no receipt or copied tool was repaired in place. R14 is the seed used
by the accepted AMD64 bin/helper run, while its original live metadata binding
subsequently became stale. Fresh native R15 and composite ARM64 R11 materialize
8,342/16,679 snapshot files with 8,338/16,674 bound copies. These are Make-produced
seed floors, not production-malloc world or independent bootstrap evidence.

Maintained frontend bazel-bin-service-native-amd64-r2-20261114 passes five targets
containing 59 Python checks and captures 133 logical outputs / 103 unique files,
including the Log-enabled service helper. Complete receipt/manifest/payload and
test-log/XML hashes verify in bazel-bin-service-review-amd64-r1-20261114.
An independently rebuilt original Make /bin parent uses the recorded system
compiler, 16 CPUs, explicit NIS/sendmail/tcsh on, tests off and a fresh bound
libsm reference. Both build-tools and full build/install/installconfig pass.
This component reference explicitly selects production malloc; it does not
qualify a complete production world or publication. Evidence:
bazel-bin-current-make-amd64-r1-20261114.

Both current complete /bin captures match all 1,469 original Make installation
records with zero missing/extra objects, exact numeric ownership/modes/flags/
tags/links and matching script/data payloads. All 41 ELF programs per platform
match metadata, imports, NEEDED order and hardening; all 22 instrumented programs
match linked provider schemas and 70 locations. The 82 regular ELF/debug payload
byte differences per platform remain retained; this is not full code/DWARF or
live provider-firing qualification. See bazel-bin-current-{install,program}-parity-
{amd64,aarch64}-r1-20261114.

Kldconfig, kldload, kldstat and kldunload now admit both Tier 1 CPUs. Their Make
recipes have no differing CPU source selection. The three traced tools use the
shared explicit target-object-ABI DTrace selector before the execution transition.
Fresh maintained bazel-bin-kld-native-aarch64-r1-20261114 passes all three host
provenance targets (40 Python cases), captures 141 logical outputs / 108 files
and builds the complete /bin aggregate plus all four tool installation archives.
All four independent original Make references pass; complete component inventory
and metadata match in 16 records. Four executable ELF contracts pass; kldconfig's
matching provider absence and two linked locations each in the other three tools
are retained. No module load/unload, linked ARM64 patch-instruction validation,
audit delivery or live probe-firing claim is made. Evidence: bazel-kld-make-
references-aarch64-r1-20261114, bazel-kld-install-parity-aarch64-r1-20261114,
bazel-kld-program-parity-aarch64-r1-20261114 and
bazel-bin-kld-review-aarch64-r1-20261114.

The installed QEMU BSD user emulator also executes all 47 captured ARM64 math
programs and all 462 actual registered bodies. Native Bazel and independent
original Make programs/libm/libutil produce identical results: 448 passed,
13 source-declared expected failures and one skip for unavailable FP trapping.
All result diagnostics match after only the explicit /usr/src/ source-root
prefix normalization. The strict all-passed exploratory reports remain failed;
the separate comparison reports matched original Make outcomes, not repaired
math bugs. Ninety-four actual loader startup traces bind all reported DSOs to the selected
private target runtime. Missing target ATF fails execution; the loader attempts
a host default directory and rejects its AMD64 library as unsupported machine.
This does not establish filesystem confinement. See
ARM64-USER-MATH-QUALIFICATION.md. Maintained Bazel emulated-test integration and
full ARM64 kernel/VM qualification remain open; do not relabel these as host
artifact-only tests. No target-OS or host installation was performed.

Frontend review: existing format-5 architecture/SDK/target/test inputs cover the
component builds and helper capture. Backend recipe inputs, manual, runtime
README and observability ledger are updated together. No new C CLI dispatch,
signing, staging, publication or production-backend change is required. All six
gates remain open, Make remains production/default, and BIP stays excluded.


### Installed operator qualification checkpoint (2026-11-14)

Service policy format 3 extends the maintained normal-runtime runner with
explicit installed operator/program inputs bound to authenticated image payloads.
NetworkControl performs numeric address/service resolution as the actual ordinary
SSH user through its existing software attributes; sysextctl config enumerates
persistent policy through the normal root read-only query view. Complete output,
endpoint semantics, unique ready policy records and required caller contexts are
checked. No provider visibility, attributes or guest policy is changed. Paths
come from the request and must be regular image payloads. Configuration syntax
checks, local module lists and UID 0 alone do not substitute for provider RPCs.

Sixteen direct service-policy/parser/control-flow checks pass, including
truncation, wrong endpoint/transport, unready/inconsistent policy, duplicate
records, unauthorized program substitution, missing ordinary callback and failed
operation propagation. The request under bazel-provider-operator-request-r1-20261114
resolves both operator payloads and the two uploaded helpers against immutable
passing qualification receipts. The fresh full upgrade VM scenario under
bazel-provider-operator-vm-r1-20261114 now passes both operators at baseline,
post-inactive-install, new boot and rollback, then shuts down normally.
All 34 checks and 147 root-operation records verify, with signed 450-package
upgrade/new kernel, authentication, shared-file persistence and unused-BE deletion
reclaiming 2,828,836,864 bytes in that guest. Each phase has 13 ready boot units,
six ordinary cases and both installed operators. Baseline enumeration returns
43 ready extension policy records and both TCP/UDP numeric endpoints. Review:
bazel-provider-operator-vm-review-r1-20261114. A fresh Log-enabled superset request
and VM are under bazel-provider-log-operator-{request,vm}-r1-20261114; both
native capture and all four live Log phases now pass. No complete-provider,
Secure Boot or performance claim is made. This superset runs seven ordinary
cases and both operators at all four phases; the older operator-only helper
retains its narrower six-case scope. All-provider coverage
remains explicitly false; Trace, Crypto, Audit, authorized Device and Filesystem
need their legitimate contexts and useful operations.

Frontend integration review: existing build-bsd format-5 image/target/test inputs
and VM plan format 5 carry this policy; the maintained backend and frontend
manual document format 3. No C dispatch, signing, staging, publication or
production-backend change is required. All six gates remain open.


### Descendant resource accounting checkpoint (2026-11-14)

The original time-l wrapper omitted an already-running Bazel server. Normal
frontend command records and receipts now explicitly identify that client-only
boundary. The new source-owned resource_tree target measures an entire bounded
private-server lifecycle under a process reaper. It sums wait accounting once
across waited/adopted descendants and samples simultaneous descendant RSS,
including nested reapers, while reporting observer CPU and actual sample gaps.
The older serial-action resource_run interface remains unchanged.

Maintained build-bsd qualification bazel-resource-tree-native-amd64-r3-20261114
passes one native test target containing seven Python regressions: simultaneous
workers with waited/adopted CPU transfer, nested reapers, unrelated-daemon
exclusion, timeout and signal cleanup, command failure and existing-report
refusal. Its two captured native outputs and all report/log/XML hashes verify.
The test's subprocesses use the declared SDK Python, not absolute host utilities.
A complete fresh private-server startup/build/test/shutdown sequence is measured
under bazel-resource-tree-review-r3-20261114. All descendants drain, both sequence
commands pass, and current source copies/hashes and client timing labels verify.
R1/R2 evidence remains retained; R1 shutdown had a Java-default startup mismatch,
corrected with the same explicit JAVA_HOME in R2/R3. These are instrumentation
checks on a busy host, not comparative performance trials.

RSS is sampled and sums shared pages repeatedly; it is not exact physical peak
RAM. Kernel snapshots are non-atomic and short-lived peaks can be missed. Block
operations are not physical disk bytes. CPU/block totals cover the whole
sequence, not individual phases. Controlled Make/Bazel clean/incremental and
cache/compression/device/retained-storage comparisons remain open. See
RESOURCE-ACCOUNTING.md for the maintained measurement contract.

Frontend integration review: existing format-5 targets/tests/build-state inputs
select the helper through build-bsd without new C dispatch or CLI semantics.
The backend timing records/receipt and manual are updated in this change.
No signing, staging, security-policy or publication change; Make stays the
production/default backend and all six completion gates remain open.


### ARM64 world data and complete-root diagnostic (2026-11-14)

The full world_contribution_products request exposed AMD64-only byte-order
selectors in LC_CTYPE, both LC_COLLATE sets and termcap. They now share an
explicit supported-target little-endian condition derived from bsd.endian.mk.
Unmapped architectures still fail analysis; no host-endian/default fallback is
introduced. The existing little/big termcap producers remain separate. Its host
compiler now gets execution-runtime libraries instead of target sysroot DSOs.
RISC-V's existing little-endian mapping is declared, not newly qualified.

Maintained frontend runs bazel-locale-data-native-{aarch64,amd64}-r1-20261114
both pass all four complete installation archives, capturing 12 unique outputs
per architecture. Eight independent original Make references pass at the actual
production profiles, with 16 CPUs and tests still enabled in the reference
profile. Complete inventory/metadata/archive headers/ownership/flags/links and
all regular payload bytes match: colldef 229 records/113 regular files, Unicode
colldef 161/40, ctypedef 391/28 and termcap 4/3. Total per architecture: 785
records and 184 equal regular payloads. The two architectures' regular payloads
also match one another. These are data-generation/install comparisons, not
execution of ARM64 programs or a full-system build.

Evidence under /usr/obj/usr/src:
- bazel-locale-data-make-references-r1-20261114
- bazel-locale-data-install-parity-{aarch64,amd64}-r1-20261114
- bazel-locale-data-review-r1-20261114 (hash-verified captures and source bindings)

The original full-world request R1 also omitted explicit package_version;
R2 supplies it and ARM64 compiler-target settings. Byte-order analysis failures
are cleared, but the normal frontend correctly rejects the incompatible world
root: bazel-arm64-world-native-r2-20261114. This is terminal failed qualification,
not a running build or proof of world completion. The public configured DAG in
bazel-arm64-world-blockers-r3-20261114 contains 50,560 dependency records and
1,534 incompatibilities, all on the ARM64 target platform. It preserves execution
and trimmed configurations; incompatible nodes can prune descendants. These
counts are neither programs/libraries nor an exhaustive remaining Make inventory.
At this checkpoint the library aggregate still explicitly required x86; its
architecture selections needed reconciliation (vgl and Intel PT versus ARM
OpenCSD). The later PMC/library-aggregate checkpoint below corrects that boundary;
other userland/kernel/module/configuration/bootstrap/runtime gates remain open.

The earlier blocker R1 selects only the target configuration. Blocker R2 includes
all configurations but emitted Starlark errors for objects without providers,
despite Bazel exit zero; it is invalid evidence. R3 handles missing providers and
checks stderr for evaluation errors as well as process status. Earlier captures
remain retained rather than silently overwritten.

Frontend review: the existing format-5 target and architecture/SDK inputs cover
these generators. No new CLI/C dispatch, security, staging, signing or publication
semantics; the cross-data contract is documented in the manual. Make remains
production/default, all six gates stay open, and BIP remains excluded.


### Library aggregate and PMC trace dependencies (2026-11-14)

lib/ production traversal now admits both Tier 1 architectures; incompatible
children still reject the aggregate and installed tests remain explicitly
unsupported there. Source-owned selection follows lib/Makefile: vgl is x86-only,
Intel PT requires x86 plus PMC, OpenCSD requires ARM64 plus PMC, and libpmc is
selected with PMC on either. The real configured direct archive selections match
original Make SUBDIR with PMC on/off on both architectures. This qualifies those
four selections, not every feature/architecture selection or all libraries.

libpmc now selects the existing ARM64 event generator and declares the three
ARM machine-dependent PMC headers. OpenCSD's portable source inventory now admits
ARM64. Existing ordinary/PIE internal libpmcstat producers are included in the
focused comparison. Actual aquery actions declare all 182 ARM64 / 377 x86
architecture/shared-test dataset files and use the proper explicit generator
architecture. All native generation remains source-owned Bazel; original Make
runs are independent references, not product actions.

The first ARM64 original reference caught an incorrect helper restriction:
host generator and target compiler executables had to have identical bytes.
Their identities are now separate. Generator receipts must bind their own native
compiler; multiple generators must agree on that execution compiler, and the
actual generator artifact must have the execution platform's ELF64/type/machine.
Receipt/artifact/path/source provenance and actual metadata recipe checks stay
required. The manifest format is unchanged. Ten provenance regressions pass,
including foreign/relocatable ELF rejection and changed/mixed compiler identity.
The original failed reference remains retained; the corrected ARM64 PMC R2 uses
the separately qualified native Make jevents and audits its actual arm64 recipe.

Maintained frontend qualifications:
- bazel-trace-libraries-native-aarch64-r1-20261114: 16 captured files, three host
  artifact targets / 39 Python checks; no ARM64 program executes.
- bazel-trace-libraries-native-amd64-r2-20261114: 17 captured files, four targets /
  49 Python checks, including the ten generator provenance cases.

All receipt/manifest/log/XML hashes verify. Independent Make references pass
for the native generator and all three selected components per architecture
(using 16 CPUs, actual production profiles, focused TESTS disabled), with the
corrected ARM64 PMC reference substituted for its retained failed R1. Four
ordinary/PIE archives match Make order/symbols, and both DSOs match ELF metadata,
imports/NEEDED order and hardening. On each platform 52/62 member allocated
byte/symbol/relocation contracts match exactly; the ten differences are solely
diagnostic source paths. Original ARM64 OpenCSD spelling also has two repeated
separators. Raw differences remain; actual referenced source-file identities
verify without rewriting or normalizing either artifact.

The complete 74 PMC plus 49 OpenCSD installation metadata records match on both
platforms, including ownership/numeric IDs, flags, tags, headers, manuals and
links. Compiled/debug payload differences remain. Generated event C files match
Make byte-for-byte: 536,400 ARM64 / 7,334,658 x86 bytes. Full DWARF, live PMC or
OpenCSD operation and ARM64 runtime are not qualified.

Evidence under /usr/obj/usr/src:
- bazel-library-architecture-selection-r1-20261114
- bazel-trace-libraries-make-references-r1-20261114
- bazel-trace-pmc-make-aarch64-r2-20261114
- bazel-trace-libraries-{parity,objects,literals,install-parity}-{architecture}-r1-20261114
- bazel-trace-libraries-review-r1-20261114 (source/hash bindings and aquery review)

The complete world R3 request still fails because transitive children remain
incompatible: bazel-arm64-world-native-r3-20261114. Its analysis now traverses the
library aggregate; success of selected dependencies is not full world acceptance.
The earlier 1,534-incompatibility snapshot predates this aggregate expansion.
Concurrent unrelated PF work is outside this focused qualification/change.

Frontend review: existing format-5 targets and target/execution SDK inputs cover
these producers. The maintained original Make reference helper, its native tests,
manual and observability ledger are updated. No new CLI/C dispatch, staging,
security policy, signing or publication semantics. Make remains production/default;
all six gates stay open and BIP remains excluded.


### Complete ARM64 /bin construction and reference checkpoint (2026-11-14)

All direct /bin declarations now admit both Tier 1 architectures. The batch also
admits the required libedit, tinfo and internal sendmail library producers. This
is an entire aggregate request, not a selected list of convenient programs:
NIS/sendmail/tcsh are all explicitly enabled, installed tests disabled, and
DTrace/dynamic-root enabled. The original Make reference uses the same component
selections against its unchanged production SDK/profile.

Zsh's MACHTYPE now follows the target instead of always saying amd64. The shared
target_dtrace_bootstrap selector chooses the object ABI before execution-tool
transition, for all 22 traced utilities and their existing related declarations.
It has explicit AMD64/ARM64 cases and rejects unmapped ABIs. Shell signal/errno
preprocessing and terminal/editor generators retain their declared source/tool
pipelines. No production C, shell implementation, provider or audit source is
rewritten by this batch.

Maintained build-bsd qualification bazel-bin-native-aarch64-r1-20261114 passes
and captures all 126 logical outputs (96 unique payloads) from 42 installation
archives. The complete independent original Make parent reference passes at
bazel-bin-make-aarch64-r4-20261114, using 16 CPUs and maintained recursive all,
install and installconfig. Installation comparison preserves the source archive
order: all 1,469 logical paths and metadata match, with no missing/extra paths.
Ownership/numeric IDs, modes, tags, flags, links and all ordinary data/script
payloads match. Exactly 82 compiled/debug regular payloads differ and are retained.

Every regular installed /bin executable is compared: all 41 match Make ELF
class/machine, imports, NEEDED order and hardening. The remaining program component
is the byte-identical freebsd-version script; hard-link aliases are checked in
installation metadata. Linked provider names/schemas and location counts match
in all 41 ELFs, including explicit matching absence in 19 programs. The 22 traced
programs retain 70 locations. This does not check linked ARM64 instruction patches,
registration/firing, full program code/DWARF equality or target execution.

Reference-tool fixes were necessary and are retained with failed evidence:
- Original Make may select SYSTEM_COMPILER: an object-root cc alias can resolve
  to /usr/bin/cc. Library/generator/drti validators now share recorded compiler
  mode/executable/digest validation; actual artifacts must still stay under
  /usr/obj. Unsupported modes, mismatched executables and unbound/changed digests
  are rejected. The successful cross reference actually uses that external compiler.
- A recursive parent need not define LIBSM search-directory metadata itself.
  Explicit verified library directory bindings now propagate to descendants;
  the actual rmail link recipe witnesses the separately built Make libsm_pie.a.
- Isolated cross compilation must run native build tools first. The maintained
  reference helper adds explicit --build-tools, invoking Makefile.inc1's original
  _build-tools inventory/environment in fresh reference objects, using the source
  Make include path and existing verified SDK. Normal BUILD_TOOLS_META=.NOMETA
  prevents target flags from rebuilding those native tools during metadata builds.
  Five checked shell/terminal generator executables are actually AMD64 ELF, while
  every compared installed program is actually ARM64 ELF. No copied/fake generator
  or replacement C implementation is used.

Direct maintained provenance regressions pass 23 library, ten generator and seven
drti cases. Their fixtures stay in the declared test temporary directory. These
three metadata suites are now explicitly host-artifact rules. The requested native
rerun has NOT passed: the other live AMD64 buildworld job refreshed shared tool
inputs, invalidating old SDK source bindings. Fresh AMD64 /bin qualification also
stopped before output creation on its missing original compiler input. Source
verification remains strict. Regenerate/reverify SDKs after the shared build is
stable, then finish both native reruns; do not treat the direct tests as equivalent.

Evidence under /usr/obj/usr/src:
- bazel-bin-declarations-r1-20261114 (44 before/after declaration bindings)
- bazel-bin-make-references-r1-20261114 (internal library references and failed attempts)
- bazel-bin-make-aarch64-r{2,3,4}-20261114 (failed/successful reference history)
- bazel-bin-install-parity-aarch64-r2-20261114
- bazel-bin-program-parity-aarch64-r2-20261114
- bazel-bin-reference-review-r2-20261114 (40 direct provenance tests)
- bazel-bin-review-r1-20261114 (immutable capture/hash and actual tool-role review)

Frontend review: existing format-5 target/architecture/settings inputs construct
the aggregate. The maintained reference backend, its tests, DTrace selection,
manual and observability ledger are updated. No new build-bsd C dispatch or CLI,
security, signing, publication or normal Make behavior. Concurrent PF edits/build
are other work and are preserved. Make remains production/default. All six gates,
including full ARM64 world/kernel/modules/pkgbase/options/runtime, remain open.


### Ordinary Log operation implementation (2026-11-14)

The VM-only service_operations client now has a log mode using explicit
liblogcmp open/create/emit/flush/query calls. It publishes one public event to a
fresh category, then queries within its own label with exact subsystem/category
filters. It validates every length before computing body pointers, and requires
the expected event/message/severity/privacy plus provider receive clocks and
sequence. A zero-result scan may be retried for up to ten seconds for commit
visibility; transport/permission/framing errors are failures, not absent records.
The process-wide 20-second deadline remains. No syslog fallback, visibility
change, identity grant, root shortcut or new transport is used.

The existing format-2 case list accepts log; positive Device remains rejected in
ordinary contexts. Declared native dependencies include liblogcmp. Strict host
C syntax checking (-Wall/-Wextra/-Werror) and all 11 direct service-policy tests
pass. This is implementation evidence, NOT a native link or VM result. The
review at /usr/obj/usr/src/bazel-provider-log-review-r1-20261114 explicitly records
native_log_operation_qualified=false and vm_log_operation_qualified=false.
The other live AMD64 buildworld remains responsible for changing shared SDK
inputs; source verification is not bypassed while it runs.

The runtime README is reconciled: its old 'runner does not invoke the helper'
and 'format 2 VM pending' paragraphs were stale. The retained current upgrade R3
really passes the original six ordinary operations in all four phases. It does
not contain the new log mode. The eight implemented helper modes are distinct
from the seven allowed ordinary cases (positive Device is SYSTEM-only).

Next runtime steps remain: capture this updated native helper after SDK refresh,
run log in baseline/active-before-activation/new-boot/rollback, and exercise
restricted providers through existing approved operator binaries where suitable
or normal builder-authorized signed SYSTEM/attribute test units where necessary.
Trace's declared software requirement and SystemExtension/Device/Network scope
must remain enforced; ordinary UID/root identity must not stand in for authority.
Filesystem container qualification needs a real bundle identity. Required
readiness remains installed-manifest-derived. Complete provider-operation
coverage, runtime acceptance and the six closeout gates remain open.

Frontend review: maintained format-5 targets and format-2 operation inputs cover
the new mode. Backend C client/dependencies, policy validation/tests, runtime
README and manual are updated together. No build-bsd C dispatch/CLI, security,
signing or publication change. Make remains production/default; BIP excluded.


### Focused math and static unwind checkpoint (2026-11-14)

The source-owned libm declaration now selects the ARM64 portable/binary128
source inventory, builtin macros, fenv header and three ordered ABI symbol maps.
AMD64 retains its optimized/ld80 inventory, FMA renaming and maytrap policy.
The binary128 gamma implementation is an explicit textual dependency with
visibility restricted to libm. Static archives preserve declared source order.
Static libgcc_eh now admits ARM64 while retaining C/C++ visibility distinctions
and restricting frame API definitions to x86, matching original Make policy.

Maintained frontend runs bazel-math-unwind-native-{aarch64,amd64}-r1-20261114
pass with 13/16 unique captured artifacts. Both run the three host-artifact
targets (39 Python checks); AMD64 additionally passes static/shared math smoke
programs and the safe descriptor ATF case pulled into its verification closure.
Captured report manifests/logs/XML hashes are verified. No ARM64 code executes.
The three host checks are not 39 installed OS cases or a full test suite.

Four isolated original Make references pass, using 16 CPUs and the actual
production profiles with TESTS explicitly disabled for these focused component
installs: bazel-math-unwind-make-references-r1-20261114. Both platform comparisons
pass archive member order/symbols, libm shared ELF metadata/hardening and exact
generated ABI-map bytes. Every math object matches allocated bytes, symbols and
relocations: 277/277 ARM64 and 280/280 AMD64. Static unwind matches 7/9 objects
on each platform; the other two have only diagnostic string bytes differing by
the /usr/src prefix, with original objects retained and no normalization.
Evidence: bazel-math-unwind-parity-{aarch64,amd64}-r1-20261114,
bazel-math-unwind-objects-{aarch64,amd64}-r1-20261114 and
bazel-math-unwind-literals-{aarch64,amd64}-r1-20261114.

Complete installation inventory, ownership/numeric IDs, modes, tags, flags,
headers, manual payloads and links pass: 316 libm plus six static-unwind records
per platform. Compiled archives/DSO/debug payloads remain byte-different and
are retained; full DWARF is not qualified. Evidence:
bazel-math-install-parity-{aarch64,amd64}-r1-20261114 and
bazel-static-unwind-install-parity-{aarch64,amd64}-r1-20261114. Declaration and
frontend review: bazel-math-unwind-review-r1-20261114. These paths are all under
/usr/obj/usr/src. The existing format-5 frontend already selects these targets;
no CLI, signing, security policy, publication or production default changes.
Full installed math tests, target runtime and full system/configuration gates
remain open. Make remains production/default and BIP stays excluded.


### Original math suite and utility dependencies (2026-11-14)

The libutil/libnetbsd declarations now admit both Tier 1 architectures. libutil
uses the target-aware source-built host DTrace generator/native drti, retaining
its original separate provider/static-anchor semantics. The host artifact
archive checker takes the declared target machine and rejects the other Tier 1
machine; all nine checks pass on both platforms. Math tests select the original
architecture's builtin and long-double policy. The one hypot near-underflow
case requiring a 64-bit mantissa remains x86-only. The -nodefaultlibs link now
explicitly supplies native compiler-rt, preserving ARM64 binary128 helpers.

Maintained native runs bazel-math-suite-native-aarch64-r2-20261114 and
bazel-math-suite-native-amd64-r1-20261114 pass, capturing 50/51 unique artifacts.
Both pass four host artifact targets (39 general Python checks plus nine
utility archive checks). AMD64 additionally executes all 463 original math
cases: captured ATF body logs report passed for every case, with no skips or
expected failures. All report-manifest/log/XML hashes verify. ARM64 builds all
47 programs and their complete installation archive; none of its math bodies
execute. Its 462-case runtime/listing qualification remains open.

Original Make refs: bazel-math-suite-make-references-r1-20261114, with the stable
ARM64 test replacement bazel-math-suite-make-tests-aarch64-r2-20261114. All final
six component references pass using 16 CPUs, actual production profiles and
TESTS enabled for the test component (explicitly disabled for focused library
installs). ARM64 native R1's missing-runtime link failure is retained. The first
ARM64 Make test capture correctly rejected a concurrent tests.bzl edit; that
failed capture is retained and is not used for parity.

Both architectures match libutil and ordinary/PIE libnetbsd archive order/symbols,
libutil ELF metadata and generated ABI-map bytes. Every libnetbsd object (4+4)
matches allocated-byte/symbol/relocation contracts. libutil matches 33/35; the
two differences are diagnostic source-path strings and the provider's raw DOF,
with actual one-probe schema/location/companion patch checks matching Make.
All 47 installed math binaries pass original Make ELF metadata, hardening,
imports and NEEDED-order comparison. Full installation inventories and metadata
match: 124 utility plus 100 math-test records per architecture. Kyuafile and
noncompiled payloads match; compiled/debug payload differences remain retained.
Full code/DWARF equality and ARM64 execution are not established.

Evidence under /usr/obj/usr/src:
- bazel-math-suite-libraries-parity-{aarch64,amd64}-r1-20261114
- bazel-math-suite-library-{objects,literals}-{aarch64,amd64}-r1-20261114
- bazel-util-provider-parity-{aarch64,amd64}-r1-20261114
- bazel-math-suite-program-parity-{aarch64,amd64}-r1-20261114
- bazel-util-install-parity-{aarch64,amd64}-r1-20261114
- bazel-math-suite-install-parity-{aarch64,amd64}-r1-20261114
- bazel-math-suite-review-r1-20261114 (actual Make inventory/include closures,
  test report hashes, all ATF body outcomes and frontend integration review).

Existing format-5 qualification and explicit host artifact execution cover the
new dependencies without new CLI or security/publication policy inputs. Make
remains production/default. All six full-system gates remain open; BIP excluded.


### Crypto/compression dependency checkpoint (2026-11-14)

libcrypt and its two original test programs now admit ARM64. Existing optimized
ARM64 libmd/zlib/bzip2/liblzma selections are qualified against the refreshed SDK
and independent Make references. This is not five newly converted declarations.
Maintained native runs bazel-crypto-compression-native-aarch64-r2-20261114 and
bazel-crypto-compression-native-amd64-r1-20261114 pass with 43/47 unique captured
artifacts and 31/35 selected targets. Both run six host artifact targets: the
three general Python targets (39 checks) plus original zlib, bzip2 and XZ
archive/ABI/static-extraction inspections. ARM64 executes no target code.

AMD64 additionally passes the zlib example and static/shared zopen programs.
Its original crypt md5 and invalid ATF cases pass. Imported crypt_salts reports
its existing FreeBSD expected failure for old-style/bad salts, preserved in the
source and captured logs. This is explicitly not a clean pass. All report
manifest/log/XML hashes verify; logs with binary salt bytes are rendered with
escaped non-UTF-8 bytes after checking their original raw hashes.

All ten original Make library refs pass in
bazel-crypto-compression-make-references-r1-20261114. Both original test refs
pass in bazel-crypt-tests-make-references-r1-20261114. Builds use 16 CPUs, actual
production profiles and explicit TESTS disabling for focused library installs;
the direct test components retain tests enabled. No host installation/reboot.

For both platforms, five static archives match Make order/symbols, five DSOs
match ELF metadata/hardening/imports/exports/NEEDED order, and all three generated
ABI maps are byte-identical. Static object contracts match 136/138 per platform:
libcrypt 9/9, zlib 16/16, bzip2 7/7, liblzma 78/78 and libmd 26/28. Both remaining
digest objects differ only in diagnostic string source prefixes; original raw
artifacts are retained, with no normalization. Both crypt test programs match
original Make ELF metadata/import/hardening/library-order contracts.

Full installation inventory/metadata/flags/links and noncompiled payloads match:
127 libmd, 10 crypt, 11 zlib, eight bzip2, 22 liblzma and 10 crypt-test records,
188 per platform. Compiled/debug payload differences remain recorded; full
code/DWARF equality, disabled-crypt/other configurations and ARM64 execution
remain open. Evidence under /usr/obj/usr/src:

- bazel-crypto-compression-parity-{aarch64,amd64}-r1-20261114
- bazel-crypto-compression-{objects,literals}-{aarch64,amd64}-r1-20261114
- bazel-crypto-compression-install-review-{aarch64,amd64}-r1-20261114
- bazel-crypt-tests-program-parity-{aarch64,amd64}-r1-20261114
- bazel-crypto-compression-review-r1-20261114 (actual Make include closures,
  source bindings, raw report hashes/outcomes and frontend integration review).

The existing maintained format-5 frontend covers these source-owned target,
architecture and test selections. No new CLI, build inputs, security policy,
staging/signing, packaging or publication defaults. All six gates remain open;
Make remains production/default and BIP stays excluded.


### Data/configuration libraries and original tests (2026-11-14)

The reviewed portable Make selections now admit ARM64 for libsbuf, the libnv
installation/test traversal, libucl, libyaml, libbsdconf, private SQLite and ATF
C++, plus the original sbuf/libnv test declarations. The existing cross-target
XML implementation is included in the qualification batch. The two original
test inventories match actual Make: three sbuf programs and eleven name/value
programs, including four C++ ATF programs and six TAP programs.

Maintained final native R2 captures at
bazel-data-libraries-native-{aarch64,amd64}-r2-20261114 pass with 50/61 unique
captured artifacts. Both pass the three general host Python targets (39 checks)
and the XML host artifact inspection. AMD64's 161 selected targets preserve
actual XML outcomes: 160 passed and one skipped, not a full pass. Raw ATF logs
show 146 passing bodies (129 name/value, 17 sbuf) and the original ASan-only
nvlist_send_recv__overflow_header_size skip. All six TAP programs pass through
Kyua, with no broken/failed/skipped program results. Buffer and XML static/shared
smoke programs pass. The datagram send-many-FDs case remains declared but
excluded from host execution because it changes global sysctls. Neither that
VM case nor the ASan case is qualified by these runs; no ARM64 target executes.
All captured report manifests/logs/XML hashes verify, including cached results.

All twenty isolated original Make references pass in
bazel-data-libraries-make-references-r1-20261114, using 16 CPUs and actual
production profiles. TESTS is explicitly disabled only for focused library
installs; the direct original test components retain it enabled. Both platforms
match eight archive member orders/symbol inventories, eight shared-library ELF
metadata/hardening/import/export/NEEDED contracts, and byte-identical generated
sbuf ABI-map output. The 50 static object contracts match exactly in 28 cases;
all 22 other objects differ only in diagnostic /usr/src string prefixes. Raw
objects, relocations and debug differences remain retained; none are normalized.
The final ownership correction preserves all 32 selected archive/DSO bytes
across both platforms, explicitly hash-bound to the original object review.

The independent ARM64 install comparison found libsbuf missing the explicit
/usr/lib/debug/lib runtime/dbg ownership claim emitted by Make. The declaration
now uses existing utility_debug_directories(runtime, /lib). The first failing
comparison is retained; no inventory/metadata check was weakened. Final full
inventories, ownership/numeric IDs, modes, tags, flags and links match for all
ten components: 121 records per architecture. Both platforms' 14 installed test
binaries also match Make ELF metadata/import/hardening/library-order contracts.
Kyuafiles and noncompiled payloads match; compiled/debug byte differences remain
recorded. This is not full code/DWARF or installed-system qualification.

Evidence under /usr/obj/usr/src:

- bazel-data-libraries-parity-aarch64-r2-20261114 and
  bazel-data-libraries-parity-amd64-r1-20261114
- bazel-data-libraries-{objects,literals}-{aarch64,amd64}-r1-20261114
- bazel-data-libraries-install-parity-aarch64-r2-20261114 and
  bazel-data-libraries-install-parity-amd64-r1-20261114
- bazel-{sbuf,nv}-program-parity-{aarch64,amd64}-r1-20261114
- bazel-data-libraries-review-r1-20261114 (actual Make include closures/program
  inventories, final raw report hashes, explicit skip outcomes, unchanged
  compiled-artifact bindings and frontend integration review).

Existing format-5 target/architecture/test selection covers this batch without
new CLI, build input, security policy, staging/signing, package or publication
defaults. The maintained frontend was used for each native run. Make remains
production/default; all six system gates remain open and BIP stays excluded.


### Device libraries and structured output (2026-11-14)

Source declarations now admit ARM64 for libdevinfo, libdevstat, GEOM, CAM,
libxo production traversal and the original CAM test programs. Existing CSV
plugin construction/installation is qualified with this group. Review found
two CAM topology_* test targets pointing to nonexistent topology_test.c. Those
invalid declarations and their unused import were removed; no original Make
program was removed or invented. The two actual CAM programs remain installed,
with only their safe cam_strmatch case selected here. Device/root-sensitive
cases remain unqualified. GEOM's missing debug-directory ownership declaration
now uses the existing utility_debug_directories(runtime, /lib), derived from
its actual original Make package and install-directory policy.

Maintained native runs bazel-device-output-native-{aarch64,amd64}-r1-20261114
pass with 34/40 unique captured artifacts. ARM64 passes the three explicit host
Python targets (39 checks); no ARM64 target code executes. AMD64 passes nine
selected test targets: those host targets, static/shared GEOM topology parsing,
static/shared libxo formatting, the original safe CAM string case and the CSV
plugin suite. The latter's five checks load the actual generated plugin, verify
quoting/newlines/options and inspect declared runtime library resolution. All
captured report manifests/logs/XML hashes verify; there are no reported skips.
These parser/format/plugin tests do not establish hardware or disk-I/O behavior.

All fourteen original Make references pass in
bazel-device-output-make-references-r1-20261114, using 16 CPUs and actual
production profiles. TESTS is explicitly disabled only for the focused library
and plugin installs; the direct CAM test component retains it enabled. Both
platforms match five archive orders/symbol inventories, five library ELF
metadata/hardening/import/export/library-order contracts, CSV plugin SONAME and
ELF contracts, and both original installed CAM binary ELF contracts. Of 21
static object contracts, 19 match exactly and two differ only in diagnostic
/usr/src string prefixes; raw artifacts remain retained, with no normalization.

Full inventories, ownership/numeric IDs, modes, tags, flags, headers, manuals,
links and noncompiled payloads match: 215 installation metadata records per
platform across seven components. Compiled/debug byte discrepancies remain
recorded; full code/DWARF, device access, real storage I/O, complete tests and
ARM64 execution remain open. Evidence under /usr/obj/usr/src:

- bazel-device-output-parity-{aarch64,amd64}-r1-20261114
- bazel-device-output-{objects,literals}-{aarch64,amd64}-r1-20261114
- bazel-csv-plugin-parity-{aarch64,amd64}-r1-20261114
- bazel-device-output-install-parity-{aarch64,amd64}-r1-20261114
- bazel-cam-program-parity-{aarch64,amd64}-r1-20261114
- bazel-device-output-review-r1-20261114 (Make include closures, original CAM
  inventory, removed invalid declarations, report hashes and frontend review).

The existing maintained format-5 frontend selects the corrected source rules
and package metadata. No new CLI, security/build-input policy, staging/signing
or publication default. Make remains production/default, all six system gates
remain open, and BIP stays excluded. No host installation or reboot.

## Configuration completion checklist

[BUILD-OPTIONS.md](BUILD-OPTIONS.md) separates source kernel diagnostics from
debug artifacts and allocator mode, records current native boundaries, and lists
required Make-option/configuration and ARM64 implementation gaps. GENERIC-NODEBUG,
custom kernel/module selectors and the documented acceptance matrix remain open
until their actual outputs and runtime checks pass. These belong to the existing
six gates. The normal build-bsd backend remains Make; no frontend option changed.

## Current closeout execution (2026-11-14)

The maintained reference-world refresh R2 now passes both architectures at
4f0683e6286, with stable source/diff identities: ARM64 2,224 seconds and AMD64
2,948 seconds, each using 16 CPUs and production malloc. The refreshed profiles
record tests enabled. Evidence: bazel-current-head-world-refresh-r2-20261114.
These are Make reference worlds, not independent native bootstrap or native
Bazel world/configuration qualification. No host installation/reboot occurred.
The ARM64 loader capture R4 contains all 99 files selected from actual Make
object/archive/program/debug/map inventories. Its isolated Make install R2 also
passes with recipe metadata. Six files differ from the earlier capture; stale
SDK bindings must not be rewritten to reuse the old comparison.

SDK copied-byte verification now checks inventoried source hashes against copies
before tool execution and against the final snapshot before issuing a receipt.
The copied_payload_sources field preserves source correspondence; final checks
reuse the existing snapshot hashes. Cross preparation also binds the unchanged
execution-SDK copies; its execution-role BUILD is generated separately.
All 29 direct maintained SDK cases pass,
including transient source mutation/restoration, inventory changes, contained
aliases, escapes, cycles and post-copy changes. Actual AMD64 R12 and ARM64 R8 materializations now pass: 8,345/16,682 snapshot
files and 8,341/16,677 final copied-source bindings. ELF checks confirm host
compiler/native libc/drti machine 62, ARM64 target libc/drti machine 183 and
execution libc machine 62. Evidence: bazel-current-sdk-refresh-r1-20261114.
The copy helper/tests/manual are committed as 5074a0933b1. The fresh AMD64 SDK/loader run passes all four selected test targets (7 compiler, 29 SDK and 3 symbol-visibility Python checks, plus one ATF case), with all captured report hashes verified and 82 output files. The fresh ARM64 qualification also passes all three host-artifact targets (39 Python checks) and captures 75 files; this is not native bootstrap or filesystem isolation. Candidate review: bazel-sdk-copy-binding-candidate-r3-20261114.

The loader declarations now select actual ARM64 sources/flags and target-aware
host DTrace generation. Review of the original Make provider recipe found that
native DTrace previously received only ten core C objects; the corrected source
rule receives all 54 ordered local objects, including startup/private libc,
while the 38 selected external runtime objects remain outside that recipe.
The six NOSSP selections and 42 private-libc groups preserve original Make order.
Lazy provider generation (-xlazyload), ordinary runtime-archive extraction and
private namespaces remain required. Current-source native loader/DWARF/install
parity and AMD64 regression builds remain pending. Review:
bazel-rtld-order-candidate-r2-20261114; original references:
bazel-current-arm64-rtld-component-capture-r4-20261114 and
bazel-current-arm64-rtld-make-install-r2-20261114.

An actual uncached processwrapper-sandbox action reads an undeclared absolute
sentinel and writes outside its action directory. Runner, cache miss, input/output
inventories and matching bytes are bound by the execution log in
bazel-sandbox-boundary-probe-r2-20261114. Full AMD64 R15 used this runner;
it does not provide the required OS filesystem isolation.
A separate 2 GiB/4 CPU VM mechanism test passes on recorded guest kernel
83d696e46e20: a child drops root, attaches through a jail descriptor, cannot
read/write an outside path, closes its descriptor and starts a new session.
Killing its supervisor closes the last owning descriptor and kills that child.
The VM powers off normally; no owned VM remains. Evidence:
bazel-jail-lifecycle-vm-r2-20261114. R1's short SSH deadline failure remains
retained. This is an existing-kernel mechanism test, not a native Bazel sandbox,
current-head VM, unprivileged-supervisor or production-helper qualification.
Native runner/helper integration, declared-only input/runtime views, descriptor
rights/inheritance, path/timeout/error checks and performance remain open.

Coverage review confirms that R15's 450-package build selected tests=false,
although it ran 32 verification tests. The installed OS test-suite option remains
required by the acceptance matrix. Make builds jaildesc and jaildesc_cap_test;
tests/sys/kern had no native package. Their new source-owned contribution declares
both programs and all 13 original cases, preserving root and cleanup metadata.
Only get_invalid_base_descriptor is selected for ordinary host execution; the
root cases remain explicit manual/exclusive VM tests. The fresh AMD64 run builds both programs and their partial install archive and passes that one host case. The other 12 cases are declared, not executed by this run. The partial contribution
does not replace the complete kern Kyuafile or claim full test-suite installation.
Both AMD64 programs compile; corrected link-order/ELF metadata parity and the safe host case now pass;
execution of the 12 root cases remains pending. The libthr, libelf, libkvm, libjail and ATF producers now build on ARM64;
complete installed-suite composition and target execution remain open. Evidence: bazel-kernel-tests-gap-review-r1-20261114 and
bazel-jaildesc-native-candidate-r1-20261114. A fresh maintained ARM64 Make traversal
with tests enabled discovers 2,094 directories; all 2,094 detailed metadata
queries pass, with zero failed components. This is a review inventory, not a
converted-program count. Evidence: bazel-arm64-current-world-inventory-r1-20261114
and bazel-arm64-current-world-components-r1-20261114.

The maintained format-5 frontend already selects these producers/tests; no C CLI,
production backend, signing, hardware or publication default changes. The SDK
helper, tests and frontend manual are updated together. All six gates remain
open. Make remains production/default and BIP remains excluded.

The later dev merge a28032efc6f changed source headers, including fcntl.h.
Strict SDK verification correctly rejects the earlier AMD64 R11 and ARM64 R7
source bindings; their successful runs above remain dated evidence, not
current-head qualification. ARM64 loader native R1 compiled and linked before
that merge, but R2 was rejected on the changed header. Loader parity is open.
Both reference worlds and SDKs need refreshing against stable current inputs.

Replaying the recorded world profile first failed because AUTO_OBJ was placed
in SRCCONF, where Make deliberately rejects environment-only options. The
maintained frontend now exposes --src-env-conf (config key src_env_conf),
forwards SRC_ENV_CONF to every source Make step, retains /dev/null isolation
for loader construction and rejects qualification-context overrides. No Make
validation was bypassed. The frontend compiles through its maintained Makefile.
Six direct ATF cases pass: early configuration, ordinary configuration, plans,
architectures, object-environment isolation and production-loader planning.
The latter uses its packaged Python support layout; the initial source-directory
invocation failed on missing installed support, retained in the evidence.
The secureboot_plan case skips because virt-fw-vars is unavailable; this is
not a Secure Boot qualification result. Evidence:
bazel-src-env-frontend-review-r1-20261114 under /usr/obj/usr/src.
Make remains production/default; there is no host installation or reboot.

SDK preparation now distinguishes staged and explicitly Make-selected system
compilers. System selection requires matching cached Clang type/resource and
version macros, a target/sysroot match, and a complete LLVM tool map from the
resolved compiler directory. Missing tools never fall back to PATH. Plan format
3 binds these roles and the exporter implementation; ordinary Make references
do not acquire SDK-only LLVM-tool dependencies. The actual world compiler
resource and selected target SDK resource are separately recorded, not claimed
identical (the current target resource also installs ORC headers). This follows
the explicit target/sysroot/toolchain separation described in the
[Clang cross-compilation documentation](https://clang.llvm.org/docs/CrossCompilation.html)
and [Bazel toolchain configuration reference](https://bazel.build/docs/cc-toolchain-config-reference).
Fresh AMD64 R11 and ARM64 R7 snapshots fully verify source, execution-runtime
and payload hashes (8,345 and 16,682 files), with host ELF machine 62 and ARM64
target libc/drti machine 183. Their payload fingerprints equal the earlier
verified R10/R6 payloads despite corrected provenance. Evidence:
bazel-world-compiler-sdk-verify-r2-20261114 under /usr/obj/usr/src.

Final native AMD64/ARM64 R3 each passes the two explicit host-test targets:
seven compiler/world-binding cases and eighteen SDK source/staging cases. Cross
R1 correctly refused the original generic Python test kind; host-test declarations
were corrected rather than disabling cross-runner enforcement. Real startup
objects compile through both SDKs. The complete original Make FILES inventory
selects ten objects per architecture; all allocated data, symbols and relocations
match. Final R3 preserves every previously Make-qualified native object byte.
Raw Make equality remains 0/10 AMD64 and 2/10 ARM64; full DWARF is not qualified.
Evidence: bazel-world-compiler-sdk-native-{amd64,aarch64}-r3-20261114 and
bazel-world-compiler-csu-{amd64,arm64}-review-r2-20261114. No ARM64 code executes.

Conflicting input hashes now fail in environment capture, SDK export and staging;
previous bindings are not overwritten. Direct source-to-copied-payload mapping
and mutation-during-copy qualification still need explicit coverage as part of
gate 3. These snapshots remain Make-built seeds, not independent native bootstrap.
No frontend C argument or production backend default changes.

The maintained ARM64 production world run 20261114T131536Z-76523 completed
successfully at 14:23:19 UTC (4,063 seconds, 16 CPUs), source 685a13fd21e.
Its actual WMAKE metadata phase exported 241 sorted unique assignments,
TARGET=arm64, TARGET_ARCH=aarch64 and WITH_MALLOC_PRODUCTION=1. Evidence:
bazel-arm64-current-world-profile-r1-20261114 under /usr/obj/usr/src.
Although requested incremental, dependency cleanup discarded the old object
tree because its cached profile described debug malloc. This is not an
unchanged incremental performance baseline. The current SDK exporter then
rejected the normal SYSTEM_COMPILER world because it assumes a staged clang;
SDK R4 has not been created. Explicit world-selected compiler/resource binding
must be implemented and qualified; do not substitute a stale compiler.

A further SwitchBoard launch-error defect is reproduced: mkdirat succeeds,
openat returns EMFILE, and the leftover empty directory makes every retry fail
with EEXIST. The candidate removes only its newly created empty entry on open
failure, preserving errno. If removal itself fails, the entry remains rejected.
Ownership/rights-setup failure similarly removes the newly created empty entry
while retaining the parent descriptor through setup. Successful launch adds no
filesystem calls. Five direct host helper cases pass and the new retry case
fails against the original header. Evidence:
bazel-switchboard-container-open-review-r1-20261114. Native R1 now rebuilds the actual SwitchBoard and passes all three selected
regressions (fresh-only, failed-open retry and failed-cleanup refusal), with two
immutable captured files and manifest SHA-256
f1a8f18582df78800e75afcd27a2a1a88a00b005f28118a1ae064e8e9de5f8ff.
Evidence: bazel-switchboard-container-open-native-r1-20261114. This does not
exercise the ownership/rights-setup failure branch or establish a new VM result.

The runtime coverage audit retains eight required boot providers without useful
positive-operation evidence: Audit, Crypto, Device, Filesystem, Log, Network,
SystemExtension and Trace. Caller contexts must follow their installed manifests;
ordinary Device denial does not qualify authorized SYSTEM access. Evidence:
bazel-provider-operation-gap-audit-r1-20261114. The ARM64 constraint scan is
only a static candidate inventory: 1,066 BUILD files contain literal AMD64-only
constraints, including legitimate architecture-specific targets. It is not a
program count or portability verdict. Full ARM64 world remains substantial work.
All six gates remain open; Make stays production/default and BIP stays excluded.

The clean original-Make ARM64 production world completed successfully at
12:58:17 UTC (4,108 seconds, 16 CPUs), source c940c120059. Evidence:
/usr/obj/usr/src/build-runs/20261114T114948Z-90444. This is the reference world,
not a native Bazel ARM64 world, kernel, package or runtime qualification.

Inspection exposed a stale October .src_opts despite the current production
world. The maintained world metadata phase now atomically exports the resolved
SRC_OPT_LIST into OBJTOP/.src_opts, including architecture and allocator mode.
The inventory comes from src.opts.mk; new options need no parallel list.
The installed Make interface includes this helper in both Make and Bazel.
Native world-profile R2 passes five actual-Make regression cases, including
stale-profile replacement, write failure preservation and unchanged default
target selection. Its 72 regular share/mk installed files match the independent
Make reference in content, modes, ownership and package tags. Evidence:
bazel-world-profile-native-r2-20261114 and
bazel-world-profile-install-review-r1-20261114 under /usr/obj/usr/src.
The fresh AMD64 SDK R8 records updated build-metadata provenance and remains a
Make-built seed. R1 correctly rejected stale SDK R6 provenance. The normal
build-bsd world backend already invokes this maintained metadata phase; no new
frontend switch or alternate build path is needed. A real incremental ARM64
world/profile capture and refreshed cross SDK remain required before continuing
current-seed native ARM64 qualification. All six gates stay open.

The maintained original-Make reference producer now accepts an explicit
--dtrace-runtime-input manifest (format 1, one receipt/object binding), requiring
--make-meta. It validates the original Make component/target/compiler provenance,
receipt and object digests, canonical regular object-tree path and target ELF64
ET_REL ABI. It rechecks runtime, manifest, receipt, compiler and generator inputs
around each phase and at completion. Completed direct DTrace -G metadata recipes
must select exactly the bound syslibdir; missing/duplicate/conflicting selections
fail. The reference points directly to the original Make object, without SDK
mutation or native Bazel outputs used as Make inputs.

All four maintained reference option/generator/library/runtime test targets pass
in bazel-reference-runtime-tests-r1-20261114. New runtime regression coverage
checks seven cases plus invalid provenance/ABI/digest/recipe subcases. A fresh
independent optimized-production ARM64 libc reference passes with all three
regular/PIC/NOSSP provider recipes selecting the current Make-built drti:
bazel-arm64-libc-current-runtime-make-r1-20261114. Its complete archive symbol
graphs now match; provider non-DOF allocated code/data matches, including the
registration-state guard. Static/PIC orders remain 1,450/1,438 and shared metadata
passes. Raw provider DOF differences remain recorded, not relabeled byte parity,
in bazel-libc-compose-arm64-current-runtime-review-r1-20261114.

Further inspection isolates a separate stale generator input: the cached
original Make cross-DTrace generator still emits DOF_SECT_UTSNAME (1,280 bytes),
which the current dt_dof.c intentionally excludes for provider -G output. Native
Bazel's source-built generator already has the current behavior. Text relocations
also reflect the resulting __SUNW_dof object-size difference. A fresh current ARM64
Make world/bootstrap baseline is therefore next; do not ignore this field or
modify either compiled output to make the comparison pass. The reference build
still uses the explicitly older seed/profile and is not a current full ARM64
world/hardening/runtime result.
Existing build-bsd format-5 inputs select the tests and native producers. This is
a maintained comparison-helper input, with no C frontend option, production
backend, signing or publication-default change. Make stays production/default;
all six gates remain open and no host installation or reboot is performed.


ARM64 libc_nonshared now selects the actual portable CPU boundary. All twelve
members match the independent current-source original Make archive, including
allocated sections, external symbols and relocations. Its staged archive payload
and logical owner/group/mode/flags/pkgbase tags pass original Make comparison.
The public libc CcInfo interfaces and static/shared ABI probes now support ARM64;
the shared probe consumes the actual public ABI interface rather than the legacy
implementation link context. With iconv enabled, both probes exercise its wrapper
using the bounded invalid-handle error path, without conversion modules/data.
The ARM64 shared client contains a local hidden iconv_close wrapper, imports the
versioned __bsd_iconv_close implementation and needs only libc.so.7; the static
client has no dynamic dependencies. These are linked clients, not ARM64 execution.

ARM64 NOSSP libc builds all 1,437 members in exact Make order. Every non-provider
allocated/relocation contract matches; raw res_send path-derived alias and
provider differences remain retained. The six loader-extracted objects match
original Make NOSSP members exactly. Separate ELF-based validation verifies
provider attributes, schemas and actual instructions for all 14 ordinary and 19
enabled NOSSP sites. The older staged reference drti discrepancy still requires
fresh reference provider composition; these reports do not waive it or qualify
the full ARM64 loader. Evidence: bazel-libc-public-arm64-review-r1-20261114,
bazel-libc-nonshared-arm64-install-review-r1-20261114 and
bazel-libc-nossp-arm64-dof-review-r2-20261114. The first DOF diagnostic attempt
failed because LLVM nm's default AArch64 symbol filtering omitted aliases; it is
not recorded as a completed passing review.

That filtering exposed a maintained archive verifier gap: nm must explicitly use
--special-syms on AArch64 to retain $dtrace aliases. Both bulk and duplicate-member
symbol reads now request it. Make's .nossppico naming is also recognized. A new
source-reviewed host artifact test creates independent ELF/ar fixtures and uses
the declared real execution-host LLVM nm: defined and undefined aliases must be
visible on AMD64 and ARM64, and changed function names or lost definitions must
be rejected. Three test cases pass, including their architecture subcases. Native
ARM64 R3 passes this host-only inspection test; native AMD64 R2 passes all six
selected tests (public/static libc runtime, archive identities, both existing
DTrace regressions and the new symbol-visibility regression). Older raw ELF
allocated/DOF contracts remain independently checked; previous nm-only archive
symbol results must not stand in for the strengthened check.
A fresh complete NOSSP symbol review now reads all 1,437 members with special
symbols visible and matches the full strong-alias definition/reference graph.
Its sole ordinary-symbol difference is dof_registered in the reference provider,
retained as review-required in bazel-libc-nossp-arm64-symbol-review-r1-20261114.

A configured-graph review also found target-only NOSSP entering host DTrace's
bootstrap configuration. Before correction, ordinary/NOSSP consumers select two
host bootstrap configurations, one carrying nossp=true. The bootstrap transition
now resets that private libc setting to its normal false default without changing
target-object ABI selection. Actual before/after cqueries prove a single normal
host generator; all thirteen captured nonshared/client/NOSSP/loader/install
outputs remain byte-identical. Evidence: bazel-libc-bootstrap-nossp-before-20261114,
bazel-libc-bootstrap-nossp-after-20261114 and
bazel-libc-bootstrap-nossp-preservation-r1-20261114. This establishes configuration
separation/output preservation, not controlled CPU, memory or disk performance.
Existing build-bsd format-5 architecture/SDK/feature inputs select these rules;
no C CLI, production backend or publication default changed. Documentation and
maintained regression targets accompany the producers. Full R15/VM R11 evidence
predates these changes; all six gates remain open and Make stays production/default.


ARM64 libc now builds final static/PIC archives and libc.so.7 using source-owned
architecture selections in the common archive recipe and actual ARM64 version
maps. Architecture-specific context, syscall, long-double and optimized-string
order stays separate; common member lists are retained once. The archive rule
still rejects missing, extra or duplicate object identities. The library-owned
installation uses the no-SSP linker script selected by original Make on ARM64;
public CcInfo/nonshared/NOSSP linkage remains a separate pending boundary.

Optimized production ARM64 native R3 and portable-string/debug-malloc R2 pass
construction. Independent Make comparisons establish exact member order and
allocated/relocation contracts for every non-provider member: 1,450 regular /
1,438 PIC for optimized production and 1,443/1,431 for portable/debug. Both DSOs
pass the maintained shared metadata comparison, including SONAME, ordered NEEDED,
versioned imports/exports, version requirements and hardening. These are older-seed
component profiles; differing shared sections, full DWARF and runtime are not
waived. Full archive review reports retain provider bytes and path-derived alias
IDs as differences, rather than claiming raw byte equality.

The original ARM64 reference embedded an older staged drti.o: it lacks the
current dof_registered constructor/cleanup guard. A fresh independent original
Make drti build passes; the captured native drti matches its complete allocated,
external-symbol and relocation contract. Fresh reference-provider composition
with that current object is still required. Do not relabel the existing whole
archive reports passed. Current evidence:
bazel-libc-compose-arm64-review-r4-20261114,
bazel-libc-compose-arm64-portable-review-r2-20261114,
bazel-arm64-drti-make-r1-20261114 and
bazel-libc-compose-arm64-install-review-r2-20261114.
The latter passes debuglink CRC/GNU build-ID binding and Make metadata/content
checks for five core files, libxnet symlink and the debug directory. It is not
all libc catalogs, manuals, configuration, NOSSP or public-client linking.

Portable/debug comparison exposed allocator assertion identities containing
virtual include paths. Existing source-only CcInfo header roots now preserve
physical declared header identities; compiler prefix maps use declared source
alias execpaths and logical BSD source paths. No bazel-out configuration path or
compiled payload is hardcoded or rewritten. After correction, all non-provider
portable/debug allocator bytes/relocations match. Earlier portable review R1
retains the observed mismatches. The initial core-install request was rejected
for the AMD64-only linker-script constraint; native R3 includes the actual script
and passes, rather than omitting it from the payload.

AMD64 native R2 passes all five selected DTrace/archive/static/shared runtime
tests. Independent Make review R1 establishes 1,455/1,443 exact member order,
non-provider allocated/relocation equality and shared metadata; raw provider
alias/DOF differences remain retained for review. The ordering-only change was
also proven byte-preserving before the allocator header identity correction
(bazel-libc-compose-amd64-preservation-r1-20261114). Full R15 predates these
changes and needs refresh; no new full-system or VM claim is made.
Existing build-bsd format-5 architecture/SDK and malloc/optimization inputs select
the native producers. No C CLI, production backend or publication default change
is required. Documentation accompanies the source rules. Make remains production/
default; all six gates stay open, with no host installation or reboot.


ARM64 libc joint NSS/resolver/semaphore DTrace generation now passes with tracing
retained. The source-built generator still executes with the host ABI; a declared
bootstrap variant selects the existing DTRACE_TARGET_AARCH64 object rewriter
without changing the execution platform. The target-built drti remains ARM64.
The initial native R1 failure exposed the missing cross-rewriter selection;
R5 passes all six selected artifact targets. These are component builds against
the explicit older ARM64 SDK profile, not a current full ARM64 world.

The relocatable DOF verifier now checks AArch64 PREL64/ABS64 semantics,
matching object machines, bounded hidden function aliases and aligned NOP/RET
patches for both ordinary and enabled sites. Maintained regression coverage adds
wrong-relocation, mixed-machine, malformed-patch, unaligned and out-of-bounds
cases. All 35 verifier cases pass; AMD64 native R2 passes both maintained DTrace
regression targets and libc archive identity/static/shared runtime tests (five
selected tests). Existing linked AMD64 site-check semantics are unchanged.

Retained ARM64 review R3 compares all 56 transformed regular and 56 PIC objects
with independent original-Make production libc: allocated sections and relocation
contracts match; provider attributes and all 12 probe records match, with 14
ordinary and 19 enabled sites per variant checked against actual instructions.
Static hidden DOF anchors are checked. The res_send path-derived alias IDs differ;
the maintained symbol-graph verifier maps them only with equal validated DOF
schemas, exact function bytes, bounds and binding context. Raw differences remain
in the report. Five NSS/resolver assertion source identities were corrected by
compiler prefix maps on both CPUs, without rewriting compiled outputs.
Evidence: bazel-libc-dtrace-arm64-native-r5-20261114,
bazel-libc-dtrace-arm64-review-r3-20261114 and
bazel-libc-dtrace-amd64-native-r2-20261114. R3/R4 attempted ARM64 test selections
were rejected by frontend validation (selection/host-artifact declarations),
not counted as passing tests; regression execution is the explicit native AMD64
run. Complete member-set/composition/order, lexer and provider linking, DWARF,
current ARM64 world/hardening/runtime and full AMD64 capture refresh remain open.
The earlier cumulative component count is not increased by this focused proof.
Existing build-bsd format-5 architecture/SDK inputs select this implementation;
no C CLI, production backend, signing or publication default changes are needed.
Make remains production/default and all six gates remain open.


ARM64 sized-free, jemalloc and iconv groups now use explicit portable CPU
constraints; the existing FreeBSD jemalloc header retains actual per-CPU pointer,
page and virtual-address definitions. Production malloc policy stays an explicit
build input. All seven selected archives match independent original Make member
sets, allocated ELF sections, external symbols and relocations on both CPUs:
sized-free 2+2, jemalloc 62+62, iconv 22+22 and static-only iconv wrappers 11,
183 object variants per CPU. The ARM64 reference explicitly selects
MALLOC_PRODUCTION=yes (and omits test program construction only), matching the
requested native policy; no debug-malloc comparison or allocator mode substitution
is claimed. The separate PIC/hidden libc_nonshared interface still needs ARM64
qualification. No implementation source or compiled payload is rewritten.
Evidence: bazel-libc-allocator-iconv-arm64-parity-r1-20261114 and
bazel-libc-allocator-iconv-amd64-parity-r1-20261114.

AMD64 native R1 passes archive identities and static/shared libc smoke tests.
Full static/PIC libc source-payload digests remain equal to full R15, retained in
bazel-libc-allocator-iconv-amd64-preservation-r1-20261114. This extends target CPU
support without changing selected AMD64 library artifacts; full R15 remains the
latest complete selected package capture. Default ARM64 component coverage is
now 1,392 regular and 1,380 PIC members. The corresponding original-Make production
reference confirms 1,450/1,438 total members, leaving 58 members per variant
outside this cumulative component proof. Joint NSS/resolver/semaphore DTrace
processing, complete composition/order/linking, full DWARF, current ARM64 SDK/world,
hardening, runtime and controlled performance qualification remain open.
Existing build-bsd format-5 architecture/SDK/malloc inputs select these source
rules; no C CLI option, backend target or staging helper change is needed.
Manual/options updates accompany the producers. Make remains production/default;
no host installation, upgrade, reboot or combined repository publication occurs.


Full AMD64 R15 is terminal passed: all 450 indexed packages and 32 selected tests,
including static/shared libc smoke probes. It captures 1,616 files / 663,908,158
bytes, artifact-manifest SHA256
3ffb64bceaab90cb1acc4389385fbc20ed034d5351f8dad1a95d45ed9ed09da4.
All fourteen general-helper archives match the independently Make-qualified
focused AMD64 artifacts; retained bindings are in
bazel-libc-general-full-r15-binding-r1-20261114/result.json. This refresh includes
the general-helper identity corrections and supersedes R14 as latest full selected
package capture. The upgrade VM remains bound to R11; whole-system Make parity,
bootstrap, sandbox, resources/performance and publication gates remain open.

An additional original-Make ARM64 libc reference completes with explicit
MALLOC_PRODUCTION=yes and TESTS=no under the existing older SDK seed:
bazel-arm64-libc-production-make-r1-20261114/receipt.json. This prepares the next
allocator comparison with matching requested malloc policy; it is not native
Bazel allocator or current full-world qualification. No host installation,
upgrade, reboot or combined repository publication was performed.


ARM64 libc's ordinary general-helper groups now select explicit portable CPU
support, with target-correct rtld_machdep.h for loader/TLS-facing sources. The
new ARM64 loader header package does not enable or qualify the full ARM64 loader.
Eight compiler groups (fourteen archives) cover directory/blocks, process,
random, system helpers, support, loader imports and account code. All 174 regular
and 174 PIC member sets and allocated ELF/symbol/relocation contracts match
independent original Make on both AMD64 and ARM64. Ownership comes from Make
compiler dependency records plus declared architecture and cancelpoint source
lists, including contributed vis/unvis/pwcache inputs. The original ARM64 pass
found only vis/unvis diagnostic source identities remaining; declared compiler
prefix maps fix those imported identities without rewriting compiled outputs.
Final evidence: bazel-libc-general-arm64-parity-r2-20261114 and
bazel-libc-general-amd64-parity-r1-20261114. AMD64 native R2 also passes maintained
archive identities and static/shared libc smoke tests.

The semaphore group remains a separate unresolved DTrace contributor alongside
NSS/resolver; its probes are not disabled and its raw objects are not substituted
for the required joint provider processing. Full DTrace integration and provider
qualification remain open. Cumulative default ARM64 component coverage is now
1,295 regular / 1,294 PIC members against the older-profile 1,450/1,438-member
Make reference. This is not complete libc composition/order/linking, full DWARF,
current ARM64 SDK/world/hardening, runtime or controlled performance acceptance.
Full AMD64 R14 predates this general-helper identity correction; R15 subsequently
refreshes the package capture.
Existing build-bsd format-5 architecture/SDK inputs select these producers; no
new C CLI option, backend target or staging helper is needed. Manual/options
updates accompany the declarations. Make remains production/default; no host
installation, upgrade, reboot or combined repository publication occurs.


Full AMD64 R14 is terminal passed: all 450 indexed packages and 32 selected tests,
including static/shared libc smoke probes. It captures 1,602 files / 660,429,741
bytes, artifact-manifest SHA256
fa96101b4319506c9b1e9394eed6e2c204c7196c9b547c36097ee375032ab527.
All 34 portable component archives match the independently Make-qualified focused
AMD64 artifacts byte-for-byte; retained capture bindings are in
bazel-libc-portable-full-r14-binding-r1-20261114/result.json. This refresh includes
the portable-group assertion/source identity correction and supersedes R13 as
the latest full selected package capture. It is not whole-system Make parity,
native bootstrap, performance/publication acceptance or new upgrade-VM evidence;
the complete VM scenario remains bound to the earlier R11 candidate. All six
gates remain open, Make stays production/default, and no host installation,
upgrade, reboot or combined repository publication was performed.


Seventeen more portable libc groups now support AMD64/AArch64 through a shared,
explicit CPU constraint declaration: capability, compat-43, db, gmon, inet, isc,
locale, nameser, nls, posix1e, regex, rpc, secure, stdbit, stdtime, uuid and xdr.
All 280 regular plus 280 PIC members pass independent Make allocated ELF,
external-symbol and relocation comparisons on both CPUs. Reference inventory
classification accounts for imported kernel capability/ACL sources, copied ACL
source bytes, declared RPC protocol generation and contributed timezone code.
The original ARM64 build exposed 70 differing variants across 35 routines; their
instruction bytes match and differences traced to assertion filename identities,
including assertions in locale headers. Compiler source-prefix mappings now
preserve Make's logical source identities. For the kernel ACL source that Make
copies into its object directory, $(execpath) references the actual declared
source label and preserves the copy's basename; no bazel-out/configuration path
is hardcoded and no compiled output is rewritten. Official path-variable reference:
https://bazel.build/reference/be/make-variables and C/C++ copts contract:
https://bazel.build/reference/be/c-cpp#cc_library.copts.

Evidence: bazel-libc-portable-arm64-parity-r2-20261114 and
bazel-libc-portable-amd64-parity-r1-20261114. AMD64 native R1 also passes maintained
archive identities and static/shared libc smoke probes. The diagnostic identity
correction intentionally changes artifacts from full R13; earlier unchanged-byte
results do not qualify this change; full R14 subsequently refreshes packages.
Cumulative default ARM64 libc component coverage is now 1,121 regular and 1,120
PIC members against the recorded older-profile 1,450/1,438-member Make reference.
This is not full libc composition/order/linking, DWARF, current ARM64 SDK/world,
hardening, boot/runtime or performance acceptance. All six gates remain open.
Existing build-bsd format-5 architecture/SDK inputs select these declarations;
no frontend C option, backend target or tool staging change is required.
Manual/options documentation changes with the producers. Make remains production
and default; no host installation, publication, upgrade or reboot occurs.


ARM64 libc startup relocation now selects its actual aarch64/reloc.c rather than
AMD64's implementation. The syscall composition selects real ARM64 helpers,
handwritten cerror/vfork and generated ABI stubs; ordinary and shared syscall
bodies remain separate, and shared stubs retain Make's empty-body preprocessing.
The ARM64 vDSO implementation replaces x86-only pkru/vDSO support, while AMD64
keeps its original group ordering and source selection. Normal/NOSSP architecture
selection stays explicit without changing existing production defaults.

All twelve selected component archives pass independent original-Make member-set,
allocated ELF, external-symbol and relocation checks: 1,057 object variants.
Counts are CSU 1+1; C wrappers 61+61; static libsys additions 2; shared libc stubs
1; common interfaces 8+8; architecture helpers/vDSO 6+6; generated syscall stubs
451+451. Expected inventories come from original Make's actual SASM/SPSEUDO,
MDASM, INTERPOSED and libsys variant declarations, with included Makefile hashes
bound to the recorded Make include closure. Diagnostic parsing initially rejected
hyphenated basenames and looked for an external Makefile in the local source
inventory; retained failed diagnostics precede those explicit schema corrections.
Production inputs or comparison rules were not relaxed.
Evidence: bazel-arm64-libc-sys-parity-r3-20261114. Final native R2 captures match
all twelve qualified archive bytes, bound by bazel-libc-sys-arm64-binding-r1-20261114.

AMD64 archive identities and static/shared libc runtime smoke checks pass, and
full libc static/PIC archives retain completed R13 source-payload digests. Both
string component archives remain byte-identical as well. Evidence:
bazel-libc-sys-amd64-preservation-r1-20261114. Full R13 remains the latest complete
selected package capture; this is not a fresh full-package or upgrade-VM claim.
Together with earlier default groups, 841 regular and 840 PIC libc members are
now component-qualified against the 1,450/1,438-member older-profile reference.
Remaining groups, complete composition/order, DSO linking, full DWARF, current
ARM64 SDK/world/hardening and runtime remain required. Existing build-bsd format-5
architecture and SDK inputs select these producers; no C CLI, backend target or
tool staging change is needed. Manual/options documentation changes with the
source-owned declarations. Make remains production/default; no host installation,
upgrade, reboot or combined repository publication occurs.


ARM64 context/jump sources now have a native source-owned group selected by libc
composition, with the original NO_COMPAT7/ABI flags, shared C ldexp implementation
and declared textual scalbn input. All twelve regular and twelve PIC objects
match original Make's allocated sections, symbols and relocations. The loader's
standalone setjmp filegroup follows the new package boundary and matches the
actual source bytes. Proof: bazel-libc-arm64-gen-parity-r1-20261114.

ARM64 optimized strings now select actual BSD/Arm implementations, preserve
existing alias wrappers, generate only the six absent function wrappers and
three MOPS wrappers with normal expand_template actions, and declare the imported
assembly/header closure. All 94 regular and 94 PIC members match independent
Make allocated/symbol/relocation contracts, including IFUNC resolvers and MOPS.
The explicit MACHDEP_OPTIMIZATIONS=no native configuration additionally matches
all 87 + 87 portable members against a separate original-Make reference with
that option disabled (and test program construction disabled for the reference).
AMD64 keeps its optional archlevel implementation; ARM64 never selects that
AMD64-only group. No optimized routines are disabled to obtain a passing result.
The first build rejected a nonexistent declared zva64 assembly include; the real
BSD zva64 wrapper includes memset.S, now correctly declared. The failed build logs
are retained; no completed receipt was produced. No compiled object or ELF output is rewritten.

Final proofs: bazel-libc-string-arm64-parity-r2-20261114 and
bazel-libc-string-arm64-portable-parity-r1-20261114. The final combined capture
bazel-libc-gen-string-arm64-native-r1-20261114 matches all previously qualified
component bytes, retained in bazel-libc-gen-string-arm64-binding-r1-20261114.
AMD64's archive identities and static/shared libc smoke checks pass; both string
archives remain byte-identical to full R13 captures and full libc static/PIC
archives retain R13 source-payload digests. That binding is retained in
bazel-libc-string-amd64-preservation-r1-20261114. This is not a fresh full-package
or VM acceptance. Full R13 remains the latest complete selected package capture.

The default validated ARM64 libc groups now contain 312 members in each regular
and PIC variant, against the recorded older component SDK/profile. This is not
full libc composition/order, shared linking, DWARF equivalence, current full
world/hardening, ARM64 runtime or controlled performance qualification. Existing
build-bsd format-5 architecture and machdep_optimizations inputs select these
rules; no C CLI/backend option or tool staging change is required. The manual
and options document change with the source-owned rules. Make remains normal
production/default. No host installation, upgrade, publication or reboot occurs.


Full AMD64 R13 is terminal passed: all 450 indexed packages, 32 selected tests
(four executed, 28 cached), including newly selected static/shared libc smoke
probes. These exercise allocation, sorting, numeric/text conversion, streams,
regex/locale, mmap/protection, fork/pipe/wait and numeric address lookup; they are
bounded probes, not the complete libc suites. The hash-verified capture contains
1,568 files / 653,346,342 bytes, artifact-manifest SHA256
f286f3f54e409aea51534587a928868b2b938f57059d4bffdf96d42b17469e34.
All eight gdtoa/stdio/stdlib/string component archives match final focused AMD64
R4 bytes exactly; retained binding is
/usr/obj/usr/src/bazel-libc-full-r13-binding-r1-20261114/result.json.
This refresh includes the diagnostic source-identity correction. VM upgrade
proof remains bound to R11, and all remaining gates stay open. No host
installation or combined repository publication was performed.


ARM64 floating-point header selection now uses the ABI's actual _fpmath.h,
arith.h and gd_qnan.h, quad-precision machdep_ldisQ/strtorQ sources and generic
C division. AMD64 keeps its extended-precision sources and optional division
assembly. Unsupported floating-point header ABIs are incompatible rather than
silently selecting AMD64. The existing standalone ARM64 setjmp filegroup now
references the new source-owned package boundary explicitly.

Fresh independent Make libc components complete on both CPUs (ARM64 retains the
recorded older SDK/profile; AMD64 excludes test programs only for this library
reference). Native gdtoa, stdio and stdlib each pass all original-Make allocated
ELF, external-symbol and relocation contracts: 21 + 111 + 74 members in both
regular and PIC variants, 412 comparisons per architecture. Original Make
compiler dependency records and declared static-only source origins establish
the compared inventories; allocator/provider objects keep separate ownership.
The comparison first exposed assertion filename differences in eleven stdio
routines and rand, now corrected with declared compiler source-prefix maps on
both CPUs. No object or ELF payload is rewritten. Final evidence is retained in
/usr/obj/usr/src/bazel-libc-arm64-components-parity-r8-20261114 and
/usr/obj/usr/src/bazel-libc-amd64-components-parity-r8-20261114.

The earlier AMD64 preservation R2 checks all 588 affected gdtoa/stdio/stdlib/string
raw object variants against actual full R12 package payloads, but predates the
intentional diagnostic-source correction; it is not final byte-preservation
acceptance. Full R12 likewise predates that correction; R13 subsequently refreshes it.
These component contracts do not establish full libc archive composition/order,
DSO linking, DWARF equivalence, current ARM64 world/hardening or runtime.
Existing build-bsd format-5 SDK/architecture inputs select these source producers;
no new C CLI option or backend target is needed. The manual and options document
are updated with the declarations. Make stays production/default; no host
installation, publication, upgrade or reboot occurs.


Full AMD64 R12 is terminal passed: 30 expanded tests and the full selected
450-package target, with 1,559 captured files / 647,928,098 bytes. It refreshes
the compiler-runtime correction that postdated R11. Its artifact-manifest SHA256
is 29867a9b319ca61485468fe63a4656ed2f3ef271b5b48e8e960619f5c80edf75.
This does not replace the R11 candidate's VM evidence or close remaining gates.

ARM64 libsys now declares architecture-owned headers/sources, generated getcontext,
compatibility-syscall exclusions, GNU feature notes, generic thread helpers and
version-map inputs. WANT_HYPERV and the pkru manual stay x86-specific. Both
471-member archives pass original-Make member/order/allocated/symbol/relocation
contracts. Shared SONAME, imports/exports/versions, dependencies and hardening
metadata pass, as do logical installation records, the reference-created debug
directory, 418 header/manual payloads and native split-debug binding. Shared ELF
section bytes still differ (including text/unwind/dynamic relocation and DWARF);
this is not exact shared-code/full-DWARF or ARM64 runtime acceptance. The original
Make reference uses the recorded older ARM64 SDK/profile. R1 order mismatch and
driver tool/directory handling diagnostics remain retained. R3 also captures the
explicit rtld PIC dependency boundary, without qualifying a complete ARM64 rtld.
AMD64 R4 passes both syscall runtime tests and preserves all 424 install records
and 242 file payloads exactly against completed full R12. A malformed initial
AMD64 request was rejected because tests were not listed as selected targets;
the corrected request adds them explicitly without relaxing validation.
Evidence: /usr/obj/usr/src/bazel-arm64-libsys-parity-r3-20261114 and
/usr/obj/usr/src/bazel-amd64-libsys-preservation-r1-20261114. Existing build-bsd
format-5 architecture/SDK inputs select these producers; C CLI and backend targets
need no new option. Source declarations, installation inventory and manual change
together. Make remains production/default; no installation/publication occurred.


Fresh signed full-R11 upgrade VM R3 is terminal passed: all 34 high-level checks,
143 root operations, normal shutdown, unchanged backing image/source bindings,
new-kernel SSH/su positive/negative cases, rollback authentication/services,
shared-file persistence and unused-BE deletion. It reclaims 2,828,603,392 bytes.
Its 2 GiB guest records max sampled QEMU RSS 3,340,582,912 bytes and overlay peak
2,155,889,152 bytes, within unchanged 4 GiB/8 GiB observation budgets.
The declared upgrade phase is 5,400 seconds and whole run 9,000 seconds; all
checks stay enabled with verbose per-package checksums and failure journaling.
Actual vm_seconds is 1,679.79; this shared-host TCG run is not a controlled
performance comparison. Each service phase validates 13 installed-manifest boot
units and six selected ordinary-session operations, not every provider protocol;
all_provider_operations_qualified remains false. Evidence is retained under
/usr/obj/usr/src/bazel-current-upgrade-vm-r3-20261114 with complete signed
repository R3 and full R11 kernel/package bindings. R1/R2 timeout results remain
unchanged and are superseded only for this exact fresh candidate's scenario.

Compiler-runtime native declarations now select actual AMD64/AArch64 sources,
with 125 independently compiled size/model atomic variants and explicit archive
member order. ARM64 R3 passes original-Make comparison for every one of 276
members; final AMD64 R2 independently passes all 165 members. Both comparisons
check allocated ELF, external symbols/relocations, order and logical installation
metadata without rewriting outputs. AMD64 runtime tests also pass. The initial
ARM run exposed an omitted direct CPU-model .inc input, now covered by the
maintained CPU-model include inventory. A follow-up found 15 abort diagnostic
filename differences; declared CRTSRC prefix maps fix them on both architectures.
The earlier AMD preservation result predates that intentional source-identity
correction and is not the final acceptance claim. Native metadata uses symlink
while MTREE uses link; the diagnostic's original schema assumption was retained
as failed, then corrected explicitly. AMD's original world METALOG has no file
hash, so its staged reference bytes are independently bound to the completed
Make package receipt and payload instead of inventing a field.
Evidence: /usr/obj/usr/src/bazel-compiler-rt-arm64-parity-r3-20261114 and
/usr/obj/usr/src/bazel-compiler-rt-amd64-parity-r2-20261114. These are component
allocated/installation contracts, not DWARF/full-world or ARM64 runtime proof.
The runtime producer change postdates full R11; R12 subsequently refreshes its
package capture, but the VM scenario above remains bound to R11. Normal build-bsd uses the existing architecture/SDK
inputs and source-owned producers; no C option or backend-default change applies.


The maintained split-debug checker now additionally requires valid GNU build-ID
notes on both files when either has one, and equal identities within the pair.
ELF class/type/symbol policy, debuglink filename and CRC checks remain strict;
files with no GNU identity on either side retain their existing supported policy.
A retained before/after real-module probe shows the legacy checker accepts five
CRC-consistent identity/format faults, while the new checker rejects them. The
new native module test passes seven cases; both existing retained-symbol tests
and the runtime journal/policy tests also pass in focused checker R1. Its Bazel
report records five outer passing test cases; script logs contain the individual
unittest cases. Current kernel parity/debug regression R5 passes as well.
Evidence: /usr/obj/usr/src/bazel-debug-build-id-draft-r1-20261114 and
/usr/obj/usr/src/bazel-closeout-checker-native-r1-20261114. This strengthens own-pair
binding; it does not accept cross-build module ID differences or establish full
DWARF semantic equivalence. The generic module comparison remains strict.
Existing build-bsd format-5 inputs select the maintained tests; helper, tests and
manual change together without a new C option or production backend switch.


Full AMD64 R11 completes with all 27 expanded tests, 450 indexed packages and
1,556 captured files / 647,862,684 bytes. Kernel parity R5 again passes strict
allocated/symbol/CTF checks, matches the full R11 kernel payload digest and passes
kernel split-debug positive/five-rejection regression checks. The maintained
focused checker run passes all five selected suites. R10/R11 index inspection
finds only bsd-build, kernel-generic and kernel-generic-dbg archive digests changed;
this is an index observation, not complete unpacked-payload comparison.

Fresh VM R2 is terminal failed at rollback checksums after its 3,600-second phase,
not a passing upgrade. It completed 28 checks and 116 recorded root operations,
including new-kernel SSH/su and manifest services plus rollback console. The
partial rollback scan reached eight progress dots. Source inspection confirms
these are coarse per-package progress, not a completed scan or a proof of hang.
Observed max QEMU RSS is 3,344,449,536 bytes and overlay allocation 2,176,692,736
bytes, within declared budgets; these are not controlled performance figures.
The runner previously omitted the failing operation's record when a deadline
raised. It now always journals process status, elapsed time, error and partial
output hash after child cleanup, and never binds a pre-existing log to an attempt.
Seven actual-process tests pass locally and through maintained Bazel; policy tests
also pass. Full checksum scans now use pkg's verbose per-package diagnostics,
without dropping verification. No host installation or publication occurred.
Normal frontend C options are unchanged; the maintained VM helper, tests, source
bindings and manual are updated together.


Seven-module source-identity follow-up R3 now builds all 21 module/full/debug
outputs and passes the maintained inventory test. Independent per-module review
retains only allocated GNU build-ID digest differences for if_lio, jedec_dimm,
p2sb, sdio, superio, tcp_bbr and tcp_rack: all other allocated contracts,
relocations and external symbols match Make. All seven CTF payloads are byte
exact; all native split-debug checks pass and each native binary/debug build ID
matches its own pair. Strict comparison still returns review-required; no build-ID
waiver or completed module acceptance is claimed. Evidence is retained in
/usr/obj/usr/src/bazel-module-source-identity-review-r1-20261114, with public
capture bindings, original Make references and checker/driver hashes.
The source correction declares each module's relative source-directory identity
from its maintained recipe, uses lexical repository-prefix mapping at compile
time and preserves the default canonical policy elsewhere. No product action
queries Make and no ELF bytes are rewritten. Shared AMD64/cross declarations
support the input; cross-module builds/runtime are not established by this run.


Configured-output query correction: the seven-module follow-up exposed two
configurations for the export-all superio alias (trimmed and untrimmed test
fragments). The strict inventory correctly rejected duplicate actual labels.
Public cquery JSON protocol inspection retains both checksums; config(..., target)
selects all 21 requested roots once, including the alias. Maintained target and
test inventory queries now use that operator, retaining duplicate, compatibility
and per-selector binding rejection. All 34 source inventory unit cases pass;
the real module R3 inventory passes and its native inventory test also passes
while product compilation continues. Evidence roots are
/usr/obj/usr/src/bazel-module-alias-query-r2-20261114 and r3-20261114, and
/usr/obj/usr/src/bazel-module-source-identity-native-r3-20261114.
The first read-only JSON diagnostic omitted the qualification JAVA_HOME and
failed on a different local JDK discovery; the next retained attempt restores
the declared environment. Product frontend execution already supplies it.
The earlier module R1 also retains a rejected unsupported Starlark hex escape,
corrected to octal before R2. R2 retains the alias ambiguity failure. No component
is dropped to avoid these failures and no duplicate result is silently selected.
No C option or production backend selection changes; the maintained format-5
backend, query helper, tests and manual carry the correction together.


ARM64 CSU native R3 now completes successfully, including the real target/host
preprocessing ABI regression. The independent original-Make comparison passes
all ten installed startup objects: exact allocated sections, symbols/relocations,
ELF64 AArch64 relocatable identity and logical installation metadata. The parent
production archive selects identical child bytes. Evidence is retained under
/usr/obj/usr/src/bazel-arm64-csu-parity-r1-20261114 with public capture bindings,
original reference hashes, maintained checker hashes and the driver.
This is the actual component build with recorded older Make ARM64 seed/profile,
including WITHOUT_BRANCH_PROTECTION, not a refreshed full ARM64 world, native
bootstrap, complete DWARF comparison or runtime acceptance. Continue compiler
runtime/libsys/libc/threads/rtld and full Tier 1 world/kernel/pkgbase/runtime work.


Cross-generator correction: SDK staging now declares configured_compile_inputs
using the execution ABI from the bound host receipt, while retaining the existing
narrow compile_inputs groups. The generator's explicit compiler-containment guard
is unchanged. Six source declaration sites (including repeated shell/ncurses
variants) select that configured group. An execution_c_runtime role supplies the
host libc/libsys for source-built ncurses helpers, separately from target libraries.
The initial ARM64 R2 experiment using all_files passed the previous analysis
boundary but failed three ncurses generators on target libc's unsupported machine.
Its logs remain retained. That broader input change was discarded after review
of the documented October 26 input-size regression; no all_files workaround is
part of the final source change.
Fresh native SDK R6 verifies 8,345 files and component cross SDK R3 verifies
16,193 files. AMD64 script-cpp R1 passes the new actual target/execution ABI test
and builds the affected shell, sysdecode and ncurses generator outputs. ARM64
CSU R3 also passes that ABI test, retaining strict narrow compiler declarations;
its remaining host-linker/startup build and original-Make comparison are pending.
The test preprocesses real declared OS headers in both configurations and checks
CPU, pointer width and an expanded OS version without executing target code.
Evidence roots: /usr/obj/usr/src/bazel-script-cpp-amd64-native-r1-20261114,
/usr/obj/usr/src/bazel-csu-arm64-native-r3-20261114,
/usr/obj/usr/src/bazel-closeout-sdk-r6-20261114 and
/usr/obj/usr/src/bazel-arm64-csu-sdk-r3-20261114. SDK R3 remains an older Make
ARM64 component seed, not a current world or native bootstrap proof. Runtime VM R2
is still running. Normal build-bsd format-5 inputs and SDK staging helpers carry
this change; no new C option or production backend default is introduced.


ARM64 startup declarations now share the source-owned CSU recipe with AMD64,
including distinct startup variants, ordered partial links and installed metadata.
AMD64 native component R1 builds; preservation audit R2 proves all ten object
bytes and exact installation rows unchanged against completed full R10, and the
parent production archive selects the child bytes. Audit R1 failed in its own
inventory parser on directory/link records without source fields; driver/result
remain retained, and R2 selects source-bearing records explicitly.
Fresh component cross SDK R2 verifies 16,193 files with current AMD64 execution
SDK R5 and the explicitly recorded older Make ARM64 seed. Native ARM64 CSU R1
is rejected during analysis: ncurses nomacros_header selects the host compiler
but its hardwired compile_inputs names the target bundle. Preserve this declared-
input rejection; correct the generator's selected C toolchain dependency before
retrying. No ARM64 startup parity or full current world/runtime acceptance is
claimed. Existing build-bsd format-5 architecture/SDK inputs are used; no C option
or production backend default changes. Evidence roots are
/usr/obj/usr/src/bazel-csu-amd64-preservation-r2-20261114,
/usr/obj/usr/src/bazel-arm64-csu-sdk-r2-20261114 and
/usr/obj/usr/src/bazel-csu-arm64-native-r1-20261114.


Full selected AMD64 R10 now passes all 25 expanded tests with the equivalent
explicit CTF version label. Its immutable capture contains 1,554 files totaling
647,801,494 bytes. The actual packaged kernel is independently extracted from
the uniquely claiming package and matches both its captured payload inventory
and focused R11's strictly qualified kernel SHA-256
281e7f04efa2f3ef47aa73e3d5ea204e7915879c31cd6e6189997c268d2b3f3a.
Private upgrade repository R2 verifies all 450 packages, catalogue signatures and
actual wrong-key rejection. It is a disposable qualification fixture, not combined
hardware publication; configured repository pointers are unchanged.
Upgrade VM R2 is running with the same 2 GiB guest, explicit RSS/overlay bounds,
a 3,600-second upgrade phase and a 7,200-second whole-run deadline calibrated
from R1's measured timeout. No checks are removed. Do not report runtime success
until its terminal result proves every upgrade/rollback/persistence/removal check.
Evidence roots: /usr/obj/usr/src/bazel-closeout-system-native-r10-20261114,
/usr/obj/usr/src/bazel-current-runtime-request-r2-20261114,
/usr/obj/usr/src/bazel-current-upgrade-repository-r2-20261114 and
/usr/obj/usr/src/bazel-current-upgrade-vm-r2-20261114.
Normal build-bsd uses the existing maintained format-5 path; no frontend C flag
or production/default backend change is required for these qualification inputs.


Focused kernel R11 now passes the unchanged strict kernel parity checker R4:
allocated section metadata/content (GNU build-ID content separately reported),
loader symbols and merged CTF bytes match the independent current Make control.
The maintained split-debug checker also passes. The sole remaining R10 CTF
string-inventory difference was the omitted version label: R11 explicitly uses
Make's VERSION query, with command/source hashes retained in label-input.json.
No ELF payload or comparison output was normalized. Evidence is retained under
/usr/obj/usr/src/bazel-current-kernel-parity-r4-20261114, including captured-output
bindings, driver and both checker reports. This proves the focused equivalent-input
GENERIC kernel contract, not all package/debug/configuration/runtime gates or
automatic source-derived label selection. Refresh the full graph with that input
before constructing the next upgrade candidate.


Latest kernel follow-up: full AMD64 R9 passes all 25 expanded tests. Focused
kernel R10 additionally preserves imported PF built-in source identity from the
kernel's ../contrib declarations, without changing module source-path policy or
rewriting ELF output. The strict kernel parity R3 reaches its CTF-only rejection:
all allocated section contracts (GNU build-ID content reported separately) and
loader symbol identities match the independent Make control. The maintained
kernel split-debug check also passes. These are not complete kernel acceptance.
CTF inspection identifies a missing explicit version-label input: native uses
ctfconvert's unlabelled default while Make exports its source-derived VERSION.
The string inventories differ only in that label; exact CTF equality remains
required until an equivalent-input rebuild proves it. Automatic version-label
selection, full package refresh and runtime qualification remain open.
Evidence: /usr/obj/usr/src/bazel-current-kernel-native-r10-20261114/receipt.json
and /usr/obj/usr/src/bazel-current-kernel-parity-r3-20261114/result.json.


ARM64 preparation continues while AMD64 R7 remains the active full build.
The component cross SDK also passes full verification of 16,193 snapshot files
and explicit ARM64 target/AMD64 execution bindings; its recorded target seed
is older Make output, not a qualified native SDK or refreshed ARM64 world.
The original Make aarch64 CSU component reference passes; its separate retained
ELF/installation audit verifies all ten startup objects as ELF64 little-endian
AArch64 relocatables with matching payload hashes and logical clibs-dev metadata.
This uses the recorded older ARM64 Make SDK and does not qualify a current ARM64
world, native CSU producer or runtime. The shared CSU declaration patch remains
a temporary unapplied draft until the AMD64 capture is complete. The ARM64
libsys original-Make component reference now also passes; its ELF audit covers
the shared library and all 471 members of each static/PIC archive as AArch64.
This is a comparison baseline with the recorded older SDK, not native migration
or runtime acceptance. The ARM64 compiler-runtime Make reference also passes
with original recipe metadata: 151 regular sources and 125 separately compiled
outlined-atomic variants. All 276 installed archive members audit as AArch64
relocatables. A source-owned native draft preserves these variants and archive
order; it is retained unapplied beside the reference until the AMD64 capture
finishes and actual native comparison can run. No maintained
frontend behavior or production backend selection changes for this audit.

AMD64 R8 passes all 21 expanded tests with SDK R5; Bazel reports 89,830
cached actions and eight processwrapper actions. This is observed warm reuse,
not independent bootstrap or a controlled performance comparison. Matched-epoch
original Make archive R2 passes all 450 packages; its comparison removes every
mtime/nanosecond difference while retaining payload/size/manifest differences.
Bounded per-artifact diagnosis classifies 716 allocated-build-ID-digest-only
module differences, seven other module differences and one kernel classification
failure, without accepting any. The kernel-specific contract separately rejects
real allocated-section differences and CTF is not equal.

Two producer defects are now corrected: AMD64 built-in source paths lacked the
logical source-root prefix, and unconditional option re-addition reordered three
unchanged options in kern_conf. Native input-fix R4 passes all five suites,
including eighteen actual parser cases across the three source platforms.
Earlier failures remain recorded: execution/target runfile configuration,
standard location expansion, precreated empty Bazel tree outputs and omitted
RISC-V SoC metadata in the test closure. Collision and stale-content guards stay
strict. Rebuild the full selected graph before claiming the kernel fixes pass
allocated/symbol/CTF/debug or runtime parity.

The R7 upgrade VM passes new-kernel boot/authentication/manifest service checks
and boots back into the old BE, then exhausts its 2,400-second upgrade phase
before rollback checksums and unused-BE removal. Its result remains failed.
Observed installation took 910 seconds, candidate checksums 394, active checksums
260 and new-boot checksums 237; a fresh bounded budget must cover all remaining
checks under TCG. Keep the 2 GiB guest and memory/disk budgets, and qualify the
corrected kernel before launching the next complete upgrade run.

Current indexed ELF review completes with 1,325 passing contracts and 724
review-required results, confined to the kernel and module packages. Raw notes,
allocated sections and relocations remain strict; no differences are waived.
The maintained Make package recipes now pass the resolved explicit epoch to
pkg -t and honor PKG_OUTPUT_DIR for world as well as kernel placement. The real
pkgbase-inputs regression R2 passes PKG_TIMESTAMP=0 and SOURCE_DATE_EPOCH=946684800
with three actual packages each, matching payload and manifest file timestamps
and unchanged latest/latest-built pointers. R1's incorrect expectation for the
two format-metadata header timestamps is retained as a failed test; those
headers are independently zero in pkg's buffer writer. Fresh independent Make
archives with matched epoch inputs are still required. These Makefile changes
stale the old source-bound SDK receipt; prepare a fresh SDK before further native
runs, rather than rebinding R4. Fresh SDK R5 now passes full verification of
8,345 files and has a byte-identical toolchain snapshot to R4, with new source
bindings. Full AMD64 R8 is running with that SDK and both retained-symbol tests;
cache reuse and its final outcome remain unproven until completion. Original
Make matched-epoch archive rebuild R2 is running in a separate output directory
under the standard repository, preserving the first 450-package reference.
Normal build-bsd uses the maintained backend
changes; no new C option or production backend switch is introduced.

The current original-Make split-debug reference audit passes all 724 kernel/module
pairs. The first strict userland audit passes 1,077 pairs and reports two bootloader
DSOs whose source policy deliberately retains symbol tables. A general strict
retain-symbols checker draft preserves default rejection, requires symbols in
retain mode and passes real artifact/rejection tests. With that explicitly
selected draft, original-Make reference policy discovery passes all 1,079 world
pairs (1,077 stripped, two retained). There are no pathname waivers. After R7 completed, the checker change was applied. Both real native userboot
artifact regression targets pass through the current frontend (twelve unittest
cases), including missing-symbol, CRC, filename and policy-conflict rejection.
Full current native package debug-pair policy comparison remains required.
Inputs/results are retained beside the fresh stages.

The refreshed original Make archive creation now passes all 450 selected packages
at /usr/obj/usr/src/repo/FreeBSD:16:amd64/16.0.qual.20261114. Its result binds
both fresh stage results, all archive hashes, commands and unchanged latest and
latest-built pointers. No catalogue signing/combined publication occurred.
Fresh corrected SDK R4 verifies 8,345 snapshot files, schema 2 and a separate
four-declaration count. Artifact-contract native R3 passes all six suites through
the current C frontend, including actual stager-to-source-consumer metadata.
Full selected AMD64 native R7 now passes all nineteen expanded tests, using the
exact Make vers.c revision dev-n288204-e4d2059c4b4f and matching package version.
Its verified capture contains 1,551 files / 647,563,521 bytes. The complete
450-package copy verifies; current archive comparison reports identical package
sets but raw payload/timestamp/size differences, not full parity. ELF review and
the signed inactive-BE upgrade VM are running. The current manifest-derived
service helpers and signed-repository/wrong-key controls pass. No wider gate
is closed by build action success.

Captured R6 compiler/runtime exploration now passes with a package-derived ELF
NEEDED closure, native runtime linker and verified loaded paths: eight packages,
eighteen selected payloads, compiler/linker version checks and six compile/link
ELF-machine checks over AMD64, ARM64 and RISC-V. The missing-library-directory
negative reveals actual host fallback and rejects it through loaded-path checks.
Follow-up toolset R2 extends the same package-derived runtime containment checks
to all eight compiler-tool roles: clang, cpp, LLD, ar, nm, objcopy, strip and
objdump. Eight packages and twenty-four selected payloads satisfy those checks;
the six header-free compile/link checks still pass. This remains frozen R6
exploration, not a maintained SDK producer or a complete bootstrap qualification.
This is an explicitly retained exploratory probe, not a maintained SDK producer,
independent second-stage world, architecture runtime or sandbox qualification.
It supplies evidence for the remaining native SDK/runtime boundary work without
changing source producers or normal build-bsd behavior. These documentation-only
updates are not source inputs of the running native graph or the SDK receipt.

Stable-head Make world refresh R2 and current GENERIC/CTF kernel/module R1 now
pass at e4d2059c4b4, with clean unchanged source before/after. Fresh private
NO_ROOT world and kernel stages also pass. Their original logs, input hashes and
world option snapshot are retained under /usr/obj/usr/src/bazel-current-make-*.
This supersedes the earlier clean-world result's source-review limitation for
the refreshed build scope, not full package/runtime/performance acceptance.
No host installation, hardware build or repository publication was performed.

Native artifact-contract R2 is rejected before Bazel actions: the preparer confused
freestanding_toolchains schema version 2 with four generated declarations.
Restore the schema field and derive a separate freestanding_toolchain_count;
keep the consumer's rejection strict. A producer-to-consumer regression runs
actual generated metadata through source SDK/platform validation. Fresh staging
and native rerun are required; do not repair existing receipts in place.

The maintained SDK preparer now supports explicit preparation format 2: a target
SDK root and complete execution compiler map, with no objtop or implicit Make
layout. Existing format 1 remains the declared Make-object adapter. Thirteen host
selection/declaration cases pass; full explicit-mode fixture R2 materializes and
verifies 8,344 snapshot files without reading the live Make object tree. That
fixture deliberately uses frozen older Make-produced seed bytes and is not a
current or native-produced SDK. The initial count change was incorrect: freestanding_toolchains is schema 2,
not a count. The corrected producer reports a separate derived count; emitted
declarations are not architecture qualification. Existing qualification/SDK ABI receipt formats
and C frontend flags remain unchanged; preparation helpers/tests/manual change
together. Old source-bound SDK receipts require fresh preparation after these
helper/live-object changes; they are not rebound to suppress verification failures.

The initial R6 compiler probe R2 executes --version on the host; its package role correctly
resolves an archive hardlink to c++. This is not independent bootstrap: the thin
compiler still loads host shared libraries. The indexed native package inventory
contains the compiler/linker/header/library payloads. fidlc is intentionally
build-only and already has a native source-owned execution target, so its absence
from installed packages is not a base packaging omission. Native-produced target
and compiler-runtime closure, full second-stage builds, cache/sandbox/dependency
invalidation and controlled aggregate memory/disk I/O remain open.
SDK invalidation diagnosis R1 compares frozen SDK2/SDK4 metadata: 53 files change,
including six system headers, but no compiler executables. The current mandatory
compiler_files closure contains every SDK header. Upstream follow-up R2 rules
out enabling the experimental include scanner as a production fix: its own
option contract explicitly excludes full preprocessing semantics. Keep complete
declarations. After the stable AMD64 run, measure actual used/unused input
invalidation and evaluate supported compiler-generated .d discovery with declared
headers/CcCompilationContext, including generated, macro-selected and conditional
headers. Changing compiler_files_without_includes alone cannot fix this boundary.
See the hash-bound SDK invalidation diagnosis R1 and R2 records and
[Bazel 9.3.1 options](https://github.com/bazelbuild/bazel/blob/9.3.1/src/main/java/com/google/devtools/build/lib/rules/cpp/CppOptions.java#L828-L866).

The existing resource wrapper measures per-command max RSS and block operations, not parallel
aggregate RAM or physical disk bytes; it does not close gate 4.

R6's runtime linker now passes a general explicit SONAME-absence DSO metadata
contract against the index-verified Make package; named libc passes the same
checker's strict named-library contract. The parser separates descriptive GNU
VER_FLG_BASE output labels from public symbol versions, following LLD emission
and rtld's explicit skip of BASE entries. Raw labels/equality, section differences
and hashes remain reported. Both sides must have the selected SONAME/absence;
public versions, dependencies, symbols, dynamic flags and hardening remain strict.
Duplicate dynamic flag tags, malformed version rows and PIE DSOs are rejected.
All 89 final host cases pass (33 metadata, 22 archive/context, 30 DOF, four stream).
The combined native request is prepared for execution after the live current
Make world build releases its global lock. No producer/runtime bytes or frontend
flags change. The complete previous indexed report is not retroactively upgraded;
full ABI/debug/runtime, coherent current Make controls and all wider gates remain.

The frozen R6 PAM archive now passes its ordered member/full-symbol contract
against the index-verified Make package. Its twenty mapped alias groups include
nineteen merged groups resolved through validated emitted DOF context, rather
than ID ordering or a filename exception. A real R6 archive with one corrupted
probe instruction is rejected while its member/symbol inventories remain equal.
Host regressions pass 22 archive alias/context, 30 relocatable DOF and four package
stream cases. Native tests are prepared but currently blocked by the maintained
frontend's global lock held by the fresh Make world build; they are not counted
as native acceptance. The parser is a declared data/binding input of its consumers.
No C frontend flag or production build setting changes. Full ABI/debug/runtime,
current full-review integration and the wider six gates remain open.

Combined native R6 passes the selected AMD64 world/GENERIC kernel/modules and
450-package graph at explicit kernel revision `0bb24324ee7`, all fifteen selected
expanded test reports and digest-verified capture of 1,547 files (647,575,911 bytes).
This integrates the libicp_rescue/libzfs order fixes. It still uses a Make-prepared
SDK; no bootstrap, runtime, production publication, performance or ARM64 gate is
closed by this build. R6 used the older qualification frontend executable; a fresh
current-source C frontend now passes the maintained package-review test via the
explicit --target-arch path. Wider current-frontend backend qualification remains.

Indexed ELF review R6 finishes all 450 frozen R5 packages with unchanged bindings:
1,321 contracts pass, 728 remain review-required and no selection differences exist.
All 734 ET_REL payloads are now covered: eleven pass exactly, 711 have allocated
GNU-build-ID-only differences (708 in the kernel package), and twelve kernel
modules have further bytes/relocations to review. The remaining five cases are
the two later-fixed archive orders, ambiguous PAM aliases and special kernel/loader
contracts. Raw diagnostics remain strict. The read-only module diagnosis identifies
canonical versus redundant-slash/../ source strings in eleven modules; mqueuefs
also has real source fixes after the November 11 Make control. Neither observation
waives byte/relocation differences. Refresh the coherent current Make baseline
before treating source-epoch drift as a producer defect or claiming parity.

Large review output now streams JSON encoding without constructing a second full
serialized string; a real DTrace report remains byte-identical and the current
frontend's four maintained package-stream cases pass. This is not a measured
peak-RAM bound: per-package object retention still needs resource work. The kernel
report itself is about 925 MiB. A current production-malloc Make world control is
prepared through the freshly compiled frontend, with explicit src.conf, sixteen
jobs, standard /usr/obj and no installation/publication. The other six-gate work,
including Bazel in base and ARM64 Tier 1, remains required.

## Current closeout execution (2026-11-13)

The indexed reviewer now applies the existing boot-object ELF contract to ET_REL
payloads, comparing exact allocated bytes, external symbols and resolved
relocations with duplicate section occurrences preserved. Build IDs and DTrace
IDs are not normalized; debug-only contents and module loading remain separate.
Native relocatable review R1 passes all three selected test targets: ten real
ELF32/64 object tests, four archive-stream tests and twelve alias-graph cases.
The complete frozen R5 package recheck is running as indexed ELF review R6;
no acceptance count is inferred before its final unchanged-input checks pass.
There is no build-bsd flag/C change; maintained reviewer inputs/runfiles and the
manual are updated with the same check. Other closeout gates remain required.

Focused duplicate-library order native R2 passes libicp_rescue/libzfs ordinary
archives, shared-library products and installation archives plus the ZFS daemon
unit suite (22 cases) and maintained DTrace alias test target. Independent R1
comparison passes both complete static member-order/symbol contracts, including
repeated member occurrences. Source groups retain the original GCM undefinition
and hidden-visibility flags; installed order follows the source recipe across
those groups. The first native attempt exposed a stale OpenZFS source-export
consumer; it is corrected and its failed preflight retained. These focused fixes
are not a new full combined candidate or ARM64 qualification.

Occurrence-aware archive review R2 now checks each repeated member through
LLVM ar's public xN selector, preserving its ordinal, symbols and multiplicity.
All sixteen real-artifact regression cases pass, including reordered, extra and
merged duplicate-member negatives. Four of the six previously unsupported real
archives pass; libicp_rescue and libzfs expose actual member-order differences
and remain unaccepted. This refines the prior 743 review-required cases rather
than retroactively changing R5. The indexed review's failure evidence now uses
the same occurrence-aware representation. No build-bsd C/CLI input changes are
needed; its maintained checker/manual are updated. Other six-gate work remains.

The complete count-preserving indexed R5 review finishes all 450 combined-build
packages with verified final input hashes and no selection differences. It passes
1,306 ordinary ELF/archive contracts and retains 743 review-required cases:
734 ET_REL objects outside that contract, six duplicate-member archives, PAM's
ambiguous alias mapping, and special kernel/loader representations. No ordinary
program/shared or supported static archive order/symbol differences remain in
this selected candidate. This is not full ABI/debug/runtime or whole-system parity.
Strict R7 still retains content/size/timestamp/manifest diagnostics.

The maintained frontend now preflights every explicit product using public cquery
with the exact selected configuration/environment. It binds aliases to actual
configured targets, rejects missing/incompatible requests before main build/test
actions and hashes the resulting inventory into receipts. Final end-to-end R2
passes a real libc alias plus all 34 inventory tests; missing and wrong-platform
products are rejected with no main invocation. Earlier prototype failures remain
recorded. This closes the known late-invalid-product inefficiency, not the wider
native bootstrap/output-query/cache/sandbox gate. Make remains production/default.

The new complete `bazel-closeout-system-native-r5-20261113` run passes the selected
current AMD64 world/GENERIC kernel/modules/450-package graph at explicit kernel
revision `5e12086b5cbd`, all thirteen selected tests and capture of 1,545 verified
files. It combines all focused ordering fixes. Separate review then reproduced a
checker defect: repeated ELF local names were collapsed into sets. The parser
now retains multiplicity; twelve real-artifact cases and twelve native alias
contract cases pass, including the formerly accepted extra-symbol negative.
Prior symbol-only reviews did not establish multiplicity and are not upgraded
retroactively. Fresh complete R5 artifact review with the corrected checker is
required. PAM's ambiguous ID mapping and all wider closeout gates remain open.

Libc order native R2 passes ordinary/PIC/NOSSP/shared/install products and all seven
runtime/identity/analysis rejection tests. Independent R2 comparison passes its
ordinary and PIC archive member/full-symbol contracts and shared metadata against
verified Make packages. The native configured composition data also matches all
48 recipe-order checks across sixteen iconv/NIS/machine/DTrace combinations;
that declarative comparison is not qualification of sixteen configured builds.
All thirteen identified archive-order defects now have focused producer fixes.
A fresh complete candidate is still required, as are PAM alias resolution, other
artifact/debug/configuration checks and the remaining six-gate requirements.

Libarchive/liboes provider-order native R1 passes both archive/shared/installation
families and six maintained test targets (eleven reported cases). Independent
review R1 passes both complete archive member/symbol contracts and both shared
metadata contracts, retaining explicit DTrace ID mappings where needed. Their
original source inventories/compile-group options remain intact. Twelve of the
original thirteen order defects are fixed; libc remains. These later focused
outputs still require complete system integration, and all wider gates stay open.

The maintained archive symbol checker now maps path-derived DTrace IDs only by
an unambiguous whole-archive member/function/kind incidence graph, preserving raw
symbols and an explicit bijection. Eleven native adversarial cases and all ten
existing real-artifact cases pass. Fresh hash-bound rechecks accept fifteen of
the sixteen previously ID-only archive differences; PAM remains rejected because
its merged module has ambiguous alias graphs. This is symbol metadata evidence,
not DOF relocation, registration or live probe acceptance. Raw prior reviews stay
unchanged; the three outstanding archive-order defects remain separate.

Libzpool focused native R1 now passes archive/shared/installation construction and
the queue selftest target (all eight selftests reported OK). Independent review
R1 passes the full 204-member archive order/symbol contract and shared metadata.
Compression flags remain selected independently from installed member order using
one maintained source inventory. Ten of the original thirteen archive-order cases
are fixed; libc, libarchive and liboes remain. Focused later outputs still require
complete candidate integration and the other six-gate requirements remain open.

Ncurses/tinfo focused native R1 passes both static/shared products, the normal
installation archive and the maintained API integration test. Independent review
R1 passes both complete member/symbol and both shared-library metadata contracts.
Their 109/60 source identity sets are unchanged; generated sources now retain
original recipe positions through shared compilation/archive declarations.
Four original archive-order cases remain: libc, libzpool, libarchive and liboes.
These later focused fixes are not yet a new complete candidate or ARM64 proof.

Focused libsys archive-order native R1 passes ordinary/PIC archives, shared and
installation outputs and both selected syscall runtime tests. Independent review
R1 passes all three Make contracts, including the complete 477-member order and
symbol table for each archive. The checker now handles Make's `.pico` spelling;
its ten positive/adversarial host cases pass. Six of the original thirteen
archive-order cases remain. These are later focused results, not another full
combined system build, native bootstrap or ARM64 acceptance.

Focused mixed-source archive native R1 now passes libdwarf, libpcap and
libibnetdisc products plus four DWARF/packet-filter tests. Independent review R2
passes all six archive/shared Make contracts. Generated DWARF/lex/yacc outputs
and interleaved C/C++ members use declared source order; no runtime Make query or
reference-output substitution selects the build. Seven of the original thirteen
archive-order cases remain. This is newer focused evidence, not a fresh complete
system candidate or RDMA hardware acceptance.

The completed indexed ELF R4 review covers all 450 frozen combined-build packages
with no selected payload differences: 1,275 contracts pass and 774 remain review
required (including 734 ET_REL inputs outside the checker contract). All 43 prior
NEEDED-order defects and zstream's import discrepancy are gone in that combined
candidate. Subsequent focused libdq ordinary/PIC correction passes its five tests
and static/shared Make contracts. Source-ordered libnv/libipsec/libelf archives
then pass all six archive/shared contracts and four roundtrip tests in native R3.
The original libelf generated-source order failure remains recorded in review R2.
These later focused fixes are not yet incorporated into a new complete candidate.

The newer `bazel-closeout-system-native-r4-20261113` receipt passes the combined
selected AMD64 world/GENERIC kernel/modules/450-package graph at explicit kernel
revision `4a75f49343bb`, including all seven selected tests and digest-verified
capture of 1,542 unique files. Independent package comparison R6 retains no
package-name, payload-path or directory-claim differences. It still reports
content, size, timestamps and manifest differences; complete parity is unaccepted.
The new indexed ELF/archive review is a separate diagnostic, not implied by build
success. The SDK is still Make-prepared and the normal backend remains Make.

Bazel itself is not yet a base payload: the host uses the ports package
`bazel9-9.3.1` at `/usr/local/bin/bazel`, and the selected 450-package index has no
Bazel package. Shipping and qualifying Bazel in base remains required under gate
5, including its runtime dependencies and fresh-install build usability. Keep the
previously agreed OpenJDK build dependency boundary explicit; do not claim that
using Bazel to build base makes Bazel part of base.

The completed `bazel-closeout-system-native-r3-20261113` receipt passes the
selected AMD64 world/kernel/module/450-package graph and all four selected tests
at explicit kernel revision `83d696e46e20`. It captures 1,539 unique files with
verified output digests. This is the selected source/configuration epoch, not
native bootstrap or qualification of subsequent changes.

The independent R3 archive comparison covers all 450 packages. No package-name
or nondirectory payload-path omissions remain, and the two shared-library
requirements mismatches are gone. That R3 comparison retains byte/size, timestamp
and directory-claim differences; the later R5 comparison closes the latter.
Complete package parity is not accepted.
The subsequent directory-policy native R3 run passes the complete 450-package
graph and three selected tests, including immutable capture. Independent R5
comparison now has no package-name, payload-path or directory-claim differences.
Source-owned DQ/OpenSSL installation declarations and explicit world/kernel
ancestor policy fix the ten prior directory mismatches; physical directory
metadata remains enforced. Byte/size/timestamp and manifest-file diagnostics
remain, so final parity is still unaccepted. Native R2's digest-capture rejection
is preserved, not counted as acceptance. See the Make closeout record.

A two-header SDK change accompanied broad compile invalidation; keeping the
same state directory does not establish acceptable incremental efficiency.

After that full run ended, the certctl staging-root METALOG fix was applied and
passes all 31 maintained host regression cases. Certificate native R3 passes the
producer/archive test (ten cases), construction-input test (seven) and world
inventory test (eight), through the maintained frontend. The captured complete
world inventory now includes all 168 generated certificate files, selected by
CAROOT/OPENSSL/CRYPT and reconciled from declared tree metadata. Image composition
uses the same declarations. The complete updated image/package graph now passes
`bazel-certificate-image-native-r1-20261113`, and its 2 GiB VM passes 15 normal
boot/authentication/installed-tree/default TLS checks with normal poweroff.
Ordinary-user fetch rejects an untrusted server, accepts it after normal local-CA
installation/rehash, rejects it after removal and restores the original bundle.
This is selected fresh-image acceptance, not a repeat of the full signed-BE
upgrade/provider/rollback scenario on this candidate. See the Make closeout record
for retained failures, source bindings and remaining gates.

Close remaining defects in batches against the retained Make control. Reuse the
Bazel state/cache and test the affected targets before repeating the complete
integration graph. Do not rebuild the Make control unless its relevant inputs or
required configuration change. Preserve raw differences and historical failures.
See MAKE-CLOSEOUT-CONTROL-QUALIFICATION.md for the current comparison and bounds.
All six gates below remain the completion criteria; Make remains production/default.

The indexed ELF review now covers all 450 frozen candidate packages, accounting
for 1,817 non-debug ELF files and 232 static archives without selection omissions.
It passes 1,231 existing contracts and explicitly retains 818 review-required
cases, including 734 relocatable objects outside its scope. This does not close
ABI/debug/kernel/module or runtime gates. Focused newer native builds and Make
ELF comparisons pass ctfconvert/ctfmerge source LIBADD-order corrections and
zstream's missing Solaris compatibility-header dependency; all eight zstream
queue selftests and four bounded reviewer regression cases pass. Complete
integration of those newer fixes and the remaining library/archive discrepancies
is still required. See the Make closeout record for exact receipts and failures.
Focused corrected-source batches additionally pass independent ELF comparisons
for nine utility/RDMA programs, three Kerberos administration programs and two
plugins, and five ZFS/C++ products. The Kerberos database/KDC tests pass; zfsd's
newly qualified shared GoogleTest/regex closure passes all 22 unit cases. The
failed initial non-PIC test link is preserved. SSH/SystemExtension then passes
ten product comparisons and all 34 selected startup/policy cases. Twenty-nine
of 43 frozen-review library-order discrepancies then had focused corrections.
The LLVM batch now passes all fourteen remaining product comparisons and seven
code-generation/native-link/LTO tests. All 43 recorded library-order discrepancies
have focused corrected-source evidence; complete new-candidate integration and
independent archive/runtime comparison remain required. Archive/debug/kernel/loader,
configuration, ARM64, bootstrap/cache/sandbox, performance, publication and broader
runtime gates stay open.



## Independent Make closeout comparison (2026-11-11)

Fresh original AMD64 buildworld, GENERIC kernel/modules and NO_ROOT staging pass
at clean source d44de404cb7. The installed comparison against captured native R10
finds 245 additional Make paths and unaccepted raw byte/package diagnostics;
this is not parity acceptance. Seventy confirmed omitted installation paths now
have source-owned declarations/root edges. Focused native archive builds and
independent metadata/link/data/debug-CRC checks pass all 70 paths; raw binary
parity and full root/pkgbase integration remain open.
The zfsd Make selector now respects TESTS and GOOGLETEST; fresh staging and
the original complete-directory plist/package coverage preflight pass.
Certificate generated state and final artifact/package parity remain open.
See [MAKE-CLOSEOUT-CONTROL-QUALIFICATION.md](MAKE-CLOSEOUT-CONTROL-QUALIFICATION.md)
for exact evidence, observer limits and the independent configuration/bootstrap
input checks. All six completion gates remain; Make stays production/default.

## Runtime cleanup implementation (2026-11-11)

The confirmed early-read-only cleanup bug has a source fix. Cleanup runs once
before the first native launch, returns errors, and recreates the live-marker
directory before provider descriptor delivery. Maintained Make compilation and
three host regression cases pass. Fresh SDK materialization and native R3
qualification pass Switchboard, the inventory helper and all 11 selected tests.
The corrected service-aware VM R4 passes the complete upgrade/rollback/removal
scenario and selected provider operations. Broader provider coverage remains open. See RUNTIME-CONTAINER-CLEANUP-QUALIFICATION.md.

Full corrected-source R10 passes the selected AMD64 world/kernel/module/pkgbase
graph and both selected native tests at kernel revision 5b1325c979ab. Its captured
inventory contains 450 packages, including dq/dq-dbg/dq-dev. The complete signed
private VM repository passes verification and real wrong-key refusal. This is
not fresh Make parity, native bootstrap, ARM64 or performance acceptance.

The service-aware VM plan is prepared against the retained 447-package baseline
and the current 450-package candidate, with actual signed-archive kernel bytes.
The runner now executes selected ordinary-user operations after manifest-derived
readiness and also checks the active system after inactive installation. Native
service/inventory/upgrade policy tests pass. VM R3 passes all six selected
operations on the baseline and active system after offline installation. On the
new boot, Time and Sysctl pass, but Notify open fails with Broken pipe despite
all 13 required boot services reporting running. Rollback and unused-BE removal
are not reached. The original failed evidence is retained. Notify's two descriptor-receiving
processes now omit the incompatible NOFDRECV restriction, retaining the other
protections. Focused native qualification passes 68 cases; R10 contains the fix.
The complete signed private R5 repository passes verification and wrong-key
refusal. Fresh 2 GB VM R4 passes all 33 checks and powers off normally. Baseline,
active-before-activation, new boot and rollback each pass all 13 required boot
services and the six selected operations. Shared writes survive rollback and
unused-BE removal reclaims 2,818,023,424 bytes. Independent acceptance review
checks raw command hashes, service reports and resource bounds. This is selected
provider coverage and BIOS boot, not Secure Boot or complete provider coverage.
The probes do not cover all providers or authorized SYSTEM Device access.
The DQ resolution-ledger action now has declared inputs and is required before
native kernel linking; focused native R3 passes the checker and actual AMD64 link.
Actual source-addition/content/deletion invalidation and no-op reuse now pass
(R4-R8); independent captured-inventory and Make-checker comparisons pass too.
Broader sandbox isolation, sealed inputs and native bootstrap remain open under
gate 3. See DQ-SOURCE-AUDIT-QUALIFICATION.md. Maintained frontend target interfaces cover these BUILD
changes; production remains Make.


## Closeout status and required gates (2026-11-11)

The latest complete selected AMD64 build is November 11 R10: 450 packages,
kernel/modules and both selected native tests. It does not establish independent
Make parity or every optional configuration. The retained November 7 baseline is
447 packages and passes its original 14 normal login/SSH/su and installed-tree/
firstboot checks. Corrected VM R4 now passes the signed 447-to-450-package
upgrade, new kernel, authentication, selected operations, rollback, shared-file
persistence and unused-BE deletion. Other provider operations remain open.

The strict upgrade retry is terminal **failed**, not running:
`bazel-system-upgrade-vm-r2-20261107/result.json`. Its serial log confirms cleanup
returns EROFS while root is still read-only. That captured candidate predates
the lifecycle fix now committed and covered by host/native regression tests.
R3 then exposed the separate Notify admission defect. Corrected R10/VM R4
supersede both failures with actual selected-operation and complete-scenario
acceptance. R1's historical green result remains rejected and unchanged.

Close out in this order, retaining evidence for each required gate:

1. Fix runtime-container initialization ordering and error handling without
   adopting stale service directories. Check required services from installed
   manifests, then repeat complete upgrade/new-kernel boot, useful service
   operations, rollback, shared-data persistence and unused-BE removal in a VM.
2. Rebuild current AMD64 sources and complete maintained Make comparison for the
   required world/kernel/modules/pkgbase configuration, installation/debug/
   metadata contracts and outstanding configuration selections. Report exact
   scope; the previous snapshot is not current-head qualification.
3. Close native bootstrap/output-query and reproducible input boundaries; prove
   declared dependencies, incremental invalidation, cache reuse and sandbox
   isolation. The existing prepared Make-built SDK is not a native bootstrap proof.
4. Compare clean and incremental Make/Bazel builds with CPU, peak memory, disk I/O
   and retained disk usage. Include debug-package compression/cache behavior.
5. Integrate the qualified production backend into maintained build-bsd targets:
   world, kernel and pkgbase; preserve Make-based ports, separate hardware builds,
   kernel/hardware identity checks and verified combined publication under
   /usr/obj/usr/src/repo using /usr/obj/5BSD-ports. The current frontend exposes
   bazel-test qualification; its normal build backend remains bsd-make.
6. Complete ARM64's required Tier 1 qualification. RISC-V implementation/tests
   continue as Tier 2 and do not block this closeout.

These are the outstanding completion gates, not a new architecture project.
Make remains production/default until the required gates pass; only then decide
whether to change the default. BIP remains excluded. Historical progress entries
below retain their original context and are superseded by this current status.


## Qualification priorities (2026-11-10)

AMD64 and ARM64 are the Tier 1 platforms for completing this migration and
qualifying a production/default Bazel backend. Their required world, kernel,
module, package, runtime, correctness and performance gates still apply.

RISC-V (riscv64) is Tier 2. Continue its implementation, builds and tests, retain
its existing targets, and report its evidence and unresolved failures separately.
Its unfinished qualification does not block Tier 1 completion or a justified
Bazel default decision. Do not label RISC-V qualified without its own evidence.
Shared correctness, bootstrap, dependency/cache/sandbox, reproducibility,
hardware/publication and resource gates are not waived by this priority change.
This current policy supersedes historical references below that make all three
architectures prerequisites for completion. Make stays production/default until
the required gates pass. BIP remains out of scope.


## Real BE upgrade exposes capability-service restart failure (2026-11-07)

`bazel-system-upgrade-vm-r1-20261107` completes the signed network upgrade of all
447 packages in an inactive ZFS BE, boots its new kernel, passes positive/negative
SSH and su, rolls back with shared-file persistence, and deletes the unused BE
(reclaiming 2,805,727,232 bytes). This is useful mechanism evidence, **not an
accepted full-system upgrade qualification**: the new boot logs existing runtime
containers and failed capability-service launches. The old automatic gate omitted
those diagnostics and incorrectly reports overall `passed`.

`bazel-system-upgrade-acceptance-review-r1-20261107/review.json` preserves both
original result/serial hashes and rejects that upgrade log under the strengthened
service-failure gate; the earlier normal-boot R8 log still passes that gate.
Historical result files are unchanged. Runtime cleanup now reports failed
unlink/rmdir/fdopendir operations instead of hiding them. The cleanup cause remains
unproven; root starts read-only and cleanup precedes rc, which is a hypothesis to
verify, not a license to move cleanup after live services or adopt old directories.

NEXT: capture the cleanup errno on the real upgraded boot, fix its lifecycle at
the production boundary, and check required services from installed manifests,
including useful operations rather than process existence alone. Diagnostic
rejection alone does not prove all services healthy. Cross-platform completion,
fresh Make parity, native bootstrap/reproducibility, sandbox/cache/performance,
hardware and combined publication remain open. Make stays production/default;
BIP remains excluded. No host upgrade or installation was performed.


## Current AMD64 baseline audit and real firstboot proofs pass (2026-11-07)

Complete R10 image / fresh 2 GB VM R8 passes 14 checks, including normal
console/PAM/SSH/su, exact declared firstboot account/group transitions, actual
live-versus-rebuilt password DB records, and all 33,982 baseline file / 1,369
directory content/ownership/mode/security-flag/symlink checks. All buffers sync
and QEMU powers off normally; backing/source/input hashes remain unchanged.
Raw diagnostics remain visible: only 23 archive bookkeeping changes, five proven
account payload changes and one consumed marker are reconciled. Timestamps,
hardlink inode identity and runtime-added objects remain outside this audit.

The actual next-version 447-package set and newly stamped kernel also build and
pass the selected solver/SSP tests; all archive identities/versions and the changed
kernel bytes are independently reviewed. NEXT: actual boot-environment upgrade,
rollback and old-BE removal. Other configured/cross completeness, fresh Make
compilation parity, native bootstrap/source snapshot/reproducibility, sandbox/cache/
controlled CPU/RAM/disk I/O, hardware and combined publication gates remain open.
See INSTALLED-TREE-AUDIT-QUALIFICATION.md. Make stays default; BIP is excluded.

## Complete installed audit exposes image flag loss (2026-11-07)

Fresh normal VM R6 repeats all 12 startup/authentication checks, then its complete
35,351-object audit fails. Native makefs ZFS ignored declared flags, dropping all
13 schg declarations and adding uarch. The constructor now maps supported input
flags and rejects unsupported bits. Native build and rootless read-only zdb
inspection pass; the new imported-image ATF case and corrected full-image runtime
still need qualification. Firstboot account/marker differences remain explicit,
without blanket configuration exclusions. See INSTALLED-TREE-AUDIT-QUALIFICATION.md.
Make remains default; full migration and installed audit are not complete.

## Complete AMD64 package image passes normal startup and authentication (2026-11-06)

Image R9 passes its full 447-package construction and five native test targets.
Fresh normal VM R5 passes 12 checks: console/PAM, actual terminal size, exact
Capsule PID 1, preserved signal denial, expected ZFS root, installed package count,
PAM-enabled/running SSH, and positive/negative SSH and su. It then powers off
normally with unchanged backing bytes and runner bindings. Two GB guest RAM,
four vCPUs; sampled QEMU RSS is about 998 MiB. See
SYSTEM-IMAGE-BOOT-QUALIFICATION.md for hashes, actual logs and retained failures.

A real procstat compatibility bug was corrected: denied signal permission does
not mean a visible process vanished. Only ESRCH now suppresses its binary row.
The generic cross-UID ATF case is added/built, with final wrapper bytes verified;
it is not yet executed. No MAC permission or PID 1 protection was weakened.

NEXT: exhaustive installed-file metadata/content and legitimate mutable changes;
actual new-version boot-environment upgrade, rollback and old-environment removal.
All base/service/application and optional/custom/cross completeness, fresh Make
compilation parity, source snapshot/native bootstrap/reproducibility, cache/sandbox,
comparative CPU/RAM/disk I/O, hardware and verified combined publication remain
open. Make stays production/default; BIP remains excluded.

## Corrected kernel reaches normal startup; fixture fixes pending (2026-11-06)

Complete image R7 passes all four selected native tests and all 447 packages.
The 2 GB guest passes the former panic, mounts ZFS, runs Capsule/Switchboard and
normal rc, obtains DHCP, starts SSH and authenticates serial root login via PAM.
Formal runtime qualification still fails: rc.local leaked strict shell options,
and the harness sent its first command before resizewin/profile input completed.
The fixture now contains its options, and the harness waits for the prompt and
answers bounded terminal-size probes. Streaming protocol unit checks and the fresh R8 image pass all five native test
targets; the R3 normal VM is running. SSH/su/upgrades and all other
global gates remain open. See SYSTEM-IMAGE-BOOT-QUALIFICATION.md. Make stays default.

### Required performance follow-up from current observations

After the normal runtime/upgrade gates, profile stable-source no-op and one-object
incremental builds against Make with equivalent compiler/configuration inputs.
Separate Bazel metadata/digest checks, package compression, image reconciliation
and evidence capture in the measurements. Retain output validation. Qualify
parallel package compression with correct declared CPU scheduling before raising
thread counts; compilation already requests all 16 logical CPUs. Continue the
required CPU/RAM and filesystem/disk-I/O comparisons with explicit configurations.

## Complete package image; startup defect found and corrected (2026-11-06)

The complete 447-package BIOS/ZFS disk now builds from the actual native package,
inventory, construction and source directory contracts. No init/rc substitution,
memdisk root, package-order workaround or missing-path exclusion is used.
The first normal 2 GB/four-vCPU VM exposed an early guard-initialization panic:
a source-specific SSP exception removed the local flag but left the toolchain
feature enabled. The corrected feature opt-out passes a regression inspecting
actual guard and ordinary protected kernel objects. The corrected full image later passes R7/R8; runtime retries are recorded above.
Normal startup/PAM/SSH/su acceptance remains pending. See
SYSTEM-IMAGE-BOOT-QUALIFICATION.md for retained failure, construction evidence,
resource scope and the remaining global gates. Make stays production/default.

## Complete current AMD64 pkgbase composition passes (2026-11-06)

`//:amd64_system_packages` creates all 447 selected packages: the existing world
families plus kernel-generic/kernel-generic-dbg, with explicit oes/mac-abac module
records merged into their world packages. The real pkg solver reports no conflicts.
The final system qualification passes 25 selected tests (two executed, 23 cached).
Independent exhaustive inspection passes all 33,968 file claims, actual payload
bytes, aliases, directory/mode/flag/config policy and Make-compatible pkg encoding.
A declared-input digest inventory binds all 19,393 execution paths, including
external repository aliases, to the captured bytes without mutable path lookup.
Separate native tests cover the inventory/archive reader and strict full-name
artifact resolution. See SYSTEM-PKGBASE-COMPOSITION-QUALIFICATION.md.

NEXT: normal boot/services and actual installation/version upgrades with the full
system set; qualify alternative kernel layouts/debug packaging against corrected
source Make classification. Cross/custom/root-selection completeness, bootstrap,
cache/sandbox/reproducibility/resources, hardware and combined publication gates
remain open. The explicit format-5 frontend carries these candidates; Make remains
production/default, and BIP is excluded.

## Complete current AMD64 kernel installation passes (2026-11-06)

The native complete archive composes the kernel, 722 selected modules, three
aliases, separate debug/GDB helpers and generated linker.hints. Default,
no-separate-debug (CTF retained) and relocated kernel/debug profiles each pass
21 selected test targets, with cache reuse permitted. Independent full archive
inspection checks original Make membership/installation policy and GDB inventory,
all declared regular payload bytes, ownership/modes, ELF/CTF and debug CRCs.
All 723 runtime ELF allocated-section/CTF contracts match across profiles;
relocation preserves every regular payload byte. Custom ancestor directories
require explicit kernel_directory_policy mtree input; absent policy fails closed.
See KERNEL-INSTALLATION-COMPOSITION-QUALIFICATION.md for evidence and limits.

NEXT: final kernel-flavored pkgbase families and non-kernel module/world package
merge, then normal boot/services and real upgrades. Alternative root profiles,
custom/cross completeness, bootstrap/cache/sandbox/reproducibility/debug/resource/
hardware/publication gates remain open. Make remains production/default; BIP excluded.

## Normal AMD64 root module graph passes (2026-11-06)

Source-owned root selection now builds the complete current 722-module profile.
Default, nineteen-features-disabled (468) and ACPI-off/Veriexec-on (726) profiles each
pass 20 test targets. Complete original source Make traversal, leaf/base-install
policy and exact ordered OBJS+BLOB_OBJS match; all 1,916 selected ELF/debug pairs
pass. Actual VMM and amdsmu header dependencies are fixed. Shared checked kernel
options and native device directives preserve tied source selection. A focused
Bazel follow-up passes the final 13-case Make-audit regression and option tests.
Iwlwifi ACPI objects, CTF paths and flags now follow the actual device option;
configured compile-action checks cover every linked object.
See ROOT-MODULE-GRAPH-QUALIFICATION.md for hash-bound evidence and retained failures.

NEXT: coherent current-profile kernel/GDB/modules/directories/aliases/linker.hints/
pkgbase. FDT/MMCCAM/TESTS root branches still require missing parent/producers;
MODULES_OVERRIDE/EXTRA/WITHOUT_MODULES/ALL_MODULES are not implemented. These and
custom/cross, normal boot/services/upgrades, bootstrap/cache/sandbox/reproducibility/
debug/resources/hardware/publication remain open. Make stays default; BIP excluded.

## Netgraph/TCP module parent selection passes (2026-11-06)

Four AMD64 profiles compose 47/38/46/43 unique products and each pass 19 test targets.
Independent original Make export-aware membership, leaf/install policy and exact
ordered link inputs match; all 174 selected ELF/debug pairs pass. IPsec/signature
selectors share checked native GENERIC option authority. Optional MPPC follows
source crypt and precise RC4 source availability, with present/absent/generated
predicate analysis tests. See NETWORK-MODULE-PARENTS-QUALIFICATION.md for evidence
and limits; this is not normal boot or fresh Make machine-code parity.

NEXT: source-owned root selection and coherent kernel/GDB/modules/directories/
aliases/linker.hints/pkgbase, then normal startup/services and genuine upgrades.
Custom/ALL_MODULES/cross, bootstrap/cache/sandbox/reproducibility/debug/resources/
hardware/publication gates remain open. Make stays production/default; BIP excluded.

## FDT option authority and I2C/GPIO parents pass (2026-11-06)

Three new AMD64 parents compose 45 unique module/debug products under auto/no and
55 under FDT=yes, including ten added AMD64 producers and three corrected source
alternatives. Sixteen test targets pass in each final profile. Independent original
Make parent-export propagation, complete membership/installation attributes and
ordered object lists plus all 145 selected ELF/debug pairs pass. Final captures
preserve every reviewed artifact byte for byte. See FDT-MODULE-PARENTS-QUALIFICATION.md.

Auto defaults live in one source-owned declaration shared by selectors/configuration;
normal parser actions validate the complete actual option-header set before publishing
identity/inventory. A real wrapper negative check rejects a stale expectation even
without running a Bazel test. Eighteen parser inventory cases pass across the three
architectures; they are not full cross builds. Retained failed producers and observers
are documented; no source C, installation payload or signing/publication policy changed.

NEXT: remaining root/kernel-option selection and optional producers; coherent full
kernel/GDB/modules/directories/aliases/linker.hints/pkgbase, then normal startup/
authentication/services and genuine upgrades. FDT-enabled whole-kernel/custom-config
and all cross/bootstrap/cache/sandbox/reproducibility/debug/resource/hardware/publication
gates remain open. Make stays production/default; BIP excluded.

## USB and test-framework parent selection passes (2026-11-06)

New source-owned AMD64 USB and test-framework parents compose 83 actual module/debug
pairs. Default, firmware/gadgets-disabled (71), and USB-disabled (79) profiles each
pass 14 existing tests; independent original Make membership/leaf attributes and
all actual ELF/debug CRC checks pass. Common configured products stay byte-identical.
The gadget selector preserves kern.opts.mk's USB dependency. See
USB-MODULE-PARENT-QUALIFICATION.md for exact scope, including unqualified USB debug
macro variants. No new runtime/module source or signing/publication policy changed.

NEXT: remaining kernel-option/root selection and optional producers; coherent
kernel/GDB/modules/directories/aliases/linker.hints/pkgbase, then normal startup,
authentication/services and genuine upgrades. All cross/bootstrap/cache/sandbox/
reproducibility/debug/resource/hardware/publication gates remain open. Make stays
production/default; BIP excluded.

## Current-profile AMD64 kernel build passes (2026-11-06)

The full current-profile AMD64 GENERIC link, CTF merge and runtime/debug split now
pass through maintained build-bsd with 16 CPUs. Immutable artifact/header/override
and actual ELF/debug CRC review pass. This refresh uses the new shared TCP option;
it is distinct from earlier controlled Make parity, normal boot and full installed
kernel packages. See CURRENT-PROFILE-KERNEL-QUALIFICATION.md.

NEXT: finish root module selection and coherent kernel/module/pkgbase composition,
then normal startup/authentication/services and real upgrades. Refreshed independent
Make parity, cross-platform, bootstrap/cache/sandbox/reproducibility/debug/resource/
hardware/publication gates remain open. Make stays production/default; BIP excluded.

## Shared kernel-option and TCP module checkpoint (2026-11-06)

TCP_HHOOK now has one typed setting shared by the actual GENERIC parser overrides
and source-owned cc/khelp membership. Enabled, disabled and no-debug native profiles
each pass 14 Bazel tests; independent Make tied/standalone/ALL_MODULES checks and
all 13 selected debug pairs pass. A reproduced original Make OPT_GLOBAL defect is
fixed using resolved KERN_OPTS while preserving standalone behavior. Fifteen native
parser inventory cases pass across AMD64/ARM64/RISC-V; these are not cross kernel
builds. See TCP-HHOOK-MODULES-QUALIFICATION.md.

NEXT: remaining kernel-option/root traversal and optional producers; coherent kernel/
module/pkgbase composition and a fresh full current-profile kernel build, then normal
startup/services and genuine upgrades. All cross/bootstrap/cache/sandbox/reproducibility/
debug/resource/hardware/publication gates remain open. Make stays production/default;
BIP is excluded. Earlier full-kernel evidence retains its original input scope.

## Current architecture/source-option parent checkpoint (2026-11-06)

Nineteen more AMD64 parents now compose 127 actual module/debug pairs, including
parent-owned modules and the existing VirtIO DTrace/Chelsio OFED selectors. Together
with the prior static cohort, 43 source parents cover 258 unique module products.
Thirteen test targets and complete original Make membership/leaf-policy plus actual
ELF/debug CRC reviews pass. Disabled DTrace/OFED profiles remove exactly two modules
and preserve all 33 common products byte for byte. See
CONDITIONAL-MODULE-PARENTS-QUALIFICATION.md for evidence and retained observer errors.

NEXT: kernel-option-dependent parents and shared option authority, remaining root
traversal and optional gaps (including missing AIC7xxx producers); coherent full
kernel/GDB/module/directory/alias/linker.hints and pkgbase composition. All normal
startup/service/upgrade/platform/bootstrap/cache/sandbox/reproducibility/debug/
resource/hardware/combined-publication gates remain open. Make stays production/
default, BIP remains excluded, and no host installation or reboot is performed.

## Current module hierarchy checkpoint (2026-11-06)

Twenty-four unconditional source parents now select and compose 134 unique AMD64
modules using typed hierarchical sets. Thirteen test targets pass, including real
nested selection, duplicate rejection and empty module-installation rejection.
Original Make parent membership, every leaf's installation policy and all 134
ELF/debug CRC pairs pass independent review. This expands source-owned composition;
it does not mean only 134 modules have compiler support, or that the full kernel
is packaged. See STATIC-MODULE-PARENTS-QUALIFICATION.md.

NEXT: explicit conditional/source-option parents and root module traversal; coherent
kernel/GDB/module/directory/alias/linker.hints installation and pkgbase; then normal
startup/services and genuine upgrades. Preserve all architecture/bootstrap/cache/
sandbox/reproducibility/debug/resource/hardware/combined-publication gates. Existing
format-5 frontend APIs suffice; backend/source/test/manual changes are together.
Make remains production/default; BIP remains excluded.

## Current checkpoint: complete same-version pkg reinstall passes (2026-11-06)

All 445 selected default AMD64 pkgbase packages now pass actual installation and
same-version force reinstall in a 2GB disk-backed VM. Both phases verify all
32,512 files and 1,369 directories with zero discrepancies; exact inventory, pkg
checksums, site SSH configuration/account/data and generated metadata pass. Cleanup
and poweroff pass. This is a bootstrapped-target chroot test, not normal startup
or a real version upgrade. See WORLD-PACKAGE-INSTALL-VM-QUALIFICATION.md.

The final provenance audit found that the passing full suite used the legacy
helper because the new one was supplied under an unused alias. Exact fixture keys
now reject that mistake. The native reaper's independent positive/expected-timeout
VM tests pass; the corrected complete repeat now passes with the expected native helper hash. Do not describe the older
passing full suite as new-helper qualification.

The next kernel composition audit is recorded in KERNEL-PACKAGE-COMPOSITION-WORK.md.
The matching TESTS-disabled profile selects 722 modules, all with native source
descriptions; 729 was the earlier broader profile. Actual coherent kernel/module
installation/pkgbase remains open. Original Make joins explicit oes/mac-abac module
owners into world packages, so native composition must preserve that ownership.

NEXT: source-owned kernel module selection/
installation/pkgbase composition; normal startup/login/PAM/SSH/capability services;
genuine version upgrades; ARM64/RISC-V and independent world/debug/bootstrap/cache/
sandbox/reproducibility/resource/combined-publication gates. Make remains production/
default; BIP remains excluded. No host installation, upgrade, kernel/module loading
or reboot is authorized or performed.

## Complete world dependency/conflict solver test passes (2026-11-06)

The maintained //:world_package_solver_test derives its complete package set from
native outputs/index and selected family metadata. The real SDK pkg imports a
private unsigned file:// catalogue and dry-runs all 445 packages with an exact plan,
zero conflicts and zero installed packages. Eight requested test targets pass.
Effective database/cache paths are probed against the real pkg before mutation.
The root-shell helper's incorrect explicit-path relocation assumption is fixed;
it also rejects Lua scripts and uses pkg inventory queries. Its actual privileged
add/check/delete remains unexecuted. Copied archives/private databases are scratch,
not retained test output duplicates. See WORLD-PACKAGE-SOLVER-QUALIFICATION.md for
hash-bound commands, independent catalogue/probe review and retained failures.

NEXT: disposable disk-backed VM fresh install/update/ownership/generated-state and
real package-script tests, with target account identities; then normal startup/
services and native kernel/module package integration. This dry-run is not system
installation or normal boot proof. Keep all broader world/debug/cross/bootstrap/
cache/sandbox/reproducibility/resource/combined-publication gates. Existing
frontend target/test inputs select the work; CLI/default/publication contracts do
not change. Make stays production/default; BIP stays excluded.

## Complete native package manifests match Make with inspection dependencies (2026-11-06)

All 445 full package manifests now match the original Make recipes on the complete
same native corpus under matched explicit package epochs. Source-derived inspection
Files/trees and separate inspection records repair missing automatic library
metadata without changing ownership. The former SDK's pkg followed absolute aliases
into host ELF; a retained negative control proves it. The already maintained patched
pkg port passes, and a fresh receipt-bound SDK selects it explicitly without host
installation. Independent inspection again passes all 32,510 packaged paths and
thirteen cross-package hardlinks. Seven maintained test targets pass, including
native Skylib component-order/limit/cycle cases and expanded real-pkg alias cases.
A test-only follow-up preserves every package/plan/index and installation output
with zero package actions. See WORLD-PACKAGE-INSPECTION-QUALIFICATION.md for scope,
epoch normalization, hashes, retained failures and remaining limitations.

NEXT: actual solver/fresh-install/ownership/generated-state/update qualification,
then VM normal startup/services and kernel/module package integration. Keep every
independent Make world/debug/cross-platform/bootstrap/cache/sandbox/reproducibility/
CPU/RAM/disk I/O/footprint/combined-publication gate open. Make stays production/
default; BIP stays excluded. Existing frontend inputs select the work; provider,
backend rules/tests/manual are updated without changing CLI or publication defaults.

## Original Make package control exposes inspection-input gap (2026-11-06)

All 445 original Make package targets now build over a complete shared stage of the
same captured native world. Full decoded manifests match for 355; 87 have missing
or incomplete shared-library requirements (utilities-dev also differs in ignored
providers). Three bootloader packages differ only in nonzero per-file timestamps
versus explicit native package_epoch=0 normalization. No fields were excluded.
A real-pkg libmagic-dev control reproduces the native gap and becomes fully equal
to Make after adding only its source-declared library referent for inspection;
the extra library is not included in that package's payload. This is diagnosis,
not a production fix. See WORLD-PACKAGES-CONSTRUCTION-QUALIFICATION.md for hashes.

NEXT: declare source-derived symlink inspection dependencies in native package
actions, cover chains/directory/absolute/dangling/cyclic links and generated trees,
verify rooted pkg inspection without host reads, and preserve package ownership
and cache granularity. Resolve/qualify explicit epoch semantics. Add real-pkg
regressions and repeat all 445 complete manifest comparisons. Do not replace
missing metadata with hardcoded SONAMEs, a global shared stage, host lookups or
ignored comparison fields. Retain every broader world/kernel/module/runtime/cross/
bootstrap/cache/sandbox/reproducibility/CPU/RAM/disk/publication gate. Make stays
production/default; BIP stays excluded. No host installation or publication occurred.

## All 445 selected native world pkg archives constructed and inspected (2026-11-06)

The declared world_packages candidate creates actual standard pkg archives through
separate package-local actions and deterministic per-package plans/indexes. There
is no production Make invocation, path whitelist or whole-world extraction for
every package. Generated-tree providers forward tags/additional Files; source
allowlists remain enforced. Explicit pf-dev metadata-only output is accepted and
ordinary empty output rejected. Shared pkg staging preserves file/config/flag
attributes and directory ancestor closure. A linear inode planner preserves links
within each package; real shared-stage pkg controls agree on cross-package behavior.
Frontend --jobs now binds build_jobs and enables declared action CPU/memory
estimates; package_threads/epoch remain explicit inputs. Its manual is updated.

The final maintained 16-job full run passes four Bazel wrappers, including fourteen
real flag/directory cases, CPU-budget checks and the real hardlink/readonly-directory/
empty-ancestor regression. Independent host libarchive inspection checks every
one of 445 packages against 1,280 captured native installation archives: all 32,510
packaged paths, file/directory/config metadata/flags, hashes, symlinks and thirteen
cross-package inode relationships pass. Seven generated construction files remain
separate. The audit found and fixed missing empty-directory ancestors in three
packages; standard pkg manifest percent-encoding and tar trailing-directory slashes
are decoded correctly, with no source filename changes or skipped packages.
Across the correction, 441 package archives remain byte-identical; the remaining
changes are three directory-only fixes and the maintained manual/hardlink alias.
See WORLD-PACKAGES-CONSTRUCTION-QUALIFICATION.md for hashes and retained failures.

This is real archive construction and SAME-NATIVE-CORPUS inspection, not independent
Make-built world bytes, complete Make pkg/shared-stage auto-shlib parity, solver,
installed-system/upgrade/runtime, kernel/module packages, signing/verified boot or
publication. NEXT: original maintained Make pkg recipes over the complete captured
native stage, full manifest/partition comparison, then fresh/upgrade/VM and combined
base/hardware publication qualification. Keep every world/kernel/module/debug/cross/
bootstrap/cache/sandbox/reproducibility/CPU/RAM/disk I/O/footprint gate. Make stays
production/default; BIP stays out of scope.

## Selected world metadata reconciles; ATF support leak fixed (2026-11-06)

Source-owned world traversal now selects typed option/CPU family providers;
production has no Make parser/query or staged-file scan. The selected catalogue
rejects duplicate families/packages and inconsistent identities. A declared action
requires exact complete-world inventory coverage, explicit metadata-only handling
and nonempty ordinary packages, and hashes all UCL outputs. The final default
passes with 177 families, 445 manifests, 444 payload packages, pf-dev metadata-only
and 32,517 file/link paths. All 445 default and 492 tests-profile manifests and
both entire family sets match original Make traversal/decoded metadata. The
latter profile does not qualify full tests-enabled world payloads.

The real prior inventory is rejected: ATF's unconditional discovery child installed
a tests-owned Kyuafile with TESTS disabled. Make and native parents now select it
only with TESTS; support binaries remain available. Explicit component directory
claims replace an overbroad global mtree attempt. Fresh Make/native positive and
negative installation/ELF controls pass (44/32 files, six/three directory claims).
Retained failures and final immutable bindings are in
WORLD-PACKAGE-SELECTION-QUALIFICATION.md. Maintained reconciliation rejection
unit tests and source-settings tests pass. Existing format-5 frontend targets/
settings select all work; its manual is updated and CLI/backend/stage/signing/
publication interfaces/defaults remain unchanged.

NEXT: actual whole-world pkg archives from the reconciled providers, transition
packages and cross-package hardlinks; independent full pkg/install/upgrade/system
and combined base/hardware publication qualification. Keep world/kernel/module/
debug/cross/runtime/bootstrap/cache/sandbox/reproducibility/CPU/RAM/disk I/O/disk
footprint gates open. More option/CPU and whole-world Make directory/content
controls remain. Make stays production/default; BIP stays out of scope.

## All 239 source family owners declared; conditional metadata qualified (2026-11-06)

The final seven conditional family owners now have native rules. All 17 default,
17 alternate and nine minimal-profile manifests match complete original Make
metadata. Actual target-ABI Python/RE2 package archives supply explicit optional
FIDL SDK dependency versions. Missing either version is rejected independently
by native analysis and original Make, with expected failures retained. The shared
rule accepts declared typed UCL settings; no host-version fallback or parser clone.
The review found and fixed a real original Make bug: split libcompat manuals
replaced dev despite the independently installed static archive's dev ownership.
Make and Bazel now retain dev while adding man. See
CONDITIONAL-PACKAGE-FAMILIES-QUALIFICATION.md for scopes, exact evidence and failures.

This closes family declaration coverage (239/239), not actual world traversal,
selected metadata/payload reconciliation or package archive creation. Optional SDK
and debug flags here control metadata only; cross-CPU branches remain to qualify.
Existing format-5 frontend inputs handle these targets/flags and its manual is
updated; C/backend/stage/signing/publication interfaces are unchanged. NEXT:
migrate source-option/architecture package traversal, require full selected-world
metadata/inventory reconciliation and construct native whole-world pkg archives.
Retain every independent world/kernel/module/debug/pkgbase/upgrade/runtime/cross/
bootstrap/cache/sandbox/reproducibility/resource/combined-publication gate. Make
remains default; BIP stays out of scope.

## All 208 remaining static family declarations match Make (2026-11-06)

The static_family_manifests aggregate adds all static owners not previously
migrated: 232 of 239 family directories now have native declarations. The seven
conditional owners remain explicit work. All 489 default and 429 alternate
manifests match entire decoded original Make metadata, with exact output coverage
and effective option checks. Shared/local UCL and Make include inputs are hash
bound and checked unchanged; sixteen independent one-job Make controls use all
logical CPUs. Native aggregates/source-settings tests pass through the maintained
frontend. One-time migration generated checked-in declarations; no parser or Make
invocation is in the production graph. See STATIC-PACKAGE-FAMILIES-QUALIFICATION.md.

This is direct family metadata, not actual world traversal, package archives or
installed-system qualification. Existing format-5 inputs select the new aggregate
and the manual is updated; C/backend/stage/signing/publication interfaces are
unchanged. NEXT: seven conditional owners, actual source-option/architecture family
selection, full world inventory reconciliation and native pkg creation. Retain
all independent world/kernel/module/debug/pkgbase/runtime/cross/bootstrap/cache/
sandbox/reproducibility/resource/combined-publication gates. Make remains default;
BIP stays out of scope.

## Nineteen additional capability package families match Make (2026-11-06)

The explicit capability_family_manifests aggregate adds nineteen source-owned
service/library families, including Capsule, Switchboard, OpenES and BSD service
packages. All 47 default and 45 alternate manifests match full original Make
metadata. Exact coverage and effective Make options are checked. Both maintained
frontend captures/source-settings tests pass with 16 jobs. The alternate capture
exposed a default-template include omitted when only the base override is selected;
the generic rule now declares its default template unconditionally. No sandbox
weakening or template/path fallback was used. See
CAPABILITY-PACKAGE-FAMILIES-QUALIFICATION.md for evidence and retained failures.

There are now 24 source-owned families in these two explicit aggregates, not
complete world metadata or package/archive/runtime qualification. Older component
package targets remain separate. Existing format-5 frontend inputs select these
targets; its manual is updated, and C/backend/stage/signing/publication contracts
are unchanged. NEXT: remaining source-owned family declarations, including optional
libfidl SDK tools with explicit target ports versions, full inventory/metadata
reconciliation and actual whole-world pkg creation. Keep all world/kernel/module/
debug/cross/bootstrap/cache/sandbox/reproducibility/resource/runtime/combined-repo
gates and Make production/default. BIP stays out of scope.

## First five source-owned package families match Make metadata (2026-11-06)

The explicit //packages:core_family_manifests aggregate builds runtime, clibs,
utilities, toolchain and bsdlog family metadata using declared native rules and
the maintained Lua UCL generator. Typed package identity inputs are configurable.
Two profiles pass the maintained frontend and source-settings test. All 14 default
and 15 alternate manifests match complete decoded original Make metadata,
including scripts/dependencies/sets/vital properties. Exact family coverage and
effective Make options are checked. The comparison exposed seven unsupported
lib32 variants; they and the invented compatibility flag were removed because
source LIB32 is unconditionally broken. See CORE-PACKAGE-FAMILIES-QUALIFICATION.md.

This is five families, not all 445 world buckets or package archive construction.
The debug_files flag controls only family metadata for now; global debug payload
selection remains open. Make-built static SDK flua does not close bootstrap.
Existing format-5 frontend inputs handle the additive flags/targets; the manual
is updated and stage/signing/publication contracts remain unchanged. NEXT:
complete the remaining source-owned family declarations, reconcile them with the
whole selected inventory and connect native whole-world pkg creation. Retain all
world/kernel/module/debug/cross/bootstrap/cache/sandbox/reproducibility/resource/
runtime/combined-publication gates. Make remains default; BIP stays out of scope.

## MAN=false source inclusion fixed and qualified (2026-11-06)

Manual files/aliases are explicitly marked at their source-owned installation
entries. Typed MAN controls their provider contribution and payload dependencies;
no final inventory/path filter is used. Shared/custom helpers and mixed tables
are corrected, with source AST review of all 257 changed BUILD/Starlark files.
The current enabled/disabled complete native world captures pass: 32,518/14,546
file/link paths, zero disabled manual paths, identical ordinary metadata and
13,397 byte-identical ordinary file payloads. 1,279 prior enabled archives remain
byte-identical; the sole other archive changes only its maintained manual.

Fresh original Make libmd/gzip installations match all paths, metadata, links,
directory claims and nonbinary contents in both settings (126/17 and 24/12 paths).
Gzip's independently discovered /usr/bin utilities directory claim is repaired.
The maintained whole-world MAN guard passes in both profiles; enabled package/
ownership regressions also pass. See MAN-OPTION-QUALIFICATION.md for exact
profile differences (servicesdb is independently disabled), scopes, retained
failures, source review, immutable archives and the final passed audit.

Existing format-5 frontend MAN input, source-owned backends and maintained tests/
manual cover this work; C/CLI/signing/publication/defaults are unchanged. NEXT:
complete native package family templates/dependencies and whole-world pkg archive
creation from the qualified inventory, then package-driven fresh construction,
existing-account preservation and normal installed service tests. Retain all
independent world/kernel/modules/debug/cross/bootstrap/cache/sandbox/reproducibility/
resource/runtime and combined base/hardware publication gates. Make remains default.

## Complete native world package inventory; MAN=false gap found (2026-11-06)

The maintained whole-world inventory accounts for 32,518 file/link paths,
1,202 physical directories, 445 package buckets, seven source-declared generated
files and 13 cross-package hardlinks. Generated zoneinfo metadata and every source
resolved physical-directory sidecar are declared action inputs. No path scan,
package-file whitelist or unknown untagged-file fallback is used.

Every source record/claim matches the retained full native capture; all physical
permissions match actual tar headers. All 445 file/config/directory partitions
match the real maintained Make plist generator on the SAME NATIVE CORPUS.
1,279 archive payloads remain byte-identical; the only other archive differs solely
in the maintained manual, verified against source. Seven unit methods plus twelve
real pkg fixture cases pass; unchanged libmd component-layout construction passes.
See WORLD-PACKAGE-INVENTORY-QUALIFICATION.md for exact scopes, retained failures,
immutable evidence and the new provider/metadata interface.

The disabled profile removes manual indexes and services DB correctly but leaves
13689 manual payload paths. The final audit remains differences-found.
NEXT: fix MAN inclusion at source-owned utility/manual rules and qualify both
settings; do not filter the final inventory. Then port complete source family
metadata/dependencies and connect actual whole-world pkg creation, package-driven
construction/account preservation and normal installed service tests.

Existing format-5 frontend targets/backend providers/serializers/tests and manual
cover this change; C/CLI/signing/publication/defaults remain unchanged. All
independent whole-world/kernel/module/debug/pkgbase/cross/bootstrap/cache/sandbox/
reproducibility/resource/runtime/combined-publication gates remain; Make is default.

## Native package driver preserves declared file flags (2026-11-06)

The driver no longer rejects schg-marked base files. It validates source archive
flags against layout records, uses --no-fflags only for temporary extraction and
carries flags through pkg's standard fourth plist field for files/directories.
The maintained package inspector now validates actual flag bits and handles
explicit directory payloads correctly. No package ownership/file list changed.

The six real-pkg flag fixtures and existing six directory fixtures pass through
the maintained frontend. Four successful packages have retained emitted fixtures
and pass independent libarchive/header/partition/extraction inspection; two flag
mismatches are rejected. See PACKAGE-FLAGS-QUALIFICATION.md for immutable logs,
frozen BEP outputs, exact scope, failed inspection invocation and prepared root
construction command forms. These are fixtures, not complete clibs or pkgbase
parity. uid 1001 lacks sudo/doas; private-jail/installed account checks remain
pending root or the authorized VM path. No home repository or host install is used.

Next complete native whole-world package partition/manifests/archive creation,
then package-driven fresh construction and existing-account preservation plus
normal service/authentication runtime. Existing format-5 frontend/backend package
helpers and tests are updated; manual records the change; C/signing/publication
interfaces are unchanged. Keep every remaining whole-world/kernel/module/debug/
bootstrap/cache/sandbox/reproducibility/resource/cross-target gate and Make default.

## Seven ncurses raw data differences inspected with actual consumers (2026-11-06)

Retained lossless diffs show only source-path comments in curses.h/terminfo.5
and generator-banner comments in the five pkg-config files. No production source
was changed to insert a false banner or absolute checkout path. All 17 host
consumer comparisons pass: identical preprocessed C, rendered manual and selected
isolated pkgconf version/link queries. See NCURSES-GENERATED-DATA-REVIEW.md for
hash-bound artifacts, actual commands and host-tool/common-header limitations.
The full installation audit still reports the seven raw-byte differences; this
is bounded consumer evidence, not native whole ABI/runtime or cross-target proof.
No frontend C/backend/signing/publication change is needed for this evidence;
Make remains default and all broader qualification gates remain open.

## Fresh-world account construction is connected and built (2026-11-06)

The source-owned fresh_world_contributions target extends the existing finalized
world with the separate untagged account archive. world_contribution_products
now includes that fresh construction closure. Maintained frontend construction
passes with all 16 CPUs; source-settings and manual-database tests pass.
The hash-bound full inventory verifies 1280 archives,
32518 nondirectory paths and 1211 claims over
789 directory paths with no collisions. All existing finalized
outputs remain unchanged within the same capture; exactly one account archive
and its two metadata files are added. All three actual account members match
original Make bytes and numeric archive ownership/modes.

See WORLD-ACCOUNT-FINALIZATION-QUALIFICATION.md. Initial visibility failure is
retained; access was granted only to the root composer. Existing format-5 input
selection, maintained world backend and manual cover the change; C/CLI/signing/
publication/defaults remain unchanged. This output is fresh construction, not an
existing-system overlay or account migration. Next qualify package-driven stage
construction/nonreplacement and installed login/PAM/SSH; preserve replace=false.
Independent complete world/library binary/debug/pkgbase parity, sanitizer control,
raw ncurses data differences, cross-target/kernel/module/runtime/VM and bootstrap/
cache/sandbox/resource gates remain open. Make remains production default.

## Existing fresh-account generator matches original library construction (2026-11-06)

The maintained frontend now builds the existing //etc:account_databases and
//etc:account_install_archive candidates with current inputs. All three generated
account outputs match full original Make installconfig bytes and archive modes.
The audit verifies original receipt/component metadata and immutable captures.
See LIBRARY-ACCOUNT-CONSTRUCTION-QUALIFICATION.md. No generator change was needed.

The three paths remain absent from the selected library/world payload: source
composition intentionally separates untagged account construction state from
package payloads. packages/runtime/runtime.ucl requires replace=false. Next
integrate complete fresh-system construction and qualify existing-account
nonreplacement/upgrades plus installed lookups, not add package tags or copy host
databases to hide the inventory gap. Nondefault accounts/shells, TCSH-disabled
transformation and cross-target variants also remain. Existing format-5/backend
facilities cover the bounded build; C/CLI/signing/publication are unchanged and
the manual is updated. Continue all broader library/world/kernel/package/runtime,
performance/bootstrap/cache/sandbox/cross-architecture gates; Make remains default.

## Full selected library directory claims reconciled (2026-11-06)

The maintained frontend constructs all 164 selected installation parents plus
build-only outputs and two tests. Independent full original Make comparison now
has zero directory package-claim differences (previously 20 over 16 paths).
There are 323 archives and 617 claims over 353 paths; common file metadata and
hardlinks still match. All 650 affected file payloads remain byte-identical.
Utilities-owned libc dummy fixtures retain a separate archive from tests, debug
ancestors use the existing derivation helper, and suite data directories remain
source-owned. Removed invalid copied CAM targets from libfetch; its real local
file/URI test passes. Global tests-off and separate GoogleTest-off captures
exclude suite paths and tests package claims.

See LIBRARY-DIRECTORY-CLAIMS-QUALIFICATION.md for immutable captures, actual
runtime scope and audit. The full comparison remains differences-found for three
account files, two sanitizer test files and seven ncurses data outputs. Existing
account database generation is separate; inspect correct construction/package
composition next, without installing prebuilt databases over local accounts.
Then continue remaining binary/debug/library/world/pkgbase/runtime/VM,
cross-architecture/bootstrap/cache/sandbox and performance gates. Existing
format-5 inputs/backend select the fixes; frontend C/signing/publication policy
is unchanged and the manual is updated. Make and the full-tests guard remain.

## Four recorded ELF dependency gaps corrected (2026-11-06)

Powercmp/timecmp remove an extra direct thread-library dependency; notify and the
sysdecode test retain original load order. Standard native declarations own the
fix, without linker filtering or binary editing. All four complete parent/Make
comparisons match: 185 component paths, 41 directory claims, all four original
needed-set/order gaps, 12 ELF and two raw archive contracts. The two traced raw
archive differences remain recorded with unchanged actual object bytes and prior
DOF/order evidence. All four own archives are unchanged; 24 debug controls pass.

The exact installed sysdecode case passes with native sysdecode/ATF/libc/libsys;
original metadata/body identity and actual loader resolution match. No production
service API, kernel policy enforcement, live tracing or full-system acceptance is
claimed. Warm BEP counters record 56 executed/2,355 created actions, one C compile;
controlled cache/resource/performance gates remain open. See
LIBRARY-DYNAMIC-DEPENDENCY-QUALIFICATION.md for immutable evidence and scope.

Existing frontend format-5/backends/signing interfaces suffice; manual updated.
Next reconcile full-library generation/directory policy and inspect the remaining
ncurses/positive-runtime differences, then repeat the complete selected comparison.
Keep full-tests guards, Make default and all world/kernel/module/pkgbase/VM/cross/
bootstrap/cache/sandbox/reproducibility/performance/publication gates. BIP stays out.


## Remaining nine recorded installed static substitutions reconciled (2026-11-06)

Seven libcapbundle and two libcapimage installed C tests now retain original
native dynamic PIE ABI. Both libcapsulert tests use native ABI precedence too;
original Make removes embedded object-tree RPATHs and uses TESTS_LD_LIBRARY_PATH.
All 204 selected original host body targets pass (203 ATF, one plain), no skips.
All 211 original C-program ATF metadata identities match; eight capimage kernel/
root cases and 17 capbundle shell-format bodies remain unexecuted in this cohort.

Complete comparisons match 70 component file/link records and 22 directory claims.
All 14 program/library ELF contracts, two raw archive symbol/member comparisons
and 28 native/original debug checks pass. Existing raw capsulert DTrace keys remain
visible; all three production tars are unchanged. Captured body identities and
native startup dependency resolution are checked. Both actual stripped plain
clients also execute successfully. See CAPABILITY-INSTALLED-TEST-QUALIFICATION.md.

All ten static-substitution gaps from the recorded 23-parent cohort are now
reconciled, including earlier capreclaim. This does not establish whole-tree
binary/body coverage. Next correct direct/ordered DSO dependencies and full-library
generation/directory gaps, then recheck the complete selected graph. Existing
format-5/frontend/backend/signing contracts suffice; manual updated. Full-tests
root guards, Make default and all world/kernel/module/pkgbase/VM/cross/performance/
bootstrap/cache/sandbox/reproducibility/publication gates remain. BIP stays out.


## libcapreclaim installs and exercises its original dynamic test ABI (2026-11-06)

Installation now selects the native dynamic PIE test, preserving original ATF/
component/libc ABI precedence and C warning policy. The separate static host
candidate is no longer shipped. All 28 original cases pass against the exact
stripped installed body using declared native ATF/component/libc/libsys runfiles;
no skips. Exact original/native registration metadata matches all 28 executed
identities. Explicit loader traces resolve only those four captured DSOs.

Complete original installation matches 11 paths and seven directory claims;
shared/test ELF and archive symbol/member contracts pass. Both native/original
library/program debug checks pass, and production library tar is unchanged.
See CAPRECLAIM-NATIVE-TEST-QUALIFICATION.md for captures, the repeat-run cache scope
and callback-fixture/host-loader/tracing limits. This fixes one of the ten recorded
static-versus-dynamic installed-test gaps, not the remaining nine or system gates.

Existing frontend format-5/capture and installation interfaces suffice; manual
updated, C/backend/signing contracts unchanged. Next correct the remaining
libcapbundle/libcapimage installation variants, original build-tree test paths,
direct/ordered dynamic dependencies and full-library generation/directory gaps.
Keep full-tests guards, Make default, and all world/kernel/module/pkgbase/runtime/
VM/cross/performance/bootstrap/cache/sandbox/publication gates. BIP stays out.


## Six original archive orders corrected and checked in both DTrace modes (2026-11-06)

The six recorded source-order gaps are fixed with native component archive
object_order declarations. Every selected object must occur exactly once; no
production Make parsing, archive rebuilding workaround or source/provider change
is added. All six complete parents construct through the maintained frontend in
normal DTrace, no-DTrace and the existing section-archive prototype modes.

Twelve original Make archive comparisons pass: exact member order in both normal
modes; all member symbols match without DTrace; ordinary symbols match with DTrace
and every changed generated alias resolves to an actual validated function/site.
The traced cohort preserves 55 schemas and 79 patched ordinary sites on both
sides. Raw differences remain recorded; original bodies/live tracing/static
extraction and whole-system acceptance remain unqualified. Prototype qualification
is construction only. See LIBRARY-STATIC-ORDER-QUALIFICATION.md for all bindings.

The existing format-5 API and native archive rule suffice; manual updated, C/
backend/signing options unchanged. Next fix the remaining installed test linkage,
original build-tree runtime paths, direct/ordered dynamic dependencies and full
library generation/directory gaps. Make/default and full-tests guards remain;
all world/kernel/module/pkgbase/runtime/VM/cross/performance/bootstrap/cache/
sandbox/publication gates remain open. BIP stays excluded.


## Full library comparison exposes bounded installation gaps; stat parent added (2026-11-06)

The independent complete original Make lib build/install passed, including the
actual original JEVENTS metadata recipe audit. The complete 164-parent comparison
now covers 322 archives and 12,467 native versus 12,468 original paths. Common
file/link metadata and original hardlink identities have zero mismatches; 10,097
non-ELF data files match exactly. It remains differences-found: 3 derived account
files absent, 2 native h_raw paths requiring a positive original UBSan control,
7 ncurses data differences and 20 missing package claims over 16 directory paths.
The first audit's immediate-hardlink-chain assertion was corrected generically;
its failed evidence is retained. See LIBRARY-COMPLETE-INSTALLATION-GAPS.md.
All six independent original DTrace-disabled archive-order controls also pass.

The next userland inventory gap, stat, now includes every original stat/readlink/
mountpoint test script and Kyuafile through the normal tests feature. Complete
positive/negative Make comparison matches 11/7 paths and 3/2 directory claims;
production-only tar is byte-identical before/after. All three installed ELF
metadata contracts and both stat debug separation/name/CRC controls pass.
All 26 original metadata identities match under the recorded host ATF interpreter;
no bodies run. See STAT-PARENT-QUALIFICATION.md. The existing format-5 frontend is
used and the manual updated; C/schema/signing inputs need no changes.

Return to the recorded library installation and binary corrections now that the
source-bound controls have exited. Preserve all original evidence, feature
variants and root guards. Make remains default; all whole-system/runtime/VM/
cross/performance/bootstrap/cache/sandbox/publication gates remain. BIP stays out.


## Complete selected lib construction and queued regressions passed (2026-11-06)

The normal frontend full selected AMD64 lib hierarchy run passed all 164
installation parents, 36 build-only outputs and the source helper. All 201 labels
are captured with no incompatible targets: 683 unique files, 2,142,741,312 bytes.
The complete public tests-enabled aggregate remains guarded. No original library
bodies run; this is construction, not independent whole-system qualification.

The subsequent maintained frontend regression also passes: source settings (28),
generator provenance (8), original option/metadata restrictions (20) and multi-object
DTrace inspection (30), totaling 86 actual unit methods across four reported Bazel
wrapper cases. This supersedes earlier pending regression entries. See
LIBRARY-COMPLETE-CONSTRUCTION-QUALIFICATION.md for exact manifests and receipts.

The complete original Make control remains active. The queued full installation
comparison and original JEVENTS recipe audit await its terminal receipt. Six
original no-DTrace component controls are running separately to support the
archive-order corrections. Preserve these live controls' source identities;
prepared source patches are not applied or qualified yet. All known installation/
linkage/order gaps and full world/kernel/module/pkgbase/runtime/cross/performance/
bootstrap/cache/sandbox/publication gates remain. Make remains default; BIP stays
excluded. Existing frontend format-5/capture interfaces are used unchanged.


## Four flagged static DTrace archives inspected against actual members (2026-11-06)

The independent inspector now accepts explicit repeated companion objects and
rejects ambiguous definitions and duplicate inputs while preserving all existing
relocation/function/site checks. Thirty host regressions pass; its normal Bazel
regression is added to the already queued frontend validation and remains pending.
The manual is updated; existing BUILD data, format-5 and C/frontend inputs suffice.
No active library compiler/action or original Make-control input is changed.

Actual native/Make libcapsulert, libchannel, libservice and libshmring archives
validate five provider records, 46 matching schemas and 63 patched ordinary sites
on each side. All non-DTrace member symbols and archive orders match. Every raw
changed alias occurs in an actual validated DOF/function binding. Original strict
symbol failures are retained; raw equivalence, path-hash recomputation, static
extraction and live tracing remain unqualified. Other installation/linkage/order
mismatches remain open. See DTRACE-RELOCATABLE-METADATA-QUALIFICATION.md and
bazel-library-static-dtrace-review-r1-20261106 under /usr/obj/usr/src.


## Real binary comparison finds additional gaps in 23 library parents (2026-11-06)

The entire previously completed positive 23-parent directory cohort now has an
independent original Make binary-contract comparison. Eight parents pass all
contracts tested; 77 individual contracts pass (13 archives, 20 DSOs, 44 programs).
Twenty-six checks fail across 15 parents: 10 static-versus-dynamic installed tests,
2 runtime-path differences, 6 archive-order differences, 2 extra libthr dependencies,
2 dependency-order differences and 4 raw path-derived DTrace symbol differences.
No parent or failure is omitted. Runtime paths in original libcapsulert tests
also expose an OBJTOP-dependent installation policy to correct, rather than copy.

See LIBRARY-BINARY-COMPARISON-GAPS.md and
bazel-library-directory-binary-review-r1-20261106 under /usr/obj/usr/src for the
complete evidence and ordered fixes. Directory/package coverage and successful
construction do not close these binary gaps. Preserve running full-library
controls' source identities; apply component corrections after they terminate.
Make/default and full-tests guards remain. No bodies execute in this comparison.


## Independent libfidl ELF comparison exposes archive order gap (2026-11-06)

While the complete native and original Make library builds remain live, an
independent comparison of the earlier complete GoogleTest-disabled libfidl parent
passes the shared library and four installed test ELF metadata contracts. The
static archive fails: internal.c is placed after scalar.cc instead of after
handle_close_many.cc. Correct declared ordering after the live source-bound
controls exit; no running library inputs have been changed.

Both actual static DTrace providers independently validate against runtime's own
compiled objects: one provider, 19 matching schemas, 19 DOF relocation bindings
and 26 ordinary patched sites on each side. Raw generated DTrace identifiers
still differ with object paths; raw symbol/archive equivalence is not claimed.
No bodies or live probes execute. See LIBFIDL-BINARY-QUALIFICATION.md for immutable
evidence, exact limitations and the pending correction.

The complete namespace/metadata/non-ELF comparison is queued behind the two
actual existing process identities in
bazel-library-complete-comparison-queue-r1-20261106. It requires both passed
terminal receipts and verifies original component metadata against its receipt.
That comparison and the already queued maintained Bazel validation are pending,
not successful results. Make remains default and the full-tests guard remains.


## Complete library Make tool prerequisite found; native build continues (2026-11-06)

The first complete original Make control terminated unsuccessfully: libpmc uses
its normal JEVENTS build-tool command, which was absent from the isolated reference
object tree. The original generator now passes its own native Make build/install
reference at /usr/obj/usr/src/bazel-library-jevents-make-r1-20261106. The declared
executable/receipt/sha256 binding is recorded in
bazel-library-complete-generator-inputs-r1-20261106/generators.json.

The reference interface now accepts source-named uppercase generator commands,
including JEVENTS, while rejecting compiler, target/path/environment and feature
control overrides. Existing provenance, effective selection, unchanged compiler/
SDK identity, before/after hashes and observed direct metadata recipe checks stay
in force. Eight host provenance/tamper tests and twenty host option/metadata
restriction tests pass. The added validation-module
and directory-metadata dependencies are declared on the Bazel test target.
Run the maintained Bazel provenance/options tests after the live native build
finishes. The running library compiler/action inputs are unchanged.

The complete Make control has restarted fresh as
bazel-library-complete-make-r2-20261106, with --make-meta and the explicit original
JEVENTS binding. The original failed r1 evidence is retained. The full native
library run bazel-library-complete-native-r1-20261106 is still active. Both were
confirmed live at this checkpoint. Inspect terminal receipts/logs before restart;
this is not completed construction, installation parity or runtime qualification.
The global tests-enabled library guard and Make production default remain.


## Complete library construction and independent original install in progress (2026-11-06)

After reconciling the 25 recorded directory-policy overwrites, qualification now
requests every selected installation child parent, the original lib/tests root,
and all selected build-only outputs. `bazel-library-complete-request-r1-20261106`
under /usr/obj/usr/src records 164 installation parents plus 36 build-only outputs
and the source helper. The normal build-bsd bazel-test path constructs these in
`bazel-library-complete-native-r1-20261106`, using all 16 CPUs and the existing
explicit format-5 SDK/offline inputs. No child contributions are filtered out.

An independent complete original Make library hierarchy build/install is running
in `bazel-library-complete-make-r1-20261106`, also with 16 jobs and the recorded
explicit TESTS/FDT/other component options. It uses ordinary original Make mode,
without source-directory metadata logs or host installation. These processes were
confirmed live when this checkpoint was recorded. Inspect their terminal receipts
and logs before assuming completion or restarting; progress output and observation
timeouts do not prove success or failure.

The actual tests-enabled aggregate cquery returned an empty archive selection
because the aggregate is intentionally incompatible. That observation is retained
in `bazel-library-positive-selection-r1-20261106`. The child request is bound to
the current source-owned root composition and prior configured child selection;
`bazel-library-build-only-selection-r1-20261106` records the actual 36 build-only
outputs. The guard is retained, and this request does not qualify the public full
aggregate or change the production/default backend.

Next inspect terminal construction results and reconcile the complete captured
namespace, every file/link/package/directory policy and exact non-ELF data against
the actual complete original installation. The comparison must account for
generated tree archives and every selected child. ELF/static archive/debugger,
original body execution, full world/kernel/module/pkgbase, normal-service VM,
CPU/RAM/disk-I/O/footprint, bootstrap/output-query/cache/sandbox/reproducibility
and combined publication remain open. Make remains default; BIP is excluded.
No C frontend/schema/signing/manual option change is needed for this qualification
request; it uses the maintained workflow's existing explicit inputs.


## All 25 recorded library directory-policy overwrites reconciled (2026-11-06)

All 25 affected positive/negative parents now match complete independent Make
controls: 876/694 component file/link records and 260/102 distinct directory
package claims. Exact non-ELF data and debug separation/name/CRC match; full ELF,
static archive members, DWARF and body execution remain separate. A shared native
archive-composition macro preserves source-owned feature selectors and independent
production/test claims. All 25 production archives are byte-identical across test
modes. The negative root still selects the same 231 archive output paths.

The complete batch exposed and fixed original-test linkage drift in cryptocmp,
networkcmp, notify and tracecmp without duplicate-symbol suppression or provider
removal. Five scripted fixture service-symbol sets match Make. libservice's omitted
worker source fixture is restored. libfidl's GoogleTest-disabled alternative also
matches its actual original control (120 records, 29 directory claims).

The recorded explicit policy-overwrite audit is now zero, not whole-library
completion. Only source helpers execute during construction. Next finish complete
selected library/world payload and package reconciliation, retaining the global
full-tests guard and Make production default. Remaining runtime/VM, ELF/archive/
debugger, kernel/module/cross-target/pkgbase, CPU/RAM/disk-I/O/footprint, bootstrap/
output-query/cache/sandbox/reproducibility and combined publication gates remain.
See LIBRARY-DIRECTORY-POLICY-COMPLETION.md for captures and failed checks. BIP stays
excluded; existing maintained frontend inputs select this work.


## Preserve original production/test package directory claims (2026-11-06)

Complete Make controls confirm that libmp/libbsnmp record separate production and
test package claims for shared debug ancestors. Separate source-owned production
and optional test archives now preserve both, including original test-directory
claims. Positive/negative file/link and directory metadata, exact non-ELF data and
debug separation/name/CRC match Make: libmp 9/6 files and 7/2 directory claims;
libbsnmp 104/101 files and 8/3 claims. These construction runs execute only the
source helper. ELF ABI/content, raw static archives and runtime remain separate.

All 231 negative root archive output paths are preserved. The recorded configured
policy-change audit now has 23 unresolved entries, down from 25; it is not a full
package inventory. Next reconcile the remaining entries and complete full library/
world payload/package gates. Keep the full-tests library guard and Make default.
See LIBRARY-PACKAGE-DIRECTORY-QUALIFICATION.md for original controls, failures,
actual scope, maintained frontend integration and remaining system gates.


## Complete native Casper parent and original discovery repair (2026-11-06)

Casper now composes all nine previously disconnected original test entry roots.
Complete positive/negative parents match Make's 155/130 file/link records, all
22/1 directory claims and 17/9 ELF/split-debug contracts. Original root Kyua
discovery omitted the services subtree; the existing supplied-Kyuafile mechanism
now includes its unchanged automatic dispatcher. Both installations list 65 cases
across eight programs with matching per-program order and all 63 ATF metadata
records. No production or test C bodies changed.

Thirteen original ATF cases and two TAP programs pass; TAP retains 387 checked
assertions without skips. The source helper is separate. Fifty original cases
remain unexecuted here, including network and root/exclusive sysctl checks.
The refreshed Make traversal preserves 326/442 directories and 66 entry roots;
configured reachability is now 66/66, not a completion percentage or proof of
complete payload/runtime coverage. All 231 negative archive output paths remain.
See CASPER-PARENT-QUALIFICATION.md for exact captures and remaining gates.

Next reconcile 25 recorded explicit directory-policy changes with original Make
package claims, then finish complete library/world payload and runtime coverage.
The global tests-enabled library guard and Make production default remain.
World/kernel/modules/pkgbase/debug, normal-service VM, CPU/RAM/disk-I/O/footprint,
bootstrap/output-query/cache/sandbox/reproducibility and verified combined
base/hardware publication remain open. BIP stays excluded.


## Actual selected library test composition and fourteen missing parent edges (2026-11-06)

The configured graph, not declaration presence, exposed fourteen existing test
contributions disconnected by production-only parent selection. They are now
connected, including libdiff's tests-only contribution and the original lib/tests
root. Configured entry-root reachability rises from 43 to 57 of the recorded 66;
the nine missing roots are all Casper recursion/service tests. All 231 negative
root archive output paths remain exactly equal. All 597 original traversal Make
include hashes remain current; expanded Make declarations now cover all 116
selected nested test/helper directories. These are graph/declaration counts,
not payload completeness or a percentage of the migration.

All fourteen changed parents and lib/tests construct successfully through the
normal frontend, producing 59 archives. Only the source helper executes here.
Forty-one test archives from ten components remain byte-identical to their prior
captures, retaining each earlier scope/limitation. An actual full-tests root
request is still rejected by the guard. See LIBRARY-TEST-PARENT-WIRING.md.

Next finish Casper's nine missing entry roots, reconcile 25 recorded changes in
explicit production/test directory policy against completed Make install records,
and preserve distinct package claims where required. Then finish complete library/
world payload and runtime qualification. Full world/kernel/module/pkgbase/debug,
normal-service VM, CPU/RAM/disk-I/O/footprint, bootstrap/cache/sandbox/reproducibility
and combined publication gates remain. Keep both full-tests guards and Make default
until their actual requirements pass. BIP stays excluded.

## Native C libutil suite and shared runtime links (2026-11-06)

All twelve original programs now use native final ATF/util/C ABI providers, with
original wrapped production sources and GNU17/WARNS=2. Twenty ATF cases and six
TAP programs pass. Retained TAP databases/stdout show 253 checked assertions and
31 original humanize skips; program-level success does not erase those skips.
All 25 suite files and 148/123 positive/negative parent records match Make,
including directory claims, exact data, hardlinks and thirteen/one ELF/debug
contracts. Six registered normal/private link pairs share actual input files;
only output path/private inherited RPATH differs. Native util/C/sys trace receipts
and copied TAP programs are retained and bound to final report hashes.
Final twenty ATF adapters execute installed stripped programs; all final captured
outputs remain byte-identical to the initial independently compared artifacts.
See LIBUTIL-TEST-QUALIFICATION.md for complete evidence and separate trace/body scope.

Continue remaining selected library tests/full tests-enabled world and complete
world/kernel/module/pkgbase/debug, normal service/VM, CPU/RAM/disk-I/O/footprint,
bootstrap/cache/sandbox/reproducibility and combined publication gates. Make
remains default; cross-target installed runtime remains open; BIP excluded.

## Native libutil++ test ABI and parent installation (2026-11-06)

All three original C++ programs now use native final ABI/unwinder providers and
original GNU++17/WARNS=6. Four original cases pass with native runfiles. Complete
suite/positive parent/negative parent controls match all 7/14/7 file records,
original directory claims and data; three executable ELF/debug contracts match
Make. The missing test-directory package claim is corrected. Original internal
archive/header non-installation and seven manual files are preserved. See
LIBUTIL-CXX-TEST-QUALIFICATION.md for actual evidence and limits.

The larger C libutil suite remains separate and next. Continue all remaining
selected library tests/full tests-enabled world, world/kernel/module/pkgbase/debug,
service/VM, CPU/RAM/disk-I/O/footprint, bootstrap/cache/sandbox/reproducibility and
combined publication gates. Make remains default; cross-target installed runtime
remains open; BIP remains excluded.

## Native libmd installed tests and original parent profiles (2026-11-06)

All fourteen original digest drivers now have a normal native system installation
closure, separate from the retained portable testonly candidate artifacts.
All 44 test files and fourteen original registrations match Make; all fourteen
actual shell cases pass with native drivers and declared original tools/runtime.
The source helper is a fifteenth reported pass. Complete parent profiles match
170/126 file/link records with tests enabled/disabled, including all directory
package claims, hardlinks, exact data and fifteen/one ELF/debug contracts. No test
payload remains when disabled. Earlier helper source ASTs and digest order remain
unchanged; fresh cross-target legacy qualification is not claimed.

See LIBMD-SYSTEM-TEST-QUALIFICATION.md for actual evidence, retained errors and
limits. Continue remaining selected library tests/full tests-enabled world,
world/kernel/module/pkgbase/debug, normal service/VM, CPU/RAM/disk-I/O/footprint,
bootstrap/cache/sandbox/reproducibility and combined publication gates. Make
remains default; native installed ARM64/RISC-V runtime remains open; BIP excluded.

## Native crypt tests, complete parent and bounded cache check (2026-11-06)

Both original programs now use native final ABI/runtime dependencies, retain
WARNS=6/GNU17 and expose the full installed suite archive. All three original
registrations match Make. The two local cases pass; the imported salt case has
one original expected failure, exactly matching independent Make program/crypt
DSO execution. Final reports preserve that distinction instead of counting it
as a passed original case. Tests-enabled/disabled parent profiles match all
14/9 file/link records, directory claims, hardlinks, data and three/one ELF/debug
contracts. No test payload remains when disabled.

A controlled original-source comment change executes exactly its own compile;
warm and restored phases execute zero. Source is restored and every final
captured output is byte-identical to the independently compared initial artifacts.
See CRYPT-TEST-QUALIFICATION.md for receipts, known salt compatibility limitation,
retained audit errors and scope. Remaining selected library test/world traversal,
world/kernel/module/pkgbase/debug, service VM, CPU/RAM/disk-I/O/footprint,
bootstrap/cache/sandbox/reproducibility and combined publication gates remain.
Make stays default; BIP remains excluded.

## Original library test traversal and CAM/Capsicum/jail parents (2026-11-06)

The recorded Make tests-off/on traversal reaches 326/442 directories, adding
116 directories through 66 test entry edges. The declaration inventory identified
three test roots without installation contributions: CAM, Capsicum and jail.
All five original programs now build with native dependencies; twenty actual
case metadata records match Make and seven host-safe original bodies pass.
Thirteen CAM privilege/device cases remain unexecuted.

Both complete parent profiles reconcile: tests on has 78 file/link records and
seven ELF/debug contracts, tests off 65 and two contracts with no test payloads.
All directory package-claim sets, hardlinks, non-ELF data and test registration
match Make. Jail preserves its libjail-tests package and both runtime/test claims
on shared ancestors. Production debug-directory omissions/incorrect assumptions
were caught and repaired against actual installed paths. See
CAM-CAPSICUM-JAIL-TEST-QUALIFICATION.md for final evidence and retained failures.

Continue the remaining selected library test contributions and full tests-enabled
world assembly. Declaration presence alone does not establish payload coverage;
retain the wider guard until its actual selected closure is verified. Full
world/kernel/module/pkgbase/debug, runtime/VM, CPU/RAM/disk I/O/footprint,
bootstrap/cache/sandbox/reproducibility and combined publication gates remain.
Make stays default, ARM64/RISC-V remain in scope, and BIP remains excluded.

## Complete selected AMD64 ATF parent and nested traversal (2026-11-06)

Both original profiles now reconcile independently: tests enabled has eight
archives/173 records, tests disabled two archives/89 records/no tests payload.
All file/link metadata, directory package-tag claim sets, original hardlinks and
non-ELF/non-static-archive bytes match Make. Thirty-six positive and two negative
ELF/debug contracts pass. Actual SDK Kyua discovery matches 333 unique identities
and per-program order. Original upstream five-suite registration and unregistered
protocol helpers remain intact; six shell programs match Make under single-body
and ordered-fragment script API forms. Final bindings and retained registration/
listing-audit failures are in ATF-PARENT-QUALIFICATION.md. Sixteen C++ bodies are
qualified; the other 317 bodies are not executed by assembly or metadata listing.

The last initially missing declaration root is closed, including test-programs.
This is not full library/world closure: the lib root still selects many library-
only contributions. Next reconcile every selected original library test edge and
existing declaration, assemble the full tests-enabled parent/world, and retain
independent world/kernel/module/pkgbase/debug, normal-service VM, CPU/RAM/disk-I/O/
footprint, bootstrap/cache/sandbox/reproducibility and combined publication gates.
Fill ARM64/RISC-V and expected death/exit/timeout runner gaps alongside shared
work. Make default; wider full-tests guards stay until proven; BIP excluded.

## Complete selected AMD64 ATF C++/detail construction (2026-11-06)

All twelve original harnesses, version helper and thirty installation records
match independent Make metadata/Kyua/directory and thirteen ELF/debug contracts.
All 101 native/Make registrations match. Sixteen original environment/exception/
text bodies pass with eight native loader bindings; eighty-five bodies remain.
Normal/runtime links share actual object/input sets and differ only in output
and inherited private RPATH. The original 300-second deadlines are preserved.
ATF-CXX-TEST-QUALIFICATION.md records final bindings, the missing-unwinder link
failure and the correctly rejected host-libsys loader resolution.

Continue the final initially missing ATF parent and nested test-programs, using
the already built independent complete Make parent control. Then finish selected
tests-enabled world traversal/assembly, independent world/kernel/module/pkgbase/
debug, normal-service VM acceptance, CPU/RAM/disk-I/O/footprint, bootstrap/cache/
sandbox/reproducibility and verified combined publication, filling ARM64/RISC-V
gaps in shared work. Full-world tests guards stay until closure; Make default;
BIP excluded; no host installation/upgrade/reboot.

## Build-storage cleanup after test construction (2026-11-06)

Five obsolete isolated execution trees were removed, followed by successful
standard Bazel clean of the primary /usr/src execution outputs. About 58 GiB is
available afterward; concurrent filesystem activity means this is not a
controlled reclaimed-byte measurement. Sources, SDK inputs/materializations,
original Make controls, qualification captures/test reports and repositories
remain. Four recent library/test archive captures and final libxo/ATF C test
report hashes verify after cleanup. Maintenance evidence is retained under
/usr/obj/usr/src/bazel-storage-cleanup-r{2,3}-20261106.

Removed execution outputs will rebuild when selected. Retained action-cache hits
remain possible; do not describe the next run as an entirely cold-cache benchmark.
No frontend, SDK-input, signing, stage or publication requirement changes arise
from maintenance. Continue remaining ATF C++/parent traversal and the full world/
package/runtime/performance/cross-architecture gates below. Make remains default.

## Complete selected AMD64 ATF C/detail test construction (2026-11-06)

All seventeen original C/detail harnesses and two helpers build natively. All
42 installation records, original directories and nineteen ELF/debug contracts
match fresh independent Make controls. Actual installed-form metadata matches
214 original registrations; no original bodies execute in this batch. Native
alwayslink preserves original direct-helper object inclusion, after independent
comparison detected missing imports under lazy extraction. Private header access
is explicit. ATF-C-TEST-QUALIFICATION.md records final evidence and exact limits.

One initially missing declaration root remains, the ATF parent. Existing partial
C++ declarations and nested test-programs still need complete original traversal
and installation qualification; file presence is not closure. Continue those,
full tests-enabled world assembly, independent world/kernel/module/pkgbase/debug,
normal-service VM acceptance, CPU/RAM/disk-I/O/footprint, bootstrap/cache/sandbox/
reproducibility and verified combined publication. Fill ARM64/RISC-V gaps in
shared work. Make default; full-tests guards remain; BIP excluded; no host install.

## Complete selected AMD64 libbe test and parent construction (2026-11-06)

The original helper and root/cleanup shell case now have native construction and
all four installed test records. The complete tests-enabled library parent builds
two archives, matching all 45 original Make records, recorded directories,
manual hardlink identities and 39 exact non-ELF/non-archive payloads. Helper and
production DSO ELF/debug contracts match. Actual installed-script metadata is
identical; the privileged pool-creation body remains disposable-system work.
The one passing source-settings helper is not original libbe body execution.
LIBBE-TEST-QUALIFICATION.md records final bindings and exact scope.

Two initially missing declaration roots remain: ATF C tests and ATF parent,
including nested detail/test-programs traversal. Continue those and complete
tests-enabled world assembly, independent world/kernel/module/pkgbase/debug,
normal-service VM acceptance, CPU/RAM/disk-I/O/footprint, bootstrap/cache/sandbox/
reproducibility and verified combined publication, filling ARM64/RISC-V gaps
alongside shared work. Full-world tests guards remain until closure; Make default;
BIP excluded; no host installation/upgrade/reboot. Available storage is close to
the qualification cache's 10 GiB free-space floor; inspect/reclaim reproducible
build data before larger builds, preserving retained qualification evidence.

## Complete selected AMD64 libxo test and parent construction (2026-11-06)

All eleven original core programs, test encoder and 206 saved output/error files
build natively. All 233 test records and twelve ELF/debug contracts match Make.
The complete tests-enabled production/test parent builds four archives and
matches all 324 Make records and 293 non-ELF/non-archive payload bytes, including
manual hardlinks. All 92 non-encoder bodies pass; eleven absolute-path encoder
cases remain disposable-system work. A shared original harness fix makes all
103 registrations unique and exposes four stale default-text references; five
references are corrected from existing explicit-text expectations, after source
review and unchanged native/Make output identity. Retained failures and final
bindings are in LIBXO-TEST-QUALIFICATION.md.

One more initial missing declaration root closes, leaving three: ATF C tests,
ATF parent and libbe tests. Nested/existing roots still require closure. Continue
full tests-enabled world assembly, independent world/kernel/module/pkgbase/debug,
normal-service VM acceptance, CPU/RAM/disk-I/O/footprint, bootstrap/cache/sandbox/
reproducibility and verified combined publication, filling ARM64/RISC-V gaps
alongside shared work. Full-world tests guards stay where children are incomplete;
Make remains default; BIP excluded; no host installation/upgrade/reboot.

## Complete selected AMD64 libarchive test construction (2026-11-06)

All 356 original translation units, 446 reference files and 450 installation
records build natively and match independent Make installation/ELF/debug
contracts. All five library/CLI registries match original source selection and
grep output (836/73/49/28/18 registrations). Seven generator boundary methods
pass. Controlled private-header mutation rebuilds exactly three affected sources;
warm and restored builds execute zero compiles. Final artifacts are byte-restored.
Three original in-memory bodies pass with zero skips and Make-matching assertion
counts; 833 libarchive bodies and the original ATF wrapper remain unqualified.
See LIBARCHIVE-TEST-QUALIFICATION.md for immutable evidence and retained failures.

One more initial missing declaration root closes, leaving four: ATF C tests,
ATF parent, libbe tests and libxo tests. Nested directories and existing BUILD
roots still require independent closure. Continue full tests-enabled world
assembly and remaining parents, independent world/kernel/modules/pkgbase/debug,
normal-service VM qualification, CPU/RAM/disk-I/O/footprint, bootstrap/cache/
sandbox/reproducibility and verified combined publication. Fill ARM64/RISC-V
gaps in shared work. Full-tests guards remain; Make default; BIP excluded;
no host installation/upgrade/reboot.

## Original AMD64 Casper fileargs and services dispatcher (2026-11-06)

The original fileargs program matches fresh Make three-record metadata/Kyua/
directory and ELF/debug contracts. All eleven cleanup-bearing authority cases
execute from installation-form code with native broker/service libraries and pass,
no skips/expected failures. The original directory-discovering services parent
matches a separate Make file/directory control; real SDK Kyua metadata discovery
sees an added/removed private child without parent changes (11/22/11 cases).
FILEARGS-TEST-QUALIFICATION.md records final bindings and the retained first
header-visibility analysis failure. Two more initially missing declaration roots
are closed; five initially discovered roots remain without sibling BUILD files.
Other existing/nested roots still need full inventory and qualification.

Continue remaining base test parents and full tests-enabled world assembly,
independent world/kernel/modules/debug/pkgbase and normal-service VM gates,
CPU/RAM/disk-I/O/footprint, bootstrap/cache/sandbox/reproducibility and verified
combined publication. Fill ARM64/RISC-V gaps alongside shared work. Dispatcher
discovery does not qualify unreviewed sibling suites. Full-tests guards stay;
Make remains default; BIP excluded; no host installation/upgrade/reboot.

## Complete selected AMD64 libproc test construction/runtime (2026-11-06)

The original test, dynamic helper and fully static helper now match fresh Make
seven-record metadata/Kyua/directory and dynamic/static ELF/debug contracts.
Original -O0 and STRIP= behavior, local/weak/strong aliases and native transitive
static-link providers are retained. All ten original installed-form mapping/
symbol/breakpoint/signal cases execute and pass; no skips/expected failures.
Source-settings is one separate cached helper result. See
PROC-TEST-QUALIFICATION.md for final artifact bindings and exact limits.
One more missing declaration root is closed; seven initially discovered roots
remain without sibling BUILD files, with nested traversal/existing roots still
requiring independent qualification rather than file-presence assumptions.

Continue remaining base test parents, full tests-enabled world assembly,
independent world/kernel/modules/debug/pkgbase closure and normal-service VM
qualification, then CPU/RAM/disk-I/O/footprint, bootstrap/cache/sandbox/
reproducibility and verified combined publication. Keep fixing ARM64/RISC-V gaps
in shared work. Full-tests guards stay; Make default; BIP excluded; no host install.

## Complete selected non-ASan AMD64 libnv construction and runtime (2026-11-06)

All eleven original C/C++ ATF and TAP programs and 23 installation records match
fresh independent Make metadata, Kyua/directory and ELF/debug contracts. All
131 ATF registrations match; 129 cases pass, one original ASan-required case
skips, and one global-sysctl case remains guest work. All six TAP programs pass
Kyua with retained native libnv/libc/libsys loader receipts/databases. Normal and
runtime TAP links reuse identical declared object inputs; only the explicit
private runtime RPATH/output path differs. The original datagram sysctl test
needs failure/skip/interruption restoration before privileged guest qualification.
Positive ASan coverage is still open. NV-TEST-QUALIFICATION.md records final
bindings and the retained initial configured-link-count audit failure.
This closes one more missing declaration root; eight initially discovered roots
remain without sibling BUILD files. Existing BUILD presence is not qualification.

Continue remaining base installed-test parents and full tests-enabled world
composition, independent world/kernel/modules/debug/pkgbase, normal-service VM
qualification, CPU/RAM/disk-I/O/footprint, bootstrap/cache/sandbox/reproducibility
and verified combined publication. Fill ARM64/RISC-V gaps alongside shared work.
Full-tests guards stay; Make default; BIP excluded; no host installation/reboot.

## Four complete selected AMD64 library test constructions (2026-11-06)

librt, libsbuf, libexecinfo and libkvm now provide all twelve original selected
programs and 28 installation records, matching fresh independent Make metadata,
Kyua/directory and ELF/debug contracts. libexecinfo retains its original STRIP=
symbol tables through an explicit maintained installation option. All 33 reviewed
host cases execute from installation-form binaries and pass; all 48 registrations
and privilege/cleanup/deadline policies match Make. Fifteen original root/named-
semaphore cases remain manual guest work, not skips. See
FOUR-LIBRARY-TEST-QUALIFICATION.md for complete evidence and exact deferred labels.
This closes four more previously missing sibling BUILD roots; nine discovered
roots still need declarations, and existing file presence is not qualification.

Continue the remaining base test parents and full tests-enabled world assembly,
then independent whole installation/kernel/module/debug/pkgbase and normal-service
VM gates, CPU/RAM/disk-I/O/footprint, bootstrap/cache/sandbox/reproducibility and
verified combined publication. Address ARM64/RISC-V shared gaps without claiming
unexecuted profiles. Full-tests guards stay; Make default; BIP excluded.

## Complete selected AMD64 libm test suite (2026-11-06)

All 47 original programs and 95 installation records match fresh independent
Make metadata, directory/Kyua and ELF/debug-link contracts. Actual metadata for
all 463 original cases matches; all 463 execute and pass with native libraries,
no skips or expected failures. Final 464 target results include one separate
source-settings helper and are valid cache hits. Both registered compile variants
retain original FP definitions, -fno-builtin, source aliases and declared headers.
See MSUN-TEST-QUALIFICATION.md for final bindings and retained first failures.
This closes msun from the previous missing-library-test-directory inventory;
13 discovered roots still lack sibling BUILD files, and file presence alone does
not qualify the other existing roots. RISC-V expected-death ATF handling is a
concrete shared-runner gap to close with its cross-ABI/math qualification.

Continue AMD64 remaining base installed-test composition, whole installation/
kernel/modules/debug/pkgbase and normal-service VM gates, then controlled CPU/
RAM/disk-I-O/footprint, bootstrap/cache/sandbox/reproducibility and publication.
Fill ARM64/RISC-V gaps alongside shared work without claiming unexecuted ABI
profiles. Full-tests guards remain. Make default; BIP excluded; no host upgrade.

## Complete selected AMD64 libc test parent and SSP (2026-11-06)

The complete selected libc test parent now builds 31 installation archives.
A fresh original Make parent confirms all 870 original records against 872 native
records, exact 106 scripts/fixtures/Kyuafiles and original directory contracts.
All 375 common executables and five DSOs pass independent ELF/debug-link review.
The two additions are the native-built sanitizer helper and its debug file;
independent positive-runtime Make comparison remains open. All 19 original SSP
cases pass (plus one source-settings helper); no skips. The all-disabled optional
profile builds 28 archives/772 records and matches actual Make traversal queries.
Retained failed audits and exact bounds: LIBC-TEST-PARENT-QUALIFICATION.md.

A directory inventory finds 69 lib/**/tests/Makefile roots: 55 have sibling
BUILD.bazel files and 14 do not (ATF C/parent, libarchive, libbe, Casper services/
cap_fileargs, libexecinfo, libkvm, libnv, libproc, librt, libsbuf, libxo, msun).
Evidence: bazel-library-test-directory-inventory-r1-20261106/inventory.json under
/usr/obj/usr/src. This is file-presence discovery, not proof that 55 roots are
complete or that nested children and selected Make reachability are covered.

Drive AMD64 system-wide completion next: compose remaining base installed-test
parents, independent assembled-world/kernel/module/debug/pkgbase closure, then
normal-system boot/services and comparative CPU/RAM/disk-I/O/footprint, bootstrap,
cache/sandbox/reproducibility and combined publication. Fill ARM64/RISC-V gaps in
shared work as encountered; neither cross platform nor AMD64 system acceptance
is complete. Do not remove the full-tests guards until their whole scope is
covered. Make stays production/default; BIP excluded; no host upgrade/reboot.

## Original AMD64 iconv installation (2026-11-06)

The program, separate debug file and Kyuafile now match all three original Make
installation records and directory policy. Dynamic ELF/debug-link contracts and
actual one-case ATF metadata listings match. Independent comparison rejected the
first libc-before-ATF dependency order; the declared final-consumer sequence now
matches original Make. The old VM fixture target remains an alias. The original
case body needs real installed Citrus resources and is not executed here. See
LIBC-ICONV-TEST-QUALIFICATION.md for retained failed/final evidence and scope.

Next: SSP construction and complete libc test-parent traversal, followed by
installed-guest cohorts. Complete world/pkgbase/cross/bootstrap/cache/sandbox/
reproducibility/normal-service/performance/publication gates remain open. Make
stays default; BIP excluded.

## Complete original AMD64 gen/execve/spawn construction (2026-11-06)

All 67 original executables (64 ATF programs and three helpers), the test DSO and
143 installed records match independent Make metadata/link/Kyua/script/fixture/
ELF/debug contracts. The login-record test retains fully static EXEC linkage,
qualified through explicit static verifier API/CLI checks without weakening
dynamic defaults. All 239 case metadata listings and adapter policies match.
Thirty-eight selected host cases yield 36 passes and two original architecture
skips. Three executable fixture byte/mode checks pass. The remaining 201 cases
are unexecuted manual/deferred work. See LIBC-GEN-TEST-QUALIFICATION.md for final
receipts, fixture semantics, skipped coverage and retained first analysis failure.

Next: libc SSP/iconv installation and complete parent traversal, then disposable
installed-guest cohorts. All full world/pkgbase/cross/bootstrap/cache/sandbox/
reproducibility/normal-service/performance/publication gates remain open. Make
stays default, BIP excluded.

## Complete original AMD64 system-call test construction (2026-11-06)

All 63 selected original programs and 128 installed records match independent
Make inventory/metadata/Kyua/fixture/ELF/debug contracts. All 283 case registrations,
72 cleanup requirements and original users/deadlines match. Nineteen reviewed
bounded host cases pass without skips. The other 264 cases remain unexecuted
manual/deferred work; package-owned ownership and global-state tests require
actual guest installation, not a user-owned Bazel fixture. Configured action
analysis preserves the textual wait input and both two-source mlock consumers.
See LIBC-SYS-TEST-QUALIFICATION.md for final receipts, scope and retained diagnostics.

Next: remaining libc gen/ssp/iconv installation and parent traversal, alongside
resource-bounded disposable-guest runtime cohorts. All independent full world/
pkgbase/cross/bootstrap/cache/sandbox/reproducibility/normal-service/performance/
publication gates remain open. Make stays default; BIP excluded.

## Complete original stdlib construction and bounded host cases (2026-11-06)

Thirty-six original executables, both native dlopen DSOs and seventy-eight
installation records now match independent Make metadata/ELF/debug/Kyua/script
contracts. All 136 C/C++ case registrations/metadata and two custom deadlines
match. Five declared monetary/numeric payloads match original Make. Of 132
selected stdlib cases, 130 pass, one original expected signal failure and one
unconditional original skip remain explicit. Both getopt cases and all thirty
locale cases run. The native supervisor validates real expected signals with
thirty lifecycle regression methods. Final combined 171-target reports retain
169 pass entries, one expected failure and one skip. Six system/benchmark cases
remain unexecuted. See LIBC-STDLIB-TEST-QUALIFICATION.md for exact scope, receipts,
original exceptions and retained failed attempts. Network outputs remain stable
through shared C++ policy consolidation. Plugins/runtime data are consumer-scoped.

Next: remaining libc gen/sys/ssp contributions and test-parent traversal;
disposable-guest system/network cases and resource-bounded benchmarks. All full
world/pkgbase/cross/bootstrap/cache/sandbox/reproducibility/normal-runtime/
performance/publication gates remain open. Make stays default; BIP excluded.

## Complete original network/getaddrinfo construction (2026-11-06)

All thirteen original programs, including two C++20 programs, four shell suites,
two configuration fixtures and twenty-six expected-output fixtures now build and
install. Sixty records, exact scripts/data/Kyua, thirteen ELF/dependency/hardening
contracts and split-debug checks match independent original Make. Forty original
C/C++ case metadata listings match; thirty-seven selected host cases pass without
skips. Native compiler-runtime ordering was corrected after a real ELF mismatch;
ATF shell dirname is explicit. Final outputs retain all six independently reviewed
installation hashes. See LIBC-NET-TEST-QUALIFICATION.md for receipts and retained
failed attempts. Six resolver C and fourteen VNET shell cases remain unexecuted.

Next: remaining libc families/test-parent traversal and disposable guest network
coverage. Keep all independent whole-world/pkgbase/cross/bootstrap/cache/sandbox/
reproducibility/runtime/performance/publication gates; Make default, BIP excluded.

## Network generator groundwork (2026-11-05)

Original gen_ether_subr now runs as a declared native action using explicit
output-file argument support. Captured output and unchanged stdout-mode GENERIC
assym/offset outputs match independent Make bytes. See
LIBC-NET-GENERATOR-QUALIFICATION.md. This does not complete the network suite;
next are original C/C++20 programs, shell/helper/data installation and bounded
runtime qualification. All whole-system gates below remain open.

## Complete selected locale/fortify suites execute in bounded VM (2026-11-05)

A declarative installed-ATF plan now drives actual program metadata/case selection
through the maintained fixture assembler and daemon-runtime VM harness. The final
2 GiB guest executes all 418 original locale/fortify cases: 417 pass, one original
iconv PR 59019 expected failure, zero skips. All ten root/jail and five terminal
fortify cases pass. Native programs, Citrus resources and locale data use real
installed paths on a disk-backed 768 MiB UFS root; SDK loader/Python and supplied
matching execution kernel remain explicit bootstrap inputs. Peak sampled QEMU RSS
is 688205824 bytes under the enforced 3 GiB cap; no performance comparison claim.
Independent review verifies exact original case/user inventory and preserves all
six prior Make-reviewed installation output hashes. See
INSTALLED-ATF-VM-QUALIFICATION.md for final receipts, expected failure, unsupported
embedded locale scenarios and retained failed attempt. This closes the previously
pending ten locale-resource and ten root fortify cases for this selected profile.

Continue remaining libc/test roots and parent traversal, source-owned archive
ordering, independent whole-world/debug/pkgbase acceptance, other ABI/options,
Bazel kernel/module execution, bootstrap/cache/sandbox/reproducibility, normal
system/services, controlled CPU/memory/disk-I/O/resource comparisons and combined
hardware publication. Make stays production/default, full-tests guards remain;
BIP excluded. Fixture boot is not verified boot or a complete installed OS proof.

## Complete locale-test construction; installed-resource cases open (2026-11-05)

All twenty-eight original local/imported locale programs now build/install with
five local aliases and scoped compatibility/diagnostic policy. Fifty-seven file
records, exact Kyua, twenty-eight ELF/interface/hardening contracts and debug CRCs
match original Make. All forty original case registrations/metadata match. Eight
physical native LC_CTYPE payloads (nine requested identities) match original Make
bytes, following maintained ctypedef aliases. Thirty host cases pass; unsupported
individual NetBSD locale scenarios remain explicitly reported, not claimed tested.
Final r2 retains reviewed output hashes and captured runtime/data payloads. See
LIBC-LOCALE-TEST-QUALIFICATION.md for exact scope and unsupported scenarios.

Next: execute the ten ICONV-enabled c16rtomb/mbrtoc16/iconv cases with declared
native installed Citrus modules/data in a disposable VM, using existing maintained
fixture/harness work and real installed paths. Those cases are built/installed but
not runtime-qualified here. Continue remaining libc/test roots, parent traversal,
source-owned archive ordering and all independent whole-world/debug/pkgbase/cross/
bootstrap/runtime/resource/cache/sandbox/publication gates. Full-tests guards and
Make default remain; BIP excluded.

## Complete fortify installation and ordinary runtime coverage (2026-11-05)

All twelve original fortify programs and twenty-five installed records match
original Make, including exact Kyua, twelve ELF/interface/hardening contracts and
debug CRCs. Every one of the 378 original ATF case registrations and full metadata
matches; ten original root/jail cases have a separate explicit privileged suite.
Final native r3 passes all 368 ordinary cases without skips. Five terminal cases
initially skipped; real stdin PTY support now executes them without source changes.
The maintained supervisor preserves output capture, process groups, deadlines and
cleanup; 25 lifecycle regressions include real PTYs and initially closed stdin.
Final 371-target detailed reports contain only passes. All twelve final archive/
metadata outputs retain independent secure and prior local-suite review bindings.
See LIBC-FORTIFY-TEST-QUALIFICATION.md for retained skips and scope boundaries.

Ten privileged fortify cases remain VM work. Continue remaining libc/test roots
and parent traversal, source-owned archive ordering and all independent whole-world/
debug/pkgbase/cross/bootstrap/runtime/resource/cache/sandbox/publication gates.
Full-tests guards and Make as production/default remain. BIP stays excluded.

## Complete original hash contribution and selector acceptance fix (2026-11-05)

Both original programs, shell wrapper and all five fixtures now build/install;
five original runtime cases pass. Enabled eleven-file and disabled nine-file
inventories, exact scripts/data/Kyua, directory attributes and ELF/debug contracts
match independent original Make controls. OpenSSL-disabled inventory records the
three SHA2 tests as incompatible, not passed. Source-owned ABI imports retain the
original md/crypto library order and compatibility headers.

Review exposed an acceptance defect: an unexpanded suite alias could disappear
behind another passing requested test. The maintained backend now validates every
requested selector independently, with no extra query for direct tests. An actual
negative frontend run rejects the formerly accepted alias, and twenty-three
inventory regression methods pass under Bazel. The misleading one-test diagnostic
is retained and explicitly not hash runtime proof. See
LIBC-HASH-TEST-QUALIFICATION.md for evidence, failures and exact limits.

Continue remaining libc/test roots and parent traversal, source-owned archive
ordering and every independent whole-world/debug/pkgbase/cross/bootstrap/runtime/
resource/cache/sandbox/publication gate. Full-tests guards and Make default remain;
BIP stays excluded. Earlier qualification scope is not widened by this checkpoint.

## Complete selected NSS/resolver/stdtime construction (2026-11-05)

All eleven original programs and twenty-seven installed file records now match
original Make, including original host lists, Kyua timeout, dynamic pthread
resolver, debug CRCs and eleven ELF/interface/hardening contracts. Forty-four
native account/group/protocol/RPC/service/shell cases and the original day-of-week
case pass. Host-dependent NSS cases are external/no-remote: repeated final runs
freshly execute all forty-four while two independent targets remain cached.
Final r4 retains all nine independently reviewed installation output hashes.
Shared warning policies match Make and existing levels retain identical flags.
See LIBC-LOCAL-TEST-BATCH-QUALIFICATION.md for exact scopes and retained evidence.

External DNS and privileged/zoneinfo/timezone-change scenarios remain installed-
system requirements. Continue remaining libc/test roots and parent traversal,
source-owned archive ordering and every independent whole-world/debug/pkgbase/
cross/bootstrap/runtime/resource/cache/sandbox/publication gate. Full-tests parent
guards and Make as production/default remain. BIP stays excluded.

## Complete libc regex suite construction and execution (2026-11-05)

All three original C programs, two shell suites, README and twenty-six fixture
files now build/install with original flags, private headers and native libc
regex behavior. All thirty-six installed file records, exact nonbinary bytes,
physical suite/data/debug directories, three ELF contracts and debug CRCs match
original Make. All thirty original cases run: twenty-nine pass and leftassoc
retains its original expected failure. Shell cases use declared native tools,
C++ runtimes and C.UTF-8 data; exhaustion retains its original 256 MiB bound.
Final frontend r5 passes 31 targets including source settings, retaining explicit
expected-failure reporting. See LIBC-REGEX-TEST-QUALIFICATION.md for failures and
independent hash-bound review. Existing WARNS=2/4 flag lists remain identical.

Continue remaining libc/test roots and parent traversal, source-owned archive
ordering and every independent whole-world/debug/pkgbase/cross/bootstrap/runtime/
resource/cache/sandbox/publication gate. Make stays default, BIP excluded.

## Complete selected libc TLS construction (2026-11-05)

Both selected original TLS programs, two helper DSOs and two static archives now
build and install. All twelve installed file/link records and exact Kyua bytes
match original Make; two program, two DSO and two archive contracts plus debug
CRCs pass. ABI imports preserve original helper-first dependency order and the
dlopen plugin's unresolved main-program callbacks. Explicit path comparison
inputs preserve original RUNPATH while retaining default rejection and hardening.
Ten regression methods and both original native cases pass. An independent fresh
execution traces actual opens of both captured native helpers, ruling out host TLS
helper substitution. See LIBC-TLS-TEST-QUALIFICATION.md for evidence and failures.

Continue remaining libc/test roots and parent traversal, source-owned archive
ordering and independent whole-world/debug/pkgbase/cross/bootstrap/runtime/
resource/cache/sandbox/publication gates. Full-tests parent guards and Make as
production/default remain. No whole-system completion or performance claim.

## Complete libc stdio-test construction (2026-11-05)

All thirty original stdio programs now build/install with original aliases,
scoped compatibility/math/MD dependencies and only the four original format-warning
exceptions. All 75 selected native cases pass, including C23 narrow/wide formats,
floating-point rounding/locales, streams and interrupted I/O. Numeric fixtures
follow maintained source locale/alias inventories in private runtime paths.
All 61 installed records and exact Kyua bytes match fresh Make; thirty ELF/
hardening and native/original debug CRC contracts pass. Final frontend r2 passes
76 targets from cache and separately freezes four numeric data payloads while
retaining all three independently reviewed installation outputs. See
LIBC-STDIO-TEST-QUALIFICATION.md. No original C test was rewritten.

Continue remaining stdio/libc/test roots and parent Kyua/helper/data traversal,
full installed-system case/privilege/PTY coverage, source-owned archive ordering
and every whole-world/debug/pkgbase/cross/bootstrap/runtime/resource/cache/sandbox/
publication gate. Full test-enabled guards remain and Make stays default.

## Complete libc string-test construction (2026-11-05)

All 42 original string programs now build/install with original source aliases,
no-builtin policy and selective compatibility/libmd linkage. Eight textual C
consumers use exact per-body textual_hdrs dependencies. All 85 installed file
records and exact Kyua bytes match fresh original Make; 42 ELF/hardening contracts
and native/original debug CRCs pass. All 31 selected native runtime cases pass,
including six libmd-dependent cases. Final frontend r3 passes 32 targets from
cache and all three final installation outputs retain independent review bindings.
See LIBC-STRING-TEST-QUALIFICATION.md. No original C program was rewritten.

Remaining string/locale cases, libc and other test roots, parent Kyua/helper/data
traversal and every full-system/cross/bootstrap/runtime/resource/publication gate
remain open. Source-owned archive ordering and independent whole-world/debug/
pkgbase parity still require acceptance. Full test-enabled parent guards remain;
Make stays the production default and BIP stays excluded.

## Complete libc DB/RPC test contributions (2026-11-05)

DB now builds five ATF C programs and two helpers plus the real transformed shell
suite and README. RPC uses its actual native-libc installed programs and declared
rpcgen products; SDK-runtime/partial-object prototypes are removed. Sixteen DB
and two local RPC cases pass. Final frontend r3 passes nineteen targets (cache
hits). All nine program ELF/hardening and debug CRC contracts, 22 installed file
records, exact script/README/Kyua bytes and both generated RPC products match
fresh original Make. Shared compiler policy extraction preserves all eighteen
prior six-family installation outputs. See LIBC-DB-RPC-TEST-QUALIFICATION.md for
retained parser/order failures and exact scope.

DB shell/dictionary scenarios, external RPC network cases and remaining libc/
parent test hierarchy still require installed-system qualification. Full-tests
parent guards stay active. Continue remaining test roots, source-owned archive
ordering and every independent whole-world/debug/pkgbase/cross/bootstrap/runtime/
resource/cache/sandbox/publication gate. Make stays default; BIP excluded.

## Six libc installed-test families added (2026-11-05)

C063/inet/setjmp/termios/time/ttyio now build all 24 selected original programs,
24 debug files and six Kyuafiles through source-owned native declarations. All 54
installed file records, exact Kyua bytes and 24 ELF interface/hardening contracts
match original Make; native/original debug CRCs pass. The original threadjmp
pthread dependency named an absent program; both Make and Bazel now select the
real pthread library and a fresh original control validates the correction.
Twenty-six original ATF cases pass against native runtime libraries, including
real pthread and PTY behavior. Final frontend r2 passes 28 targets (one fresh
reader regression, 27 cache hits). All eighteen final installation outputs retain
independent review bindings. See LIBC-NETBSD-TEST-BATCH-QUALIFICATION.md.

C063 privilege/filesystem cases and termios terminal behavior remain unexecuted;
the latter returns without checking when stdin is not a terminal. No headless
pass substitutes for terminal evidence. Finish remaining libc/test roots, parent
Kyua/helper/data composition and installed-system cases, along with source-owned
archive ordering and all whole-system/cross/bootstrap/resource/publication gates.
Full tests-enabled parent guards remain; Make stays production/default.

## ELF comparison I/O correction (2026-11-05)

The maintained comparison helper now streams actual ELF section ranges after one
readelf table query, removing full-file scratch copies and objcopy processes per
section. All 28 retained ELF64 section maps, a real ELF32 boot object and compressed
split-debug control agree exactly. Eight regression methods pass freshly through
Bazel. Metadata/interface/hardening checks are unchanged. See
ELF-SECTION-READER-QUALIFICATION.md. This improves diagnostic overhead; controlled
whole-build/system CPU/memory/disk performance acceptance remains open.

## Libc stdbit installed-test contribution (2026-11-05)

All fourteen original stdbit programs now build natively with declared textual
framework inputs and original no-builtin policy. The seventy ATF operation/type
cases pass with native libc/libsys/ATF. Complete installed file metadata and exact
Kyua bytes match fresh original Make; all fourteen ELF interfaces/hardening and
native debug CRCs pass. The shared test archive helper derives debug ancestors
from its declared directory and existing policy. All 27 previous TAP outputs
remain byte-identical. Final maintained frontend r5 passes 71 test targets (cache
hits); see LIBC-STDBIT-TEST-QUALIFICATION.md for evidence and retained failures.

Continue remaining libc and other installed-test owners, helper DSOs/fixtures and
parent Kyua composition. Full tests-enabled parent guards remain active. Archive
ordering, independent whole-world/debug/pkgbase parity and every cross/bootstrap/
runtime/resource/cache/sandbox/publication gate remain open. Make stays default.

## Current world construction includes rescue/libc corrections (2026-11-05)

The combined production contribution/product build passes through the maintained
frontend with 16 jobs and all nine selected tests passing as cache hits. The
actual rescue executable and real rescue package are included. The immutable
review verifies 1279 archives, 32515 nondirectory paths with no duplicate claims,
and all 3566 directory claims across 789 unique destinations with consistent
physical attributes and no file/directory collisions. Both manual indexes match
Make on this same native corpus (11596 main / 6373 OpenSSL paths). See
WORLD-CONTRIBUTION-FINALIZATION.md for exact evidence and the explicit NIS-disabled,
production-malloc profile; counts are not completion percentages.

Next: source-owned archive ordering and complete installed test roots, independent
whole-world installation/debug/pkgbase parity, then the remaining bootstrap,
configuration/cross/runtime/resource/cache/sandbox and publication gates. Current
contribution construction is proven; complete world acceptance is not. Make stays
default, BIP excluded, no host upgrade.

## Fresh libc comparison and weak DTrace aliases (2026-11-05)

A fresh original Make libc parent builds/stages successfully, including configured
test binaries. Its 1455 regular archive members compare with the native alias
checkpoint: 1396 exact nondebug contracts, 57 filename controls, one path-derived
DTrace symbol case and one provider case. All 57 independent original filename
controls and 12 real provider-to-code bindings pass. The review found and fixed
the DOF verifier's missing hidden weak alias support; matching binding, visibility,
function bounds and patch validation remain mandatory. See
LIBC-SOURCE-ALIASES-QUALIFICATION.md for retained failures and evidence scopes.
Raw member ordering/naming/debug, other libc variants and final ELF acceptance
remain open, along with every full-system/cross/runtime/resource gate below.

## Libc source identities and bounded rescue controls (2026-11-05)

Native source producers now preserve original gdtoa/jemalloc prefixes,
C99_Exit and cancelpoints_ aliases before compilation. The real libc archive
identity/extraction test and six existing libc/rescue/source-settings targets
pass through maintained frontend r3 (six cache hits). Retained r1/r2 failures
and fixes are documented in LIBC-SOURCE-ALIASES-QUALIFICATION.md.
Independent original compiler controls account for all 45 application filename
string differences; actual path hashes explain 21 DTrace alias-only differences;
23 provider cohorts validate 64 code bindings. These are bounded earlier-run
controls, not whole-library/debug/live-tracing or final ELF parity.

Next: source-owned libc archive ordering and independent library/startup payload
review. Root-only private pkg tests and every full-system/cross/runtime/resource/
cache/sandbox gate remain open. Make stays default; no BIP or host upgrade.

## Rescue installation, world membership and actual pkgbase candidate (2026-11-05)

Native rescue now has its actual rescue-named dispatcher, shared source-owned
assembly, original no-debug installation, suppressed login aliases, hardlinks,
owned directory and actual DHCP sed generation. All 142 metadata/inode records
and script bytes match a fresh full Make parent build/stage. Six installed-layout
runtime methods join 107+5 runtime and 28 source-setting methods; 146 pass for
both development and explicit matching-production-malloc controls. Original Make
on identical native inputs reproduces all 208 rescue-named pipeline outputs.
World include/exclude selection works through MK_RESCUE-equivalent settings.
The existing rescue.ucl now has native single-package construction; its real
archive inventory, exact script/ELF payloads and private tar hardlinks/modes pass.
See RESCUE-INSTALLATION-QUALIFICATION.md for immutable evidence and retained
failures. No host installation/publication/reboot occurred; Make stays default.

Remaining independent parity is concrete: matching malloc reduces final ELF size
difference to 3064 bytes but does not make bytes equal. All 592 application objects
were independently compared: 503 direct contracts match; 45 read-only string,
23 DOF and 21 symbolic/relocation differences remain recorded. Reconcile these
and common-library/startup contributions before claiming independent complete
rescue payload parity. Private pkg add/check/delete needs OS root or a guest;
the exact maintained command is prepared under the package review directory.
Then guest recovery/helper/PID1/services, other options/architectures and every
full-world/kernel/pkgbase/bootstrap/resource/cache/sandbox gate remain required.

## Configured rescue and real untraced-policy correction (2026-11-05)

The core now selects programs and compiler/link inputs through standard select
expressions and ordered typed compiler metadata. A shared candidate catalog
replaces the duplicate parent allowlist. Common links restore original alias/
devstat archives and conditionally omit ZFS/iSCSI support. Default passes 107+5
runtime and 28 source-setting methods; all 208 current pipeline outputs retain
original same-input Make byte parity. Independently configured original Make
matches all 92 reduced-program names/aliases/ordered objects, both with tracing
and with tracing disabled. The first untraced run exposed ten unconditional
legacy rescue providers despite passing smoke tests; source policies are fixed,
enabled behavior is preserved and a maintained provider-selection regression
method passes. Executed reduced common-link arguments match all 32 original
archive roles/order. See RESCUE-CONFIGURATION-QUALIFICATION.md for retained
failures, exact scopes and inputs.

Next priority: actual rescue-named dispatch, original no-debug-file installation,
hardlinks/suppressed login aliases and generated dhclient-script; staged pkgbase
metadata and guest helper/recovery qualification. Do not install a renamed
rescue_core as a substitute. Remaining option combinations, cross/independent
library/debug/runtime/resource/cache/sandbox and every full-system gate remain.
Make stays default; BIP excluded; no host upgrade or reboot.

## Recovery helper objects connected to native rescue (2026-11-05)

Seven native librescue replacements now link directly after crunched programs
and before ordinary archives, preserving original override semantics. A fresh
Make reference explicitly matches the native NIS-enabled selection; all seven
ELF payload/symbol/relocation contracts agree. Native frontend r2 passes 107
runtime plus 28 source-setting methods; original Make reproduces all 208 entire
pipeline outputs with identical helper/object/archive inputs. Retained r1
configuration/order mismatches are documented in RESCUE-103-PROGRAM-QUALIFICATION.md.
Next: complete option composition and real rescue installation/aliases/helper
runtime qualification, then all remaining system gates. This closes composition,
not guest recovery behavior, full debug/resource parity or complete migration.

## Default rescue source selection reaches 103 applications (2026-11-05)

Bectl/zfs/zpool/zdb/zfsbootcfg complete default program selection in the bounded
AMD64 core. Source-owned compiler policies retain original include precedence,
inherited definitions, zfs_main source-specific warnings and zdb C99. Typed
metadata preserves each program's original archive extraction order. Maintained
frontend r4 passes 107 runtime methods plus 28 source-setting methods. All 14
new compiler policies, 2219 consumed dependencies, all 103 ordered object lists
and seven per-program archive lists match original Make. Seven diagnostic-path
object differences have independent original compiler controls; 208 pipeline
outputs are byte-identical on identical captured inputs. See
RESCUE-103-PROGRAM-QUALIFICATION.md for retained failures and exact scope.

Next priority is actual librescue overrides, complete configuration and
installation semantics. This is not installed rescue acceptance. Continue all
whole-world/kernel/modules/pkgbase/cross/bootstrap/runtime/performance/cache/
sandbox gates below. Make remains default; BIP excluded; no host upgrade/reboot.

## Native rescue expansion to ninety-eight applications (2026-11-05)

Camcontrol/geom/ifconfig/pfctl reach 98 of 103 default applications. Native core
object descriptors now consume typed ordered compiler metadata and exact DTrace
rewrite maps; manual parent route/ping object cases are removed. Source-specific
ifpf compilation and constructor order remain explicit, and program-specific
archives stay in original partial-link stages. Default and Netlink-disabled cores
pass 102 runtime methods plus 28 source-settings methods. All 98 descriptors and
two program archive lists match fresh original Make in each profile; disabled
route/ifconfig select two/23 objects. All 56 default compiler policies and 4844
consumed dependency occurrences are checked; one exact generated PF parser
occurrence remains explicitly byte-different with successful producer controls.
Original pipeline on identical inputs matches all 198 outputs. See
RESCUE-NINETY-EIGHT-PROGRAM-QUALIFICATION.md. Finish remaining five ZFS-family
applications, actual rescue libraries/config/cross/full installation and every
full-system gate. Make stays default; BIP excluded. No system/performance claim.

## Native rescue expansion to ninety-four applications (2026-11-05)

Sh/csh/vi reach 94 of 103 default applications. Final native r3 passes 99 runtime
methods plus 28 source-settings methods. All 196 compiler policies agree with
original Make; 166 fresh post-alias-fix executions and 30 retained executions bind
to immutable passing outputs. Eleven shell generator payloads match exactly;
original crunchgen/Make on identical inputs matches all 190 pipeline outputs.
The review found and fixed the missing native ncurses.h compilation alias instead
of accepting SDK fallback. All 17295 consumed occurrences are declared: eleven
exact comment differences, five proven alias uses and twelve proven virtual-parent
spellings remain explicit. Six diagnostic-path controls pass. See
RESCUE-NINETY-FOUR-PROGRAM-QUALIFICATION.md. Continue remaining nine applications,
actual libraries/config/cross/full install and every full-system gate. Diagnose
csh NO_NLS_CATALOGS policy: no bundled source consumer found; runtime disabled
catalog behavior is not established. Make stays default; BIP excluded.

## Native rescue expansion to ninety-one applications (2026-11-05)

Six init/network/iSCSI/archive owners reach 91 of 103 default applications.
Default and target-OpenSSL-disabled selected cores pass 95 runtime methods plus
28 source-settings methods, including private tar binary/link/compression round
trips. All 39 executed compiler policies agree with original Make with explicitly
bound init duplicate-macro and header-derived tar-version preprocessing controls.
Original crunchgen/Make on identical inputs matches all 184 outputs. DHCP's
anchored provider and five diagnostic-path controls pass. All 3031 consumed inputs
are declared; two raw generated C differences remain reported and require exact
original/native producer replays. Six ordinary declarations remain structurally
unchanged. See RESCUE-NINETY-ONE-PROGRAM-QUALIFICATION.md. Continue remaining 12
applications, actual libraries/config/cross/full install and every full-system gate.
Make stays default; BIP excluded. No installed-system/performance completion claim.
Diagnose the original iSCSI yacc PCP warning and qualify that configuration option.

## Native rescue expansion to eighty-five applications (2026-11-05)

Five UFS/NFS owners reach 85 of 103 default applications, sharing unchanged
ordinary source declarations. Passing native r2 executes 92 runtime methods plus
28 source-settings methods, including private UFS1/UFS2 five-phase checks, debugger
reads and dump/restore table reads with unchanged source hashes. All 51 actual
compiler policies and 3368 declared dependency occurrences agree with original
Make; successful actions from rejected r1 bind to immutable passing raw outputs.
Original crunchgen/Make on identical inputs matches all 172 pipeline outputs.
Fsck_ffs provider/function/patch sites and dump diagnostic-path controls pass.
See RESCUE-EIGHTY-FIVE-PROGRAM-QUALIFICATION.md. Continue remaining 18 applications,
actual libraries/config/cross/full installation and every full-system gate.
Make stays default; BIP excluded. No installed-system/performance completion claim.

## Native rescue expansion to eighty applications (2026-11-05)

Nine lifecycle/storage/transfer owners reach 80 of 103 default applications.
Default and target-OpenSSL-disabled cores pass 89 runtime methods and separate
28 source-settings methods. Fresh original Make produces 13 C objects and one
anchored mount provider with 4713 bindings. All actual compiler policies and 943
consumed dependency occurrences agree; original crunchgen/Make on identical
inputs matches all 162 pipeline outputs. The real nos-tun identifier/group bug
is fixed without renaming original files; rejected r1 remains retained. Disabled
final link omits SSL/crypto archives/symbols; host tools still need crypto.
See RESCUE-EIGHTY-PROGRAM-QUALIFICATION.md. Continue remaining 23 applications,
actual rescue libraries/config/cross/full install and full-system gates. Make
stays default; BIP excluded. No installed-system or performance acceptance claim.

## Native rescue expansion to seventy-one applications (2026-11-05)

Six owners add xz/zstd/less/route/rtsol/mount_msdosfs, reaching 71 of 103 default
applications. All ordinary declarations are preserved with shared source lists.
Original WARNS=1 and route AWK/Netlink/IPv4/IPv6/rescue options are explicit.
Both Netlink-enabled/disabled selected cores pass 84 runtime methods, including
requested two-worker compression. Fresh Make builds 81 C objects; all actual
compiler policies match, bound from successful actions in a failed-test run to
passing captures. Original generated Make on identical inputs matches all 144
pipeline outputs and the executable. All 5535 consumed occurrences are declared;
one exact generator-comment provenance difference remains explicitly reported
rather than claimed byte-identical. See RESCUE-SEVENTY-ONE-PROGRAM-QUALIFICATION.md.
Continue remaining 32 applications, actual libraries/options/cross/full install,
independent library/debug/header/pkgbase acceptance and all full-system gates.
Make stays default; BIP stays excluded.

## Native rescue expansion to sixty-five applications (2026-11-05)

Eight text/compression/digest/configuration/FAT tools bring the AMD64 core to
65 of 103 applications. Native compression/threading/digest archives and explicit
gzip textual C includes preserve source behavior. The runtime wrapper passes
78 methods, including binary compression/aliases and read-only checking of a
private FAT image. All seventeen actual compiler policies and 1032 declared/
hash-matched dependency occurrences agree with original Make's names/bytes.
Independent assertion-path/compiler/provider controls preserve untouched baselines;
actual sysctl and anchored FAT sites verify. Original generated Make on identical
inputs matches all 132 pipeline outputs and the executable. See
RESCUE-SIXTY-FIVE-PROGRAM-QUALIFICATION.md. Continue remaining 38 applications,
actual rescue libraries/options/cross/full installation and all full-system gates.
Review ordinary gzip's existing SDK DTrace/drti producer against the native
bootstrap path; rescue's source-mandated exclusion does not exercise it. Full
library/debug/raw-DOF, pkgbase/bootstrap/publication/VM/resource/cache/sandbox
acceptance remains open. Make stays default; BIP stays excluded.

## Native rescue expansion to fifty-seven applications (2026-11-05)

Eight filesystem tools bring the selected AMD64 core to 57 of 103 programs with
native libufs and anchored unmount provider. Explicit WARNS=2/3/6 profiles match
all fifteen actual original/native compiler recipes. All 999 consumed dependency
occurrences are declared/hash-matched, with matching original name/byte multisets;
full logical namespace and incremental invalidation are not yet qualified. The
runtime wrapper passes 71 methods, including real private UFS1/UFS2 create/read/
relabel/inode-generation/clear and FAT12 image creation. Original generated Make
on identical inputs matches all 116 pipeline outputs and the complete executable.
See RESCUE-FIFTY-SEVEN-PROGRAM-QUALIFICATION.md. Continue the remaining 46
applications, actual rescue libraries/options/cross/full installation; all full
world/kernel/pkgbase/bootstrap/publication/VM/resource/cache/sandbox gates remain
open. Make stays default; BIP stays excluded.

## Native rescue expansion to forty-nine applications (2026-11-05)

Thirteen system-program owners bring the selected AMD64 core to 49 of 103 default
applications. Native GEOM/bsdxml/kiconv/sbuf archives join original selected order.
The runtime wrapper passes 68 methods including eleven pre-mutation argument
rejection subcases and private rcorder graphs. Two mistaken test expectations
were corrected against source without changing production behavior; failed r1
is retained. Fresh original Make produces sixteen C/two provider objects; actual
provider/function/patch-site and independent diagnostic-filename controls pass.
Original generated Make on identical captured inputs matches all 100 pipeline
outputs and the complete executable. See RESCUE-FORTY-NINE-PROGRAM-QUALIFICATION.md.
Continue remaining 54 applications and actual rescue library/configuration/cross/
installation coverage. Positive privileged operations require disposable VMs;
full debug/raw-DOF/library/pkgbase/world/kernel/bootstrap/publication/runtime and
resource gates remain open. Make stays default; BIP stays excluded.

## Native rescue expansion to thirty-six applications (2026-11-05)

Nine further source owners add ls/df/ps/pkill/tail/tee/id/chroot/chown; the native
static core reaches 36 of 103 default applications and passes 64 runtime methods.
Declared lazy static imports preserve original selected archive order. Fresh
original nested Make builds produce 20 C/two provider objects; provider schemas,
actual function/patch sites and independently checked alias hashes agree.
Separate original compiler controls explain ps/pkill assertion-filename
strings without changing native or baseline bytes. Original generated Make on
identical captured inputs matches all 74 pipeline outputs including the complete
executable. See RESCUE-THIRTY-SIX-PROGRAM-QUALIFICATION.md. Continue the remaining
67 applications, actual rescue library variants, options/cross/full installation;
independent library/debug/raw-DOF parity and all full-world/kernel/pkgbase/
bootstrap/publication/runtime/resource gates stay open. Make stays default.

## Native rescue expansion to twenty-seven applications (2026-11-05)

Eight source-owned variants add date/chio/kenv/setfacl/stty/kill/sync/dd. The
native static core now links 27 of the default 103 applications and passes 54
runtime methods. Fresh original nested Make builds check 25 C objects and three
providers; allocated code/relocations agree, with independently verified DTrace
path aliases and actual function/patch-site parity. Fresh original generated
Make on identical captured inputs matches main, 27 stubs, 27 combined objects and
the complete executable in all 56 whole-byte comparisons. This is pipeline parity,
not independent complete library/debug/DOF/full-rescue acceptance. Sync is not
executed on the host. See RESCUE-TWENTY-SEVEN-PROGRAM-QUALIFICATION.md. Continue
remaining 76 applications, libraries/configuration/cross and full rescue install;
all full-world/kernel/pkgbase/bootstrap/publication/runtime/performance gates
remain open. Make stays production/default; BIP stays excluded.

## AMD64 boot parent construction and normal sys world (2026-11-05)

The selected native AMD64 boot parent now builds data, EFI/IA32/BIOS/userboot/
kboot producers and the internal userboot harness together; three tests pass.
Fresh complete original parent comparison closes unique inventory/metadata and
24 directory claims across 127 paths. It exposed and corrected btxld over-install,
the missing libsa manual and missing per-owner directory claims. 107 payloads
match exactly; sixteen binary/debug differences remain explicitly unresolved.
The repeated loader.help.efi claim now has one source-owned installation manifest;
standalone Lua/simple installs stay complete. All 127 records/payloads and 24
directory claims stay identical, no repeated file claims remain, and four tests
pass. The selected AMD64 stand parent now joins the world contribution graph
under BOOT; the combined construction and two tests pass. The combined
review verifies 1295 archives, 32454 unique file/link paths without collisions,
and both manual indexes against Make on the same assembled native corpus. See
WORLD-CONTRIBUTION-FINALIZATION.md; independent whole-world parity remains open. Do not call this full binary or boot acceptance.
See AMD64-BOOT-PARENT-CONSTRUCTION.md. Normal sys world traversal independently
has no payload without MODULES_WITH_WORLD; its explicit empty native contribution
is connected without creating a disruptive sys source package. The combined
world rerun and boot-data package-layout consumer pass; all 108 prior boot
target/output bindings retain exact content. Module-world
installation remains explicitly unsupported, not silently empty. Finish stand
binary/product/option/ABI gaps, rescue and installed tests; all complete
system installation/pkgbase/bootstrap/hardware/publication/runtime/resource gates
remain open. Make stays production/default; BIP stays excluded.

## Combined world contributions and finalization (2026-11-05)

A single maintained frontend invocation now builds the current native production
contribution roots, etc termcap/distribution and both manual databases. Its 1268
archives have 32327 unique non-directory paths. Main/OpenSSL indexes cover 11586/
6373 manual paths and match Make's indexer on that same assembled native corpus;
this is not independent Make installed-world parity. The final rerun includes
noninstalled internal products and keeps all reviewed installation outputs and
indexes identical. The combined graph caught a real LLVM Support subpackage
ownership error; explicit source-owner labels/header grouping preserve exact
source/option declarations and bootstrap/TableGen construction now passes.
See WORLD-CONTRIBUTION-FINALIZATION.md. Rescue/sys/stand/full tests and extension
roots remain absent: finish them, join the complete world/kernel/modules build,
then prove complete Make installation/debug/metadata/directories/pkgbase, bootstrap,
cross/configuration, hardware/publication, runtime/VM and resource/cache/sandbox
gates. Make remains production/default; BIP stays excluded.

## Native manual database dependency checkpoint (2026-11-05)

A typed native rule now indexes installed manual records with selected file inputs,
physical hardlink preservation and bounded symlink validation. A static native
mandoc execution variant generates bytes matching maintained Make makedb using an
independently Make-built tool and fresh original corpus: 4248 paths, 1426 inode
groups. Three real database/query/rejection test methods pass. Archive providers
carry static records plus explicit execution-expanded tree boundaries; the latter
cannot silently disappear from an overlapping manual corpus. The unrelated
zoneinfo variant excludes timezone payloads from its observed action inputs and
produces the same database. All 33 existing shared-manual outputs stay unchanged.
See MANUAL-DATABASE-QUALIFICATION.md. This is selected shared-manual generation,
not full-world afterinstall: join program/library/OpenSSL manuals during world
finalization, then qualify complete etc installation. Remaining rescue/sys/stand,
installed tests, full packaging/bootstrap/cross/runtime/resource gates stay open.
Make remains production/default; BIP stays excluded.

## Native etc distribution phase (2026-11-05)

Complete selected distribution profiles now match independent Make stages:
23 files/five links/two directories with sendmail, and nine files/three links/two
directories for the alternate GSS/test-specification profile. Native m4 actions
declare the source include closure; generated configuration bytes match exactly.
The original reference explicitly distinguishes install and distribution phases.
Review corrected the misplaced /etc/rmt utility-install claim; its three existing
payloads remain unchanged and original normal-install metadata matches. See
ETC-DISTRIBUTION-QUALIFICATION.md. This closes distribution for tested profiles,
not the complete etc parent: install/afterinstall manual databases, additional
sendmail configuration modes and other ABIs remain open. Continue remaining
etc/rescue/sys/stand/world composition and installed tests; all full-system,
bootstrap, package/publication/runtime/resource gates remain required. Make stays
production/default; BIP stays excluded.

## Complete selected include parent (2026-11-05)

The native include endpoint now composes ordinary/generated/RPC/fixed/kernel ABI
headers, architecture companions and aliases. Complete default original comparison
matches 1417 files, fourteen symlinks and three directory claims; includes-disabled
and optional-kernel-families-disabled profiles have independent full originals.
The latter keeps includes enabled so feature selections are actually exercised.
The reduced comparison caught and corrected an incorrect assumption about Make's
conditional realinstall dependency; rejected evidence is retained. Actual action
logs bind 1368 file inputs across 95 observed archives; nine up-to-date actions
remain unobserved, and all 312 default artifacts remain identical after the fix.
See COMPLETE-INCLUDE-QUALIFICATION.md. Default cross-capture namespace evidence
is 1265 archives/32297 non-directory paths without conflicts, not a combined world.
Continue remaining etc/rescue/sys/stand/world roots and installed tests; complete
installation/debug/pkgbase, bootstrap, cross/runtime/resource gates remain open.
Make stays production/default; BIP stays excluded.

## Ordinary public include checkpoint (2026-11-05)

Native source-owned declarations now install the 100 common ordinary public
headers and configured iconv, Hesiod and legacy GSS contributions. Default and
alternate selections match full independent Make include stages: 101 and 103
exact payloads with clibs/dev metadata. Includes-disabled is checked against its
own original profile. The common archive remains identical across optional
selection changes. See ROOT-PUBLIC-HEADERS-QUALIFICATION.md. Default cross-capture
namespace evidence is 1174 archives and 31093 non-directory paths without
conflicts; empty optional archives are included, not program/library counts.
Continue kernel/architecture public header groups and aliases, then complete
include/world composition and installed tests. Full installation/debug/pkgbase,
bootstrap, cross/runtime/resource gates remain open. Make stays production/default;
BIP stays excluded.

## Native osreldate generation checkpoint (2026-11-05)

The public OS version header now builds with declared source/copyright inputs
and SDK execution tools through maintained shell generators. A new explicit
copyright query and stateless stdout mode avoid source/clock discovery and
scratch files in the Bazel action. Fresh full Make include staging matches the
native header byte for byte and preserves clibs/dev metadata. Three meaningful
generation test methods and the source-settings target pass; altered fixture
inputs and missing/invalid inputs are exercised with only sh/awk/sed available.
Existing copyright/version-query/kernel explicit-version outputs retain exact
bytes against the previous committed script; no rebuilt-kernel claim is made.
All eighteen existing fixed-header outputs remain identical. See
OSRELDATE-GENERATION-QUALIFICATION.md. Namespace evidence is 1169 archives and
30992 non-directory paths without conflicts. Continue ordinary root/kernel/
architecture headers and aliases toward complete include/world construction;
all existing package/bootstrap/cross/runtime/resource gates remain required.
Make stays production/default; BIP stays excluded.

## Fixed public headers and Make reference destination correction (2026-11-05)

Six further public include children now match complete original stages: 89 files
and two companion directory records. The selected AMD64 parent has five archives;
the explicitly tested ARM companion data does not count as ARM64 target acceptance.
Companion directory tags and includes-disabled behavior match actual Make. A full
include reference exposed a harness defect: SYSROOT-derived SDESTDIR sent copies
to the object SDK. That baseline is rejected; eight missing SDK input contents
were recovered from the verified snapshot and all 8381 content bindings rechecked.
The maintained helper now passes SDESTDIR explicitly and verifies actual staged
objects/types/hashes/links. Bazel regression tests pass, including rejection of the
actual bad stage. The corrected complete original include baseline verifies 1417
file hashes and fourteen symlinks; it is not complete native include coverage.
See PUBLIC-FIXED-HEADERS-QUALIFICATION.md. Cross-capture AMD64 namespace evidence
is 1168 archives/30991 non-directory paths without conflicts. Continue root/kernel/
architecture headers and osreldate, then remaining world/system acceptance gates.
Make remains production/default; BIP is excluded.

## Public RPC include installation checkpoint (2026-11-05)

The native include RPC contribution now covers both complete maintained RPC/RPC
service header groups: 77 exact files/schemas and their clibs/dev metadata match
independent Make stages. Includes disabled matches both original empty stages.
The existing XDR round-trip and source-settings Bazel tests pass. Fresh build-state
and action-cache evidence observes all 22 public header generators, including the
declared nis_object.x dependency; all 23 installed generated paths match producer
digests and all six installation outputs match the Make-qualified capture.
See PUBLIC-RPC-HEADERS-QUALIFICATION.md. This is not the complete include parent;
ordinary/architecture/kernel header groups, osreldate and remaining include child
contributions are next. Cross-capture namespace evidence is 1163 archives and
30943 non-directory paths without conflicts. Existing world/package/bootstrap/
cross/runtime/resource gates remain open and Make stays production/default.

## Complete selected production share parent (2026-11-05)

The native share parent now follows the maintained production traversal and
settings. Complete independent Make subtree comparisons pass default and raw/
split-manual profiles (47 archives, 6875 file/hardlink paths, 641 symlinks) and a
reduced-data profile (seven archives, 54 files). Directory claim attributes and
multiplicity are checked; twenty-one explicit native timezone directories are
independently reconciled with Make's plain-mkdir stage/global mtree policy.
Complete comparison exposed and corrected the missing mbufid-sidecar script/two
DTrace directories. Termcap now honors manual-disable/compression and explicit
manual package policy. See SHARE-PARENT-COMPOSITION-QUALIFICATION.md. The actual
tests-enabled full endpoint remains rejected pending installed share/example/
timezone suites. Cross-capture namespace evidence is 1161 production archives and
30866 non-directory paths without conflicting claims; it is not a combined world
build. Next close remaining world roots and installed tests, compose full world,
then complete installation/debug/pkgbase, cross/bootstrap, runtime and resource/
performance gates. Make remains default; BIP stays excluded.

## Shared locale and encoding composition checkpoint (2026-11-05)

The new configured locale parent composes ten existing native owners and keeps
C.UTF-8 when optional locales are disabled. Together with existing i18n data,
complete independent original comparisons pass 3052 component metadata records,
1207 exact regular files and 640 symlinks. Directory records repeat across
components; no whole-world directory/pkgbase reconciliation is implied. Review
found and corrected missing localedef execution-runtime dependencies: all 181
observed actions now declare libc/libsys/loader, and all 33 archive/metadata outputs
remain unchanged. The minimal parent passes its complete three-record original
comparison; returning to the full profile preserves all outputs without uncached
share actions. See SHARED-LOCALE-COMPOSITION-QUALIFICATION.md. Cross-capture evidence
now covers 1158 archives and 30736 non-directory paths without conflicting claims.
Next compose the complete share parent and close remaining world roots/installed
tests. AMD64-only locale selections, other ABIs, bootstrap, complete installation/
pkgbase, runtime and comparative resource gates remain open. Make stays default.

## Sendmail shared source data checkpoint (2026-11-05)

Source-owned Bazel globs now install the maintained sendmail cf subtree through
existing typed installation/archive rules, with no Python implementation change.
Complete independent original Make comparison passes 200 records: 190 exact file
payloads and ten directories, including ownership, modes and package tags.
Cross-capture reconciliation now covers 1147 archives and 28889 non-directory
paths without conflicts; this is not a combined full-world build.
See SHARE-SENDMAIL-DATA-QUALIFICATION.md. This covers the production copy layout;
source-checkout symlink layout and runtime configuration/mail behavior remain
unqualified. Remaining locale/encoding installation and complete share/world
composition are next; all existing system acceptance gates remain required.

## Generated timezone checkpoint (2026-11-05)

Native timezone generation and installation now match complete original Make
staging for 601 files with and without leap seconds. All 21 created directories
match the physical original stage and global mtree policy; original file-only
component METALOG and native expanded metadata are explicitly distinguished.
Bazel expands the generated directory artifact into declared archive inputs;
there is no fixed zone-name inventory. Three selected test targets pass,
including eight serializer cases and a real zic-generated fixture. Final cold,
cache-restored and independent builds preserve all three installation outputs.
See ZONEINFO-GENERATED-TREE-QUALIFICATION.md. Cross-capture namespace evidence
now covers 1146 production archives and 28699 non-directory paths without
conflicts; this is not a combined world build. The full tests-enabled zoneinfo
endpoint still rejects explicitly: installed ATF tests and timezone activation
remain open. Next close remaining share locale/encoding/sendmail data and parent
composition, then outstanding world roots and installed test coverage. Existing
full-system, cross-platform, bootstrap, pkgbase, runtime and resource/performance
gates remain required. Make stays production/default and BIP stays excluded.

## Current combined native build (2026-11-05)

One maintained frontend request now builds nine composed AMD64 production
families together, including MIT Kerberos: 1114 installation archives and their
selected internal build outputs, with 52 selected test targets passing. The
complete captured request namespace has 23350 non-directory paths and no
conflicting file claims. MIT contributes 43 installation archives and ten internal
archives; all 48 configured original owners match the native selection. Strict
original gssd/KDC comparisons caught and corrected a profile dependency leak.
See MIT-FAMILY-COMPOSITION-QUALIFICATION.md for current scope and evidence and
EIGHT-FAMILY-COMPOSITION-QUALIFICATION.md for the preceding checkpoint.
This is a selected construction/namespace milestone; remaining world roots,
complete installed tests/Make/pkgbase parity, other ABIs, bootstrap, system
runtime/VM and comparative resource/performance gates remain open. Make stays
production/default. No complete world endpoint or system acceptance is implied.

## Shared data installation checkpoint (2026-11-05)

Six additional share owners now produce native installation archives: dictionaries,
miscellaneous data, skeletons, installed Make support and two repository-key
payload owners. Independent complete Make comparisons pass 114 metadata records
and 107 exact file payloads. The alternate USB/editor/test-support branches pass
95 records and 93 file payloads across misc/mk. Source-owned BUILD declarations
preserve package tags, modes and the dictionary link; no Python implementation
change is needed. See SHARE-DATA-INSTALLATION-QUALIFICATION.md. This is additional
component coverage, not a complete share/world endpoint or package acceptance.

## VT, firmware and SNMP data checkpoint (2026-11-05)

Four more original share owners now have native installation archives and complete
original Make comparison: 121 metadata records and 117 exact payloads, including
all fifteen generated VT fonts. Native generation reuses the existing declared
execution-platform converter; no new Python implementation is introduced. Source
parents cover VT, SNMP MIBs and iwm firmware. See
VT-FIRMWARE-SNMP-INSTALLATION-QUALIFICATION.md. Console, SNMP and firmware runtime,
complete share/world composition and the system gates remain open.

## Shared manual sections checkpoint (2026-11-05)

Eight manual sections now have native inventories and a shared Starlark helper
for compression, group packages and hardlinks. Complete original comparisons pass
3296 installed records/payloads, including 2609 hardlink aliases. The raw/split/
optional-group profile passes 3233 records; disabling man suppresses all eight
components. Cross-capture namespace reconciliation now covers 1132 archives and
26871 non-directory paths without conflicting file claims. See
SHARE-MANUAL-SECTIONS-QUALIFICATION.md. Section 4 and complete share/world/package
and system qualification remain open; this is not a combined full-world build.

## Complete configured shared-manual parent (2026-11-05)

The native share/man parent now includes section 4 and both original architecture
children. Complete original subtree comparisons pass for normal and raw/split/
opposite-feature profiles: 4248 and 4075 records respectively. Normal mode has
1426 unique files and 2822 exact hardlink aliases. Manual-directory choices match
actual Make query inventories; target-ABI cross-build and independent alternate
architecture-choice staging remain open. All eleven components also pass the
native manual-disable check. See SHARE-MANUAL-PARENT-QUALIFICATION.md. Mandoc
databases, remaining share/world composition and the system gates remain open.

## Configured shared documentation checkpoint (2026-11-05)

The native share/doc parent now composes the book, legal notices and selected
IPv6/compiler/test documents. Complete independent original subtree comparisons
pass both profiles: 104 unique records each, with 90 normal and 91 alternate exact
file payloads. Only identical shared legal-directory claims are reconciled and
the original/native repetition counts must agree. See
SHARE-DOCUMENTATION-QUALIFICATION.md. Examples, zoneinfo, locale composition and
remaining world/system gates remain open; this is not a full world build.

## Production examples checkpoint (2026-11-05)

The maintained Make inventory now corrects bootforth/jail/MAC_ABAC sample package
assignments and installs the missing OES source independently of Bluetooth.
Native production examples match complete original staging in both profiles:
235 records/185 exact files with optional groups, 185 records/144 files without.
The full tests-enabled endpoint is explicitly rejected while the installed test
hierarchy remains unconverted. See SHARE-EXAMPLES-QUALIFICATION.md. Source data
installation is qualified for these AMD64 profiles, not sample/service runtime,
actual package upgrades, complete world or system acceptance.

## Current composition checkpoint (2026-11-05)

NIS and sendmail administration are now included when selected; their combined
AMD64 profile builds 368 installation archives and passes ten selected test
targets. CDDL now has a source-owned production parent: 37 installation archives
plus two internal libdtotel archives, with fourteen selected test targets passing.
The secure production parent also builds 21 installation archives and two internal
archives, with twelve selected crypto/TLS/SSH-configuration/SFTP test targets
passing. All 167 CA certificates and both source-owned category directories
match original Make. See NIS-ADMIN-NATIVE-QUALIFICATION.md,
SENDMAIL-NATIVE-QUALIFICATION.md, CDDL-COMPOSITION-QUALIFICATION.md and
SECURE-FAMILY-COMPOSITION-QUALIFICATION.md for exact scope, failures and evidence.
Full native world composition, installed tests/metadata/pkgbase, other ABIs,
bootstrap, system runtime and controlled resource/performance acceptance remain
open. Make remains production/default. The dated checkpoints below are historical
evidence, not a substitute for those outstanding gates.

## Established kernel milestone and remaining system gates

The complete amd64 GENERIC kernel already builds natively through link, CTF and
split debug. The 2026-11-03 source-bound refresh compares all 2,462 link objects
and complete allocated kernel/CTF contracts against an independent Make build.
See [CURRENT-KERNEL-REFRESH-QUALIFICATION.md](CURRENT-KERNEL-REFRESH-QUALIFICATION.md).
This is a completed controlled kernel construction milestone; it is not a full
world/modules/pkgbase system build or a VM boot. The subsequent aggregate build of all 729 selected amd64 modules and the kernel
also passes; its captured ELF/debug/install-payload review passes. See
[AMD64-AGGREGATE-MODULES-QUALIFICATION.md](AMD64-AGGREGATE-MODULES-QUALIFICATION.md).
Complete module installation/pkgbase parity, ARM64/RISC-V/configuration coverage,
complete world installation,
bootstrap, pkgbase/hardware/publication, full tests, runtime/VM and comparative
CPU/memory/disk/cache/sandbox gates remain required. Do not describe the kernel
milestone as missing or use it to imply whole-system acceptance.

## Program and library composition checkpoint (2026-11-05)

The normal frontend completed `bazel-world-program-families-native-r1-20261105`:
40 bin, 74 sbin, 20 libexec, 266 usr.bin and eight administration archives
(408 total, 3,361 unique non-directory destinations). The source-settings test
passed. Captured archive/request serialization and logged producer payloads were
reviewed for all 408, including eight cached outputs matched to their retained
prior producer evidence. This is selected-profile construction and serialization
coverage, not independent complete Make installed-world parity.

That request disables installed tests and leaves tests_support automatic, so it
also disables Kyua. The recorded Make SDK profile explicitly enables tests support.
The r2 request sets tests_support=yes to match that input without enabling the
unconverted full installed test hierarchy. Its first execution correctly failed
on undeclared nvpair headers after SPL compatibility includes became private.
The r3 execution exposed the same accidental inheritance in zutil. Explicit
implementation dependencies now reproduce each affected owner's original Make
include contexts. The r4 build passed, selecting 410 archives: 40 bin, 74 sbin,
21 libexec, 267 usr.bin and eight administration owners. The added contributions
are ATF and Kyua. The final r5 rerun also passes after the RPC wrapper correction
below; all 408 prior archive/request/directory-metadata outputs remain identical.
The final archive-review-r2 and its prior-witness supplement now cover all 410
archives and 3,423 collision-free non-directory paths. All metadata, exact
requested inventories and logged producer payloads agree. The two added
contributions still need independent complete Make installation parity.

`bazel-library-admin-composition-native-r10-20261105` completed five selected
tests, the GEOM/Clang/ATF/Googletest parents, administration archives, SPL/CTF and
actual dtraced/switchboardctl programs and source objects. The r9 administration
review compares 273 original metadata records and 220 exact file payloads for
fwget, periodic, bsdconfig and two test-discovery roots. The r10 daemon review
passes strict ordered ELF dependencies, loader/interfaces/hardening, complete
component metadata, manuals/policy and native/original debug CRCs.

Composition revealed real dependency defects: private CTF/SPL compatibility
headers leaked into ordinary C++ clients; SPL used pthread symbols without its
own provider; dtraced mixed declared and SDK C++ include trees and ordered pthread
incorrectly. Native rules now keep private includes private, declare pthread,
select declared libc++ headers and preserve original direct library order.
SPL's maintained Makefile and src.libnames catalogue also declare pthread. The
maintained SDK staging helpers refreshed changed source bindings while retaining
the identical tool snapshot. The default CTF public C++ consumer and static/shared
functional tests pass at r10. The follow-up openzfs-header-closure r3/r4/r5 runs
pass all nine CTF/SPL/AVL/nvpair tests and build CTF-enabled libproc, including its
production archive. CTF-enabled original parity remains open. The first request
failed on my incorrect libproc target name; its corrected request uses the
existing production_install_archive, with no fallback or source alias.

Both nvpair tests exposed a pre-existing native include-precedence defect.
The virtual RPC header tree bypassed SPL's xdr_control userland wrapper; actual
XDR decoding used the wrong x_ops offsets. The RPC context now follows SPL in
the original include order. Tests remain unchanged and both encodings pass.
Fresh Make comparison also caught the missing package-owned debug directory;
the native archive now preserves it. The final nvpair independent comparison
passes six original metadata records, header bytes, static member order/symbols,
shared ELF dependency/interfaces/hardening and native/original debug CRCs.
Evidence: bazel-openzfs-header-closure-native-r5-20261105/nvpair-wrapper-review-r3.

See [COMPOSITION-QUALIFICATION-20261105.md](COMPOSITION-QUALIFICATION-20261105.md)
for retained evidence and limits. These results do not complete world/pkgbase,
bootstrap independence, diagnostic/alternate profiles, daemon runtime,
cross-platform, VM or comparative resource qualification. Make remains default.

## Complete lib selection reconciliation (2026-11-05)

The library-parent queue now accounts for internal owners separately from
installed contributions. Original component metadata identifies libelftc's nine
manuals even though it is INTERNALLIB. Its missing native manual archive is now
implemented and independently qualified: twenty original records/payloads,
eleven hardlinks and regular/PIE archive members/symbols match Make; the existing
API test executes and passes. Evidence:
`bazel-elftc-parent-native-r1-20261105/original-review/review.json`.
See LIB-FAMILY-CLOSURE.md. This is another completed contribution, not complete
lib-parent selection or world acceptance. Continue explicit configured parent
composition without treating internal-only archives as installed files.

## Native administration parent checkpoint (2026-11-05)

The source-owned AMD64 usr.sbin production parent now declares all 242 selected
child owners and its previously omitted parent-owned nvram manual. The normal
r3 build passes: 336 installation archives plus affected SSH/telnet targets;
its source-settings test is cached. Six actual configured selections match Make
(242/238/238/240/234/206). Captured-output review explains the updated frontend
manual, preserves the other 1,005 baseline outputs and independently matches the
added manual against original Make metadata/payload.

Option review exposed KERBEROS_SUPPORT's final dependent-option handling in
src.opts.mk. The shared setting is now auto/yes/no; SSH headers, dependency
selection and unsupported-Heimdal guards use the same effective condition.
Explicitly disabled telnet regular/PIE archive members/symbols match fresh Make.
See USRSBIN-FAMILY-CLOSURE.md for evidence and limits.

The follow-up optional-admin r2 normal build implements bootparamd/callbootd,
ofwdump and freebsd-update and removes their three parent gates. The expanded
profile matches all 245 original owners and builds 340 installation archives;
all 1,009 prior parent outputs remain identical. Fresh original component
metadata/data and three strict program ELF/debug/usage comparisons pass.
See USRSBIN-FAMILY-CLOSURE.md for exact evidence and limitations.

The printing follow-up implements all eleven executables, lp script, manuals,
configuration/sample files and both internal archive variants. Normal r3 builds
the expanded 246-owner profile, 353 installation archives and both internal
printing archives. Complete original printing metadata/data and all eleven
ELF/debug comparisons pass, along with both archive member/symbol comparisons
and four bounded pure-output runtime cases. Logging fragments also match fresh
original Make. See USRSBIN-FAMILY-CLOSURE.md for exact evidence and limits.

The original-reference helper now always executes maintained installconfig
recursion: root-only CONFGROUPS discovery had omitted descendant configuration.
The corrected printing reference includes its two lpd files; an empty library
leaf also succeeds. Review/refresh earlier recursive references for descendant
configuration before accepting full installation parity. Preserve their bounded
ELF/archive evidence without upgrading it to complete filesystem acceptance.

Next: finish missing optional usr.sbin owners (NIS and sendmail) and installed
tests, remove their explicit incompatibility gates as qualified, reconcile all
family ownership/payloads and unconsumed internal variants, and complete remaining
world roots. This parent still rejects other ABIs.
No selected construction/analysis result substitutes for full installed-world,
bootstrap/pkgbase/hardware/publication/runtime/VM/resource acceptance.

## Native library parent checkpoint (2026-11-05)

The source-owned AMD64 production parent now declares library contributions and
internal regular/PIE outputs with native labels/selects. The normal r4 build
passes its two selected tests; all 720 logical output paths and captured hashes
match the accepted explicit r2 library aggregate. Six actual configured selection
analyses match Make recursion (172/169/170/167/182/151 owners). The disabled-test-
support case caught and corrected the shared GOOGLETEST option dependency.
The final r5 normal rerun passes with both selected tests cached; its regular/PIE
FDT archives match Make member order and symbols, and an explicit tests=true
build is rejected. See LIB-FAMILY-CLOSURE.md for endpoints and evidence.

Continue installed-library ownership/payload/test closure and remaining native
world parents, including usr.sbin. The production library parent explicitly
rejects installed tests and other ABIs; this does not complete world/pkgbase,
bootstrap/runtime/performance gates. Make remains default. Generic format-5
supports this parent without a C dispatcher or signing/publication schema change.

## Complete selected-family construction requests (2026-11-05)

A fresh maintained BuildEnvironment query of lib's production recursion, using
the recorded SDK profile with an explicit WITHOUT_TESTS override, selects 172
immediate owners. TESTS_SUPPORT remains explicitly enabled as recorded. The
retained request at `bazel-lib-family-composition-request-r1-20261105` maps every
owner to its reviewed existing native installation endpoint, or to regular/PIE
build archives for eleven internal-only owners. Libelftc also retains its build
archives alongside its manual-only installation. All 185 contribution/build
targets plus source-settings and existing libelftc API tests are selected.

The maintained frontend completed
`bazel-lib-family-composition-native-r1-20261105` with sixteen jobs: 230 selected
installation archives, two cached passing tests, 12,197 executed/internal
processes and 21,607 action-cache hits. Bazel reports 652.836 seconds; this is
construction timing, not controlled Make performance parity.

The r2 request adds the four explicit regular/PIE archives for libotelexport and
libutil++, whose production endpoints only install manuals/data. Like libelftc,
these internal libraries must be built without inventing installed binaries.
`bazel-lib-family-composition-native-r2-20261105` passes all 191 targets: 189
contribution/build targets for every one of the 172 selected immediate owners,
plus two cached passing tests, with zero incompatible selected targets. Its
immutable capture contains 492 unique files, 1,213,883,227 bytes; the 230 archive
count is an installation contribution count, not a distinct library count.
This completes this configured combined construction check, not an accepted
source-owned lib parent, independent full installation comparison, package or
runtime result. Source,
configuration, command, explicit label mapping and request-preparation bindings
are retained. No Make recipe evaluates the native build graph: Make supplies
the independent qualification inventory, and native declarations supply builds.

The same fresh production recursion query selects 242 immediate usr.sbin owners.
`bazel-usrsbin-family-composition-request-r1-20261105` maps each one to its
reviewed native production contribution, including capability daemons. Tests
and daemon runtime are not silently included in production acceptance. The r1 normal frontend attempt stopped at pkg's existing repository-policy
analysis guard: the request omitted version_branch. No source fallback or
invented repository channel was added. A fresh maintained Make pkg query reports
BRANCH=CURRENT, REVISION=16.0 and PKGCONFBRANCH=latest. The r2 request explicitly
supplies the branch input and retains its original query/provenance. The normal
frontend has launched `bazel-usrsbin-family-composition-native-r2-20261105` after
the failed r1 terminated. That r2 execution correctly caught a missing snapshot
header declaration: bhyve snapshot.h includes vmgenc.h. The local quoted include
closure contains sixteen bhyve headers; vmgenc.h was the sole missing declaration.
The snapshot_headers provider now includes it, preserving the enabled feature
and unchanged C sources.

`bazel-usrsbin-family-composition-native-r3-20261105` passes all 242 selected
production owners plus the cached source-settings test, with 335 installation
archives and no incompatible selected targets. Its immutable capture binds 674
unique files (143,265,537 bytes). The fresh original
`bazel-bhyvectl-snapshot-header-make-r1-20261105` dependency record confirms the
same source header is consumed. The r3 `bhyvectl-snapshot-header-review/review.json`
passes all five original metadata records, exact compressed manual, strict ELF
loader/interfaces/hardening/ordered dependencies and both debug CRCs. No VM,
snapshot/migration operation or daemon runtime was exercised.

Both selected family construction checks now pass separately; this is not one
complete world build or original aggregate installation/package acceptance.
Commands, configurations, inputs, failed attempts and complete bindings remain
retained.

After these combined attempts, correct actual graph failures and reconcile all
installation namespaces/owners. Then introduce source-owned lib and usr.sbin
parents with real option-dependent selects, matching the maintained Make inputs.
Qualification request preparation is not a replacement production parent or a
claim that all alternate profiles are implemented. Complete installed tests,
remaining world families, pkgbase, other architectures, bootstrap, VM/runtime
and comparative resource gates remain open. Make stays default.

## Cross-family installation namespace checkpoint (2026-11-05)

`bazel-world-family-namespace-review-r1-20261105/review.json` resolves every
captured installation request from the final program, library and administration
family runs. The 975 archive selections contain 967 unique archives; eight
repeated administration selections have identical archive/request identities.
Across those unique contributions, all 15,350 non-directory destinations are
collision-free. Directory claims are retained separately; this does not assert
complete directory-ownership reconciliation, payload equivalence, full original
Make parity, pkgbase or complete-world acceptance. No conflicting file claim was
ignored or hidden through an output filter.

The remaining configured world families include cddl, etc, include, krb5,
rescue, secure, share, stand, sys and the installed test hierarchy. Existing
children and some parents already have native declarations; inspect actual
configured products rather than treating a missing parent as missing code or
existing declarations as successful build evidence. Next consolidate source-owned
lib/usr.sbin parent selection and reconcile/build the remaining family products
before a complete world-stage/package attempt. Preserve the outstanding kernel/
module installation, cross-platform, bootstrap, VM/runtime and resource gates.

## Earlier dtraced configured-option checkpoint (superseded by composition above)

All eleven original daemon C++ sources now have native compilation and declared
source-header/library dependencies. Four opt-in diagnostic settings preserve
Make's sanitizer precedence and robust/debug flags; existing dtrace_optimized
selects AMD64 compile/link LTO. Cross-platform support remains incompatible.
Three original references pass, including the final corrected source file set
and original source-header context.
Actual configured metadata matches all five original records, and five real
configured action profiles pass (both regular/PIC contexts and the link action).
A dependency review caught the original -I sys header scope: seventy private
source kernel headers plus the bare transport header are now explicit. In all
five profiles, every configured compile context declares all 71 original source
headers and the exact eleven original C++ sources. This avoids substituting SDK
headers for the known source closure. These checks do not establish native
compilation, executed preprocessing or diagnostic runtime.
See [DTRACED-PRODUCTION-QUALIFICATION.md](DTRACED-PRODUCTION-QUALIFICATION.md).

The earlier prepared request was
/usr/obj/usr/src/bazel-library-admin-composition-request-r3-20261105/inputs.json.
Its request.json records the exact normal frontend command and supersedes the
unstarted r2 request. It adds the real daemon, source objects and installation
archive. Native payload/ELF/debug/runtime qualification remains required. No
second compilation frontend was launched while the existing aggregate runs.

## Switchboardctl production candidate and remaining daemon gap (2026-11-05)

Switchboardctl now has a distinct native production binary, real source-object
output group and complete attributed bundle installation. Existing static test
objects are unchanged. Two original Make references pass; the second binds the
final source file set. Actual configured dependency analysis matches all sixteen
original metadata records, the relative command symlink and both policy files.
Native binary/debug/manual and embedded-policy/ELF comparisons remain pending.
See [SWITCHBOARDCTL-PRODUCTION-QUALIFICATION.md](SWITCHBOARDCTL-PRODUCTION-QUALIFICATION.md).

The next request is now
/usr/obj/usr/src/bazel-library-admin-composition-request-r2-20261105/inputs.json,
which supersedes the retained unstarted r1 request. It includes this program and
its genuine source objects alongside the preceding batch. It is prepared, not
queued or started while the current aggregate owns the frontend lock. The
original embedded policy remains unsigned input; no signing/boot claim is made.
Dtraced initially had headers only at this checkpoint. Its subsequent production
and option-selection candidate is recorded above; native construction and runtime
qualification still remain open.

## Bsdconfig and two test-discovery roots (2026-11-05)

The complete source-owned bsdconfig graph now covers all 42 original owners,
including the optional examples branch. The missing lib/tests and usr.sbin/tests
roots install the original directory-discovering Kyuafile rather than a child
allowlist. Three original Make references pass. Actual configured aggregate
closure analysis matches all 44 selected manifests, 205 installation records and
159 original source payloads; the generated manual and native archives remain
pending. See [BSDCONFIG-DISCOVERY-QUALIFICATION.md](BSDCONFIG-DISCOVERY-QUALIFICATION.md)
for retained receipts, source/audit bindings, request location and scope.
The next native request combines these targets with the preceding library and
administration batch. No second compilation frontend or VM has been launched.
Configured metadata parity does not establish complete test traversal, functional
administration, alternate profiles or installed-world qualification.

## Fwget and complete periodic hierarchy candidates (2026-11-05)

Native source-owned declarations now cover fwget, hardware-install, its seven
selected PCI scripts and three USB scripts, plus the full periodic daily,
security, weekly and monthly configuration groups. The unselected
pci_network_ittim source is not installed. Periodic preserves configuration tags,
per-group package/mode differences, all original option guards and the existing
independently usable ZFS producer. Shared configuration directories belong to
utilities; executable/manual ownership remains separate.

Original Make references pass in bazel-fwget-make-r1-20261105 and
bazel-periodic-make-r2-20261105. The latter retains 58 raw component records,
including five repeated identical directory contributions. These are original
references, not native parity acceptance. Actual unconfigured Bazel declaration
queries pass in bazel-admin-hierarchies-query-r2-20261105; configured construction,
archive/metadata comparisons, option profiles and functional runtime remain open.
The next maintained frontend request is prepared in
/usr/obj/usr/src/bazel-library-admin-composition-request-r1-20261105/inputs.json, combining these
owners with GEOM, LLVM/Clang, ATF and Googletest composition and reference-helper
Bazel tests. It must wait for the current aggregate frontend to finish; no
second compilation frontend has been launched or silently queued.

The first periodic reference correctly failed after NO_OBJ descendants wrote
44 recipe metadata files into source. Only those verified, untracked generated
files were moved under the failed run's generated-source-metadata directory.
The supported metadata mode now uses curdirok=no, retaining object recipes while
skipping source-directory recipe logs. All source-set checks remain intact; a
fresh periodic reference passes without source metadata. The existing helper
suite passes sixteen host Python methods, including a real bmake source/object
regression, and all six maintained CLI guards pass. Bazel execution of the
updated helper suite remains part of the next request. Top-level NO_OBJ/NOOBJ
metadata preflight still rejects. Existing format-5 selection needs no dispatcher,
SDK, staging/signing or publication-interface change. Make remains default;
BIP, host installation and publication are not part of this batch.

## Startup parent and eight administration-script owners qualified (2026-11-05)

The corrected AMD64 csu parent passes bazel-csu-parent-native-r2-20261105.
parent-review-r1/review.json matches all 64 logical installation records against
130 original Make records (66 repeated identical directory contributions), all
ten startup allocated-data/symbolic-relocation contracts, six byte-identical
Kyuafiles, fifteen original/native debug pairs and seventeen loader contracts.
All 36 unchanged original runtime cases pass: r1 executes all 36; r2 executes the
affected cases after correcting library order and suite-directory ownership.
The final run reports 38 passing wrappers/cases, thirteen freshly executed and
twenty-five cached, including source settings and the existing ELF inspector test.
That inspector retains its original real ELF32/64 cases and adds five independent
fixtures for repeated-section payload/binding identity (nine methods pass).
The default inspector still rejects duplicate names; its explicit occurrence
mode retains every payload and symbol/relocation binding in legal partial links,
without editing inputs, dropping notes or normalizing code/relocation bytes.

The same completed request builds all eight new administration-script owners:
adduser (including rmuser), crashinfo, etcupdate, service, sysrc (including its
subr data), vigr, spkrtest and manctl. admin-script-review/review.json binds eight
fresh original production Make receipts and compares every one of their 29
component records and twenty script/data/manual payloads byte for byte. There
are no non-directory collisions. The common source-owned script helper derives
owned directories from declared destinations, preserves standard script/data
modes and manual package policy, and performs no ELF/debug processing or shell
rewriting. The generated vigr copy has the original source bytes. Sysrc and
etcupdate production contributions remain separate from their incomplete installed
test hierarchies; requesting their full tests-enabled installation rejects.
Script functional/service/user-management scenarios remain runtime/VM work.

The generic maintained format-5 frontend builds these labels without a C/schema,
security, signing or publication change. The larger bin/sbin/libexec/usr.bin plus
eight-script production request is now running at
bazel-world-program-families-native-r1-20261105, with sixteen jobs and explicit
tests-disabled installation. This is a larger construction attempt, not full
world/pkgbase or runtime acceptance. Make stays default; BIP excluded.

## Full-world convergence and larger build groups (2026-11-05)

Prioritize complete configured world ownership and aggregate build failures over
separate leaf reports. The refreshed maintained Make traversal at
/usr/obj/usr/src/bazel-world-inventory-r1-20261105/inventory.json succeeds with
2,128 directories and sixteen top-level families. The complete component query
at bazel-world-components-r1-20261105 passes all 2,128 directories with zero failed
queries. This establishes metadata inventory only. Existing native parent packages must be reconciled
with actual selected products, installation manifests and generated inputs.
Root BUILD files are absent for lib, cddl, rescue, share, sys and usr.sbin;
children may already have native producers, so absence is an assembly review
item, not a count of missing implementations. Other roots may have differently
named or incomplete installation ownership and also require reconciliation.

The AMD64 csu parent now passes the bounded original comparison above; other
startup architectures remain explicitly incompatible. Complete selected ownership
is still required across every world family. The successful isolated, 1 GiB heap
Bazel declaration query at bazel-world-declarations-query-r1-20261105 captured
662 actual archive/archive-set rules before the script batch; its selection-review
maps every selected immediate lib (173) and usr.sbin (243) owner. Internal
libraries and alias roots are not missing producers merely because they lack an
exact archive rule. The query does not resolve configured providers/build/runtime,
and alternative target namespaces still require ownership review. The refreshed
presence survey remains a review queue, not coverage evidence.

The first external waiting helper was canceled without starting a build. A direct
overlap attempt correctly failed the outer build-bsd nonblocking lock; the inner
backend's blocking lock is not an exposed build queue. After csu completed, the
larger maintained frontend request was dispatched normally. It now combines the
four existing program-family parents and eight script owners. Preserve actual
errors, fix coherent groups and compare installed ownership with the independent
Make inventory. All missing world parents, full tests, pkgbase/bootstrap/runtime,
other architectures, resource and default-switch gates remain required.

## Library composition batch prepared (2026-11-05; not yet qualified)

The GEOM installation parent now uses the typed archive-set provider, preserving
request and directory metadata alongside the same OpenSSL-selected child tar
outputs. The previous plain filegroup retained files but lost those metadata
output groups, blocking typed world composition. This source-level fix joins the
same aggregate qualification request; payload equality and configured output
coverage remain to be checked, so it is not accepted from BUILD inspection alone.

The next source-owned library assembly batch adds original ATF parent selection,
archive endpoints for existing Googletest manifests, and LLVM/Clang library
archives plus the lib/clang shared-library parent. Compiler library ownership is
kept separate from usr.bin/clang programs: llvm is unconditional inside the
selected parent, clang/resource headers follow CLANG or LLDB, and the debugger
library follows LLDB. Existing leaf producers/manifests are reused; no binary
payload, compiler source, generated implementation or Make dependency is copied.
ATF's incomplete original test-parent recursion remains explicitly gated rather
than represented by its two production libraries. Googletest retains its existing
optional full-test manifest separately from the new production-only contribution.
The normal format-5 frontend request is prepared; these new archive/parent labels
are candidates until configured analysis, original selected ownership comparisons
and aggregate construction pass. Static compiler-library profiles and foreign
architectures remain open. Do not count prepared declarations as built libraries.

## libcasper production parent and original connection cases (2026-11-05)

The native parent now composes the original library and all eight service
production contributions. Fresh original parent/test references match 139
production plus eight test installation records, 103 header/manual payload paths,
83 hardlinks, shared/program ELF interfaces and separate-debug CRCs. Both original
many-connections and connection-churn cases execute and pass with native DSOs.
Emitted DOF matches nine providers, 35 schema entries and 68 validated sites;
this is not live tracing or full original object/code parity. The test declaration
now preserves original PIE and direct library order after strict audits rejected
earlier candidates. Tests-disabled installation retains identical production
archives; incomplete tests-enabled full installation rejects explicitly. See
CASPER-PARENT-COMPOSITION-QUALIFICATION.md. Complete service-test/recursion
ownership, other wrappers/ABIs, full world/pkgbase/bootstrap/VM/cache/sandbox and
resource gates remain required. Make stays default; BIP excluded.

## libxo production parent composition (2026-11-05)

The source-owned libxo and encoder parents now preserve both production archive
contributions and their metadata groups. Fresh independent Make references match
all ninety-six installation records, eighty-five header/manual payloads and
fifty-six hardlink identities; both shared ELF interfaces/sections match except
for .gnu_debuglink, with valid original/native debug CRCs. Three existing native
runtime targets actually execute. Tests-disabled full installation passes with
identical production archives, and tests-enabled full installation rejects the
still-unmigrated original functional hierarchy. See
LIBXO-PARENT-COMPOSITION-QUALIFICATION.md. This closes production parent assembly,
not all libxo tests or full world. libcasper/csu/atf and complete lib owner
reconciliation remain; full pkgbase/bootstrap/VM/resource gates stay required.

## Capsicum production and protobuf parent composition (2026-11-05)

The Capsicum helper owner now contributes its original header/manual/thirteen
manual aliases; all fifteen records, bytes and hardlink identities match fresh
original production Make. Both original static C/C++ ATF programs now build;
all four unchanged stream cases execute and pass through the maintained runner.
The protobuf parent explicitly builds all four original child owners, including
internal regular/PIE archives, and preserves three actual install contributions:
protobuf-lite, protobuf and upb licences. All eight build outputs and the exact
nine parent archive/request/directory outputs are captured; payloads have zero
non-directory collisions. This is parent assembly, not refreshed protobuf Make
implementation parity. Installed Capsicum test metadata, other lib wrappers and
full world/pkgbase/bootstrap/VM/performance remain open. See
CAPSICUM-PROTOBUF-COMPOSITION-QUALIFICATION.md.

## Native AMD64 thread debugging library (2026-11-04)

libthread_db now builds its actual four sources, AMD64 register helper, original
version map and production installation instead of providing only a header.
Independent Make comparison passes all eight raw regular/PIC object contracts,
static archive order, version-script/header bytes, seven metadata records,
original/native debug CRCs and shared ELF metadata/ordered dependencies. All ten
debugger-supplied ps_* callback imports remain unresolved, matching original Make;
no callback substitutes are linked. This is build/install/interface qualification,
not debugger runtime. Other ABIs, actual thread/process control, full lib/world/
pkgbase/bootstrap/cache/sandbox/performance remain open. See
THREAD-DB-NATIVE-QUALIFICATION.md. Make stays default; BIP excluded.

## Process-library production installation (2026-11-04)

Native libproc/libprocstat/librtld_db now declare original production headers,
static/shared libraries, manuals/aliases and debug artifacts. Fresh original
Make production references (explicit TESTS disabled) compare all 53 metadata
records, five header/manual payloads, all 30 manual hardlink identities, debug
CRCs and shared ELF metadata/ordered dependencies. Fourteen object contracts
pass: nine raw, five isolated filename compiler controls. Native libprocstat's
new self-process/argv sysctl runtime test executes successfully. The configured
CDDL/ZFS and CTF code remains unchanged; alternate profiles and libproc's
original installed ATF hierarchy remain open. See
PROCESS-LIBRARY-INSTALLATION-QUALIFICATION.md. Full lib/world/pkgbase/bootstrap/
VM/cache/sandbox/performance and other architectures remain required.

## Library production archive prerequisites (2026-11-04)

Seven existing library installation manifests now expose explicitly production
archive contributions: libarchive, libexpat, liblzma, libmd, libz, libzstd and
libc_nonshared. Their existing installed test contributions remain separate.
Normal format-5 builds all seven archives and passes six selected targets (five
runtime tests execute, source-settings cached). The captured assembly review
passes 438 records, canonical members/metadata/links and zero duplicate
non-directory paths across 429 members. A fresh original libc_nonshared reference
matches its one installation record, twelve raw object contracts and archive
order. Other library implementation/Make parity is not newly claimed by this
assembly result. The fresh Make lib-family plan selects 173 immediate entries,
not 173 libraries or a completion percentage. Full lib composition still lacks
production installation owners and wrapper/test/configuration closure; see
LIB-FAMILY-CLOSURE.md and LIBRARY-PRODUCTION-ARCHIVES-QUALIFICATION.md.

## compile_et original consumer qualification (2026-11-04)

Maintained library reference inputs now support explicit shared ELF kind and
installed include directories with receipt/METALOG/content/inventory bindings.
Actual original link recipes and compiler dependencies are audited. Supported
CFLAGS_LAST/LDFLAGS_LAST hooks preserve existing flags; the old ineffective
CFLAGS_EARLY reference knob is removed. Fresh original compile_et build/stage
passes against original roken/vers. Its three object contracts match raw; full
five-record component metadata, manual bytes, debug CRCs and ELF metadata match.
The comparison identified and removed native compile_et's extra direct crypt
link. All eleven original error tables produce identical C/H files (22 outputs)
with each generator's own roken and explicitly recorded SDK runtime. Native
runtime tests separately pass with native DSOs. The conditional parent archive
edge is declared; full Heimdal and installed-test gates remain. See
COMPILE-ET-NATIVE-QUALIFICATION.md. Complete world/pkgbase/runtime/performance
and other architectures/profiles remain open; Make stays default.

## Roken native installation and regular/PIC comparison (2026-11-04)

Native roken now contributes the original static/shared library, symlink, eleven
public headers and separate debug file through maintained typed installation and
archive rules. A fresh original Make build/stage passes with the bound original
header generator. All 17 component metadata records match; all eleven headers
match byte for byte. Both installed debug CRCs pass, as do shared versioned
exports/ELF hardening/identity and ordered runtime-library requirements. All 118
regular/PIC object contracts pass (114 raw, four explicit filename compiler
controls); all 59 static archive members match in order. Full linked/debug bytes,
consumer Make parity, other options/architectures and whole Heimdal/world/pkgbase
composition remain open. See ROKEN-INSTALLATION-QUALIFICATION.md.

## Original Heimdal library references and generation tests (2026-11-04)

Maintained Make references now bind original native generator executables through
versioned receipt/artifact inputs, verify compiler identity and hashes, and
require direct use in completed metadata recipes. SDK verification precedes
optional component configuration, so Heimdal can be selected against an unchanged
MIT-profile SDK. Fresh original roken/vers builds pass. Sixty-one library object
contracts pass: 59 raw exact and two isolated filename compiler controls; this
covers regular roken and regular/PIE vers, not roken PIC/shared parity. Native
compile_et generation tests pass for sparse indices/prefix reset/repeatability,
invalid table names and missing input with no output artifacts. Six selected
Bazel targets pass, including provenance-helper regressions. Consumer Make
link/install/debug parity, roken installation and broader Heimdal composition
remain open. See HEIMDAL-ORIGINAL-REFERENCE-QUALIFICATION.md.

## Heimdal libraries and compile_et candidate (2026-11-04)

Native regular/PIE roken and vers archives, versioned roken DSO, generated
lexer/parser, compile_et consumer and component installation archive now build
through maintained format-5. The CLI version test executes with declared native
runtime libraries. Both roken archives contain all 59 original source members;
both vers archives contain the original single source. The captured three-file
consumer archive has a verified executable/debug CRC pair. This is a candidate,
not independent Make consumer/library/install parity or full Heimdal closure.
The existing root Heimdal rejection remains. Next: original generator-tool
bindings for fresh Make library references, generated error-table semantics,
shared-library installation and parent integration. See
HEIMDAL-COMPILE-ET-CANDIDATE.md.

## Heimdal platform-header generator (2026-11-04)

Native make-roken now preserves the original AWK -> configured C executable ->
roken.h pipeline with explicit execution-platform tools and source/configuration
inputs. The maintained format-5 frontend passes the selected generator targets
and source-settings test. Its captured 7,027-byte AMD64 header matches an
independently built original Make generator byte for byte. This is a generator
prerequisite; libroken/libvers/compile_et consumer conversion, installation and
other architectures remain open. See HEIMDAL-ROKEN-GENERATOR-QUALIFICATION.md.

## Native Telnet and shared protocol source fix (2026-11-04)

The original Telnet source now builds with option-dependent native libraries and
proper public/private headers. Its existing baud code had an undefined command,
wrong trace pointer, extra NUL, missing IAC escaping and truncating validation;
shared Make/Bazel sources now use a bounded codec with wire/capacity tests and
compatible numeric parsing. Default and no-OpenSSL/IPv4 profiles pass five tests.
Nineteen consumer contexts match original Make (seventeen raw, two explicit
filename controls), as do eleven raw internal-library contexts, complete
component installation metadata/manual bytes/debug CRCs/runtime-library order.
The combined production parent passes 273 archives and five cached tests, with
all 813 preceding products unchanged, canonical collision-free members, and
exact component-to-aggregate binding. The final parser changes only Telnet's tar
among 819 products. Only compile_et remains unconverted in this optional usr.bin
queue; the unfinished Heimdal graph, full installed tests/world/pkgbase,
alternate architectures/profiles and full service/bootstrap/cache/sandbox/
resource gates remain required. Three configured checks preserve explicit
rejection of unfinished Heimdal and full installed-test paths.
See TELNET-NATIVE-QUALIFICATION.md.
Make stays default; BIP excluded.

## Native vacation and original archive search binding (2026-11-04)

Native vacation now builds with its existing generated Sendmail header and PIE
libraries. Original internal-library references pass; the comparison helper
correctly binds actual LIB<name>DIR-based -L/-l searches, rejecting shadows and
unsupported ambiguity. Consumer object and original installation metadata/manual
parity pass; all 76 libsm filename controls and the original controlled linked
allocated image/entry/program-header comparison pass. Ordinary raw Make/debug
byte parity is not claimed. Safe usage executes without sending a reply.
The full SENDMAIL profile passes 268 archives and four selected tests, retaining
all 801 previous default products unchanged. Only compile_et and telnet remain
unconverted optional usr.bin programs. Full installed tests/world/pkgbase,
alternate architectures/profiles, real mail scenarios, bootstrap/cache/sandbox,
VM/runtime and comparative resources remain required.
See VACATION-NATIVE-QUALIFICATION.md. Make remains default; BIP excluded.

## Private libsys implementation include (2026-11-04)

The identified bcopy.c leak is corrected through a private implementation_deps
provider. Four actual downstream compiles lose only that unintended input; their
commands, raw objects, nine archive products and native libc/libsys DSO bytes
remain unchanged. Structured aquery verifies both variants of all four consumer
sources exclude it and both actual libsys memcpy variants retain it. Six tests
pass (three runtime tests execute, three results cached). The unchanged repeat passes with all 22 output records unchanged and zero
actual logged spawns (all six test results cached). This is a dependency-boundary correction, not complete cache or
resource-performance acceptance. Internal group-level private dependencies,
mutation/cold/restore/sandbox and full world/package/runtime gates remain open.
See LIBSYS-PRIVATE-HEADER-QUALIFICATION.md. Make stays default; BIP excluded.

## Native NIS clients and aggregate dependency follow-up (2026-11-04)

ypcat, ypmatch and ypwhich now build through normal format-5 with configured
native libc and shared native/source protocol headers. All four original/native
object contracts match fresh Make objects; three archive audits and two safe
alias tests pass. Parent queries select 267/270 archives when NIS is disabled/
enabled. A fresh original NIS libc reference passes separately. Complete client
link/stage and live RPC parity remain open. Three optional programs still need
conversion: compile_et, vacation and telnet.
The combined NIS/Hesiod aggregate exposed libypclnt's missing native libc link;
its dependency and quota/chpass final links are corrected. The full combined
profile passes 271 archives and four tests; namespace/delta review passes.
All 795 unaffected default outputs remain exact; the iconv symbol-order delta
is separately inspected with unchanged targets and valid debug CRCs.
The final default regression passes with all 801 prior output hashes unchanged.
The actual input audit also finds libsys's public bcopy.c implementation include
leaking into consumer compiles; private implementation scoping is next.
See NIS-CLIENTS-NATIVE-QUALIFICATION.md. Make remains default; BIP excluded.

## Optional Hesiod consumer and test package boundary (2026-11-04)

Native AMD64 hesinfo now builds with its configured native libc exports, declared
source header and normal installation/debug/archive rules. Its safe CLI and
source-settings tests pass; archive payload/action audit passes. The default SDK
cannot build an independent original reference because it lacks optional Hesiod
headers/exports. Full original HESIOD profile parity and DNS runtime remain open.
Six other optional programs still need conversion. A parent query exposed invalid
file2c fixture labels after its tests became a package; explicit restricted labels
repair that boundary. Both parent profile queries pass (267 archives disabled,
268 enabled). Complete default production rebuild and nine existing file2c cases
pass; all 801 production captures remain unchanged. See
HESINFO-NATIVE-QUALIFICATION.md.
Generic build-bsd dispatch remains valid; manual updated. Make stays default.

## usr.bin production build and TAP archive results (2026-11-04)

The maintained format-5 frontend now passes the complete declared AMD64 usr.bin
production aggregate: 267 flattened archives, the seven-contribution LLVM family,
strict LLVM manifest and test-root archive. All six selected tests pass (five
executed, source_settings_test cached). This is a native build and selected-test
result, not independent full Make installation parity or full-world acceptance.
The separate producer/payload audit now passes all 267 archives and 1,482
file/link records with no duplicate non-directory paths: 254 current logged
producer actions and 13 exact prior captured witnesses for cached outputs.

Eleven original TAP suite archives now match fresh maintained Make installation
references: 283 files (13 TAP programs, 259 fixtures and 11 Kyuafiles), eleven
explicit directories, exact payloads, modes, ownership and tags. Archive producer
bindings are checked. This batch does not execute the TAP programs; complete
installed tests, optional profiles, full world/modules/pkgbase, other architectures,
bootstrap, VM/runtime and performance remain open. See USRBIN-FAMILY-CLOSURE.md
for evidence and remaining scope. Make remains default; BIP stays excluded.

Capture inspection now supports a verified batch, parsing one receipt/manifest
snapshot while independently hashing every selected payload. The maintained
qualification_artifacts_test target passes, including corruption and concurrent
metadata-change rejection. This improves audit metadata I/O; it is not a build
performance qualification. Existing build-bsd dispatch and publication policy
remain unchanged; its manual describes the interface.

## usr.bin production parent under qualification (2026-11-04)

The source-owned AMD64 production parent now analyzes with 242 immediate owners,
matching the retained selected Make production roots. The 267 flattened archive
outputs are not compiled products or installed-world coverage. All 192 leaf
changes (184 selected plus eight optional interfaces) are structurally verified
as archive-parent visibility grants only. Four configured gate checks pass;
these execute no compilation or runtime actions.
Complete installation with tests remains explicitly incompatible until its full
hierarchy is carried forward. Seven optional programs remain to convert:
hesinfo, compile_et, ypcat, ypmatch, ypwhich, vacation and telnet; selecting their
profiles is explicitly rejected. Native production/archive/runtime qualification,
complete tests, alternate profiles and ARM64/RISC-V acceptance remain next work.
See [USRBIN-FAMILY-CLOSURE.md](USRBIN-FAMILY-CLOSURE.md). Continue full world,
kernel/modules, bootstrap, pkgbase/hardware/publication, runtime and performance
gates; this checkpoint does not replace them. Make stays default; BIP excluded.

## LLVM family composition in progress (2026-11-04)

Normal LLVM family analysis now passes after preserving LLDB's existing archive
visibility while granting its new family consumer. Full native compilation is
running. Configured review now closes toolchain/utility overlap through one shared
owner and a strict merged manifest: seven contributions account for all 17
selected Make directories, with all 50 metadata input hashes rechecked. This
query executes no actions. Before native qualification, run existing utility/
profile/debugger tests and compare the usr.bin test-root archive with Make's
two original files and directory metadata. Keep extras and unresolved alternate
profiles explicit. No passing aggregate is claimed yet. See
[USRBIN-FAMILY-CLOSURE.md](USRBIN-FAMILY-CLOSURE.md). All full-world/kernel/
pkgbase/bootstrap/runtime/performance gates remain open; Make stays default.

## Full usr.bin tests remain a separate completion gate (2026-11-04)

The selected-profile review queue now maps all 243 immediate owners, not builds.
A conservative scan finds 84 roots mentioning test recursion and 36 existing
child test directories without local native BUILD declarations. Some declared
native tests are samples, not the full original installed tests (awk/comm).
Before family acceptance with tests enabled, reconcile configured child recursion,
fixtures, support files, nested tests and original installation inventory. Keep
these gaps visible; do not accept a source/query count as completed coverage.
See USRBIN-FAMILY-CLOSURE.md and the r2 owner queue under /usr/obj/usr/src.

## usr.bin family closure prerequisites (2026-11-04)

The production queue points to missing family composition rather than unowned
iconv/OpenSSL/NSS/EFI producers. Fresh usr.bin/LLVM metadata and an unconfigured
archive query establish the next review inputs. Six missing component archives
now preserve existing manifests: bzip2recover, gzip, xz, xzdec, lzmainfo and zstd.
Real archive audit: 56 file/link records, 29 hardlinks, exact payload/mode/ownership.
Existing bzip2 package/recovery tests pass with an explicit qualification version.
Two bc/dc rule-output name collisions are fixed without changing installed scripts
or Kyuafile names. See [USRBIN-FAMILY-CLOSURE.md](USRBIN-FAMILY-CLOSURE.md).
Next is the complete source-owned usr.bin/LLVM aggregate with option/test/nested
coverage. The family is not yet built; full-world/kernel/pkgbase/bootstrap,
runtime/VM and performance remain open. Make stays default; BIP stays excluded.

## Userboot image parity and automatic Forth default (2026-11-04)

Independent original Lua/Forth recipes now match complete ELF identity/entry,
all program headers and all allocated section bytes/layout. A stale generated
Ficl reference was replaced with current original builds, exposing and fixing
Make's host-date insertion under WITH_REPRODUCIBLE_BUILD. Original/native
softcore C bytes now agree. A fresh Lua-disabled Forth default stage matches
native metadata and hardlink ownership; the actual extracted alias executes
callback commands. See [USERBOOT-IMAGE-PARITY.md](USERBOOT-IMAGE-PARITY.md).
Whole debug bytes/source lookup and remaining site/profile/script/disk/guest
checks are still open. Resume complete-world gaps while retaining those gates;
full system/bootstrap/package/runtime/performance remains unfinished. Make stays
default; BIP stays excluded.

## Native AMD64 userboot shared construction (2026-11-04)

Both Lua/Forth variants now build their 42 native PIC contexts, ordered native
shared links, split debug and original default installation/archive contributions.
The audit binds 84 object contracts (82 direct plus two original filename controls)
and 3,896 consumed pairs. Actual callback interpreter replies and exit behavior
match original Make controls. Regression: 35 passing targets (one executed,
34 cached), 34 previous boot outputs unchanged. This is a construction checkpoint,
not complete userboot qualification. Next: independent whole linked-image/library
controls, alternate default/profile stages and scripted/disk/guest startup. See
[USERBOOT-SHARED-CONSTRUCTION.md](USERBOOT-SHARED-CONSTRUCTION.md). Full-system,
bootstrap/package/debug/runtime/performance gates remain open. Make stays default;
BIP remains excluded.

## Userboot harness and original variant references (2026-11-04)

The hosted AMD64 internal harness now builds natively with original object and
linked allocated-section parity, 85 consumed source/header bindings, real debug
splitting and verified debuglink CRC. Three safe runtime error paths pass through
the declared BSD linker and SDK libraries. It adds no installation contribution.
Configured metadata and explicit original Make references for both 42-source
Lua/Forth shared objects now pass. Native shared linking, variant installations,
default aliases and successful callback/guest startup remain the next work. See
[USERBOOT-HARNESS-QUALIFICATION.md](USERBOOT-HARNESS-QUALIFICATION.md). Complete
system/bootstrap/package/debug/runtime/performance gates remain open; Make stays
default and BIP stays excluded.

## AMD64 Lua kboot consumer (2026-11-04)

The native consumer now has 39 original compiler contexts, declared dependencies,
version/help generation, original ordered link, strip and two-file installation
archive. Thirty-seven entry contracts match directly; two original filename-only
controls plus the original libsa controls reproduce the entire installed image
through original link/install recipes. The audit binds 1,818 consumed pairs.
Final regression: 33 passing targets (one executed, 32 cached), 34 prior outputs
unchanged, all kboot outputs rebound. The selected profile is AMD64 Lua with
FDT disabled; alternate profiles and Linux/kexec runtime remain open. See
[KBOOT-LOADER-QUALIFICATION.md](KBOOT-LOADER-QUALIFICATION.md). Full system,
bootstrap/packages/debug/runtime/performance gates are still incomplete. Make
remains default; BIP stays excluded.

## World inventory and AMD64 kboot library (2026-11-04)

Fresh Make discovery and all 2,128 component queries pass. The declaration review
queue distinguishes 1,510 local owners and 618 ancestor owners; presence is not
native build coverage. Native AMD64 libkboot now has eight original compiler
contexts, exact allocated/symbol/relocation contracts, declared headers and the
real archive producer. The audit binds 255 consumed source/header pairs and the
original empty install contribution. Regular verifier and other architectures
remain unavailable; the complete kboot consumer is still missing. See
[KBOOT-LIBRARY-QUALIFICATION.md](KBOOT-LIBRARY-QUALIFICATION.md). Complete system,
runtime, packaging/bootstrap/debug and performance gates remain open. Make stays
default; BIP remains excluded.

## Complete selected BIOS interpreter family (2026-11-04)

Lua/Forth/simple now share one source-owned model with 36 contexts each. The two
new producers retain original archive/link/strip/BTX contracts; 70 new raw entry
contracts match directly and two assertion-filename controls explain the rest.
Original recipe controls reproduce whole clients/images. Default aliases follow
actual Lua/Forth/simple feature precedence or an explicit input; only simple owns
the generated shared help file. PXE inherits that default or an explicit real
client. Five routing profiles and actual Make default stages pass. The audit binds
108 family compiler contexts/4990 consumed pairs, 120 producer associations, ten
install record comparisons and 34 unchanged prior boot outputs. Default test
profile: 31 passes, four executed and 27 cached. Retained failed first analysis
and prior cached-producer provenance remain explicit. See
[BIOS-FAMILY-QUALIFICATION.md](BIOS-FAMILY-QUALIFICATION.md). The maintained frontend
and manual are updated; complete system, runtime, packaging/bootstrap/debug and
performance gates remain open. Make stays default; BIP stays excluded.

## PXE construction checkpoint (2026-11-04)

The missing PXE consumer now has native i386 assembly/link, actual native Lua
client dependency, original size guard, a.out BTX packing, ordered concatenation,
2048-byte alignment and shared-policy archives. Four console combinations match
fresh original Make prefix/object bytes; actual original BTX/dd recipe controls
over the independently qualified original loader reproduce every complete image.
The older SDK client in the raw Make references remains explicit. The audit binds
four compilers/twelve consumed pairs, 28 producer associations, eight install
record comparisons and 32 unchanged prior boot products. Actual over-limit and
unsupported-interpreter builds fail. Final default: 29 passing test targets, two
executed and 27 cached. The normal frontend/manual and restricted boot-selector
reference API are updated. See [PXE-BOOT-QUALIFICATION.md](PXE-BOOT-QUALIFICATION.md).
Firmware/network execution, alternate profiles and complete system/package/
bootstrap/debug/cache/performance gates remain open. Make stays default; BIP is
excluded.

## GPT/ZFS BIOS checkpoint (2026-11-04)

The missing GPT/ZFS consumer now builds ten original i386 entry contexts, ordered
startup/BIOS/standalone links, flat/BTX images and shared-policy archives. Two
console/manual profiles pass actual artifact tests and independent original
compiler/link controls. The audit binds twenty compiler contexts/910 consumed
pairs, the explicit zfsimpl.c prerequisite in both contexts, 32 producer chains
and four installation-record comparisons. Thirty prior boot products stay exact.
Default profile: 27 passing test targets, three executed and 24 cached; no claim
of firmware or full-system qualification. The maintained frontend/manual are
reviewed; no new C dispatcher is required. See
[GPT-ZFS-BOOT-QUALIFICATION.md](GPT-ZFS-BOOT-QUALIFICATION.md). PXE/alternate profiles,
complete system/package/runtime/debug/bootstrap and performance gates remain
open. Make stays default; BIP is excluded.

## GPT/ISO BIOS checkpoint (2026-11-04)

Two previously missing boot consumers now build native standalone i386 entry,
ordered archive link, flat image, BTX and installation pipelines. Three UFS/console
profiles pass real artifact tests and independent original recipe controls. The
audit binds thirty compiler contexts/1098 consumed pairs and 69 producer chains;
four original install records have twelve profile comparisons. ISO matches raw
Make; GPT matches explicit original compiler filename controls. A one-byte ISO
limit fails in the real build action. Twenty-six existing boot products stay exact.
Shared boot-data policy additionally passes default/disabled/uncompressed split
manual checks against six actual Make references. The maintained reference helper
now verifies direct custom-link archive operands
with strict metadata/output checks; eleven validator methods pass. The normal
format-5 frontend needs no new C dispatch. See
[GPT-ISO-BOOT-QUALIFICATION.md](GPT-ISO-BOOT-QUALIFICATION.md). GPT/ZFS/PXE and other
profiles, complete system/package/runtime/debug/bootstrap/performance gates
remain open. Make stays production/default; BIP is excluded.

## Standalone legacy BIOS checkpoint (2026-11-04)

Five remaining legacy producers (boot0, serial boot0, MBR, protective MBR and
cdboot) now use standalone i386 compilation, direct declared SDK linking and
explicit public artifact boundaries. Five fresh original Make controls establish
whole-byte equality for all objects/images and six actual installation records.
The audit binds ten compiler/link chains and nineteen unchanged prior boot
outputs. All 24 selected tests pass; one executes and 23 reuse unchanged cached
results. Alternate policy/options, firmware/runtime, complete system/package,
bootstrap and performance acceptance remain open. The normal format-5 frontend
requires no new C dispatch; the manual is updated. Make stays default; BIP stays
excluded. See [the standalone legacy record](LEGACY-STANDALONE-QUALIFICATION.md).

## Current CTF linker checkpoint (2026-11-03)

LLD section integration is implemented. Fresh verified SDKs now pass normal
maintained build-bsd/Bazel nullfs profiles on AMD64, ARM64 and RISC-V. The strict
CTF/export/debug-split tests actually execute (112/112/114 associations and
fourteen named-type checks per architecture). Actual selected SDK/tool actions
are reviewed on all three architectures.

Native Bazel now builds LLD and passes its 138 section/graph/script cases and
ten symbol/thunk/reference cases. Its first run exposed an SDK/compiler versus
source-built LLVM runtime collision in a test. Explicit per-child runtime
selection fixes that collision; every regression assertion remains intact.
BEP outputs and both executed tests are retained. The rebuilt exact-version
upstream converter now verifies the native action chain from eight relevant
source compilations through the PIC archive, LLVM shared library, LLD and both
executed tests. Failed and corrected symbol tests use identical linked inputs.

Shared test-runner runtime inheritance still needs an audit beyond these fixed
harnesses. Independent refreshed Make controls, debugger/runtime, compression/
footprint, complete LLVM/bootstrap, world/kernel, packaging/publication,
sandbox/cache and broad performance acceptance remain open.

Current CTF output is uncompressed v3: tested full modules grow about 37 KiB,
about 13-15%. Compression/footprint and broad CPU/memory/I/O/disk gates remain
open. Limited no-CTF controls show no regression. See CTF-NAMESPACE-UNION.md.
This supersedes chronological entries saying LLD is not connected. Full system
and publication gates remain open. Make stays default; BIP is excluded. No host
upgrade, installation into the running system or reboot occurred.

## Storage module checkpoint (2026-11-03)

Twenty-three shared storage module leaves per ARM64/RISC-V architecture and
two ARM64-only Linux compatibility children pass native builds and artifact
review. The shared components cover 92 plain/CTF variants, 380 compiler
contexts/55,888 canonical consumed pairs, 184 ordered links and 138 installation
records. Forty-two of 46 plain artifacts equal untouched Make bytes; four equal
explicit identical-source filename controls. CTF/runtime contracts retain that
42/4 distinction. All 46 shared separate DWARF files differ; source/debugger
qualification remains open.

Complete recursive MFI/MRSAS comparisons cover eight family variants and all
24 installation records, including the two ARM64 children. The children add
four compiler contexts/546 consumed pairs and eight ordered links. Family
records overlap component records; they are not extra installation coverage.
Original amd64 controls qualify MMC/consumer exports and MRSAS compiler policy.
Twelve actual positive/negative provider tests pass across six profiles.

The changes preserve real Make compiler options, forced headers, generated
schemas, exports and child selection. The normal format-5 build-bsd workflow
uses 16 CPUs and a disk reserve. Its C frontend needs no new command-line option.
No C implementation or probe changed. Full world/cross kernels, separate DWARF,
package publication, runtime, bootstrap/sandbox and performance gates remain
open. Make remains production/default; BIP remains excluded.

See [the storage qualification record](CROSS-STORAGE-BUSES-QUALIFICATION.md).

## Cross-target network protocol checkpoint (2026-11-03)

Twenty-eight selected network protocol/interface module leaves per architecture
pass ARM64/RISC-V builds and artifact checks. Fifty of 56 plain modules equal
untouched Make bytes; six equal explicit identical-source canonical-filename
controls. CTF/runtime checks retain the same 50/6 distinction. The review
covers 344 actual compiler contexts/55,296 canonical consumed pairs, 224 ordered
links and 168 installation records. It preserves WireGuard's forced header,
TCP-specific defines and Netlink's relative CTF object paths. A missing tuntap
generated-header prerequisite and localized TCP timer API exports are corrected
in maintained Make and native metadata. Twelve actual provider tests pass
across six profiles, including amd64 regressions. Separate DWARF, runtime,
full-system and performance gates remain open. See
[CROSS-NETWORK-PROTOCOLS-QUALIFICATION.md](CROSS-NETWORK-PROTOCOLS-QUALIFICATION.md).

## Cross-target I/O-bus checkpoint (2026-11-03)

Sixty-one selected GPIO/I2C/1-Wire/PWM/SPI module leaves per architecture pass
ARM64/RISC-V Bazel builds and artifact checks. Of 122 plain modules, 110 equal
untouched Make bytes; 12 equal explicit identical-source canonical-filename
controls. CTF/runtime checks retain the same 110/12 distinction. The review
covers 340 actual compilers/34,550 canonical consumed pairs, 488 ordered links
and 366 install records. A real 1-Wire export defect is fixed in both backends
and additionally qualified on amd64. All twelve positive/negative provider
tests pass. Separate DWARF, runtime and performance gates remain open. See
[CROSS-IO-BUSES-QUALIFICATION.md](CROSS-IO-BUSES-QUALIFICATION.md).

## ARM64/RISC-V USB core/peripheral checkpoint (2026-11-03)

Twenty-two USB core/controller/storage/peripheral modules on each of
ARM64/RISC-V pass four normal build-bsd profiles/provider tests and 88 original
Make controls. All 44 plain modules match whole-file bytes; 44
CTF/runtime/debuglink comparisons, 240 actual compilers/30,264 canonical
consumed input pairs, 176 ordered links and 132 original installation
records/payload bindings pass. Target FDT adds usb_fdt_support.c; a real cp2112
Make prerequisite omission is corrected in both build descriptions. Separate
DWARF/source lookup and device/runtime/performance gates remain open. See
[CROSS-USB-CORE-MODULES-QUALIFICATION.md](CROSS-USB-CORE-MODULES-QUALIFICATION.md).

## ARM64/RISC-V USB serial/input checkpoint (2026-11-03)

Twenty-nine USB serial/input module leaves on each of ARM64/RISC-V pass four
normal build-bsd profiles/provider tests and 116 original Make controls. All 58
plain module bytes match; 58 CTF/runtime/debuglink comparisons, 116 actual
compilers/15,232 canonical consumed input pairs, 232 ordered links and 174
original installation records/payload bindings pass. Actual parent-exported
Make options, GENERIC KERN_OPTS and 64 regular Makefiles are retained alongside
the explicit empty configuration sentinel. Separate DWARF/source lookup and
device/runtime/performance gates remain open. See
[CROSS-USB-INPUT-MODULES-QUALIFICATION.md](CROSS-USB-INPUT-MODULES-QUALIFICATION.md).

## ARM64/RISC-V input module checkpoint (2026-11-03)

Twenty-six input modules per architecture pass original Make comparison on
ARM64 and RISC-V: 52 exact plain modules, 52 CTF/runtime/debuglink checks, 120
actual compilers/13,522 canonical consumed input pairs, 208 ordered links and
156 original installation records/payload bindings. Four maintained
provider-test profiles pass, checking required callbacks and deliberate
localization defects. KOBJ schema provenance comments are the only permitted
generated-input content differences and remain explicit; standalone
DWARF/source lookup remains open. See
[CROSS-INPUT-MODULES-QUALIFICATION.md](CROSS-INPUT-MODULES-QUALIFICATION.md).

## Open module debug qualification gate

Read [MODULE-DEBUG-QUALIFICATION.md](MODULE-DEBUG-QUALIFICATION.md) before interpreting
historical “CTF/debug” claims. Installed stripped module/CTF parity and separate
CRC validity do not establish cross-build DWARF parity. Direct audits of 117
pairs find five differing sections; semantic DIE/line mapping and actual debugger
source lookup against a canonical source/debug package layout remain required.
Carry any input/toolchain/package/frontend change through maintained tooling.


Resumed by user instruction on 2026-11-01 after the committed upgrade
checkpoint (`7ffc0048161`). The target is complete base-system Make coverage
and a complete native Bazel system build, not BUILD-file presence. Make
remains supported for ports and third-party software. BIP remains out of scope.

## Latest system/I/O module checkpoint (2026-11-02)

Thirty-seven further amd64 module leaves pass compiler/input/link and artifact/
install checks: 125 actual compiler contexts and 13,134 original / 13,135 native consumed
dependencies per profile, with the sole extra TPM header alias verified as the
same physical file and bytes, plus 37 ordered links. Thirty-five plain modules equal
untouched Make; two equal explicitly documented filename controls. CTF/debug
payloads/CRCs and 74 install records pass, plus 37 plain records. Explicit iconv/
nvdimm exports and Thunderbolt's module option header are preserved. Actual
before/after dconschat archives, including debug payloads, remain byte-identical
using the unchanged public ABI view with physical package-owned file labels.
See [SYSTEM-IO-MODULES-QUALIFICATION.md](SYSTEM-IO-MODULES-QUALIFICATION.md).

BUILD presence is 628/729 selected amd64 leaves (101 missing), not qualification
percentage. Other architectures/options, full world/rescue/pkgbase/hardware,
bootstrap/publication, VM/runtime and CPU/memory/disk I/O/cache/sandbox gates remain
open. Existing build-bsd format-5 inputs/rules carry this cohort; no new CLI or
security/publication policy. Make stays production/default; BIP remains excluded.

## Latest storage-adapter checkpoint (2026-11-02)

Seventeen further amd64 storage module leaves pass native compiler/input/link,
artifact and installation checks: 260 compiler contexts, 36,990 original/native-
consumed dependencies and seventeen ordered links per profile. Four original
vendor ELF objects are explicit hash-bound link inputs. All seventeen plain
modules match untouched Make whole-file; CTF/debug payloads, CRCs and 34 install
records pass, plus seventeen plain records. Qualification found and corrected
hptmv's missing original CFLAGS-reset policy using native feature selection;
its first artifact remains rejected. Eighty unchanged-default output bindings
remain exact. See
[STORAGE-ADAPTERS-MODULES-QUALIFICATION.md](STORAGE-ADAPTERS-MODULES-QUALIFICATION.md).

BUILD presence is 591/729 selected amd64 leaves (138 missing), not qualification
percentage. Other architectures/options, full world/rescue/pkgbase/hardware,
bootstrap/publication, runtime and CPU/memory/disk I/O/cache/sandbox gates remain
open. Maintained build-bsd format-5 inputs carry this cohort; module helper and
docs are updated without new CLI/security/publication policy. Make stays default;
BIP remains excluded.

## Latest platform-module checkpoint (2026-11-02)

Twenty-four further amd64 platform/GPIO/watchdog modules pass two native
compiler/input/link and artifact/install profiles: 36 actual compilers and 3,843
original/native-consumed dependencies per profile, plus 24 ordered links.
Twenty-two plain modules equal untouched Make whole-file; p2sb/superio equal
independent canonical-filename Make controls. Original lexical-path discrepancies
remain recorded. CTF/debug payloads, CRCs and 48 install records pass, alongside
24 plain records. Six existing provider tests pass per profile; device runtime
is not qualified. See
[PLATFORM-FAMILIES-MODULES-QUALIFICATION.md](PLATFORM-FAMILIES-MODULES-QUALIFICATION.md).

BUILD presence is 574/729 selected amd64 leaves (155 missing), not qualification
percentage. Other architectures/options, full world/rescue/pkgbase/hardware,
bootstrap/publication, VM/runtime and CPU/memory/disk I/O/cache/sandbox gates remain
open. Existing build-bsd format-5 inputs/helpers carry this cohort; no new CLI or
security/publication policy. Make stays production/default; BIP remains excluded.

## Latest Intel Ethernet checkpoint (2026-11-02)

Seven more amd64 modules pass two native compiler/input/link and artifact/install
profiles. Each binds 118 actual uncached compiler actions and 21,775 original and
native-consumed dependencies; all seven plain modules are whole-file identical
to Make. CTF/debug sections, CTF payloads, split-debug CRCs and seventeen install
records pass; ten plain records pass. Three relative aliases follow configured
kernel directories. The common helper has positive archive and negative prefix
tests; existing archive and prior network outputs remain exact. Actual Make
staging also qualifies the empty-alias-package-tag correction and explicit
package/tag overrides. See
[INTEL-ETHERNET-MODULES-QUALIFICATION.md](INTEL-ETHERNET-MODULES-QUALIFICATION.md).

Local BUILD presence is 550/729 selected amd64 leaves (179 missing), not whole
system qualification. ARM64/RISC-V, complete world/rescue/pkgbase/hardware,
bootstrap/publication, runtime and CPU/memory/disk I/O/cache/sandbox gates remain
open. The maintained build-bsd frontend exercises these changes with existing
format-5 inputs; module rules, tests and manual are updated. Make stays default;
BIP remains excluded.

## Latest network-module checkpoint (2026-11-02)

Nine amd64 network/RDMA leaves now pass native compiler/input/link and artifact/
installation reviews against eighteen original Make controls. Both profiles bind
98 actual compilers and 27,502 original and native-consumed dependency occurrences,
plus nine complete ordered links. Five plain modules match whole-file bytes;
four differ only in independently reproduced 20-byte build-ID descriptors from
original local debug compilation, with every other final byte equal. CTF/debug
sections, CTF payloads, split-debug CRCs and eighteen installation records pass;
nine plain installation records pass. Six existing provider tests pass per profile.
See [NETWORK-FAMILIES-MODULES-QUALIFICATION.md](NETWORK-FAMILIES-MODULES-QUALIFICATION.md)
for the rejected initial strict criterion and exact linker-control evidence.

BUILD presence is 543/729 selected amd64 leaves (186 missing), not qualification
percentage. Fresh parent-export-aware inventories select 627 ARM64 and 553 RISC-V
leaves; only 216/214 have recognized cross-module declarations. Older cross
inventories omitted twelve/ten FDT-selected leaves. Evidence and exact gaps are
retained under `/usr/obj/usr/src/bazel-current-module-selection-20261102/`.
The separate real static rescue dispatcher is under qualification; its bounded
three-application result does not close the full rescue selection. Full world,
rescue/pkgbase/hardware/bootstrap/publication, alternate options/architectures,
VM/runtime and CPU/memory/disk I/O/cache/sandbox qualification remain open.
Existing build-bsd format-5 inputs and maintained rules carry these declarations;
no new CLI/backend/security/publication policy. Make stays production/default;
BIP remains excluded.

## Latest kernel checkpoint (2026-11-02)

Complete native amd64 GENERIC now passes controlled full Make parity: all 2,462
objects match code/allocated data/CTF, and the linked full/runtime kernels match
55 allocated payloads plus validated build-ID metadata, 96,147 loader symbols
and merged CTF. The comparison found and fixed the initial helper DSO build-path
DT_NEEDED defect; old artifacts fail the new test. See
[FULL-KERNEL-PARITY-QUALIFICATION.md](FULL-KERNEL-PARITY-QUALIFICATION.md).
Native kernel installation now also matches original Make staging in default,
alternate and colocated-debug layouts; see
[KERNEL-INSTALLATION-QUALIFICATION.md](KERNEL-INSTALLATION-QUALIFICATION.md).
Next kernel work is pkgbase integration and module/configuration/architecture
qualification, followed by VM/runtime and performance gates. Full world and
bootstrap/publication remain open; Make stays production/default.

The package driver now preserves first-class directory layout records, including
empty directories, alongside optional mtree ownership metadata. Its registered
real-pkg/BSD-tar Bazel regression passes three valid layouts and three rejection
cases. Kernel/GDB component packages also preserve the captured payloads; this
does not close complete kernel packaging. See
[PACKAGE-DIRECTORY-QUALIFICATION.md](PACKAGE-DIRECTORY-QUALIFICATION.md).


Two further hardware modules, amd_ecc_inject and amdsbwd, now pass native plain
and CTF/debug artifact/install comparisons against corrected original Make
controls. See [HARDWARE-MODULE-GAP-QUALIFICATION.md](HARDWARE-MODULE-GAP-QUALIFICATION.md)
for the export-policy correction, debug-definedness mismatch and fresh SDK
qualification after a changed host tar input. Other module coverage remains open.


Nine further hardware modules now pass native plain and CTF/debug artifact and
installation comparisons: AAC/AACRAID and their Linux adapters, Alder Lake/AMD
GPIO, Apple BCE, Areca and Apple SMC. The batch covers 19 source files and 2,799
Make dependency occurrences; see
[NINE-HARDWARE-MODULES-QUALIFICATION.md](NINE-HARDWARE-MODULES-QUALIFICATION.md).


Ten Atheros loadable modules now pass native default plain/CTF-debug comparison,
including the complete 138-object default inventory and both alternative rate
algorithms. All twelve plain binaries are byte-identical to Make; CTF/debug
runtime sections and 36 install records agree. Actual compiler/input and ordered
link audits pass. Source corrections and runtime limitations are recorded in
[ATH-MODULES-QUALIFICATION.md](ATH-MODULES-QUALIFICATION.md).

The next twelve-module Broadcom group has original Make source facts captured.
Its two native NVRAM header producers now match original Make output bodies with
declared AWK/map/runtime inputs; module compilation remains open. See
[BHND-NVRAM-GENERATOR-QUALIFICATION.md](BHND-NVRAM-GENERATOR-QUALIFICATION.md).

Twelve Broadcom bus/wireless modules now pass native 75-object compile/input and
ordered-link audits, corrected Make plain/CTF-debug comparisons and 36 install
records. Static import review found four local-only shared provider policies;
explicit exports and positive/negative artifact tests remove fallback reliance.
GPIO providers and runtime/module loading remain open. See
[BROADCOM-MODULES-QUALIFICATION.md](BROADCOM-MODULES-QUALIFICATION.md).

Six GPIO modules now pass ten actual compiler/input and six ordered-link audits,
plain/CTF-debug comparisons and eighteen install records. Both profiles pass three
provider tests, including explicit Broadcom-to-GPIO edges. Two ordinary Make
filename differences require separately audited compiler-policy controls; the
untouched baselines and a rejected first control remain recorded. SPI providers,
full loading and runtime/performance gates remain open. See
[GPIO-MODULES-QUALIFICATION.md](GPIO-MODULES-QUALIFICATION.md).

At the GPIO checkpoint, the 729-leaf amd64 selection had 284 local BUILD files
and 445 leaves without one; these were source-coverage counts only.

Six SPI controller/bus/flash/HID modules now pass eleven actual compiler/input
and six ordered-link audits, untouched Make plain/CTF-debug comparisons and
eighteen install records. Both profiles pass four provider tests. The qualified
kernel plus twenty-four Broadcom/GPIO/SPI modules now have providers for every
strong import with no hidden supplied providers; loading/runtime remain open.
See [SPI-MODULES-QUALIFICATION.md](SPI-MODULES-QUALIFICATION.md).

At the SPI checkpoint, the 729-leaf amd64 selection had 290 local BUILD files
and 439 leaves without one; these were source-coverage counts only.

Twenty-four HID/evdev modules now pass 28 actual compiler/input and 24 ordered-link
audits, Make plain/CTF-debug comparisons and 72 install records. An original hgame
policy localized three public callbacks used by three controller modules; explicit
exports and positive/negative provider tests remove reliance on local-symbol fallback. Static strong-import
coverage passes for the kernel plus 48 Broadcom/GPIO/SPI/HID modules. Runtime and
hardware behavior remain open. See
[HID-MODULES-QUALIFICATION.md](HID-MODULES-QUALIFICATION.md).

At the HID checkpoint, the 729-leaf amd64 selection had 314 local BUILD files
and 415 leaves without one; these were source-coverage counts only.

Module export tests enforce explicit ELF bindings; the source loader defaults permit
local-symbol lookup for compatibility. Earlier claims that local-only findings
necessarily caused default load failures are withdrawn. Explicit exports remain;
actual VM loading under both settings is still required. See
[MODULE-LOADER-EXPORT-CONTRACT.md](MODULE-LOADER-EXPORT-CONTRACT.md).

Four crypto modules now pass 80 actual compiler/input and four ordered-link audits,
untouched Make plain/CTF-debug comparisons and twelve install records. Assembly,
fifteen custom SIMD compilations and 820 explicit SDK header occurrences are covered;
48 prior HID artifacts remain byte-identical and all six provider regressions pass
in both profiles. Existing OpenCrypto SDT descriptor/relocation sections match Make.
Crypto runtime/known-answer/performance gates remain open. See
[CRYPTO-MODULES-QUALIFICATION.md](CRYPTO-MODULES-QUALIFICATION.md).

The current 729-leaf amd64 selection has 318 local BUILD files and 411 leaves
without one. These are source-coverage counts, not qualified builds.

Earlier component checkpoints below are retained historical evidence.

Refreshed Make module selection finds 729 selected amd64 leaves, with 245 local
BUILD files (244 direct audited macros and one separate ZFS description). This
is discovery, not build qualification; see
[MODULE-SELECTION-QUALIFICATION.md](MODULE-SELECTION-QUALIFICATION.md).

## Current resumption (2026-11-02)

The user resumed after the committed kernel-upgrade checkpoint a28f294501e.
Eight host execution input hashes changed; the maintained SDK preparation was
rerun into bazel-postupgrade-sdk-20261102 under /usr/obj/usr/src rather than
rebinding the historical receipt. All 16,812 new baseline checks pass. The next
twenty-four amd64 GENERIC virtual-memory objects pass actual compile/input,
code and CTF inspection; see VM-KERNEL-QUALIFICATION.md. This is component
progress, not a full native kernel/world/package/runtime or performance gate.
A further forty-three selected IPv4/TCP built-in objects pass the same native
compile/input, code/CTF and symbolic relocation checks; see
IPV4-KERNEL-QUALIFICATION.md. Full kernel link/network runtime gates remain open.
Twenty-nine selected IPv6 objects now pass corresponding native object/input
checks; see IPV6-KERNEL-QUALIFICATION.md. These cohorts do not close full kernel
aggregation, cross-build or runtime/performance gates.
Userland completed native WPA utility/crypto private libraries and passphrase
qualification across five declared configurations; see WPA-PRIVATE-QUALIFICATION.md
for 25 immutable ELF comparisons, 35 runtime methods and source/input/install
checks. The common library and hostapd control client now also pass four profiles,
twelve immutable ELF comparisons and sixteen safe CLI/loader methods; see
WPA-COMMON-CLIENT-QUALIFICATION.md. Remaining WPA private libraries/programs and
wireless/service behavior are open. Nine further support libraries now pass
38 Make configurations, five native profiles and 76 archive comparisons; see
WPA-SUPPORT-QUALIFICATION.md. All four remaining private libraries now pass
32 archive comparisons and 660 actual object/compiler/input checks across four
profiles; see WPA-FINAL-PRIVATE-QUALIFICATION.md. All sixteen private library
directories have bounded native output qualification. The wpa_cli client now
passes four immutable ELF contracts, actual compiler/link/input checks, sixteen
safe CLI/loader methods and original install metadata; see WPA-CLI-QUALIFICATION.md.
Remaining programs are wpa_supplicant and hostapd. Their source/link/install
graphs and all actual service/wireless runtime gates remain next. The next upgrade checkpoint records prepared
common/control-client Make references, which require post-upgrade revalidation. All remaining work
and final completion requirements below apply.

Thirty-two selected network built-ins now pass native code/CTF, input and
symbolic relocation checks; see NETWORK-KERNEL-QUALIFICATION.md. The corrected
graph reuses existing interface providers. Whole-kernel aggregation, cross-build
and runtime/performance gates remain open. This work resumed at user instruction
after the November 2 committed stopping point; host/SDK revalidation passes.

Thirty-six selected MII built-ins now pass native code/CTF, input and relocation
checks; see MII-KERNEL-QUALIFICATION.md. Refreshed known-builtin analysis finds
512 source matches among 2,466 Make final link products, plus six weaker name
matches and 1,948 unmatched products. These counts describe analysis, not full
compiled coverage. Kernel aggregation, cross-build, runtime and performance
requirements remain open.

Thirty-seven wireless built-ins now pass native code/CTF, input and relocation
checks after five actual per-source warning exceptions were corrected; see
WIRELESS-KERNEL-QUALIFICATION.md. Latest known-builtin configured analysis finds
549 source matches among 2,466 Make final link products, six weaker name matches
and 1,911 unmatched products. Earlier counts above are retained snapshots.
These remain analysis counts; full compile/link/runtime/performance gates apply.

Twenty-five OpenCrypto built-ins now pass native code/CTF/input/relocation
checks, with consumed libsodium headers owned by their source package; see
OPENCRYPTO-KERNEL-QUALIFICATION.md. Complete known-built-in analysis passes
across that boundary: 574 source matches among 2,466 Make final link products,
six weaker name matches and 1,886 unmatched in this known graph. Earlier counts
are retained snapshots; complete link/runtime/performance gates remain open.
The existing frontend API handles these targets unchanged; no new CLI/manual
option or signing/packaging policy is required.

Native amd64 VDSO production now uses separate declared compile/link/validation/
offset/embed actions; see VDSO-QUALIFICATION.md. Four original products match
Make byte for byte and 16 native validator regression methods pass. This closes
a producer prerequisite for elf_machdep, not the prepared 32-source low-level
amd64 conversion or full kernel link/runtime qualification. Existing staged
compiler/linker/Python and format-5 artifact/host-test APIs remain the workflow.

The 32-source low-level amd64 cohort now passes native object/input and
symbolic relocation checks, including seven CTF-bearing assembly files and
two actual Make no-CTF exceptions; see AMD64-LOWLEVEL-QUALIFICATION.md. Nested
architecture headers retain their logical namespaces. Latest successful known-
builtin analysis finds 606 source matches, six weaker name matches and 1,854
unmatched among 2,466 Make final products. These remain analysis counts, not a
linked kernel; earlier counts above are retained snapshots. The next 22 x86
C objects have unchanged independent Make object/recipe/dependency references
prepared; declarations and output qualification remain to be done.

The next 22 x86 C built-ins now pass native code/CTF/input/relocation review;
see X86-CORE-KERNEL-QUALIFICATION.md. New physical header ownership preserves
bhyve's recorded configured header context. Latest successful known-builtin
analysis finds 628 source matches, six weaker name matches and 1,832 unmatched
among 2,466 Make final products. These remain configured-analysis counts, not
a full compile/link. The next 22 debugger objects have unchanged independent
Make object/recipe/dependency references prepared; native output qualification
is still required. Existing whole-system and performance gates remain open.

The 22 debugger built-ins now pass native code/CTF/input/relocation review;
see DDB-CORE-KERNEL-QUALIFICATION.md. Latest successful known-builtin analysis
finds 650 source matches, six weaker name matches and 1,810 unmatched among
2,466 Make final products. These are configured-analysis counts, not a complete
kernel build. The next 29 ACPI drivers have unchanged independent Make object/
recipe/dependency references prepared; native declarations/output qualification
remain required. Full system, runtime and performance gates remain open.

Format 5 now supports opt-in compact execution evidence, matching formats 3/4;
see SOURCE-COMPACT-LOG-QUALIFICATION.md. Three native test targets pass 25 actual
unittest methods, configured inventory succeeds, and the hash-verified upstream
converter preserves source/XML bindings through the shared streaming reader.
JSON remains default. Compiler/link/generator coverage on subsequent component
runs and controlled resource/cache comparisons remain required; this bounded
integration does not close the full-system performance gate.

The 29 ACPI platform built-ins now pass native code/CTF/input/relocation checks;
see ACPICA-CORE-KERNEL-QUALIFICATION.md. The corrected graph declares the real
maintained quirk-table AWK producer and preserves its output hash exactly.
Upstream compact-log reconstruction binds actual compiler/CTF/generator records
without expanded disk logs. Latest successful known-builtin analysis finds
679 source matches, six weaker name matches and 1,781 unmatched among 2,466
Make final products. Earlier counts remain snapshots; full kernel/world/package,
cross-build, runtime and controlled resource/performance gates remain open.

## ACPICA engine checkpoint (2026-11-02)

156 additional amd64 GENERIC engine objects pass exact code/CTF, actual compiler
input and relocation checks. The upstream source-owner move also passes affected
acpidb/iasl configured action comparison, native binary/archive builds and bounded
host-runtime launch checks. See ACPICA-ENGINE-KERNEL-QUALIFICATION.md for evidence
and limitations. Known kernel reconciliation now has 835 source matches plus six
name-only matches among 2,466 products; 1,625 remain unmatched. Full kernel/world,
all architectures, package, runtime and performance gates remain open.

## ISCI checkpoint (2026-11-02)

109 additional amd64 GENERIC Intel SAS built-ins pass native compilation,
code/CTF, actual input and relocation checks. Source-owned header closures and
actual config/interface producers preserve maintained Make policy. Known graph
reconciliation now has 944 source matches plus six name-only matches among
2,466 final products; 1,516 remain unmatched. See ISCI-KERNEL-QUALIFICATION.md.
Full-system, module, other-architecture, runtime and performance gates stay open.

## LinuxKPI checkpoint (2026-11-02)

46 native amd64 GENERIC compatibility objects pass final code/CTF, actual input,
forced-include policy and relocation checks. The strict policy audit caught and
corrected an omission despite matching machine code. Known graph reconciliation
now has 990 source matches plus six name-only matches among 2,466 final inputs;
1,470 remain unmatched. See LINUXKPI-KERNEL-QUALIFICATION.md. Full-system, module,
other-architecture, runtime and performance gates remain open.

## OpenZFS checkpoint (2026-11-02)

237 native amd64 GENERIC built-ins pass exact code/CTF, actual compiler-policy/
input/overlay-order and nondebug relocation checks. Per-file RPC/config exceptions
are independently preserved. Additive macro ordering inputs leave all 999 prior
configured compile actions unchanged. The standalone CTF checker's untyped string
address limitation is documented alongside bounded hash-bound graph/relocation
proof, without weakening the tool. Known graph reconciliation now has 1,227 source
matches plus six name-only matches among 2,466 final products, leaving 1,233
unmatched. See OPENZFS-KERNEL-QUALIFICATION.md. Full-system/module, other-architecture,
filesystem/runtime and comparative performance gates remain open.

## Atheros checkpoint (2026-11-02)

130 native amd64 GENERIC driver/HAL objects pass exact code/CTF, actual compiler
policy/input/include-order and nondebug relocation checks. New source owners and
actual config-generated AH/ATH options replace no runtime policies or source code.
Known graph reconciliation now has 1,357 source matches plus six name-only matches
among 2,466 final products, leaving 1,103 unmatched. See ATH-KERNEL-QUALIFICATION.md.
Full-system, module, other-architecture, radio/runtime and performance gates remain.

## Intel NIC checkpoint (2026-11-02)

69 native amd64 GENERIC objects pass code/CTF, compiler policy/input/header-order
and nondebug relocation checks. bhyve's header/action contracts remain unchanged
apart from 333 recorded action keys; an actual post-move binary build passes. Known
graph reconciliation has 1,426 source matches plus six name-only matches among 2,466
final products, leaving 1,034 unmatched. See INTEL-NIC-KERNEL-QUALIFICATION.md.
Full-system/module, other-architecture, device/guest/runtime and performance gates
remain open.

## Mellanox checkpoint (2026-11-02)

52 native amd64 GENERIC objects pass code/CTF, compiler policy/input/compatibility
header order and nondebug relocation checks. Explicit OFED/UAPI child exports
preserve source ownership. Known graph reconciliation has 1,478 source matches
plus six name-only matches among 2,466 final products, leaving 982 unmatched.
See MLX-KERNEL-QUALIFICATION.md. Full-system/module, other-architecture,
device/runtime and performance gates remain open.

## Storage HBA checkpoint (2026-11-02)

39 native amd64 GENERIC OCS FC/SmartPQI objects pass code/CTF, actual compiler
policy/input and nondebug relocation checks. Known graph reconciliation now has
1,517 source matches plus six name-only matches among 2,466 final products,
leaving 943 unmatched. See STORAGE-HBA-KERNEL-QUALIFICATION.md. Full kernel link,
modules, other architectures, storage runtime and performance gates remain open.

## Storage core checkpoint (2026-11-02)

76 native amd64 GENERIC CAM/GEOM/NVMe/UFSHCI objects pass code/CTF, actual compiler
policy/input and nondebug relocation checks. Existing source package boundaries
are preserved. Known graph reconciliation has 1,593 source matches plus six
name-only matches among 2,466 final products, leaving 867 unmatched. See
STORAGE-CORE-KERNEL-QUALIFICATION.md. Complete kernel link, modules, other
architectures, runtime and performance gates remain open.

## Filesystem/RPC checkpoint (2026-11-02)

101 native amd64 GENERIC objects pass code, compiler policy/input, NFS tracing
header precedence and nondebug relocation checks. CTF is byte-exact for 100;
ufs_bmap passes the unchanged production graph/symbol verifier with one fewer
unreferenced empty slot. Native RPC TLS reuses its existing protocol generators.
Known graph: 1,694 source matches plus six name-only matches among 2,466 final
products, leaving 766 unmatched. See FILESYSTEMS-RPC-KERNEL-QUALIFICATION.md.
Complete kernel/world/modules, other architectures, runtime and performance gates
remain open.

## Device I/O checkpoint (2026-11-02)

98 native amd64 GENERIC USB/input/audio/console objects pass exact code/CTF,
actual compiler/input and nondebug relocation checks. Native audio/teken tables
use original scripts; sound preset overrides pass through normal format-5 inputs.
Existing AWK default actions remain exact. Unchanged outputs are reused with only
workspace-status execution (ten BEP local cache hits in the two-target closure);
restoring previous preset configurations re-executes because no persistent disk
action cache is configured. Retain that failed expectation and add/qualify managed
persistent action-cache support before full-system cache/performance claims.
Known graph: 1,792 source matches plus six name-only matches among 2,466 products,
leaving 668 unmatched. See DEVICE-IO-KERNEL-QUALIFICATION.md. Full kernel/world,
modules, other architectures, runtime and performance gates remain open.

## Work order

1. Revalidate host, SDK and independent Make references after upgrades.
   Resume the saved bsdtrace and PCI Ethernet candidates, qualify actual
   outputs, installation metadata, declared inputs and code generation.
2. Refresh maintained Make inventories for world, libraries, programs, tests,
   generated data, kernel and modules on amd64, ARM64 and RISC-V64. Reconcile
   selected products to actual native targets and installed destinations;
   retain every missing or unqualified item as an open gate. Presence counts
   are diagnostics, never completion evidence.
3. Complete native libraries/programs/generators and kernel/driver/module
   graphs with explicit configuration inputs and dependencies. Preserve
   DTrace/FIDL generation, audit hooks, embedded policy, debug/CTF and
   installation semantics. Review each converted cohort and commit it.
4. Supply maintained aggregate world, kernel and installation targets,
   including bootstrap and cross-build dependencies. Compile and link the
   system with Bazel actions; wrapping Make does not satisfy conversion.
5. Integrate native products with pkgbase-only package construction, separate
   hardware builds and verified combined publication under
   `/usr/obj/usr/src/repo`. Retain ports Make interoperability. Publication
   worlds require production malloc and existing identity/validation gates.
6. Build the full system and packages through the maintained frontend; run
   Bazel tests and disposable-VM boot, login/PAM/su, SSH and service checks.
   Qualify clean/incremental/cache behavior and CPU, memory, disk I/O and
   disk-use regressions. Record configuration coverage and runtime limits.
7. Audit inventory closure and reproducible build/package evidence before
   claiming completion or changing the production default to Bazel.

## Integration and checkpoints

Each implementation change checks `usr.sbin/bsd-build/build-bsd.c`, maintained
backend targets, helpers, tests and manual for corresponding updates. Existing
component qualification uses the format-5 frontend API; the pending component
resumption adds no CLI option. Aggregate world/kernel/package backend work
will require frontend integration in the same changes.

Use standard `/usr/obj`, configured ports inputs and all logical CPUs. Do not
install or reboot the host as part of build qualification. Commit reviewed
chunks and update qualification documents with checks actually performed.
The saved patches remain historical checkpoints; applying them is not proof
that the active graph is qualified.

## Explicit reconciliation gates found during component work

- Close host execution dependencies and sandbox isolation before claiming a
  hermetic toolchain. In particular, the existing makeobjops AWK generator
  invokes host /bin/sh through system(); output parity does not establish
  complete execution-platform input closure.
- Reconcile Make compile policy as well as runtime output. Mailwrapper review
  found a missing -DPIC and warning vector in its initial native declaration.
  Its correction is component-scoped; earlier userland declarations still
  require an explicit warning/macro-policy audit. Kernel cohorts retain their
  actual per-source warning-vector checks.
- Parent-export-aware module selection is a discovery audit. Before accepting
  aggregate configurations, reconcile source-owned recursive command-line and
  SUBDIR_ENV overrides too; export propagation alone does not model arbitrary
  recursive Make semantics. Native products must retain explicit Bazel inputs.

- Keep source-package ownership valid as BUILD files are introduced. A configured
  query of existing built-in kernel groups exposed stale root-package ACPICA
  and autofs header paths; loading a narrow cohort does not establish whole-
  graph validity. Correct ownership and qualify affected consumers rather than
  excluding the kernel version/COPYRIGHT dependency that exposes the error.
- Diagnose execution-tool cache behavior from paired configured actions and
  actual execution records. PPP observed uncached tool compilation in a later
  profile, but matching execution output roots disprove the tentative differing-
  root explanation. Neither build-progress counts nor execution-log size alone
  establish how many tools rebuilt or why. Qualify compact evidence logging
  before full-system scale and controlled performance comparisons.

- Root header ownership is now corrected with unchanged physical/logical
  source closure and actual configured version/COPYRIGHT analysis. Preserve
  package boundaries in later source-owner conversions. Next reconcile the
  exact bhyve dependency order (equal sets are insufficient) and investigate
  actual acpidump/iasl/autofs/bhyve physical section differences. Retain shared
  directory package-tag contexts when qualifying pkgbase splitting; final
  staged metadata alone is not full package ownership evidence. See
  ROOT-HEADER-OWNERSHIP-QUALIFICATION.md.

- Generate fresh independent configured-kernel references from the selected
  current source/configuration before closure audits. The old amd64 configured
  Makefile omitted 385 current final-link products. The maintained
  kernel_inventory.py audit retains the actual final link order, architecture
  link arguments/post-processing, missing generated sources and unresolved
  custom products. CFILES/SYSTEM_OBJS-only counts are insufficient. See
  KERNEL-INVENTORY.md for current evidence and analysis/build distinctions.

### Ordered dynamic lookup and current-source references

The common ELF checker now rejects ordered DT_NEEDED differences for programs
and shared libraries, including existing probe callers. Follow
[ELF-NEEDED-ORDER-QUALIFICATION.md](ELF-NEEDED-ORDER-QUALIFICATION.md): fix historical
hwstat/bsdinstruments/dtrace ordering gaps in native dependencies, retain original
failed evidence, and rerun immutable comparisons. bhyve default order/install
passes a fresh post-merge Make reference; code/DOF/section parity and other
configurations remain separate gates. Every reused Make receipt must still pass
its recorded source hashes after merges; an old successful receipt is not a
current-source baseline.

### WPA daemon continuation (2026-11-02)

The genuine AES-SIV dependency fix and native hostapd checks are recorded in
WPA-AES-CTR-QUALIFICATION.md and WPA-HOSTAPD-QUALIFICATION.md. Four of five WPA
programs had bounded native qualification at that checkpoint. Native
wpa_supplicant now adds 51 actual code/input/raw-relocation checks, eight safe
methods and sixteen install records (WPA-SUPPLICANT-QUALIFICATION.md). All five
programs have bounded qualification. Audit configured Make world coverage and
aggregate/install/pkg ownership next; retain shared wpa/hostapd directory package
contexts. Reconcile the independent internal-backend SAE/EHT/crypto API failures
without silently disabling features.
Qualify hostapd IPv6/examples-disabled and custom build selections explicitly.
Retain live control, root driver setup, wireless/EAP/authentication and audit
event delivery as separate runtime gates. Archive construction and safe CLI
reports do not establish those behaviors. Existing compact execution logging,
configured exec-action caching and full pkgbase/system gates remain open.

### WPA family milestone and next world gap (2026-11-02)

WPA-FAMILY-QUALIFICATION.md records default family composition, 37 products, 33 install records and 23 safe methods. The old default control-client capture was invalidated and independently requalified; unsafe one-off objcopy dump invocations must not be reused. All audit tools must preserve source/reference/candidate bytes, bind producer output hashes and recheck inputs after inspection. The fresh 2,127-directory metadata survey is a review queue, not action coverage. Next convert the actual csv.enc plugin/install gap under inherited parent context, then reconcile selected world actions/generated sources/install/pkg ownership. Retain internal WPA backend failures and live runtime/full-system gates.

### Selected CSV plugin gap closed (2026-11-02)

LIBXO-CSV-QUALIFICATION.md qualifies the actual csv.enc producer and six installation records after parent-export comparison: one original source, exact object code/constants/relocations, strict shared ELF and five runtime methods. Installed-path discovery, whole-libxo tests/composition and final packages remain open. Continue the actual configured world action/install queue; usr.sbin/apm is a selected program with no native producer in the fresh inventory and requires source/parent-context review before conversion. Presence counts are not build coverage.

### APM selected leaf and next static PAM product (2026-11-02)

APM-PROGRAM-QUALIFICATION.md records native source/ELF/install qualification of the selected x86 APM leaf; whole-world aggregation must retain its parent MK_APM switch. Next close lib/libpam/static_libpam, the actual missing /usr/lib/libpam.a product: compile the real core with OPENPAM_STATIC_MODULES, retain all option-selected module archives and registration partial-link order, preserve DTrace/DOF and original install metadata. Existing shared-core/module targets alone do not establish this static product. Keep device runtime, full PAM authentication, pkg/world and performance gates explicit.

## Virtualization built-in checkpoint (2026-11-02)

60 Hyper-V, Xen and VirtIO built-ins compile through the maintained frontend with exact code/CTF and checked inputs/policies/relocations. See VIRTUALIZATION-KERNEL-QUALIFICATION.md. Full kernel/world/pkgbase, architecture, runtime, bootstrap and performance gates remain open.

## Storage-controller checkpoint (2026-11-02)

62 additional native storage-controller built-ins pass exact code/CTF and compiler/input/relocation checks through the maintained frontend. See STORAGE-CONTROLLERS-KERNEL-QUALIFICATION.md. Full kernel/world/pkgbase, architecture, runtime, bootstrap and performance gates remain open.

## Ethernet built-in checkpoint (2026-11-02)

73 additional native Ethernet built-ins pass exact code/CTF and compiler/input/relocation checks through the maintained frontend. See ETHERNET-KERNEL-QUALIFICATION.md. Complete kernel/world/pkgbase, architecture, runtime, bootstrap and performance gates remain open.

### Combined static PAM selected product (2026-11-02)

STATIC-PAM-QUALIFICATION.md closes the missing native `/usr/lib/libpam.a` producer:
54 original core sources, original selected module registration/partial-link order,
DTrace metadata/sites, compiler/input/relocation checks, default/reduced install
records and two fully static registry-only native tests (24/20 modules). Keep
full PAM aggregation/pam.d, installed original authentication/login/SSH tests,
other LOCALBASE/options/architectures and whole-world/pkgbase/runtime gates open.
Next reconcile the actual configured userland action/install queue from the
2,127-directory Make survey; source BUILD presence alone is not coverage.

## Network stack and PF built-in checkpoint (2026-11-02)

73 additional native Network stack and PF built-ins pass exact code/CTF and compiler/input/relocation checks through the maintained frontend. See NETWORK-POLICY-KERNEL-QUALIFICATION.md. Complete kernel/world/pkgbase, architecture, runtime, bootstrap and performance gates remain open.

### PAM policy installation (2026-11-02)

PAM-POLICY-QUALIFICATION.md closes the selected pam.d file/archive producer:
27 exact original payloads and 29 unique Make-matching records across default
and AT/FTP-off profiles. Retain full PAM aggregation, explicit directory ownership
consumption by final package composition, installed authentication tests, other
configurations/architectures and whole-world/pkgbase gates.

## Kernel codec/crypto checkpoint (2026-11-02)

73 additional native Kernel codec/crypto built-ins pass exact code/CTF and compiler/input/relocation checks through the maintained frontend. See CODECS-CRYPTO-KERNEL-QUALIFICATION.md. Complete kernel/world/pkgbase, architecture, runtime, bootstrap and performance gates remain open.

## Peripheral-device checkpoint (2026-11-02)

90 additional amd64 GENERIC objects pass native compilation, exact machine code/CTF and compiler/input/relocation checks. Reconciliation r29 leaves 187 missing Make link products, plus six weaker matches. See PERIPHERAL-DEVICES-KERNEL-QUALIFICATION.md. Full linking, modules, architectures, world, packaging, runtime, bootstrap and performance remain open.

## Platform-support checkpoint (2026-11-02)

56 platform built-ins pass object/CTF/compiler/input/relocation checks; the native ACPI assembly-to-binary/header chain matches Make. Reconciliation r30 leaves 131 missing link products and six weaker matches. See PLATFORM-SUPPORT-KERNEL-QUALIFICATION.md. Full linking, modules, architectures, world, packaging, runtime, bootstrap and performance remain open.

## Monitoring/device checkpoint (2026-11-02)

52 additional amd64 GENERIC objects pass native object/CTF/compiler/input/relocation checks. Reconciliation r31 leaves 79 missing link products and six weaker matches. See MONITORING-DEVICES-KERNEL-QUALIFICATION.md. Full linking, generators/tracing remainder, modules, architectures, world, packaging, runtime, bootstrap and performance remain open.

### Original PAM test inventory (2026-11-02)

PAM-TESTS-QUALIFICATION.md closes the three missing original program producers
and seven-program installation inventory. Nineteen exact object-policy/payload
checks, seven ordered ELF contracts, twenty install records and fourteen safe
wrapper results pass. Retain nine installed-path policy cases plus one root
accounting case for disposable-guest execution, then PAM aggregate reconciliation
and full world/pkgbase gates. No source assertions or requirements were disabled.

## DTrace built-in checkpoint (2026-11-02)

15 additional amd64 GENERIC objects pass native object/CTF/compiler/input/relocation checks after fixing real parent-header namespace and late Solaris utility ordering. Reconciliation r33 leaves 64 missing link products and six weaker matches. See DTRACE-BUILTINS-KERNEL-QUALIFICATION.md. Full linking, generated products, modules, architectures, world, packaging, runtime, bootstrap and performance remain open.

## Generated-interface checkpoint (2026-11-02)

49 KOBJ interface objects and 98 generated C/header bodies pass independent Make comparisons through the maintained frontend. Reconciliation r34 leaves 15 missing link products, 53 generated-name-only and two object-name-only matches; independent provenance/artifact checks strengthen 49 of those generated matches. See KOBJ-BUILTINS-KERNEL-QUALIFICATION.md. Full linking, remaining generators/custom products, modules, architectures, world, packaging, runtime, bootstrap and performance remain open.

## Generated RPC checkpoint (2026-11-02)

Four RPC generated objects pass exact machine-code/CTF/runtime-section/compiler/input/relocation checks; six generator products match Make byte-for-byte. Reconciliation r35 leaves 11 missing products, 57 generated-name-only and two object-name-only matches; independent provenance/artifact checks strengthen 53 generated matches. See RPC-BUILTINS-KERNEL-QUALIFICATION.md. Complete linking, custom identities, modules, architectures, world, packaging, runtime, bootstrap and performance remain open.

## SIMD crypto checkpoint (2026-11-02)

Five optimized SIMD crypto objects pass native code/CTF/runtime-section/compiler/input/relocation comparisons; 276 external SDK header occurrences match Make. Existing 2,284 configured groups retain identical compiler commands/output paths; five debug targets select O0. Reconciliation r36 leaves six missing products and conservative generated/name-only classifications, with separate artifact/source proofs retained. See SIMD-CRYPTO-KERNEL-QUALIFICATION.md. Full linking, remaining identities, modules, architectures, world, packaging, runtime, bootstrap and performance remain open.

## PAM family checkpoint (2026-11-02)

PAM-FAMILY-QUALIFICATION.md records default28/reduced23 component archive sets,
108 actual shared compiler recipes with 3756 fresh Make input bindings, both
linked ELF/DOF contracts and 65 install records per configuration. Default15 safe
wrappers pass; KERBEROS-off13 pass with two explicit exclusions. Preserve original
nine installed-policy and one privileged accounting guest gates, final pkgbase
composition, inherited world selection and full-system/runtime/bootstrap gates.

## Custom-named kernel checkpoint (2026-11-02)

Four radix/OpenZFS SHA objects pass code/CTF/compiler/input/relocation checks, including one complete hash-bound filename spelling difference. Three declared symlink aliases preserve actual final-link names and bytes. Reconciliation r38 binds 2,405 physical-source identities, leaves 57 generated-name matches (53 independently qualified), two weak object identities and two missing producer chains (VDSO and force-dynamic). See CUSTOM-NAMES-KERNEL-QUALIFICATION.md. Full linking, modules, architectures, world, packaging, runtime, bootstrap and performance remain open.

## Refreshed final-producer checkpoint (2026-11-02)

After merge 7056e69713f, refreshed SDK/config inventories and a complete independent Make amd64 GENERIC reference pass. The native force-dynamic helper and existing VDSO yield six original products exactly matching fresh Make. Current query r45/reconciliation r39 accounts for all 2,462 selected amd64 products with no missing producer in this audit, retaining two weak object identities and four unqualified generated identities. The prior VDSO missing classification was a query-selection gap, now corrected. See FINAL-PRODUCERS-KERNEL-QUALIFICATION.md. Complete native kernel linking/post-processing/install, modules, other architectures, world, packaging, bootstrap, runtime and performance remain open.

## DWATCH and post-merge world checkpoint (2026-11-02)

DWATCH-QUALIFICATION.md records native default 133 / EXAMPLES-off 131 installation
records, 259 exact installed-path payloads and 198 actual hardlink checks. One
actual syntax case parses 30 original inputs; the second configuration explicitly
reuses the byte-identical cached result. Live tracing/world/package gates remain.
Fresh Make recursion selects 2,128 directories, adding sbin/mount_virtiofs; this is
not compiled coverage. External merge 7056e69713f changes existing userland
sources/tests (including capability/runtime libraries, kldload/mount,
BSDExtension/base-accounts/bhyve/switchboard/dtraced) and adds requalification
obligations. Earlier receipts remain historical; no SDK receipt was rebound.

## Generated core checkpoint (2026-11-02)

Five generated built-ins and clock calibration pass source/compiler/prerequisite/code/CTF/runtime-section and 5,091 strict relocation comparisons. The initial successful build with missing debug/CTF was explicitly rejected; typed shared policy now supplies them. Config/version references use identical declared inputs without normalizing payloads. Clock declares selected-SDK SSP availability and opt-only O3. Query r47/reconciliation r40 leaves no missing or weak object-name identities in the 2,462-product configured inventory; 53 generated-name matches retain separate KOBJ/RPC proofs. See GENERATED-CORE-KERNEL-QUALIFICATION.md. Next: complete native kernel aggregation/link/order/post-processing/install and per-object debug/CTF validation. Modules, other configurations/architectures, world, packages, bootstrap, runtime and performance remain open.

## LLDB generation milestone (2026-11-02)

The root-selected four-source TableGen producer and 19 library headers pass
native/Make output, eight actual compiler-policy, 5,882 prerequisite-hash and
789 relocation checks. The original bootstrap stddef wrapper is now declared.
Host-static Make versus declared-native dynamic execution is explicit; this is
not installed LLDB completion. The 756-source private shared library now passes
actual compiler/input/archive-order checks, exact allocated object and linked DSO
sections against a complete declared filename-policy Make control, five install
records and one safe API wrapper. See LLDB-LIBRARY-QUALIFICATION.md for the
untouched baseline differences and historical SDK binding. Next: two CLI option
headers, programs, debugger runtime/package context and ancestor MK_LLDB selection.
See LLDB-GENERATORS-QUALIFICATION.md; original ordinary-leaf and strict input
failures are retained. No host installation or debugger activation occurred.

## Parser-owned kernel input inventory (2026-11-02)

`config -J` now exports the resolved ordered input table; native config exposes
it as an explicit manifest without Make discovery. All 12 architecture/option
cases match independent Make OBJS exactly; custom prefix/no-obj/JSON escaping,
unchanged ordinary outputs, deterministic writes, failed writes and shortcut
rejection pass using both Make-built and captured native config. Three native
architecture manifests exactly match Make. See
KERNEL-CONFIG-INVENTORY-QUALIFICATION.md. Next remains native aggregate coverage
validation/link/post-processing/install; no full kernel/world completion claim.

## Native kernel aggregation guard (2026-11-02)

All 2,285 public native object groups expose exactly the 2,462 default selected
link products. An explicit migrated catalog and ordered File provider reject
missing/ambiguous/surplus products; parser metadata validation passes all four
ZSTDIO/NFS_ROOT selections. Bazel host rejection tests pass separately from
kernel artifact profiles. See KERNEL-AGGREGATE-GUARD-QUALIFICATION.md. The final
linker must consume the validation marker and ordered Files; full kernel link,
post-processing/install and wider system gates remain unfinished.

## Complete amd64 GENERIC native link milestone (2026-11-02)

The complete 2,462-product native kernel compiles/links through the maintained
frontend; CTF merge and runtime/debug split also pass. Actual link order/flags
match Make, recorded inputs are hash-bound, all allocated sections survive
postprocessing, and original Make postprocessing of identical native inputs is
byte-exact. The initial missing socket audit-header dependency was fixed locally.
See FULL-KERNEL-LINK-QUALIFICATION.md. This is not complete independently compiled
Make-kernel parity, installation or boot/runtime acceptance. Those gates plus
modules, other configurations/architectures, world, packages, bootstrap and
performance remain open; Make stays production/default.

## LLDB CLI milestone (2026-11-02)

The original one/five-source programs, two generated option headers, native
shared dependency closure, safe loader/pre-initialization tests and ten
installation records now pass. Direct compiler objects preserve original Make
link order. Every allocated object/program section matches independent explicit
filename-policy Make controls; original baselines/rejected archive links remain.
LLDB-CLI-QUALIFICATION.md records actual input, link, SDK and scoped cache proof.
Next: family aggregate and inherited MK_LLDB selection/package ownership;
debugger execution, upstream suite, cross/static variants and full world stay open.

## LLDB family milestone (2026-11-02)

The native debugger subset now composes three independently qualified components
with original order and separate installation contexts: fifteen records, three
safe wrappers and exact prior immutable payload hashes. Existing LLDB/tests
selection supports a zero-payload disabled family and rejects an explicitly
requested all-incompatible suite. Four original Make parent controls pass; fresh
recursive world inventory observes 2,128 directories, not compilation coverage.
See LLDB-FAMILY-QUALIFICATION.md. Next: reconcile actual selected product/action
and aggregate coverage. sbin/mount_virtiofs already has a native graph and
October 26 component evidence; later recursive selection is not a missing-native
proof. Full world/bootstrap/package ownership and debugger execution remain open.


### printenv selected original test/package gap (2026-11-02)

The selected printenv program/test graph now preserves actual Make PIC/warning
policy, all four original cases and separate utility/debug/test installation
contexts. Native default and TESTS-off products match eight/five Make records;
object/program allocated sections and all 73 consumed dependency occurrences
agree. Legal non-shell environment names exposed an original shell-variable
oracle defect, corrected by a complete-byte comparison to native env with no
filtering. A missing ATF tr dependency was caught after green XML and fixed
before qualification. See PRINTENV-QUALIFICATION.md. This bounded completion
adds no full-world, cross-architecture or final-package completion claim.

## I2C/SMBus module milestone (2026-11-02)

Qualified 39 selected amd64 GENERIC leaves spanning controllers, buses, devices
and muxes: 51 actual compiles/5,089 original consumed prerequisite occurrences,
39 ordered initial links and 117 plain/CTF-debug installation records. All plain
artifacts are exact respective Make references: 37 untouched originals plus two
independent canonical-filename controls whose four actual recipes differ only
by one explicit map and whose 382 prerequisites agree. Existing SDT sections
and relocations are exact. No runtime/Make/helper/CLI policy changed. See
I2C-MODULES-QUALIFICATION.md. Discovery coverage is 357/729 local BUILD leaves,
not a qualified percentage; 372 still lack local BUILD declarations in this
selection. Remaining configurations, architectures, actual bus/controller/input/
RTC/sensor behavior, aggregate world/pkgbase/bootstrap, VM and performance gates
remain open. The six existing family provider regressions passing each profile
are regression evidence, not I2C hardware execution or strict-loader proof.

## Sound module milestone (2026-11-02)

Closed the ten remaining local-BUILD gaps in the reviewed selected amd64 sound
subtree: forty actual compiler actions, 6,239 original consumed prerequisites,
ten ordered initial links and thirty plain/CTF-debug installation records pass.
All ten plain modules match untouched Make byte for byte; CTF/debug and compiled
PCM SDT sections/relocations match the stated contracts. Seven KOBJ and three
existing AWK header producers remain native and declared. An initial duplicate
computed-name header view was rejected before compilation, then corrected to
reuse the existing providers. See SOUND-MODULES-QUALIFICATION.md.

Discovery now observes 367/729 local BUILD leaves, with 362 still missing in this
selection. This count neither qualifies every existing declaration nor replaces
full-world/cross-architecture/module/pkgbase/bootstrap/publication gates. Audio
playback/capture/MIDI/mixer, hotplug/error paths, live probes, hardware and
CPU/memory/disk I/O/disk-use/cache/sandbox performance remain open. Make stays
production/default; BIP remains excluded.


### Internal rescue replacements (2026-11-02)

Native librescue now preserves seven regular/seven PIE own objects, both internal
archive products, Make's no-install contract and direct-object consumer interface.
Two independent configurations match object payloads/relocations/symbols and
1,694 consumed dependency occurrences. This closes the bounded internal library
product gap, not full rescue: crunchgen generation, all crunched application
variants, static linking, aliases/scripts/install and safe/guest runtime gates
remain. HESIOD-enabled SDK/header preparation is an explicit configuration gate.
See LIBRESCUE-QUALIFICATION.md.

## USB cohort milestone and genuine Make fix (2026-11-02)

Qualified 63 remaining selected amd64 USB leaves: 99 ordinary compile contexts
and four firmware compile contexts, 13,412 consumed prerequisite occurrences,
63 ordered initial links and 189 plain/CTF-debug file-install records pass. All
plain files match respective Make references: 62 untouched originals plus fresh
corrected i2ctinyusb. Its real duplicated SRCS/OBJS produced duplicate module
registration/sysinit; original compiler argv is unchanged and corrected Make/
native each have one entry. Old artifacts/failures are retained.

Firmware blobs and registration C are produced by declared native uudecode/AWK
actions; original firmw.S uses explicit cc_library additional_compiler_inputs
for .incbin payloads, then the existing object-alias rule preserves .fwo names.
Twenty previous sound artifacts remain byte-identical with the helper default.
Actual successful partial-run compilers reused by the accepted retry are bound
from original logs, not invented cache spawns. See
USB-REMAINING-MODULES-QUALIFICATION.md for exact evidence and retained failures.

Discovery now observes 430/729 local BUILD leaves, leaving 299 missing in this
selection. Existing BUILD presence is not a qualified percentage. USB device/
controller/WLAN/storage/input/video/serial/gadget and firmware runtime, live
probes/audit, cross/KERNCONF/FDT and aggregate world/pkgbase/bootstrap/publication
gates remain open, along with CPU/memory/disk I/O/disk-use/cache/sandbox checks.
Make stays production/default; BIP remains excluded.

## Remaining firmware reference checkpoint (2026-11-02)

Read-only source queries now cover all 299 remaining selected amd64 leaves.
Selection by actual nonempty FIRMWS identifies 38 modules, 59 images and 111
object contexts. This includes LiquidIO's fourteen real driver C objects as well
as its firmware registration/embedding; it must not be reduced to a data-only
module. All 76 original Make build/install controls pass, sequentially with
sixteen jobs per control. No host installation occurs.

`/usr/obj/usr/src/bazel-remaining-module-source-facts-r1-20261102` retains the
complete missing-leaf query. `bazel-firmware-module-make-references-r1-20261102`
under the same object root contains original controls;
`bazel-firmware-module-source-facts-r1-20261102` binds actual compiler/producer
recipes and payload hashes. Twenty-four inputs are uudecoded; thirty-five are
raw, including two Otus copies whose original source and copied bytes agree.
Original FIRMWS specifications preserve omitted, dotted and hexadecimal version
spellings and image order. No filename/family-based producer guesses are needed.

Next: implement and qualify native composition of decode/raw inputs, original
AWK registration, declared .incbin inputs, original ordered driver objects and
module/debug/install stages. A native macro draft is retained as design material,
not implemented or qualified production code. Required gates are real per-context
compiler/input and link audits, payload/generated-source equality, plain and
CTF/debug/install parity, prior firmware regressions and honest configuration/
runtime limits. These 38 modules still count as missing native declarations;
coverage remains 430/729 local BUILD leaves. Hardware/firmware-loading, complete
world/cross/pkgbase/bootstrap/publication and performance gates remain open.


### Rescue tool and dispatcher generation (2026-11-02)

The original native crunchgen, declared cwd/runtime and explicit object metadata
now produce the default 103-program/39-alias dispatcher with no Make invocation.
C bytes, three normal compiler objects, program ABI/allocated payloads, actual
input/link chains and five tool installation records match original controls;
ten native wrapper targets pass (nine analysis negatives and six runtime methods
inside one fixture wrapper). See RESCUE-DISPATCH-QUALIFICATION.md. The 592 original
application object names remain descriptors: actual RESCUE/static/NOSSP source
variants, generated stubs, crunchide transforms, complete static link/aliases/
script installation and runtime/package matrices remain required. No full rescue
or complete option/architecture/world coverage claim is added.


### Remaining FIRMWS module qualification (2026-11-02)

The preceding reference-only checkpoint is superseded by the implemented and
qualified native firmware composition. All 38 remaining selected FIRMWS modules
now declare their 59 image inputs and original ordered registration/driver links.
All 111 compiler contexts and 38 links pass actual input reviews. Plain modules
match 37 untouched Make references and one independently checked LiquidIO
filename-policy control; CTF/debug payload and all 114 installation records match.
Four prior USB firmware artifacts remain byte-identical. The six existing provider
tests pass in each profile; these are not firmware-loading or hardware tests.
See FIRMWARE-MODULES-QUALIFICATION.md for evidence and configuration limits.

Local BUILD presence is now 468/729 selected amd64 leaves (261 missing), not a
whole-system qualification percentage. Complete rescue application/static linking,
remaining module families, ARM64/RISC-V, aggregate pkgbase/hardware/bootstrap,
publication, VM/runtime and CPU/memory/disk I/O/cache/sandbox gates remain open.
Add maintained automatic parameter-file capture before later build profiles:
current proof preserves exact hash-verified recovered parameter bytes, not an
implemented frontend capture guarantee. Make remains production/default; BIP is
excluded. Existing format-5 build-bsd/backend inputs cover this composition; no
CLI, signing, staging or publication policy change is needed for this cohort.

### Rescue direct-stub checkpoint (November 2)

Original crunchgen direct output and declared native entry-stub groups are
qualified: 103 files equal actual original Make echo recipes, with unchanged
default dispatcher/cache/Makefile bytes and fresh tool/install checks. See
[direct-stub evidence](CRUNCHGEN-DIRECT-STUBS-QUALIFICATION.md). Next production
gates are genuine per-application RESCUE objects, original crunchide/relocatable
transforms, complete static link and rescue installation/package/runtime.
Generating 103 stubs does not count those applications as compiled.


### ISP and Myricom module qualification (2026-11-02)

Eleven additional selected amd64 leaves now use native C/module composition:
six ISP firmware selections, four Myricom firmware modules and its network driver.
All eleven plain modules are byte-identical to untouched Make outputs; CTF/debug,
33 installation records, eleven actual compiler contexts/1,008 prerequisites and
eleven initial links pass. Nine firmware array headers are declared inputs.
Original runtime C and Makefiles are unchanged. See
CARRAY-FIRMWARE-MODULES-QUALIFICATION.md for evidence and qualification limits.
Local BUILD presence is 479/729 selected leaves (250 missing), not a qualified
whole-system percentage. Six existing provider tests pass in each profile; no
firmware loading/hardware claim. Cross-architecture, complete world/rescue/pkgbase,
bootstrap/publication, VM and performance/cache/sandbox gates remain open.
Existing build-bsd format-5/backend helpers cover this composition without a new
CLI, helper extension, signing/staging or publication policy. Make remains the
production/default build. BIP stays excluded.


### libalias and NTB module qualification (2026-11-02)

Fifteen more selected amd64 leaves use native C/KOBJ and module helpers: eight
libalias core/extensions and seven NTB core/hardware/transport/network/tool modules.
All fifteen plain binaries are byte-identical to untouched Make references;
CTF/debug, 45 installation records, 21 actual compilers/2,793 prerequisites and
fifteen initial links pass. Original export policies are retained, including
libalias/ntb/ntb_transport EXPORT_SYMS=YES. No runtime C or original Makefile change.
See ALIAS-NTB-MODULES-QUALIFICATION.md for scoped evidence and remaining gates.
Local BUILD presence is 494/729 selected amd64 leaves (235 missing), not a
whole-system qualification percentage. Six existing provider tests pass per
profile; protocol behavior, module loading, hardware, KTR variants and live
tracing remain open. Whole world/rescue/cross/pkgbase/hardware/bootstrap,
publication, VM/runtime and CPU/memory/disk I/O/cache/sandbox qualification remain
required. Existing build-bsd C/format-5/backend helpers cover this composition
without new CLI, helper extension, signing/staging or publication requirements.
Make remains production/default. BIP stays excluded.

### Real rescue object checkpoint (November 2)

Three source-owned RESCUE application variants (cat/echo/head) plus crunchide's
three tool objects pass original Make allocated/relocation/symbol and actual
compiler policy/input checks. Ordinary tool installation metadata also passes.
[Evidence](RESCUE-CORE-OBJECTS-QUALIFICATION.md) explicitly keeps successful
stub-plus-application ld-r/crunchide transformation, static dispatcher/runtime
and complete rescue installation/package coverage open. Raw Clang input rejection
is preserved; it is not a successful transformation or reason to relax the tool.


### FireWire and Hyper-V module qualification (2026-11-02)

Twelve additional selected amd64 leaves now use native C/assembly/KOBJ module
stages. All twelve plain binaries match untouched Make byte-for-byte; exact CTF
bytes, debug CRCs and 36 installation records pass. Thirty-eight original executed
compiler contexts/4,853 prerequisites and twelve actual ordered links are bound;
final CTF-only results reuse prior compilations, with no invented cached spawns.
The original VMBus custom assembly recipe skips ctfconvert. A per-group boolean
convert_ctf defaults true and participates in the global kernel setting; false
preserves that recipe and cannot override global disable. All 22 prior ISP/Myricom
module artifacts remain byte-identical. The frontend manual records the exception.

Shared FireWire source/header ownership moved into its package with the old root
header target retained as a native alias. fwcontrol/dconschat are built separately
with the userland SDK: executable sections match except debug links, manifests/
manuals are unchanged and debug CRCs validate. Archives/DWARF differ; full byte
identity is not claimed. Rejected analysis/mixed-toolchain/CTF/archive-equality
attempts are retained with diagnosis. See FIREWIRE-HYPERV-MODULES-QUALIFICATION.md.

Local BUILD presence is 506/729 selected amd64 leaves (223 missing), not a whole
system qualification percentage. Original export policies are retained. Six
existing provider tests pass per module profile; hardware/loading/live probes,
other options/architectures and complete world/rescue/pkgbase/hardware/bootstrap,
publication, VM/runtime and CPU/memory/disk I/O/cache/sandbox gates remain open.
During ARM qualification, review/fix the existing Hyper-V Make branch that uses
SRC instead of SRCS for its architecture sources; current evidence is amd64 only.
Existing build-bsd C/format-5/backend inputs cover the composition; no new CLI,
signing/security, staging or publication contract. Make remains production/
default; BIP is excluded. Automatic parameter capture remains a frontend gate.


### NVMe-oF, TCP and kernel-test modules (2026-11-02)

Thirteen more selected amd64 leaves use native C/module stages: four NVMe-oF,
four TCP and five ktest modules. Twenty-nine compiler contexts/4,803 consumed
prerequisites and thirteen actual ordered links pass. All thirteen plain modules
match respective Make references byte-for-byte: eleven untouched originals and
two independently checked BBR/RACK filename-policy controls. Sixteen original/
control recipes and 3,218 prerequisites differ only by one source-path-derived
macro map. Original noncanonical-path differences are retained; no final artifact
normalization or production source/compiler-policy change. CTF bytes/debug CRCs
and 39 file installation records pass, including original package=tests for the
five test modules and package=kernel for the other eight. Export policy retained.

Static registration checks preserve 34 compiled ktest cases, including twenty
enabled HPTS functional cases, not merely its disabled warning stub. None is
claimed executed. The example Python wrapper skips two intentional failures;
matching-guest VM qualification must report skips and explicitly test failure
reporting. Six existing provider test targets pass per build profile; these do
not demonstrate protocol/storage/kernel-test runtime behavior. See
STORAGE-TCP-KTEST-MODULES-QUALIFICATION.md for bounded evidence and open gates.

Local BUILD presence is 519/729 selected amd64 leaves (210 missing), not a whole
system qualification percentage. ARM64/RISC-V, alternate KERNCONF/options, actual
loading/ktest/NVMe-oF/TCP/live-probe behavior, complete world/rescue/pkgbase/hardware/
bootstrap/publication, VM and CPU/memory/disk I/O/cache/sandbox gates remain open.
Existing build-bsd C/format-5/backend/helper inputs already carry this composition
and package tags; no new CLI/manual behavior, signing/security, staging or
publication requirements. Make remains production/default; BIP is excluded.


### IPMI, storage, one-wire, PWM and VMware modules (2026-11-02)

Fifteen more selected amd64 leaves now use native C/KOBJ module stages: IPMI and
its Linux compatibility module; MFI core/Linux/CAM; MRSAS core/Linux; one-wire
bus/temperature/GPIO controller; PWM bus/controller; VMware PVSCSI/VMCI/VMXNET3.
Forty-four compiler contexts/5,098 consumed prerequisites and fifteen original
ordered links pass. All fifteen plain modules match untouched Make byte-for-byte;
CTF bytes/debug CRCs and 45 file installation records pass. Original export and
package=kernel policies are retained. No runtime C, Makefile or common helper
change. Three Linux modules reuse the existing declared machine/../linux header
view; only dependency edges and narrow visibility extend. Rejected initial
missing-view compilation is retained; failed spawns are excluded from evidence.
See DEVICE-FAMILIES-MODULES-QUALIFICATION.md for exact scope and retained proofs.

Local BUILD presence is 534/729 selected amd64 leaves (195 missing), not a whole
system qualification percentage. Six existing provider test targets pass in each
profile; they do not establish device/Linux-ioctl/hardware behavior. FDT-enabled
PWM and other option/architecture variants, actual loading, live probes, complete
world/rescue/pkgbase/hardware/bootstrap/publication, VM and CPU/memory/disk I/O/
cache/sandbox qualification remain open. Existing build-bsd C/format-5/backend
inputs carry these relationships; no new CLI/manual behavior, signing/security,
staging or publication requirement. Make stays production/default; BIP excluded.

### Rescue combined-object milestone (November 2, 2026)

Three actual application objects now pass the original stub-first relocatable
link and basename-sensitive crunchide pipeline, with 6 actual compiler actions,
135 consumed inputs, 3 links/transforms and 12 accepted suite members (2 fresh
negative tests; 10 cached results). [Evidence](RESCUE-COMBINED-OBJECTS-QUALIFICATION.md)
retains exact runtime object proof and identical-input whole-file controls;
DWARF path bytes differ explicitly. Next: real bounded static rescue dispatcher
and safe application execution, then all selected applications/static libraries,
full rescue install/package and option/architecture coverage.

### Bounded static rescue execution (November 2, 2026)

[Real cat/echo/head subset](RESCUE-CORE-PROGRAM-QUALIFICATION.md): native main,
three hidden objects, libutil/libc/compiler_rt and startup link successfully;
whole main/binary bytes equal original generated Make using those same native
library/startup inputs. Ten actual runtime methods pass; two consumed-input
inventories total86 occurrences. This does not close full world/library or rescue
install/package parity. Next correct the existing libutil cc_library's missing
Make standard/pipe/fno-common/warning policy, qualify its archive/DSO and repeat
core tests, then expand the complete rescue application/static-library closure.

### Libutil compiler policy and SDK refresh (November 2, 2026)

[Qualified correction](LIBUTIL-COMPILE-POLICY-QUALIFICATION.md): 68 original Make
normal/PIC recipes, 3,778 original and actual native consumed-input occurrences,
all compiler-object allocated sections/nondebug relocations, 72 unchanged
representative default actions and keys, four PIC fixture methods and eleven
real bounded rescue methods. A fresh maintained SDK explicitly snapshots the
new default-disabled small-PIC feature; no historical receipt was rebound.
Before/after native DSO/archive runtime sections are unchanged and rescue ELF
bytes exact. Remaining library work: Make member order (including pw_scan),
section-archive versus separate provider/DOF and final DSO payload/installed-test
parity. Then expand real rescue applications, static libraries, selected options,
complete installation/pkgbase and full world/bootstrap; this bounded correction
does not close those gates.

### Real eight-program rescue integration (November 2, 2026)

[Evidence](RESCUE-EIGHT-PROGRAM-QUALIFICATION.md): five more original RESCUE
variants add 11 application objects and a genuine no-header expr Yacc producer;
current 17 compiler actions have 691 consumed occurrences per side. One generated C
pair differs only 38 exact #line filename fields. Eight original stub/link/hide
pipelines match runtime sections/relocations/symbols, with one explicit pwd
filename control; 21 actual runtime methods pass. An identical-input original
Make control reproduces main, eight stubs/hidden objects and the complete static ELF.
Next expand the remaining selected applications/static libraries and preserve
actual generator, object order, per-source policy, aliases and installation
contracts. All 103 programs, full independent world/library parity, rescue install/
pkgbase, options/architectures/bootstrap/hardware/publication remain open;
libutil's archive/provider/final DSO and installed-test gates remain separate.

### Real fourteen-program rescue integration (November 2, 2026)

[Qualification](RESCUE-FOURTEEN-PROGRAM-QUALIFICATION.md) adds six original RESCUE
variants, including five actual DTrace header/provider transformations. Six raw
and transformed object contracts, 314 consumed input pairs, complete DOF schemas/
relocated sites/encoding, actual ordered links and 31 runtime methods pass.
Original generated Make on identical accepted native objects/archives/startup
reproduces the entire static ELF. Continue remaining actual rescue applications
and library dependencies, selected options and original standalone tests, then
complete rescue install/pkgbase and world/bootstrap. The full 103-program graph
and independent full-library/installed-test parity are not closed by this subset.

### Module inventory early source context (November 2, 2026)

[Context and checks](MODULE-INVENTORY-CONTEXT.md): recursive audits now supply
normal kernel SYSDIR and MODULE_TIED inputs before leaf parsing. The maintained
Bazel test passes all 11 Python methods, including real Make under a custom
source root. Refreshed selections remain amd64 729 / ARM64 627 / RISC-V64 553;
amd64 local BUILD presence is 628, leaving 101 selected leaves without one.
The pending network cohort's first six source-lookup failures are retained;
repeat original controls with the actual kernel source context before native
conversion. No accepted native artifacts or full-system gates are inferred from
selection, and no build-bsd CLI/signing/publication change is required.

### Network/routing/entropy modules (November 2, 2026)

[Qualification](NETWORK-SERVICES-MODULES-QUALIFICATION.md): 37 more selected amd64
leaves, 188 actual compiler contexts and exactly 32,362 consumed original/native
dependency occurrences per plain/CTF profile; actual ordered parameters retained.
All 37 plain ELF files match untouched Make bytes; all CTF/debug payloads and
CTF data match, with valid debug CRCs and 111 original installation records.
ENA's physical include namespace is explicitly declared; netlink's nested CTF
sort paths are an optional validated native rule input. Four actual-rule analysis
negatives and the existing CTF executable regression pass; 108 default-path
outputs are unchanged. All 22 compiled SDT/DTrace module sections are preserved.
Local BUILD presence is now 665/729, leaving 64; it does not close architecture,
full kernel/world/rescue/library/pkgbase, bootstrap/runtime or performance gates.
No build-bsd CLI, signing or publication policy change; Make remains default.

### Real nineteen-program rescue integration (November 2, 2026)

[Qualification](RESCUE-NINETEEN-PROGRAM-QUALIFICATION.md): five actual traced
file-operation variants add six C objects/398 consumed pairs and unlink. Two
original one-map filename controls, six rewritten objects, five complete DOF/
relocated-site comparisons, actual link order and 43 runtime methods pass.
Original generated Make with identical accepted inputs reproduces the entire
static ELF. Initial wrong cp -n expected status is retained; test-only correction
matches source and leaves ELF bytes unchanged. Next close the genuine original
static-library/provider/order gate or first new library dependency, remaining
applications, original test suites and installed rescue/mv helper/pkgbase paths;
full world/bootstrap/publication/resource gates remain open.

### RDMA/InfiniBand/Mellanox modules (November 2, 2026)

[Qualification](RDMA-MODULES-QUALIFICATION.md): fourteen more selected amd64 leaves,
206 actual uncached compiler contexts and exactly 83,230 original/native consumed
dependency occurrences per plain/CTF profile. All actual ordered link parameters
are captured. Thirteen plain ELFs match untouched original Make files; iSER
matches an independent one-map original filename control (ten exact compiler
vector comparisons, ordinary originals retained). All CTF/debug data and CRCs
and 42 installation records match corresponding controls. Original iSER header
precedence is preserved by ordered provider composition; default helper vectors
and 39 other-module outputs remain unchanged. Four compiled SDT/DTrace modules
retain exact sections/relocations. Local BUILD presence is 679/729 (50 remain),
not full-system completion. No frontend CLI/signing/publication policy change;
Make remains default and cross-target/full world/kernel/packages/runtime and
performance gates remain open.

### Chelsio modules and complete option coverage (November 2, 2026)

[Qualification](CHELSIO-MODULES-QUALIFICATION.md): eleven selected amd64 leaves,
50 compiler contexts and exactly 11,730 original/native consumed occurrences per
plain/CTF profile. All eleven plain ELFs are whole-file exact untouched Make;
CTF/debug payloads/CRCs and 33 install records match, with actual ordered link
parameter captures. Four compiled SDT/DTrace modules retain exact sections.
A supplementary option observer's directory/KMOD and host-helper coverage bug
was found and corrected: mandatory object-driven coverage now agrees with full
compiler inputs (Chelsio127, network365, RDMA554 option occurrences). No native
artifact/input result was changed; correction diagnostics retain old behavior.
BUILD presence is 690/729 (39 remain), not full qualification. No helper/runtime/
Make/frontend/signing/publication policy change; full architecture/world/kernel/
packages/bootstrap/runtime/performance gates remain open and Make stays default.

### Independent libutil static archive gate (November 2, 2026)

[Qualification](LIBUTIL-STATIC-ARCHIVE-QUALIFICATION.md): fresh original Make
35-member archive/order/provider contract, 34 exact C allocated payloads and
35 exact nondebug relocation sections; all nine DOF sections and actual probe
site accounted for with independently verified path keys. Actual archive action
order and all member hashes bound; eight maintained contract methods pass.
Default DSO/rescue and explicit experimental archive/DSO regression bytes match.
Keep default CcInfo anchored-provider static-consumer semantics as the next
independent gate; full DSO/installed tests, untraced modes, full rescue/packages
and runtime/performance remain open. Existing format-5 workflow only; Make default.

### Default libutil static-consumer gate (November 2, 2026)

[Qualification](LIBUTIL-STATIC-CONSUMER-QUALIFICATION.md): original missing-provider
and native over-extraction defects corrected with the existing retained-anchor
mechanism and lazy provider import. Two complete ordered extraction graphs match
corrected original Make. All 68 actual normal/PIC compilers, 3,778 consumed
occurrences, 35 component members and actual anchor/archive producers are bound;
56 actual test methods pass without credential changes. Shared ELF metadata
passes; full DSO payload/install, arbitrary CcInfo ordering and DTrace host
provenance/cache hermeticity remain open. Make remains default.

### libutil DSO allocated-payload gate (November 2, 2026)

[Qualification](LIBUTIL-DSO-PAYLOAD-QUALIFICATION.md): actual link controls isolate
misordered pw_scan and missing original local-symbol discard. Two native
declarations repair these; corrected allocated sections match original Make
except fully accounted DOF path encoding and verified actual linked sites.
Each mode preserves 68 actual compiler controls; unaffected archive/consumers/
rescue remain byte-identical. Default 56 and experimental 43 methods are cached
accepted results. Whole/debug/install/original ATF, arbitrary CcInfo and full
world/package/runtime/provenance gates remain open; Make remains default.

### Compatibility/storage/tracing modules (November 2, 2026)

[Qualification](COMPAT-SERVICES-MODULES-QUALIFICATION.md): eighteen more amd64
leaves, 130 actual compiler contexts and 26,206 exact consumed occurrences per
profile; actual ordered links, whole-file untouched-Make plain parity and 54
installation records pass. Seven compiled SDT/DTrace modules retain exact
sections/relocations. Explicit existing architecture views fix eight original
Linux-header consumers; attempts and fresh SDK provenance are retained.
BUILD presence is 708/729, leaving 21, not full qualification. Complete debug,
architecture/world/kernel/packages/bootstrap/runtime/performance gates remain
open; existing build-bsd format-5 workflow applies and Make stays default.

### Wireless/crypto/EFI/SGX runtime-artifact qualification

[Work record](FINAL-DRIVERS-MODULES-WORK.md): all 42 original controls for the last
21 selected amd64 leaves pass. Eighteen native declarations pass both profiles:
455 compiler contexts and 159,574 consumed prerequisite occurrences per profile,
complete original object identities/order, installation metadata and runtime
ELF/CTF comparisons. All eighteen plain modules are byte-identical. Both RTWN
microcode settings additionally pass 101-context original/native reviews per
profile and actually change runtime code. Local declaration presence is 726/729;
Linux64/OpenSSL/VMM still lack native declarations. Separate DWARF/source lookup,
nondefault configurations and full world/kernel/cross-target/pkgbase/bootstrap/
runtime/cache/performance gates remain open. No C/shared-rule/frontend-C changes
are required: the maintained typed setting interface carries the new RTWN flag,
and its producer/manual are updated together. Make stays production/default.

### OpenSSL crypto module runtime-artifact qualification

[Qualification](OSSL-MODULE-QUALIFICATION.md): nineteen actual compiler contexts
(ten C, nine checked-in assembly), 821 consumed occurrences and nineteen option
headers pass per profile. Plain whole-file equality, CTF/runtime sections, debug
CRCs, complete ordered object identities and installation manifests pass against
original Make. Local declaration presence is 727/729; Linux64 and VMM remain.
Separate DWARF, runtime crypto/dispatch, alternative settings, cross targets and
full-system/cache/performance gates remain open. Existing native helpers and
normal format-5 frontend inputs suffice; no new frontend/manual policy is added.

### VMM native module and layout-producer qualification

[Qualification](VMM-MODULE-QUALIFICATION.md): both profiles pass 185 actual module
compiler contexts, 15,693 consumed occurrences, 204 option-header occurrences,
complete original object order, installation and runtime ELF/CTF comparisons.
The full plain module is byte-identical. Two actual layout compilers/extractors
per profile preserve original common-symbol policy, 227 consumed occurrences and
full generated-header equality; helper objects are excluded from module linkage.
The bhyve native consumer build and actual affected source/header/link inputs
pass after physical-package label relocation. Local declaration presence is
728/729; Linux64 remains. Separate DWARF, live VM execution, alternative settings,
cross targets and full-system/pkgbase/bootstrap/cache/performance gates remain
open. Existing rules/format-5 frontend suffice; no new C/helper/manual option.

### Linux64 native generated-input and module qualification

[Qualification](LINUX64-MODULE-QUALIFICATION.md): both profiles pass 34 actual
module compilers, 5,004 consumed occurrences and forty selected kernel options.
Three native helpers per profile preserve original flags and 140 consumed
occurrences. The layout header, five syscall outputs and complete 5,392-byte
VDSO are exact original payloads; actual compiler/extractor/generator/link/image/
incbin dependencies are independently bound. Plain full-file module equality,
CTF/runtime/debug CRCs, complete ordered links and installation pass. The initial
missing architecture-header declaration and observer -Wa classification failures
are retained and corrected. Existing format-5/backend workflow and updated manual
carry the graph without frontend-C inputs; no C/Make source changes are added.

All 729 selected amd64 directories have BUILD files, but inspection of the
actual top-level declarations finds 690 generic and 38 firmware module producers:
728/729. ZFS has headers and separate built-in kernel rules, with no loadable
module producer. Implement and qualify that missing module; directory presence
must not stand in for module-target coverage.

The [Linux64 original/changed/restored check](LINUX64-INCREMENTAL-QUALIFICATION.md)
now passes actual generated-image/embedding invalidation and exact original-byte
restoration in a clean isolated object-root checkout. Next refresh the complete
current GENERIC kernel and aggregate module build, and continue original userland
install/test/package closure. Cross-target world/kernel/modules, other options,
complete pkgbase/hardware/publication, bootstrap, source/debug lookup, sandboxing,
VM/runtime and measured CPU/memory/disk/cache gates remain part of the full
objective. Make stays production/default; BIP is excluded. Individual profile
parity is not full completion.

## libutil original test/install closure (2026-11-03)

The [bounded original test/install gate](LIBUTIL-TEST-INSTALLATION-QUALIFICATION.md)
now supplies all twelve owning Make-selected programs and their 25 installed
test/debug/Kyuafile payloads plus five tagged directories. Sixteen compiler
contexts/740 consumed pairs and all twelve final allocated ELF payloads match
the separately audited original filename-policy control. All 31 native test
rules pass; the zero-status wrong-value TAP negative is rejected. TESTS-off
removes exactly that subtree and preserves 124 runtime/dev records and payloads.
The safe fork-failure correction preserves EAGAIN and prevents kill(-1); the
existing Kyua environment attribute now reaches constructors while preserving
unmentioned inherited environment. Make remains production/default. Continue
actual world install/package closure; full independent library/debug/source
lookup, other options/architectures and the broad completion gates above remain.

## ZFS loadable module closure (2026-11-03)

The [native ZFS module](ZFS-MODULE-QUALIFICATION.md) passes two normal build-bsd
profiles against fresh original Make: 261 actual compiler contexts, 68,785
consumed input occurrences and 261 selected options each, plus complete ordered
compiler/CTF/alias-to-link identities. Whole-file plain equality, CTF/runtime
sections, split-debug CRCs and all installation records pass. The unchanged
sources preserve all eight compiled SDT sections/relocations. Original module
policy is separate from built-in kernel objects; no C/Make/shared-rule/frontend-C
change is introduced. The source declaration inventory is now 729/729 amd64
leaves (691 generic, 38 firmware). This supersedes the prior ZFS missing-producer
checkpoint, not the outstanding full-build gates.

Next refresh the current full GENERIC kernel and aggregate selected module
build; continue the missing stand boot-program/library world closure in parallel
with userland installation/pkgbase work. ARM64/RISC-V/configuration, world/rescue,
bootstrap, hardware/combined publication, debugger source lookup, sandboxing,
VM/runtime and measured CPU/memory/disk/cache qualification remain required.
Make stays production/default; BIP stays excluded.

## First native legacy boot products (2026-11-03)

Fresh maintained world recursion retains 2,128 selected directories, including
52 in stand. The [first seven real products](LEGACY-BOOT-QUALIFICATION.md) now
have source-owned native compile/link/install composition. Seven complete ELF32
objects and flat images are exact original bytes; all actual flags, ten consumed
pairs and six original installation records match. Seven host unittest methods
pass without executing an image. The original expression is preserved through
response-file quoting; successful cached witnesses remain explicitly bound to
the rejected first profile's individual successful actions. No global helper/
toolchain/SDK policy changes. Continue the remaining BIOS/EFI/kboot/library and
full world/rescue/pkgbase graph, cross/options/bootstrap, boot/runtime and broad
completion gates above; directory presence or raw equality is not boot/security
qualification. Make stays production/default.

## Current full GENERIC compiled parity refresh (2026-11-03)

The [new current-source full build](CURRENT-KERNEL-REFRESH-QUALIFICATION.md) passes
normal build-bsd and fresh controlled original Make. All 2,462 object code,
allocated metadata/payloads and CTF bytes match. Both full/runtime kernels pass
56 allocated contracts (55 exact payloads plus validated build-ID note), 96,147
loader symbols and merged CTF; native debug positive/negative checks and original
CRC pass. Before/after source bindings and actual original dependency coverage
are retained, including explicit earlier helper-source hashes supplementing the
initial failed audit. External Make prerequisites, standalone DWARF/source
lookup and general cache/toolchain hermeticity are not declared complete.

Next aggregate all 729 amd64 module producers and installation/pkgbase closure;
continue actual stand/boot2, world/rescue and cross-architecture/configuration
coverage. Bootstrap, hardware/combined publication, sandboxing, VM/runtime and
controlled CPU/memory/disk/cache qualification remain required. Make stays
production/default; BIP stays excluded. This is current compiled parity, not a
booted installed system or full-goal completion.

## Complete selected amd64 aggregate (2026-11-03)

The [combined request](AMD64-AGGREGATE-MODULES-QUALIFICATION.md) passes the current
full kernel and all 729 selected amd64 modules with CTF/debug: 2,191 targets and
3,649 captured output records. All module ELF/debuglink CRCs and producer/install
payload bindings pass; all component destinations are collision-free. The real
mac_ntpd compile failure is fixed by reusing its existing precise capability
header provider; failed build and inspection records remain retained. Default
component paths and package-pair consistency are not full original installation
or pkgbase parity. Full aggregate installation/package closure remains next.

Continue actual userland library/program/stand/rescue closure and ARM64/RISC-V
native architecture coverage. The last maintained cross selections contain 627
ARM64 and 553 RISC-V leaves; current literal declaration inspection recognizes
216 and 214 respectively, not successful-build counts. Cross firmware/driver and
architecture-specific generated inputs remain real work. Bootstrap, hardware/
publication, debugger source lookup, sandboxing, VM/runtime and controlled CPU/
memory/disk I/O/cache qualification remain required. Make stays production/default;
BIP remains excluded. This checkpoint supersedes earlier aggregate-build TODOs.

### Boot2 producer closure and directory installation checkpoint (2026-11-03)

Added the actual selected boot/boot1/boot2 chain: seven i386 compile objects,
ordered internal BTX crt0, original nm/AWK header generation, selected linker/
objcopy and source-built btxld, size checking/padding/concatenation. Corrected the
existing btxld target's missing original policy through normal source-owned
objects/direct program linkage, preserving its public/install/archive labels.
Eleven actual compiler contexts bind 310 consumed pairs; five ordered links and
seven complete generated outputs match original policy/bytes. Nine original
install records preserve file/directory ownership and distinct package tags;
the missing original /boot record is represented through first-class
bsd_install_directory using the existing provider/manifest/archive protocol.
Six host artifact methods pass and previous legacy archive bytes are unchanged.
Retained source/recipe/cached-action proofs, first rejected tool-policy and
missing-directory comparisons, and explicit separate DWARF/source lookup/boot
limits are in [BOOT2-QUALIFICATION.md](BOOT2-QUALIFICATION.md). No final package,
publication or runtime/boot qualification follows. Continue portable library/
program closure and proper ARM64/RISC-V target/execution SDK support; this
architecture-specific BIOS cohort is not cross-world coverage.

## ARM64/RISC-V routing module checkpoint (2026-11-03)

The [four routing/diagnostic modules](CROSS-ROUTING-MODULES-QUALIFICATION.md)
dummymbuf, fib_dxr and dpdk_lpm4/6 now pass both architectures and plain/CTF-debug
settings: eight whole-file plain matches, eight CTF/runtime/debuglink comparisons,
24 original install records, 24 actual module compilers/3,056 consumed pairs and
32 ordered links. The first real missing ARM64 CK dependency is corrected with
an explicit original-consumed source-header view; no C/Make/shared-rule/frontend
policy changes. Original parallel-log interleaving and overridden RISC-V default
flags are handled with per-object Make metadata and actual compiler-driver proof,
not ignored. Separate DWARF/source lookup, complete architectures/world/pkgbase,
bootstrap/publication, VM/runtime and controlled performance/cache/sandbox gates
remain open. Existing format-5 --arch profiles carry this cohort. Make stays
production/default; BIP stays excluded.

## ARM64/RISC-V firmware module checkpoint (2026-11-03)

The [shared native firmware pipeline](CROSS-FIRMWARE-MODULES-QUALIFICATION.md)
now covers seventeen selected ARM64 and twelve RISC-V leaves. Four normal
build-bsd profiles and all 58 original Make controls pass: 29 whole-file plain
matches, 29 CTF/runtime/debuglink checks, 87 install records, 140 actual compiler
contexts/5,108 consumed pairs and 116 ordered links. All 82 embedding instances
bind exact payload bytes and explicit .incbin input digests; 29 registration and
20 decode actions bind original sources/specifications. All 38 current amd64
module/debug/install captures remain byte-identical after the shared refactor.
No C/assembly/AWK/Make/compiler-policy or security change. Existing format-5
architecture selection carries the cohort. Separate DWARF/source lookup,
complete cross/world/pkgbase/bootstrap/hardware/publication, runtime and controlled
performance/cache/sandbox gates remain open. Userland target/exec SDK separation
continues independently with fresh receipts after receipt-bound tool changes.
Make stays production/default; BIP stays excluded.

### 2026-11-03: actual userland target/execution SDK separation

Maintained SDK-only preparation explicitly selects amd64/ARM64/RISC-V real
world profiles and composes cross targets with an independently validated native
execution SDK. Fresh native-r3 validates 16,712 bindings; only intentional
conditional RISC-V ccconfig bytes differ from native-r1. Existing native and
kernel role policy is retained; cross tests require the host artifact provider.
Original cross header floors were repaired through maintained private-sysroot
header recipes, with fresh cross original references afterward. Two maintained
policy test targets pass (15 settings/18 inventory direct methods; 10 reference
option methods separately pass). See USERLAND-SDK-QUALIFICATION.md. Actual
three-architecture bz2/bzip2 component evidence is a separate bounded gate;
full world/rescue/pkgbase/foreign execution/bootstrap remain incomplete.

### 2026-11-03: genuine libbz2/bzip2 production closure on three ABIs

Normal format-5 amd64/ARM64/RISC-V profiles pass actual production builds,
source-owned original-order regular/PIC archives and default static CcInfo
extraction, actual shared/program links and component installation archives.
All 45 production CPP contexts/995 original-native consumed pairs, 42 archive
members, nine ordered link sequences, six linked allocated payloads and 54 original
component installation records pass independent Make comparison. All nine
declared tests pass without skips/foreign execution. Strict final review caught
real omitted executable-link -gz=zlib despite green initial tests; final r3
preserves original compressed DWARF, and the maintained host test rejects all
three real earlier outputs. Actual debuglink/CRC checks are distinct from open
separate DWARF/source lookup parity. See BZIP2-THREE-ARCH-QUALIFICATION.md.
Next real package-family gate is bzip2recover original policy/installation plus
the existing packages/bzip2 aggregate and real pkgbase outputs on selected ABIs;
full world/rescue/bootstrap/foreign runtime and publication remain incomplete.

### 2026-11-03: selected bzip2 recovery/package family on three ABIs

The next component gap is closed: actual recovery production/installation and
four selected pkgbase outputs pass three normal profiles and independent
original Make package recipes. All 48 production contexts/1,040 consumed pairs,
nine allocated linked payloads, twelve actual links, 66 original component
records→57 composed records and sixteen declared tests pass. Six prior component
archives are unchanged whole bytes. Default-off identical-directory composition
preserves every metadata field and rejects file collisions. Ordinary Make
package stage timestamps versus declared native epoch zero and separate DWARF
source lookup are retained distinctions; no package archive byte-equality claim.
See BZIP2-FAMILY-QUALIFICATION.md and its hash-bound summary. Complete selected
world/rescue/pkgbase, dependency solver/installation, bootstrap, foreign runtime
and publication remain incomplete; this is the selected four-package profile.

### 2026-11-03: actual libz and three-package family on three ABIs

The selected lib/libz gap now has original-order regular/PIC archives, genuine
default CcInfo extraction, DSO, generated metadata and original installation
records. Three normal profiles pass 96 production compiler contexts/3,648
consumed pairs, three allocated DSO comparisons, ten links, 33 install records,
nine independent original package comparisons and seven declared tests. The
initial SDK/project header identity rejection is preserved and corrected.
See ZLIB-THREE-ARCH-QUALIFICATION.md. Package timestamp policies and separate
DWARF/source lookup remain explicit; this is not full world, bootstrap, foreign
runtime, installation or publication qualification. Broader libz consumer
rebuilds remain a full-world gate because CTF tools consume this library.

### 2026-11-03: private zstd library, command and packages on three ABIs

The next selected compression dependency now has genuine original-order regular
and PIC archives/default CcInfo extraction, private DSO, eleven-source CLI and
four actual packages per ABI. All 233 compiler contexts/9,937 consumed pairs,
200 archive members, six linked allocated payloads, nine core links, 57 original
install records→54 unique records, twelve package comparisons and five declared
tests pass. RISC-V's original extra runtime C source is retained. Ordinary
references remain untouched: 206 objects match allocated bytes, while 27
filename-sensitive objects require separately audited original one-map controls.
The final ARM64 link correction preserves its original Cortex-A53 policy;
other architecture branches remain empty. See ZSTD-THREE-ARCH-QUALIFICATION.md.
Separate DWARF/source lookup, alternate options/upstream suites, package-manager
installation, full-world/rescue/bootstrap and foreign runtime remain open.
Cross libmd/liblzma/xz and the larger libarchive stack remain distinct gaps.

### 2026-11-03: complete original cross-kernel baselines and SDK selection

ARM64/RISC-V original GENERIC kernels and private staged installations pass;
2,035/1,194 selected products plus three auxiliary generators each have actual
compiler/dependency/producer review (408,447 canonical consumed pairs).
The four-header crypto provenance control and explicit assembly firmware input
are retained distinctions. Source-derived policy grouping identifies 37 ARM64
and 19 RISC-V compiler groups. The maintained format-5 backend now accepts a
matching composite target/native execution SDK, with 17 settings tests and
three real SDK snapshot checks. See CROSS-KERNEL-BASELINE.md. No full Bazel
cross-kernel claim: next implement precise owners, intrinsic-header policies,
source-derived DTS version, generated inputs and ordered links/installations,
then compare complete native outputs before module/pkgbase/runtime/performance.

### 2026-11-03: genuine three-ABI libmd prerequisite for XZ

The inherited amd64-only libmd graph now models actual default amd64/ARM64
optimized and RISC-V portable source selections. Explicit regular/PIC archives
serve installation, default CcInfo extraction and the DSO. Three normal profiles
pass 158 compiler contexts/4,762 consumed pairs, 158 archive member bindings,
three DSO allocated comparisons, six link contracts and 381 library records.
Twenty-eight genuine native static/shared digest tests and three host archive
tests pass. Initial SSP/header-origin policy failures are retained and fixed.
Ordinary references retain twelve filename-sensitive contexts; three separately
checked original one-map controls prove full allocated/relocation parity without
rewriting bytes. See LIBMD-THREE-ARCH-QUALIFICATION.md. Nondefault optimization,
bootstrap, foreign runtime, separate DWARF, recursive installed-test producer
parity and full runtime/tests packages remain open. The liblzma/XZ four-package
family is staged privately and still requires its own native qualification.

### 2026-11-03: native common cross-kernel compilation foundation

Source-owned built-in helpers preserve ARM64/RISC-V policies separately from
KLD modules. The first 46/48 common sources and ARM64 crypto wrapper pass 282
object configurations, 19,054 consumed pairs and explicit source-derived DTS
header checks. All 141 plain objects are byte-equal to matching original plain
controls; 141 raw CTF payloads and all allocated/symbol/relocation contracts
match. Eight normal profiles pass ten declared tests. The public C++ archive
API fixes a genuine composite host-tool declaration defect; libc++ dynamic/static
runtime and native member-order checks pass. See CROSS-KERNEL-COMMON-QUALIFICATION.md
and its hash-bound summary. Next expand precise built-in owners and generated
producers across the full config inventory, then complete ordered cross-kernel
links/installations and cross-module/pkgbase aggregates. Separate DWARF,
configuration breadth, bootstrap/sandbox/cache, actual boot/runtime/upgrades
and CPU/aggregate memory/disk I/O/usage remain gates. Make remains production;
BIP remains excluded.

### 2026-11-03: XZ/liblzma commands and package family on three ABIs

The libmd prerequisite is now consumed by genuine native liblzma, xz, xzdec and
lzmainfo producers on all three ABIs. Three normal profiles/captures pass
561 production contexts/46,575 consumed pairs and 63 real static-command test
contexts/5,079 pairs, with strict distinct SDK versus public source API origins.
All twelve production ELF metadata/allocated payloads match untouched originals;
468 archive members, fifteen actual links/generated outputs, 49-to-44 install
records per ABI, twelve actual package comparisons and nineteen independent
native/original runtime comparisons pass. Three declared artifact tests pass.
The ordinary installed archive is the default CcInfo input. Rejected test-PIE,
DSO pthread, production header-origin and shared-root dependency policies remain
retained. See XZ-THREE-ARCH-QUALIFICATION.md. Separate DWARF/source lookup, foreign
execution, i386/alternate options, full-world/rescue/bootstrap, package solver/
installation/publication and measured performance remain gates. The earlier
XZ-pending entries are historical checkpoints; the larger libarchive stack and
complete selected world still need independent closure.

### 2026-11-03: ARM64/RISC-V VM built-in cohort

Four maintained profiles and independent Make controls qualify 24 selected VM
sources per architecture: 96 object configurations/13,740 consumed input pairs,
48 byte-identical plain objects, 48 exact CTF payloads and exact runtime
sections/symbols/relocations throughout. Ten options per architecture come from
the selected config; vnode interfaces remain declared producers. Source hashes
and 122 existing lexical instrumentation markers are retained. See
CROSS-KERNEL-VM-QUALIFICATION.md. Full cross-kernel linking, remaining owners,
configuration breadth, separate DWARF/source lookup, boot/runtime, packages,
bootstrap/sandbox/cache and comparative performance remain open. The private
next network candidate is not counted as qualified coverage. Make remains
production; BIP remains excluded.

### 2026-11-03: BSD XML prerequisite on three ABIs

The selected libbsdxml default normal/PIC archives, DSO, generated headers,
public API/default static extraction and eight install records per ABI pass
three ordinary profiles. Strict review binds 30 production contexts and 1,020
consumed pairs; original archive order and nine actual links pass. Five tests
pass, including two native parser executions. Six filename-sensitive xmlparse
contexts retain untouched-original rejections and match three independent
original controls with exactly one macro-prefix map; the other 24 objects
match untouched originals. All three DSO metadata/allocated contracts match
controls. See BSDXML-THREE-ARCH-QUALIFICATION.md. This is a runtime component,
not an invented standalone package. Next substantive libarchive closure needs
source-owned ARM64/RISC-V libcrypto inventories, architecture assembly/flags,
ordered normal/PIC archives and default consumer/provider semantics, preserving
selected OpenSSL/FIPS/KTLS/DTrace/iconv. Recursive providers/engines, separate
DWARF/source lookup, foreign execution, full world/bootstrap and pkgbase remain
gates. Make remains production; BIP remains excluded.

### 2026-11-03: ARM64/RISC-V network built-in cohort

The selected sys/net and sys/netinet lists now qualify 175 products through
four maintained profiles: 350 runtime object matches, 175 whole-byte plain
objects and 175 exact CTF payloads. The 54,306-pair input ledger separately
records 54,280 raw exact pairs and 26 independently reproduced KOBJ header
path-policy pairs. Existing C/runtime instrumentation is unchanged (89 distinct
sources, 124 lexical marker lines). See CROSS-KERNEL-NETWORK-QUALIFICATION.md.

Next kernel gates include composite SDK host-tool closure for KOBJ, remaining
owners and configs, complete source/generator/link closure and boot/runtime.
The debug source follow-up must replace the private prototype with public
artifact/provider based archive and mapping outputs, package identity binding,
and maintained frontend integration. Validate actual primary/inline/generated/
SDK text after relocation and with execution trees unavailable. ARM64 private
inline-header lookup succeeded; RISC-V ET_REL debugger relocation is unresolved
and requires linked-artifact qualification. No debug package completion claimed.
Full world/pkgbase/hardware publication, bootstrap/sandbox/cache and comparative
CPU/memory/disk I/O/usage gates remain. Make stays production; BIP is excluded.

### 2026-11-03: reproduced composite KOBJ runtime defect

The unchanged ARM64 composite networking profile failed with the native loader
rejecting target libc in BSDKobjInterface. Inspection also finds foreign
libc/libsys declarations under the RISC-V SDK. Source defaults are corrected
to execution-runtime labels, retaining execution-configured source libm.
Corrected ARM64/RISC-V composite profiles pass: 175 whole-byte plain objects,
175 bound compiler contexts, 27,140 raw exact input pairs, 13 independently
controlled KOBJ provenance pairs and 89 explicit ARM64 DTS header additions.
Five ARM64 KOBJ actions execute; two RISC-V consumed header members are cached
and independently checked. Other execution declarations (CTF/modules, RPC,
device IDs, locales, crunch, boot images and callers) require role classification
and composite qualification; intentional target ABI inspection stays target data. See KOBJ-EXECUTION-RUNTIME-QUALIFICATION.md.
This does not close complete host sandbox, source/debug, cross-kernel/link,
world/package/bootstrap/cache/runtime or comparative resource/performance gates.

### 2026-11-03: selected core-owner qualification closed

All 212 ARM64 and 209 RISC-V core-owner products, including layout auxiliaries
and source-decoded firmware, pass four maintained composite-SDK profiles.
Independent Make controls establish 842 runtime object matches, 421 byte-exact
plain objects, 414 exact CTF payloads and seven matching CTF absences. The input
ledger preserves 103,782 raw exact pairs, 212 independently regenerated KOBJ
provenance pairs, 424 explicit DTS header additions and two separately checked
firmware binary inputs. Six declared tests pass; all 212 primary sources and
existing instrumentation remain unchanged. See CROSS-KERNEL-CORE-QUALIFICATION.md.
Initial missing MSI/PIC header views and an observer pre/post-CTF mismatch are
retained with their explicit corrections. The existing frontend contract handles
these native source targets; no CLI, package or signing interface change occurs.
Next kernel work includes remaining source/generator owners, ordered full links,
configuration breadth and execution-runtime helper classification. Source/debug
packages, bootstrap/sandbox/cache, full world/pkgbase/hardware, boot/runtime and
comparative CPU/memory/disk I/O/usage remain gates. Make stays production;
BIP remains excluded.

### 2026-11-03: execution versus target library role audit

The static follow-up classifies 538 literal SDK references in 185 files:
380 intentional target inputs, 148 host-runtime candidates, six shared-variable
references requiring separate host/target lists, and four unresolved data-flow
references. Actual ELF inspection confirms eight foreign SDK/library pairs
cannot be loaded as native runtime libraries. These are inspected declarations,
not 148 executed failures or complete label coverage. See
KOBJ-EXECUTION-RUNTIME-QUALIFICATION.md and its standard-object-root audit ledger.
The unchanged composite nullfs CTF path reproduced two native converter
failures loading ARM64 libc. The isolated two-helper correction is applied;
corrected ARM64/RISC-V host runtime selection passes (ten executed actions,
74 native ELF inputs). Complete target artifact qualification remains rejected. Preserve target test runtimes, target drti and package
ABI inputs; review FIDL and remaining generator families individually. Existing
frontend/SDK interfaces cover the proposed correction; no new CLI or package
contract is introduced. The runtime selection fix is qualified only for those selected host actions.

### Immediate kernel gate: refresh and qualify foreign bootstrap tools

The new strict composite nullfs review caught wrong ARM64 CTF associations,
including SDT probe/provider data, at export localization. Source/history review
finds the robust identity-preserving objcopy fix already committed in d7f9be55deb;
its 65-case maintained format suite exists. Do not reinvent pipeline ordering
or the previously rejected fuzzy-merge workaround. The unchanged native r4 SDK
passes all 65 cases; both foreign r4 tools fail the localization case.

Refresh ARM64/RISC-V bootstrap objcopy through its maintained cross-tools
source-owner recipes, with all available CPUs and guarded resource budgets.
Rebuilding the LLVM bootstrap library is separate from installing it: replaying
the full cross-tools library installation over a completed foreign sysroot can
replace target libraries with native bootstrap libraries. Derive the XMAKE
context from the recorded profile, build libllvm without installing it, then
build and stage only the objcopy/strip programs. Hash the complete target
header/library inventory before and after; require it to remain unchanged.
Coordinate world/tmp mutations
with original-reference controls. Generate fresh SDKs/receipts; retain r4 inputs
and failures unchanged. Run the existing semantic/format suite for each SDK's
actual selected tool, then rerun real module/CTF/export/debug/install profiles
and cache checks. Make source already contains the correct objcopy algorithm;
foreign staged tools require refresh and behavior qualification. Version strings
and hashes alone cannot prove the needed capability. Full native Bazel toolchain
bootstrap and declared regression coverage for every selected SDK remain gates.
Separate DWARF/source lookup, remaining runtime helper families, whole-system
production/runtime and comparative performance remain open.


### 2026-11-03: selected-default libcrypto core checkpoint

The native AMD64/ARM64/RISC-V core producers now have source-owned ordered
normal/PIC lists, architecture assembly/ISA policy, target-derived buildinf,
explicit installed archive providers and shared whole-PIC linkage. Actual input
and link receipts bind all 5,826 production contexts. Independent original
controls add only the recorded filename-map flag: all allocated bytes and
runtime relocations match; all DSO symbols match. RISC-V raw object symbols
remain unequal only in 300,356 exhaustively classified local offsets into
nonallocated debug sections (1,868 objects). This is not raw Make byte parity
or completed debug qualification. The untouched filename rejections remain.

Each ABI core install manifest matches 6,465 original metadata records through
physical hardlink equivalence; 6,460 fixed source payloads are exact. AMD64 runs
the real static/shared API tests; foreign profiles run host artifact inspection
without executing foreign ELF. See LIBCRYPTO-CORE-THREE-ARCH-QUALIFICATION.md.
Existing format-5 frontend/SDK/install interfaces cover this checkpoint; no new
CLI, signing, packaging or publication fields are required.

Next close default recursion: engines, providers, FIPS tests, libssl, openssl
CLI and complete component/package ownership. Do not disable Make recursion,
produce a partial OpenSSL package, or count core-only qualification as selected
world completion. Separate debug/source lookup, alternate options, foreign
runtime, native toolchain bootstrap and performance remain open.


### 2026-11-03: ARM64 bootstrap tool refresh closes format gate

The maintained bootstrap source-owner rebuild/install completed for ARM64's
native objcopy. All 65 format regressions pass on its actual newly staged bytes.
The initial inventory rejection is retained; exactly its separate native program
debug file changed under usr/lib, and follow-up checks prove that install output
against the new build while every other target header/library entry is unchanged.
RISC-V refresh is active, not yet qualified. Both frozen r4 SDKs remain unchanged.
See KOBJ-EXECUTION-RUNTIME-QUALIFICATION.md for hashes and actual evidence.

Next finish the RISC-V refresh, construct fresh composite SDKs and qualify their
selected tools, then rerun real module export/CTF/debug/install and cache paths.
Add a declared cross-module semantic test: the existing AMD64 whole-module audit
cannot establish foreign ET_DYN coverage. Preserve original failures and compare
against independently refreshed original controls. Full-system/bootstrap/debug/
performance gates and Make production/default policy remain unchanged.


### 2026-11-03: final shared-link CTF regression remains open

Both refreshed foreign-stage objcopy tools pass all 65 format checks. A fresh
ARM64 composite SDK is materialized and passes its own format checks; the new
RISC-V composite SDK is not yet materialized. Explicit host artifact tests now
inspect real target module full/runtime pairs. Native passes all 112 association
checks and 14 policy object checks; actual ARM64 fresh-SDK and RISC-V native-SDK
kernel frontend profiles reject CTF links to SYMTAB. Their failures are retained.
A controlled captured-action replay independently isolates final LLD shared
linking: both lose sh_link and RISC-V corrupts 106 object associations.

Next correct exact symbol/type association preservation in the linker and
qualify independent refreshed Make controls and actual native/foreign profiles.
Account explicitly for the initial multi-input relocatable link plus maintained
ctfmerge; no fuzzy matching, output patching, CTF disabling or relaxed acceptance.
See CROSS-MODULE-CTF-QUALIFICATION.md. No LLD fix or complete module acceptance
is claimed. The native Bazel parser/copy suites pass 37 methods.

The normal frontend now uses independent OS copy offload for duplicate SDK and
private repository-cache files, with mandatory identical snapshot verification.
The copy/cache helpers are bound in receipts; all seven copy methods pass and
16,179 actual ARM64 snapshot paths plus independent regular-file inodes verify.
The initial disk-guard interruption remains rejected, followed by fully verified
cache reuse. This is storage-copy correctness, not comparative performance.
No config schema, SDK staging helper, signing, packaging or publication change
is introduced. Keep Make production/default and BIP excluded.


### 2026-11-03: correct the CTF checker before linker extraction

Independent producer/ctfdump checks disproved the proposed per-function padding
change to objcopy. The semantic checker was wrong for consecutive packed v2
function associations; its single-record fixture masked the defect. Corrected
it, added subsection alignment checks, and replaced the misleading fixture with
16 format/alignment combinations. Normal build-bsd/Bazel executes all 30 CTF
methods successfully, and explicit-tool independent/semantic checks pass 129
cases. Previous-reader rejection and proposed-padded-fixture failure remain
retained. See CTF-SEMANTIC-CHECK.md for source bindings and qualification scope.

Still OPEN: local libctf init_symtab's inconsistent v2 width/record rounding;
exact linker symbol provenance and final CTF sh_link/association preservation;
initial multi-input CTF link/merge handling; full module and system acceptance.
No linker fix, producer change or completed world/kernel build is claimed.
No frontend schema or production-default change is required for this checker
correction. Keep Make production/default and BIP excluded.


### 2026-11-03: shared CTF symbol-association foundation

Extracted the ObjCopy container rewriter into LLVM Object CTFSymbolTable so
linker work can share one owning parser with exact original symbol identities.
Make and Bazel source ownership are updated. ELF policy and the unchanged opaque
fast path remain in ObjCopy. No type-graph merger or LLD fix is implemented yet.

Independent review also found and reproduced the old identical-payload/different
header-boundary bug in all eight format combinations. Fixed the unchanged
check; the rebuilt native bootstrap tool passes 137 format checks and the
explicit-library API diagnostic passes 160 checks. Source-owner Make builds,
source/library/tool bindings, first failed compilation, unchanged staged tool
and 16 GiB disk reserve are retained. See tests/ctf/LOCALIZATION.md and
/usr/obj/usr/src/bazel-ctf-shared-helper-review-r1-20261103.

Next: integrate exact input-file/index provenance with final LLD symtab order,
preserve CTF section links, solve the initial multiple-input-container contract,
and qualify refreshed original controls and actual modules across all three
architectures. Native Bazel LLVM API/bootstrap qualification is still required;
these explicit-tool diagnostics do not substitute for it. Full world/kernel,
packages, runtime and performance gates remain open; Make stays default.


### 2026-11-03: qualify disjoint CTF namespace relocation before LLD hooks

LLVM Object can now union self-contained v2/v3 dictionaries into a valid v3
namespace using exact container/index provenance. It relocates all supported
record layouts and internal/external string references; preserves cycles,
duplicate names and root flags; and rejects unrepresentable label/parent cases.
String interning avoids copying unused ELF strings. All source association refs,
including discarded symbols, are validated. This is not type deduplication.

Normal build-bsd/Bazel tests now qualify the source-built Object/Support API
(160 checks), semantic reader (30 methods), and union graph suite (1,024 graphs,
256 source-built ctfdump controls, 16 negatives and layout/resource controls).
Make-library and Bazel drivers serialize all 1,024 compared cases identically.
Source bindings, prior rejected attempts and resource recovery are retained.
See CTF-NAMESPACE-UNION.md for scope, evidence and normal test labels.

The union is NOT CONNECTED TO LLD yet. Next implement exact selected-definition
provenance, section/script placement, final symtab ordering and CTF links, then
qualify refreshed original controls plus real native/foreign module pipelines.
No module acceptance, complete bootstrap/world/kernel, package/publication or
performance qualification is claimed. Make stays production/default; BIP stays
excluded. Keep signed/staged SDKs immutable and refresh through normal helpers.

### 2026-11-03: LLD exact symbol provenance, not final module acceptance

Selected input indices now follow definitions through COMMON conversion,
version copies, replacement and wrapping, without increasing SymbolUnion.
No-CTF files use a decision bitset and allocate a transient index map only for
same-file collisions; CTF files retain exact index maps for later output work.
The initial all-global map cost time/memory in a 200,000-symbol diagnostic and
was replaced. Final samples show no regression on that limited workload;
whole-system performance gates remain open.

The maintained source-owner LLD build passes with frozen sources and no install.
An existing same-file weak/strong section-selection bug is reproduced by the
old tool and fixed by the candidate. Eight payload/binding/size regression cases
and 16 baseline link controls pass. A native Bazel source-built linker test is
declared but not yet executed. See CTF-NAMESPACE-UNION.md for exact scope.

Next: script-respecting CTF section synthesis, correct final output symbol order,
output section links and refreshed native/ARM64/RISC-V real module checks.
No final-link CTF, complete world/kernel or publication acceptance is claimed.
Make stays default. BIP remains excluded. No host upgrade or reboot authorized.

### 2026-11-03: exact CTF layout size without dictionary serialization

Added shared size planning with the same identity/overflow validation as symbol
rewriting. It counts real packed function records, unknown associations and
alignment without copying/compressing the dictionary. Final order still must be
used for serialization. Normal frontend/Bazel tests pass: 328 API checks and
1,024 union graphs actually run; semantic suite is cached. The first two suites
use native source-built LLVM components. See CTF-NAMESPACE-UNION.md.

Next remains LLD synthetic section placement, participation in layout before
final offsets, final symbol ordering and sh_link, then refreshed real module
qualification. Sizing alone does not satisfy any final module/world/kernel gate.
No frontend configuration or security-policy changes are needed at this step.

### 2026-11-04: selected EFI libsa matrix on AMD64, ARM64 and RISC-V

Private ARM64 (259 objects) and RISC-V (263 objects) now reuse the regular source
inventory and the same 69 verifier sources. Platform selections retain the real
wchar, machine include and soft-float/general-register ABI differences. Shared
flag definitions remove duplicated option lists. The selected regular/private
matrix has six archive contexts; it is not a count of new programs or libraries.

Both foreign archives pass complete member-order/symbol comparisons, generated
header and actual compiler/archive bindings. Only three assertion filename
members differ in raw allocated bytes; isolated original compiler controls
explain all three. Regular archive bytes remain unchanged. See
LIBSA-CROSS-EFI-QUALIFICATION.md for retained evidence and exact profile limits.

A repeat on the final flag factoring correctly refused a changed HyperTrace SDK
origin after dev advanced to a914137016e. Preserve that failure and the immutable
previous captures. Fresh native/cross SDKs were prepared with maintained
plan/staging helpers. All three current-input frontend repeats pass and preserve
both archive byte hashes. The changed SDK update reran all 451 native compilers;
that coarse invalidation is not a warm-cache pass. Old receipts and origin
checks remain intact. See SDK-VERIFICATION-QUALIFICATION.md.

The maintained frontend now performs bounded parallel full-content verification
using --jobs, with receipt-bound file/byte/worker/hash-phase timing records.
Native Bazel runs 43 methods covering corruption, concurrency, settings and test
inventory. No digest cache or input-check suppression was introduced. Narrowing
freestanding compiler inputs and measuring SDK materialization/CPU/memory/physical
I/O remain required; parallel hashing alone does not qualify performance.

Next: actual loader entry and final EFI links.
Complete world/rescue/cross kernel/module, installation/debug, runtime/boot,
bootstrap/sandbox/cache, pkgbase/hardware/combined publication and CPU/memory/disk
performance gates remain required. The broad SDK input/validation overhead is
still open. No VM, installation, upgrade or reboot occurred. Make stays default;
BIP remains excluded. No frontend C switch or policy default changed.

### 2026-11-04: first EFI loader construction reference

The maintained AMD64 loader reference passes at
`bazel-efi-loader-amd64-make-r1-20261104`, with 58 actual object recipes,
REPRODUCIBLE_BUILD explicitly enabled and BUILD_UTC explicitly selected. It
produces the full/debug/stripped symbol files, PE image and installation records.
Its link still consumes the existing world SDK's three private EFI archives;
this is an entry-object/generator reference, not a closed whole-loader oracle
or a native Bazel loader build.

Next carry the actual font, help and version generators into declared actions,
then entry objects and final links. The existing newvers.sh still collects host
metadata even when -r suppresses it; remove that unnecessary dependency while
preserving Make output. PE epoch must be a declared input; the current recipe's
maintained 2024 timestamp default is reference policy, not a value to embed in a
new generator. Close the original-library link inputs before asserting complete
loader parity or boot qualification. All broader completion gates remain open.

### 2026-11-04: native loader font and ordered help

The actual source-built execution converter and maintained AWK script now produce
font/common/FDT-help artifacts on all three target configurations. Generated font
and common help match the actual Make reference, and all three output sets have
identical hashes. Native ELF/runtime and full configured input/action reviews
pass. Seven methods execute natively and are reused by foreign profiles; cached
results are not counted as fresh executions. See LOADER-GENERATORS-QUALIFICATION.md.

The native runtime audit was corrected to inspect transitive dependencies. The
foreign audit was corrected to attest cached producers using exact configured
actions and input hashes. Production outputs or tests were not changed to hide
those diagnostic assumptions. Final helper search paths exclude Python data
directories. No new frontend C switch or input format was needed.

Next: maintained-script version generation with declared tools/output/build
metadata, then real entry objects and final links. Preserve the version script's
ordinary Make interface and output while removing metadata-only calls from -r.
Continue the full installation/debug, world/rescue/cross kernel/module,
bootstrap/sandbox/cache, publication, runtime and CPU/memory/disk gates.
Make stays default; BIP remains excluded. No installation or reboot authorized.

### Native loader version generation (2026-11-04)

The maintained version script now runs as a declared native Bazel action for
AMD64, ARM64 and RISC-V. Original-script byte comparisons, seven focused methods
and metadata change/restoration checks pass. Typed format-5 settings select
reproducible output or an explicit metadata source label; no host identity or
test metadata is selected by default. See
[LOADER-VERSION-QUALIFICATION.md](LOADER-VERSION-QUALIFICATION.md).

Next: actual loader entry objects and final native links, then installation/debug
and runtime qualification. All complete world/kernel/module, bootstrap/sandbox,
package/publication and performance gates remain open. Make stays default.

### AMD64 EFI entry objects (2026-11-04)

The selected Lua/EFI profile now compiles all 58 actual entry sources natively.
All 3,137 consumed input pairs bind to actual successful compiler actions; 56 raw
allocated payloads/relocation sets match Make and two assertion filename cases
match independent original compiler controls. No production mappings or assertion
suppressions were added. See [LOADER-ENTRY-QUALIFICATION.md](LOADER-ENTRY-QUALIFICATION.md).

Next close the original-library reference and final native entry/archive links,
then qualify installation/debug, PE conversion and runtime/boot. ARM64/RISC-V entry
profiles and alternate inventories remain open, as do the broader system gates.
Make remains production/default.

### AMD64 EFI final ELF link (2026-11-04)

The selected loader now links all 58 native entry objects and three native private
archives through cc_common and the selected C++ toolchain. Its runtime ELF payload
matches an independently linked original after six original compiler filename-only
controls. Raw differences remain recorded; production assertions/output are not
rewritten. The final-source repeat reports six passing ordering cases and the
identical linked hash. See [LOADER-LINK-QUALIFICATION.md](LOADER-LINK-QUALIFICATION.md).

Next: debug splitting, explicit PE timestamp input/conversion and installation
metadata, followed by firmware execution. ARM64/RISC-V entry/link profiles and all
broader system completion gates remain open. Make remains production/default.

### EFI transformations in progress (2026-11-04)

The selected AMD64 loader has source-owned debug splitting, PE conversion and
three installation file/link records. The PE timestamp is a typed format-5 source
setting with Make's maintained default and no execution-host clock fallback.
The native elfcopy execution closure and final transformations now pass the
checks recorded in LOADER-PE-QUALIFICATION.md.
It includes libc/libthr DTrace generation and the existing full dtrace executable's
C++/HyperTrace/telemetry/protobuf build dependencies. Review that cold tool-closure
cost during bootstrap/performance qualification; do not suppress probes or silently
replace the tool to avoid it. Next verify PE bytes/debug integrity/metadata and
exercise timestamp override/rejection/restoration before firmware tests.

PE/debug/metadata qualification completed: final PE bytes match independent
original filename controls, runtime ELF/debuglink integrity passes, and all three
file/link records match Make. Beyond-2038 and out-of-range settings plus exact
default restoration are exercised. The timestamp change/restoration executes
only conversion. Runtime search paths exclude data directories and the native
interpreter input is explicit, with host-interpreter equality attested.

Next rerun relevant shared EFI regressions, stage the actual component/archive
with maintained directory/pkgbase policy, and qualify firmware execution. Foreign
entry/image profiles and all complete-system/debug/bootstrap/performance gates
remain open. Make remains production/default; BIP remains excluded.

### Loader component stage and shared regressions (2026-11-04)

The existing EFI conversion target passes its seven unittest methods. The selected
AMD64 archive derives ancestor modes and named IDs from maintained mtree/account
inputs and preserves actual payload/hardlinks. Its package partition is explicitly
component scope, with complete manifests refused. Typed archive times support
2147483649; literal 42 and configured 00042 produce identical archives. Four
invalid-input guards and the existing partial-package guard pass.

The original component install adds a utilities tag to /boot in addition to the
common mtree's bootloader assignment. Record and handle multiple directory package
assignments at complete-package aggregation; do not claim full metadata parity
from this component. See LOADER-STAGE-QUALIFICATION.md. Next retain default archive
restoration, then complete bootloader aggregation and firmware qualification;
foreign/alternate profiles and all broader completion gates remain open.

Default restoration now preserves the complete archive, PE and component-layout
bytes on final source. Only conversion and archive serialization rerun; no compiler
or final ELF link reruns. Retained proof: restoration-review.json in the future
stage review. Complete package directory assignments and boot remain open.

### Native AMD64 boot1 and gptboot (2026-11-04)

Two additional actual EFI programs now build their twelve entry sources, final
ELF/debug/PE products and original installation selections natively. All twelve
entry allocated payloads/relocations match unmodified Make; both final payloads
and PE bytes match closed originals under the recorded archive controls, with
gptboot PE also matching raw Make. All 784 consumed input pairs and both actual
object/archive link orders are verified; manual/default metadata and unchanged
Lua loader bytes agree. See [EFI-BOOTSTRAP-QUALIFICATION.md](EFI-BOOTSTRAP-QUALIFICATION.md).

Next: final-source reuse, remaining interpreter/IA32 and foreign entry profiles,
complete bootloader aggregation and firmware runtime. All broader world/kernel/
module, debug, bootstrap/sandbox, publication and performance gates remain open.
Make stays production/default.

### AMD64 Forth and simple EFI interpreters (2026-11-04)

Both variants now build full native entry/link/debug/PE/install candidates using
one shared source/order/options model with Lua. The 116 entries preserve 112 raw
allocated/relocation sets, with four independently explained filename cases.
Both final payloads and PE bytes match completed original controls, including
fresh private Ficl filename controls; all 6,227 consumed input pairs and final
link orders agree. Forth's actual version.veriexec and help exclusion are retained;
simple's ordinary version/help and unchanged Lua output are checked. See
[EFI-INTERPRETERS-QUALIFICATION.md](EFI-INTERPRETERS-QUALIFICATION.md).

Next retain final-source reuse, then IA32/foreign entry profiles, complete bootloader
aggregation (shared help/directories), firmware/interpreter execution and the
broader system gates. Make remains production/default.

### Original cross-loader library inputs (2026-11-04)

The maintained reference helper now binds independent original archives by exact
receipt/content hashes, target/compiler identity and actual LDADD use. Missing
SDK archives remain missing; no copies or search-path fallback are used. ARM64
and RISC-V original loader references pass with all five explicit libraries,
FDT and EFI verification selected, each with 48 object recipes and full outputs.
Seven validator methods and fourteen existing option methods pass through the
maintained frontend. See
[REFERENCE-LIBRARY-INPUTS-QUALIFICATION.md](REFERENCE-LIBRARY-INPUTS-QUALIFICATION.md).

Next implement native cross-loader entry/FDT/link/raw-image selection from those
references. These are original Make references, not completed Bazel cross loaders.
All full-system, package, firmware, bootstrap and performance gates remain open.
Make stays default.

### 2026-11-04: Cross Lua EFI candidates and DTrace consumer ABI

ARM64/RISC-V source-owned Lua/FDT entry, final link, debug, image and component
stage builds pass. Each selects all 48 Make entry objects and five native archives.
Raw objects match 46/48 per architecture; independent original filename controls
explain both entry differences and the existing EFI/standalone archive cases.
Final loadable payloads and PE bytes match controlled originals; FDT help,
debuglink integrity and extracted stage metadata are checked. RISC-V non-loadable
ABI-attribute file offsets differ with debug layout and remain explicitly recorded.
The root loader Make reference owns help; the private loader_lua reference does not.

A real cross-build failure selected target drti.o for an execution-host libarchive.
All thirteen source provider declarations now obtain drti from the resolved consumer
C/C++ toolchain; probes remain enabled. See CROSS-EFI-LOADER-QUALIFICATION.md.
Final-source 56-output equality passes for each cross profile. All 48 actual final
compiler chains per architecture bind 2,451/2,468 consumed input digests. The
AMD64 regression retains all 225 prior captures. Explicit unsupported cross option
selection is rejected at analysis. Continue IA32/alternate interpreter profiles, complete bootloader contributions and actual
firmware qualification. All broader system/package/bootstrap/sandbox/cache/performance
gates remain open. Make stays default; BIP remains excluded.

### 2026-11-04: Native boot data, source policy and configured Lua paths

Six components now provide native data/man/font installation and aggregate archives.
Default AMD64/ARM64 inventories contain 86 files; RISC-V contains 85 after correcting
its source-defined KBOOT exclusion. Independent default/option Make references check
payload bytes and file metadata. Actual archive, VFNT/catalog/gzip/PNG tests cover
normal, site-path/split, raw/reduced and MAN=no configurations. A missing custom
path policy is rejected. Explicit supplemental mtree input mutation changes only
its two directory modes, causes only archive/test actions, and restores 271 captures.

Cross compiled-path qualification found and removed stale literal LUA_PATH operands.
Real ARM64/RISC-V entry, private Lua archive and final-loader strings now agree with
the eighteen relocated scripts. Default loader restoration and the existing 225
AMD64 / 50-per-cross loader outputs are checked. See BOOT-DATA-QUALIFICATION.md.
These are data/selected-loader contributions, without complete package, firmware,
world/kernel/module, bootstrap/sandbox/cache or performance qualification. Continue
missing boot programs/interpreter profiles, shared help/directory package aggregation
and actual firmware execution; preserve all broader completion gates. Make stays default.

### 2026-11-04: Cross EFI first-stage programs

Source-owned boot1/gptboot profiles now build ARM64 and RISC-V entry, native
archive links, debug and PE images. All 24 cross entry objects match original
Make code/relocations; final payload/PE comparisons and two artifact wrappers per
architecture pass. Configured graph reviews account for original dependency names
and ordered links. AMD64 regression retains all 225 prior captures; MAN=no and raw/split
manual comparisons pass, with all 27 ARM64 pre-test captures retained in the tested build. See [CROSS-EFI-BOOTSTRAP-QUALIFICATION.md](CROSS-EFI-BOOTSTRAP-QUALIFICATION.md).

A shared userland warning-policy gate remains: literal -Werror operands currently
prevent reliable werror=false selection. Complete bootloader/system/package,
firmware, bootstrap/sandbox/cache and performance gates remain open. Make stays default.

### 2026-11-04: Cross Forth/simple EFI variants

Four independent original Make references pass for ARM64/RISC-V Forth/simple.
The shared native cross ABI/source/order model now selects interpreter inputs
explicitly; all 192 original compiler recipes agree with its flag/order model.
Both native cross builds, thirteen artifact wrappers across three architectures,
controlled payload comparisons and actual 192 compiler/input-chain reviews pass.
The first response-file audit failure and its digest-bound correction are retained.
AMD64 retains all 225 prior captures; each cross Lua profile retains fifty. See
[CROSS-EFI-VARIANTS-QUALIFICATION.md](CROSS-EFI-VARIANTS-QUALIFICATION.md).
Complete bootloader, whole-system and performance gates remain open.

Freestanding input-closure follow-up: a retained RISC-V compiler action declares
4,346 inputs, with 4,104 SDK sysroot files under -nostdinc. Review native
freestanding toolchain specialization and incremental invalidation with real
input/cache tests; preserve every required input and dependency validation.
See the cross EFI variant qualification record.

### 2026-11-04: Explicit freestanding SDK toolchains

The maintained SDK stager and source backend support standalone target platforms
with native execution tools, full SDK verification and source-owned header inputs.
Three native EFI/resource profiles pass; all 498 selected entry objects and fifteen
PE images preserve their earlier qualified bytes. Configured input sets exclude
unused SDK headers. Hosted-header rejection and local cache mutation/restoration pass; the
900 prior capture records retain exact bytes. Persistent action CAS integration
and installation-metadata cache safety remain explicit gates. See
[FREESTANDING-TOOLCHAIN-QUALIFICATION.md](FREESTANDING-TOOLCHAIN-QUALIFICATION.md).
Full-world ABI boundary integration and broader completion gates remain open.

Persistent action-cache gate: source_graph.py currently configures module-download
repository caching and Bazel's ordinary local action cache, without a maintained
disk/remote CAS. The freestanding source-restoration experiment correctly executes
one compile on restoration and zero on the next unchanged run. Add a separately
configured/recorded action cache under /usr/obj and qualify switching/fresh-output
restoration after resolving representation/cache safety for hardlinks and other
installation metadata. Earlier isolated disk-cache successes do not close the
whole frontend gate; do not enable caching around an unsafe directory artifact.

### 2026-11-04: Managed local CAS and physical installation boundary

Optional typed action-cache policy now reaches native Bazel through build-bsd.
Named private output states share the managed CAS. Two empty output bases restore
all 66 native compiler actions and exact canonical archives from disk, while
physical installation executes without directory-cache restoration. The inode
validator runs on every phase; external BSD tar extraction preserves links/modes.
Twenty-seven frontend methods, native installation tests and all six older link
cases pass. Retained setup/report-classification failures and policy limits are
documented in [MANAGED-ACTION-CACHE-QUALIFICATION.md](MANAGED-ACTION-CACHE-QUALIFICATION.md).

This supersedes the isolated missing-CAS gate above, not the full-system cache,
installation, sandbox, bootstrap, runtime or performance gates. Make stays default.

Failed-test evidence retention is already implemented in the frontend exception
path. The managed-cache failed adapter log/XML copies and manifest hashes were
rechecked after later builds. Review failure-test-reports, not mutable BEP URIs.

### 2026-11-04: Hosted world consumes freestanding boot artifacts

A platform-only dependency transition now connects hosted image/install consumers
to five EFI producers on AMD64, ARM64 and RISC-V. The source module registers the
disjoint SDK toolchains; native execution tools avoid transition-specific toolchain
overrides. Source qualification explicitly requires the maintained snapshot-bound
SDK capability. The shared Ficl AWK generator fixes a configuration-dependent
assertion filename using a logical source name without changing body line numbers.
See FREESTANDING-BOUNDARY-QUALIFICATION.md for strict comparisons, actual configured
execution sharing, passing tests and retained initial failures. This closes the
selected ABI-boundary mechanism; complete world/boot aggregation and the other
full-system, bootstrap, sandbox, runtime and performance gates remain open.

### 2026-11-04: IA32 boot ABI prerequisite

The selected AMD64 world includes 32-bit BIOS/EFI producers. A real i386 standalone
SDK platform now uses x86_32 constraints and native execution tools. SDK schema 2
is staged and verified, rather than retagging old receipts. Eleven wrappers pass;
ELF32 compilation/static linking and the other three ABIs are checked, all fifteen
EFI image bytes are preserved, and hosted-header/old-SDK rejection is explicit.
See IA32-TOOLCHAIN-QUALIFICATION.md. Convert the selected BIOS/IA32 EFI contexts
next; this prerequisite does not close those programs or complete world/pkgbase.

### 2026-11-04: Selected IA32 EFI support archive

The shared libefi graph now represents the selected AMD64 DO32 context through
stand/efi/libefi32. Its nineteen-unit order, firmware ABI/flags and original
Make contract are qualified with eighteen raw matches and one isolated original
filename control. The ELF32/64 inspector is reusable and tested; independent
readelf counts cover all 2,461 allocated-target relocations. A discovered
multi-configuration runfiles collision is fixed with explicit artifact paths
and a runner analysis guard. See LIBEFI32-QUALIFICATION.md. Continue real
libsa32/EFI/interpreter/BIOS contexts; complete world/pkgbase/runtime and the
broader gates remain open. No test subset establishes whole-system completion.

### 2026-11-04: IA32 regular and private EFI standalone archives

The shared graph now builds the selected 191/260-member DO32 contexts. Raw Make
contracts match 188/257 members, with six matching original filename controls
and all symbol/identity/order contracts retained. Private generated headers match
the fresh isolated reference; all 451 actual compiler producers preserve CPU,
size, assertion and verifier policy. Fourteen wrappers pass. Existing regular
AMD64/ARM64/RISC-V member contracts and all fifteen EFI image bytes are preserved;
full regular archive/debug bytes remain different and explicit. See
LIBSA32-QUALIFICATION.md. Continue 32-bit interpreter/loader composition before
world/pkgbase aggregation; broader runtime/bootstrap/performance gates remain.

## IA32 interpreter archive checkpoint (2026-11-04)

All four regular/private EFI Lua and Ficl DO32 archives now use the source-owned
shared graph. Eighteen wrappers pass through the maintained frontend. Both Lua
archives match all 31 original member contracts directly. Each Ficl archive has
four direct matches and eleven assertion-filename controls; all raw identities,
symbols, relocations and member orders match. Actual 92 compiler/four archive
producer records retain ABI and private policy, and fifteen previous EFI images
are unchanged. IA32 EFI Lua now shares the existing native-width private source
admission policy; its independent post-fix Make reference is explicit. See
INTERPRETERS32-QUALIFICATION.md. Next integrate complete IA32 loader consumers;
full system/pkgbase/runtime/debug/performance gates remain open.

## Complete IA32 EFI Lua producer checkpoint (2026-11-04)

The source-owned graph now composes all 56 IA32 entry objects with private Lua,
EFI and standalone archives and the original linker script. Explicit architecture
rows prevent accidental inheritance of AMD64-only sources. Nineteen frontend
tests pass. A real-image test exposed and fixed elfcopy's unconditional EFI
PE32+ selection; IA32 is now PE32. Fifty-four entry contracts match raw Make;
two match isolated original filename controls. The complete corrected image
equals an independent Make compiler/link/converter control with six documented
filename controls across entry and libraries. Fifteen existing EFI images remain
unchanged. See IA32-LOADER-QUALIFICATION.md. Alternate IA32/BIOS consumers, full
debug/system/pkgbase/runtime/boot/bootstrap/performance acceptance remain open.

## BIOS platform archive checkpoint (2026-11-04)

The source-owned libi386 graph now builds all thirty original BIOS platform
objects with explicit i386 ABI, generated Teken prerequisite, ordered archive
and typed serial/debug/framebuffer controls. Default qualification passes twenty
tests. Twenty-nine raw object contracts match Make; Teken matches an isolated
original filename control. A nondefault frontend build passes and matches three
original compiler option controls, with all other member contracts unchanged.
Actual default/nondefault compiler input chains and both archive producers are
reviewed; all sixteen existing EFI images remain unchanged after source ownership
moves to the new package. See LIBI386-QUALIFICATION.md. Next compose the remaining
BIOS loader and GPT/ZFS/ISO/PXE programs; full debug/system/pkgbase/runtime and
performance acceptance remain open.

## BTX startup boundary checkpoint (2026-11-04)

The three BTX startup assemblers now use the verified i386 standalone toolchain,
an explicit ordered ET_REL link and debug split through public artifact aliases.
Their six compiler/full/stripped/debug allocated and symbolic contracts match
original Make directly; full file/debug bytes differ and remain open. Twenty-three
frontend tests pass, including the existing boot2 and legacy BIOS format suites.
The actual compiler/link/split chain is reviewed and sixteen previous EFI images
remain unchanged. See BTX-STARTUP-QUALIFICATION.md. A complete original BIOS Lua
reference passes its unchanged size limit with 16,600 bytes available. Next
compose its native entry/link/strip/BTX image and installation pipeline; complete
system, debug, pkgbase, runtime/boot and performance acceptance remains open.

## Complete default BIOS Lua producer checkpoint (2026-11-04)

The native source-owned graph now compiles all 36 selected BIOS entry sources,
links startup/three regular archives in original order, enforces the configured
505000-byte client bound and produces the real a.out/BTX image and installation
archive. Both BTX prerequisites also use explicit standalone producers and match
original Make bytes. Twenty-four frontend tests pass, including real archive
inodes/modes, exact-size and overflow handling. A site address/tighter-limit
profile passes; a maximum-1 full build is rejected. An inherited startup-object
debug link was demonstrated by a failing real-image test and removed in Make
and native strip recipes. The corrected client is 488328 bytes. Five original
compiler diagnostic-filename controls explain the raw Make differences; complete
controlled client/image bytes match. Typed archive metadata survives the ABI
boundary for aggregation; sixteen prior EFI images remain unchanged. See
BIOS-LUA-QUALIFICATION.md. Graphical/verifier/alternate-interpreter profiles and
remaining GPT/ZFS/ISO/PXE producers, full debug/world/kernel/pkgbase/bootstrap/
runtime/VM and broad performance acceptance remain open.

## Native LLVM build and test-root export follow-up

The initial 17-archive LLVM qualification now passes in
bazel-llvm-family-r2-20261104. Its only test is source_settings_test; this is not
the revised seven-contribution production aggregate or LLVM runtime acceptance.
The first test-root run failed because the existing generic Kyuafile export
allowed bin/sbin/libexec but omitted usr.bin. Its source export now grants the
same narrow usr.bin subtree access; bytes, automatic discovery and installation
policy are unchanged. Fresh qualification r2 passes through the maintained frontend. Its actual
archive matches the original two 0444 root/wheel files and 0755 tests directory,
including package tags and exact file bytes. The initial queued broader build
stopped on that failed prerequisite. After the corrected qualification passed,
the maintained frontend started bazel-usrbin-production-runtime-r1-20261104
with all six expanded runtime/configuration tests. That aggregate remains live
and unqualified. Evidence: bazel-usrbin-test-root-review-r1-20261104.
Complete world, aggregate modules and cross-architecture/system qualification
remain unfinished. Make remains default; BIP remains excluded.

## Original TAP installations in progress (2026-11-04)

The next installed-test batch carries eleven original suites, 259 fixtures,
thirteen TAP programs and eleven Kyuafiles through shared native installation
helpers. Existing apply/lastcomm manifests and all scripts remain unchanged.
Configured archive analysis passes; original Make references and native/archive
comparison are in progress. Actual suite runtime and the remaining installed-test
hierarchy remain open, with the full tests-enabled parent still explicitly gated.
This does not replace remaining full world/modules/pkgbase/bootstrap/runtime/
VM/performance acceptance. See USRBIN-FAMILY-CLOSURE.md.

## Native NIS administration and libc ABI checkpoint (2026-11-05)

All ten selected NIS administration owners now have source-owned native targets,
declared RPC/parser/header generation and original package installation entries.
The final maintained frontend run passes with 363 administration installation
archives and five selected test targets; three database unittest cases run in
the focused corrected-ABI qualification. Original Make selection accounts for
256 immediate owners in this profile. Three NIS programs have full component
metadata/data and strict ELF/debug comparisons, bound unchanged into the final
capture. Seven original linked references and all live NIS service/authentication
checks remain open; the bootstrap reference SDK lacks the selected NIS ABI.

A public source-built libc ABI interface prevents leaking implementation libsys
link inputs into packaged clients. Strict ELF comparison rejected the earlier
leaking candidate. Legacy libc link-interface consumers still require migration
and original ELF checks. The final NIS-disabled regression preserves 1413/1415
captured entries exactly; the remaining two reference only the updated manual
archive, with all other payload and metadata unchanged. The LDAP parser header
matches Make exactly; C differences are only generated #line paths.

See NIS-ADMIN-NATIVE-QUALIFICATION.md for immutable evidence and limitations.
Next close sendmail, installed-test and remaining world-family construction;
obtain independently matching original feature profiles for linked comparisons.
Complete world/kernel/module installation/pkgbase, cross-architecture, bootstrap,
runtime/VM and CPU/RAM/disk I/O/footprint/cache/sandbox gates remain open. Existing
format-5 frontend support suffices; the manual is updated. Make stays default;
BIP remains excluded.

## Native sendmail administration checkpoint (2026-11-05)

The remaining five optional SENDMAIL administration owners now build natively
through the source-owned parent. All five complete original component metadata/
manual and strict ELF/debug comparisons pass with fresh original internal-library
link witnesses. Three native PIE archives match original member order/symbols.
Companion tools correctly retain utilities ownership; the daemon remains
sendmail, setgid smmsp, with an explicit opt-in setuid metadata selector.

Combined NIS/SENDMAIL construction passes with 368 administration archives and
ten selected test targets. Actual configured selection matches all 261 immediate
original owners in this expanded profile. A no-TLS/no-wrapper/no-IPv6 profile
also builds and passes the six selected libsm/settings tests. See
SENDMAIL-NATIVE-QUALIFICATION.md for original references, immutable captures
and limitations. No live mail service or performance qualification is claimed.

The administration parent still rejects installed tests and other ABIs. Custom
sendmail compiler/link input configuration, complete world-family composition,
remaining original NIS/libc ABI checks, cross-architecture, install/pkgbase,
bootstrap, runtime/VM and CPU/RAM/disk I/O/footprint/cache/sandbox gates remain
open. Existing format-5 frontend support suffices; the manual is updated. Make
remains production/default; BIP remains excluded.

## CDDL production-family composition checkpoint (2026-11-05)

The new CDDL root and six explicit subparents compose 37 selected production
installation archives plus both build-only libdtotel archives. The final normal
frontend build passes all fourteen selected tests. Original owner selection
matches Make across five configurations; installed tests and other ABIs remain
explicitly gated. Full original lockstat and zhack component metadata/manual and
strict ELF/debug comparisons pass.

Aggregate failures exposed lockstat and ZFS command header dependency gaps and
a private libumem header leak. An attempted extra zhack link was rejected by
strict ELF comparison and removed from both Make and Bazel; implementation_deps
now keeps that header private, and original SPL wrappers are selected. Original
Make sources remain unchanged. DTrace, including its experimental section
selector, now follows CDDL's original disabling dependency. A real CDDL-disabled
build and ordinary untraced libutil/constructor test pass.

See CDDL-COMPOSITION-QUALIFICATION.md. Continue remaining full-world roots and
installed-test/ownership closure; complete original CDDL installation/pkgbase,
other profiles/ABIs, bootstrap, runtime/VM and comparative CPU/RAM/disk I/O/
footprint/cache/sandbox gates remain required. Existing format-5 frontend support
suffices and the manual is updated. Make remains default; BIP remains excluded.

## Secure production-family composition checkpoint (2026-11-05)

The secure root now owns four explicit production subparents and optional CA
certificates. Existing OpenSSL manifests gain five component archives, preserving
engine/provider recursion; both internal libpkgecc archives remain build-only.
The final normal frontend run builds 21 installation archives and two internal
archives, with twelve selected native test targets passing. Existing crypto/TLS,
module/archive, SSH configuration and direct SFTP transfer/read-only checks are
reused. No listeners, host authentication or host trust-store updates occur.

All 167 original CA certificate payloads and two original directory records
match fresh Make. The comparison caught and corrected directory ownership tags
(utilities for directories, caroot for files). Actual configured parent selection
matches original Make across six option profiles. All 86 production capture
entries remain unchanged when the additional runtime tests are selected.

See SECURE-FAMILY-COMPOSITION-QUALIFICATION.md. Full original OpenSSL/SSH/secure
installation/debug/pkgbase, installed tests, other profiles/ABIs and actual
authentication/boot trust initialization remain open alongside the remaining
world roots and system/bootstrap/package/VM/resource gates. Existing format-5
support suffices; the manual is updated. Make stays default and BIP is excluded.

## Eight-family integration and cached test artifacts (2026-11-05)

The combined bin/sbin/libexec/usr.bin/usr.sbin/lib/cddl/secure request now passes
with 1071 installation archives and all 34 selected test targets. Actual namespace
review verifies all captured archive/request hashes, accounts for duplicate
filegroup entries, and finds 23156 non-directory paths with no conflicting file
claims. This does not establish complete installed-world or directory/pkgbase
parity.

The integration exposed a real optional runtime mismatch: SSH tests supplied
bootstrap libc to NIS-enabled libwrap. Their declared runtime now selects native
libc/libsys for NIS; bodies and expectations are unchanged. The final default
secure regression passes twelve tests and preserves all 86 production outputs.

A separate qualification failure rejected missing cached libsm test executables.
Explicit test-target/default-group experiments failed and were removed. The
maintained driver now records an ordinary Bazel build of the configured test
executables with unchanged flags, then verifies the original test BEP digests
when freezing outputs. Test caching remains enabled; no tests run again in this
phase. The final receipt binds both commands and companion logs. See
EIGHT-FAMILY-COMPOSITION-QUALIFICATION.md.

Continue remaining world roots and original installed-test/ownership closure,
then complete kernel/module/pkgbase/bootstrap/hardware/publication, other ABI,
real runtime/VM and comparative CPU/RAM/disk I/O/footprint/cache/sandbox gates.
The maintained backend and manual are updated; no C/frontend input-schema change
is needed. Make remains default; BIP remains excluded.


## MIT Kerberos integration checkpoint (2026-11-05)

The final nine-family r3 build passes 52 selected tests and namespace review.
Native production parents include both original internal-library variants;
PIE consumers use the proper profile variant and callers own their link closure.
Current original Make comparisons pass profile archive members/symbols, empty
internal installations and complete changed gssd/KDC component/ELF/debug contracts.
The public generated profile header retains one recorded filename-comment
variation; byte identity is not claimed. See MIT-FAMILY-COMPOSITION-QUALIFICATION.md.
Remaining full world, installed tests/metadata/pkgbase, cross-architecture,
bootstrap, runtime and performance gates remain open. Make remains default.


## Shared base data checkpoint (2026-11-05)

The six new native data owners pass complete original component inventory,
metadata, exact payload, symlink and tar checks. Their option-dependent files and
Make test fragments also pass independently configured original comparisons.
Missing directory metadata and an overly broad package-wide mtree selection were
caught and corrected in the declarations; no comparison exception was added.
Continue complete share and other remaining world roots, then installed-world/
package/bootstrap/runtime/performance qualification. See
SHARE-DATA-INSTALLATION-QUALIFICATION.md for retained evidence and limits.


## VT/shared hardware data checkpoint (2026-11-05)

Source-owned VT/font/keymap, SNMP MIB and iwm firmware parents now build through
the maintained frontend. All four complete original Make component inventories,
metadata, file payloads and archive serialization pass. Font conversion uses the
existing source-built execution-platform tool and declared runtime. These data
components add no service/hardware runtime acceptance and do not complete share.
Continue remaining share/world composition and the outstanding system gates.
See VT-FIRMWARE-SNMP-INSTALLATION-QUALIFICATION.md.


## Native manual inventory checkpoint (2026-11-05)

Sections 1/3/3lua/5/6/7/8/9 now declare all selected pages and alias relationships
natively. Both compressed/default and raw/split/opposite-option Make comparisons
pass complete metadata, exact payload and staged inode-equivalence checks.
The initial invalid nested selects were replaced by normal condition groups;
an interrupted original reference remains rejected and stable references pass.
No Python implementation changes are needed. Continue section 4 and remaining
share/world composition and the open installed-world/package/bootstrap/runtime/
performance gates. See SHARE-MANUAL-SECTIONS-QUALIFICATION.md.


## Shared-manual parent checkpoint (2026-11-05)

Complete configured share/man source construction now passes through the normal
frontend and an independent original Make subtree comparison in two profiles.
Native section-4 CPU/feature choices and architecture-directory aliases preserve
actual source policy; unsupported CPUs are incompatible at the endpoint. The
manual_architectures input has explicit canonical inventories, with bounded
original-query/payload checks for each nondefault choice. Cross-capture namespace
review covers 1135 archives/27823 file paths without conflicting claims and keeps
the prior eight manual contributions identical. Continue docs/examples/zoneinfo,
remaining world roots and the open installed-world/package/bootstrap/runtime/
resource gates; Make remains default. See SHARE-MANUAL-PARENT-QUALIFICATION.md.


## Shared documentation parent checkpoint (2026-11-05)

Normal (nine archive) and test-doc/no-compiler/no-IPv6 (eight archive) native
parents match complete original Make staging. Book inventory guards remain active;
original notices/package assignments are retained. Duplicate legal-directory
claims were inspected and reconciled only when metadata and repetition counts
match; files cannot be duplicated through this path. The maintained frontend's
existing schema suffices and its manual is updated. Continue examples/zoneinfo,
locale and world composition plus the outstanding system qualification gates.
See SHARE-DOCUMENTATION-QUALIFICATION.md.


### Source example inventory defects recorded before correction

Read-only original Make queries confirm SER_BOOTFORTHPACKAGE,
SER_MAC_ABACPACKAGE and SER_JAILSPACKAGE all resolve to examples: their apparent
package declarations use names not consumed by the SE_<normalized-directory>PACKAGE
lookup (SE_BOOTFORTH_PACKAGE, SE_MAC_ABAC_PACKAGE and SE_JAILPACKAGE). The OES
example exists, but oes is absent from SE_DIRS/FILESGROUPS; only the legacy LDIRS
cleanup list mentions it, inside the Bluetooth block. Native parity with that
inventory alone would preserve an uninstalled OES sample. Correct the maintained
Make declarations and native inventories together, then compare complete example
metadata/payloads and selected option branches. No example implementation change
has been made in the documentation checkpoint.


## Example source corrections and native construction (2026-11-05)

The previously recorded group-name mismatches and missing OES file group are now
fixed in maintained Make and represented natively. All selected production sample
paths, packages, modes, exact payloads and tar records match complete independent
Make staging, including the optional-groups-disabled profile. The OES file remains
present with Bluetooth disabled. The full endpoint does not claim the missing
installed ATF/plain/TAP/Googletest examples: its actual tests-enabled request fails
explicitly and retains FAILED.json. Continue those tests, zoneinfo/locale/world
composition and outstanding package/bootstrap/runtime/resource qualification.
See SHARE-EXAMPLES-QUALIFICATION.md for evidence and limits.

### Source distrib-dirs correction — 2026-11-06

The first privileged full-package fixture exposed missing /dev before installation.
Fix the actual native world composition, not the fixture: complete source MTREES
now generate an archive and typed ownership sidecar. Exact original Make checks
pass for 904 physical definitions and 454 unique claims. Two original NLS aliases
are now declared and pass enabled/disabled metadata comparison. All eleven native
tests and independent inspection of all 445 archives / 32,512 payload paths pass.
See WORLD-DIRECTORY-LAYOUT-QUALIFICATION.md. The disk-backed 2GB VM retry is live;
its unchanged service baseline passed, package installation remains pending.
Next: finish real install/reinstall and new-layout complete manifest comparison,
commit the maintained VM qualification suite with actual results, then normal
startup/new-version upgrade and the remaining full-system/platform/performance gates.

Updated evidence: all 445 complete original Make package manifests match after
this layout correction (same native corpus, zero differing fields). Bounded
TESTS-enabled native layout/test also passes, including both test roots. Neither
result establishes full independent Make-world or normal installed startup.

Maintained VM suite checkpoint: complete package-derived disk assembly and native
ATF driver are implemented with root confined to the disposable VM. The current
2GB retry is live, with final install/reinstall acceptance pending. See
WORLD-PACKAGE-INSTALL-VM-QUALIFICATION.md for exact scope, input paths, resource
limits, retained failures and the outstanding normal-startup/upgrade gates.

### Shared module products and first base-family composition — 2026-11-06

Complete package reinstall now passes with the intended native reaper helper;
all 445 packages, both 32,512-file/1,369-directory checks, state and cleanup pass.
Independent review closes the unused-helper provenance gap without relabeling old
results. Normal startup and real version upgrades remain separate gates.

Typed module products now compose base installation from the same configured
runtime/debug Files used by standalone installation, with one source attribute
policy. A source-owned six-member FireWire parent and real NewReno checks pass.
Ten native test targets pass, including custom/inline paths and invalid/collision
rejection; a real debug-disabled branch is separately checked. The configuration
transition candidate was replaced before commit to avoid its extra configured
product. See KERNEL-MODULE-PRODUCTS-QUALIFICATION.md. Continue actual source-owned
conditional module traversal and coherent full kernel/world pkgbase composition;
all normal startup/upgrade/platform/bootstrap/cache/sandbox/reproducibility/debug/
resource/hardware/publication gates remain open. Make stays production/default.

### Current AMD64 loader comparison checkpoint — 2026-11-14

The fresh AMD64 SDK/loader run completed with a passed receipt:
`bazel-current-sdk-loader-native-amd64-r1-20261114`. Independent original Make
loader build/install R1 also passes. The maintained comparison finds equal
runtime-archive member order and symbols, matching linked ELF public metadata
and hardening, and exact allocated/symbol/relocation contracts for 50 of 55
local/provider objects. Four remaining objects embed relative diagnostic source
paths where Make embeds `/usr/src/...`; the fifth is the DTrace provider.
Both actual providers validate all ten probe schemas, companion-object
relocations and patched instruction sites. Their provider bytes and generated
aliases differ. Raw object, linked-section and debug differences remain retained,
not normalized or declared byte parity. Evidence:
`bazel-current-loader-amd64-parity-r1-20261114`. This is not loader runtime, full
DWARF or complete installed-system qualification. The prepared ARM64 run is live.

Frontend review: these source-owned target/test additions use the maintained
`build-bsd bazel-test --bazel-inputs` workflow; no production backend, policy,
signing, stage-verification or publication default changes are required.

Current AMD64 follow-up: all ten startup objects match the refreshed original
Make FILES inventory and allocated/symbol/relocation contracts; raw debug bytes
differ. Evidence: `bazel-current-startup-amd64-parity-r1-20261114`. Complete loader
component install metadata matches all nine logical records, including physical
archive flags and actual hardlinks; only loader/debug regular-file payload hashes
differ. Evidence: `bazel-current-loader-amd64-install-parity-r2-20261114`. The
first install diagnostic rejected libarchive's type-zero hardlink headers; R2
correctly requires their regular payload targets and preserves raw header types.
No product code was relaxed.

The next ARM64 libthr candidate is staged outside the source tree while the
loader run is live. Its source-owned architecture selections match all 60 ordered
objects in the actual Make traversal, including the generic `_umtx_op_err.c`
wrapper and no AMD64 `thr_machdep.c`. Evidence:
`bazel-arm64-thr-candidate-r2-20261114`. This is an unapplied declaration review,
not a successful native build. The independent ARM64 and AMD64 libthr Make install references pass. Independent ARM64 libelf, libkvm, libjail and ATF references also pass; the portable library declarations remain staged outside the source tree until the loader run and descriptor link-order rerun complete. Runtime, debug/provider parity, installed tests and the
remaining complete-world gates are still required. No frontend input/default,
signing or publication requirement changes in this checkpoint.

Descriptor follow-up caught a genuine DT_NEEDED order mismatch against both
current original Make programs: ATF must precede kvm/pthread or jail, then libc.
The source-owned link sequence is corrected; a fresh native rerun and exact
metadata comparison remain required. Earlier build/host-test success is not
reclassified as link parity. Evidence:
`bazel-current-descriptor-amd64-parity-r1-20261114`. This unrelated package edit
does not change the selected inputs of the live ARM64 loader run. No frontend
input/default or backend-target interface changes are required.

The descriptor link-order rerun request is prepared at
`bazel-descriptor-link-order-request-amd64-r1-20261114`. The maintained frontend
correctly rejects a concurrent invocation with its build-lock busy error; that
attempt ran no qualification. Retry after the live ARM64 loader job terminates.
The next source changes remain staged in
`bazel-arm64-thr-candidate-r2-20261114` and
`bazel-arm64-foundation-candidate-r1-20261114`, with a 24-target maintained input
request in `bazel-arm64-foundation-request-r1-20261114`. These declarations and
ARM64 descriptor binaries are not yet qualified.

Resource-accounting audit: the current frontend times the Bazel client while
the persistent JVM server is reparented to PID 1. Client `time -l`/wait4 rusage
therefore cannot establish total build CPU or aggregate memory. A live
process-tree observation and bound source review are retained in
`bazel-resource-accounting-review-r2-20261114`. Controlled qualification must
include the identified server and descendants, baseline lifetime counters,
sample aggregate RSS, distinguish logical block operations from physical device
bytes, and measure retained SDK/objects/cache/scratch separately. Cold and warm
incremental workflows both matter; switching only the benchmark to batch mode
would not qualify the ordinary persistent-server workflow. No performance gate
is closed by current resource observations. No runtime/frontend policy is
changed during the live loader build.

### ARM64 loader and descriptor correction accepted checkpoint — 2026-11-14

The fresh ARM64 loader run terminates passed with 75 immutable captured files
and 39 Python checks across three host-artifact targets. All captured test
report hashes verify. No ARM64 target binary executes on the AMD64 host. All
ten startup-object allocated/symbol/relocation contracts match Make. The loader
runtime archive member order/symbols and linked ELF metadata/hardening match;
50 of 55 local/provider object contracts match exactly. The four diagnostic
literal paths and raw DTrace provider differences are retained. Both actual
providers have equal ten-probe schemas and symbol-relative probe locations,
with validated companion-object relocations and patched instruction bytes.
All nine loader install metadata records match, including archive flags and
links; loader/debug payload hashes still differ. Evidence:
`bazel-current-loader-arm64-parity-r1-20261114`,
`bazel-current-loader-arm64-install-parity-r1-20261114`, and
`bazel-current-startup-arm64-parity-r1-20261114`. This does not close full
DWARF, target execution, full-world or any entire completion gate.

The descriptor link-order correction is verified in a fresh terminal native
AMD64 run: both programs now match original Make ELF metadata, hardening and
DT_NEEDED order. Four selected test targets pass (39 Python checks plus one ATF
host case), with hash-verified captured reports. Raw program/debug differences
remain retained; the twelve root cases remain unexecuted. Evidence:
`bazel-descriptor-link-order-native-amd64-r1-20261114` and
`bazel-current-descriptor-amd64-parity-r2-20261114`.

Frontend review: existing maintained format-5 target inputs and `bazel-test`
cover both changes. No new CLI, security-policy, signing, stage-verification,
hardware or publication interface/default is required. Make remains production.

### Tier 1 pthread and foundation libraries — 2026-11-14

Source-owned ARM64 selections now cover libthr, libelf, libkvm, libjail, ATF-C
and the existing descriptor programs. The real Make inventories select the
ARM64 pthread header and generic `_umtx_op_err.c`, omit AMD64 thr_machdep.c,
and preserve 60 ARM64 / 61 AMD64 pthread archive members. The special umtx
source receives the same library definitions Make supplies in both languages.
The initial nested-select declaration failed analysis and is retained as R1;
R2 builds all 24 targets, then strict installation comparison exposes libelf's
missing debug-directory package claim. The maintained debug-directory helper
restores that actual Make claim; the comparison is not weakened.

Final native ARM64 R3 passes 24 targets, captures 93 unique files and passes
39 Python checks in three host-artifact targets. The AMD64 regression passes
25 selected targets, captures 95 unique files and passes those checks plus the
safe descriptor ATF case. All captured test report hashes verify. All five
archives match Make member order/symbol contracts; all five DSOs match ELF
metadata/hardening; all 240 component install metadata records per architecture
match, including numeric IDs, names, modes, tags, flags and actual links.
Both descriptor programs also match Make ELF metadata and dependency order on
ARM64. The library batch uses the maintained build-bsd format-5 workflow; no
CLI/security-policy/signing/hardware/publication interface or default changes.

The complete static archive inventory contains 152 ARM64 / 153 AMD64 members,
with actual machine IDs checked. Exact allocated/symbol/relocation contracts
match 95 / 96 respectively. ARM64 raw allocated-byte differences outside the
provider are source diagnostic strings (including generated libelf source
paths); raw contracts/relocations remain retained. The pthread providers match
all fourteen schemas and symbol-relative locations, with companion-object
relocations and actual patched instruction checks on both architectures. These
are metadata/site checks, not live registration or firing. No artifact is
rewritten to manufacture equality; archive/DSO/debug payload hashes still differ.
Full DWARF, complete tests-enabled payloads, the twelve root cases, ARM64 target
execution and the other six-gate requirements remain open.

Evidence: bazel-arm64-foundation-native-r3-20261114,
bazel-amd64-foundation-native-r1-20261114, per-architecture foundation-parity,
foundation-install-parity, foundation-object-contracts and foundation-literal-review
records, and per-architecture thr-provider-parity records. Original Make
references and failed diagnostics remain retained. Make remains production/default.

### Tier 1 C++ ABI, standard library and unwinder — 2026-11-14

The next source-owned batch enables ARM64 libcxxrt, libc++ and libgcc_s.
It reuses the existing nine ABI and 55 C++ source inventories and selects all
151 ARM64 builtins from the compiler-runtime inventory. Original Make recipe
metadata confirms that fp_mode.c resolves to aarch64/fp_mode.c; the first source
review's spelling-only diagnostic failure is retained. Both selected platforms
use LP64 new/delete names. libgcc_s preprocesses its version map for the actual
target, enables the legacy frame API only on x86, and uses the correct
architecture's builtin sources. Math headers select ARM64/quad-precision or
AMD64/extended-precision directories; this does not yet port the full libm
producer. Only the six additional builtin sources required by libgcc_s gain
visibility to that package; the LSE assembly interface remains restricted.
The initial native analysis exposes this missing visibility and is retained.

Final ARM64 R2 passes all 14 selected targets and three host-artifact test
targets (39 Python checks), with 19 immutable unique files captured. AMD64 R1
passes 19 selected targets and eight test targets (39 Python checks plus five
existing native runtime programs), with 23 unique files captured. Captured
report hashes verify. The native unwinder test checks that dlopen/dlsym returns
functions from the newly built DSO, ordered caller frames and callback stopping.
The static/shared demangler and C++ runtime tests also pass; the existing C++
runtime fixtures still declare the bootstrap SDK unwind runtime, so these are
not evidence of an independently bootstrapped C++ stack. ARM64 target binaries
are not executed on this AMD64 host.

Both architecture comparisons pass archive member order/symbol contracts,
shared-library ELF metadata/hardening and byte-identical generated ABI maps.
All 1,681 install metadata records per architecture match original Make, including
numeric ownership, names, modes, tags, flags and links. Headers/linker scripts
match in bytes; compiled archive/DSO/debug payload differences remain retained.
These results do not establish complete object-code/DWARF equivalence or full
world/kernel/pkgbase/runtime/configuration qualification. Frontend review found
no new CLI/input, signing, stage-verification, hardware or publication interface
required: the existing maintained format-5 bazel-test workflow covers this batch.

Evidence: bazel-cxx-native-aarch64-r2-20261114,
bazel-cxx-native-amd64-r1-20261114, bazel-cxx-parity-{aarch64,amd64}-r1-20261114,
bazel-cxx-install-parity-r1-20261114, bazel-cxx-make-references-r1-20261114 and
bazel-arm64-cxx-declarations-r2-20261114. All six gates remain open, Make remains
production/default, and no host installation or reboot occurred.

### Historical ARM64 component ledger before execution reset

The former detailed current row is retained here for evidence history; the
short current ledger and execution sequence above govern the remaining work.

| 6. ARM64 Tier 1 | Complete libc static/PIC archives and DSO build in optimized-production and portable-debug profiles with exact Make order/non-provider object contracts and shared metadata. Nonshared now matches all 12 Make objects and its install contract; public/shared and static ARM64 clients link, NOSSP matches 1,437 ordered members apart from retained provider differences, all NOSSP probe sites and six loader-extracted objects validate. Native R3 passes the explicit host-only symbol visibility test; no ARM64 client is executed. The refreshed production Make world at 4f0683e6286 and its recorded profile complete, including tests. The earlier R7/startup comparison is dated evidence; refreshed SDK, all ten startup-object contracts and focused loader metadata/install/provider comparisons now pass; raw source-path/provider/debug differences remain recorded. Focused five-library/descriptor builds now pass on ARM64 and AMD64, with 240 original Make install metadata records per architecture matching. C++/unwind component builds also pass on both platforms, with 1,681 original Make install metadata records per architecture matching and byte-identical generated ABI maps. AMD64 demangling, native backtrace and static/shared C++ runtime tests pass. Focused libm/static-unwind builds now pass on both platforms: all 277 ARM64 and 280 AMD64 math object contracts and both ABI maps match Make; 322 component install metadata records match per architecture. AMD64 static/shared math smoke tests pass. The 47-program original math suite now builds/installs on both platforms, with all 463 AMD64 ATF bodies passing and complete program ELF metadata matching Make on both platforms. The 462 ARM64 math bodies now execute under BSD user-mode QEMU with identical original Make outcomes: 448 passed, 13 existing expected failures and one unsupported-FP-trap skip. Full ARM64 VM/kernel qualification remains open. Current five-component crypto/compression builds and crypt test installs also match Make archive/ELF/ABI-map and 188 install metadata records per architecture. Target execution outside the focused emulated math scope remains unqualified. Eight selected data/configuration/ATF libraries and 14 installed test programs now match focused Make archive/ELF/map/install contracts (121 metadata records each platform); AMD64 reports 160 passing results and one ASan-only skip. The datagram sysctl case remains VM-only. Five device/output libraries, the CSV plugin and two original CAM test programs now match focused Make archive/ELF/install contracts (215 records each platform); AMD64 parsing/formatting/plugin/string checks pass, while live device/I/O and ARM64 execution remain unqualified. Locale/termcap generation now uses shared explicit target byte-order selection and execution-runtime dependencies: four complete component archives match all 785 original Make metadata records and every 184 regular payloads on each Tier 1 architecture. Library aggregate traversal now admits both Tier 1 architectures and follows Make for x86 vgl/Intel PT versus ARM OpenCSD, including PMC on/off. Focused PMC/OpenCSD/internal support builds match 123 install metadata records each, byte-identical generated event tables and archive/shared contracts, with diagnostic-path differences retained. Full ARM64 world R3 still rejects incompatible transitive children; the earlier 1,534-record diagnostic predates aggregate traversal and is not a remaining-program count. The entire all-options-on /bin aggregate now builds on ARM64: 42 archives, exact 1,469-path Make install inventory/metadata, 41 passing executable ELF comparisons, and matching linked DTrace schemas/counts in 22 programs / 70 locations. No ARM64 /bin program executes in that aggregate run. Fresh AMD64 bin/helper qualification now passes five test targets / 59 Python cases and captures 103 unique files. Fresh ARM64 bin plus four module-tool archives pass three host targets / 40 Python cases and capture 108 files; both complete bin installation and 41-program ELF/provider comparisons pass. The four ARM64 module tools match 16 component install records and all ELF/provider contracts. Ten further portable libraries, libc/libmd installation aggregates and declared fresh-account ARM64 data now pass focused qualification: 14 archive/six DSO contracts and 1,737 complete Make install records per platform; AMD64 elftc/stdbuf runtime tests pass. The capability/FIDL stack adds nine focused archive/shared/install comparisons (344 records per platform), all 29 cross-target IRs and five static DTrace providers (65 locations each platform); its real host/target runtime defect is corrected. These are selected component checkpoints, not complete world or native bootstrap qualification. Full loader runtime, full DWARF, native world/kernel/modules/pkgbase/configurations/runtime remain open. RISC-V stays nonblocking Tier 2. |
