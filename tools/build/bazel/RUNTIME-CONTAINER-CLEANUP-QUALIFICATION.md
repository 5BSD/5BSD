# Runtime-container cleanup qualification

## Confirmed defect

The retained November 7 strict upgrade VM R2 fails with EROFS from unlink/rmdir:
Switchboard swept scratch directories before rc made root writable. A clone of a
running BE contains live scratch directories, so ignoring those errors left
existing entries that fresh-only container creation correctly rejected.

## Implementation (2026-11-11)

Switchboard now prepares runtime storage once, immediately before its first
native launch, including an on-demand provider requested during rc. Normal rc
has made storage writable before these requests. RC compatibility commands do
not trigger native scratch preparation. A request before storage is ready still
fails; there is no remount, temporary-filesystem or permission fallback.

Preparation sweeps old entries and recreates the live-marker directory before
any provider can receive its descriptor. It marks success only after both steps
succeed. Once native services may exist, it never repeats the global sweep.
Per-service stop cleanup remains scoped to that unit's leaf. Creation retains
its existing fresh-only semantics; stale directories are never adopted.

The separate descriptor-based cleanup module checks failures, avoids symlink
traversal and filesystem crossings, and uses an allocated traversal stack so
service-controlled nesting cannot overflow the manager's C stack. Allocation/fd
exhaustion returns an error. Callers must own the namespace against concurrent
mutation. This is runtime lifecycle handling, not BIP or protection from root.

Both maintained Make and native Bazel source/test declarations include the new
module and regressions. Existing format-5 frontend target/test inputs suffice;
no C frontend option/backend change is required. Make stays production/default.

## Evidence and limits

- `bazel-run-cleanup-make-tests-r2-20261111/receipt.json`: all three real host
  ATF cases pass: nested directories/symlink escape protection/fresh replacement,
  actual Capsicum denial followed by retry, and invalid leaf names/idempotence.
- Its `switchboard-build.log` records successful maintained Make compilation and
  linking of the actual traced Switchboard binary, including the cleanup module.
- R1 host tests retain a file-flag setup failure. The final denial test uses real
  Capsicum rights restrictions, requiring neither root nor file-flag changes;
  there is no test skip or fabricated syscall success.
- Native frontend attempt `build-runs/20261111T125603Z-34949` refuses the old SDK
  before compilation because its recorded `tmp/usr/bin/clang` origin is missing.
  No recorded origin, receipt or snapshot was edited to suppress verification.

All evidence paths are below /usr/obj/usr/src. These checks do not establish
native Bazel compilation or a successful upgraded boot. NEXT: recreate explicit
SDK inputs, run the native regressions and production build, then repeat the
complete signed-package VM upgrade with manifest-derived service-health coverage,
rollback, shared-data persistence and unused-BE deletion. Other closeout gates
remain in COMPLETION-PLAN.md. No host installation or reboot was performed.

## SDK prerequisite rebuild

The new source fix is committed as b2e1c8d7e3e. The Make-built executable/test
captures and source hashes are retained in the R2 host-test directory's
`build-review.json` and `captured/`.

SDK preparation also confirms that the current Make world selected a system
compiler wrapper, while the maintained qualification planner requires a genuine
staged Clang executable and resource tree. A proposed path-only input extension
was insufficient and was removed without landing; no planner check or old SDK
receipt was relaxed. Failed preparation logs remain in
`bazel-run-cleanup-sdk-r1-20261111` (the first attempt also correctly refused a
nonfresh output directory). Individually verified bootstrap-tool copies prepared
for that experiment are not used by the running rebuild.

`bazel-closeout-make-toolchain-r1-20261111` retains the command and live build log
for the maintained Make `toolchain` target, using 16 jobs, production malloc and
explicit WITHOUT_SYSTEM_COMPILER/WITHOUT_SYSTEM_LINKER. This rebuilds the staged
compiler, resources and SDK libraries under the standard object root. It does not
install the host or establish native Bazel bootstrap. Once it succeeds, regenerate
the SDK with the maintained planner/materializer, then rerun native tests and the
service-aware upgrade. The toolchain build is still in progress at this update.

## Manifest-derived readiness coverage

The package-runtime runner now defines a format-5 plan with explicit installed
bundle roots, a captured native inventory helper and a service deadline. The
helper calls the real libcapbundle parser; its inventory determines all required
boot labels. Baseline, upgraded boot and rollback require those labels running
with PIDs and no pending cleanup. Manager counts, duplicate rows and terminated
output detect incomplete status responses. New boot declarations require no
runner list change. Post-boot non-config package checksums run as well.

Host `service-health-test.py` passes six methods, including strict policy input checks, newly added boot
units, stopped/missing services, duplicates and truncated manager output.
`bazel-service-inventory-host-r1-20261111` builds the actual C helper against host
libraries and passes three fixture methods using real boot/on-demand manifests
and malformed/missing bundle roots. These are host results; native Bazel tests
and actual format-5 VM execution remain pending the SDK rebuild. The frontend
uses its existing format-5 target/test interface, with no new C frontend option.
This is readiness and a useful manager RPC, not per-provider operation coverage
or on-demand activation qualification. Those remain part of gate 1.

## Bounded traversal work and completed bootstrap prerequisite

The explicit cleanup stack now grows geometrically, with overflow/allocation
checks. Deep service-controlled nesting therefore does not cause quadratic
frame-array copying. `bazel-run-cleanup-make-tests-r3-20261111/receipt.json`
retains the updated source hashes, executable and all three passing host cases,
including 80 nested levels and a real denied-cleanup retry. Native/VM acceptance
is still pending.

The maintained Make toolchain rebuild completed with exit zero; its receipt and
full log are in `bazel-closeout-make-toolchain-r1-20261111`. This is a bootstrap
prerequisite, not a controlled Make/Bazel benchmark or full world qualification.
Fresh SDK planning succeeds in `bazel-run-cleanup-sdk-r3-20261111`; materialization
is running. Its existing declarative tool configuration explicitly selects
/usr/bin/llvm-objdump (LLVM 21.1.8) because the old normal-object-tree disassembler
was cleaned. The compiler/resource-tree validation is unchanged.

Read-only host inventory confirms the Memory unit has no published IPC endpoint.
Source inspection also finds argument-validation/test-double client cases, such
as libdevicecmp/tests/devicecmp_api_test.c and the daemon-runtime suites described
in their README. These must not substitute for useful operations against the
installed production providers. Host inventory is diagnostic discovery, not VM
service acceptance; the operation coverage portion of gate 1 remains open.

## Native source build and regression acceptance

`bazel-run-cleanup-native-r3-20261111/receipt.json` passes the actual traced
Switchboard build, captured native inventory helper and all 11 selected test
targets. This includes the three cleanup cases, fresh-only creation, real native
parser fixtures and strict readiness/policy validation. Ten targets were reused
from the preceding run; the previously unexecuted inventory fixture now runs and
passes. This is not full-world or VM upgrade acceptance.

The retained R2 native attempt correctly fails while linking the new inventory
helper: its initial PIE declaration selected a non-PIC static crypto archive.
The helper now declares capbundle_shared through native cc_binary.dynamic_deps,
which supplies the shared-library dependency closure. PIE and linker checking
remain enabled; no compiler warning/error or test was disabled. Fresh SDK
materialization and all strict origin/runtime verification succeed. NEXT: build
the complete current-source candidate and run the service-aware VM upgrade.

## Current-source candidate graph blockers

The fresh current-source full candidate R3 fails analysis because DQ's selected
module has no BUILD producer. Commit 29782836293 adds the normal module producer,
standalone DEV_DQ option, and declared MAC/SipHash headers. Native DQ R2 passes
built-in objects and module/CTF/debug output, with no selected tests. Full
candidate R4 then fails analysis because mac_abac's legitimate opt_dq.h dependency
is not visible. Its Make module also lists opt_dq.h and its source gates served
hooks on DEV_DQ. The AMD64, ARM64 and RISC-V option targets now admit this named
consumer; their source options remain generated from the selected kernel config.
No broad public visibility, source omission or fixture alternative is introduced.
The existing build-bsd target interface, config extraction and package helpers
require no interface change. Full current-source build/VM qualification remains
pending; ARM64/RISC-V visibility edits do not prove those platforms build.

The next VM run has an explicit service policy at
`bazel-system-service-policy-r1-20261111.json`, validated against the retained
baseline image and native R3 helper capture. It derives boot-unit requirements
from installed manifests. It is not per-provider operation qualification.

## Upgrade inventories across changing package sets

Upgrade policy format 2 selects the baseline package-family capture explicitly.
The old image's package count and expected version must agree with it; actual
baseline/rollback databases are checked against that old set. Candidate checks
use the new signed complete repository. Newly added base packages are requested
with normal pkg install and obsolete names removed with normal pkg delete inside
the inactive BE, followed by exact version-set and checksum checks. No package
list is embedded in the runner. The existing target/test interface is sufficient;
the VM runner README and frontend manual document the new policy input.

`bazel-upgrade-inventory-host-r2-20261111/receipt.json` passes all three policy
validation methods and resolves the actual 447-package baseline family plus the
retained 447-package signed repository. The initial R1 input validation failed
because the new validator assumed a list rather than the maintained name-keyed
family object; R2 uses that real schema. Neither run executes guest package
transitions. Native regression execution, new current-candidate inventory and
actual added/obsolete-package VM transitions remain unqualified.

Full candidate R5 passes complete graph analysis, then fails compiling
fdesc_vnops.c because its recently added MAC framework include is undeclared in
the native target. Its failed result is retained at
`bazel-system-upgrade-native-r5-20261111/FAILED.json`. The builtin vnode target
and AMD64/ARM64/RISC-V module source groups now declare the actual framework
header provider. No source include, MAC hook, warning or failure is suppressed.
Focused native compilation and the next full candidate remain to be qualified.
These are maintained BUILD dependency edits; the existing frontend/package
interfaces require no additional options.

## Focused fdescfs and upgrade-policy native acceptance

`bazel-fdescfs-native-r1-20261111/receipt.json` passes the actual AMD64 module
source group, builtin vnode objects and native upgrade-policy test. The test
uses the declared module/comparator inputs and executes its three Python methods;
this does not qualify real guest added/obsolete-package transitions. The next
full candidate must use the newly committed kernel revision and preserve the
failed full R5 evidence. No host installation or VM run occurred in this step.

## NFS module closure correction

Full R6 is terminal failed: nfs_nfsdport.c includes dev/dq/dq.h, absent from the
module's declared inputs. Review found nfs_commonport.c's module closure also
omitted it; both builtins already include the DQ header provider. Both module
source groups now declare the public DQ ABI provider, shared with their ARM64
and RISC-V declarations. No include, hook or source selection was removed.
`bazel-nfs-dq-native-r1-20261111/receipt.json` passes both actual AMD64 module
products with CTF/debug processing. It selects no tests, and is neither NFS
runtime qualification nor ARM64/RISC-V qualification. Existing module/package
backend and frontend target interfaces require no additional options.

## Performance evidence boundary

The existing /usr/bin/time -l around the Bazel client does not measure the
pre-existing server and its compiler children as one complete build workload.
Do not use its CPU or maxrss fields as whole-build comparison evidence. Likewise,
a maximum per-process RSS is not the simultaneous aggregate memory peak, and
block-operation counts are not physical device byte counts. The dedicated
single-action resource runner remains scoped to the child actions it owns.

For the later controlled comparison, retain explicit Bazel JSON profiles and
server/JVM measurements alongside whole-workload CPU/RSS and disk-I/O accounting,
with consistent source/config/cache conditions and external load accounted for.
System-wide profile samples alone do not attribute load on this shared host.
Bazel's maintained profiling documentation is at
https://bazel.build/advanced/performance/json-trace-profile and
https://bazel.build/advanced/performance/build-performance-breakdown .
No performance gate is closed by the ongoing correctness rebuilds.

## Linux compatibility closure and complete failure collection

Full R7 is terminal failed on linux_stats.c's MAC framework header, now a direct
dependency of its native module source group. The full linux64 module product
passes `bazel-linux64-mac-native-r1-20261111/receipt.json`, including CTF/link/debug
processing, with no selected tests. This is build acceptance, not Linux runtime
or cross-platform acceptance. The related Linux files were reviewed for the
same include; their existing dependencies already provide it.

The maintained format-5 qualification backend now passes Bazel --keep_going.
This lets independent actions complete and reports all reachable failures in one
run. The unchanged nonzero-exit check still rejects any such run, and no partial
build is accepted as passed. The actual native linux64 command/receipt binds the
updated backend. Existing host source-settings and source-test-inventory suites
pass 29 and 23 methods respectively. The frontend manual documents the behavior;
its C interface and production Make selection need no change. Full R8 is next.

## Correct Memory operation model and pending VM consumer

The native service_operations target now implements time, sysctl, notification
round-trip and memory-pressure observation cases. It remains unlinked/unexecuted
under native qualification and the VM runner has not yet been wired to invoke it.
Host strict syntax checks pass in
`bazel-service-operations-host-syntax-r2-20261111/receipt.json`; this is not provider
acceptance. The existing frontend target selection is sufficient; the manual and
runner README describe the new captured-consumer target and its limits.

Earlier notes calling BSDMemory a memory-allocation factory were incorrect.
BSDMemory.c and its actual Unit.ucl show that it samples three Sysctl counters and
publishes authenticated reserved Notify state, with no published IPC endpoint.
The memory client waits boundedly for valid pressure state, requires ordinary
consumer set/clear attempts to be denied, and checks its read session survives.
It does not treat unknown/missing as normal or require pressure to be normal.
This is not induced-pressure, restart-recovery or long-interval freshness proof.
The client must run in the ordinary authenticated guest user context.

Full R8 is still collecting failures at this update: mac_capability_dev.c's MAC
header, vfs_syscalls.c's quota header and vfs_aio.c's MAC header. Reviewed patches
are prepared under `bazel-current-closure-review-r1-20261111` but not applied to
the live build inputs. No full-system pass or VM upgrade is established.

## Power and Device consumer operations pending native/VM execution

The test-only client now has six operation modes. Power queries supported states
without requiring any particular virtual-hardware sleep state or requesting a
transition. Device enumerates and validates one owner-scoped page without opening
hardware; an empty default-deny list is valid. These checks do not qualify all
power actions, device opens or pagination. Shared dependencies are declared in
the existing native target, and the frontend manual/runner README are updated.
Host strict syntax passes in
`bazel-service-operations-host-syntax-r3-20261111/receipt.json`. Native linking,
runner integration and actual VM execution remain open; no host providers were
contacted. The ongoing full R8 graph still reports the same three header gaps.

## Device probe context review

Source review of BSDDevice/capbundle/device.ucl confirms visible=[system]; Power
explicitly permits user-domain lookup and returns zero supported states on absent
ACPI. The positive Device enumeration probe requires legitimate SYSTEM context.
A separate device-denied mode first completes Time lookup/RPC in the ordinary
session, then requires Device to be hidden/denied. Missing transport and arbitrary
RPC errors do not count. No visibility, attributes, signing or authority policy
is changed to enable a test. Native/VM execution remains pending for both modes;
seven client modes are not seven qualified provider operations.

## Current closure corrections and native consumer link acceptance

Full R8 finishes failed with exactly the three recorded compile sites. Its main
JSON trace is retained at `bazel-system-upgrade-native-r8-20261111/profile.json.gz`
with a separate digest/UUID capture. The old default profile matched the earlier
inventory query, not the build. Do not use either failed correctness run as a
controlled performance comparison.

All three header corrections now pass
`bazel-current-closure-native-r1-20261111/receipt.json`: MAC capability builtin
objects and real loadable-module product, both VFS object groups, and native
PIE/shared linking of service_operations. Both backend regression targets pass
(24 inventory/profile methods and 29 setting methods in their Python suites).
This is not VM execution of any consumer mode or full-system acceptance.

The maintained backend now gives main/test-artifact commands separate explicit
profile paths and strips that path from inventory queries. Each profile is
hash-bound in its phase receipt. The actual native main and materialization
profiles have distinct UUIDs, each matching its own BEP started event. The new
regression protects that phase ownership. The frontend manual is updated; no new
C frontend option or production backend change is required. Full R9 is next.

## Full current candidate and operation-runner native acceptance

`bazel-system-upgrade-native-r9-20261111/receipt.json` passes the complete selected
AMD64 graph, kernel stack-protector and package-solver targets. The actual family
inventory is 450 packages; dq, dq-dbg and dq-dev are the additions to the old
447-package baseline. `bazel-system-upgrade-repository-r4-20261111/receipt.json`
passes complete archive/catalogue verification and actual wrong-key rejection.
The actual kernel extracted from that signed archive is 39,943,080 bytes, SHA256
d99073670cafc428a909458b0138573833c0dd75bb6c052f745043ecf0dc1c4e,
revision ccf8f8bbc42c. These do not close independent Make parity, bootstrap,
reproducibility, resource, publication or ARM64 gates.

The format-2 service policy binds the captured client and its selected ordinary
operations. The runner executes them over pinned user SSH, enforces the expected
UID and phase deadline, validates exact JSON results, and propagates failures.
It also checks that the active old system remains healthy after offline install.
Native service-health, real inventory-fixture and upgrade-policy tests pass in
`bazel-service-operations-native-r1-20261111`. Service-health's 11 Python methods
include failure propagation and ensuring every selected operation is invoked;
these controller fixtures are not real provider operation proof.

`bazel-system-upgrade-plan-r3-20261111.json` uses the real 447/450 inventories,
signed candidate and actual new kernel identity. It selects time, sysctl, notify,
memory, power and device-denied. Full provider coverage remains explicitly false;
SYSTEM Device and the other provider operations remain open. VM execution is
next. The frontend manual and runner README document the schema; its existing
format-5 interface needs no new C option. Normal production remains Make.

## Service-aware upgrade VM R3 fails Notify admission

`bazel-system-upgrade-vm-r3-20261111/result.json` is terminal failed. Baseline
normal startup, installed-tree audit, authentication, all 13 manifest-required
boot services and all six selected ordinary-user operations pass. After the
actual signed 447-to-450-package inactive-BE installation, the active old kernel,
package checksums, authentication, manifest readiness and all six operations
still pass. The candidate boots kernel ccf8f8bbc42c, with the expected archive
SHA256 and exact 450-package inventory/checksums; console, SSH and su checks pass.
All 13 required services report running. Time and Sysctl operations pass, but
Notify client open returns Broken pipe. This failure is preserved, not retried
into success or accepted based on service state. Rollback, persistence after the
new boot and unused-BE deletion were not reached in this run.

A separate diagnostic child overlay of the stopped failed disk preserves the
original disk and evidence. A rebooted diagnostic cannot reproduce the exact
original process state; its logs are diagnostic evidence only. No host upgrade,
installation, publication or reboot was performed. No build input, package or
security policy changes are introduced by this diagnosis; the maintained C
frontend and production backend require no interface change.

## Notify receive restriction correction awaiting qualification

Diagnostic child overlay R2 reproduces ordinary Notify open failure three times.
The provider and router remain live; process existence is insufficient. Source
review finds both processes apply NOFDRECV while their roles require receiving
new-client descriptors. Candidate kernel commit fdbc6085418 adds the missing
mac_file_check_receive hook to channel receive/replies, enforcing the restriction
that the older kernel did not enforce on that path.

Notify now omits NOFDRECV for its long-lived acceptor and router. All other
process restrictions remain; private worker-channel admission, per-hop descriptor
attenuation and descriptor-free client FIDL queues remain. Existing source-token
checks no longer demand the incompatible restriction. This correction is not yet
VM-qualified: real candidate rebuild and the complete upgrade scenario must pass.
The existing production/frontend interfaces accept this ordinary source change;
no build input, packaging, staging, signing or publication interface changes.

The correction is committed as 5b1325c979a. Native
`bazel-notify-admission-native-r1-20261111/receipt.json` passes the real daemon,
PIE/shared consumer client and four broker/transport/policy/dispatcher targets
(68 reported cases passed). These fixtures do not run the normal provider's
protected process lifecycle, so they do not establish the admission fix at
runtime. Diagnostic R2's receipt binds its outputs and three actual failures;
that owned child VM powered off normally. Full candidate R10 is rebuilding
with 16 jobs, production malloc, kernel debug/CTF and the corrected source
revision. The complete signed upgrade scenario remains required.
