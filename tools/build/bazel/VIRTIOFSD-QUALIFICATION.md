# Native virtiofsd component qualification

2026-11-01. Make remains production/default. The native amd64 candidate owns
all nine maintained virtiofsd C units, dependencies, installation/manual/debug
metadata and a safe usage test. Three original daemon ATF cases also have native
execution targets. No production source, original test body or timeout changed.
This does not qualify a complete hypervisor/guest filesystem or the full
WASPNest test harness.

## Source and installation ownership

The selected architecture Makefiles include virtiofsd with MK_BHYVE on amd64,
ARM64 and RISC-V64. Current userland qualification is amd64 only. Six local
sources and three shared bhyve backend/I/O/outbox sources use ordinary rules_cc
compilation. Narrow bhyve exports and the actual backend/range headers preserve
the original source/header owners. No source copies or generated BUILD substitute
are used in the production graph. Native libthr supplies the original pthread
link dependency; PIE and original defaults remain intact.

Five installation records match Make: /usr/sbin/virtiofsd, two debug directories,
separate debug file and compressed virtiofsd.8, with bhyve package ownership.
The native program's incomplete-argument usage test exits 64 before closefrom,
export open or socket creation, checks expected output and accepts no created
working-directory files.

## Original functional tests

The existing tests/sys/kern/vsock_device_harness/virtiofsd_daemon_test.c textually
includes all nine production C units and renames main, exactly as its maintained
Make harness does. Separate native textual-header providers expose the original
implementation files with their original adjacent headers; they are not
separately compiled a second time into this test executable. The test source
and production input hashes are checked. Its original 200ms HELLO timeout remains
inside the unchanged test source; the shipped daemon keeps its normal timeout.
No testing define is applied to the normal program.

All three original cases passed through the maintained native ATF adapter:

- pending_limit_validation;
- silent_authenticated_client_times_out;
- foreground_daemon_is_sandboxed_event_driven_and_cleans.

The foreground case starts the compiled-in daemon in a child using a private
/tmp export/socket, exercises real local backend/FUSE operations and state
transfer, requests termination, waits for successful exit and verifies socket,
file and directory cleanup. Its operations require no root, host VM, live network
interface or installed service modification. The test is a production-source
integration harness, not an exec of the installed daemon binary. The ATF runner
also terminates phase descendants on normal/failing completion. These outcomes
are more specific than a live guest or full service qualification claim.

The new native harness BUILD covers this one original three-case test program.
The other WASPNest harness programs, its complete waspnest-tests package, Kyuafile
and native installation aggregation remain migration work. No partial Kyuafile
replaces the maintained complete test inventory.

## Evidence and frontend integration

All paths below are under /usr/obj/usr/src:

- bazel-virtiofsd-make-r1-20261101: fresh independent maintained Make program and
  NO_ROOT installation, baseline SDK/profile verification and 16 build jobs.
- bazel-virtiofsd-qualification-r1-20261101: maintained build-bsd bazel-test
  qualification of seven targets and four passing test cases (usage plus the
  three original ATF cases).
- bazel-virtiofsd-parity-r1-20261101: comparison commands/reports and
  compile-test-audit.json. Program/install outputs use the immutable capture
  resolver's receipt/target/output/containment/size/SHA checks.

The program ELF contract and exact NEEDED order match Make. All five install
records, the literal compressed manual and both actual native/Make debuglink
CRCs pass. Full ELF bytes differ; this does not prove complete code equivalence.
Nine actual production compile records preserve source hashes and PIE flags;
all 35 original Make source/header prerequisites under /usr/src are declared
with matching digests. The separately checked test compile retains its original
source, all nine embedded production C files and original timeout, and all four
reported test results passed. The broader test suite was not executed.

Existing normal format-5 target/test inputs and maintained adapters suffice;
no frontend C, backend API, SDK or shared source-graph helper change is needed.
The standard manual and native metadata are updated with this tranche. Native
package creation/dependency/publication, cross userland and full world/kernel
qualification remain open.

## Remaining runtime and observability gates

The full separate daemon binary, live bhyve device/guest path, full protocol
matrix, concurrent load/backpressure, credential boundaries, export escape and
migration/recovery behavior need their wider maintained tests and guest work.
No controlled CPU, disk-I/O, memory or cache performance claim is made.
A bounded compiled-source scan found no direct DTrace/SDT provider or explicit
BSM submission. Review peer authorization, export/path/handle denials, malformed
frames, resource limits, timeout/disconnect, migration and failure visibility
against actual callers; this scan does not establish transitive observability.
