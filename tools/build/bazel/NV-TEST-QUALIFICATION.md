# Original AMD64 non-ASan libnv tests (2026-11-06)

## Complete selected construction

All eleven original programs now build natively: one C and four C++ ATF programs,
and six C TAP programs. A fresh independent original Make test-component control
builds/stages with sixteen jobs and metadata. All 23 installed non-directory
records, original directory attributes and exact mixed ATF/TAP Kyuafile bytes
match. All eleven program dynamic ELF contracts match original Make, including
NEEDED order, symbol imports/exports and versions. Native and Make separate debug
filenames/CRCs and DWARF presence verify. Raw ELF/DWARF equality, actual debugger
source resolution and complete ASan/other-ABI profiles are not claimed.

The C send/receive program retains original msgio.c as an extra translation unit,
explicit common/message/private wire-layout headers and NO_ASAN for the selected
original MK_ASAN=no profile. C++ tests retain GNU++17, WARNS=3, native ATF C++/C,
libnv and explicit libc++/libcxxrt/math/compiler-runtime/unwinder ABI inputs.
The test C sources, C++ sources and Makefiles are unchanged.

## TAP links and actual engine results

Each TAP source compiles in one declared cc_library object group. Its normal
installation link and runtime-only qualification link consume identical declared
object/library inputs. The only link argument differences are the output path
and explicit inherited private $ORIGIN RPATH on the qualification link. The
installed program retains original no-RPATH Make contracts. This is not a claim
that the runtime variant is byte-identical to the installed program.

The existing maintained Kyua TAP adapter uses the explicitly declared SDK Kyua
execution tool and retains typed database/JUnit results. All six original TAP
programs pass the real TAP engine; these are six program outcomes, not six total
TAP assertions. Loader-trace checks verify native libnv/libc/libsys SONAMEs and
artifact hashes, without library environment overrides on the consumer. The final
audit retains every TAP database/log/loader receipt and checks each result as a
single TAP main case with passed status. The six runtime variant executables are
explicitly captured by the final frontend request and match receipt binary hashes.
SDK Kyua/Python/host kernel tools remain execution inputs; this is not proof of
an entirely Bazel-bootstrapped or hermetic test engine/runtime.

Configured-action review verifies all 24 registered regular/PIC compile actions,
source identities, selected NO_ASAN/private-header inputs and six identical-input
TAP link pairs. Six additional cc_library shared-link alternatives are registered
in the queried graph; they are not six newly executed shared-library builds or
installed helper DSOs. The first audit's guessed total of seventeen link actions
fails on the actual twenty-three registrations; the corrected audit explicitly
accounts for those six alternatives without weakening object-sharing checks.

## Original ATF metadata and execution

Actual native and original Make ATF listings match for all five programs and 131
case registrations. Source-owned case maps preserve their original default
300-second deadlines and absence of declared cleanup/required-user metadata.
The ATF adapter executes actual installation-form binaries with native DSOs.

Of 130 selected original cases, 129 execute and pass; one returns its original
non-ASan skip, with exact reason "This test requires ASAN" for
nvlist_send_recv__overflow_header_size. This is not sanitizer coverage or a pass.
The high-descriptor regression case runs normally: it changes only its own
resource limit and duplicates two descriptors above FD_SETSIZE, rather than
allocating a host-wide descriptor workload. The original global datagram-sysctl
case remains an explicit manual/external/no-remote target for a disposable guest;
it is not run on the host or counted as passed/skipped.

Native r1 executes six TAP programs; native r2 executes the 130 ATF cases and
reuses TAP/helper results; final r3 reuses valid results while explicitly capturing
all six runtime-only TAP executables. Final totals are 137 PASSED Bazel targets,
but detailed outcomes are 136 passes and one skip, including six TAP program
results and one separate source-settings helper. all_reported_cases_passed is
false and remains false. The final audit accounts for every original ATF case,
retains actual skip XML/reason and binds final archives, metadata, directory
outputs and all runtime DSOs byte-for-byte to independently compared captures.

## Original test cleanup issue before guest qualification

The original nvlist_send_recv__send_many_fds__dgram body changes maxdgram before
attempting recvspace. A later failure/skip can bypass restoration; ordinary ATF
cleanup is not registered. Before qualifying this case in a privileged guest,
fix and test restoration on failure/skip/interruption rather than claiming the
normal return path covers cleanup. Disposable guest isolation prevents host
mutation in the meantime. Positive ASan and this guest case remain open work.

## Retained evidence

Under /usr/obj/usr/src:

- bazel-nv-tests-request-r{1,2,3}-20261106/inputs.json: construction/TAP, ATF and
  final explicit runtime-variant capture requests, respectively.
- bazel-nv-tests-native-r1-20261106/receipt.json: complete installation and six
  TAP executions; the source-settings helper is a valid cached result.
- bazel-nv-tests-make-r1-20261106/receipt.json: fresh original Make control.
- bazel-nv-tests-review-r1-20261106/review.json: eleven ELF/debug contracts,
  23 installation records, exact Kyua and directory comparisons.
- bazel-nv-tests-case-inventory-r1-20261106/review.json: actual five-program/
  131-case ATF metadata comparisons using explicit captured native DSOs.
- bazel-nv-tests-native-r2-20261106/receipt.json: 130 actual ATF executions,
  including one exact original non-ASan skip; one sysctl case unexecuted.
- bazel-nv-tests-native-r3-20261106/receipt.json: final cached results and explicit
  runtime-variant/DSO/installation captures.
- bazel-nv-tests-actions-review-r1-20261106/: retained failed link-count audit.
- bazel-nv-tests-actions-review-r2-20261106/review.json: complete configured
  compile/header policy and identical-input original/runtime TAP link review.
- bazel-nv-tests-final-review-r1-20261106/review.json: final immutable bindings,
  complete case/outcome accounting, six retained TAP output trees/databases and
  native consumer/library trace hashes. Read-only SQL uses explicitly hashed
  /usr/local/bin/sqlite3; the host Python installation lacks _sqlite3.

All reviews retain audit scripts and input hashes. Mutable auxiliary test outputs
are copied into retained evidence with before/after content checks and tied to
immutable final test log/XML hashes, captured variant executables and libraries.
No historical proof relies solely on a mutable bazel-bin path.

## Frontend and remaining gates

The existing build-bsd format-5 inputs carry every new target/test/runtime capture.
No frontend C/schema, stage/signing or publication policy change is required; its
manual, roadmap and observability ledger are updated in the same change. Remaining
base installed-test roots, positive ASan/guest/other-ABI qualification, full world/
kernel/modules/debug/pkgbase, bootstrap/cache/sandbox/reproducibility, normal
services, CPU/RAM/disk-I/O/footprint and hardware/combined publication gates stay
open. Make remains production/default; BIP excluded. No host installation,
sysctl write, upgrade, reboot, module load or VM launch occurs in this cohort.
