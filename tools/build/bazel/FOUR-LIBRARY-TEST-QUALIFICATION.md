# Original librt/libsbuf/libexecinfo/libkvm tests (2026-11-06)

All twelve original selected AMD64 ATF programs now build with source-owned native
rules. Fresh independent original Make controls for the four test components
build/stage with sixteen jobs and recipe metadata. All 28 installed non-directory
records, directory ownership/modes/tags, exact Kyuafile bytes and program dynamic
ELF contracts match. Every native and Make separate-debug filename/CRC and DWARF
presence verifies. Raw ELF/DWARF identity and debugger source lookup are not claimed.
Original C sources and Makefiles are unchanged.

The four kvm programs that originally use kvm_test_common.c retain that additional
translation unit; close retains its single source. Private kvm layout and common
sbuf headers are declared. Imported sched/sem/backtrace sources retain native
NetBSD compatibility dependencies; all consumers use explicit ATF, selected
library and libc ABI providers and original WARNS=6 policy.

## Original symbol preservation and installed-form execution

libexecinfo's original STRIP= is required for runtime backtrace symbol lookup.
The maintained utility_installation helper now accepts strip_symbols=False:
original debug extraction/strip-debug/debuglink actions remain, while the
additional all-symbol stripping action is omitted through an alias to the
separated binary. Default consumers keep their original stripping pipeline.
The libexecinfo installation explicitly selects this behavior; both native and
Make runtime ELF files retain .symtab. This is not a synthetic section-retention
workaround or a modification of the backtrace tests.

All selected runtime targets execute their actual installation-form
*_install_stripped outputs, not full preinstallation producer binaries. Thus
backtrace and signal-trampoline success tests exercise the preserved symbols
that package installation will receive. Default stripping is also exercised by
the other three families' installed-form tests and independent Make comparisons.

## Case metadata and runtime outcomes

All 48 original native/Make ATF case metadata listings match. Explicit source-
owned case maps retain required users, cleanup and deadlines, including original
five-second semaphore child and twenty-second timed/clock-wait cases.

All 33 reviewed host cases execute and pass, no skips/expected failures:

- librt: two scheduler queries and five unnamed timed/clock-wait semaphore cases;
- libsbuf: all seventeen original cases;
- libexecinfo: original backtrace formatting and signal-trampoline cases;
- libkvm: seven ordinary negative-input cases.

The source-settings helper is a separate valid cached result, yielding 34 passing
Bazel targets/reported cases. It is not counted among original library cases.

Fifteen cases remain unexecuted, with explicit manual/external/no-remote targets:
six root scheduler cases, seven root kernel-memory/input cases and two original
named-semaphore cases. The latter create/unlink fixed /sem_a and /sem_b names;
they require a disposable guest to avoid interfering with host process-global
objects. They are not rewritten with randomized names or passed via skips.
Required-root preconditions and original cleanup/deadlines remain declared.
Host libkvm cases are external/no-remote because their negative input behavior
observes host filesystem/device state; they are not claimed hermetic cache tests.
These manual adapters do not themselves establish a qualified VM runner.

## Evidence

All roots are under /usr/obj/usr/src:

- bazel-four-library-tests-request-r{1,2}-20261106/inputs.json: construction and
  explicit selected-runtime requests through normal build-bsd format 5.
- bazel-four-library-tests-native-r1-20261106/receipt.json: first construction,
  archive/metadata/directory and eleven native runtime DSO captures.
- bazel-{librt,libsbuf,libexecinfo,libkvm}-tests-make-r1-20261106/receipt.json:
  four independent current-source original Make controls.
- bazel-four-library-tests-review-r1-20261106/review.json: complete inventory,
  directory/Kyua and twelve ELF/debug/symbol-preservation comparisons.
- bazel-four-library-tests-case-inventory-r1-20261106/review.json: actual native
  and original Make listings for all twelve programs and 48 registrations.
- bazel-four-library-tests-native-r2-20261106/receipt.json: all 33 original host
  cases execute and pass; source-settings helper is a valid cache hit.
- bazel-four-library-tests-final-review-r1-20261106/review.json: final archive/
  metadata/directory and runtime DSO bytes match compared r1 captures; every
  original case's source-owned metadata and host/deferred selection is accounted
  for; passing log/XML hashes verify. Exact fifteen deferred labels are recorded.

Reviews retain their scripts and hash-bound inputs/captures. No mutable bazel-bin
artifact is used as historical proof. These builds/reviews have no failed
construction, independent parity or runtime attempts.

## Integration and limits

Normal build-bsd explicit inputs already carry these targets, settings, runtime
cases and maintained installation-helper behavior. No frontend C/schema,
stage/signing or publication-policy change is required. The manual, roadmap and
observability ledger are updated together. Other architectures/configurations,
all fifteen guest cases, remaining base test parents, complete world/kernel/
module/debug/pkgbase, bootstrap/cache/sandbox/reproducibility, normal services,
CPU/RAM/disk-I/O/footprint and hardware/combined repository publication remain
open. Make remains production/default; BIP excluded. No host installation, kernel
memory access, upgrade, reboot, module load or VM launch occurs in this cohort.
