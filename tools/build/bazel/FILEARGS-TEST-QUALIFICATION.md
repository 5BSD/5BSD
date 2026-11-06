# Original AMD64 Casper fileargs tests and services dispatcher (2026-11-06)

## Construction and independent Make controls

The original fileargs_test builds natively with explicit ATF, libcasper,
cap_fileargs, nv and libc ABI inputs, WARNS=3 and WITH_CASPER. src.opts.mk declares
CASPER required; incompatible disabled profiles are rejected rather than running
authority checks against unrestricted inline compatibility stubs. Test macro and
native nv header visibility are extended only to the new test package.

A fresh original Make component control builds/stages with sixteen jobs and recipe
metadata. All three program/debug/Kyuafile installation records, original directory
attributes and exact Kyuafile bytes match. The program dynamic ELF contract and
native/Make split-debug filename/CRC and DWARF presence match. Raw ELF/DWARF
identity, actual debugger lookup and other ABI/configuration profiles are not
claimed. Original test/service sources and Makefiles remain unchanged.

The shared services test parent installs the original tests/Kyuafile with original
root directory and file metadata. A separate original Make parent control verifies
both records (one directory, one file), modes/owners/groups/package tags and exact
2321-byte payload. The parent preserves original filesystem discovery, without a
second manually maintained list of service test children.

## All original authority cases execute

Actual native and original Make -l listings match all eleven case registrations.
All retain has.cleanup=true, no required-user metadata and original implicit
300-second body/cleanup deadlines. Each native adapter invokes the original
cleanup phase; successful cleanup status is not a claim beyond original cleanup
semantics. All eleven execute and pass from the actual installation-form binary,
with native libc/libsys/ATF/nv/casper/cap_fileargs libraries and real kernel
Capsicum support. None skips or expects failure. A separate source-settings helper
is a valid cache hit: twelve passing targets/reported cases, eleven original cases.

The original cases check permitted/forbidden opens, reads/writes/creation, fopen,
lstat, realpath and broker-channel use, including rights and operation restriction
checks against generated private files and the original forbidden /etc/passwd
path. Source constants/checks are unchanged. Host feature/filesystem/service state
remains involved, so adapters are external/no-remote rather than claimed hermetic
cache tests. Original providers remain unchanged; DTRACE_DOF_INIT_DISABLE=1 is an
explicit runtime setting, not evidence of live provider firing.

## Actual extensible parent discovery

The final audit uses the explicitly bound SDK Kyua execution tool to list a
private suite containing the unchanged captured parent Kyuafile and real native
fileargs metadata program/Kyuafile. One original-named child yields eleven cases.
Adding a synthetic additional_service directory containing the same unchanged
child artifacts yields twenty-two cases; removing it returns to eleven. Parent
bytes remain unchanged throughout. Each phase's listing/log is retained. These
are metadata discovery checks, not execution or acceptance of a new service or
all other existing Casper service families. Original fileargs body execution is
qualified separately above. SDK Kyua is still an execution input; this does not
establish a completely Bazel-bootstrapped test engine.

## Retained evidence

Under /usr/obj/usr/src:

- bazel-fileargs-tests-request-r{1,2}-20261106/inputs.json: explicit construction
  and eleven-case runtime requests through maintained build-bsd format 5.
- bazel-fileargs-tests-native-r1-20261106/: initial analysis correctly rejects
  missing access to the native nv headers. Scoped dependency visibility fixes it.
- bazel-fileargs-tests-native-r2-20261106/receipt.json: complete construction,
  parent/test archive/metadata/directory and six native runtime DSO captures.
- bazel-fileargs-tests-make-r1-20261106/receipt.json: independent original Make
  fileargs control; source and SDK identity guards remain in force.
- bazel-casper-services-parent-tests-make-r1-20261106/receipt.json: independent
  original Make services dispatcher control.
- bazel-fileargs-tests-review-r1-20261106/review.json: all three file records,
  directory/Kyua and program ELF/debug-link comparisons.
- bazel-fileargs-tests-case-inventory-r1-20261106/review.json: actual native/Make
  eleven-case metadata listings and original cleanup requirements.
- bazel-fileargs-tests-native-r3-20261106/receipt.json: all eleven original cases
  execute and pass; source-settings is a separate cached helper.
- bazel-fileargs-tests-final-review-r1-20261106/review.json: final unchanged
  compared artifact/DSO bindings and complete case log/XML hash/outcome review;
  parent data/metadata comparison and private added/removed child discovery.

Reviews retain their audit scripts and input hashes. Historical build proof uses
immutable captures; added/removed discovery fixtures are private qualification
data under /usr/obj, not a replacement installed OS image or service inventory.

## Frontend and remaining gates

The existing build-bsd format-5 workflow already carries all targets, libraries,
fixtures and tests. No C frontend/schema, staging/signature or publication-policy
change is required; its manual, roadmap and observability ledger are updated in
the same change. The production-only services parent remains explicit, and full
installed-tests world guards are not removed: the dispatcher does not qualify
unreviewed sibling service test integrations. Remaining base test roots, other
ABIs, whole world/kernel/modules/debug/pkgbase, bootstrap/cache/sandbox/
reproducibility, normal service VM boots, CPU/RAM/disk-I/O/footprint and hardware/
combined publication remain open. Make stays default; BIP excluded. No host
installation, upgrade/reboot, module load or VM launch occurs in this cohort.
