# Configured native rescue qualification (2026-11-05)

## Composition

rescue/rescue/selection.bzl uses ordinary Bazel select expressions to preserve
original program order while honoring tcsh, vi, PF, ZFS, netcat, iSCSI, INET/
INET6 and INET6_SUPPORT conditions. It shares PROGRAMS with the default catalog;
the duplicate parent program allowlist is removed. Program compiler inputs and
crunched object inputs use the same configured selection. Source owners still
supply exact ordered object/archive metadata. No Make or filesystem discovery
runs inside native actions.

bsd_crunchgen accepts an ordered applications label list corresponding exactly
to configured programs. It validates the list length and typed own-object data.
Existing explicit object_names and object_files interfaces remain supported and
mutually exclusive. Optional catalog_programs allows a complete alias catalog
while selecting a subset; selected names and alias owners must belong to that
unique explicit catalog. Only selected programs emit aliases/stubs. The guarded
default_dispatch remains a reference fixture; the live configured core does not
consume its fixed object descriptors.

Common native links now include original libalias and libdevstat. They were
previously omitted from the bounded link despite appearing in Make's common
inventory. Conditional edges retain pthread without ZFS, omit ZFS common archives
when disabled, omit iSCSI support when disabled and preserve OpenSSL selection.
Per-program archives remain in their original partial-link stages.

## Real defect found and fixed

The first DTrace-disabled build passed its runtime smoke suite but failed the
independent Make object-inventory comparison: ten early source declarations
still unconditionally defined WITH_COVERAGE_DTRACE, depended on provider headers
and supplied rewritten/provider objects. The affected programs are chflags,
chmod, cp, ln, mkdir, mv, realpath, rm, rmdir and sleep. Their source declarations
now select all three aspects using the existing dtrace_enabled condition. An
AST review confirms their enabled-trace declarations, including all ordinary
compiler/install targets, remain unchanged after resolving the explicit select
and list concatenation. The obsolete traced-only core guard is removed only in
this change with actual disabled-profile qualification.

The maintained configuration_runtime_test receives --dtrace=yes/no through
Bazel test args. Five methods check exact declared dispatcher inventory/order,
application-provider selection, shell builtin dispatch, binary stdin and gzip
roundtrip. This small suite supports reduced selections. The broad 107-method
core_runtime_test remains a default-profile suite, not an automatic claim about
every optional configuration. No test silently skips missing programs.

## Evidence

All evidence is under /usr/obj/usr/src; requests use existing format-5 inputs,
maintained build-bsd bazel-test and 16 jobs. No installation/reboot/publication.

- bazel-rescue-configured-default-native-r3-20261105: final default passes
  107 broad runtime, five configured runtime and 28 source-settings methods.
- bazel-rescue-configured-default-metadata-review-r1-20261105: all 103 original
  ordered object descriptors and seven per-program archive lists still agree.
- bazel-rescue-configured-default-pipeline-review-r1-20261105: original Make
  on identical captured native inputs reproduces all 208 entire pipeline outputs
  with restored common archives. Final r3 captures bind to those exact 208 hashes
  in bazel-rescue-configured-default-continuity-r1-20261105.
- bazel-rescue-configured-minimal-make-r1-20261105: independently generated
  original metadata with MK_TCSH, MK_VI, MK_ZFS, MK_PF, MK_NETCAT and MK_ISCSI=no.
  Native r2 passes four configured methods (before adding the provider method)
  plus 28 source-settings methods. Its 92 programs, all aliases and all ordered
  objects match original Make in bazel-rescue-configured-minimal-review-r1-20261105.
- bazel-rescue-configured-notrace-make-r1-20261105 adds MK_DTRACE=no to that
  explicit reference. Corrected native r3 passes five configured methods plus
  28 source-settings methods. All 92 names/aliases/ordered objects agree with
  Make, and no application provider object remains, in
  bazel-rescue-configured-notrace-review-r2-20261105.
- bazel-rescue-conditional-declaration-review-r1-20261105 verifies enabled
  declaration preservation across all ten corrected owners.
- bazel-rescue-configured-minimal-link-review-r2-20261105 binds effective
  linker arguments to an actually executed response-file hash and the captured
  final executable. ZFS-family/iSCSI archives are absent; alias/devstat/pthread
  remain. bazel-rescue-common-archive-review-r1-20261105 verifies all 32 common
  archive roles/order against original generated Make, with explicit maintained
  termcapw/tinfo, ncursesw/ncurses and privatezstd/zstd naming correspondences.

The link audit uses Bazel aquery with parameter expansion. Exact newline-encoded
arguments hash to the recorded executed response input; it does not read an old
qualification's mutable execroot symlink as historical evidence. Its first
observer expected direct arguments and failed on the response file. The first
separate query omitted the frontend's JAVA_HOME and failed local-JDK analysis;
r2 explicitly uses the request's Java home. Failed observers and the original
untraced inventory failure remain retained. Neither green smoke tests nor a
reconstructed query alone established compiler/link parity.

## Remaining scope and frontend

Existing format-5 settings/target APIs suffice. No frontend C/schema, signing,
staging or publication policy changes are required. The manual, completion plan
and instrumentation ledger record the increment. Make stays production/default;
this is unsigned development qualification, not verified boot or BIP.

These cases do not qualify every option combination, independent alternate
library/compiler/debug payload parity, other architectures, successful live
probe registration/firing, installation, normal guest recovery or performance.
The untraced case also rebuilt host-tool dependencies and emitted source warnings;
its successful bounded result does not certify those libraries as warning-free
or establish cold/cache resource performance.

Next implement actual rescue-named dispatch and installation without renaming
rescue_core as a substitute (EXECNAME affects dispatch). Match original
MK_DEBUG_FILES=no, installed hardlinks and suppressed login aliases (-sh/-csh/
-tcsh remain dispatcher names), and the declared dhclient-script shebang
transformation. Compare actual staged installation/package metadata and run
private guest recovery/helper cases. All whole-world/kernel/modules/pkgbase,
ARM64/RISC-V/bootstrap/cache/sandbox and CPU/memory/disk gates remain open.

## Installation follow-up

Actual rescue-named dispatch, original installation records/script, world
membership and a real pkgbase candidate are now implemented and bounded checks
pass. See RESCUE-INSTALLATION-QUALIFICATION.md for current evidence and unresolved
independent ELF/object, package database, guest and full-system gates.
