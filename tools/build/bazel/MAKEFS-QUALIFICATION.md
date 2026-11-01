# Native makefs and complete fstyp runtime candidate

2026-11-01. Make remains production/default. This tranche declares the real
makefs program and complete original test installation, and closes the six
previously open fstyp cases in a fresh disposable guest. It does not establish
all makefs feature behavior, full image production or native system completion.

## Source ownership and configuration

Native rules_cc owns all 38 maintained default makefs translation units:
31 ordinary and seven optional ZFS sources. Actual successful compiler commands
and an independent Make command inventory have identical source paths. Included
ZFS fletcher.c/sha256.c remain declared inputs of vdev.c, not extra objects.
Source-owned headers retain the actual Make include namespaces. Narrow exports
cover shared mtree/mknod sources, FFS tables, FAT formatting and boot ZFS inputs;
no copied source implementations or generated production BUILD replacement is
introduced. The existing etdump header exports remain available.

The program retains MAKEFS, _WANT_MSDOSFS_INTERNALS and native stat definitions,
PIE, the internal netbsd PIE archive, and util/sbuf dependency order. Existing
typed zfs/tests settings select ZFS sources/HAVE_ZFS and original installed test
products. No native source-graph, SDK stager, toolchain or root module edits are
needed; normal build-bsd format-5 targets/settings build this graph.

The complete makefs test scripts, common script and Kyua metadata are installed,
including root, mount-tool and required-module properties and conditional ZFS
suite. This is installation evidence, not execution of the whole makefs suite.
The already native newfs/mdconfig programs supply the unchanged device case.
Review repaired mdconfig's incomplete component install archive to include its
already declared tests. The sbin aggregate keeps a separate program archive
and its existing separate test archive, preserving unique ownership.

## Independent Make and artifact evidence

Fresh references, using the recorded SDK/profile and 16 compilation jobs:

- /usr/obj/usr/src/bazel-makefs-make-20261101/
- /usr/obj/usr/src/bazel-newfs-make-20261101/
- /usr/obj/usr/src/bazel-mdconfig-make-20261101/
- /usr/obj/usr/src/bazel-makefs-minimal-make-20261101/ (ZFS/tests disabled)

`/usr/obj/usr/src/bazel-makefs-helpers-parity-r1-20261101/` retains scripts,
inputs, source inventories and actual comparisons. All 23 complete installation
records match Make: makefs 12, newfs four and mdconfig seven. Original scripts,
Kyuafiles, compressed manuals and common data match bytes; real separate debug
files and their debug-link CRC/DWARF relationships pass. Logical NO_ROOT records
do not prove actual installed host ownership. All three ELF contracts,
imports/exports, dependency order and checked hardening match. Newfs/mdconfig
installed sections match completely except GNU debuglink.

Makefs retains source-path and layout differences in text, read-only data and
link tables. Twenty path strings are source-relative rather than /usr/src-prefixed;
raw whole-binary strings also contain differing instruction bytes. Exact raw
section/string reports remain retained. This is bounded contract/install parity,
not machine-code equivalence or full debugger qualification. No absolute-path
fixup, artifact rewriting or ignored source is used to force equality.

The minimal native receipt and reports are
`/usr/obj/usr/src/bazel-makefs-minimal-qualification-20261101/` and
`/usr/obj/usr/src/bazel-makefs-minimal-parity-20261101/`: all five installation
records, compressed manual, ELF contract and debug checks match the independent
reduced reference. This proves the stated default/reduced settings, not every
feature combination. The first default native run rejected the actual missing
cd9660_rrip.h input; declaring that maintained source header fixes the closure.

The final default receipt is
`/usr/obj/usr/src/bazel-fstyp-complete-qualification-r2-20261101/receipt.json`:
89 selected targets and 25 passing test targets (cached results are possible).
All 88 previous production/test outputs are unchanged when the explicit group
input is added. A separate one-target mdconfig aggregate receipt verifies its
four program records equal the complete component's program subset.

## Original 22-case fstyp suite in a bounded guest

The maintained explicit-input fixture preparer consumes complete native install
archives for makefs, newfs and mdconfig alongside the existing iconv/fstyp closure.
Native cat is declared for the original cleanup script. The standard source-owned
/etc/group is an explicit artifact, preserving operator's actual GID. No account
is invented and no stderr assertion is relaxed. All installed executable and
resource paths stay intact. SDK Python and loader remain separately identified
bootstrap inputs, as described in ICONV-RUNTIME-QUALIFICATION.md.

The VM-only adapter explicitly requests --fstyp-complete. Twenty-one ordinary
cases run with the verified nonzero uid/gid/groups. Only the original
ufs_on_device body/cleanup runs as guest root. It creates a real 64MiB swap-backed
md device, formats it with native newfs and verifies fstyp recognition/label.
The checker invokes the original ATF cleanup even after a failed body and checks
that mdconfig's before/after device lists match. All original test bodies remain
unchanged; newfs warnings, skips, failures or missing cleanup are not passes.

`/usr/obj/usr/src/bazel-fstyp-complete-vm-r2-20261101/result.json` reports PASS;
serial and iconv-runtime-results.json record all 48 passing checks, including
all 22 original fstyp cases, previous iconv/identity checks, root cleanup and
restored md inventory. Four baseline daemon-runtime cases pass as well. Both
temporary mount cleanups pass, QEMU exits zero and no forced termination occurs.
The fixture record is
`/usr/obj/usr/src/bazel-fstyp-complete-vm-fixture-r2-20261101/fixture.json`;
its versioned plan and native inputs are retained beside the parity reports.

The fresh root is a 768MiB disk-backed UFS/GPT image; guest limits are 2GiB RAM
and four CPUs, with a bounded 384MiB scratch tmpfs and 3GiB sampled host RSS cap.
Payload is 362669959 logical bytes including explicit bootstrap inputs. The
observed 32.148 seconds, 49.83 QEMU CPU seconds and 843395072 maximum sampled RSS
bytes are resource observations, not a controlled performance comparison.
Sampling excludes between-sample peaks and host page cache.

The prior fullsuite VM failure is retained at bazel-fstyp-complete-vm-r1-20261101:
47/48 checks passed, but the root newfs case correctly rejected its warning about
missing operator group data. Original md cleanup passed even then. Staging the
actual declared base group file resolves the fixture gap; no production software
or test assertion was changed. Earlier iconv fixture failures remain recorded.

## Remaining scope

The full original fstyp suite now has concrete amd64 guest evidence. This does
not qualify every possible filesystem image, ZFS pool/device behavior, physical
hardware, cross-architecture userland, normal Capsule startup, SSH, full pkgbase
system/image/publication paths or performance. No direct DTrace provider, SDT
probe or explicit audit submission was found in makefs/newfs/mdconfig sources;
dependency instrumentation remains in the existing graph. Live tracing/audit
and the full installed makefs/mdconfig test suites remain open.
No host md device, chroot, sysctl, installation, service change or reboot was used.

## Complete makefs suite follow-up

See MAKEFS-RUNTIME-QUALIFICATION.md for the complete 63-case source-owned
inventory, native helper closure, additional ZFS-disabled/tests-enabled
installation comparison and bounded guest execution, including retained
fixture failures. The original artifact/layout limitations above still apply.
