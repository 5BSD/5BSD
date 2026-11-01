# Native iconv resources and default-path runtime qualification

2026-11-01. Make remains production/default. This tranche qualifies the existing
native Citrus module/data graph and supplies an explicit-input disposable VM
fixture for its absolute installed resource paths. It adds no Make interpretation
to the production graph and does not install anything on the host.

## Native ownership and independent reference

The native graph owns all 23 Citrus modules and the complete i18n install
archive. Fresh independent Make component builds/installations are retained at
`/usr/obj/usr/src/bazel-iconv-modules-make-20261101/` and
`/usr/obj/usr/src/bazel-i18n-make-20261101/`. The maintained reference helper uses
16 jobs, records effective options, and preserves the selected source/SDK/profile
checks. The aggregate Makefiles do not expose MALLOC_PRODUCTION as a component
option; the attempted explicit override was rejected, rather than bypassing the
helper's namespace validation. Default development profile was retained.

The data reference records and rechecks the actual installed mkesdb/mkcsmapper
generator identities. The independent native graph builds its own generators.
`/usr/obj/usr/src/bazel-iconv-resource-parity-r3-20261101/` retains exact comparison
scripts, receipts, inputs and reports: all 722 data installation records and
687 ordinary resource files match; all 72 module installation records and 23
symlink targets match. Logical NO_ROOT metadata comparison does not establish
actual host installation ownership.

Review found an unnecessary native direct libsys DT_NEEDED edge in every Citrus
module. Make requires libc directly; libc already provides its own libsys edge.
Removing that one native dynamic_deps entry restores the actual dependency graph.
All 23 module ELF contracts, imports/exports, dependency order, symbol versions
and installed sections then match Make except `.gnu_debuglink`. Each actual
separate debug file and its CRC/DWARF relationship is checked independently.
Prior dependency mismatches remain in the retained r1 comparison evidence.

The final maintained build-bsd native receipt is
`/usr/obj/usr/src/bazel-iconv-runtime-qualification-r5-20261101/receipt.json`:
83 selected targets and 25 passing test targets, comprising 23 actual module
load/getops tests, seven fixture boundary checks and sixteen additive-root checks.
Some tests are valid cached results; this is not 25 newly executed processes.
All production module/data outputs are tied back to the comparison artifacts.

## Explicit disposable fixture

`iconv-runtime-fixture.py` consumes a completed native qualification plus a
versioned JSON plan. The plan explicitly supplies archives, individual artifact
labels/destinations/modes, matching kernel, boot directory, guest driver,
checker, readelf and baseline daemon-runtime test binaries. It rejects duplicate
artifact configurations, wrong hashes, archive traversal, escaping symlinks,
unsupported archive objects and payload collisions. Output is a new directory
under /usr/obj; the tool does not choose an implicit host resource fallback.

Three complete native install archives provide Citrus modules, all i18n data
and fstyp/tests/manuals. Explicit native programs and libraries complete the
selected test closure. libc/iconv modules/data run inside /fixture at their real
compiled paths /usr/lib/i18n and /usr/share/i18n. Shell/ATF helpers and
newfs_msdos keep their intended installed paths. The checker invokes native
chroot with explicit nonzero uid/gid and supplementary groups, verifies them,
and uses the ordinary system executable search paths.

The SDK loader and a separate outer SDK Python runtime are bootstrap inputs,
not native migration achievements. The assembler derives Python SONAME aliases
from the declared SDK ELF objects, rejects ambiguity/unresolved NEEDED entries,
and records all 41 SONAMEs and hashes. Bootstrap Python encoding is used only
for expected-byte oracles; the programs under test use native code/resources.
The fixture records kernel, driver, source checker, all payloads and boot files.
Host loader policy and secret entropy are excluded; defaults/loader.conf stays.

The maintained daemon-runtime harness boots a fresh disk-backed 768MiB UFS/GPT
root with the explicit matching GENERIC-NODEBUG kernel, 2GiB guest RAM and four
CPUs. A static VM-only ATF adapter mounts devfs and a bounded 384MiB scratch tmpfs
at /fixture/tmp, then asserts cleanup. Passed fstyp work directories are removed
as a test runner normally does, bounding scratch live images to one case.
Programs/data/root are disk-backed; this does not load the OS into a memdisk.
The harness records sampled QEMU RSS/CPU and enforces a 3GiB host RSS ceiling.
These bounds are resource checks, not a filesystem or performance benchmark.

The additive-root helper now accepts printable punctuation such as the literal
percent in actual installed Citrus map filenames and uses maintained mtree octal
escaping. Traversal, aliases, whitespace/control characters and symlink escapes
remain rejected; focused tests cover both valid punctuation and invalid input.
No payload was renamed to satisfy a fixture limitation.

## Runtime evidence and remaining gates

The final fixture is
`/usr/obj/usr/src/bazel-iconv-vm-fixture-r7-20261101/fixture.json`, assembled from
the r5 native receipt. The final plan and native inputs are retained beside the
parity reports as final-r7-fixture-plan.json and final-r5-native-inputs.json.
Its 361305977 logical payload bytes include separately identified bootstrap code.
The kernel SHA-256 is
`8a3b1cf6446946f9cc6a12f7645274fd59d49a8a44ca74137fd9189c5e9383da`;
the maintained harness independently checks staged/object kernel identity.

`/usr/obj/usr/src/bazel-iconv-vm-r4-20261101/result.json` reports PASS, QEMU exit
zero and no forced termination. Serial output and extracted
iconv-runtime-results.json retain all 39 passing checks: child uid, gid and
supplementary groups; the original libc iconvctl ATF case; sixteen conversions
covering eight encoding round trips; invalid input, unknown encoding and listing;
and all sixteen maintained fstyp file-image/error/label ATF cases. These include
exfat, ext4, FAT and NTFS label conversions. The four existing daemon-runtime
baseline cases and both fixture mount cleanup checks also pass.

The observed VM duration is 30.157 seconds, QEMU CPU is 43.18 seconds, and maximum
sampled QEMU RSS is 811073536 bytes over 30 samples. Sampling excludes
between-sample peaks and host page cache, and other independently managed VMs
were active on this host; no controlled speed comparison is claimed.
The guest and harness are terminal; no test VM remains running from this tranche.

Previous attempts remain visible. Preparation caught unreadable host entropy,
missing copied boot defaults, and the additive-root filename restriction before
successful boot. VM r2 booted but exposed the fixture's read-only inner /tmp;
VM r3 fixed scratch policy and passed the 23 iconv/identity checks, then correctly
failed all 16 fstyp cases because the checker PATH omitted /usr/sbin. The fix is
normal system PATH plus actual /sbin/newfs_msdos installation, not program or
recognizer source changes. Each attempt uses a fresh disk and its own results.

No normal Capsule/PID1 startup, login, SSH, network services, full pkgbase image,
all encodings, device-based fstyp behavior, cross-architecture userland runtime,
live tracing/audit behavior or performance is established by this fixture.
The later MAKEFS-QUALIFICATION.md tranche records passing guest evidence for
the five makefs and one privileged md/newfs case, completing all 22 fstyp cases.
The generic Bazel test runner still does not provide a privileged chroot; the
VM-only adapter is an explicit harness case, not an automatically running host
test. No frontend/backend change is needed: maintained format-5 target/test
inputs and existing build-bsd bazel-test workflow build the declared artifacts.
The new assembler is qualification tooling, not an alternate image publisher.
