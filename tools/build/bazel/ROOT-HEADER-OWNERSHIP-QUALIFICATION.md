# Source-owned root header correction (2026-11-01)

## Defect and correction

The actual configured kernel query loaded root BUILD.bazel through legitimate
version/COPYRIGHT inputs and failed: root header providers still named files
under newer ACPICA-include, evdev and autofs packages. An exhaustive audit
found 130 such references among 483 root file entries, including IASL and
bhyve evdev cases beyond the first reported ACPICA/autofs failures.

ACPICA public/debugger/compiler header lists now belong to the existing
`sys/contrib/dev/acpica/include` package; the two bhyve input ABI headers belong
to `sys/dev/evdev`; the userland autofs ioctl belongs to `sys/fs/autofs`.
Pure consumers use those source-owner labels. Root wrappers retain only files
still legitimately root-owned, such as ACPICA compiler declarations and bhyve
vmm/e1000/register headers, plus narrow dependencies on the child providers.
No new broad subpackage, source glob, input omission or compatibility alias was
introduced. COPYRIGHT/version targets remain in the real configured graph.

Every former consumer's physical files and logical include names are exactly
preserved: bhyve 27, public ACPI 19, debugger 45, IASL 54 and autofs 1. The
original `/sys` strip prefix is Bazel source include spelling, not a host mount
or absolute checkout directory; autofs retains its basename include. All
original file bytes remain unchanged. Every remaining direct root file label
is root-owned. No production C/header/manual, compiler flag or package install
policy was modified.

## Checks performed

The corrected r6 query successfully analyzes all 111 existing configured
built-in source groups, with zero execution actions. r5 correctly failed on
missing required `kernel_source_revision` after the package errors were fixed.
A fresh r6 supplies actual git revision plus explicitly recorded dirty diff
identity; no rule/default validation or targets were bypassed. This is
analysis evidence, not complete kernel coverage or compilation.

All 14 native binary/install targets pass through the normal format-5
`build-bsd bazel-test` frontend: acpidump, acpiconf, einj, acpidb, iasl,
automountd and bhyve. Seven fresh independent maintained Make builds/install
references also pass. No new frontend C, SDK, signing or publication input is
needed for source-owner changes. The native profile has no runnable tests;
compile/install success is not reported as a test-suite or hardware pass.

All 131 final per-path install records and literal files match Make. This
includes bhyve keyboard layouts, GDB data and slirp helper, plus autofs helper
scripts/configuration. Sixteen installed debug-link CRC checks pass. Both
autofs hardlinks have matching Make source/target inode identities and exact
native alias payload/target bindings. Bhyve's shared debug directory has two
Make package-tag contexts; the final staged entry matches, and both original
contexts are retained. This does not qualify full split-pkgbase ownership.

Seven immutable program ELF metadata/import/export/hardening comparisons pass.
Six dependency orders match. Bhyve's order differs despite equal dependency
sets; it remains a real reconciliation gate because order can affect symbol
resolution. Exact vectors are retained below. No full ABI or byte identity is
claimed. acpiconf/einj/acpidb differ only in seven DWARF sections. acpidump,
iasl, automountd and bhyve also differ in physical runtime/data sections;
reports retain every section difference. Their actual causes need analysis,
not a blanket source-path explanation. Those wider existing native declaration
limits do not alter the exact before/after header ownership proof.

Make dependency order for bhyve:

```text
libproc.so.5
libctf.so.2
libelf.so.2
libz.so.6
librtld_db.so.2
libthr.so.3
libutil.so.10
libvmmapi.so.7
libmd.so.7
libnv.so.1
libuvmem.so.1
librt.so.1
libsbuf.so.6
libcam.so.7
libprivate9p.so.1
libprivateucl.so.1
libxo.so.0
libnetgraph.so.4
libcrypto.so.35
libssl.so.35
libc.so.7
```

Native dependency order for bhyve:

```text
libproc.so.5
libctf.so.2
libelf.so.2
librtld_db.so.2
libvmmapi.so.7
libmd.so.7
libnv.so.1
libuvmem.so.1
librt.so.1
libz.so.6
libutil.so.10
libsbuf.so.6
libcam.so.7
libprivate9p.so.1
libprivateucl.so.1
libxo.so.0
libnetgraph.so.4
libcrypto.so.35
libssl.so.35
libthr.so.3
libc.so.7
```

## Retained evidence

All paths below are under `/usr/obj/usr/src/`:

- `bazel-root-header-owner-{before,after}-20261101.json`: full original file
  inventory/hash records and exact physical/logical header closure comparisons.
- `bazel-kernel-native-closure-query-r{5,6}-20261101/`: original failure,
  successful actual configured query, commands/JDK/environment/source identity.
- `bazel-root-header-*-make-20261101/`: all seven independent receipts, actual
  Make commands, dependency files, stages and component METALOGs.
- `bazel-root-header-userland-qualification-r1-20261101/`: passed normal frontend
  receipt and hash-verified immutable binary/archive captures, execution logs.
- `bazel-root-header-userland-install-audit-20261101/report.json`: all final
  metadata/payload/hardlink/CRC checks and original repeated directory contexts.
- `bazel-root-header-*-elf-audit-20261101.json`: original ELF contracts,
  dependency order and all physical section differences.
- `bazel-root-header-*-20261101.py` retain query/audit implementations.

The disk guard exits zero without reserve interruption. Sixteen logical CPUs
are selected, and all outputs stay under /usr/obj. No program/device/service
was activated on the host; no VM, mount, installation or reboot was performed.
Full kernel/world/pkgbase, live ACPI/autofs/hypervisor behavior, independent
configuration coverage, and controlled performance remain open. Make remains
production/default.
