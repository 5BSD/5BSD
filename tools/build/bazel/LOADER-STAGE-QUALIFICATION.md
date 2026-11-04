# Selected AMD64 loader component staging (2026-11-04)

## Source-derived hierarchy and package scope

//stand/efi/loader:install_archive materializes the real PE/help/hardlink payload
through the maintained typed installation/archive pipeline. Required ancestor
directories come from etc/mtree/BSD.root.dist; named identities come from the
source master.passwd and group files. There is no inline system UID/GID map,
manual protected-path inventory or scan of the running host's package database.
The archive contains two directories and three file/link entries. Directory
modes/identities agree with Make's actual distrib-dirs metadata. Extraction
preserves the PE/help bytes, 0555/0444 modes and actual hardlink inode relationship.
This is a user-owned qualification extraction, not a root system installation.

//stand/efi/loader:component_package_layout explicitly partitions these three
entries into a component contribution to bootloader. It cannot become a complete
package manifest: other boot programs and profiles still need aggregation.
The existing scope guard is exercised. No incomplete bootloader.pkg is produced,
no package version is fabricated, and no repository pointer is advanced.

A retained directory-tag difference matters at aggregation: the source mtree
assigns /boot to bootloader, while the original component installdirs emits an
additional utilities assignment with identical owner/group/mode. bsd.dirs.mk's
fallback and the original pkgbase reader's multiple-assignment handling explain
that record; it is not silently called metadata equality. This component uses
canonical mtree ancestry. Complete package/directory assignment parity remains a
gate, including shared directory ownership across package contributions.

## Explicit archive time input

bsd_install_archive retains the existing explicit integer epoch API and now also
accepts epoch_setting, a typed decimal-string setting. Exactly one source of the
time is allowed; missing, negative, malformed and conflicting inputs are refused.
Decimal parsing is explicit, including leading zeros. Existing literal epochs
retain identical serialized bytes. The loader selects the existing configured
loader_source_date_epoch for both PE and staging time; no host clock is consulted.
Other callers keep their explicit time policy. No production/default backend or
package publication rule changes.

## Retained evidence

Paths below are under /usr/obj/usr/src:

- bazel-loader-pe-regressions-amd64-r1-20261104: existing conversion_test passes.
  Its immutable unittest log reports seven methods, including original recipe
  comparisons, future timestamp, raw sections, undefined imports before/after
  stripping, in-place source preservation and invalid time. Bazel's wrapper XML
  reports one test target/case; it is not described as seven XML cases.
- bazel-loader-stage-amd64-r1-20261104 and its review directory: five archive
  members, all declared payload bytes, logical root IDs, source directory modes,
  actual extracted hardlink and old integer epoch consumers are inspected.
  The legacy BIOS component archive still uses epoch 0; the existing fixture's
  explicit epoch 42 and fixture-only IDs are preserved.
- bazel-loader-stage-amd64-future-r1-20261104 and its future-review directory:
  real component members retain 2147483649 without truncation, and the PE agrees
  with the independently qualified original future recipe. The typed 00042 epoch
  fixture is byte-identical to the old literal 42 archive.
- Five reported guard cases pass: four new archive input rejections and the
  existing component-scope package manifest rejection. These are exact analysis
  error checks, not acceptance of an arbitrary failed build.
- The future run's executed-action-review.json distinguishes new guard/test and
  archive/PE actions. No compiler or final ELF link reruns occur. This is a
  component-local observation, not system-wide cache/performance qualification.

The first diagnostic extraction used Python's data filter, which deliberately
adds owner read/write bits. That failed mode comparison is preserved. The review
then checked the exact finite member/path/type/link allowlist before using
mode-preserving extraction. No source archive, original reference or product
code was adjusted to accommodate the diagnostic filter.

## Remaining completion gates

bazel-loader-stage-amd64-restored-r1-20261104 and restoration-review.json in the
future review bind exact final-source default restoration of the complete archive,
PE and component layout, plus five passing reported guard cases. Its actual
noncached spawn inventory contains only PE conversion and archive serialization. Complete bootloader and base package aggregation, shared directory
package assignments, full debug/source lookup, production trust policy and actual
firmware execution remain open. ARM64/RISC-V entry/stage/image profiles and
alternate loader options are still required, alongside full world/kernel/module,
reproducible bootstrap/output-query/sandbox/cache, hardware/combined publication
and comparative CPU/memory/disk I/O/storage performance gates. Make remains
production/default; BIP is excluded. No host install, upgrade, reboot or VM occurred.
