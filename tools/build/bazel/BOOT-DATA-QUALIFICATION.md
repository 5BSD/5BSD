# Native boot data contributions (2026-11-04)

## Source ownership and normal frontend

Six source components now declare their installation payloads in native Bazel:
stand/defaults, images, lua, forth, man and fonts. The stand package aggregates
these through boot_data_manifest, boot_data_archive and boot_data_package_layout.
The layout remains explicitly component-scoped; it cannot publish an incomplete
bootloader package. Other boot programs and directory package assignments remain
separate integration work. Make stays the production/default system backend.

Source-owned lists retain the selected Make inventories; no action or repository
rule invokes/parses Make to construct them. Thirteen normal/optional-bold BDF
pairs use the real native vtfontcvt, then declared gzip actions. Existing embedded
C font generation shares the extended rule without changing its default output.
Regular scripts, loader defaults, the actual 5BSD logo, font index and manuals
are declared data. Manuals use their source section, compression and pkgbase tags.
Forth selects the actual AMD64 machine loader.rc and common ARM64/RISC-V files.

Creating the stand package required moving seven existing stand-owned header/
source declarations out of the repository root and updating their consumers.
This moves Bazel ownership without changing physical source paths. Existing
AMD64 and cross-loader artifacts are checked for byte preservation.

The maintained build-bsd bazel-test action already accepts format-5 inputs with
explicit SDKs, target labels, tests, jobs and build-settings. No new C frontend
switch or replacement builder is needed. Useful labels include:

- //stand:boot_data_manifest
- //stand:boot_data_archive
- //stand:boot_data_package_layout
- //stand:boot_data_test
- //stand/<component>:install_manifest

The configured contribution observes man, mancompress, forth, loader_lua, efi,
loader_kboot and split_manpages settings under //tools/build/bazel/config.
KBOOT follows src.opts.mk: supported on AMD64/ARM64 and forced off on RISC-V,
including its manual. These controls currently qualify this contribution;
they do not establish that every other base component supports those choices.
Other source options, manual filters and complete world selection remain gates.

loader_lua_path is shared with the existing compiler definitions and installation
prefix. New directories require explicit policy through boot_data_directory_policy,
a file-valued label setting selecting an optional supplemental mtree artifact.
The maintained default selects no override, using an empty optional filegroup,
without fabricating an mtree file. The archive rule accepts zero/one configured
file, rejects multiple files or simultaneous explicit/configured overrides, and
retains the existing source mtree/account checks. Site metadata augments base
policy; the archive does not guess missing directory permissions.
The supplied site.mtree is explicitly a qualification fixture, never a default.
Arbitrary build configuration and policy inputs are not signature verification,
verified boot or protection against compromised root. BIP remains excluded.

## Evidence and configuration coverage

All paths below are under /usr/obj/usr/src. The maintained install-reference.py
constructs six sequential independent default Make references, plus original
cross Forth, RISC-V manual, split-manual, reduced-option and MAN=no references.
Original receipts, compiler/profile identity, payload hashes and METALOGs remain.

| Selected profile | Installed files | Aggregate archive members |
| --- | ---: | ---: |
| AMD64 default | 86 | 97 |
| ARM64 default | 86 | 97 |
| RISC-V default | 85 | 96 |
| AMD64/ARM64 site Lua path, split manuals | 86 | 98 |
| RISC-V site Lua path, split manuals | 85 | 97 |
| Interpreters/EFI/KBOOT disabled, raw manuals | 19 | 29 |
| MAN=no, split requested | 57 | 63 |

Defaults comprise exact file-inventory, bytes, owner/group/mode and package-tag
comparisons, followed by actual archive extraction and byte/mode checks. Root
IDs are logical archive metadata; this is not a root installation test. Site
checks bind all original payloads to relocated script destinations and inspect
the supplied 0750 directory modes. Raw/split/no-manual cases inspect real Make
option references and component package layouts, without deleting unexpected
files or silently substituting another profile.

Retained review directories include:

- bazel-boot-data-amd64-tested-review-r1-20261104 and final-default reviews:
  all selected default files, generated-font preservation, and extracted archive.
- bazel-boot-data-aarch64-review-r1-20261104 and final-default reviews:
  actual common Forth startup files against their original cross reference.
- bazel-boot-data-riscv64-profile-review-r2-20261104 and final-default reviews:
  corrected actual 85-file profile against its original RISC-V manual inventory.
- bazel-boot-data-{site,reduced,noman}-review-r1-20261104 and cross site reviews:
  configured destination sets, original payload bytes, tags, modes and layouts.
- Existing AMD64 EFI regression retains 225 captured outputs. Each cross
  loader retains its 48 entries, full link and embedded font: 50 exact outputs.
  Final default restoration reviews bind these to the final declarations.

Bazel boot_data_test inspects actual VFNT geometry, complete bitmap/mapping
bounds, glyph references and catalog references; it exercises corrupt-font
rejection. It verifies gzip stream integrity/deterministic headers, manual text,
PNG chunk checksums and regular-file ownership/modes. Directory permissions
remain declared policy inputs. Four unittest methods run within one Bazel test
wrapper; method count is not claimed as four separate Bazel XML test cases.
Foreign profiles use the explicit host-artifact provider, without executing
foreign programs or firmware.

## Findings retained and corrected

The initial catalog test treated MENU records as filenames. The corrected test
follows INDEX.fonts/kbdmap's documented MENU/FONT localization syntax and keeps
actual font references checked. The first supplemental mtree fixture omitted
parent hierarchy and failed parsing; the corrected fixture is a normal mtree
with declared parent entries. Both failures are retained.

The first RISC-V data report incorrectly reused AMD64's manual inventory and
therefore included loader.kboot.8. It is superseded, not evidence for the current
profile. Source/profile inspection found src.opts.mk's BROKEN_OPTIONS exclusion;
the native constraint/option selectors and independent reference now omit it.

Compiled-path review also found stale literal LUA_PATH=/boot/lua operands in
the earlier cross entry declarations beside the typed path provider. They are
removed. Both real cross builds now verify allocated strings in interp_lua.o,
private Lua loadlib.o and the final loader, together with all eighteen installed
script destinations, against /boot/site/lua. Debug strings are not used to infer
this. Default restoration checks the original loader payloads. This does not
execute firmware lookups or establish a bootable complete image.

A custom path without supplemental directory policy is rejected by the actual
archive action. The policy-cache review changes only the fixture's two directory
modes from 0750 to 0710 and restores it. Actual action logs bind each archive to
the policy input digest. Only the archive/test spawn; font conversion, compression
and compilation do not rerun. Only the archive capture changes, and all 271
captures restore exactly. This is component invalidation/restoration evidence,
not a whole-system, remote-cache or comparative performance result.

## Remaining completion gates

Complete bootloader programs/variants, shared help and directory package
aggregation, firmware command/device/error execution, full world/kernel/modules,
reproducible bootstrap/output-query/sandbox/cache, verified combined publication
and comparative CPU/memory/disk I/O/storage remain open. No host install, upgrade,
reboot or firmware VM was performed. Native tests do not certify signing keys,
Secure Boot, runtime policy or whole-image integrity.
