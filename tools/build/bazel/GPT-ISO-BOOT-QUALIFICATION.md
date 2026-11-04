# Native GPT and ISO BIOS boot qualification (2026-11-04)

## Native graph

The missing gptboot and isoboot components now build their ten original entry
compiler contexts through the standalone i386 SDK. Shared assembly/C/templates
and physical headers have source-package owners. Architecture views preserve
machine/pc and sibling x86 includes. The included ufsread.c/gpt.c templates are
explicit textual inputs, not omitted C files. Existing standalone header rules
provide the original aliases and deliberately empty xlocale compatibility files
that Make itself produces. No reference object/header is imported into Bazel.

Each native graph explicitly links gptldr at 0x7c00 and its BTX client at zero.
The client preserves crt0, program, sio, drv, cons order followed by the real
native libsa32 archive. The existing boot-link rule now accepts ordered declared
archives and rejects duplicate inputs or a multi-file/non-archive selection.
The SDK objcopy creates flat clients and the native execution-configured btxld
packs the real kernel/stub/client. Public firmware products cross an i386
artifact boundary, without forwarding CcInfo into hosted links.

Original serial parameters are typed inputs: loader_comconsole_port and
loader_comconsole_speed reuse the platform-library settings; the new
loader_boot_serial_format defaults to Make's 3. loader_gptboot_ufs selects
UFS1_AND_UFS2 (default), UFS1_ONLY or UFS2_ONLY. The new
loader_isoboot_max_size retains Make's 30720-byte bound. The actual ISO image
passes a declared size-check action; it is neither padded to that bound nor
allowed to bypass it. The byte helper validates before replacing output on
size failure. Selected GELI/disk prerequisites are explicit; unsupported library
source profiles remain incompatible pending their own qualification.

Both components reuse boot_data_installation for man/mancompress/split_manpages
selection and expose real image/manual installation manifests and archives,
with source account/mtree policy and the existing loader_source_date_epoch.
The normal format-5 build-bsd interface carries all targets/settings without a
new C dispatcher, stage override or alternative production build entry point.
Make remains production/default; BIP is excluded.

## Original reference integrity

The maintained install-reference.py archive interface previously required every
bound library to occur in LDADD. These original custom boot recipes instead
invoke ld directly. With --make-meta, the helper now audits the completed original
link metadata after construction and before installation. Every supplied archive
must occur as an actual operand in a recognized compiler/linker recipe with its
matching completed output inside the isolated object tree. Merely querying a
Make variable, a compile-only recipe, another output or a path printed by a later
shell command does not qualify. Shell operators/expansions are refused by this
conservative direct-recipe checker; response-file/shell-wrapper links need an
explicit future implementation. Existing archive/compiler/ABI hashes and
before/after input checks remain intact. Non-metadata references retain their
original LDADD requirement. No CC/CFLAGS/LDADD injection is added to the API.

The archive validator's eleven unittest methods cover the previous binding
checks and new positive/negative recipe consumption/output/escape cases. Their
fixtures are test data, never native production defaults. Final-source original
Make references exercise the strict parser on both real boot link recipes.

## Retained evidence

All roots below are under /usr/obj/usr/src.

- bazel-{gptboot,isoboot}-make-r1-20261104: fresh original Make constructions
  using the explicitly bound original libsa32 reference. --make-meta captures
  the actual custom links and installation records. Each uses sixteen jobs.
- bazel-{gptboot,isoboot}-make-r2-20261104: final strict-helper original builds;
  actual archive-consumption audits pass and all image/client/stub bytes equal
  the first references. Original SDK BTX startup/kernel and packing tools are
  recorded reference prerequisites, not a claim of hermetic bootstrap.
- bazel-gpt-original-dependencies-r1-20261104: these custom Make recipes do not
  generate .depend files. Ten separate original-compiler -M controls capture
  their actual include closure without changing any original objects. The
  ordinary code-generation recipe/flags stay bound alongside each control.
- bazel-gpt-reference-tests-r1-20261104: the initial extended archive validator
  and existing boot regressions pass through build-bsd.
- bazel-gpt-iso-r1/r2/r3/r4-20261104: complete native pipelines and archives. R2
  executes the new four-method real-image test; R3 passes the final eleven-method archive validator. Final R4 passes 26 selected
  targets (two execute, 24 reuse unchanged cached test results), including the
  updated real-image/manual-policy test. Wrapper XML counts are test targets,
  not unittest-method totals. Existing boot2 and legacy checks remain intact.
- bazel-gptboot-filename-control-r1-20261104: all ten default entry objects
  match original Make allocated/symbolic/relocation contracts. ISO client/image
  and both loader stubs match untouched Make bytes. GPT client/image differ
  because of existing library compiler filename strings. Independent original
  link/objcopy/BTX recipes using the three previously qualified original libsa32
  filename controls reproduce the whole native client and image bytes exactly.
  The untouched reference remains retained; production uses no filename map,
  copied control object or binary rewriting. Debug/source lookup is not qualified.
- bazel-gpt-iso-site-r1-20261104 and bazel-gpt-iso-ufs1-r1-20261104: both
  four-method artifact tests pass with COM2 (760), 57600 baud, serial format 7,
  ISO bound 16384 and UFS2_ONLY/UFS1_ONLY respectively.
- bazel-gpt-iso-options-control-{site,ufs1}-r1-20261104: independent original
  compiler/link/objcopy/BTX option controls reproduce all entry contracts and
  complete configured image/client/stub bytes. These are compiler/recipe controls,
  not two complete reconfigured Make system builds.
- bazel-gpt-iso-overflow-r1-20261104: a real build-bsd profile with ISO bound 1
  fails the actual BSDBootImageBytes action with the original overflow assertion.
  Its FAILED.json and execution evidence are retained. The host test separately
  checks exact observed size succeeds and one byte below fails without replacing
  the previous output.
- bazel-gpt-iso-review-r1-20261104: thirty actual compiler contexts across the
  three profiles, 1098 canonical consumed source/header pairs, 69 compiler/link/
  flatten/BTX/check/archive chains. Four original installation records are
  checked across three profiles (12 comparisons), including exact manual bytes,
  modes/ownership/package metadata and real native image payload bindings.
  Twenty-six prior products remain byte-identical: sixteen EFI images, the BIOS
  Lua image/archive, boot2's combined image and all seven legacy BIOS/BTX images.

## Shared manual policy qualification

Final review replaced duplicated leaf manual rules with the existing shared
boot_data_installation helper. The final default archives still match their
qualified payload/metadata policy. Existing man=false omits manuals;
mancompress=false and split_manpages=true install original uncompressed sources
with package=bootloader-man. These inputs change package contents without
changing boot images.

bazel-gpt-iso-{no-man,split-man}-r1-20261104 execute the real artifact test for
both options. Four additional actual Make references are
bazel-{gptboot,isoboot}-no-man-make-r1-20261104 and
bazel-{gptboot,isoboot}-split-man-make-r2-20261104. The latter selects original
WITH_MANSPLITPKG, the real Make counterpart of native split_manpages. The initial
SPLIT_MANPAGES selector was ineffective: its reference builds succeeded but their
unsplit package tags failed installation comparison. Those r1 references remain
retained and are not qualified as split-manual references. Assertions were not
relaxed to accept their wrong package policy.

bazel-gpt-manual-policy-review-r1-20261104 compares default and both manual modes
against six actual Make references. It checks exact paths, owners/groups, modes,
file/package tags, original manual bytes and actual native archive image payloads;
it also checks the original /boot directory record against the real tar directory.

## Remaining scope

GPT/ZFS and PXE consumers, other boot interpreters/profiles, normal firmware/VM
startup, complete world/kernel/modules/pkgbase/hardware publication, bootstrap,
DWARF/debugger/source mapping, broad sandbox/cache/incremental acceptance and
CPU/memory/disk I/O/storage measurements remain open. This is construction
qualification, not boot/device behavior or a system performance comparison.
No running-system installation, host upgrade, reboot or publication occurred.
