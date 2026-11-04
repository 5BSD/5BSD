# Native GPT/ZFS BIOS boot qualification (2026-11-04)

## Source-owned construction

The previously missing gptzfsboot component now builds ten original entry
compiler contexts with the standalone i386 SDK. Shared sources and physical
headers have package-owned labels and architecture views preserve machine/pc
and sibling x86 includes. Compiler policy retains BOOT2, GPT/MBR/ZFS/GELI support,
original warning/optimization/debug operands and the existing ABI. The original
Make prerequisite zfsboot.o: zfsimpl.c is explicitly represented through
additional_compiler_inputs even though it is not a compiler include; actual
execution logs verify that input rather than inferring it from BUILD presence.

An ordered direct SDK link preserves crt0, zfsboot, sio, cons, bcache, devopen,
disk, part, zfs_cmd and misc, then native libi386 and libsa32 archives. A separate
GPT loader links at 0x7c00; the client links at zero. Declared flat conversions
and execution-configured native btxld produce the real BIOS image. Public
artifacts cross explicit i386 boundaries without leaking CcInfo to hosted links.
No Make objects, fixture images or comparison controls feed the production graph.

The existing typed COM port, speed and UART format settings apply. Selected
GELI/disk/ZFS prerequisites are explicit and unsupported archive profiles remain
incompatible. Shared boot_data_installation carries man/mancompress/split_manpages
policy; the real archive uses original account/mtree policy and the existing
loader_source_date_epoch. No leaf-specific manual policy is duplicated.

The existing host artifact test is parameterized over selected BIOS components.
The gpt_iso_boot_test target retains its two components, while the new
//tools/build/bazel:gpt_bios_boot_test includes GPT/ZFS as the third. Both use the
same real ELF32/BTX layout, archive/policy and actual ISO size-guard assertions.
No target firmware executable runs in the host test. Known Make entry inventories
remain independent assertions against missing or wrong-ABI object construction.

## Retained evidence

All roots below are under /usr/obj/usr/src.

- bazel-gptzfsboot-make-r1-20261104: fresh maintained original Make reference,
  sixteen jobs and explicit passed original LIBI386/LIBSA32 receipt bindings.
  The strict reference helper proves both actual custom-link operands. Original
  SDK startup/kernel and packing tools remain external reference prerequisites.
- bazel-gptzfsboot-dependencies-r1-20261104: ten original compiler -M controls,
  exact source/recipe/compiler/dependency hashes and before/after original-file
  bindings. The nine existing Make dependency files are retained too. Dependency
  control output is separate from original code-generation objects.
- bazel-gptzfsboot-r1/r2-20261104: normal maintained build-bsd native graph and
  archive construction. R2 passes all 27 selected test targets: three execute,
  24 reuse valid cached results. The original two-component and new three-
  component boot tests each execute four methods. Wrapper XML counts targets,
  not unittest methods. Existing boot2/legacy/EFI assertions remain intact.
- bazel-gptzfsboot-filename-control-r1-20261104: nine original default entry
  objects match native allocated/symbolic/relocation contracts directly. The
  sole disk.o allocated difference is an assertion's diagnostic filename; its
  original compiler control explains it without removing the assertion. Four
  prior original library filename controls (three libsa32, one BIOS Teken) retain
  their original proof hashes. Independent original link/objcopy/BTX recipes
  then reproduce the complete native client and final image bytes. The GPT
  loader stub equals untouched Make bytes. Production has no filename mapping,
  binary edit or assertion-disable flag. Separate DWARF/source mapping remains
  unqualified; object contract equality is not full debug-byte equality.
- bazel-gptzfsboot-site-r1-20261104: COM2 (760), 57600 baud, UART format 7 and
  uncompressed separate-manual policy pass the real three-component artifact
  test. This uses existing typed settings, not a replacement source profile.
- bazel-gptzfsboot-options-control-r1-20261104: ten independent original entry
  compiler option controls match the configured native contracts. All thirty
  BIOS archive member contracts are compared: comconsole changes with the
  console options, and Teken retains the known filename control; the other 28
  match original contracts. Original ordered link/flatten/BTX recipes reproduce
  the configured whole client, loader stub and image bytes. This is an explicit
  original compiler/recipe control, not a complete alternate Make system build.
- bazel-gptzfsboot-split-man-make-r1-20261104: actual original Make installation
  with WITHOUT_MANCOMPRESS and WITH_MANSPLITPKG. Its plaintext manual path,
  package=bootloader-man ownership, root/wheel permissions and source bytes
  match the native configured installation.
- bazel-gptzfsboot-review-r1-20261104: twenty compiler contexts across two
  profiles, 910 canonical consumed source/header pairs and 32 complete producer
  chains. The one explicit zfsimpl.c prerequisite is verified in both compiler
  actions in addition to that consumed-pair count. All original source-owned
  compiler operands remain in order, with ABI/SDK/output/dependency/include-view
  plumbing explicitly accounted for. Both final links bind exact object/archive
  order and selected tools; flat/BTX/archive outputs bind to captured artifacts.
  Two installed file records are checked in both profiles (four comparisons),
  including actual manifest package tags, archive payloads and /boot directory
  metadata. Thirty previous boot products remain whole-byte identical: sixteen
  EFI images, BIOS Lua image/archive, combined boot2, seven legacy BIOS/BTX
  images, and the two GPT/ISO images plus their two archives.

## Frontend, observability and remaining scope

The maintained build-bsd.c dispatch and format-5 backend already accept the
public source targets and existing console/manual settings; no new C switch,
staging exception or publication repository is needed. The manual and completion
plan are updated with this scope. Original C/assembly, assertions and diagnostics
are unchanged. These preboot components contain no OS DTrace/BSM provider to
migrate; construction tests do not establish live probes or audit delivery.

PXE/alternate BIOS and IA32 profiles, complete world/kernel/modules/pkgbase,
bootstrap, debugger/source lookup, sandbox/cache/incremental acceptance and broad
CPU/memory/disk I/O/storage comparison remain open. Normal firmware/VM startup,
ZFS reader/pool-feature behavior, disk/console access and boot-environment loading
require actual matching guest/hardware tests. This record does not prove them.
Frontend/client timing and RSS logs do not measure the persistent JVM or a
complete system build; they are not performance acceptance evidence.
Make stays production/default; BIP stays excluded. No running-system install,
host upgrade, reboot, package publication or VM execution occurred in this batch.
