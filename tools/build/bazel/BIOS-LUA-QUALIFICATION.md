# Complete native BIOS Lua loader (2026-11-04)

## Source-owned construction

The new stand/i386/loader_lua contribution crosses an explicit i386 standalone
boundary into a source-owned graph in stand/i386/loader. It compiles the original
36 selected entry sources and declares all consumed physical headers, including
the load_elf/load_elf_obj/reloc_elf textual C templates. Version generation uses
the maintained newvers.sh with bootstrap loader/x86 identity and the existing
typed reproducibility/metadata inputs. The existing Lua path provider supplies
the interpreter path. No native action executes Make or imports Make objects,
archives or migration metadata.

The static ELF link preserves crt0.o first, all 36 objects in the original order,
then regular Lua, BIOS libi386 and standalone libsa archives. It retains the
original script, origin zero, garbage collection, retained linker sets, maximum
page size and no-rosegment policy. Make disables separate debug files for this
static program; the entry compile contexts preserve that behavior.

Both BTX binary prerequisites now use the real i386 standalone toolchain, declared
SDK linker and public artifact boundaries. Their original manual hosted-ABI
cc_binary declarations are removed. Independent Make comparisons show both
assembler objects and both flat binaries are byte-for-byte unchanged.

## Explicit inputs and supported profile

| Setting under //tools/build/bazel/config | Default | Effect |
| --- | ---: | --- |
| loader_bios_textonly | true | Selects the currently qualified source profile. |
| loader_bios_max_size | 505000 | Enforced on the actual stripped ELF client. |
| loader_bios_address | 2097152 | BTX stub origin and final a.out entry. |

The address also reaches the original LOADER_ADDRESS compiler definition. The
current assembly does not use that macro, so its object bytes do not change;
the linked stub does change with its origin. The selected site profile uses
3145728 and a tighter 500000-byte maximum. Actual compiler/link/strip/BTX records
prove the configured operands, and the real artifact test passes at that address.
The ELF client remains unchanged across these address-only construction choices.
Existing serial/debug/framebuffer inputs remain owned by the BIOS library.

This graph currently qualifies default text-only Lua with GELI, disk, network,
MD and ZFS enabled and the regular loader verifier disabled. Its compatibility
conditions reject unsupported source profiles, including graphical and verifier
variants, rather than silently building this source selection for them. Alternate
interpreters and those profiles remain explicit follow-up work.

## Size enforcement and the inherited debug-link defect

The new declared strip action runs the selected SDK strip tool using the original
recipe. It writes a private temporary file, checks its actual size and atomically
publishes it only on success. Its maximum is a typed input, not a generated-image
size chosen to make qualification pass. Failed attempts leave a previous output
unchanged and remove the temporary file. The test exercises the real CLI at the
exact observed size and at one byte below that size. A separate full frontend
build with maximum 1 fails in BSDBootStripClient, not in a substituted test.

Independent original compiler controls first proved all complete ELF load
segments matched native output. The remaining four client-byte differences were
exactly the CRC inside an inherited .gnu_debuglink naming crt0.o.debug. That file
describes a relocatable startup object, not the complete static executable, whose
Make rule disables separate program debug files. The real artifact regression
was added and failed on that stale link before either producer was changed.
Both Make and the native strip helper now remove it. No executable segment or
assertion is removed, no size limit is raised and the regression remains strict.

The corrected default client is 488328 bytes, with 16672 bytes available under
505000. The pre-cleanup reference was 488400 with 16600 available. The complete
page-aligned a.out image remains 499712 bytes. These are component sizes, not
runtime RAM or whole-image performance measurements.

## Installation and provider integration

The contribution declares /boot/loader_lua root:wheel 0555 in bootloader, with
/boot/loader and /boot/zfsloader hardlinks, matching the selected Make policy.
Shared directory metadata comes from maintained BSD.root.dist and account IDs
from the source account files. This is a component contribution, not a complete
bootloader package, full installed-system inventory or published repository.

The actual deterministic tar is built through bsd_install_archive. The explicit
ABI boundary now forwards BsdInstallArchiveInfo/BsdInstallArchiveSetInfo with
their existing output groups. It still rejects executable tools/tests and never
forwards CcInfo. The host-side archive-set target proves the typed archive can be
aggregated after the boundary. The test checks actual payload bytes, numeric
ownership/modes and hardlink targets, then extracts the validated build-owned
archive and checks real shared inodes and 0555 modes. Logical root ownership is
checked in tar metadata; no running-system root installation is performed.

The initial archive extraction assertion exposed Python data_filter's deliberate
addition of owner write permission. The tar header was correct. The test keeps
its path/type/link validation and mode assertions and uses mode-preserving
extraction for that owned fixture. Production archive generation is unchanged.

## Evidence

All paths below are under /usr/obj/usr/src.

- bazel-bios-loader-lua-make-r1-20261104 and -r2-20261104: original complete
  Make references before/after cleanup, with original archive receipt bindings,
  reproducible versions, metadata and sixteen jobs. Their linked symbol inputs
  are byte-identical; only the strip recipe changes.
- bazel-bios-btx-make-r1-20261104 and bazel-bios-btxldr-make-r1-20261104:
  independent original BTX prerequisites.
- bazel-bios-loader-r8-20261104: final normal frontend build, real installation
  archive and twenty-four passing tests. The BIOS wrapper runs six methods,
  covering real source/ELF ABI, full a.out/BTX/client layout, absence of inherited
  startup debug links, installation policy, archive/inodes/modes and guarded strip.
- bazel-bios-loader-object-review-r2-20261104: all 36 final entry contracts versus
  post-fix Make. Thirty-five allocated/symbolic/identity/external contracts match
  directly; disk.o differs only in allocated diagnostic filename data. All raw
  symbolic/identity/external contracts match. Both BTX objects/binaries match bytes.
- bazel-bios-loader-filename-control-r1-20261104: five isolated original compiler
  filename controls (disk, three previously qualified libsa objects and Teken),
  original link/strip/pack commands and exact matching complete ELF load segments.
  It retains the four original nonallocated debug-link CRC differences.
- bazel-bios-loader-filename-control-r2-20261104: the corrected original strip
  and BTX recipes applied to those independent controls. The complete stripped
  ELF client and a.out image match native bytes. Production macro mappings are
  unchanged and original reference files remain untouched.
- bazel-bios-loader-site-r2-20261104: post-cleanup site profile at address 3145728
  with maximum 500000, including the five core real-image/guard tests before the
  additional archive assertion was introduced.
- bazel-bios-loader-overflow-r1-20261104: retained full-build rejection at maximum
  1 before metadata cleanup. The final wrapper separately tests the unchanged
  guard on the corrected client at its exact size and one byte below it.
- bazel-bios-loader-debuglink-failure-r1-20261104: retained real-image regression
  failure before clearing the stale startup debug link.
- bazel-bios-loader-action-review-r1-20261104: actual compiler dependency/output
  chains, complete link order, default/site address and size operands, strip/BTX
  producers and installation archive bound to their compact execution records.
- bazel-bios-loader-final-review-r1-20261104: source/evidence bindings, final
  client/control and archive/reference checks, and sixteen unchanged prior EFI
  images. Setup failures r1-r4 and the r7 archive-test assumption remain recorded.

Full unstripped/debug-file byte and source-mapping equivalence remain unqualified.
Archive and format tests do not execute BIOS, boot a complete native system, test
network/login services or establish CPU/memory/disk performance acceptance.

The maintained build-bsd format-5 target/test/settings path handles these targets;
its C dispatch needs no special action or one-off production command. The backend,
tests and manual are updated together. Make remains production/default. Next
complete alternate BIOS/IA32 source profiles and GPT/ZFS/ISO/PXE consumers, then
close complete world/kernel/pkgbase, bootstrap, runtime/VM and performance gates.
