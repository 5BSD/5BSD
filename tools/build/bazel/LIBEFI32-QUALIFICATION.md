# AMD64 DO32 EFI support library (2026-11-04)

## Source-owned implementation

The selected world includes stand/efi/libefi32. Its Makefile sets DO32 and
includes the libefi Makefile. The new BUILD alias therefore selects the shared
libefi source graph through an explicit i386 artifact boundary. It does not copy
Make objects or author a second source inventory. The existing seventeen common
sources, Teken and time.c retain the original nineteen-member archive order.

The x86_32 context preserves Make's -m32/-march=i386, short wchar, eight-byte
firmware integer alignment, no-SIMD/soft-float, PIC, size optimization and section
policies. Its explicit i386 machine header view has the seven original consumed
headers; the existing six-header x86 sibling view is shared. The compile-only
ABI contract checks pointer/status width, CHAR16/GUID, wchar and UINT64 alignment.
Other CPU branches retain their flags and source selections.

This is the AMD64 DO32 firmware context, not support for an i386 system/world.
The archive is INTERNALLIB: its Make METALOG is identical to the seeded mtree
METALOG, adding no component payload.
No userland installation or artificial package record is introduced.

## Independent comparison

The maintained install-reference.py builds the original component with metadata
and all sixteen CPUs in bazel-libefi32-make-r1-20261104 under /usr/obj/usr/src.
Its original object, header, recipe and archive inputs remain intact.

All nineteen member identities and external symbol records match. Eighteen
members directly match exact allocated bytes and symbolic relocations. Teken
retains the known absolute-versus-relative assertion filename difference. Its
separate original-compiler control maps only the macro filename prefix and
redirects output/dependency bookkeeping into private evidence storage. That
control matches the complete allocated/symbolic contract exactly. Production
compiler flags do not add a filename map or disable assertions. Raw differences
remain recorded; full object/debug equality is not claimed.

The reusable elf_object_contract.py inspects ELF32 and ELF64 little-endian
relocatable objects. It compares exact allocated data and layout, ELF identity,
external symbol records and relocations resolved through real symbol tables.
REL implicit addends remain in the exact allocated bytes; RELA addends remain
explicit. Debug-only data is outside its scope. Independent readelf counts agree
for all 2,461 relocations targeting allocated sections in the nineteen original
ELF32 objects. Its Bazel tests use real ELF32/64 objects and detect changed code
and ABI identity while excluding nonallocated metadata.

The actual compact execution log binds all nineteen matching producer digests,
required IA32 firmware flags and the resulting archive. No implicit SDK system
headers, stack protector, NDEBUG or production filename mapping is accepted.
The verified upstream Bazel 9.3.1 log converter is used; native actions do not
execute Make or parse migration metadata.

## Test runfiles correction

The initial two-ABI inspector test found a real ambiguity: configured outputs
shared the same short_path, and a runfiles tree represented only one ABI.
The native Python runner now rejects conflicting configured runfiles during
analysis. The positive test declares distinct ABI input paths using pinned
Skylib copy_file with allow_symlink, producing two ordinary symlink actions;
producer bytes and archive identities do not change. The negative analysis
case confirms the unnamespaced pair is rejected before test execution.
This changes test validation, not the boot artifact or installation interfaces.

Evidence below /usr/obj/usr/src:

- bazel-libefi32-r1-20261104: initial archive/ABI success.
- bazel-libefi32-r2-20261104: retained wrong-ABI runfiles test failure and copied
  failure reports; no original failure log is lost to subsequent builds.
- bazel-libefi32-r3-20261104: runfiles correction and passing inspector tests.
- bazel-libefi32-r4-20261104: final inspector identity checks and thirteen passing
  wrappers, including the four libefi archive methods and four inspector methods.
- bazel-libefi32-object-review-r1-20261104: untouched Make/native object captures,
  raw differences and independent readelf crosscheck.
- bazel-libefi32-filename-control-r1-20261104: isolated Teken control and original
  reference-file hash checks.
- bazel-libefi32-action-review-r1-20261104: nineteen actual compiler records and
  the matching archive producer.
- bazel-test-runfiles-collision-rejection-r1-20261104: real analysis rejection.
- bazel-libefi32-final-review-r1-20261104: final source/artifact/commit bindings.

All fifteen existing EFI program/architecture images must retain their prior
whole-file bytes. This selected default component does not qualify every optional
setting, complete BIOS/IA32 loaders, libsa32, 32-bit interpreters or a full world.

## Remaining work

Continue selected libsa32/private EFI, interpreter and BIOS/userboot contexts,
then complete world/kernel/install/pkgbase and hardware/publication composition.
Shared werror policy, separate debug/source lookup, bootstrap, sandbox/cache,
VM runtime and CPU/memory/disk performance gates remain open. Make remains the
production/default backend. BIP remains excluded. No host installation, upgrade,
reboot, publication or firmware execution occurred.
