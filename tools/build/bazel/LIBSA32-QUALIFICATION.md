# Regular and private EFI IA32 standalone libraries (2026-11-04)

## Source-owned contexts

The shared standalone graph now represents both selected AMD64 DO32 contexts:
stand/libsa32 and stand/efi/libsa32efi. Their BUILD aliases select distinct regular
and private EFI archives owned by stand/libsa, through explicit i386 artifact
boundaries. Native actions do not execute Make, read migration metadata or import
prebuilt Make objects. The common inventory, architecture selection and original
member order remain ordinary Starlark declarations.

Both select the actual i386 setjmp assembler and retain the x86 hypervisor helper.
Their machine view declares seventeen physical i386 headers and the existing
twelve-header x86 sibling view, derived from original consumed dependencies.
Regular flags preserve -m32/-march=i386, no SIMD/soft-float, size optimization and
function/data sections. Private EFI flags additionally preserve short wchar,
firmware alignment, verifier/PCR policy and the inherited include search context.
These are AMD64 DO32 boot contexts, not an i386 system/world or hosted sysroot.

Make's 32-bit ffs_subr size policy requires a distinct source compiler. Its new
single-source group applies STANDALONE_SMALL only on x86_32, after the shared
architecture flags. The common tables compiler receives no extra size flag.
The existing md5c size flag and three per-source Rijndael NDEBUG selections remain;
no other assertion is suppressed. Other ABI branches retain the original flags.

## Independent Make comparisons

Evidence is under /usr/obj/usr/src. The maintained reference CLI builds each
original component with metadata and sixteen jobs. Archives remain internal:
their component METALOGs add no payload to the seeded mtree metadata.

| Context | Members | Raw allocated/symbolic contracts equal | Isolated original filename controls |
| --- | ---: | ---: | ---: |
| regular IA32 | 191 | 188 | 3/3 |
| private EFI IA32 | 260 | 257 | 3/3 |

Every member's ELF identity and external symbol records match, and both member
orders match exactly. The same three raw allocated-data differences occur in
each context: lz4, zfs_zstd and md5c embed absolute-versus-relative assertion
filenames. Their symbolic relocation records match directly in these IA32 runs.
Six isolated original-compiler controls explain the data differences without
rewriting objects, changing production mappings or disabling assertions.
Original reference files are hashed before/after those controls. Full object
and separate-debug equality is not claimed.

The private reference explicitly uses the declared policy's build UTC and fresh
local ta.h, vse.h and manifests.h. Those three generated headers match native
outputs byte-for-byte; the reference verifies their actual consumption. Native
configuration remains explicit, with no implicit signer, certificate or clock.

All 451 selected producer records and both archive outputs are bound to actual
Bazel execution-log digests using the verified upstream converter. They preserve
required CPU/firmware flags, private verifier isolation and exact per-source
size/assertion policy. No implicit SDK system-header search, stack protector or
production macro filename mapping is accepted.

## Tests and regressions

The final maintained frontend run passes fourteen wrappers. The new archive test
inspects all 451 actual ELF32 members, core I/O/setjmp APIs, absence of host stack
protector imports and verifier APIs restricted to the private EFI context. It
executes native inspection tools, never target firmware or setjmp code.

All fifteen existing EFI program/architecture images retain exact bytes. The
shared source-group change is also built on regular AMD64, ARM64 and RISC-V:
all 191/190/194 member contracts and archive orders retain their prior qualified
values. Whole archive bytes differ, so debug/source lookup remains open; code,
allocated data, symbolic relocations and external records are the comparison
scope. Those 575 existing variants are regression coverage, not new programs.

## Retained failures and evidence

- bazel-libsa32-make-r1-20261104: successful regular reference.
- bazel-libsa32-efi-make-r1-20261104: stale prepared-tree ta.h shadowing the fresh
  local output is rejected. The maintained local-generated-header option supplies
  early local include priority and verifies requested headers are consumed.
- bazel-libsa32-efi-make-r2-20261104: the helper rejects a component file-set change
  while its reference is running; a BUILD alias was added during that interval.
  No verifier was weakened. Revision 3 repeats with stable source declarations.
- bazel-libsa32-efi-make-r3-20261104: successful isolated private reference.
- bazel-libsa32-r1-20261104: both native archives and prior tests.
- bazel-libsa32-r2-20261104: new archive test and explicit generated-header capture.
- bazel-libsa32-r3-20261104: final existing-ABI regular-library regressions.
- bazel-libsa32-{regular,efi}-object-review-r1-20261104: raw object comparisons.
- bazel-libsa32-filename-controls-r1-20261104: six matching compiler controls.
- bazel-libsa32-action-review-r1-20261104: complete selected IA32 producer chain.
- bazel-libsa32-regular-regression-review-r1-20261104: three existing regular ABIs.
- bazel-libsa32-final-review-r1-20261104: consolidated bindings and commit record.

These are 451 object variants of one library in two contexts. They do not qualify
complete BIOS/IA32 loader programs, every optional feature or a whole world.
Continue the 32-bit interpreters and complete loader/link/install composition.
Shared warning policy, debug/source lookup, bootstrap, sandbox/cache/relocation,
VM runtime and fair CPU/memory/disk gates remain open. Make remains production and
default; BIP remains excluded. No host installation, upgrade, publication, reboot
or target execution occurred.
