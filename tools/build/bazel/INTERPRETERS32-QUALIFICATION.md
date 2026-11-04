# IA32 standalone and EFI interpreter archives (2026-11-04)

## Source-owned implementation

Regular liblua32/ficl32 and private EFI liblua32efi/ficl32efi now select the
shared Lua/Ficl source inventories through explicit i386 artifact boundaries.
The toolchain remains schema 2 with native AMD64 execution tools. These are
AMD64 DO32 boot components, not a new i386 world target. No production action
calls Make or imports original Make object files.

The architecture branches declare i386 machine headers and the x86 sibling
headers, Ficl's actual i386 sysdep source/header and its textual x86 source.
Regular objects retain the original no-PIC, soft-float, no-SIMD size policy.
Private EFI contexts add short wchar, no red zone and double alignment while
keeping their verifier settings separate from regular BIOS objects. Lua paths
continue to come from the existing typed path settings and provider.

The original IA32 EFI Lua wrapper omitted LOADER_VERITY_SUPPORT even though
its loader compiles authenticated-source admission and the native-width private
Lua wrapper enables it. It now includes that shared private wrapper after
setting DO32. This preserves the same admission behavior and recognition of
verified sources on IA32. It does not introduce a new verification mechanism.
The original pre-fix Make reference is retained separately; comparison uses a
fresh post-fix reference rather than claiming identical pre-fix behavior.

## Evidence

All paths below are under /usr/obj/usr/src. Independent Make references use the
maintained install-reference.py with sixteen jobs, original recipes and metadata.

| Context | Reference | Members | Raw ELF contracts equal | Isolated filename controls |
| --- | --- | ---: | ---: | ---: |
| regular Lua | bazel-liblua32-make-r1-20261104 | 31 | 31 | 0 |
| EFI Lua | bazel-liblua32-efi-make-r2-20261104 | 31 | 31 | 0 |
| regular Ficl | bazel-ficl32-make-r1-20261104 | 15 | 4 | 11 |
| EFI Ficl | bazel-ficl32-efi-make-r1-20261104 | 15 | 4 | 11 |

Every archive preserves original member order. All members match ELF32 identity,
external symbols and symbolic relocations directly. The Ficl differences are
allocated assertion filename strings. Twenty-two isolated original compiler
controls map only the source filename prefix and match all allocated/relocation/
external contracts. Production flags and raw Make artifacts are unchanged;
full object/debug byte equality is not claimed.

- bazel-interpreters32-r3-20261104: maintained build-bsd format-5 qualification,
  four new archive tests and fourteen existing wrappers, all eighteen passing.
  Tests inspect all 92 members, order, APIs and private verifier isolation;
  Lua also has compile-only number, FILE and EFI wchar ABI contracts.
- bazel-interpreters32-object-review-r2-20261104: immutable capture bindings,
  original archive hashes and all raw member comparison results.
- bazel-ficl32-filename-controls-r1-20261104 and
  bazel-ficl32-efi-filename-controls-r1-20261104: original compiler controls,
  original recipe/input hashes and unchanged original reference files.
- bazel-interpreters32-action-review-r2-20261104: compact execution log audit of
  all 92 actual compiler outputs and four archive producers, target flags,
  generated Ficl softcore dependency and private policy isolation.
- bazel-interpreters32-final-review-r1-20261104: source hashes and unchanged
  bytes for fifteen existing AMD64/ARM64/RISC-V EFI images.

The frontend's existing format-5 target/test dispatch handles these aliases;
no frontend C special case or new private build command is needed. Its manual
and observability ledger are updated in this change.

## Remaining scope

Complete IA32 loader/BIOS composition and boot execution, full debug parity,
complete world/kernel/pkgbase, reproducible bootstrap, runtime, publication,
sandbox/cache acceptance and CPU/memory/disk performance gates remain open.
Archive inspection does not establish live firmware behavior. Make stays the
production default. No running-system installation or reboot is performed.
