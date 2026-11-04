# Native AMD64 EFI final ELF link (2026-11-04)

`//stand/efi/loader:loader_lua_full` links all 58 selected entry objects with the
native private Lua, EFI and standalone archives. It produces loader_lua.sym.full,
the ELF input to Make's debug splitting and PE conversion. This is a final ELF
payload, not a firmware-tested PE image or a complete boot qualification.

## Native toolchain integration

bsd_firmware_link uses find_cc_toolchain and cc_common's compilation/linking
APIs. It validates an explicit complete object order, selects exactly one artifact
per archive label, rejects duplicate inputs and preserves the ordered archive
extraction context. The real source linker script is a declared input. Ordinary
Bazel toolchain inputs, action caching and response files apply; no host compiler,
Make invocation, archive extraction or prelinked SDK loader is used by the rule.

The selected AMD64 profile uses the source script's _start entry, PIE relocation,
nocombreloc, symbolic/notext, and existing bind-now/RELRO toolchain policy. The
link has -nostdlib, no added system library and no undefined symbols or DT_NEEDED.
Source/header/option limits are those of LOADER-ENTRY-QUALIFICATION.md and the
three component archive qualification records. Other architectures and optional
profiles remain open. There is no firmware startup-library inference or fallback.

## Closed original reference and payload comparisons

Retained paths below are under /usr/obj/usr/src:

- bazel-loader-link-amd64-r1-20261104: successful maintained build-bsd format-5
  build with all 16 logical CPUs; captures entry objects, all three archives and
  the final linked ELF.
- bazel-loader-link-amd64-make-closed-r1-20261104: the recorded original loader
  link executed with the same 58 original Make objects and three explicitly
  bound, independently built original component archives. This replaces the
  earlier link's dependence on untracked world SDK archive contents. Input
  digests are checked before and after; the original outputs are preserved.
- bazel-loader-link-amd64-review-r1-20261104/raw-review.json: raw native versus
  closed original differences remain in .text, .data and .rela.dyn. These are
  retained rather than relabelled as byte equality.
- bazel-loader-link-amd64-controls-r1-20261104: six original compiler recipes
  independently reexecuted with only a macro filename-prefix mapping: entry
  disk/gfx_fb, EFI Teken, standalone lz4/zfs_zstd/md5c. Isolated original archives
  retain their exact member order with just those controlled objects replaced.
  The original final link then uses those controls. No production flags, native
  objects, raw references or comparison payloads are rewritten.
- controlled-payload-review.json in the raw review: the native ELF agrees with
  that controlled original on ELF identity, entry point, flags, complete program
  headers, every allocated section's bytes/address/type/flags/size/alignment,
  and the dynamic table. The native ELF has no undefined symbols or DT_NEEDED.
- bazel-loader-link-amd64-final-r1-20261104: final source repeat including the
  explicit-order guard and the existing six ordering tests. All six reported
  cases pass, and the full ELF hash is unchanged from the first build.

- bazel-loader-link-amd64-action-review-r1-20261104: the actual successful
  toolchain link and hash-verified response file bind every one of the 58 object
  captures in original Make order, all three archive captures in order, and
  the source linker script and final output digest. No host system library
  appears in the expanded command. final-repeat-review.json in the raw review
  binds the unchanged final-source ELF and six reported passing test cases.

The filename controls explain actual diagnostic strings and address effects;
they do not establish raw full-object or DWARF equality. The native build does
not suppress assertions, remap their filenames or copy original linked output.

## Remaining gates

Debug splitting, PE conversion, timestamp configuration, installation metadata,
source lookup/debugger behavior and actual firmware execution still need
qualification. ARM64/RISC-V entry/link construction and alternate loader options
remain open. The installed help/PE/default-loader links must be derived from the
selected profile, not invented package fixtures.

The existing maintained frontend's format-5 targets/settings drive this build;
no new C switch or alternate frontend was needed. Complete world/kernel/module,
bootstrap/sandbox/cache, pkgbase/hardware/combined publication and measured
CPU/memory/disk I/O/storage remain required. Make remains production/default;
BIP is excluded. No host install, upgrade, reboot or VM occurred here.
