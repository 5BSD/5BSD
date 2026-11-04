# Native userboot shared-object construction checkpoint (2026-11-04)

Both selected AMD64 Lua/Forth variants now compile 42 native PIC contexts each.
Source-owned, deduplicated compiler contexts preserve original flag positions,
PIC level/defines, version generation and per-source declarations. Actual Bazel
PIC outputs feed cc_binary(linkshared=True), with cc_import and the existing
ordered dependency boundary for the original interpreter/libsa archives. This
uses Bazel's documented shared-binary model for dlopen consumers:
https://bazel.build/reference/be/c-cpp#cc_binary.linkshared
Production actions do not query Make or reuse original object/archive outputs.

The existing debug splitter now exposes unstripped_files alongside debug_files
in both enabled/disabled branches. The raw shared cc_binary remains inside the
producer graph. Only data from the debug splitter crosses the unchanged strict
standalone artifact boundary; no tool/test rejection is relaxed. Public image,
symbols, debug, objects, install_manifest and install_archive targets expose the
selected products. Other architectures and regular verifier contexts remain
incompatible. Broader feature/profile support is not claimed.

## Evidence achieved

- All 84 PIC object contracts match: 82 directly and two through original
  diagnostic-filename compiler controls, with no production path maps or
  assertion suppression.
- The audit binds 3,896 consumed source/header pairs and both actual 42-object
  link orders. Standard shared rules preserve original object and archive
  precedence. There is no hosted startup or implicit libc dependency.
- Both objects have the original SONAME, no DT_NEEDED entries and a valid
  GNU debuglink filename/CRC for their actual debug file.
- Default installation inventories match original Make: Lua contributes image,
  debug, help and default alias; Forth contributes image/debug. Both retain
  root/wheel 0444 files and the original debug-directory metadata. Tar payload,
  permissions and hardlink targets are checked. Original Make alias inode
  identity is checked; its trailing empty tag is ignored as an empty tag, not
  treated as another package tag.
- Actual hosted interpreter tests initialize both real shared objects, execute
  echo and show through the original callback harness, and finish their quit
  paths. Assertions require standalone reply lines, not echoed input text.
  Independent original Make/native runs agree on reply counts, language and
  exit statuses (Lua 1, Forth 0). Each uses an empty private host root. Lua's
  expected missing loader.lua message means this does not qualify scripted boot.
- Final regression: 35 test targets pass, one executed and 34 cached. All 34
  selected prior boot outputs remain exact; all 84 userboot PIC objects and
  their audited products are rebound to the passed capture.

Evidence is under /usr/obj/usr/src:

- bazel-userboot-shared-native-r6-20261104
- bazel-userboot-shared-review-r2-20261104 (review.json, regression.json)
- bazel-userboot-runtime-controls-r1-20261104
- bazel-userboot-shared-regression-r1-20261104

Retained failed attempts include shared generator visibility, configurable-list
append, generated-version dependency classification and an incorrect expectation
that show emits a variable name. The passing test expects its actual value and
requires real command replies. Successful compiler actions from the earlier
passing shared-object run are rebound by exact hashes when cached later.

## Follow-up status; this is not complete qualification

The subsequent [image/default comparison](USERBOOT-IMAGE-PARITY.md) proves
complete ELF runtime-image parity and the automatic Forth default. Raw debug
bytes and the remaining profiles/runtime scopes below remain open.

1. Original whole linked-image recipes with library controls now pass for ELF
   identity, entry, program headers and allocated sections. Complete debug/source
   parity remains open; raw unstripped/debug byte equality is not claimed.
2. Automatic Forth-default ownership now passes a fresh original stage and real
   extracted-alias execution. Remaining explicit/default/site routes stay open.
3. Test real packaged Lua/Forth scripts, virtual disks and guest kernel startup;
   current empty-root callback checks do not demonstrate those capabilities.
4. Continue the complete world/kernel/module/package/bootstrap/debug/runtime and
   CPU/memory/disk performance gates. Make remains the production default.

The existing maintained format-5 build-bsd dispatcher needs no new C action. The
manual, plan and observability record are updated. No host installation,
publication or boot policy changes; BIP remains excluded.
