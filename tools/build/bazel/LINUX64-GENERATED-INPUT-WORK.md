# Linux64 native module generated-input work

## Independent original evidence (November 2, 2026)

Both original Make plain/CTF controls pass. Their generated Linux VDSO images
are each 5,392 bytes and byte-identical across the profiles. The entire image is
exactly the .data payload of each original linux_vdso_inc.o. The source assembly
uses .incbin "linux_vdso.so.o". Its compiler .depend file lists only source/global
options, but Make's explicit metadata correctly lists the generated image as a
prerequisite. Do not equate compiler dependency files with the complete Make
graph, or omit this image from a native assembly action's declared inputs.

The original link order is linux_locore.o then linux_vdso_gtod.o, with the
maintained linux_vdso.lds.s script and explicit shared/soname/hash/unwind/build-id
flags. Original generated linux_assym.h bytes are equal across both profiles.
Raw hashes/commands and independent ELF embedding comparison:
/usr/obj/usr/src/bazel-linux64-generated-input-review-r1-20261102/original-vdso-inputs.json.
This is original-side evidence; no native or runtime qualification is claimed.

## Exact helper dependency controls

Six additional original compiler replays cover linux_genassym, linux_locore and
linux_vdso_gtod in both profiles. They add only dependency-reporting flags and a
private output filename while retaining the original working directory, source,
compiler and semantic flags. All six complete ELF objects reproduce their
originals byte-for-byte, and the original artifacts remain unchanged. Their
actual compiler dependency files record 280 occurrences for native declaration
work. This closes an inventory gap in custom recipes that did not emit .d files;
it does not qualify a native helper or installed Linuxulator behavior.

Evidence: /usr/obj/usr/src/bazel-linux64-helper-dependency-controls-r1-20261102/
results.json, original/actual command vectors, output and dependency hashes.

## Native implementation requirements

- Reuse existing syscall-table generation from syscalls.master/syscalls.conf;
  add the actual module syscall-switch output where required. Do not silently
  replace a generated contract with whichever checked-in file is convenient.
- Compile linux_genassym.c with its original common-symbol/layout flags and use
  maintained kernel_constants extraction. Native layout and Linux constants,
  not copied original headers, must feed the assembly actions.
- Preserve the custom VDSO compiler vectors: small model, PIC, asynchronous
  unwind tables, no stack protector, explicit system/include roots. These are
  different from ordinary module flags. Validate actual flags and inputs.
- Preserve linux_locore.asm's preprocessing semantics. The current rules_cc
  file-type list classifies .asm as raw assembly and .S as preprocessed assembly.
  Check actual actions/dependency discovery; use an explicit byte-preserving
  source alias if needed. The earlier bsd_source_alias accepted .S but not
  .asm input; the narrow extension is now exercised by actual native actions. No source-text rewrite is needed.
- Reuse declared VDSO linking and validate the target image against its actual
  architecture/runtime contract. The amd64 runtime reserves two pages; track
  the source/target layout supplying that limit instead of borrowing the native
  BSD VDSO's unrelated 2,048-byte limit.
- Declare the generated image as a compiler input for the unchanged incbin
  assembly. Verify assembler include lookup uses its declared generated location
  without depending on a temporary directory, copied Make image, or undeclared
  working-directory file. Qualify a changed-image rebuild/cache invalidation.
- Preserve linux_support.S's original no-CTF custom recipe, the embedding
  assembly's ordinary conversion policy, export-all ordering, installation and
  source/debug limitations. Do not apply one assembly exception to every source.
- Compare actual original/native full module artifacts and generated intermediate
  payloads, declared/consumed inputs, link order and installation. Keep standalone
  DWARF/source resolution as an explicit separate gate.

The native module graph is now applied, with 34 module objects, a native layout
producer, generated syscall sources/headers and ordered native VDSO compilation
and linking. The unchanged incbin source declares that generated image as an
additional compiler input and uses its configured output directory for assembler
lookup. No C/Make source or old Make image is copied into this graph.

Both native profiles and actual module/helper/input/link/artifact/install
comparisons now pass; see [the qualification record](LINUX64-MODULE-QUALIFICATION.md).
The first build found an omitted architecture view member, linux_emul_md.h; its
failed action is retained. The corrected view covers the original consumed four
headers: two generated syscall headers and two unchanged source headers. Full
plain-byte module equality, all five syscall payloads and the complete native
VDSO image match original Make. The subsequent [original/changed/restored input check](LINUX64-INCREMENTAL-QUALIFICATION.md)
closes this specific changed-image invalidation gate. Separate DWARF, runtime
and full-system qualification remain open.

The existing source-alias primitive accepts .asm for byte-preserving .S aliases.
Architecture views forward declared generated headers as well as source files.
Kernel target identity is separate from default freestanding compilation flags,
allowing the Linux VDSO helpers to disable that feature and preserve their
original hosted compiler flags. Ordinary kernel defaults remain selected.
Normal build-bsd format-5/backend paths carry these targets without new frontend
inputs; the maintained manual records the source/ABI handling in this change.
The native BSD VDSO validator has a different ABI/layout contract and is not
silently weakened for Linux. Original/native Linux image, embedding, declared
inputs are qualified by the module and subsequent incremental reviews. Full
Linuxulator execution, VM/runtime, other targets and performance remain open.
Make stays production/default; BIP stays excluded.
