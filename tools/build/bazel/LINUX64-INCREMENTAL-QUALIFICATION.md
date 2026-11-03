# Linux64 generated-image incremental qualification

## Result (2026-11-03)

The committed production Linux64 image/embedding graph passes a three-build
original/changed/restored input check. The isolated checkout is commit
74256e0ee3a7c57dae9ac5d291b6c3f9ef951f18 under /usr/obj; /usr/src is not mutated.
All three builds use maintained native-qualify.py format-5 inputs, jobs=16,
the same source-derived Bazel state and ordinary action caching. No cache purge,
forced rebuild, copied Make image or alternate embedding rule is used.

The selected target is
//sys/compat/linux:linux64_linux_vdso_inc_module_object_files. The sole changed
input is sys/amd64/linux/linux_vdso.lds.s: a nonallocated INFO section containing
one byte is added inside SECTIONS. This changes the full ELF image without a
source-text change to the assembly that embeds it. Then the original script is
restored. The isolated checkout is clean at the end.

| Case | Generated image bytes | Embedding object bytes | Result |
| --- | ---: | ---: | --- |
| Original A1 | 5392 | 6016 | Original qualified production bytes |
| Changed B | 5488 | 6112 | Both image and embedding change |
| Restored A2 | 5392 | 6016 | Both entire files equal A1 exactly |

Every case has an actual successful BSDVdsoLink and CppCompile witness in its
own execution log, with current input/output hashes. The entire embedding .data
payload equals the actual generated image. B performs a real uncached embedding
compile. Its ordinary compiler dependency file remains byte-identical to A1 and
does not name the image: the explicit additional compiler input is necessary.
Restoration is checked by bytes, without requiring or claiming a cache hit.
The unchanged .d file in all three cases demonstrates why source/dependency-file
inspection alone cannot establish this graph edge.

## Evidence and limits

Evidence root:
/usr/obj/usr/src/bazel-linux64-incbin-incremental-r1-20261102/
contains summary.json, per-case execution logs and receipts, source mutation
records, actual actions, preserved image/object/dependency payloads and strict
reviews. Original/changed linker scripts and their hashes are retained.

This is an isolated source-input fixture using the maintained backend. Normal
build-bsd production profiles are separately qualified; the frontend fixes its
source root to /usr/src and no source-override flag is introduced for this test.
No build inputs, frontend interface, staging, signing or publication policy
changes are needed. This closes this specific generated-image invalidation gate,
not whole-system cache, remote execution, sandbox, runtime or performance gates.
Make stays production/default; BIP remains excluded.
