# Native AMD64 libkboot construction (2026-11-04)

The maintained Make world traversal now discovers 2,128 directories. All 2,128
component metadata queries pass using 16 workers. The declaration survey reports
1,510 local BUILD owners and 618 directories with an ancestor owner; 158 of the
latter declare programs or libraries. These are review queues, not counts of
missing binaries or a completion percentage. Parent-owned iconv modules, for
example, already have real native producers. Evidence:
`/usr/obj/usr/src/bazel-world-inventory-refresh-20261104` and
`/usr/obj/usr/src/bazel-world-components-refresh-20261104`.

## Implemented

`//stand/kboot/libkboot:static_archive` crosses the existing standalone artifact
boundary into a real AMD64 compiler/archive graph. Its eight original sources
retain source-owned flags, original object order, PIC/no-red-zone/soft-float
policy, startup and Linux syscall assembly, and declared architecture/header
views. GELI and disk macros use existing typed inputs in their original option
positions. Other architectures and regular verifier profiles remain unavailable;
there is no hosted-libc or prebuilt-library substitute. Production actions do
not query Make or consume exported Make metadata.

The archive is internal boot support. The original Make reference installs no
component files, so this change adds no invented installation contribution.
It does not build the complete loader.kboot consumer yet.

## Evidence

- Original maintained Make build:
  `/usr/obj/usr/src/bazel-libkboot-make-r1-20261104`.
- Native frontend qualification:
  `/usr/obj/usr/src/bazel-libkboot-native-r5-20261104`.
- Independent review:
  `/usr/obj/usr/src/bazel-libkboot-review-r4-20261104/review.json`.

All eight object contracts match original Make allocated bytes, symbols and
relocations directly. Whole debug object bytes differ and are not claimed equal.
The audit checks original compiler policy in order and 255 consumed source/header
pairs against actual logged input digests. Generated header symlinks are compared
by content, including their original SDK identity. The real archive action is
bound to the captured archive; the member-order/ELF/API tests inspect that archive.
The Python suite has three methods within one Bazel test target. Related BIOS
archive, object-comparator and source-settings targets are also selected by the
final frontend run.

The first frontend input failed strict schema validation. A subsequent analysis
rejected two labels crossing a newly declared package boundary. Both were fixed.
The first compiler-policy review rejected moved feature macros; their original
positions were restored. These failed attempts remain retained. The passing
construction precedes no Linux syscall execution or firmware/OS startup claim.

The current format-5 build-bsd dispatcher already accepts the source-owned graph;
no C dispatch or signing/staging/publication policy change is needed. Its manual
is updated. Full world/kernel/module/package/bootstrap/debug/runtime/performance
qualification remains open. Make remains the production default; BIP is excluded.
