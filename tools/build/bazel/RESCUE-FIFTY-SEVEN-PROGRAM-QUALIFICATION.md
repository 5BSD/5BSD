# Native fifty-seven-application rescue construction

## Filesystem programs and compiler policy (2026-11-05)

The selected AMD64 core adds clri, fsirand, dumpfs, tunefs, newfs, fsck,
newfs_msdos and umount. It now constructs 57 of 103 default rescue applications.
Each package owns its sources/headers and ordered compiler objects; foreign
geom_bsd_enc, vfslist and mounttab sources retain their real source owners.
Native libufs joins the selected original archive order. Umount retains its
DTrace provider and static anchor through the existing source-owned producer.
Normal hosted program targets are unchanged.

The rescue macro now accepts explicit WARNS=2, 3 or 6 profiles for the selected
Clang toolchain. Clri/dumpfs use 2, fsirand/newfs use 3, and the others retain 6.
These model maintained source policy, rather than disabling warnings after a
failure. Existing level-6 flags are unchanged. Unsupported levels fail explicitly.
Actual original/native compiler recipes verify the declarations and execution.

## Evidence

Retained evidence is under `/usr/obj/usr/src/`.

- `bazel-rescue-57-native-r1-20261105`: maintained frontend, sixteen jobs, passing
  construction and tests on the first native qualification. The runtime wrapper
  executes 71 methods; source-settings executes its separate 28 methods.
- New safe host cases cover all eight entry points before opening devices. Real
  private regular-file workflows create both UFS1 and UFS2 images, inspect their
  superblocks, change/check the volume label, randomize inode generations and
  clear inode 2. Each image stays bounded at 16 MiB and is removed afterward.
  A separate private 4 MiB FAT12 image is created and its boot signature checked.
  No host device, mount, system fstab or installed helper is used. These tests
  establish file-image behavior, not mounted filesystem/kernel acceptance.
- `bazel-rescue-filesystem-more-make-r1-20261105/report.json`: fresh actual eight
  original generated `_make` targets, sixteen workers, isolated object roots.
  4629 source/policy/header/tool bindings are checked before/after, including
  foreign source directories. Fifteen actual C objects and one anchored provider
  are produced; original compiler/provider recipes and consumed headers are kept.
- `bazel-rescue-57-action-review-r2-20261105/review.json`: all fifteen executed
  native compiler commands exactly match original warning and define vectors,
  with matching optimization, C17, debug, compression, SSP and non-PIE policy.
  Actual output hashes are checked before saving raw objects/dependency files.
  The compact execution log is decoded with the original upstream converter;
  all 409 converter/runtime bindings are checked before/after. Adapter r1 parsed
  the application label incorrectly and selected no records; it is explicitly
  rejected and retained. No production rule or checker was weakened to fix it.
- `bazel-rescue-57-dependency-review-r1-20261105/review.json`: all fifteen actual
  compiler dependency closures, 999 consumed occurrences, are declared action
  inputs with matching digests. Original/native basename-and-byte multisets,
  including multiplicity, match while permitting source-owned virtual includes
  and SDK/object-root relocation. This does not establish independent full
  logical-path namespace equivalence or incremental-invalidation behavior.
- `bazel-rescue-57-object-review-r1-20261105/review.json`: all sixteen C/provider
  objects are compared without rewriting bytes. Twelve C allocated/symbolic
  contracts match directly. Tunefs and mkfs_msdos retain assertion-filename
  differences, and umount retains DTrace path aliases. The provider has raw DOF
  encoding/alias differences. Complete raw debug/DOF equality is not claimed.
- `bazel-rescue-57-provider-review-r1-20261105/review.json`: the maintained ET_REL
  checker verifies actual unmount provider/function/relocation/patch sites,
  schemas and metadata. Each differing alias independently agrees with its real
  object path hash. The traced C allocated bytes and nondebug relocations match;
  live registration/firing and complete raw DOF encoding remain unqualified.
- `bazel-rescue-57-filename-controls-r1-20261105/review.json`: isolated original
  tunefs/mkfs_msdos compiler commands with the explicit macro-prefix-map control
  match native allocated/symbolic contracts. Original inputs/objects and native
  flags/bytes stay unchanged. This explains assertion diagnostic paths without
  claiming raw baseline or independent DWARF equality.
- `bazel-rescue-57-pipeline-review-r1-20261105/review.json`: fresh original
  crunchgen/generated Make on identical captured native application, ordered
  archive and startup inputs match main C and all 116 whole-byte outputs: main
  object, 57 stubs, 57 combined ld-r/crunchide objects and the executable. AMD64
  ET_EXEC, no interpreter/dynamic segment, nonexecutable stack and GNU_RELRO
  checks pass. This proves original pipeline behavior using identical inputs,
  not independent reconstruction of all libraries or complete world.

## Integration and remaining gates

The maintained format-5 frontend already supports these targets and settings.
Its manual, completion plan and observability ledger are updated. No C dispatcher,
settings schema, signing, installation or publication helper change is needed.
Make stays production/default; BIP remains excluded. No host installation,
upgrade or reboot occurred.

Finish the remaining 46 default rescue applications and actual rescue library
variants, configuration/architecture selections, complete installation/aliases/
helper paths and debug/metadata/pkgbase comparisons. Private file images do not
replace disposable VM qualification of mounted filesystems and privileged storage
operations. Complete world/kernel/modules, reproducible bootstrap, hardware and
combined publication, runtime and CPU/memory/disk/cache/sandbox gates remain open.
