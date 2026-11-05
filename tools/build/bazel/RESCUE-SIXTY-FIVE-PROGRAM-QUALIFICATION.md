# Native sixty-five-application rescue construction

## Source declarations and dependencies (2026-11-05)

The selected AMD64 core adds sed, gzip, bzip2, mt, md5, ldconfig, sysctl and
fsck_msdosfs. It now links 65 of the default catalog's 103 applications.
Source-owned variants retain original warning levels, bzip2's large-file define,
FAT checker's HAVE_LIBUTIL_H, sysctl's RESCUE exclusion of JAIL, and the original
provider/Casper exclusions for gzip and md5. Sysctl retains its provider; the FAT
checker retains its provider and static DOF anchor. Hosted programs are unchanged.

Native lzma, pthread/libthr, mt, bz2, zstd and md archives join the selected
original library order through lazy cc_import dependencies. No SDK library archive
substitutes for native construction. Explicit access is granted only to legitimate
rescue/mt consumers of private lzma/zstd archives and the sbuf header.

Gzip includes six decompressor C fragments from gzip.c. The rescue macro now
accepts Bazel textual_hdrs for those actual includes: unbzip2.c, zuncompress.c,
unpack.c, unxz.c, unlz.c and unzstd.c. They are declared inputs, not separate
translation units or omitted decompressor features. Default empty textual_hdrs
preserves existing callers' behavior.

## Accepted and rejected evidence

Evidence is retained under `/usr/obj/usr/src/`.

- `bazel-rescue-65-native-r3-20261105`: maintained frontend, sixteen jobs,
  construction and both Bazel wrappers pass. Runtime executes 78 actual methods;
  source-settings executes its separate 28 methods. New cases cover sed extended
  expressions/private in-place backups, binary gzip/bzip2 round trips and original
  decompression aliases, an MD5 vector, read-only OS release lookup, and tape/
  linker argument rejection before access or mutation. The private 4 MiB FAT12
  image now also passes fsck_msdosfs -n and remains byte-identical afterward.
- Native r1 fails configured analysis on mt's private sbuf header. R2 fails gzip
  compilation because the rescue declaration omitted its textually included C
  fragments. Both are retained as failed; existing mutable testlog symlinks do not
  qualify those runs. Explicit header access and textual_hdrs fix the declarations
  without suppressing validation or dropping source functionality.
- `bazel-rescue-compression-more-make-r1-20261105/report.json`: fresh actual
  original generated eight `_make` targets, sixteen workers, isolated object
  roots. 4753 source/policy/header/tool bindings are checked before/after, including
  original foreign-source directories. Seventeen C/two provider objects and their
  actual compiler/provider recipes are recorded.
- `bazel-rescue-65-action-review-r1-20261105/review.json`: all seventeen actual
  native compiler warning/define vectors match original Make; optimization, C17,
  debug/compression, SSP and non-PIE policies match. Raw compiler/dependency output
  hashes are checked before copying. The original compact-log converter and all
  409 runtime/tool bindings are verified before/after.
- `bazel-rescue-65-dependency-review-r1-20261105/review.json`: 1032 consumed
  occurrences across all seventeen compiler closures are declared with matching
  digests. Original/native basename-and-byte multisets, including multiplicity,
  agree across virtual include/SDK/object roots. This verifies the decompressor
  fragments as actual consumed inputs. Full independent logical-path namespace
  equivalence and incremental invalidation remain separate gates.
- `bazel-rescue-65-object-review-r1-20261105/review.json`: all nineteen raw objects
  are compared without rewriting bytes. Thirteen C contracts agree directly;
  traced check.c differs in aliases, sysctl also has assertion-filename strings,
  and FAT dir.c/fat.c have assertion-filename differences. Two provider objects
  retain raw DOF/alias encoding differences. Full raw debug/DOF equality is not
  claimed.
- `bazel-rescue-65-filename-controls-r1-20261105/review.json`: isolated original
  FAT dir/fat compiler commands with explicit macro-prefix mapping match native
  allocated/symbolic contracts. Original inputs and objects remain unchanged.
- `bazel-rescue-65-sysctl-control-r1-20261105/review.json`: original sysctl compiler
  recipe plus explicit macro-prefix mapping, followed by its original DTrace -G
  recipe on private outputs, explains the combined assertion-path/alias difference.
  Original headers, sources and baseline objects stay unchanged; native production
  flags and bytes stay unchanged. The selected actual original tool is hash-bound.
- `bazel-rescue-65-provider-review-r2-20261105/review.json`: maintained ET_REL
  checks establish actual sysctl and FAT provider schemas/function/relocation/
  patched sites, including the anchored FAT provider. FAT probes genuinely belong
  to check.o; the checker uses that defining object rather than assuming main.o.
  All aliases independently match real object-path hashes. Untouched baseline
  schemas/sites are checked as well as the separately bound sysctl filename
  control. C allocated/nondebug relocation contracts agree with the qualified
  controls. R1 correctly rejects broad sysctl C equality against the untouched
  filename-bearing baseline; it is retained, not relabeled passed. Live firing,
  raw DOF encoding and independent DWARF parity remain unqualified.
- `bazel-rescue-65-pipeline-review-r1-20261105/review.json`: fresh original
  crunchgen/generated Make using identical captured native application, ordered
  archives and startup inputs match main C and all 132 whole-byte outputs:
  main object, 65 stubs, 65 ld-r/crunchide objects and the executable. AMD64
  ET_EXEC, no interpreter/dynamic segment, nonexecutable stack and GNU_RELRO checks
  pass. This proves pipeline behavior on identical inputs, not an independent
  full-library/world reconstruction. `thread-symbols.json` binds actual libpthread
  initialization/create symbols in that executable; it does not establish a
  thread stress/performance result.

## Frontend and remaining gates

The maintained format-5 frontend already supports these targets/settings; its
manual, plan and observability ledger are updated. No C dispatcher, settings
schema, signing, installation or publication helper change is required. Make
stays production/default and BIP stays excluded. No host installation, upgrade
or reboot occurred.

Continue the remaining 38 default applications, actual rescue library variants,
configuration/architecture selection, complete rescue installation/helper paths,
independent library/debug/metadata/pkgbase comparisons and mounted/privileged VM
qualification. Complete world/kernel/modules, reproducible bootstrap, hardware/
combined publication and CPU/memory/disk/cache/sandbox acceptance remain open.
Also review ordinary gzip's existing SDK DTrace/drti producer against the native
bootstrap path used elsewhere before full source-built generator acceptance;
rescue's deliberate provider exclusion does not exercise that ordinary producer.
