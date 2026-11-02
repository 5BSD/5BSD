# Kernel module debug qualification: proven scope and remaining work

## Scope correction (November 2, 2026)

Some module qualification prose described CTF/debug payloads as matching Make
more broadly than its checker established. The artifact observer compares the
installed, stripped module ELF section inventories/payloads, including retained
CTF, and independently checks each binary's GNU debug link against its separate
debug file's CRC. It does not compare the two separate debug files to each other.
The CRC check proves a matching binary/debug pair, not DWARF equivalence to Make.

Historical module statements about CTF/debug equality must be read with this
limit unless their evidence explicitly compares separate debug files. The
runtime ELF, CTF, full compiler-input, installation and instrumentation results
are unchanged. Full debug/source-resolution qualification remains open.

## Direct evidence

The actual separate debug ELF files were directly compared for five cohorts:

| Cohort | Actual native/original pairs |
| --- | ---: |
| System and I/O | 37 |
| Network/routing/entropy | 37 |
| RDMA/InfiniBand/Mellanox | 14 |
| Chelsio | 11 |
| Compatibility/storage/tracing | 18 |
| Total | 117 |

All file hashes still match the files previously checked by their respective
CRC verifiers. None of these 117 separate file pairs is whole-file byte-equal.
The directly differing section set is the same in all five cohorts:
.debug_line, .debug_str, .rela.debug_info, .rela.debug_line and
.note.gnu.build-id. No other debug-file section inventory/payload differs under
this direct comparison. The raw section hashes and file bindings are retained;
these differences are not ignored or classified as proved semantic equivalence.

For one inspected cfiscsi example, .debug_str differs only in compilation
directory: native '.', original its private Make object directory. LLVM's parsed
DIE dump additionally shows native relative architecture-header spellings such
as ./sys/x86/include/_types.h versus original /usr/src/sys/x86/include/_types.h.
The line-table directory/file encodings also differ. This example does not prove
that every observed difference in every module is only path spelling.

The installed LLVM 19 dwarfdump verifier passes all 36 current native/original
compatibility/storage/tracing debug files. That proves DWARF structural
consistency within the verifier's scope, not source lookup or equivalence.

Evidence in each /usr/obj/usr/src/bazel-<cohort>-modules-review-r1-20261102:
separate-debug-comparison.json. Current verifier commands, tool hash, status and
logs: bazel-compat-services-modules-review-r1-20261102/separate-debug-verify.*.
The section reader, direct observer and raw input files remain bound in reviews.

## First decoded DIE comparison

A retained LLVM 19 --debug-info --show-form comparison of the actual cfiscsi
native/original pair contains 37,006 decoded lines. After removing only the
first diagnostic filename line, exactly 289 lines differ, all DW_AT_comp_dir
or DW_AT_decl_file attributes; every other decoded line is exact. No source
paths were normalized, substituted or classified as equivalent. The raw
--debug-line dumps and their diff are retained as well. Generated-header paths
include Bazel virtual-include directories, so fixing architecture-header
spellings alone would not close source lookup. This one-module result does
not establish equivalence for the other 116 pairs or installed source lookup.

Evidence: bazel-compat-services-modules-review-r1-20261102/cfiscsi-dwarf-reader/
comparison.json and raw stdout/stderr files, bound to the actual reader/tool and
input hashes. This is a narrower decoded comparison, not a replacement for the
required canonical layout, source-resolution and debugger gates below.

## Required before claiming complete debug parity

1. Define a consistent canonical source/debug layout, independently of temporary
   object directories and checkout locations; make relevant configuration inputs
   explicit rather than embedding a machine's build directory.
2. Account for original/native DIEs, type information, ranges, locations, code
   addresses and source/line mappings with a real DWARF reader. A different
   directory table need not mean different semantics, but must be demonstrated.
3. Resolve source paths against the actual proposed installed source/debug
   package layout, including generated interfaces and headers. Relative paths
   require an explicit, qualified lookup policy.
4. Correct the shared toolchain/source-path policy where needed. Requalify its
   affected current kernel/module/world artifacts and retained runtime/CTF
   regressions. Do not add per-module compiler mappings merely to hide failed
   comparisons or rewrite artifacts.
5. Test actual debugger symbol and source/line lookup, and retain meaningful
   negative checks. A well-formed DWARF file and a passing CRC alone are not this
   gate.
6. Carry any new input, source/debug packaging or validation requirement through
   maintained build-bsd/backend/helpers/tests/manual in the same change.

Keep Make production/default until the complete objective's gates, including
this debug qualification, pass. This document changes evidence scope and the
completion plan; it introduces no source/compiler/security/publication policy.
