# ARM64 / RISC-V64 filesystem and ACL modules

2026-11-01. Explicit native declarations cover acl_nfs4, acl_posix1e, cd9660,
cd9660_iconv, fdescfs, nullfs, pseudofs, tmpfs and unionfs for both ARM64 and
RISC-V64. Each is selected by the independently architecture-checked GENERIC
Make inventories. This qualifies build/install artifacts for these candidates;
complete kernels, module sets and filesystem runtime behavior remain open.
Make remains the production backend; BIP is excluded.

## Inputs and maintained Make correction

The declarations compile the 26 original C sources with declared target headers
and registered target toolchains, using the existing relocatable/CTF/export/
shared-link/debug/install pipeline. Pseudofs, tmpfs and DDB option headers come
from each target's actual generated config tree. Existing pseudofs/tmpfs source
constants are shared with their amd64 declarations. Export lists remain explicit,
including nullfs's two exports, cd9660_iconv and pseudofs's public entry points.
No C routine, tracing site, audit path, target ABI policy or linker pipeline is
changed. There is no production Make parser or replacement header generator.

The first independent Make matrix passed 32 combinations and failed four clean
cd9660_iconv builds because vnode.h includes generated vnode_if.h, absent from
that module's SRCS. A prepopulated parent kernel tree can mask this missing
standalone dependency. The maintained Makefile now declares vnode_if.h, matching
the generated-header dependency used by the cd9660 module. The normal Make
rules generate it; no header is copied or synthesized for qualification. The
original failures remain under
`/usr/obj/usr/src/bazel-cross-filesystems-make-20261101/`.

## Actual comparison

The fresh corrected Make matrix passed all 36 build/install combinations:
nine modules, two target architectures, and CTF/debug off or on. References,
commands, target ARCH_FLAGS, resource counters, generated files and METALOGs are
under `/usr/obj/usr/src/bazel-cross-filesystems-make-r2-20261101/`. All sixteen
logical CPUs were available. Unprivileged staging uses normal NO_ROOT and
-U/-M/-D flags; NO_XREF excludes linker.hints. No host installation or loading
occurred.

The maintained `build-bsd bazel-test --arch arm64|riscv64` path built eighteen
explicit module/install targets per run with the existing kernel target profile
and typed CTF/debug settings. Receipts are at
`/usr/obj/usr/src/bazel-cross-filesystems-{arm64,riscv}-{plain,ctf}-r1-20261101/`.
No new frontend API, signing or publication behavior is introduced; the manual
records the expanded candidate coverage.

All eighteen no-debug module files match Make byte for byte. All eighteen
installed CTF/debug modules match every ELF section and file offset except the
contents of build-ID/debuglink. Code/data, symbols, relocations, CTF and SDT
match. Native and Make debuglink CRCs validate against their actual separate
debug files. Separate DWARF/build-ID/symbol/layout differences remain retained;
debugger source lookup and full debug-file identity remain unqualified. All 54
file/debug installation records match destination, type, root/wheel ownership,
mode and package/debug tags. Directory metadata and linker.hints are outside
this file comparison.

Reports, source/input hashes, scan, input JSON and reproduction scripts are at
`/usr/obj/usr/src/bazel-cross-filesystems-review-20261101/`. Kernel-profile builds
select artifacts and intentionally do not execute target tests. These are not
runtime test passes or controlled CPU/RAM/disk-performance results.

## Remaining gates

Matching-kernel loading/unloading, mount/unmount, vnode and layer behavior,
read/write/mmap, permissions/ACLs/MAC checks, rename/unlink, exhaustion and failure
paths require runtime tests. The bounded scan records nineteen SDT schemas in
cd9660_vnops, null_subr, tmpfs_subr, tmpfs_vnops and union_subr. Absence of direct
markers in other sources does not prove absent subsystem observation. Live
probe firing, audit delivery, debugger behavior, incremental/cache mutation,
full kernel/pkgbase production and controlled CPU, aggregate memory, disk-I/O
and allocated-disk comparisons remain open.
