# Native opensolaris module qualification

2026-11-01. The opensolaris compatibility module now has native GENERIC-tied
component targets on amd64, ARM64 and RISC-V64, retaining all seven maintained
C sources, genuine vnode interface, export-all policy and original object order.
The current maintained architecture selections all use opensolaris_atomic.c;
no assembly substitute was invented. This provides a native candidate for a
runtime dependency declared by the DTrace modules; loading that dependency and
its consumers remains an isolated runtime gate.

## Build and header design

The native graph uses unchanged maintained C sources. Physical source-only
headers retain ownership in their actual source packages. The shared CDDL module
helper now accepts an explicit compatibility_headers context; its default
continues to use the existing three contexts. opensolaris supplies the original
OpenZFS include, os/freebsd, os/freebsd/spl, os/freebsd/zfs, compatibility and
OpenSolaris common roots in their original Make precedence. Forced headers
retain ccompile.h, opt_global.h and debug_compat.h order, with genuine native
GENERIC options and the original warning/compile policy.

The initial native compile correctly failed because spl_misc.c includes
zfs_context.h and therefore consumes sys/zfs_debug_os.h from os/freebsd/zfs.
Earlier tracing sources did not require that root. The corrected graph declares
the real physical headers and complete ordered context. No SDK header fallback,
empty header, source rewrite or suppressed diagnostic was used.

## Evidence

All six fresh independent Make build/install references passed under
/usr/obj/usr/src/bazel-opensolaris-make-20261101. Header-only kernel reference
directories contain copied and hashed actual GENERIC option files. Four jobs
with four workers each use the sixteen-CPU host. Reference source inventories
and actual per-architecture flags are retained.

Six final native format-5 build-bsd profiles passed under
/usr/obj/usr/src/bazel-opensolaris-{amd64,arm64,riscv}-{plain,ctf}-r2-20261101:

- Six module comparisons and nine exact installation records.
- Three plain modules byte-identical to independent Make outputs.
- Three installed CTF modules have identical section metadata/payloads except
  build-ID/debuglink; .SUNW_ctf is exact. Both actual debuglink CRCs verify.
  Separate debug-file DWARF byte identity is not claimed.
- Forty-two actual C compiler actions retain source hashes, target triples,
  exact warning/forced-header policy and original compatibility definitions.
- Eighty-four option-header input hashes match genuine reference files, and
  all six captured link parameter lists preserve original source/object order.
- Every source/header prerequisite from the independent Make dependency files
  is present as an actual native physical compiler input with its expected
  source hash: 5,282 checks, comprising 226 unique source/header files.
- All forty-two actual compatibility include-root orders match Make.

Artifact payloads bind through receipt, manifest and content hashes using
qualification_artifacts.resolve. Commands, artifact/install comparisons,
compiler/link/physical-header audits, source observability scan and helpers are
retained under /usr/obj/usr/src/bazel-opensolaris-review-r2-20261101 and
bazel-opensolaris-native-runs-r2-20261101. Initial failure diagnostics remain
under the corresponding r1 directories. No runtime test targets are selected.

The independent amd64 GENERIC module inventory is recorded separately in
/usr/obj/usr/src/bazel-module-coverage-post-opensolaris-20261101.json. Its macro
and BUILD presence fields describe source declarations, not successful builds,
other architectures or runtime qualification.

## Integration and remaining gates

The existing maintained frontend accepts these native target/input profiles;
no C/CLI, signing, staging, SDK or publication policy changes are needed. Its
manual and native README describe this bounded candidate. Make remains the
production/default backend and BIP remains excluded.

Whole-kernel/module integration, other kernel configurations, actual module
loading, DTrace dependency resolution, allocator/task/CPU lifecycle behavior,
permissions and concurrency remain open. Source mutation/cache invalidation and
controlled CPU/memory/disk performance qualification remain open. No module was
installed or loaded into the host; no tracing, service or storage state changed.
