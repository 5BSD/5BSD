# Standalone Lua archive candidate (2026-11-03)

## Native implementation

`//stand/liblua:static_archive` builds the 31 Make-selected translation units in
three owned compiler groups and preserves their actual Make archive order. This
is the standalone loader interpreter library, with its integer-number Lua ABI,
mini stdio wrappers and loader modules. It does not reuse the userland Lua
configuration/header dependency or link a userland Lua/libc implementation.

The current candidate is constrained to FreeBSD/amd64. It is not yet a complete
EFI-specific variant or a foreign-architecture archive. EFI flags and verifier
policy must stay separate from BIOS/userboot contexts. No full loader is linked.

The shared `stand/libsa:standalone_headers` view declares the restricted safe
header aliases and three intentionally empty xlocale compatibility files from
`stand/libsa/Makefile`'s beforedepend recipe. Those empty files are existing
standalone semantics, not replacement implementations. Architecture aliases and
source header subsets are explicit. The native build never reads preexisting
Make-generated headers or object files. No Make query/generation occurs in the
native build. The original Make dependency records were used during migration
to author the maintained native declarations.

`loader_geli`, `loader_disk`, `veriexec`, `loader_veriexec_vectx`, and
`loader_veriexec_pass_manifest` are typed source build settings. The verifier's
header dependency is selected only when needed; it does not drag userland crypto
implementations into Lua. `loader_lua_path` defaults to Make's `/boot/lua` policy
and is a configurable string input. `stand/liblua/config.bzl` supplies CcInfo
compiler definitions directly, avoiding shell interpolation and preserving paths
as strings. The path must be absolute and contain no NUL/newline.

## Baseline evidence

- `bazel-stand-liblua-make-r1-20261103`: independent original Make reference,
  built with all 16 CPUs and supported recipe metadata. Its component METALOG
  is empty: Make marks this archive INTERNALLIB, so it must not be installed as
  a normal userland library. No fabricated installation records were added.
- `bazel-stand-lua-r3-20261103`: native archive build and two archive-inspection
  tests passed. A separate compiler contract verifies integer-number Lua and
  loader FILE ABI selection. The contract object is not an archive member.
- `bazel-stand-lua-review-r2-20261103/review.json`: all 31 member names/order,
  defined and undefined external symbol contracts, allocated ELF section bytes,
  sizes/flags/alignment and 4,786 symbolic relocations match independent Make.
  This comparison resolves relocation symbols by identity, not raw symbol index.
  All 31 full object bytes differ; complete DWARF/source mapping and debugger
  parity remain open. Allocated-section equality is not complete file equality.
- `bazel-stand-lua-r3-20261103/action-review.json`: 33 actual noncached compiler
  actions (31 archive units and ordinary/PIC variants of the separate ABI
  contract), followed by the exact owned-object archive action. Source hashes,
  standalone/configuration headers, required compiler flags and captured final
  archive hashes are bound. The upstream compact-log converter and its runtime
  were checked before and after use. No cached compiler action is called fresh.

Paths above are under `/usr/obj/usr/src`. Captured archive payloads are resolved
through the maintained receipt/manifest/content verifier before comparison.

## Options and remaining qualification

`bazel-stand-lua-verifier-r1-20261103` passes with verification enabled and
GELI/disk flags disabled. `bazel-stand-liblua-verifier-make-r2-20261103` builds an
independent verifier-enabled, GELI-disabled Make reference. The Make reference
CLI cannot disable `LOADER_DISK_SUPPORT`, which is a component variable rather
than a global MK option; the earlier attempt to use `WITHOUT_LOADER_DISK` was
rejected, not silently accepted. The comparison retains this macro difference:
all 31 members still match in allocated bytes, symbol and relocation contracts
(4,804 relocations). This is not a claim of identical compiler configuration.
`verify_required` imports appear only in the verifier-enabled archive.

Two early native attempts caught an invalid skylib newline enum and C-string
macro quoting. The final path mechanism uses typed CcInfo definitions; an
additional analysis failure caught an unsupported Starlark hex escape before it
was corrected to octal. Failed attempt evidence is retained. The final typed-path declarations pass under
`bazel-stand-lua-r5-20261103`. All 33 compiler actions execute freshly; the
archive and test are reused. The action review binds the fresh object hashes to
the actual earlier archive inputs and final captured archive digest.
`bazel-stand-lua-review-r3-20261103` independently confirms the final archive
still matches Make in all 31 allocated sections/relocation/symbol contracts.
The original r3 test methods ran freshly; r5 does not claim a fresh test run.

`bazel-stand-lua-cache-r1-20261103` passes after switching back from a different
configuration, but recompiles the selected objects. It does not establish a
no-change cache hit. The current local output cache does not prove preservation
of earlier configurations' outputs; cross-configuration disk/remote cache reuse
requires distinct evidence.

`bazel-stand-lua-cache-r2-20261103/cache-review.json` supplies the immediate
unchanged-input evidence: identical captured archive digest, no compiler/archive
execution, and one cached passing test result. BEP records only the internal
workspace-status action executing. This establishes local incremental reuse,
not preservation of outputs across different configurations or remote caching.

`bazel-stand-lua-custom-r1-20261103` passes with verification enabled and a
custom path `/opt/loader "lua"`. Its captured `loadlib.o` contains the exact
custom default path, including spaces/quotes; the baseline default path is
absent. The archive imports `verify_required`. The configured graph separately
rejects a relative path. Exact settings, payload hashes and rejection evidence
are retained in that qualification directory. No source edit or shell variable
substitution supplies the path.

## Frontend, instrumentation and scope

The maintained `build-bsd bazel-test` format-5 frontend already passes typed
`build-settings` to native labels and captures archive/test outputs. No C frontend
option, signing/staging/publication contract or manual interface changed. The
normal backend was used for qualification; Make remains production/default.

The observability audit records the standalone/firmware context. No existing
DTrace/BSM provider was dropped; loader diagnostics and verification failures
still require firmware runtime tests. Full EFI linking, ARM64/RISC-V support,
complete world/kernel/modules/pkgbase, bootstrap/sandbox and comparative CPU,
memory and disk performance gates remain open. Client-only timing is not a
whole-process-tree resource benchmark. No host install, upgrade or reboot occurred.
