# Native AMD64 thread debugging library

## Implementation

lib/libthread_db now builds thread_db.c, libpthread_db.c, libthr_db.c and the
original arch/amd64/libpthread_md.c. Private thread/KSE headers have an explicit
private provider. The existing thread_db_header interface used by libthr remains
unchanged. An actual shared producer emits libthread_db.so.3 with the maintained
source Symbol.map/Versions.def/version_gen.awk pipeline and original package
libthread_db. Version input visibility adds only this owning package.

The production archive installs the static archive, versioned shared library,
relative symlink, public header and separate debug file, with original debug
ancestor metadata. The library has no manual to synthesize. Source-owned typed
metadata replaces neither the Make recipe nor original runtime C. Target
constraints currently support AMD64 only; other architecture sources are not
silently substituted with the AMD64 helper.

## Debugger contract

A debugger supplies the ps_* process-service callbacks declared by proc_service.h.
The real library retains those unresolved imports, matching original Make. It
contains both original linker-set thread agent implementations. No fake callback
provider or API stub is linked to make it load or to claim a runtime test. A
proper debugger/process-service integration test remains required before claiming
thread enumeration, register access, TLS, events or process-control behavior.

## Retained evidence (2026-11-04, under /usr/obj/usr/src)

- bazel-thread-db-plan-r1-20261104/components.json records actual configured
  Make sources, ABI, flags, package and installation metadata.
- bazel-thread-db-make-r1-20261104/receipt.json: fresh original build/stage and
  metadata recipes pass, 16 jobs.
- bazel-thread-db-native-r2-20261104: native shared/static and production archive
  build through normal format-5 build-bsd, 16 jobs.
- bazel-thread-db-native-r3-20261104/receipt.json: final minimal installation,
  PIC archive and generated version-script capture pass. The selected existing
  source-settings test passes from cache; it is not a thread API runtime test.
- Native original-review-r2/review.json binds immutable artifacts to the passed
  receipt/manifest. All eight regular/PIC allocated code/data, symbolic relocation
  and external symbol contracts match raw original Make objects, without filename
  controls or binary normalization. All four regular archive members match order.
  Generated version-script and public-header bytes match original outputs.
- All seven logical component metadata records match Make: paths/types/modes,
  root:wheel, package/dev/debug tags and symlink. Actual tar metadata agrees.
  Original and native installed library/debug pairs pass debuglink CRC validation.
- original-review-r2/shared.json compares actual shared identity, SONAME,
  hardening, imported/exported symbols, versions and ordered runtime dependencies.
  All ten ps_* callback imports agree with Make. Whole linked/DWARF bytes and full
  calling-convention/runtime ABI coverage are not claimed from those checks.

The first native attempt correctly rejected undeclared version-input visibility;
precise package access fixed that dependency. A first review used an incorrect
expected output filename and failed; the accepted review resolves the declared
captured version_map.map artifact. Neither failure was counted as qualification.
Existing explicit frontend targets support this producer without C/backend schema
changes. The maintained manual, observability and family ledgers are updated.

## Remaining work

ARM64/RISC-V and other configuration support; a real debugger/process-service
harness and child thread/register/TLS/event/cleanup tests; full library/world and
installed tests; pkgbase/bootstrap/publication, VM/services, sandbox/cache and
CPU/memory/disk performance. SDK execution tools/runtime inputs remain separately
bound prerequisites. Make stays production/default; BIP remains excluded.
