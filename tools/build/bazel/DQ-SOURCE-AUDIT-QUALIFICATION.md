# Declared DQ resolution-ledger audit

## Build contract

Make runs sys/tools/dq_resolve_ledger.sh check before completing its standard
kernel build. Merely recording this recipe or offering an optional unsandboxed
Bazel test did not enforce the same build contract.

The native kernel-link rule now consumes a private required ledger-check output.
The producing action runs the maintained checker with its exact ledger and all
declared C/header sources. No optional target selection can bypass that dependency.

A local repository rule discovers filenames across sys package boundaries and
watches directory entries. All regular C/header bytes remain ordinary Bazel action
inputs, without filtering on existing DQ tokens. Empty directory markers retain
the checker's find namespace. There is no whole-tree copy or live-workspace read
by the checker action. Its executable PATH and runtime libraries are declared.

The maintained checker accepts an optional complete file-list argument for EDQ
discovery. This avoids recursive grep silently skipping build-system symlinks.
Its Make invocation, lookup scanning, ledger comparison and invalid-row refusal
are retained. Current source C/header and directory symlinks are rejected
explicitly during repository discovery, rather than silently skipped or followed
outside the declared closure. The current sys tree contains neither kind. Future
source-link layouts need deliberate declared-input support before native builds.

## Evidence and remaining checks

All paths below use /usr/obj/usr/src.

- Direct original Make checker invocation passes on current sources.
- Native R1 fails: recursive grep omits EDQ rows in a materialized sandbox tree.
  That adapter was removed; the old fixture-tree API is unchanged.
- Native R2 retains a repository-generator quoting failure.
- Native R3 passes the declared file-list action, actual AMD64 final kernel link
  and both selected native tests. The source inventory test contains six Python
  methods covering nested BUILD boundaries, content-independent selection,
  addition/deletion, new directories, unsupported source/directory links,
  special files, unsafe names and missing roots.
- bazel-dq-invalidation-r1-20261111/receipt.json passes five actual native
  frontend runs (R4-R8). R4 covers the added manifest-readability guard. R5
  executes neither the ledger action nor the kernel linker on unchanged inputs.
  Adding a uniquely named neutral C source reruns the checker; changing only its
  bytes to contain a stray EDQRESOLVED use makes R7 fail the required build action.
  Its raw diff names that file and STRAY. R7 produces no passing receipt despite
  an existing cached kernel output. Deleting the trial source restores a passing
  R8; the driver removes only its own verified bytes in finally.
- R9 passes both selected native targets and exposes hash-bound inventory/list
  metadata through //sys/dev/dq:resolve_ledger_inventory.
- bazel-dq-audit-review-r1-20261111/receipt.json independently matches the actual
  captured filenames against BSD find: 14,621 C/header files and 3,164 non-root
  directories. Original Make and declared-list checker invocations both pass.
  A missing manifest fails explicitly with status 2. All source bytes and bound
  script/ledger/tool hashes remain identical before and after those comparisons.
  These are observed stable inputs, not a sealed source checkout.
- These focused runs are not the full-system R10 candidate and do not
  retroactively qualify that earlier build with the new mandatory audit.
- Processwrapper-sandbox execution does not prove host read/network isolation.
  Native bootstrap, sealed sources, reproducibility, controlled resources, full
  Make parity and cross-platform completion remain open.

The maintained build-bsd format-5 target interface accepts these normal build/test
dependencies. No new C frontend option, staging/signing/publication exception or
production backend change is needed; the manual is updated. BIP is excluded.
