# lib family composition and remaining owners

## Current evidence (2026-11-04)

The fresh maintained Make plan at
/usr/obj/usr/src/bazel-lib-family-plan-r1-20261104/components.json records 173
selected immediate SUBDIR entries after removing .WAIT barriers. These entries
include actual library producers, internal libraries with no installed archive,
header/manual-only owners, recursion wrappers and test hierarchies. This is
configuration evidence, not a count of completed libraries. There is currently
no accepted complete lib production parent or full installed lib test hierarchy.

Seven known manifest-to-production-archive gaps now build and pass bounded
qualification; see LIBRARY-PRODUCTION-ARCHIVES-QUALIFICATION.md. Their archive
rules are source-owned, and no Make evaluation supplies Bazel build metadata.
The selected Make plan remains an independent comparison inventory.

## Concrete remaining review queue

| Owner | Source evidence and next work |
| --- | --- |
| lib/libproc | Native regular/shared producers exist; original Make installs libproc.a, libproc.so.5, debug and libproc.h. Add/reconcile production installation and tests; preserve CTF configuration. |
| lib/libprocstat | Native producer exists; original Make installs library/header/manual and many MLINKS. Add/reconcile production installation and selected tests. |
| lib/librtld_db | Native producer exists; original Make installs library/header/manual. Preserve header-only cycle break with libproc while adding installation. |
| lib/libthread_db | Current BUILD exports only thread_db.h to libthr. Original Make selects four C sources, architecture helpers and versioned libthread_db.so.3. Actual library conversion is still required. |
| lib/libcapsicum | Header provider exists; original Make also installs capsicum_helpers.3 and MLINKS. Reconcile production header/manual and installed tests. |
| lib/csu | AMD64/common/tests packages exist beneath the Make architecture wrapper; full parent/configuration/foreign composition is not established. |
| lib/libcasper | Native child producers exist; reconcile wrapper's libcasper/services/test recursion without selecting arbitrary descendants. |
| lib/libxo | Make recurses through libxo, encoder and tests; reconcile source-owned parent selection. |
| lib/protobuf | Make selects protobuf-lite/protobuf/protoc/upb with different internal/installed roles; preserve those distinctions in parent composition. |
| lib/atf and lib/tests | Test support and installed test hierarchy require explicit parent ownership and original configuration closure. |

This is a concrete next queue, not an exhaustive list of missing work or a claim
that every other selected entry is accepted. Reconcile every selected immediate
owner with its real products before declaring lib or full-world completion.
Internal libraries such as libder/libdiff are legitimate build dependencies even
when they produce no installed file; do not invent installed payloads for them.
All full world/pkgbase/bootstrap/runtime/cache/sandbox/performance and alternate
architecture gates remain. Make stays default; BIP remains excluded.
