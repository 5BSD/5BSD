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

See PROCESS-LIBRARY-INSTALLATION-QUALIFICATION.md for the next three completed
production contributions and their explicit remaining scope.

## Concrete remaining review queue

| Owner | Source evidence and next work |
| --- | --- |
| lib/libproc | Default production installation now qualifies against fresh Make; original installed ATF/process-control tests, CTF alternatives and other ABIs remain. |
| lib/libprocstat | Default production installation, all 30 manual hardlinks and native self-process/argv runtime qualify; alternate options/ABIs remain. |
| lib/librtld_db | Default production installation now qualifies; the header-only cycle break is retained. Loader/process operations and other profiles remain. |
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
