# lib family composition and remaining owners

## Current evidence (2026-11-05)

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

See CAPSICUM-PROTOBUF-COMPOSITION-QUALIFICATION.md for Capsicum production/ATF
execution and the explicit normal protobuf parent.

## Concrete remaining review queue

| Owner | Source evidence and next work |
| --- | --- |
| lib/libproc | Default production installation now qualifies against fresh Make; original installed ATF/process-control tests, CTF alternatives and other ABIs remain. |
| lib/libprocstat | Default production installation, all 30 manual hardlinks and native self-process/argv runtime qualify; alternate options/ABIs remain. |
| lib/librtld_db | Default production installation now qualifies; the header-only cycle break is retained. Loader/process operations and other profiles remain. |
| lib/libthread_db | Native AMD64 library/production installation now passes original regular/PIC and interface comparisons. Actual debugger runtime and other architectures remain; see THREAD-DB-NATIVE-QUALIFICATION.md. |
| lib/libcapsicum | Production header/manual/13 hardlinks now match original Make; all four original C/C++ stream ATF cases execute. Original installed-test metadata remains. |
| lib/csu | AMD64 parent now passes all 64 logical original records, ten allocated/symbolic-relocation startup contracts, six Kyuafiles, fifteen debug pairs, seventeen loader contracts and all 36 unchanged original runtime cases. Repeated note sections are retained with explicit occurrence identity. Other ABIs remain incompatible; full world remains open. |
| lib/libcasper | Native production parent now preserves all nine owners; 139 production and eight original connection-test records qualify. Both original connection cases execute; complete service-test/parent Kyuafile ownership remains gated. See CASPER-PARENT-COMPOSITION-QUALIFICATION.md. |
| lib/libxo | Production parent now preserves library + CSV encoder contributions; all 96 original metadata records and three actual runtime targets pass. Full installed functional/encoder test hierarchy remains explicitly gated; see LIBXO-PARENT-COMPOSITION-QUALIFICATION.md. |
| lib/protobuf | Explicit parent now builds all four children and preserves three install contributions, including upb licences and no libprotoc payload. Other profiles/ABIs and refreshed implementation parity remain. |
| lib/atf and lib/tests | ATF production parent candidate now declares both existing library owners; original ATF test recursion and general lib/tests parent remain open. |
| lib/clang | Shared-library parent and LLVM/Clang archive endpoint candidates now preserve original library/resource-header selection separately from tool executables; aggregate construction and selected Make ownership comparisons remain pending. |
| lib/googletest | Production/full-manifest archive endpoint candidates reuse existing four framework owners and optional selftest manifests. Aggregate analysis, build and ownership acceptance remain pending. |

This is a concrete next queue, not an exhaustive list of missing work or a claim
that every other selected entry is accepted. Reconcile every selected immediate
owner with its real products before declaring lib or full-world completion.
Internal libraries such as libder/libdiff are legitimate build dependencies even
when they produce no installed file; do not invent installed payloads for them.
All full world/pkgbase/bootstrap/runtime/cache/sandbox/performance and alternate
architecture gates remain. Make stays default; BIP remains excluded.
