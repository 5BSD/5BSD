# Process-library production installation qualification

## Source-owned contributions

libproc, libprocstat and librtld_db now declare installation_data.bzl inventories
and typed installation/debug/manual/hardlink/archive producers. All use the
original utilities package default; no new package names are invented. Existing
regular/shared C producers and their CDDL/ZFS/CTF conditions are unchanged.
The source header edge between librtld_db and libproc remains separate from
link dependencies to avoid their original dependency cycle.

| Owner | Library | Logical records | Header/manual files checked | Regular objects |
| --- | --- | ---: | ---: | ---: |
| lib/libproc | libproc.so.5 | 7 | 1 | 6 |
| lib/libprocstat | libprocstat.so.1 | 38 | 2 | 7 |
| lib/librtld_db | librtld_db.so.2 | 8 | 2 | 1 |

The libprocstat contribution includes all thirty original manual aliases as
hardlinks. Separate debug files and original debug ancestor metadata are included.
production_install_archive explicitly excludes installed test-suite contributions;
libproc's original ATF hierarchy remains to be integrated and qualified.
The inventories are checked-in Bazel metadata; no Make evaluation occurs during
the native build. Epoch zero retains the component qualification convention and
is not evidence of a complete publication configuration.

## Runtime check

A native Bazel cc_test links the real shared libprocstat closure. It queries
KERN_PROC_PID for its own PID, verifies exactly one matching kinfo_proc, retrieves
its original argv[0], then frees results and closes the library handle. The test
reads its own process only, uses no elevated privileges and performs no ptrace.
It does not replace libproc's original process-control ATF cases or prove VM/core
file/debugger service behavior. It executes successfully on the current host.

## Retained evidence (2026-11-04, under /usr/obj/usr/src)

- bazel-process-library-plan-r1-20261104/components.json: original configured
  metadata for all three owners, including package defaults and manual links.
- bazel-process-library-native-r1-20261104: three production archives and selected
  source-settings target build through maintained format-5 build-bsd, 16 jobs.
- bazel-process-library-native-r2-20261104: final readable inventories and native
  self_process_test pass. The self-process test actually executes; source-settings
  result is reused from cache. No foreign target execution is claimed.
- bazel-process-procstat-make-r1-20261104,
  bazel-process-rtld-make-r1-20261104 and
  bazel-process-proc-make-r1-20261104: fresh untouched original Make builds/stages
  with explicit WITHOUT_TESTS for the production comparison, 16 jobs and original
  metadata recipes. Disabled installed tests are recorded, not counted as tested.
- Native original-production-review/review.json binds captures to verified
  receipts/manifests. All 53 logical metadata records agree with Make: destinations,
  types, root:wheel ownership, modes, package/dev/debug/manual tags and symlinks.
  The thirty typed manual hardlink targets match actual tar links and original
  stage samefile relationships. All five original header/manual gzip payloads
  match byte for byte. No non-directory path duplicates occur across contributions.
- Each retained shared.json compares actual native/original installed shared ELF
  identity, SONAME, hardening, versioned symbols and ordered NEEDED libraries.
  Both original/native installed binary/debug pairs pass debuglink CRC checks.
  Complete linked/DWARF bytes and debugger source lookup are not claimed equal.
- Nine of fourteen raw regular allocated object/data/relocation/external-symbol
  contracts match. Five differ in original absolute source filename strings:
  proc_bkpt, common_kvm, core, libprocstat and rtld_db. The separate
  original-production-review/filename-controls/review.json replays exact original
  compiler recipes with -fmacro-prefix-map=/usr/src/= and private object/dependency
  outputs. All five controlled contracts match. Original raw bytes are preserved,
  and source/tool/metadata/original-object/native-archive hashes are rechecked.

The source-settings/profile/compiler/SDK checks are maintained; the existing
frontend/backend supports these explicit contributions without C/schema changes.
The frontend manual and family completion ledger are updated in this change.

## Remaining scope

Original installed ATF tests, ptrace/core/loader operations, alternate CDDL/CTF
options, other architectures, complete lib/world/pkgbase composition, bootstrap,
VM/services, sandbox/cache and CPU/memory/disk performance remain required.
This production installation result does not establish full package publication
or a completely Bazel-built system. Make remains default; BIP stays excluded.
