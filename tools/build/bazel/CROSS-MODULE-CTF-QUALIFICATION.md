# Cross-module CTF and cache-copy qualification (2026-11-03)

## Actual status

The refreshed native-executing objcopy tools staged for ARM64 and RISC-V each
pass all 65 maintained format checks. ARM64's new r5 composite SDK also passes
those checks on its actual frozen tool. RISC-V has a prepared r5 SDK plan but
no materialized new composite SDK in this checkpoint. All old r4 snapshots and
failed results remain unchanged.

The new maintained semantic tests establish these results:

| Profile | Result | Scope |
| --- | --- | --- |
| Native parser/copy tests | Pass | 30 parser methods and seven independent-copy methods through Bazel |
| Native nullfs | Pass | 112 symbol associations, 1,309 type records in each full/runtime graph, 14 expected-type checks and exact exports |
| ARM64, fresh r5 composite SDK | Fail | Final module CTF does not link to its SYMTAB |
| RISC-V, maintained native-SDK kernel mode | Fail | Final module CTF does not link to its SYMTAB |

The native SDK is explicitly supported for freestanding cross-kernel profiles.
The RISC-V row is not a new foreign composite-SDK qualification. Passing build
commands or a diagnostic observer do not accept either failed module profile.
No target module was loaded or executed, and no host installation occurred.

## Semantic test contract

`tools/test/construction:module-ctf-test.py` executes with the existing
bsd_host_artifact_test rule. Its declared data are the real target full/runtime
module pair, the existing source-owned module policy and the independent CTF
reader. The three public test labels are nullfs_ctf_symbols_test,
arm64_nullfs_ctf_symbols_test and riscv_nullfs_ctf_symbols_test in that package.
They require the corresponding target CPU and enabled kernel CTF setting.

The test requires explicit ELF machine/type, the actual CTF-to-SYMTAB link,
unchanged CTF payload across debug splitting, complete type/symbol graph
comparison, exact named STRUCT types for every policy object, unambiguous
nonzero type associations and exact global exports. It does not infer
correctness from type IDs, names alone or matching code bytes. The reader's
ordinary ET_REL default is unchanged; shared-module ET_DYN support requires
an explicit opt-in and ET_EXEC remains rejected. The older AMD64-only whole
module/kldxref audit keeps its own contract and is not foreign coverage.

Direct controls accept the retained native module and reject both stale
foreign families. Independent changed-machine, wrong-type-policy and wrong
export-policy controls fail as intended. The new maintained ARM64 and RISC-V
profiles reproduce the producer rejection. All raw failures remain retained.

## Additional defect isolated at the final shared link

A controlled replay uses the actual captured export/link arguments and input
digests, changing only output paths and selecting the newly rebuilt objcopy.
Localization preserves the real symbol-table link and all seven expected
nullfs object types. The following shared link drops sh_link on both ABIs.
In this replay ARM64 object/type associations otherwise remain stable; RISC-V
changes 106 object associations and fails expected SDT object types. This is
not an approved representation difference or merely a stricter-reader issue.
Independent ctfdump observations and exact tool hashes are retained.

LLD currently copies the symbol-indexed CTF data while final symbol processing
can remove/reorder eligible symbols. The correction needs exact input-file and
original-symbol-index provenance through final symbol-table order, plus the
proper output SYMTAB link. The existing Make and Bazel pipeline order is the
same. Do not apply a fuzzy post-localization merge, edit resulting ELF bytes,
disable CTF, or weaken the test. A full design must account for the initial
multi-input relocatable link and the existing maintained ctfmerge phase; one
premerged-container support must not be presented as general CTF type merging.
No LLD correction is implemented or qualified in this checkpoint.

## Frontend cache copying

The normal format-5 source_graph backend now supplies a copytree callback
using OS copy_file_range when supported, with ordinary independent copying
when copy offload is unavailable. The snapshot contents and validation policy
are identical in both cases. Storage and permission failures propagate; no
hardlinks or writable sharing are introduced. Source/destination byte checks,
complete snapshot inventory checks and private repository-cache verification
remain mandatory. Qualification receipts bind both the copy helper and cache
helper implementation. Existing cache-staging callers keep their default
copy behavior unless they explicitly select this callback.

The seven methods cover bidirectional write isolation, metadata, copytree
symlink policy, absent API, partially unsupported transfer, zero progress,
storage errors and same-file rejection. The completed new ARM64 cache copy
independently verifies all 16,179 snapshot paths and distinct inodes for 15,632
regular source/copy pairs. Successful native frontend profiles also close
repository-cache before/after verification. SDK preparation/staging helpers,
frozen snapshots, configuration schema and build-bsd C options are unchanged.
The affected normal backend, test rules and manual are updated together.

An initial frontend run was interrupted by the disk guard before analysis or
tests: reported free space crossed the reserve during cache materialization
and subsequently recovered. The completed retained cache was fully verified
before reuse. The retry and three subsequent profiles finish without disk
guard interruption. Their bounded admission budgets, raw time -l records,
CPU/job settings and free-space samples remain recorded. These are not a
comparative CPU/memory/disk-I/O benchmark; parent max RSS is not aggregate
parallel memory use. Reduced durable disk allocation or throughput is not
claimed from the transient free-space counters.

## Evidence under /usr/obj/usr/src

- bazel-objcopy-bootstrap-refresh-aarch64-r1-20261103 and its review-r2 record:
  original broad debug-path rejection and accepted exact program-output proof.
- bazel-objcopy-bootstrap-refresh-riscv64-r2-20261103: source-owner build,
  target header/library preservation and staged-tool format checks.
- bazel-userland-aarch64-sdk-r5-20261103: fresh normal SDK plan and receipt.
- bazel-cross-module-fresh-sdk-work-r1-20261103: fresh SDK format checks and
  complete retained cache-copy verification.
- bazel-cross-module-fresh-sdk-arm64-ctf-r1-20261103-disk.json: interrupted run.
- bazel-cross-module-fresh-sdk-arm64-ctf-r2-20261103: actual maintained rejection
  and retained -actual-capture-r4 action records.
- bazel-module-ctf-checker-qualification-work-r1-20261103: sequential commands.
- bazel-ctf-sdk-copy-unit-r1-20261103: native Bazel unit results.
- bazel-nullfs-host-ctf-native-r1-20261103: actual native module pass.
- bazel-nullfs-host-ctf-riscv-native-sdk-r1-20261103: actual RISC-V rejection.
- bazel-cross-module-ctf-direct-controls-r1-20261103: independent checker controls.
- bazel-cross-module-refreshed-export-link-diagnostic-r1-20261103: actual-input
  replay, raw ctfdump and symbol/type differences across the final shared link.

Full modules/kernels/world, independent refreshed Make controls, debug source
lookup, remaining helper execution libraries, OpenSSL recursion, packages and
combined hardware publication, bootstrap, sandbox/cache behavior and comparative
performance remain open. Make stays production/default; BIP remains excluded.
