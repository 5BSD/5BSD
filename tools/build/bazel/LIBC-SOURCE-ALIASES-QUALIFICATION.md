# Libc source identities and rescue object controls (2026-11-05)

## Native source identity correction

Original Make SOURCE_ALIAS declarations prefix imported gdtoa and jemalloc
sources, use C99_Exit.c for _Exit.c, and retain cancelpoints_ semaphore names.
The native compiler producers now use those same source basenames through
standard bazel_skylib copy_file actions with allow_symlink. Original source
labels remain declared inputs; compiler policies are unchanged. Aliases are
produced before compilation, not by editing completed ELF objects or archives.
Each imported source list is shared by its alias declarations and compiler input
selection. Make is not invoked by the native producer.

The previous native regular archive contained two div.o members and a
case-insensitive _Exit.o/_exit.o collision. The maintained
//lib/libc:archive_identities_test checks actual archive member uniqueness,
case-folded uniqueness, extraction of representative aliased members, ELF
identity, and independent public div and allocator __je_div_init definitions.
This tests a real archive-consumer contract, not just BUILD text.

## Qualification

All evidence directories below are under /usr/obj/usr/src.

- bazel-libc-source-aliases-native-r3-20261105: maintained build-bsd bazel-test,
  AMD64, 16 jobs, existing format-5 explicit inputs. All seven targets pass:
  archive identities, static and shared libc runtime, broad/configured/installed
  rescue runtime, and source settings. The archive test executes freshly; the
  other six results are valid Bazel cache hits. The request is
  bazel-libc-source-aliases-request-r1-20261105/inputs.json, including the existing
  actual rescue package and parent products. Production-malloc selection is an
  explicit Make comparison input; this unsigned run is not publication.
- Retained r1 fails the new collision assertion: an initial jemalloc alias used
  the src/ directory component as part of the prefix, leaving basename div.o.
  Corrected producers use the source basename.
- Retained r2 passes uniqueness but fails extraction because its test used a
  relative runfile tool path after changing working directory. The test now
  resolves its declared ar/nm paths before extraction; assertions are unchanged.

Existing build-bsd targets, backend and format-5 configuration already express
these inputs and tests. No frontend C/schema, stage/signing or publication policy
change is needed. The manual and completion plan record this checkpoint.

## Independent rescue controls completed before this correction

These reviews bind the earlier production-malloc rescue qualification, not an
assertion that every output from the new alias run is unchanged:

- bazel-rescue-filename-control-r1-20261105/review.json: all 45 application
  readonly-string differences match independent original Make compiler/rewriter
  controls with explicit -fmacro-prefix-map=/usr/src/=. Original warning,
  definition and optimization policies remain checked; baseline objects and
  consumed inputs are hash-bound. Allocated bytes and nondebug relocations match.
- bazel-rescue-dtrace-binding-review-r1-20261105/review.json: the 21 external-only
  differences follow the actual original dt_link.c FNV object-path identity.
  Remaining function symbol properties, allocated bytes and relocations agree.
  All 23 provider cohorts resolve 64 real function bindings, 73 ordinary sites
  and 77 enabled sites with matching schemas, symbol-relative locations and code
  bytes. The maintained DOF parser validates actual patches in independent
  relocatable links. Raw metadata identities remain recorded.

These bounded controls account for the earlier 89 differing application-object
contracts alongside 503 direct matches out of 592. They do not establish raw
whole-object/debug equality, final linked addresses, live probe registration or
firing, audit delivery, or complete library/final executable parity.

## Remaining work

bazel-libc-archive-order-review-r1-20261105/review.json records that original
Make OBJS+STATICOBJS exactly matches its actual 1455-member SDK archive; native
membership count alone did not establish naming, order or payload equivalence.
This correction fixes source identities, not archive ordering. Source-owned
ordered composition, independent common-library/startup payload review and final
ELF qualification remain open. There is no generated flat parent object list or
post-build sorting workaround in this change.

Private pkg database tests still require OS root or a guest. Full world, kernel,
modules, cross-platform, bootstrap, cache/sandbox, guest services and comparative
CPU/memory/disk gates remain open. Make stays production/default. BIP is excluded;
no host installation, repository publication, upgrade or reboot occurred.
