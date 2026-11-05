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

## Fresh original libc reference and complete regular-member review

The maintained install-reference.py completed a fresh original libc parent build
and private installation at bazel-libc-installation-make-r1-20261105, using the
recorded production-malloc profile, metadata recipes and all 16 jobs. Its
configured test binaries are built and staged, not executed by this reference.
No host installation occurs.

bazel-libc-member-review-r2-20261105/review.json binds that reference receipt and
all actual archive members against the immutable native r3 archive. All 1455
members pair uniquely: 1396 exact allocated-data, external-symbol and nondebug
relocation contracts; 57 read-only string/associated relocation differences;
one external-symbol-only difference; one provider metadata difference. Pairing
57 .nopic filenames with their original .o roles is explicitly diagnostic: raw
names, archive sequence, payload hashes and differing contracts remain recorded.
The earlier r1 review against the existing SDK is retained and has the same
counts. Neither report establishes raw ELF/debug or archive-order equality.

bazel-libc-filename-controls-r3-20261105/review.json accounts for all 57 string
cases with independently compiled original Make controls. Fifty-six use the
explicit /usr/src/ filename prefix map from the retained r2 build. The remaining
subr_acl_nfs4 case uses an additional explicit basename mapping: original Make
copies the kernel source into its object directory and compiles the relative
filename; native Bazel compiles the declared kernel source directly. The actual
original generated copy equals its source bytes. A fresh single-object control
matches the native contract exactly. Original warnings, definitions, optimization
and other compiler policy agree, and actual original/control dependency closures
are hash-bound. Production compiler flags are not changed to force equality.
The retained r1 control incorrectly passed .WAIT as a command-line target; r2
uses separate preparation/compilation and exposes the generated-copy distinction.

## Hidden weak DTrace alias verification

The libc review exposed an incomplete verifier assumption: dt_link.c deliberately
uses hidden keyed global aliases for ordinary functions and hidden unkeyed weak
aliases for weak functions so the linker can merge them. The metadata verifier
previously understood only the global form. It now requires the corresponding
name/binding pair and keeps exact matching-function lookup, hidden visibility,
function type/size, executable-section bounds and ordinary/enabled patch checks.
Twenty-two maintained fixture methods cover both valid forms and reject wrong
binding, visibility, function identity, relocation semantics, bounds and patches.
This is a verifier correction; libc or dt_link runtime behavior is not changed.

bazel-libc-dtrace-binding-review-r2-20261105/review.json checks the actual
res_send object-path hash against the real declared native output bytes and the
fresh original object path. Their other symbol properties, allocated bytes and
relocations match. Independent partial links include every provider-referenced
function (res_send, nsdispatch and both semaphore units). All 12 actual libc
probe bindings, 14 ordinary sites and 15 enabled sites match in schemas,
symbol-relative locations and bounded function code/patch bytes. The retained
r1 fails on the verifier's unsupported weak alias form; it is not accepted as
passing evidence. This closes the bounded regular-member differences, not live
tracing, final linked addresses, shared/NOSSP variants, raw debug or whole-library
semantic acceptance. Source-owned archive order remains open.

The final maintained frontend run
bazel-libc-source-aliases-native-r4-20261105 passes all eight Bazel test targets.
The 22-method DOF fixture target executes freshly under Bazel; the seven prior
libc/rescue/source-settings targets are cache hits. Its request is
bazel-libc-source-aliases-request-r2-20261105/inputs.json. Immutable artifact
resolution verifies the captured r3/r4 libc archives have the identical SHA-256
31508f6ff0dd18c05fcfde0dc0bda8ce23b1af9bcce9308d7c81a6c80cd8c7c8. No C frontend, backend input format or staging/signing
change is required for this verifier-only follow-up.
