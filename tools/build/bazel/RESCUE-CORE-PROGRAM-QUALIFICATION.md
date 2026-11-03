# Bounded real static rescue executable

November 2, 2026: `//rescue/rescue:rescue_core` links and executes the real cat,
echo and head RESCUE variants through original generated main/stubs and original
crunchide transformations. This follows the [combined object producer](RESCUE-COMBINED-OBJECTS-QUALIFICATION.md).
It is a three-program subset, with no full rescue installation/package target.

## Actual static link and independent control

The source-owned binary takes four direct object inputs in order: generated
main, cat, echo and head. Their already qualified hidden objects remain normal
`.o` inputs, without artificial own archives. The native libutil static archive
is lazily extracted before native libc and compiler_rt archives. A private
cc_import preserves ordinary Make -lutil archive semantics; it does not force
libutil's provider CcInfo into every link. Original head's Makefile declares
LIBADD=util. Native csu startup objects are selected through the existing declared
-B response-file interface. No SDK libc archive substitutes for native libc.

The accepted ELF is ET_EXEC with no interpreter or dynamic segment, a
nonexecutable stack and a GNU_RELRO segment. Four direct objects, three ordered
archives and five selected startup inputs are bound to actual CppLink hashes.
Original crunchgen, given the same explicit three-program metadata, produces
exact main C bytes. The original generated Make compile/link control uses the
original parent CC/CFLAGS/LDFLAGS and the accepted native archive/startup inputs.
Both its main object and complete binary are byte-identical to native captures.
This is independent original generated-Make linker/dispatcher proof using
identical library/startup bytes, not a fresh full Make world/library comparison.
The original wrapper passes three -Wl options and -static to -c; they are ignored
link-driver inputs there, recorded separately from the exact compiler warnings.

The actual native main compile was successful in rejected r1, reused by accepted
r2 and explicitly rebound to its current object and final link. An explicit -M
control uses the original actual compiler recipe with only -c/output changed;
original source/object/meta bytes remain unchanged. Together with a fresh original
Make expand_number.o reference, both native consumed dependency inventories match
all 86 source/header occurrences physically and logically. The libutil archive's
expand_number member equals its actual native compiler output and has exact
allocated sections, runtime relocation bytes and symbol records versus Make.

## Runtime and qualification scope

One fresh Bazel test wrapper runs ten actual unittest methods: list the exact
three-program catalog, echo and -n, binary cat stdin, cat/head private files,
head stdin, missing-file and unknown-program errors, and argv[0] dispatch.
The candidate is a normal declared data input. Tests use private temporary files
and stdin; LC_ALL=C and DTRACE_DOF_INIT_DISABLE=1 are supplied before each child
starts. The retained log reports ten methods; Bazel XML reports one wrapper case.
No installed rescue path, host configuration, tracing activation or privileged
application is exercised.

Initial r1 performed 3,297 uncached compiler actions plus native tool generation
but failed its final link because this bounded closure omitted libutil. No test
ran and no executable was accepted. The current retry adds the real dependency;
seven targets and the runtime test pass. Its compact execution log records
34 fresh libutil compiles, 34 archive-member actions, one archive, one successful
program link and test setup/XML actions. Reused startup/libc/main outputs remain
explicit cache provenance, rather than invented fresh producer records.

A separate existing libutil policy gap remains: its ordinary cc_library omits
Make's explicit -pipe/-fno-common/-std=gnu17 and warning vector. Optimization,
macros, SSP and debug match for the consumed member, and its actual code/input
comparison passes, but this is not a full libutil compile-policy qualification.
Correcting and independently qualifying that shared library declaration is the
next reviewed follow-up. The broader world warning-policy reconciliation stays
open. Full rescue still needs all 103 selected applications, complete original
static library/replacement-object closure, option/architecture coverage and the
actual rescue installation/package contract.

The existing maintained build-bsd format-5 native target/test/SDK/compact-log path
runs this graph normally; no frontend CLI/backend API or generic runner change
is required. Production Make output remains untouched.

## Retained evidence

Paths are under /usr/obj/usr/src:

- bazel-rescue-core-program-native-qualification-r{1,2}-20261102: rejected and
  accepted profile records, compact logs, immutable accepted captures and tests.
- bazel-rescue-core-program-failed-action-collection-r1-20261102: original r1
  source snapshots, failed-log binding and fully drained verified converter.
- bazel-rescue-core-program-action-collection-r2-20261102 and
  bazel-rescue-core-program-review-r{1,2}-20261102: accepted actual actions and
  corrected observer (the first wrongly counted ignored -Wl as warning options).
- bazel-rescue-core-program-make-control-r1-20261102: original generator,
  supported Make metadata and byte-identical main/static executable control.
- bazel-rescue-core-main-dependency-control-r1-20261102 and
  bazel-rescue-expand-number-make-reference-r1-20261102: explicit original main
  dependency control and fresh original libutil object/dependencies.
- bazel-rescue-core-program-review-drivers-20261102/manifest.json: copied drivers,
  exact scoped source hashes and accepted/rejected evidence bindings.
