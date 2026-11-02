# Eight-program native rescue subset (November 2, 2026)

This cohort extends the real static rescue subset with ed, expr, getfacl, pwd and
test. Its original relative program order is cat, echo, ed, expr, getfacl, pwd,
test, head; red and `[` are original aliases. The complete 103-program default
selection, complete world/static-library parity, rescue installation and pkgbase
remain unqualified.

## Declared production inputs

Each application owner declares its actual nested Make RESCUE variant as an
ordinary cc_library. Existing bsd_component_selected_objects exposes only its
own compiler outputs in original object order. The ed group contains all seven
objects. Original O2, GNU17, pipe/fno-common, strong stack protection, debug
compression and full ordered warning policies are preserved. Expr retains
-fwrapv and the original absence of -Wmissing-variable-declarations.

Expr has a separate source-owned rescue Yacc producer: the original recipe is
`yacc -o expr.c /usr/src/bin/expr/expr.y`, with no generated header. The existing
ordinary program parser/header target is unchanged. The native producer consumes
the real grammar with the original native Yacc target and declares its output;
it neither copies Make-generated C nor invokes Make during a native action.

Original entry stubs precede all own application objects in each SDK ld -r link.
The existing declared crunchide producer then transforms the private original
basename and exposes its transparent .o alias. The final cc_binary receives the
main and all eight hidden objects directly in order, followed by native util,
libc and compiler_rt archives and native startup. There is no lazy application
archive or host libc archive substitution.

Existing build-bsd format-5 targets/tests, selected SDK receipt, artifact capture
and compact-log interfaces carry the change. No frontend C/backend/helper API,
signing, security, staging or publication policy changes are required. The
manual documents the bounded targets and complete-rescue boundary. Make remains
production/default; BIP is excluded. No host installation or tracing activation.

## Actual original Make and native checks

Fresh original nested *_make targets build eleven application objects. All
actual original and native compiler warning/code-generation vectors match.
The original and native .d inventories each contain 636 occurrences. Every native
consumed file is declared in the actual execution inputs with its exact digest.
There are 635 direct digest-equal original/native pairs; the generated expr.c
pair differs only in the 38 producer input/output filename fields of otherwise
identical #line directives. All 1,145 lines, line numbers, other bytes and line
terminators match. Generator arguments, LC_ALL=C, grammar/tool/output hashes are
retained; no generated output is rewritten.

All eleven original application executable sections match. Ten ordinary Make
objects also have identical allocated sections and nondebug relocations. Pwd's
assertion keeps its original __FILE__ semantics: ordinary Make embeds
`/usr/src/bin/pwd/pwd.c`, native compilation embeds `bin/pwd/pwd.c`. The untouched
baseline mismatch is retained. A separate original Make control includes the
unchanged Makefile then appends exactly `-fmacro-prefix-map=/usr/src/=`; its actual
argv retains -MD/-MF/-MT and every other flag. Its 51 consumed files/.d bytes
match the baseline, and its allocated sections/nondebug relocations equal native.
No /usr/src constant or source-specific mapping is added to the native program.

Six current original compiler dependency-only controls cover the generated main
and five new stubs without changing their C/.o/.meta files. Their 55 occurrences
match actual native .d inputs, bringing the current 17 compiler-action audit to
691 occurrences per side. The one generated expr.c pair is accounted for above.
The historical cat/echo/head sources remain unchanged across 113 retained
original input bindings. Their six current raw/hidden captures match the earlier
accepted captures; they are reused results, not invented fresh executions.

Independent original Make compiles all eight stubs and performs each original
ordered ld-r/crunchide pipeline, using ordinary original application objects
except the explicitly controlled pwd object. Eight stub sources and whole stub
objects match. All 24 stub/raw/hidden object comparisons preserve allocated
sections, nondebug relocations and symbol records; eight aliases preserve exact
hidden-file bytes. The 16 raw/hidden files differ in four DWARF/string-relocation
sections, reported explicitly. Whole independent object/debug byte equality is
not claimed. Exact recorded original compiler/linker/crunchide command replays
produce eight raw captures and eight hidden files byte-identical to actual Make.
Selected compiler, linker and crunchide hashes are checked before/after.

The final original generated-Make control intentionally supplies identical
accepted native application, archive and startup bytes. Generated main C, main.o,
eight stubs, eight hidden objects and the COMPLETE static ELF match native
byte-for-byte. This proves the original pipeline/final-link contract with those
inputs; it is not an independent full-world library rebuild. Actual native final
link inputs are nine mandatory ordered objects, three ordered archives and five
selected native startup objects. ELF checks confirm amd64 ET_EXEC, no PT_INTERP
or PT_DYNAMIC, nonexecutable stack and GNU_RELRO.

## Runtime, instrumentation and limits

One fresh Bazel wrapper executes 21 actual unittest methods: all previous eleven
cases plus physical pwd, expr arithmetic/regex/overflow, test truth/false and
bracket-alias errors, private-file ed editing, red alias and getfacl reads. All
pass. Editor user-file writes are confined to private TEST_TMPDIR fixtures.
The unchanged ed implementation also creates its private /tmp/ed.XXXXXX scratch
file with umask 077 and mkstemp, then removes it on normal close/quit. The compiled
static ELF is the actual subprocess executable; there is no host command/library
fallback. DOF initialization is disabled before each product process starts.
These are bounded integration cases, not all original standalone ATF/TAP suites,
ACL/filesystem variants or full editor/parser behavior.

No production C/probe source changes. Original RESCUE definitions preserve the
source's intended probe exclusion for these variants; ordinary instrumented
program targets remain separate. Whole final ELF identity includes whatever
instrumentation the identical native archives contribute. Live probes, installed
paths and actual full-system boot/upgrade are not exercised.

The guarded native profile uses 16 jobs and the 18 GiB start/16 GiB disk reserve;
no reserve interruption. Timings are not performance qualification. Six brief
sequential dependency-only controls overlapped unrelated root Make references
due a handoff race; neither timing is a CPU/cache/I/O performance measurement.
Full world/bootstrap, all rescue applications/libraries/options/architectures,
installation/pkgbase/hardware/publication and sandbox/resource/cache gates remain
open. Libutil's full Make archive/provider/DSO payload and installed-test parity
also remain separate gates from its qualified compiler-policy correction.

## Retained evidence

All paths below are under `/usr/obj/usr/src/`:

- `bazel-rescue-five-applications-make-reference-r1-20261102`: eleven original
  objects, original parent exports, 636 dependencies and Yacc metadata.
- `bazel-rescue-eight-program-native-qualification-r1-20261102`: accepted
  immutable captures, receipt, compact log and actual 21-method test log.
- `bazel-rescue-eight-program-action-collection-r1-20261102`: actual records,
  preserved compiler outputs and upstream converter provenance.
- `bazel-rescue-pwd-filename-control-r1-20261102`: exact original flag control.
- `bazel-rescue-eight-combined-make-control-r3-20261102` and
  `bazel-rescue-eight-combined-replay-control-r1-20261102`: eight original
  pipelines and exact recorded-command raw/hidden replays.
- `bazel-rescue-eight-combined-elf-review-r1-20261102`: 24 strict object pairs.
- `bazel-rescue-eight-program-make-control-r1-20261102`: whole same-input ELF
  control, exact selected program/alias/link order and source/tool bindings.
- `bazel-rescue-eight-generated-dependency-control-r1-20261102`: six -M controls.
- `bazel-rescue-eight-program-review-r1-20261102`: actual policy/input/parser,
  ordered-link/static-ELF, cached-provenance and test reports.
- `bazel-rescue-eight-review-drivers-20261102/manifest.json`: retained observers.

Compact logs use the original upstream converter, fully drained with all 189
converter bindings verified before/after. Rejected observer preflights are kept:
first, a historical crunchide receipt's native BUILD declaration had changed
while all original C/header/Make inputs stayed exact; second, the original
object paths contained doubled slashes. Corrected checks explicitly record the
Make-unread declaration delta and prove physical object identity/order while
preserving original lexical arguments. A test-input observer initially expected
the build-output path instead of the actual declared runfiles path; the corrected
report binds the exact runfile digest. No production checker or artifact was
relaxed/rewritten to accept these observer errors.
