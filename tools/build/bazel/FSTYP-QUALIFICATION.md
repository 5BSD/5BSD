# fstyp native candidate

2026-11-01. Make remains production/default. This candidate provides native
rules_cc ownership of fstyp's thirteen ordinary translation units and optional
ZFS translation unit, plus maintained program/debug/manual/test installation.

The ZFS source has its own cc_library(alwayslink=True), retaining explicit
program-object semantics while isolating Make's per-source SPL compatibility
includes, IN_BASE/HAVE_ISSETUGID definitions and forced configuration headers.
The ordinary sources remain direct cc_binary sources; ZFS compatibility macros
and includes do not leak into them. Existing typed ZFS/iconv/tests settings
select their maintained behavior. Logical package ownership is `utilities`, as
confirmed by the independent Make installation; fixtures and ATF metadata belong
to `tests`. The default executable links native geom/md/ufs/nvpair/zfs/spl/thr
in the maintained Make order. The no-ZFS variant excludes zfs.c and its closure.

Narrow existing GELI-header and forced-ZFS-config exports are extended for
fstyp, and a declared ZFS libzpool-header view supplies its exact per-source
include needs. No recognition source is rewritten. Private implementation_deps prevent SPL include paths from propagating through
the ZFS object or linked libraries to ordinary sources. No source-graph/frontend,
SDK-stager, compiler-policy or root-module change is introduced by this tranche.
Existing build-bsd format 5 inputs support the component targets/options.

## Maintained test coverage

The installed script, Kyuafile and all eight compressed image fixtures preserve
the full 22-case maintained suite. Native ATF declarations execute the existing
`dir`, `empty`, `exfat` and `zeros` bodies with declared native executables and
libraries. The bzcat alias preserves bzip2's argv[0] behavior through the standard
copy_file rule. Sparse temporary files remain ordinary test data; no memory
filesystem, host block device, pool, module loading or host service change is
needed by these four cases.

The follow-up [iconv runtime qualification](ICONV-RUNTIME-QUALIFICATION.md)
executes sixteen original cases in a fresh bounded QEMU guest, including the
four above and twelve additional file/label cases at installed paths. All pass
with native iconv modules and complete conversion data; no host data fallback is
used. This resolves those label-conversion gates for the tested amd64 fixture.

The [makefs follow-up](MAKEFS-QUALIFICATION.md) closes the remaining six cases:
five makefs image cases and the original root-only md/newfs case all pass in a
fresh disposable guest. Original requirements, bodies and cleanup stay intact;
before/after md inventory matches. All 22 original cases now have concrete amd64
guest evidence. Cross compilation, non-little-endian selection, physical device
behavior and complete system/pkgbase products remain unqualified.

## Build/install evidence

Independent Make references completed in
`/usr/obj/usr/src/bazel-fstyp-make-20261101/` and
`/usr/obj/usr/src/bazel-fstyp-minimal-make-20261101/`. They use fresh component
objects/staging and 16jobs. The minimal reference disables ZFS, iconv and tests.
The default native receipt passed in
`/usr/obj/usr/src/bazel-fstyp-qualification-r4-20261101/`. Its four selected
ATF bodies actually executed and passed, as retained test logs and the parsed
case-count report show. Build-bsd reports six selected targets, including the
program/install pair and the four tests.

Default artifact reports and the exact comparison script are retained in
`/usr/obj/usr/src/bazel-fstyp-parity-r4-20261101/`. All sixteen installation
records match Make destinations/types/owners/groups/modes/pkgbase tags. All
compressed manuals, ATF scripts, Kyuafile and fixtures match bytes. Logical
NO_ROOT metadata does not prove actual installed ownership. Native and Make
ELF imports/exports, dependency order and checked hardening match; actual
separate debug files validate against their respective GNU debug links.

The executable retains differences in text/layout and read-only data. Its
only differing printable strings are native source-relative versus Make
/usr/src-prefixed assertion paths for exfat.c, hammer.c and hammer2.c. Complete
raw differing-section reports remain available. This bounded comparison is
not machine-code equivalence, whole DWARF identity or debugger qualification;
no per-component absolute path hack or artifact rewrite was added.

Final execution logs show all thirteen ordinary source compile commands lack
SPL include paths. The ZFS compile command, reused from cache in the final run,
is retained from r3 and has the intended forced includes. The report explicitly
records that provenance. All actual Make source/header/manual/script/fixture
inputs recheck unchanged; only native BUILD declarations changed since the
independent reference. No direct DOF section exists in either executable.

The reduced-feature native receipt passed in
`/usr/obj/usr/src/bazel-fstyp-minimal-qualification-20261101/`. Its corresponding
`bazel-fstyp-minimal-parity-20261101` reports show all five install records,
compressed manual, ELF contract/dependency order and separate debug-link checks
match the independent reference. The same source-path/layout limitation remains.
This qualifies the two stated configurations, not every possible option matrix.

The ordinary Make dependency files select current-source public system headers
through -I/usr/src/sys. The bounded review finds all seventy headers mapping to
the selected SDK layout byte-identical; the three private crypto header paths
are supplied by declared source-owned GELI dependencies. The report retains
that tied-input check rather than assuming source and SDK headers always match.

The first native run preserves an unrelated parent kernel-helper transient
load-order error; the second preserves a legitimate undeclared forced ZFS-header
visibility error. The third preserves the initial declaration's real
SPL-header propagation bug, caught by hammer.c requiring FreeBSD uuid_t.
Native private implementation_deps correct that ownership. No failure was bypassed with a host header or a compiler
fallback. Later results must reference their own completed receipts.

## Observability and runtime gates

No direct DTrace provider, SDT probe or explicit audit submission was found in
these recognizer source files. Existing native dependency instrumentation stays
in the graph. Device access, Capsicum behavior against real devices, ZFS label
recognition, live tracing, audit coverage and performance remain open. The
subsequent VM adds concrete file-image/Unicode-label conversion evidence for
sixteen original cases, as described in ICONV-RUNTIME-QUALIFICATION.md.
