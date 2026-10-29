# Development checkpoint — 2026-10-27

## Scope and resume point

This checkpoint preserves the accumulated runtime, build/packaging, and native
Bazel work on `dev`. It is not a release qualification. Make remains the
production build path and remains supported for ports. BIP is out of scope.
No host installation, upgrade, or reboot was performed for this checkpoint.

The original checkpoint component, `sbin/dhclient`, has completed its normal program and
installation comparison against Make. The native graph uses explicit C sources,
headers, dependency ordering, and DTrace generation. The comparison covers 168
defined globals, 11 installation records, seven nonbinary payloads, debuglink,
and DTrace schema and probe sites (allowing relocation of code addresses).
The program was not started against a network.

Evidence is retained under `/usr/obj/usr/src/bazel-dhclient-r2-20261027` and
`/usr/obj/usr/src/bazel-dhclient-make-20261027`. The archive SHA-256 is
`8f211925595878b2c6181110d7b4d6dac6d72752e8ad41a5ed1f189ef57133ef`.
The Bazel README and observability audit contain the detailed component record.
Dhclient tests, static/rescue variants, option coverage, cache/performance
qualification, and live network behavior remain to be completed.

## Remaining migration work

At the initial checkpoint there were 1,058 BUILD.bazel files; this is a graph-file count,
not a count of successfully qualified products or a completion percentage.
A complete native world, kernel/modules, bootstrap, pkgbase, and image build
has not yet been demonstrated. The current component builds still consume a
Make-prepared SDK. Continue native conversion and artifact/install comparisons,
carry DTrace/FIDL generators and configuration choices into explicit actions,
and maintain the observability audit. Full configuration, sandbox/cache,
runtime, packaging, and CPU/memory/disk performance qualification remain gates.
Build frontend, backend helpers, tests, and documentation must continue to be
updated together whenever their inputs or contracts change.

## Checkpoint checks and limits

- Parsed 415 changed/untracked Python files successfully.
- Shell syntax checks passed for 68 changed/untracked shell files.
- Archive-policy tests: seven passed.
- Component-plan tests: nine passed.
- Tracked-diff whitespace check passed after correcting four trailing-space lines.
- Staging also checked newly added files: cleaned Bazel source whitespace;
  retained significant whitespace in expected-output fixtures, pkg-config
  templates, and patch context. Runtime checkpoint has two harmless EOF
  blank-line warnings.

These checks supplement existing component evidence; they do not establish
runtime correctness of every accumulated change. This commit cleanup did not
rerun the complete regression suite or boot an image.

The original tracked patch, untracked archive, status, and HEAD are saved in
`/usr/obj/usr/src/dev-checkpoint-20261027`. A stray 64-byte ELF fixture at the
source root was moved there as `stray-kernel-fixture`, rather than committed.
Intentional binary and expected-output test fixtures are retained in source.
Private-key markers examined in tests contain malformed dummy input, not keys.

## Subsequent progress: dhclient tests

The native parser test now passes, and the combined program/test installation
matches Make (20 records, nine nonbinary payloads, two debug links). Test ELF
symbols and dynamic metadata also match. See the Bazel README for evidence and
remaining PCP/VNET, configuration, and performance qualification work.

## Subsequent progress: GEOM Gate

Native ggatec, ggated, and ggatel now build through the maintained frontend and
match Make binary/install comparisons. The aggregate archive has ten records.
The Bazel README records evidence, incremental-link observation, and remaining
privileged I/O/static/platform qualification. No disk was attached or exported.

## Subsequent progress: dnctl

Native program and combined test installation match Make (13 records).
Flow-layout ABI test passes. The complete four-case native suite is defined;
three shell cases fail before their bodies in dirname because of the documented
older-host/newer-source Capsicum mismatch. Preserve these failures and rerun on
a matching kernel. The Bazel README records separate artifact and runtime evidence.

## Subsequent progress: HAST

Native hastd/hastctl program artifacts and installation match Make. Parser
header matches bytewise; parser/lexer C match apart from line-directive filenames.
The libmd consumer CcInfo target is public. Privileged daemon tests, test
installation, option/static variants, and replication performance remain next
qualification work; no daemon or replication operation was started.

## Subsequent progress: HAST test installation and option parity

HAST test packaging now matches Make (eight combined records). Both programs
also match Make with INET6_SUPPORT disabled. That setting removes the compiler
define but leaves these program artifacts unchanged: current source selects
IPv6 support at runtime. Privileged ctl runtime execution remains outstanding;
test installation must not be counted as execution.

## Subsequent progress: ping

Native default ping program and six installation records match Make, including
conditional ping6 links and setuid archive metadata. No installation or packet
transmission occurred. Checksum/ATF/pytest tests, test packaging, configuration
variants and network/runtime qualification remain outstanding.

## Subsequent progress: ping tests

Four native checksum cases execute successfully. Full program/test installation
matches Make across 21 records, including shell/pytest wrappers and fixtures.
Checksum binary metadata also matches. Shell/pytest network runtime execution,
configuration variants and performance remain outstanding.

## Subsequent progress: ping configuration qualification

IPv4-only and IPv6-only component builds now match separate Make references.
The tests-disabled full archive is byte-identical to the qualified program-only
archive. Network/injection runtime, static/rescue, other architectures and
performance remain outstanding. Next unconverted sbin areas include init with
its embedded reroot_seed, pfctl, resolvconf and veriexec.

## Subsequent progress: init prerequisite

Native static reroot_seed and its debug-split internal payload match Make's
symbols/link metadata and payload size. No standalone installation target is
created. Init still needs declared assembly embedding of that payload, binary
and configuration installation, and runtime qualification. The helper was not
executed. See the Bazel README for evidence and SDK/bootstrap limitations.

## Subsequent progress: native init

Init now builds with declared seed embedding and matches Make's symbol/link and
six-record install metadata checks, including schg. Raw assembly revealed and
fixed a missing SDK assembler input declaration; a fresh SDK receipt is under
bazel-assembly-sdk-20261027. Embedded payload bytes match the native dependency.
Make's separate object-tree seed differs, so no whole-binary identity is claimed.
Boot/root-transition/rescue behavior, changed-payload invalidation and performance
remain outstanding. No lifecycle operation was run.

## Subsequent progress: resolvconf

Native template generation and installation match Make (11 records, nine
payloads); seven shell syntax checks pass. Resolver runtime, subscriber service
integration and nondefault layout qualification remain outstanding. No resolver
state or service was changed. Remaining sbin program gaps include pfctl and
veriexec plus directory-level test aggregation.

## Subsequent progress: pfctl

Native program/parser and five-record installation match Make. Explicit
compatibility and shadow headers preserve the maintained OpenBSD/5BSD build.
The changerule helper, shell/corpus packaging, jail/VNET execution and runtime
qualification remain outstanding. Veriexec and directory-level test aggregation
remain sbin graph gaps; no firewall state was changed.

## Subsequent progress: pfctl regression packaging

Changerule now builds natively and matches Make's binary metadata. Full
program/test/corpus packaging matches 585 records and 574 nonbinary payloads.
Jail/VNET requirements remain in Kyuafile; no test or firewall control helper
was executed. Runtime corpus execution remains outstanding.

## Subsequent progress: libveriexec

Native static/shared libraries and eight installation records match Make.
BearSSL and secureboot with explicit trust inputs remain missing dependencies
before the static veriexec command can be built natively. Kernel interaction,
script execution and enforcement runtime qualification remain outstanding.

## Subsequent progress: BearSSL and commit checkpoint

Native default BearSSL static/shared libraries and installation now match Make:
186 archive members, 19 installation records and 13 identical headers. Explicit
optional SSL sources and a format-5 selector are declared but that variant and
upstream crypto runtime tests remain unqualified. Evidence and exact checks are
recorded in the Bazel README.

Resume with BearSSL SSL/runtime qualification and the secureboot library's
explicit trust-generation inputs, then the static veriexec consumer. Broader
world/kernel/module conversion, native bootstrap, complete pkgbase/frontend
integration, configuration coverage and cache/performance qualification remain.
Make remains the production/default backend and the ports build system; the
current SDK is still Make-prepared. BIP remains dropped. This commit checkpoint
records a component milestone, not completion of the system migration.

## Subsequent progress: optional BearSSL and crypto tests

The full upstream crypto suite now passes as a native Bazel test with SSL
enabled; five Power8 cases remain unavailable on this amd64 host. Qualification
found and repaired 26 missing optional sources in both Make and Bazel. The
295-member optional library and all 19 installation records match the explicit
Make reference. See README for preserved failures and final evidence.

Next: explicit secureboot trust-generation inputs and the veriexec consumer.
TLS network/X.509 fixture coverage, broader configuration and performance gates
remain outstanding. All earlier system-wide migration limitations still apply.

## Subsequent progress: explicit secureboot header generation

A declared Bazel rule now generates trust/configuration headers from explicit
policy and certificate inputs. Native generated-header execution passes; 35
host reference/rejection checks pass. The fixture deliberately trusts nobody.
This does not yet build libsecureboot or establish signed-file/boot enforcement.
Next connect the generator through a configurable library graph, qualify real
certificate inputs and Make parity, then build the veriexec consumer. See README
for evidence, interface scope and unqualified cases.

## Subsequent progress: native libsecureboot static graph

Eight-source native static library now builds with explicitly selected trust
policy and certificate labels. An upstream public fixture decodes into one
anchor and cached initialization succeeds. Archive member/symbol counts match
Make (eight/41); missing policy fails analysis. No default production trust is
introduced. Shared installation, real signed-file checks, key rotation and
veriexec consumer conversion remain next steps. The audit log records an
existing hash self-test return-status weakness found during review.

## Subsequent progress: native veriexec command

Static veriexec and its maintained manifest test build natively. Four parser
cases pass using the existing test ioctl recorder; all 12 program/test install
records and binary symbol/static-link checks match Make. Evidence and reference
library selection are documented in the README. No host enforcement operation
was run. Continue with libsecureboot shared installation and signed-file/trust
rotation qualification, including the recorded self-test return-status issue.
System-wide world/kernel/package/bootstrap and performance gates remain open.

## Subsequent progress: libsecureboot shared installation

Shared library and all seven installation records now match Make. Both build
systems explicitly link BearSSL; its previously missing shared dependency is
fixed along with Make's transitive dependency metadata. Static and shared
trust-initialization tests pass. The SDK receipt was regenerated through maintained
helpers under bazel-secureboot-sdk-20261027 after the metadata change.
Next: signed-file/key-rotation qualification and the recorded hash self-test
error-propagation issue. System-wide migration and performance gates remain open.

## Subsequent progress: hash self-test failure propagation

Fixed the recorded hash-result loss in ve_self_tests: a hash failure returns
cached zero before signature tests can report success. Three native clean and
corrupted-expectation tests pass, including cached-result behavior, with real
upstream certificate fixtures. Existing caller policies and signature-count
semantics remain unchanged. Signed-file/trust-rotation qualification is next;
all broader system migration and performance requirements remain open.

## Subsequent progress: signed-file and trust rotation tests

A native integration test passes 25 checks with disposable in-memory RSA keys,
real signing/verification, old/new trust overlap, revocation precedence, malformed
or missing metadata and payload boundary sizes. All mutations are confined to
the test process and TEST_TMPDIR. README records exact scope and evidence.
Firmware/image key transitions, persisted revocation and boot-environment upgrade
rotation remain unqualified. Continue with declared-input/cache invalidation and
remaining world/kernel/package integration; do not equate this process-level test
with end-to-end system update qualification.

## Subsequent progress: freebsd-version and aggregate gaps

Native version generation and all three installation records match Make, with
default/overridden branch reporting and eight newvers compatibility queries
checked. The version comes from maintained source inputs, not copied constants.
The exact newvers -v query now avoids unrelated copyright/date discovery.
Review still finds missing bin targets for zsh (required default shell), csh and
rmail, plus directory test aggregation. Continue with zsh and its declared
signal/error table generators and existing DTrace instrumentation. A complete
bin/world aggregate remains unqualified; do not hide these gaps behind a partial
aggregate target. README records the evidence and remaining version-policy scope.

## Subsequent progress: zsh table generation

The native `//bin/zsh:tables` target now produces signal/errno tables and count
headers byte-identical to the isolated Make reference. Repeated build reuses
all generator outputs. See the README evidence paths. Continue with the zsh
executable and DTrace linkage, complete installation inventory, runtime tests,
and dependency invalidation checks; zsh itself is not yet converted/qualified.
Existing build-bsd format-5 target selection is sufficient for this increment.

## Subsequent progress: zsh executable

The native amd64 zsh executable builds and its Bazel smoke test passes with
candidate ncurses/terminfo/math libraries. Make parity: 1,898 global symbols,
ordered shared-library dependencies, NOW/PIE flags and nine parsed DTrace probe
records. The import helper now maintains both source lists. See README for
`bazel-zsh-runtime-r5-20261027` evidence and retained failures.
Next: full zsh installation inventory and upstream runtime suites, then
DTrace-disabled/static-root and cross-architecture configuration. Neither zsh
installation nor a complete bin/world aggregate is qualified yet.

## Subsequent progress: zsh installation inventory

The full zsh archive matches all 1,259 Make component records, including 1,251
byte-equal nonbinary payloads and validated split debug linkage. Function
inventories are maintained by the import helper for both build systems;
combined-manual includes and the execution tool are explicit Bazel inputs.
Final evidence: `bazel-zsh-install-r2-20261027/qualification/zsh` under
`/usr/obj/usr/src`. Next: upstream shell suites and configuration variants;
no complete world/image/package publication claim follows from this archive.

## Subsequent progress: upstream zsh tests and DTrace-disabled parity

The local noncached upstream Bazel test runs all 63 retained groups: 62 pass,
zero fail, P01privileged skips at UID 1001. Individual platform/terminal skips
remain visible in the retained summary/log. Job-control, ZLE, module and
completion groups pass. Missing-fixture failures from the first two runs are
preserved. Evidence: `bazel-zsh-upstream-r3-20261027/qualification`.

DTrace-disabled zsh also passes smoke and Make binary/install parity: 1,889
globals, no DOF section, all 1,259 installation records and 1,251 nonbinary
payloads matched. Evidence: `bazel-zsh-no-dtrace-20261027/qualification`.
Next: static-root configuration and remaining bin targets; cross/privileged
and whole-system gates remain open. README details the exact scope and limits.

## Subsequent progress: zsh static-root variant

`dynamic_root=false` now selects static non-PIE zsh and removes shared test
runtime dependencies. Smoke and Make binary/install parity pass: 4,907 globals,
nine DOF records, no interpreter/NEEDED entries, 1,259 installation records and
1,251 byte-equal payloads. Evidence: `bazel-zsh-static-r2-20261027/qualification`.
The setting currently has only the zsh consumer; adopting it across root
programs is still required. Continue remaining bin conversions (csh/rmail),
keeping cross/privileged/whole-system and performance gates open.

## Subsequent progress: libsm and rmail

Native libsm ordinary/PIE archives and rmail build/package correctly against
Make references. Evidence: `bazel-rmail-r4-20261027/qualification` under
`/usr/obj/usr/src`: 76 members/210 symbols per library, 149 rmail symbols,
four installation records, one byte-equal manual and verified debug linkage.
Five unchanged upstream library tests and five pre-delivery error cases pass.
Successful mail handoff was not run; source and host mail configuration are
unchanged. Custom sendmail options and broader suite coverage remain open.
Continue csh conversion and remaining aggregate/system gates.

## Subsequent progress: csh native build

Native csh generators and executable now build. Four generated files match
Make byte for byte; the executable matches 1,108 globals and dynamic/hardening
metadata, and a candidate-library arithmetic/array smoke test passes. Evidence:
`bazel-csh-runtime-20261027/qualification/parity.json` under `/usr/obj/usr/src`.
Next: complete csh installation including NLS catalogs/links, examples,
configuration and csh/tcsh aliases. Static-root, iconv/NLS alternatives and
interactive/upstream suites remain unqualified. World aggregation stays open.

## Subsequent progress: csh installation

Complete default csh inventory matches Make: 75 records, 38 symlinks, two
hardlinks, 19 byte-equal nonbinary records and both executable debug links.
The iconv-disabled/no-examples variant also passes smoke and binary/install
parity: 1,111 globals, 40 records, six symlinks and 17 byte-equal nonbinary
records. Evidence directories: `bazel-csh-install-r2-20261027` and
`bazel-csh-noiconv-20261027` under `/usr/obj/usr/src`.
Next: csh upstream/interactive tests and static-root/NLS variants, then review
remaining directory/aggregate coverage. Whole-world, kernel and publication
qualification still cannot be inferred from component coverage.

## Subsequent progress: csh static/NLS-disabled and test coverage audit

Static, NLS-disabled, no-examples csh passes smoke and Make parity: 3,665 globals,
four byte-equal generated files, static non-PIE ELF and 13 installation records.
Evidence: `bazel-csh-static-nonls-20261027/qualification` under `/usr/obj/usr/src`.
The imported tcsh tree has no upstream runtime suite; interactive coverage
remains open.

The retained bin inventory shows 42/42 immediate component directories have
BUILD files, but 19/25 tests directories lack them (including bin/tests).
This is file presence, not a completion percentage. Next: integrate cat's
maintained NetBSD and local ATF shell tests and their fixtures, then the other
missing test directories listed in README. A complete bin aggregate must not
omit test metadata or imply unsupported runtime qualification.

## Subsequent progress: cat tests packaged, runtime failures retained

Both maintained cat shell suites (13 cases) and eleven fixtures now have native
Bazel test/install targets. Complete program+test installation matches Make:
19 records, 15 byte-equal nonbinary payloads and a valid debug link. Evidence:
`bazel-cat-install-20261027/qualification/cat` under `/usr/obj/usr/src`.

All 13 runtime cases fail before their bodies because native dirname asserts
in cap_rights_intersect. `bazel-cat-tests-20261027/qualification` preserves logs
and a Make/native host/SDK comparison reproducing the same failure for both
builds. Do not substitute host helpers or mark this suite passed. A matching
runtime/compatibility diagnosis is still required. Next useful independent
work: continue missing bin test/install integration while preserving this
runtime gate; 18 listed tests directories remain without BUILD files.

## Capsicum runtime failure diagnosed (2026-10-27)

The cat ATF startup failure is reproducible with the host's old Capsicum ABI.
A small C probe opens /dev/null and obtains rights using cap_rights_get, built
once with installed headers/libraries and once with the authenticated SDK
sysroot. Both executions return rights words 02000fffffffffff and
040000006fffffff. Host CAP_ALL matches; SDK CAP_ALL is 02000fffffffffff and
05fc000001ffffff. Returned index-1 bits 0x6e000000 are outside the SDK's valid
mask, explaining cap_rights_is_valid rejecting the inherited rights before
cat's test bodies execute.

Commit fc21f4e34df moved local rights on October 8 and explicitly requires a
coordinated kernel/world upgrade. The running kernel was built October 7.
Some old rights also overlap newly allocated upstream rights, so masking
unknown bits is not a sound ABI compatibility fix. Keep the existing failed
Make/native runtime results. Qualification requires a matching kernel/world
runtime; neither changing PATH to host helpers nor suppressing the assertion
qualifies the candidate. No host installation or reboot was performed.

Probe source, both executables and results.json are retained under
/usr/obj/usr/src/bazel-cat-tests-20261027/qualification/capsicum-abi.
This evidence explains the shared startup failure; it does not establish
that the 13 cat cases pass on a matching runtime. The frontend and backend
require no implementation changes for this diagnostic-only update.

## echo ATF integration (2026-10-27)

The two maintained echo cases now use an ATF executable configuration input,
with /bin/echo retained as the installed-suite default. Bazel supplies the
actual declared echo target through config_files, avoiding tests of the host
binary. Test expectations are unchanged. Native scripts and Kyuafile are
included in echo's installation archive when tests are enabled.

Make installation parity passes: seven records, three byte-equal nonbinary
files and one executable debug link. Evidence is under
/usr/obj/usr/src/bazel-echo-install-20261027/qualification/echo, compared with
/usr/obj/usr/src/bazel-echo-tests-make-20261027. Archive SHA256:
1d90198833eb596dfa53c2d95424e2df791752971dbfc21126dfebf48b0ccc67.

The first runtime request was rejected because its requested test suite was
not also a selected target. Corrected inputs reach both tests, which fail
before their bodies with the previously diagnosed host/SDK Capsicum mismatch.
Failure reports and copied logs are retained in
/usr/obj/usr/src/bazel-echo-tests-r2-20261027. Neither case is runtime-qualified.
Seventeen of the previously listed bin tests directories still lack BUILD
files. The existing frontend format-5 targets/tests interface supports this
integration without C/backend changes; the maintained manual documents it.

## Native bsdcat and maintained libarchive suite (2026-10-28)

Added explicit bsdcat sources, configuration/header dependencies, native
libarchive linkage, installation/debug transforms, and all 18 maintained test
sources with eleven declared compressed/reference fixtures. The test registry
is a declared native generation action. Test utility objects use alwayslink
to preserve Make's directly linked object, and the harness explicitly declares
its maintained compression/crypto dependencies and their order.

The shared libarchive CLI runner now preserves the candidate's basename;
renaming it to program had broken the unchanged bsdcat help assertion. The
initial run executed 18 cases with one failure; after this runner fix all 18
pass, with 1,051 assertions and no skips. This is a local integration suite:
its existing runner uses host shell utilities and host libc, alongside declared
native libarchive/dependency DSOs. It remains noncacheable; it does not prove
hermetic runtime behavior or compatibility of an entire new world with this
host kernel. Installed ATF wrapper execution was not separately qualified.

Final evidence: /usr/obj/usr/src/bazel-bsdcat-r7-20261027/qualification.
Make reference: /usr/obj/usr/src/bazel-bsdcat-make-20261027.
Program and harness match 11 and 102 defined globals respectively, ordered
NEEDED libraries match, and generated list.h is byte-identical. Full program
and test installation matches 24 records, 14 byte-identical nonbinary files
and both debug links. Archive SHA256:
5752ef75b8a4f2b5604f70cd812eb7793cdba6afedc63f861d54782e30b7b093.
Earlier analysis failures (configuration visibility, manifest composition,
a delimiter error) and the help failure remain in prior output directories.

Existing frontend format-5 target/test selection supports these targets; no
frontend C or backend contract change is required. Manual coverage is updated.
Remaining: alternate configurations, full native world/kernel/bootstrap and
pkgbase aggregation, declared runtime closure, cache/performance qualification.
The directory scan found 94 immediate usr.bin Makefile directories without
BUILD files before bsdcat, now 93; that includes aggregate directories and is
not a count of missing programs or a completion percentage.

## Native stdbuf and preload library (2026-10-28)

Added native stdbuf compilation and libstdbuf static/shared targets, with
explicit package/manual/debug/symlink installation. No production C or
installed preload path changed: stdbuf still selects /usr/lib/libstdbuf.so.
The new Bazel runtime_test preloads the declared candidate DSO into child
processes and observes pipe output after _exit (no exit-time stdio flush).
All eight stdout/stderr cases pass: 0, L, B and 4k buffer modes. This exercises
the real library constructor, not an installed host copy. It does not test
stdin buffering, invalid modes, privileged loading, other architectures or
the installed stdbuf-to-library path; the last requires an isolated runtime.

Evidence: /usr/obj/usr/src/bazel-stdbuf-runtime-20261028/qualification.
Make references: bazel-libstdbuf-make-20261028 and bazel-stdbuf-make-20261028
under /usr/obj/usr/src. Program globals (6), shared globals (2), static archive
(1 member, no exported globals), SONAME, NEEDED and dynamic hardening flags
match Make. Installation matches seven library records and five command
records, two byte-identical manuals, one symlink and both debug links.
Library archive SHA256:
b55ce983050d8b9d331f3c95ed4ed173f550dee7a1bbd737a28528d54700855e.
Command archive SHA256:
f4b8ee37a87f195541ee5dd3eb655c63bb6f65af349070072702b15aa3613a46.

Existing frontend format-5 target/test inputs support this integration; no
frontend C/backend contract change is needed. Manual and observability records
are updated. Make remains production/default. Full world/kernel/bootstrap,
pkgbase aggregation and CPU/memory/disk/cache qualification remain open.

## Native xstr, revoke and tcopy (2026-10-28)

Three more utilities now have explicit native source/dependency and installation
targets. xstr declares its local pathnames header and toolchain package;
revoke retains the utilities package. tcopy declares native libutil, libc++,
libcxxrt and libm dependencies, with ordinary C++ RTTI/exceptions retained as
in Make. Production sources are unchanged.

Each installation matches five Make records, a byte-identical compressed
manual, and a valid executable debug link. Defined globals match (xstr 6,
revoke 6, tcopy 40); ordered NEEDED libraries, NOW/PIE flags and absence of
runtime search paths also match. Evidence:
/usr/obj/usr/src/bazel-xstr-revoke-20261028/qualification and
/usr/obj/usr/src/bazel-tcopy-20261028/qualification. Separate Make references
are bazel-{xstr,revoke,tcopy}-make-20261028 under /usr/obj/usr/src.

Retained runtime comparisons cover xstr file/stdin input and persistent
string-table processing, including repeated/suffix strings and escapes;
outputs match Make byte-for-byte. revoke checks cover usage and an explicitly
nonexistent path only. tcopy uses private regular SIMH-TAP files, testing read,
copy, verify, raw extraction and malformed trailer rejection (exit 65).
Extracted payload is checked against the independently supplied bytes, and
copied tape bytes match Make. Both tcopy executables use the declared native
DSOs plus the SDK runtime in this comparison. No live device was accessed.
These are retained direct runtime comparisons, not newly registered Bazel test
targets. Device revocation, physical tape/file-set behavior, complete option
coverage and native test registration remain open.

Archive SHA256:
- xstr: 36c0bc764b34b3da1fce810f7eb61e28e10f16fbd4e32b3b91b55e34d2883adf
- revoke: 29566806d0767d5e06157d465d7221af5d35248ff3aba61bf12172dea29199d8
- tcopy: ee815eb94af52c9310d2d3edf26c8cc5f307af09dff3eb7d007839163d06458a

The maintained frontend target-selection interface requires no C/backend
change for these components; the manual lists the installation targets.
World/kernel/bootstrap/pkgbase aggregation and performance gates remain open.

## Native kernel configuration tool (2026-10-28)

usr.sbin/config now has native compilation, installation and generation actions:
config.y through native yacc, lang.l through native lex with declared m4, and
kernconf.tmpl through native file2c. The small shell adapter preserves the
maintained transformation; it runs with an explicit tools-only PATH. Generated
parser headers and local config/configvers headers are declared compilation
inputs. C++ runtime dependencies and both section-5/8 manuals are explicit.
No liby dependency is needed: this parser supplies its own parser entrypoints.

Evidence: /usr/obj/usr/src/bazel-config-20261028/qualification, with independent
Make reference /usr/obj/usr/src/bazel-config-make-20261028. All 102 globals,
ordered dependencies and dynamic hardening metadata match. kernconf.c and
y.tab.h are byte-equal; generated parser/lexer C agrees after normalizing only
#line filenames (line numbers/code remain compared). Complete installation
matches six records, two byte-equal manuals and one debug link. Archive SHA256:
10020ae11ad8b76039dfafcae9dc034bbc539f028b4ed434a82972507de34600.

Both executables report version 600018 and amd64/amd64 for GENERIC. Configuring
real GENERIC and GENERIC with -g in private output directories gives identical
200-entry inventories each, including all generated bytes, modes, links and
diagnostics. Both use the same native C++ DSOs and SDK libc for this comparison.
No kernel was compiled or booted. These are retained direct comparisons, not
yet Bazel-registered configuration tests with a declared kernel-source closure.

An unchanged-input repeat at bazel-config-repeat-20261028 has zero executed
spawns and identical captured artifact hashes. This establishes local warm
cache reuse only; invalidation, cross execution, bootstrap independence and
full CPU/memory/disk performance remain open. Native compiler/SDK bootstrap
still depends on Make-prepared inputs.

The next kernel integration must express configured sources, generated headers,
compiler/linker inputs and modules as native Bazel actions. Running Make over
config's generated Makefile would not satisfy native kernel integration.
Current maintained config output parity is a prerequisite, not that end state.
The existing frontend format-5 interface needs no C/backend contract change;
the maintained manual documents the new component and its limits.

## Native install and explicit bootstrap variant (2026-10-28)

Added usr.bin/xinstall native compilation/linkage, hashing and mtree identity
headers, DTrace generation, and complete program/manual/debug plus maintained
ATF-script/Kyuafile installation. The installed program remains named install.
The separate bootstrap_install target defines BOOTSTRAP_XINSTALL and omits
instrumentation, matching the maintained source's bootstrap branch. It has
been built/inspected and exercised, but does not replace SDK/bootstrap helpers
or prove a self-hosted build; its execution-time DSO closure still needs wiring
where it becomes a declared build tool.

Evidence: /usr/obj/usr/src/bazel-xinstall-r2-20261028/qualification, versus
/usr/obj/usr/src/bazel-xinstall-make-20261028. The normal executable matches 17
globals, ordered NEEDED libraries and NOW/PIE metadata. Five DTrace records
(fallback, range-start/done, sync-start/done) match provider/function/probe
names, argument types and site counts; addresses are allowed to differ.
The bootstrap executable has no copy_file_range import or .SUNW_dof section.
Complete installation matches eight records, three byte-identical nonbinary
files and the debug link. Archive SHA256:
f7301000702b926e4eb8f10b72c83cf5cb1728891990b1935555ab7538f016aa.

Direct runtime comparisons exercise native, Make and bootstrap executables on
private files: copy/compare, safe replacement with backup, preservation of
timestamps, directory modes, hard/relative symlinks, stdin/null input, five
independently verified hashes, and METALOG with an explicit alternate identity
database. They agree, using native libmd and SDK runtime libraries. Initial
fixture errors (relative link source and missing master.passwd) were corrected;
production behavior was unchanged and earlier outputs remain preserved.

The first build exposed a missing NetBSD util.h dependency, now declared.
The installed ATF suite is packaged unchanged, but its cases are not yet
registered/executed through native Bazel. Other remaining gates include stripping,
privileged ownership/flags, complete option coverage, forced I/O failures,
DTrace attachment, runtime closure and bootstrap parity against a matching
BOOTSTRAPPING Make build. Existing frontend format-5 inputs support these
targets; no C/backend change or bootstrap-tool substitution was performed.
World/kernel/pkgbase and performance gates remain incomplete.

## Native mtree staging component (2026-10-28)

Added explicit imported mtree/mknod sources, NetBSD compatibility PIE archive,
libmd/libutil dependencies, mtree/nmtree hardlinks, both manuals and the complete
maintained test installation. Two fixture substitutions (sha256 to
sha256digest) are declared generation actions matching Make. An initial duplicate
manual alias declaration was rejected by the existing rule and corrected;
no production source or expected fixture bytes changed.

Twelve native byte-comparison tests pass, carrying the imported -C/-D conversion,
-S sorting and -M merge commands for mtree and netbsd6 flavors with their original
input/expected fixtures. These tests select declared native executable/DSOs
without requiring an ATF shell; the installed ATF suite remains unchanged.
Directory creation, permissions and other remaining ATF cases are not covered
by this twelve-case result.

Evidence: /usr/obj/usr/src/bazel-nmtree-tests-20261028/qualification; independent
Make reference: /usr/obj/usr/src/bazel-nmtree-make-20261028. Sixty globals,
ordered dependencies and NOW/PIE metadata match. Full installation matches
21 records, two hardlinks, 15 byte-equal nonbinary files and both executable
alias debug-link checks. Archive SHA256:
271e29cf2b2de3c3941e730628e74272b93470438acbf6fd8e17292d25bdd0d3.

Private-tree comparison produces identical specs and verification results for
native and Make binaries. Valid content exits 0; changed SHA256 content and
mode exit 2. An existing behavior discrepancy was confirmed: missing and extra
entries are reported on stdout but exit 0 in both builds, despite the manual's
broad mismatch-status description. verify.c reports those paths without updating
the mismatch return value. This migration preserves that behavior and records
it as an open issue; never treat exit 0 alone as proof of a complete matching
tree. The inspected Bazel archive_policy.py uses mtree -C to parse inventories,
not this tree-verification return status, and performs its own record checks.
The initial overly broad exit-status expectation was corrected to assert actual
status plus missing/extra diagnostics, with prior output retained.

The maintained frontend format-5 interface needs no C/backend change for these
targets. This candidate has not replaced the SDK staging mtree. Execution-tool
runtime closure, broader ATF cases, invalidation/performance, full bootstrap,
world/kernel/pkgbase and publication gates remain open.

## Native mtree used by an installation action (2026-10-28)

The install archive rule now accepts mtree_runtime_libraries as declared
execution-configuration inputs. It rejects duplicate library basenames and
runtime declarations without mtree policy. The policy helper validates those
files and sets LD_LIBRARY_PATH only for its mtree subprocess, leaving the
Python/controller environment unchanged. Existing SDK-tool callers retain
their current behavior when no library list is supplied.

usr.bin/xinstall:install_archive is the first consumer switched from staged
extra_mtree to //usr.sbin/nmtree:mtree. Its declared native libmd/libutil and
SDK libc/libsys are built/selected in the execution configuration. The normal
maintained frontend successfully builds the archive with that tool. Evidence:
/usr/obj/usr/src/bazel-native-mtree-archive-r2-20261028/qualification/native-mtree.json.
Authenticated captured output is byte-identical to the prior SDK-mtree archive:
f7301000702b926e4eb8f10b72c83cf5cb1728891990b1935555ab7538f016aa.
The request records native-opt-exec paths for mtree, libmd and libutil.
Nine archive-policy tests pass, including child-environment isolation and
failure before execution when a declared runtime library is missing.

This qualifies one native staging-tool consumer. Other archive targets still
use their SDK mtree declarations; the compiler, libc/libsys and Python runtime
remain staged SDK inputs. It does not establish independent bootstrap, full
runtime-loader hermeticity, cross-host execution or system-wide packaging.
The backend rule/helper/tests/manual changed together. Frontend CLI/input
formats are unchanged; no build-bsd C change is required for this rule-level
execution dependency. Further native-tool adoption and full world/kernel/
pkgbase/performance gates remain open.

## Native libkldelf and kldxref (2026-10-28)

Added the nine maintained libkldelf sources, private static/shared installation,
explicit libelf dependency, native kldxref and a static-library bootstrap variant.
Relocation backends register via linker sets with no ordinary references;
Bazel alwayslink preserves them in static consumers instead of duplicating
backend source lists in kldxref. The ordinary shared library remains
libprivatekldelf.so.5, matching the maintained ABI. No public header installation
was invented; the Make component declares none.

Evidence: /usr/obj/usr/src/bazel-kldxref-20261028/qualification. Make references:
bazel-libkldelf-make-20261028 and bazel-kldxref-make-20261028 under /usr/obj/usr/src.
Global symbols match (program 6, shared library 33, static archive 29); all nine
archive members are present. Ordered dependencies, SONAME and NOW/PIE metadata
match. All eight relocation registrations survive in the shared library and
bootstrap executable. This verifies registration retention, not functional
coverage of all represented architectures.

Using private copies of host nullfs.ko and tmpfs.ko, native, Make and bootstrap
executables produce byte-identical three-record hints. The records' bounds and
module names are independently checked. Malformed explicit input fails without
replacing the existing hints file. Fixture hashes and output SHA256 are retained:
1ce54594795f70645790cfcff5cb35e87427b822cb496d2c854c04692fe658e2.
No module was installed or loaded. This is an amd64 direct runtime comparison,
not a newly registered Bazel test suite or qualification of cross-architecture
relocations, full module generation, recursive discovery or bootstrap independence.

Private-library installation matches six records, its link and debug linkage;
program installation matches five records, its manual bytes and debug linkage.
Archive SHA256:
- libkldelf: a9f4114810019d2737f9998b3bd7f0e791c938c7a0e53be0d8215f59c68cb129
- kldxref: 395243bf4521823bd3cf72ddd0db341335b253bdf3409894577b5c9c16f69fbb

Existing frontend format-5 target selection supports these candidates without
C/backend contract changes. The manual records new targets; publication/image
helpers have not been switched to this candidate. Native execution dependencies,
maintained fixture tests, kernel/module builds, complete pkgbase and performance
qualification remain unfinished. Make remains the production/default backend.

### Native kldxref synthetic fixture qualification (2026-10-28)

`//tools/test/construction:pnp_fixtures` builds all nine maintained PNP ELF
fixtures using native C compilation and declared object outputs. Case definitions
remain in `pnp_fixture.c`, shared with Make; these are never kernel-loaded.
The maintained build-bsd format-5 frontend built the fixtures with 16 jobs in
`/usr/obj/usr/src/bazel-kldxref-fixtures-20261028`. Its existing target-selection
contract suffices; no frontend C, signing, staging or publication change is needed.

The unchanged `audit-pnp.py`, `audit-module-inputs.py`, and `audit-kldxref.py`
passed against native, bootstrap and Make kldxref using those fixtures: nine PNP
cases, twenty explicit-input checks and eight hints-update cases per variant.
Coverage includes malformed descriptors, bad pointers, mixed architectures,
selected-input validation, failed writes/renames, preservation of prior hints,
and temporary-file cleanup. Evidence, exact invocation script and reports are
under that output's `qualification` directory. No modules were installed/loaded.

These are direct host-Python audit runs, not registered Bazel tests. The script
sets the child loader environment after Python starts and uses native libkldelf,
libelf/libz and SDK libc/libsys. It does not establish loader hermeticity,
non-amd64 relocation correctness, or kernel/module build completion. Registering
these audits with declared interpreter, runtime and runfiles is still required.
Make remains production/default; full world/kernel/pkgbase, cache and performance
gates remain incomplete.

### kldxref audits registered as Bazel tests (2026-10-28)

Six maintained targets now run the unchanged construction audits for native and
bootstrap kldxref: `{native,bootstrap}_{pnp,module_inputs,kldxref}_test` under
`//tools/test/construction`. Nine PNP cases, twenty explicit-input checks and
eight hints-update cases pass per variant. Tests declare the native program,
ELF fixtures, shared-library closure, SDK Python and standard library as runfiles.
The adapter selects the child library directory only after Python starts; it
preserves audit exceptions and exit codes. Host shell and Python-loader runtime
dependencies remain, so these tests are local and uncached, not hermetic.

`/usr/obj/usr/src/bazel-kldxref-tests-r3-20261028` records six executed/passed
Bazel tests through maintained `build-bsd bazel-test` with sixteen jobs. Receipt
and retained test log/XML hashes were checked. Bazel reports six aggregate test
cases; the logs contain the individual audit reports (74 checks in total).
Existing frontend format-5 targets/tests support this without a C/backend
interface change. The manual documents the test selection.

The first run rejected the SDK Python file because the new rule omitted
`allow_files`. The second run passed its audit bodies but blocked while Bazel
collected intentional FIFO fixtures from undeclared outputs. That run was
cancelled; its blocked collectors were released and its result is not accepted
as qualification. The maintained adapter now keeps audit work in TEST_TMPDIR
and exports only regular JSON reports. The third run completes naturally.
No modules were loaded, and no host installation or publication was performed.
Full world/kernel/module builds, package aggregation, cross-architecture runtime,
bootstrap independence, sandboxing and performance qualification remain open.

### Native core kernel object-interface generation (2026-10-28)

`bsd_kobj_interface` now declares both C and header outputs from each maintained
`.m` input. The rule runs unchanged `sys/tools/makeobjops.awk` using native awk,
mv and rm selected for the execution platform, an explicit tool-only PATH,
execution-platform libraries, and declared SDK Python/stdlib. Separate source
and header output groups are available to future native kernel consumers.
A declared input symlink supplies a stable basename so generated provenance
comments do not embed the action execroot. Input contents are not rewritten.

All eight `sys/kern` interfaces are targets: bus_if, clock_if, cpufreq_if,
device_if, linker_if, msi_if, pic_if and serdev_if. Qualification at
`/usr/obj/usr/src/bazel-kobj-20261028` uses maintained frontend format-5 target
selection and sixteen jobs. Each of sixteen generated C/header files is
byte-equal to the unchanged Make recipe's separate -c/-h invocations, using
host awk and the same source basename. Results and hashes are in
`qualification/parity.json`. This compares generation, not compiled kernel ABI.

`/usr/obj/usr/src/bazel-kobj-repeat-20261028` has zero executed spawns and the
same sixteen output hashes. That proves local unchanged-input reuse only;
input invalidation, remote execution/cache portability and performance gates
remain separate work. The generator's awk system() calls still use host
/bin/sh, and SDK Python/loader dependencies remain. Full sandbox hermeticity
and native compiler bootstrap are not established.

No generated kernel interfaces were compiled or linked into a kernel. Device
interfaces outside sys/kern, configured source selection, option headers,
assembly/offset generation, kernel linking, modules and pkgbase aggregation
remain unfinished. The existing frontend needs no interface change to select
these generation targets; its manual is updated. Make remains production/default.

### Native vnode interface generation (2026-10-28)

`//sys/kern:vnode_if` runs unchanged `vnode_if.awk` with native execution-platform
awk and explicitly declared source, generator, shell, libraries and shell
runtime. The action declares all four outputs: vnode_if.c, vnode_if.h,
vnode_if_newproto.h and vnode_if_typedef.h. `vnode_source` exposes the C output;
`vnode_headers` supplies the generated headers through a native CcInfo dependency
with their maintained include names. It does not execute a generated Makefile.

`/usr/obj/usr/src/bazel-vnode-20261028` records the maintained build-bsd format-5
qualification with sixteen jobs. All four output files match the maintained
Make recipe's separate -c/-h/-p/-q generator invocations byte for byte. Exact
reference commands and output hashes are retained in `qualification/parity.json`.
The generated C retains 166 SDT probe definitions and 166 call sites; the main
header retains 166 declarations and 116 inline call sites. Counts are source
observations, not live DTrace attachment or a compiled-kernel instrumentation test.

This is generation-only qualification. Kernel compilation/linking, option and
assembly-offset generation, configured source selection, drivers/modules and
package aggregation remain unfinished. Execution still depends on the SDK and
host loader; cross execution and full sandbox/cache portability are unqualified.
The existing frontend target-selection contract needs no C/backend change; the
manual documents these candidates. Make remains production/default.

### Complete current object-interface generation inventory (2026-10-28)

Added 124 native interface targets, bringing coverage to all 132 current
`sys/**/*_if.m` definitions (also all current sys/**/*.m files). This includes
PCI, USB, ACPI, network, storage, crypto, Xen, ARM and RISC-V interfaces. Shared
`kernel_interfaces` applies the same declared generator/tool/runtime contract;
package-local globs discover additional interfaces in those packages. Existing
parent packages are preserved: CAM and GEOM use relative source declarations
rather than new child package boundaries that could exclude existing headers.
Adding a new package still requires its normal BUILD declaration.

`/usr/obj/usr/src/bazel-all-kobj-20261028` built all 132 targets through maintained
build-bsd with sixteen jobs. `qualification/verify.py` independently enumerates
the current source inventory, requires exact equality with selected target labels,
and compares every output with the maintained separate -c/-h generator recipes.
All 264 C/header files are byte-equal. The reference uses host awk with matching
source basenames; no generated output is normalized or filtered.

`/usr/obj/usr/src/bazel-all-kobj-repeat-20261028` verifies the shared macro also
preserves core-interface outputs. It executes zero spawns and all 264 hashes
match. This establishes local unchanged-input reuse, not input invalidation or
remote/sandbox portability. Foreign-architecture interface text generation is
not cross-compilation or runtime qualification. No kernel, module or driver was
compiled, installed or loaded by this work.

Frontend format-5 target selection already handles the expanded inventory;
manual and observability notes are updated without a C/backend contract change.
Kernel source selection still contains special compile rules and dependencies
that require explicit native actions. Configured options, full compiler flags,
assembly offsets, kernel/module linking, packages and performance gates remain
unfinished. Make remains production/default.

### Kernel include-generator failure propagation (2026-10-28)

Review before native offset/assembly-constant integration reproduced a shared
Make-path defect: genassym.sh and genoffset.sh both returned success when NM
could not execute. The successful final pipeline command masked symbol-reader
failure. The maintained scripts now capture NM output and require its success
before transformation; genoffset also checks selection, substitution and sorting
before emitting the include. A genoffset input with no offset symbols fails.
The valid transformation logic and formatting remain unchanged.

`python3.12 -B tools/build/bazel/kernel-offset-errors-test.py` passes two tests
with twenty failure subcases: missing NM, a partially writing failed NM, invalid
and missing object inputs (stdout and -o forms), and failed awk/grep/sed/sort.
`/usr/obj/usr/src/bazel-kernel-offset-errors-20261028/parity.json` records byte-equal
before/after output for the existing Make GENERIC genassym.o and genoffset.o:
5465 and 695 bytes respectively. Those objects are reference inputs, not native
Bazel-built kernel artifacts. The scripts' -o interface still truncates the
requested output before work; transactional publication is not claimed.

The scripts are shared by maintained kernel Make targets, so normal frontend
kernel builds receive the fix without frontend C or backend selection changes.
No staging, signing, packaging or publication contract changes. Native offset
object compilation and generation actions still need integration and configured
kernel headers; whole-kernel/module/package/performance gates remain open.

### Declared kernel constant extraction actions (2026-10-28)

`kernel_constants` wraps the maintained genassym/genoffset scripts through the
existing declared script-output rule. Object inputs, prerequisite check objects,
generator scripts, tool-only PATH and execution runtime are explicit. Native
awk, grep, sed and sort are selected in the execution configuration. llvm-nm,
shell and compiler remain SDK tools. The action reads target ELF objects and
does not execute them; cross-target correctness still requires qualification.

`//tools/build/bazel/tests/kernel_constants:constants_test` compiles real
ASSYM/OFFSYM encodings with -fcommon, extracts offset.inc, compiles OFFSET_TEST
layout assertions, requires that check object before assym.inc generation, then
compiles assertions for zero, negative, 16-bit-boundary, 64-bit and member-offset
constants. The standalone fixture supplies CTASSERT as a real _Static_assert;
this was missing in the first attempt and caused a compile failure. No assertion
was disabled. The fixture is not the kernel's actual thread structure.

`/usr/obj/usr/src/bazel-kernel-constants-r2-20261028` records a passed Bazel test
through maintained build-bsd with sixteen jobs. Both generated includes match
the maintained host-tool recipe on the same native-compiled fixture object:
offset.inc 516 bytes, assym.inc 142 bytes. Reference commands and hashes are in
`qualification/parity.json`. This qualifies extraction and its prerequisite
chain, not GENERIC genoffset.o/genassym.o compilation or a bootable kernel.

The existing frontend format-5 interface can select these targets without a
C/backend change. Manual guidance is updated. Kernel configuration/options and
complete header dependencies must precede real kernel-layout object conversion.
Complete world/kernel/modules, pkgbase, bootstrap independence, cache-invalidation,
sandbox and performance gates remain open. Make remains production/default.

### Declared native GENERIC configuration actions (2026-10-28)

`bsd_kernel_config` now runs native config in the execution configuration with
explicit configuration sources, shared files/options/template/std metadata,
source-root anchor, runtime libraries and SDK Python/stdlib. The output is the
complete generated directory rather than a curated option-header inventory.
`//sys/amd64/conf:generic_config` and `generic_debug_config` cover GENERIC and
config -g. Additional configurations must declare all their inputs; only these
two have qualification evidence. The Makefile S path is relative to its output
directory, avoiding action-root paths. The Makefile is captured, never executed.

`/usr/obj/usr/src/bazel-kernel-config-r2-20261028` passes maintained build-bsd
qualification with sixteen jobs. Both variants produce 200 files, including
196 headers. Every filename and file content matches the Make-built config
reference with the same source-root argument. All 400 regular outputs are
captured in the frontend's authenticated artifact manifest. Bazel read-only
output modes are not compared to ordinary writable reference output modes.
Reference commands and complete per-file hashes are in qualification/parity.json.

The first invocation generated both trees successfully but failed frontend
capture: BEP omits the length field for zero-byte outputs. bep_artifacts now
uses the protobuf scalar default of zero while still checking file size and
SHA-256. Tests cover an empty output with omitted length and rejection of a
nonempty output with omitted length; all fifteen capture tests pass. This is a
maintained backend fix, with no frontend C interface or package/publication
policy change. Empty headers are preserved, not dropped to satisfy capture.

No kernel objects were compiled from these headers yet. Configured source/rule
selection, kernel compiler options, full header closure, real genoffset/genassym,
linking, modules and pkgbase remain unfinished. SDK compiler/interpreter/loader
and source-access isolation still need bootstrap/sandbox qualification. Make
remains production/default. Whole-system runtime and performance gates remain open.

### Actual amd64 GENERIC layout compilation (2026-10-28)

Native targets now compile the actual sys/kern/genoffset.c twice (normal and
OFFSET_TEST) and sys/amd64/amd64/genassym.c. They use Bazel-generated GENERIC
option headers, declared source-tree sys/machine/x86/BSM/VM/ISA/CK/HWPMC headers,
-nostdinc, kernel defines, amd64 kernel ABI flags, freestanding compilation and
-fcommon. No host installed headers or copied Make objects provide these inputs.
The assembly-constant action depends on successful offset-layout assertions.
The first genassym attempt exposed missing HWPMC headers; a declared header
dependency fixed it without disabling GENERIC's HWPMC_HOOKS option.

Targets: //sys/kern:generic_genoffset_object, generic_genoffset_check_object,
generic_offset, generic_genassym_object and generic_assym. Evidence is under
`/usr/obj/usr/src/bazel-generic-layout-r2-20261028/qualification`. A fresh Make
reference was built in the earlier offset qualification's make-reference
subdirectory using current Make-built config output, maintained Make targets,
the same SDK compiler/nm, and sixteen jobs. The 6, 6 and 1167 nm symbol/size
records respectively match. offset.inc (695 bytes) and assym.inc (5465 bytes)
are byte-equal. This does not claim byte-identical DWARF/object files.

The maintained frontend's existing format-5 targets support these outputs;
manual and observability notes are updated. No C/backend interface, staging,
signing or publication change is needed. Compilation flags are currently scoped
to these amd64 GENERIC layout objects, not a complete configurable kernel policy.
The configuration tree is a coarse header dependency: finer option-header
invalidation needs attention before kernel incremental-performance qualification.
Source header inventories use package-local globs, with machine/x86 include
names represented by native CcInfo rather than source-root include fallbacks.

This qualifies real kernel layout inputs, not a linked/booted kernel, other
configurations/architectures, modules or packages. Compiler bootstrap still uses
the SDK. Full source selection, compile policy, kernel linking, runtime, cache
invalidation and CPU/memory/disk performance gates remain open. Make remains
the production/default backend.

### Precise kernel option-header dependencies and invalidation (2026-10-28)

`bsd_tree_file` exposes selected generated tree members as independently hashed
files. Layout compilation now declares only opt_global.h for the offset objects,
plus opt_hwpmc_hooks.h and opt_kstack_pages.h for genassym. The complete config
output remains captured; individual consumers no longer directly depend on the
entire configuration tree. New consumers must declare the option headers they
actually include. -nostdinc continues to prevent installed-header fallbacks.

The extraction adapter accepts Bazel's sandbox input symlinks and rejects
non-normalized member paths or nonregular/missing members. An initial attempt
incorrectly rejected sandbox symlinks; the corrected helper passes two tests
covering empty/nested/symlink-backed files and invalid member paths. Declared
artifact extraction is not an untrusted-archive security boundary.

`/usr/obj/usr/src/bazel-layout-headers-r2-20261028` qualifies the new dependency
graph. `/usr/obj/usr/src/bazel-layout-invalidation-20261028` retains the exact
mutation script, original GENERIC bytes, frontend logs, execution logs and result:
- Adding MSGBUF_SIZE reruns config plus three member extractions (four actions),
  executes no C compilation and preserves offset.inc and assym.inc hashes.
- Adding KSTACK_PAGES=8 compiles only generic_genassym (six total actions), changes
  assym.inc and preserves offset.inc. Both genoffset objects are reused.
- Restoring GENERIC recompiles only genassym and restores both original hashes.
The source was restored byte for byte and has no remaining diff. All phases use
maintained build-bsd with sixteen jobs; no host installation or reboot occurred.

This resolves the recorded whole-config dependency issue for these three layout
objects. It is concrete input-invalidation evidence, not whole-kernel cache,
remote execution or CPU/memory/disk performance qualification. Full native
kernel/world/module/package and runtime gates remain unfinished. Existing
frontend target selection handles these actions without a C/backend contract
change; the manual documents the dependency behavior. Make remains default.

### Generated kernel data objects with retained CTF/DWARF (2026-10-28)

Native targets now extract and compile GENERIC config.c, env.c and hints.c,
with -fno-common and declared generated option/offset headers. Their ordinary
objects pass through native ctfconvert. The missing offset.inc dependency
through sys/kpilite.h was caught on the first attempt and added explicitly.
No kernel options or header checks were disabled.

bsd_ctf_library now accepts preserve_debug (default false for existing callers)
and either a literal CTF label or a string build-setting label. These generated
GENERIC objects enable debug preservation, matching Make's -g conversion flag.
`//tools/build/bazel/config:kernel_ctf_label` defaults to ctfconvert's maintained
no-VERSION fallback label, and can be overridden in frontend build-settings.
The rule does not read an undeclared VERSION environment variable.

`/usr/obj/usr/src/bazel-generic-data-r2-20261028/qualification` compares native
objects against fresh maintained Make config.o/env.o/hints.o using the same SDK
compiler and the host Make ctfconvert tool. Symbols/sizes, all allocated section
contents/layout (including kern_conf bytes), and CTF label/type/data dumps match.
Both outputs retain .debug_info and .debug_line. ELF/DWARF byte identity is not
claimed. Comparison uses retained artifact blobs because later builds can
replace Bazel's live output symlinks.

`/usr/obj/usr/src/bazel-generic-data-label-20261028` proves a frontend input-file
label override reaches all three objects: zero C compilation actions, three
CTF conversion actions, and qualification-label in each label table. Existing
frontend format-5 settings/targets support this without C/backend changes;
manual and observability notes describe the new input and retained metadata.

Targets are //sys/kern:generic_{config,env,hints}_object. This remains scoped to
amd64 GENERIC's generated data, with WITH_CTF and debug enabled. Full configurable
kernel compilation, vers/vnode/runtime objects, linking/CTF merge, modules,
packages, bootstrap/runtime and whole-system performance gates remain open.
Make remains production/default; no kernel was installed or booted.

### Native vnode runtime object and SDT record parity (2026-10-28)

`//sys/kern:generic_vnode_if_object` now compiles the maintained generated vnode
implementation with GENERIC kernel options, declared source/offset/vnode headers,
normal kernel common-symbol policy, CTF conversion and retained DWARF. The
existing generated-object declarations share conversion policy with config/env/
hints. No DTrace option or assertion is disabled.

`/usr/obj/usr/src/bazel-generic-vnode-r2-20261028/qualification` compares against
a fresh maintained Make vnode_if.o built with the same SDK compiler and host
ctfconvert. All allocated section bytes/layout match, including 38011 machine-code
bytes, data, diagnostic strings and three SDT linker sets. Canonical relocations
match (target symbol identity/value/size and addend, not raw symbol-table indices).
There are 417 defined global symbols, including 166 SDT probes; SDT sets contain
166 probe pointers, 415 argument-type pointers and 5312 bytes of tracepoint
records. Their relocation counts are 166, 415 and 498 respectively. CTF
label/type/data dumps agree and both objects retain debug info/line sections.
Full ELF/DWARF byte identity is not claimed.

The initial machine code and probe records already matched, but assertion strings
contained the Bazel generated-source path. Generated-object compilation now uses
the compiler's -fmacro-prefix-map from each declared source path to its logical
filename (for example vnode_if.c), matching Make diagnostics and avoiding action
root leakage. No source/output bytes are edited by the comparison. Broader debug
path policy still needs qualification as more runtime objects are integrated.

Existing frontend format-5 target selection handles this action chain; manual
and observability notes are updated without a C/backend interface change.
This is compiled-object evidence, not kernel linking, linker-set retention after
link/GC, live probe attachment, vnode execution or audit-policy qualification.
Other runtime objects, kernel/module/package aggregation, bootstrap, runtime and
performance gates remain open. Make remains production/default.

### Kernel version input audit and producer failures (2026-10-28)

The next native kernel prerequisite is vers.c. Inspection of maintained
sys/conf/newvers.sh establishes that -r removes dynamic fields from the rendered
version, but still reads the clock, queries Make for KERN_IDENT/CC, searches host
VCS commands and checkout state, discovers copyright inputs, and increments a
local version counter. Merely invoking -r in a Bazel action would not declare
those dependencies. No native vers.c target or hermetic version action is claimed.

`/usr/obj/usr/src/bazel-newvers-audit-20261028/report.json` records four successful
-r invocations (two fresh directories, twice each) with the same actual SDK
compiler/source and SOURCE_DATE_EPOCH=0. All output hashes match while counters
advance from 1 to 2. Shell traces are retained. This is generator evidence only,
not a kernel build, cross-toolchain test or performance qualification.

The audit also reproduced silent success after failed Make KERN_IDENT/CC queries,
a failed compiler that printed a version banner, and a successful compiler with
no recognizable banner. The maintained script now checks each producer status
before using its output. tools/build/bazel/newvers-errors-test.py exercises those
four errors and a successful fixture. All four errors failed the assertions
before the fix and pass afterward; the positive case passes. These are direct
host Python regression checks, not registered Bazel tests. A separate comparison
using the actual SDK compiler proves unchanged successful vers.c bytes between
the old and fixed script (successful-output-parity.json). Existing output is not
removed on a failed regeneration; callers must honor failure. Counter creation
still occurs before these checks, so this is not an atomic publication change.

Next: introduce a maintained explicit-input generation path shared with Make,
with declared copyright/template/param inputs, configured kernel identity,
compiler identity from the selected execution toolchain, and explicit source
revision/dirty provenance. Avoid substituting a fake Make executable or omitting
provenance to obtain cache hits. Separate reproducible inputs from optional
stamped build identity; qualify changes and no-op rebuilds before native vers.o.
The existing userland newvers -v early exit is unchanged. Frontend review finds
no new user-facing input in this failure-handling fix: build-bsd's maintained
Make backend already propagates a failed recipe. Explicit kernel version inputs
will require frontend/configuration documentation when implemented. Make remains
production/default; complete world/kernel/package/runtime/performance gates stay
open. Push approval remains pending separately.

### Shared explicit kernel version rendering (2026-10-28)

Maintained sys/conf/newvers.sh now supports -e as a standalone option after
variable overrides. Required inputs are PARAMFILE, NEWVERS_COPYRIGHT (source
COPYRIGHT path), NEWVERS_COPYRIGHT_TEMPLATE, NEWVERS_IDENT,
NEWVERS_COMPILER_VERSION and NEWVERS_SOURCE_REVISION. Revision must be supplied;
an explicitly empty value represents an unversioned source archive. The shared
copyright and C rendering code remains authoritative for Make and future Bazel
callers. Quoted/backslash/multiline C-string metadata is rejected, not silently
rewritten. Missing inputs, invalid numeric metadata and output failures fail.

Explicit mode does not query Make, VCS, clock, user/hostname or a version counter.
It does not discover alternate copyright templates. The caller supplies source
provenance and selected compiler identity; this mode does not authenticate those
claims or infer dirty state. Current implicit Make modes retain discovery.
The kernel Make recipe no longer passes an unused trailing KERN_IDENT argument;
legacy generation already queries Make for it. With NEWVERS_ARGS=-e and required
environment inputs, the maintained recipe uses the same explicit renderer.

Evidence: /usr/obj/usr/src/bazel-newvers-explicit-20261028/parity.json records
identical C source and compiled-object bytes for the retained original script,
current legacy -r and explicit -e. The actual SDK clang is used; inputs include
independently collected checkout provenance and compiler banner. Explicit mode
creates no counter. make-explicit.log records maintained GENERIC Make recipe
execution with SYSTEM_DEP empty to isolate generation, matching the reference
C bytes; this is not completion of its kernel prerequisites. The object-byte
comparison is a direct compiler invocation, not a native Bazel vers.o target.

newvers-errors-test.py passes producer failures, explicit input validation,
space-containing paths, unavailable Make/clock commands, changed ambient identity,
explicitly empty revision and failed output writes. Its explicit-mode PATH
contains only awk/sed/cat; input tools remain host tools in this regression test.
Shell syntax and diff whitespace checks pass. The previous -v query continues
to use its early exit; it now also rejects failure of the param.h awk query.

Frontend review: the maintained Make backend is updated in this change, and the
manual describes the boundary. No new build-bsd C option or native Bazel target
is claimed. Next is a declared native action using the selected execution
compiler, source provenance inputs, and config-derived identity. Config identity
must come from configuration processing rather than a duplicate hardcoded
GENERIC string. Register action tests and qualify input invalidation/cache reuse
before adding native vers.o. Full world/kernel/package/bootstrap/runtime and
CPU/memory/disk gates remain open; Make remains production/default.

### Native kernel version action and object (2026-10-28)

//sys/kern:generic_version_source uses the shared newvers.sh -e renderer with
explicit param.h, copyright/template, config-derived identity and source
revision inputs. Native awk/sed/cat are execution tools with declared libraries;
SDK Python/shell and selected C toolchain remain bootstrap dependencies. The
selected C toolchain compiler is obtained through cc_common and its declared
input closure, then queried for its banner; no ambient CC/Make/VCS is consulted.
This is declared-input action evidence, not a fully sandboxed/self-hosted build.

config -i exposes the actual parsed identity, processing includes and overrides
without generating build files or reading Makefile templates. The config action
retains its existing output directory and adds a separate identity output group;
//sys/amd64/conf:generic_identity exposes it. No duplicate GENERIC identity or
Makefile scraping was added. The normal 200 generated configuration files match
the earlier Make reference byte-for-byte. The identity query rejects -m combined
with -i and has direct native-tool include/override/error checks.

The format-5 build-settings string //tools/build/bazel/config:kernel_source_revision
is required when selecting the version target; its empty default causes analysis
to fail. It must identify the source checkout/revision or a named source archive.
The caller is responsible for accurate provenance. It is not a signature or an
automatic dirty-tree detector. Existing version_branch also applies here. The
frontend accepts these through its maintained settings mechanism; no new C API
is needed. Automatic provenance acquisition/publication validation is still open.

//sys/kern:generic_vers_object compiles this source with GENERIC kernel flags,
CTF conversion and retained DWARF. Evidence under
/usr/obj/usr/src/bazel-generic-version-object-20261028/qualification includes a
retained comparison script, Make log, CTF dump, config-query checks and reports.
The maintained Make vers.o recipe uses the same explicit version inputs and
SDK compiler; SYSTEM_DEP is empty to isolate this object. Source bytes, all
allocated section contents/layout, global symbol names/sizes and CTF labels/types/
data agree. Both objects retain debug info and lines; complete ELF/DWARF byte
identity is not claimed. No kernel was linked or loaded.

The first frontend build caught a missing explicit export of kernel_version.py;
that dependency was declared. Successful generation is retained in
bazel-generic-version-r2-20261028; compiled output in the object run above.
bazel-generic-version-repeat-20261028 executes zero spawns with identical hashes.
bazel-generic-version-revision-20261028 changes only the explicit revision input
and executes exactly BSDKernelVersion, its CppCompile, and BSDCtfConvert; identity
hash is unchanged. The final config query refinement is built in
bazel-generic-version-r3-20261028 and produces the same captured artifacts.
These runs have no registered Bazel tests selected; generation invokes the actual
native tools, with additional direct checks. They are not full runtime or system
performance gates. Publication still requires the original combined repository,
hardware/kernel identity and production-world checks.

Complete programs/libraries, world, kernel runtime and link, ALL base modules and
drivers, pkgbase integration and CPU/memory/disk qualification remain required.
Modules must preserve generated interfaces, debug/CTF/DTrace, dependency metadata,
installation and packaging. Ports/third-party module Make support remains required.
Make stays production/default. This checkpoint does not mark any whole-system
migration gate complete.

### Native nullfs module objects (2026-10-28)

The next module path begins with //sys/fs/nullfs:generic_module_object_files.
All three maintained sources (null_subr.c, null_vfsops.c, null_vnops.c) compile
with declared kernel/vnode/offset/VM/CK headers, GENERIC options, KLD_MODULE and
KLD_TIED, native CTF conversion and preserved DWARF. The existing amd64 GENERIC
flags/header dependencies moved to tools/build/bazel/kernel_amd64.bzl so kernel
and module objects share policy; this remains explicitly scoped to amd64 GENERIC,
not all architectures/configurations. No module is installed or loaded.

/usr/obj/usr/src/bazel-nullfs-objects-20261028 contains the maintained frontend
build and captured objects. Its qualification/verify.py compares with the real
Make module recipe under /usr/obj/usr/src/bazel-nullfs-20261028. The reference
uses the same SDK compiler, MODULE_TIED=yes, DEBUG_FLAGS=-g, WITH_CTF=yes and the
existing GENERIC KERNBUILDDIR. Make successfully builds the full reference module;
Bazel currently builds only its objects. Host ctfconvert/ctfmerge are Make reference
tools. The native action uses the Bazel-built converter.

The initial object comparison caught different diagnostic __FILE__ paths. Make's
PREFIX_SYSDIR alone does not activate source path rewriting; the final reference
explicitly enables WITH_REPRODUCIBLE_PATHS=yes and PREFIX_SYSDIR=sys, matching
Bazel's logical source path. The three reference runs and logs are retained.
No output strings, machine code or comparison payloads are rewritten/filtered.
This qualifies the stated reproducible-path profile, not byte identity against
Make's default absolute diagnostic paths or complete DWARF byte identity.

All three objects have identical allocated section type/flags/size/alignment and
bytes, canonical allocated relocations, and defined global symbols/sizes. CTF
label/type/data dumps match; .debug_info and .debug_line are retained. null_subr
retains four nullfs SDT probe symbols plus the provider: 4 probe pointers, 7
argument pointers, 12 tracepoint relocation records. null_vfsops retains 3
module-metadata relocation records. Full source/object details are in parity.json.
These are object preservation checks, not linked-module or live instrumentation
qualification; no host module loading is authorized or performed.

Frontend review: existing format-5 targets and kernel_ctf_label select the objects;
no frontend C/backend interface change is required. The manual and observability
log describe exact scope. Next is a reusable module link/export path preserving
ldscript.kmod.amd64 page protection layout, relocatable linking, CTF merge,
EXPORT_SYMS, split debug and installation metadata. The maintained export AWK
spawns nm through a shell and does not currently check its pipeline close status;
its error propagation needs review before adopting it into the native path.
No claim is made that producing these objects completes nullfs, all base modules,
drivers, kernel/world aggregation, pkgbase, runtime or performance gates.
Make remains production/default.

### Checked module symbol-policy inputs (2026-10-28)

Before native module linking adopts the maintained export/prefix transforms,
their hidden nm subprocesses have been removed. sys/conf/kmod_syms.awk and
kmod_syms_prefix.awk now take a previously checked nm text listing as their first
argument. The export transform accepts modname for diagnostics. The maintained
kmod.mk runs nm explicitly (-g for exports, all symbols for prefixing), checks
its recipe status, and captures/checks AWK output before invoking objcopy through
xargs. The temporary ${KMOD}.symbols file is in CLEANFILES. Inspection found no
other maintained consumers requiring adaptation. No symbol policy is substituted
with a hand-maintained symbol list or a second parser.

The earlier scripts returned success for missing nm and for nm that emitted
partial output before failing. Adding close(command) checks alone did not fix it:
this one-true-awk implementation reports pclose failure, not the child's nonzero
exit status (contrib/one-true-awk/run.c closefile). That attempted approach was
replaced, not treated as passing. The new transform performs no process execution
and rejects a missing listing before emitting options. Empty valid listings are
allowed; existing missing-export warning semantics remain unchanged.

A real nullfs Make relink with an injected nm that prints one partial symbol and
exits 42 now fails. That qualification also found a failed .ko.full survived in
the standalone module build, because it did not inherit source local.sys.mk's
.DELETE_ON_ERROR. kmod.mk now declares that same standard Make behavior so failed
linked/transformed targets are removed. This affects standalone/ports module
builds as well; it does not install or load anything.

Evidence in /usr/obj/usr/src/bazel-kmod-symbol-errors-20261028 contains retained
old helpers, check-make.py, failure/success logs, before.ko.full and reports.
The failed build returns 2 and deletes the module target. The subsequent real
nullfs build is byte-identical to the pre-change full module. On null_subr.o,
both helper outputs preserve the old policy (11 export-localization/removal
options, 39 prefix-renaming options). The maintained direct host regression
kmod-symbol-errors-test.py checks explicit listing behavior with NM/PATH
unavailable and rejects missing input with no partial options. These are not
registered Bazel tests and do not establish native module-link completion.

Frontend review: kmod.mk is the maintained backend used for Make/ports; it is
updated with its helpers and tests in this change. No new frontend C option or
Bazel target is needed for this failure-propagation correction. Native module
linking should now declare nm listings as action outputs and reuse these pure
AWK transforms. Linking, CTF merge, symbol editing, split debug, installation and
pkgbase qualification remain next; Make remains production/default.

### Native nullfs module link, exports, debug and install manifest (2026-10-28)

//sys/modules/nullfs:generic_module now produces an amd64 GENERIC relocatable
nullfs.ko. Separate declared actions link the ordered native CTF objects with
ldscript.kmod.amd64 and elf_x86_64_fbsd, merge native CTF with retained DWARF,
produce a checked nm listing, run maintained kmod_syms.awk on it, apply the
component's declared export symbols, and split debug information. generic_full
and generic_debug expose nullfs.ko.full and nullfs.ko.debug. The linker uses a
Bazel-managed response file; export application uses a quoted LLVM response file
to avoid argv limits, with no shell/xargs. The export runner rejects unexpected
options and propagates objcopy failure. SDK linker/nm/objcopy/Python are still
bootstrap inputs; native awk, ctfmerge and its libraries are declared execution
tools. These are not self-hosted or fully sandbox-qualified builds.

bsd_ctf_merge now supports the same explicit CTF-label setting and debug retention
as object conversion, preserving existing callers' defaults. The new module link
and export rules are reusable declared actions; this candidate qualifies the
amd64 relocatable format and explicit export list only. Shared module formats,
PREFIX_SYMS and further module configurations remain open.

Evidence: /usr/obj/usr/src/bazel-nullfs-link-20261028 and its qualification scripts
compare captured artifacts with the maintained Make reproducible-path reference
from the previous checkpoint. Code/data and allocated-section layout match,
except .note.gnu.build-id; canonical allocated relocations and exported global
symbols match. Only null_vnodeops and null_vnodeops_no_unp_bypass remain exported.
CTF label/type/data dumps agree. Text and read-only sections are 12288 and 4096
bytes, preserving the maintained linker script's page boundaries. Build IDs
are valid SHA1 GNU notes and identical across the native full/runtime/debug
family, but differ from Make. DWARF/complete ELF byte identity is not established.

The userland debug checker correctly rejected the retained module symbol table;
it now has an explicit --module mode requiring that loader table and relocatable
or shared ELF, while still rejecting embedded debug data in the runtime file.
The native debuglink name/CRC passes; corrupt debug data and using default
userland mode on the module are rejected. Native kldxref reads the native and
Make modules and emits identical 64-byte linker.hints. No module was loaded.

//sys/modules/nullfs:install_manifest declares module/debug destinations and
package=kernel tags. Format-5 settings kernel_directory (default /boot/kernel)
and kernel_debug_directory (default /usr/lib/debug) select roots; an empty debug
root places debug beside the module. bsd_install_file supports ordered string
setting prefixes without changing existing static callers. The initial 0555
mode assumption was caught by the Make install comparison and corrected to
0444. NO_ROOT alone in the standalone module recipe did not activate install -U;
the successful staged reference queries IMAKE_INSTALL from maintained
Makefile.inc1, as install-reference.py does, and uses that actual contract.
All staging stays under /usr/obj, without host installation or ownership changes.
Paths, root/wheel ownership, modes and tags match the resulting METALOG.

bazel-nullfs-link-r2-20261028 qualifies the final linker response file; downstream
output hashes remain unchanged. bazel-nullfs-install-r2-20261028 executes zero
spawns. bazel-nullfs-install-override-20261028 sets kernel_directory to
/boot/qualification and an empty debug root; it changes the manifest, retains
all module/debug hashes and executes zero spawns (native kldxref is also a
selected, already cached target). Artifact sizes: native/Make runtime 76240/76240,
full 459736/458160, debug 439632/438056 bytes. These are artifact sizes, not peak
memory, disk I/O or system performance results.

Frontend review: the normal maintained format-5 target/settings interface handles
all actions and install roots; C/backend interface changes are unnecessary.
Manual/observability docs are updated. Direct host regression tests cover symbol
listing errors and malformed export options/failed objcopy; the qualification
runs select no registered Bazel tests. Package archives, full kernel/module
aggregation, loader/kernel compatibility, module load/unload, filesystem runtime,
live SDT/audit behavior and system CPU/memory/disk gates remain open. No host
install, module load or reboot occurred; Make remains production/default.

### Correction: module CTF association regression (2026-10-28)

The earlier Make/Bazel equality checks did NOT establish correct CTF symbol/type
associations. A new registered Bazel target,
//tools/test/construction:nullfs_artifacts_test, now checks the actual linked
module/debug family with declared native kldxref/ctfdump and the maintained debug
checker. It checks exports, page layout, allocated-data preservation, debug CRC
and corruption rejection, SDT metadata, CTF associations, kernel-tied dependency
and hints. It reuses the module audit runfiles adapter and is local/no-cache
because host shell/SDK Python loader qualification remains incomplete.

THIS TEST CURRENTLY FAILS on ctf_type_null_vnodeops. Both Make and the native
pipeline merge CTF before objcopy localizes selected global symbols. Localization
reorders the ELF symbol table without repairing CTF's order-based object/function
associations. The module dump associates null_vnodeops with STRUCT sdt_provider
and null_vnodeops_no_unp_bypass with STRUCT sysctl_oid, instead of STRUCT vop_vector.
Some SDT symbols are likewise wrong. Earlier equality and live-loader metadata
checks remain evidence of equality/metadata only, not valid CTF or live probes.
Treat the native module as an incomplete candidate; do not publish it as qualified.

The first test expectation incorrectly counted the zero-initialized queue link
inside sdt_tracepoint as a relocation. The test policy now distinguishes byte
size from relocation count (four 32-byte records, twelve relocations). Comparing
full versus stripped ctfdump text also initially compared printed ELF symbol
indices; strip-debug removes STT_FILE entries and changes those indices normally.
The test now compares exact CTF section bytes plus ordered symbol/type associations,
and independently checks expected structure names, retaining strict semantic
checks rather than rewriting module data. Exception paths mark reports failed.

A prototype moved CTF emission after localization and enabled ctfmerge's existing
-f localized-global matching. It passed nullfs (bazel-nullfs-test-r3-20261028), but
an independent two-translation-unit fixture exposed an unsafe ambiguity: a global
volatile int and a static volatile long sharing the same name were BOTH assigned
the long type. Source inspection shows matching_iidesc can prefer the apparent
static-file match after localization loses ownership context. The prototype was
rejected and removed from both kmod.mk and native module/CTF rules. No heuristic
matching fix is committed. The maintained Make pipeline remains unchanged here.

Evidence: /usr/obj/usr/src/bazel-nullfs-ctf-order-20261028 includes before/after
ctfdumps and collision/{a.c,b.c,*.o,ctf.txt}. The final current-code failure is
/usr/obj/usr/src/bazel-nullfs-ctf-regression-20261028/qualification, containing
copied test log/XML and failed result.json independent of mutable Bazel symlinks.
The passing prototype run is NOT current qualification. The regression is
intentionally failing, not skipped, marked expected-pass or suppressed.

Next: retain exact original-to-transformed ELF symbol identity when rebuilding
CTF associations. This needs explicit pre-transform metadata, not name-only fuzzy
matching; duplicate local/global names must be tested. Preserve both object and
function associations, export policy, debug metadata and all architecture rules.
Use the same robust transformation for maintained Make and native actions, then
rerun the real module test, collision fixtures and Make/native parity. PREFIX_SYMS
and other symbol transforms need the same review. Registering tests revealed a
correctness gap that simple Make parity missed.

Frontend review: existing format-5 targets/tests select this test and propagate
its failure. No C interface change is needed; docs/manual/observability record
the failing gate. BIP stays out of scope, no module was loaded, no host upgrade
occurred, and Make remains production/default. Complete migration and module
qualification remain active, unfinished work.

### CTF localization reproduction expanded (2026-10-28)

The maintained `tools/build/bazel/tests/ctf/localization-audit.py` diagnostic
now reproduces incorrect data **and function-return** types with exported,
localized and same-name static symbols. Both installed-tool and Bazel-native
runs pass their source-type baseline and fail both the current ordering and
the rejected fuzzy-merge alternative. Native evidence is retained at
`/usr/obj/usr/src/ctf-localization-native-r2-20261028`. This is additional failure
evidence, not a fix or module qualification. See `tests/ctf/LOCALIZATION.md`
under the Bazel tooling for scope and next implementation requirements.

### CTF-aware objcopy candidate (2026-10-28, work in progress)

The uncommitted LLVM ELF objcopy candidate preserves original symbol indices
and rewrites `.SUNW_ctf` object/function records after symbol transformations.
New symbols receive unknown-type entries. It also retains the CTF section's
link to the symbol table through debug stripping and section renumbering.
It does not use fuzzy name matching or change the module link/merge ordering.

An isolated binary was compiled with the maintained Make compilation flags
and linked with retained Make driver/library objects. No SDK file or installed
program was replaced. Evidence and commands are under
`/usr/obj/usr/src/ctf-objcopy-candidate-20261028`; `candidate-inputs.json` records
source and final binary hashes. This is diagnostic integration, not a freshly
qualified toolchain build.

- Final candidate: all 34 maintained static nullfs audit checks pass at
  `/usr/obj/usr/src/ctf-nullfs-candidate-r4-20261028/audit/result.json`, including
  the added CTF-to-symbol-table link check. No module was loaded.
- Nine additional diagnostic checks pass at
  `/usr/obj/usr/src/ctf-transform-candidate-r2-20261028/result.json`: copy,
  localization, rename, removal, addition, and rejection of invalid magic,
  version, offsets and compressed data. The initial candidate assertion during
  debug splitting and map-sentinel error during symbol addition were fixed;
  the final reports are from subsequent runs.
- The original collision fixture baseline and production transform passed
  with an earlier candidate at `/usr/obj/usr/src/ctf-localization-candidate-20261028`.
  `localization-audit.py --mode merge-then-localize` selects this path without
  invoking the separately rejected fuzzy-merge alternative.

Still required: move the additional transform/malformed cases into maintained
regression coverage; check version 2, byte order, uncompressed CTF, dynsym-linked
data, removal/update of CTF itself, and stripping without a symbol table;
review allocation bounds and metadata preservation; build the changed LLVM
through maintained targets; qualify a new SDK and rerun the native Bazel gate
plus incremental/cache checks. Measure costs before making performance claims.
The current SDK/Bazel nullfs target still uses the old objcopy and is not
qualified. Keep the source candidate uncommitted until this review is complete.

Frontend assessment: no new frontend option is required. The normal SDK
input/receipt must identify the rebuilt objcopy and its actual runtime closure;
do not replace a hashed SDK binary in place. Format-5 test selection remains
the integration path. Full kernel/modules/world/pkgbase qualification remains
open, and Make remains the production default.

### Maintained LLVM build and CTF format qualification (2026-10-28)

The CTF candidate now builds through the normal `make -C lib/clang/libllvm
-j16 all` and `make -C usr.bin/clang/llvm-objcopy -j16 all` targets. Outputs
remain under `/usr/obj`; nothing was installed. Dynamic testing explicitly
selects the newly built libprivatellvm, and the retained format report records
its resolved path and SHA256 plus all other ldd-resolved dependencies.

The maintained `tests/ctf/format-audit.py` passes **61 checks**, covering CTF v2
and v3, compressed and uncompressed payloads, little- and big-endian CTF
serialization, symbol localization/renaming/removal/addition, unknown added
function types, variadic records, label/type/string preservation, section links
and unrelated added sections. It independently checks little-endian fixture
types using native ctfdump. Big-endian CTF is embedded in an amd64 ELF fixture;
this does not qualify a big-endian kernel or architecture. Evidence:
`/usr/obj/usr/src/ctf-format-maintained-r3-20261028/result.json`.

All **34 static nullfs checks** also pass with the maintained tool/library:
`/usr/obj/usr/src/ctf-nullfs-maintained-20261028/audit/result.json`. This is a
real module artifact check without module loading, not a fresh Bazel SDK run.

Review corrections: CTF link preservation now applies only to explicitly
rewritten CTF sections; unrelated owned sections do not acquire a symtab link.
Version-2 function-section records are packed (unlike function-type records);
per-record four-byte rounding was wrong and has been removed. Record views now
reference the retained input buffer instead of allocating one buffer per symbol.
Non-symbol section links are rejected, while dynsym-linked CTF is left to its
unchanged dynamic symbol table. Dynsym-specific qualification is still open.

The incremental LLVM library build reported 9.65s wall time and 1,322,524 KiB
maximum RSS; retain the full `/usr/obj/usr/src/ctf-maintained-build-20261028`
logs for CPU and block-I/O counts. These are build measurements, not an old/new
objcopy or whole-system performance comparison.

Frontend assessment: existing SDK staging currently selects bootstrap tools
from objtop/tmp. Do not copy this dynamic tool over a frozen SDK or rewrite its
receipt. Rebuild/stage the appropriate bootstrap tool and generate a fresh SDK
through maintained helpers, then rerun the format-5 Bazel nullfs test and cache
checks. The source candidate remains uncommitted pending that integration and
the remaining edge-case/resource review.

### Bootstrap SDK and native Bazel module gate (2026-10-28)

The maintained `make -j16 _cross-tools` stage completed, including normal
staging under `/usr/obj/usr/src/amd64.amd64/tmp`; no host installation occurred.
`libmd-plan.py` and `libmd-stage-tools.py` generated a **fresh** SDK and receipt
at `/usr/obj/usr/src/bazel-ctf-sdk-20261028`, preserving the old SDK unchanged.
The receipt identifies static objcopy SHA256
`4af3d1fe4ad904bfb564bca6b316d9b733115d9a2617d023023607ab95d4daa5`, with no
dynamic execution dependencies. No receipt was patched or SDK tool replaced
in place. This remains a prepared-SDK migration bridge, not Bazel bootstrap
completion or a hermeticity claim.

The normal `build-bsd bazel-test` format-5 workflow now passes
`//tools/test/construction:nullfs_artifacts_test` with all 34 static module
checks. Evidence: `/usr/obj/usr/src/bazel-nullfs-ctf-fixed-20261028`, including
retained `qualification/result.json`, frontend receipt, artifacts and test
reports. Export localization/debug splitting executed with the new SDK.
The exact frozen SDK also passes the maintained 61-check CTF format suite at
`/usr/obj/usr/src/ctf-format-sdk-20261028/result.json`.

A repeat frontend run at
`/usr/obj/usr/src/bazel-nullfs-ctf-fixed-repeat-20261028` has identical selected
artifact hashes and zero spawned actions. It reused the successful test result;
it is **not** a second execution of the test. `qualification/cache-check.json`
retains the comparison and event metadata. Extra diagnostics confirmed that
full symbol stripping and explicit CTF-section removal complete successfully.

Frontend assessment: existing build-bsd input selection, maintained cross-tools
and SDK receipt generation were sufficient. No new C frontend option or
one-off build backend was needed. The initial kernel source revision input was
updated to the actual HEAD plus dirty state. Code remains under review and
uncommitted; remaining work includes broader consumer/edge-case tests, tool
performance comparison, and then module expansion. No kernel was loaded, and
full world/kernel/modules/pkgbase/runtime/performance gates remain open.

### CTF symbol-preservation fix ready for commit (2026-10-28)

The reviewed fix defers CTF decoding when eligible symbol identities/order are
unchanged. This avoids decompression on ordinary copying and debug stripping
and permits copying/removing opaque unsupported CTF; reordering such CTF still
fails. The maintained format audit now passes **65 checks**, including those
behaviors. Final bootstrap and frozen SDK objcopy have identical SHA256
`ef5e69b925fd66c30a34376a8fb366ae4487030d1eadf54f471d257236bb7eb3`.
The final fresh SDK is `/usr/obj/usr/src/bazel-ctf-lazy-sdk-20261028`.
The normal build-bsd Bazel test again passes all **34 nullfs checks** at
`/usr/obj/usr/src/bazel-nullfs-ctf-lazy-20261028`; its JSON is retained under
`qualification` independently of mutable Bazel symlinks.

Performance evidence uses 100 alternating warm-cache invocations per tool on
the same retained 459,736-byte nullfs input, via the maintained
`tests/ctf/objcopy-benchmark.py`:

| Operation | Old median wall | Fixed median wall | Old/fixed peak child RSS | Old/fixed output bytes |
|---|---:|---:|---:|---:|
| Copy | 2.509 ms | 2.503 ms | 7,256 / 15,304 KiB | 459,736 / 459,736 |
| Export localization | 2.546 ms | 5.114 ms | 19,460 / 22,008 KiB | 459,736 / 460,568 |

Copy outputs are byte-identical. Export outputs intentionally differ: the old
one has wrong types, while the corrected CTF is rewritten/recompressed. Each
measured batch reported zero block inputs and 400 block outputs; these OS
counters are not physical disk throughput. RSS varies between samples/batches
and is not a whole-build memory result. Immediate st_blocks values can reflect
deferred filesystem allocation and are retained as observations, not durable
disk-space claims. Raw CPU, RSS, timing, I/O, sizes and hashes are retained at
`/usr/obj/usr/src/ctf-objcopy-copy-perf-20261028` and
`/usr/obj/usr/src/ctf-objcopy-export-perf-20261028`. No whole-system performance
claim follows from this small input.

This supersedes the earlier uncommitted-candidate status for the reviewed CTF
fix. The manual now reflects its fresh-SDK static qualification. Existing
frontend/backends were sufficient; no build-bsd C option changed. Full kernel,
all modules, other architectures, runtime and publication qualification remain
open. The separately logged libctf v2 reader discrepancy and broader consumer
coverage remain follow-up work; no test was suppressed or expected to pass on
corrupt metadata.

## 2026-10-28: shared GENERIC module rules and fdescfs

`amd64_generic_module.bzl` now shares the qualified nullfs compilation,
CTF merge, explicit export policy, debug split, and installation metadata.
The names and settings remain compatible with existing nullfs callers.
`fdescfs` declares its two C sources and headers and uses the same rules,
with the maintained Make default EXPORT_SYMS=NO (empty export list).
This is specifically amd64 GENERIC tied-module support.

The maintained `build-bsd bazel-test` format-5 input selected both modules
using 16 jobs. Evidence: `/usr/obj/usr/src/bazel-fdescfs-20261028`, with
Make reference `/usr/obj/usr/src/bazel-fdescfs-make-20261028`.
`qualification/comparison.json` records matching allocated section types,
flags, sizes, alignment and bytes (NOBITS size only, build-id excluded),
and matching raw SUNW CTF. Runtime/debug identity and debuglink CRC pass.
The existing nullfs artifact test reused its passing cached result; this
was not a fresh test execution. No module was loaded. Relocation/symbol
comparison, installation parity, and fdescfs runtime qualification remain
to be completed before claiming this module fully qualified.

Frontend review: existing explicit target selection and kernel installation
settings cover these additions; no new C frontend option or publication
policy is required. Make remains the production/default build. Next: finish
fdescfs qualification, then unionfs, tmpfs and pseudofs.

### Follow-up: fdescfs symbols/install and unionfs

The fdescfs runtime symbol and relocation listings now match Make exactly.
`qualification/symbols-relocations.json` records the comparison with both
raw readelf listings. `installation-comparison.json` records matching paths,
owner/group/mode/type and package/debug tags against Make's staged METALOG.
The first standalone install attempt used Make's `/boot/modules` default
and failed because that staging directory was absent. The corrected
comparison explicitly supplies `KMODDIR=/boot/kernel`, as the maintained
kernel build does through `MKMODULESENV` in `sys/conf/kern.pre.mk`.
No installed file hashes are claimed equal: debug information/build-id
differ between build systems. No host files were installed.

Unionfs now declares its three C sources and MAC-framework/DDB header
dependencies. The shared GENERIC rules build its runtime, full, debug and
installation manifest targets through `build-bsd bazel-test`. Evidence is
`/usr/obj/usr/src/bazel-filesystem-modules-20261028/qualification`, with
Make reference `/usr/obj/usr/src/bazel-unionfs-make-20261028`.
Code/data sections (excluding build-id), raw CTF, complete symbols and
relocations match; the separate debug file and CRC pass. SDT provider,
probe, argument-type and tracepoint sections match, including both copy-up
probes. The nullfs test result was cached.

Remaining: unionfs staged installation comparison, incremental/cache checks
for the new modules, module runtime tests, and broader kernel qualification.
Frontend review remains unchanged: the maintained format-5 target selection
and kernel-directory settings suffice; no additional frontend option is
needed. These are native module artifacts, not a complete kernel build.

### 2026-10-28: installation/cache closure and next modules

Unionfs's staged Make install now matches Bazel paths, ownership, permissions,
file types and package/debug tags. Evidence: filesystem-modules qualification
`installation-comparison.json`. An identical frontend invocation retained
identical artifact hashes and an empty spawned-action log at
`/usr/obj/usr/src/bazel-filesystem-modules-repeat-20261028`; the nullfs test
result was reused, not executed again. This proves unchanged-input reuse,
not invalidation correctness under source/header/configuration edits.

Native tmpfs and pseudofs definitions have been added, using option headers
extracted from actual GENERIC config outputs, explicit source lists and
pseudofs's maintained 11-symbol export list. Both build through the existing
format-5 frontend. No new frontend C option is necessary.
Evidence: `/usr/obj/usr/src/bazel-tmpfs-pseudofs-20261028/qualification`,
with Make references `/usr/obj/usr/src/bazel-{tmpfs,pseudofs}-make-20261028`.

**Not yet qualified:** debuglink and symbol comparisons pass, but rodata and
relocation comparisons fail for both; tmpfs raw CTF also differs. Diagnostic
strings contain virtual-header paths (pseudofs_internal.h, tmpfs.h and
vm_pager.h), unlike Make's source paths. Correct this through compiler path
mapping derived from declared header locations, not rewriting source or
output bytes or hardcoding a particular Bazel output-root spelling. Inspect
the CTF difference independently. Machine-code bytes and SDT section bytes
currently match; that does not waive the differences. Neither module was
loaded, and their install/cache/runtime qualification remains outstanding.

### Resolved: header identity and CTF ordering

The earlier tmpfs/pseudofs mismatches above are resolved. Source headers in
`sys/vm`, `sys/fs/tmpfs` and `sys/fs/pseudofs` now expose their existing
source include root through ordinary cc_library includes and declared hdrs,
rather than redundant virtual aliases. No Bazel output-directory spelling
is embedded, no output bytes are rewritten, and header dependencies remain
declared. This resolved rodata and relocation differences.

Tmpfs's individual four objects already had identical raw CTF to Make.
`ctfmerge.c` sorts its input paths before merging; the ordinal directory
before each basename changed merge order and type IDs. The CTF conversion
rule now places basename before its collision-disambiguating index, retaining
distinct equal-basename inputs while restoring Make's basename ordering for
these modules. This resolved tmpfs's raw CTF mismatch.

Final evidence: `/usr/obj/usr/src/bazel-tmpfs-pseudofs-ctf-20261028/qualification`.
The tmpfs, pseudofs, fdescfs and unionfs comparisons all pass for full runtime
symbol and relocation listings, text/data/rodata bytes and raw SUNW CTF.
All four debug-file identity/debuglink CRC checks pass. Raw comparison dumps
and comparison.json are retained. Nullfs's existing artifact test result
was reused from cache, not rerun. These changes continue to use the existing
frontend format-5 inputs; no frontend C option or publication-policy change
is required.

Outstanding for tmpfs/pseudofs: staged installation metadata, unchanged-input
and selective invalidation checks, live module behavior/probes and broader
performance qualification. CTF output layout changes other users of the
shared conversion rule; whole-world requalification remains required.

### Five-module installation and cache checks

Tmpfs and pseudofs now also match Make's staged installation paths,
owner/group/mode/type and package/debug tags. Staging used the maintained
IMAKE_INSTALL contract with NO_ROOT and kernel-build KMODDIR; nothing was
installed into the host. The comparison is retained in
`/usr/obj/usr/src/bazel-tmpfs-pseudofs-ctf-20261028/qualification/installation-comparison.json`.

The identical frontend repeat at
`/usr/obj/usr/src/bazel-five-modules-repeat-20261028` produced identical
artifact hashes and an empty spawned-action log. The existing nullfs test
result was cached. A separate explicit format-5 input changed kernel_directory
to `/boot/qualified-test-kernel` and kernel_debug_directory to empty. All five
module manifests correctly place runtime and debug files together at that
destination, with unchanged full/runtime/debug payload hashes and no spawned
compile/link/tool processes. Metadata is produced by Bazel write actions; an
empty spawned-action log does not mean those metadata actions did not run.
Evidence: `/usr/obj/usr/src/bazel-five-modules-install-setting-20261028` and
`qualification/cache-settings-check.json` in the original CTF qualification.

Frontend assessment: maintained format-5 target and installation settings
worked as designed, so no C frontend/backend change is needed for this check.
This closes unchanged-input reuse and install-setting invalidation for the
five selected modules. Source/header invalidation, live module behavior,
whole-system packaging, and performance/resource qualification remain open.
Next expansion candidate inspected: geom_nop (single g_nop.c source with
GEOM headers); it has not yet been converted or qualified.

### GEOM nop/gate native modules

Native `geom_nop` and `geom_gate` now use the shared GENERIC module build
rules with explicit C sources and GEOM headers. The existing userland
geom_nop header target is retained. GEOM kernel headers expose the original
source include root, retaining declared inputs without virtual-path leakage.
The maintained frontend format-5 targets built both with 16 jobs; no new
frontend C option, signing or publication change is required.

Evidence: `/usr/obj/usr/src/bazel-geom-modules-20261028/qualification/comparison.json`
and retained raw readelf dumps. Make references are under
`/usr/obj/usr/src/bazel-{geom_nop,geom_gate}-make-20261028`. Both runtime
symbol/relocation listings, text/data/rodata and raw SUNW CTF match Make.
Separate debug-file identity and CRC pass. Staged Make metadata matches
paths, ownership, permissions, type, package and debug tags. No host module
load or installation occurred. These comparisons do not establish live
GEOM I/O behavior, cache invalidation or disk/memory performance.

This increment has seven native module builds: nullfs, fdescfs, unionfs,
tmpfs, pseudofs, geom_nop and geom_gate. This is a batch count, not an
authoritative total for the repository or full kernel/module completion.
The broader module inventory, hardware/drivers, source/header invalidation,
runtime, full-world/kernel packaging and performance gates remain open.

### GEOM Linux LVM, multipath and zoned

Added explicit native module targets for geom_linux_lvm, geom_multipath and
geom_zoned using the shared GENERIC rules. Existing multipath/zoned userland
header targets are preserved. Maintained format-5 frontend selection builds
the three modules with 16 jobs; no new frontend C option or publication
policy is needed.

Evidence: `/usr/obj/usr/src/bazel-geom-expanded-20261028/qualification`,
including raw comparison dumps and comparison.json. Make references are
`/usr/obj/usr/src/bazel-geom_{linux_lvm,multipath,zoned}-make-20261028`.
All three match Make's complete runtime symbol and relocation listings,
text/data/rodata and raw CTF. Debug-file identity/debuglink CRC checks pass.
Staged metadata matches paths, ownership, permissions, type and package/debug
tags. Multipath's SDT probe, argument-type and tracepoint section bytes also
match. Modules were neither loaded nor installed into the host.

The current conversion batch now contains ten module builds with artifact
comparisons. Live storage behavior, failover, zoned-device semantics,
source/header invalidation, broad configuration/architecture support and
resource/performance qualification remain unproven. This does not qualify
a whole kernel or all modules/drivers, and Make remains the production path.

### GEOM mirror and netdump header dependencies

Added native geom_mirror with both maintained C sources. The first sandbox
build correctly rejected a missing net/if.h dependency from geom_disk.h ->
sys/disk.h. The disk header's netdump interface also requires netinet/in.h,
net/vnet.h and netinet6/in6.h. These are now explicit cc_library header
dependencies in a separate GEOM disk_headers target, without disabling
netdump or exposing undeclared source files. Existing userland header targets
are retained.

The second frontend build succeeds; evidence is
`/usr/obj/usr/src/bazel-geom-mirror-r2-20261028/qualification`. Runtime symbol
and relocation listings, text/data/rodata and raw CTF match the Make reference
at `/usr/obj/usr/src/bazel-geom_mirror-make-20261028`. Debug identity and CRC
pass. Staged install parity and incremental checks are pending for this module,
as are live mirror/failover/resync and performance checks. This is the eleventh
module in the current artifact-comparison batch, not whole-kernel completion.

The existing maintained frontend format-5 selection handles these targets;
no C frontend, signing or publication changes are required. Next: mirror
installation parity, then GPT using the native g_part_if generator; GEOM label
requires its maintained opt_geom generation and broader filesystem headers.

### GPT native interface consumer and mirror install closure

Mirror installation metadata now matches maintained Make; evidence is its
r2 qualification/installation-comparison.json. No host installation occurred.

The native GPT module consumes `g_part_if.h` from the existing declared
makeobjops.awk action over g_part_if.m. No copied/generated substitute is
checked in. The first sandbox compile found missing nested disk-format
headers; sys/sys:kernel_headers now declares disk/*.h alongside its direct
headers. GPT's maintained Make list also generates bus_if.h/device_if.h;
the inspected GPT translation unit consumes neither, so those are not added
as unrelated compilation dependencies. Their native generators already exist.

Evidence: `/usr/obj/usr/src/bazel-gpt-module-r2-20261028/qualification`,
with Make reference `/usr/obj/usr/src/bazel-geom_part_gpt-make-20261028`.
GPT symbols, relocations, text/data/rodata and raw CTF match Make; debug
identity/debuglink CRC pass. Staged install metadata matches both runtime and
debug paths, ownership, mode, type and tags. The generated interface is NOT
byte-identical: one provenance-comment line uses the input basename instead
of Make's absolute /usr/src path. interface.diff and interface-comparison.json
retain and narrowly verify that sole difference; compiler inputs are not
modified by the comparison.

The current batch has twelve native module builds with artifact comparisons.
GPT runtime partition operations, live kernel integration, invalidation and
performance remain open. Existing format-5 frontend targets and inputs cover
this addition; no C frontend/backend publication change is required. Make
remains the production/default path. Next: expand partition schemes using
this shared generated interface, then GEOM label's options/header inputs.

### BSD, EBR and MBR partition modules

Added native geom_part_bsd, geom_part_ebr and geom_part_mbr. BSD explicitly
includes geom_bsd_enc.c; EBR consumes opt_geom.h extracted from the actual
GENERIC configuration. All three reuse the native g_part_if interface action.
Together with GPT this covers module builds for the four schemes selected by
the maintained sys/modules/geom/geom_part/Makefile. Other source-present
schemes are not implied to be built or qualified.

Evidence: `/usr/obj/usr/src/bazel-partition-modules-20261028/qualification`,
with Make references `/usr/obj/usr/src/bazel-geom_part_{bsd,ebr,mbr}-make-20261028`.
All three match complete runtime symbols and relocations, text/data/rodata,
and raw CTF. Debug identity and CRC pass. Staged install metadata matches
paths, owner/group/mode/type and package/debug tags. No module load, host
installation or live partition modification was performed.

Existing maintained frontend format-5 targets and build settings support
the additions without a new C option or publication change. The current
artifact-comparison batch contains fifteen module builds. Full partition
operations, mutation invalidation, runtime/performance, complete kernel/world
and pkgbase qualification remain open. Make remains production/default.

### GEOM label

Added all ten maintained geom_label C sources, explicit GEOM slice/flashmap,
multipath, partition and UFS header dependencies, and a native Skylib
write_file action for the module-local opt_geom.h. The GEOM_LABEL=1 content
is module build policy from its maintained Makefile, not a substitute for
GENERIC configuration. The reference build log confirms that local rule ran;
the two generated option files are byte-identical. Userland header targets
remain available.

Evidence: `/usr/obj/usr/src/bazel-geom-label-20261028/qualification`, with Make
reference `/usr/obj/usr/src/bazel-geom_label-make-20261028`. Symbols,
relocations, text/data/rodata, raw CTF and generated options match. Debug
identity/CRC pass. Staged metadata matches runtime/debug paths, owner/group,
mode/type and package/debug tags. No live filesystem label discovery, host
module loading or installation was performed.

The current artifact-comparison batch has sixteen module builds. Frontend
review: existing format-5 input/target selection covers the new generator
and dependency graph; no C frontend option or publication-policy change is
needed. Source/header invalidation, runtime, resource/performance and complete
kernel/world/pkgbase qualification remain open; Make remains production.

### GEOM flashmap and export-all module policy

Added native geom_flashmap. The shared module macro now supports an explicit
export_all option corresponding to maintained EXPORT_SYMS=YES. This skips
localization and exposes the CTF-merged full artifact directly through an
alias, preserving all definitions rather than substituting an enumerated
allowlist. An explicit export list combined with export_all is rejected.
The ordinary restricted export pipeline remains unchanged.

Evidence: `/usr/obj/usr/src/bazel-flashmap-20261028/qualification`, Make
reference `/usr/obj/usr/src/bazel-geom_flashmap-make-20261028`. Runtime
symbols/relocations, text/data/rodata and raw CTF match; both M_FLASHMAP and
flash_register_slicer remain exported. Debug identity/CRC and staged
installation metadata pass. No module load or host installation occurred.

The batch now has seventeen module builds with artifact comparisons.
Frontend assessment: export policy is native target metadata selected through
the existing format-5 frontend; no new C option or publication change is
needed. Runtime slicing, invalidation, performance, all-world/kernel and
pkgbase gates remain open. Next GEOM work includes uzip's conditional zstd
sources and per-source compression include paths, then RAID/ELI.

### Uzip preparation: scoped compilation and option-selected sources

The shared amd64 GENERIC object macro now accepts a source-group name and
additional copts, retaining existing names/flags by default. This permits
separate source-specific dependency/flag contexts without broadening every
translation unit's include paths. Existing seventeen-module artifact hashes
remain identical with zero spawned actions in
`/usr/obj/usr/src/bazel-module-groups-20261028/qualification/comparison.json`.
Non-default names/copts still need direct qualification with their consumer.

Uzip is NOT converted yet. Its maintained Makefile selects g_uzip_zstd.c
through SRCS.ZSTDIO and KERN_OPTS, and supplies separate LZMA/Zstd include
paths. GENERIC currently enables ZSTDIO, but that observation must not become
an unconditional source list purporting to support changing kernel configs.
The native config action currently produces its tree at execution time;
source selection needs a coherent configuration input at analysis time.
Resolve the shared option/source selection model, validate it against actual
config output, and qualify ZSTDIO both enabled and disabled. Do not invoke
Make to decide the production Bazel graph, compile a disabled implementation
unconditionally, or wrap C sources to conceal the selection gap.

Frontend review: current explicit format-5 target selection covers this
macro-only extension. The upcoming configuration model must integrate with
the maintained frontend and native config inputs in the same change.
Uzip, other configuration-dependent modules, complete kernel/world/pkgbase,
runtime and performance gates remain open. Make stays production/default.

### Native option authority for conditional module sources

Added typed kernel_zstdio (default true) and its analysis-time config_setting.
The native config rule accepts boolean-setting-to-option mappings, validates
option identifiers/uniqueness/types, and writes a declared configuration input
which includes GENERIC followed by nooptions/options overrides. The existing
native config parser resolves that composition and reports its identity.
No Make output parsing, source wrapping or duplicate handwritten header is
used. This is an explicit override: the build setting owns ZSTDIO even if
the included GENERIC text changes its default. Arbitrary configuration
selection and the remaining options still need integration.

Maintained frontend format-5 runs for true and false both pass at
`/usr/obj/usr/src/bazel-kernel-zstdio-{true,false}-r2-20261028`. Their retained
opt_zstdio.h payloads are respectively `#define ZSTDIO 1` and empty;
qualification/option-matrix.json under the true run records hashes/checks.
This qualifies option generation only, not uzip source selection or runtime.
The native uzip consumer remains to be implemented with both settings tested.

Frontend review: existing typed build-settings transport already validates
and forwards this boolean; no new C option is needed. The maintained manual
now documents its override semantics and limited qualification. Full native
config/world/kernel/package/runtime/performance gates remain open.

### Native uzip source selection

Added native geom_uzip with separate named compilation groups preserving
Make's ordered sources and LZMA/Zstd per-source include paths. Compression
API headers and zcalloc's transitive zutil dependency are declared. The shared
kernel_zstdio setting selects both native config output and the optional
g_uzip_zstd object through select(); the disabled module does not compile/link
that implementation. No C wrapper or unconditional disabled implementation
is used.

Enabled evidence: `/usr/obj/usr/src/bazel-uzip-true-r2-20261028/qualification`,
Make reference `/usr/obj/usr/src/bazel-geom_uzip-make-20261028`. Symbols,
relocations, text/data/rodata and raw CTF match; debug identity/CRC pass.
The initial build found an undeclared zutil.h include; its dependency was
fixed and the successful second run retained separately.

Disabled evidence: `/usr/obj/usr/src/bazel-uzip-false-20261028`.
`zstdio-selection.json` records enabled link inputs containing g_uzip_zstd.o
and its ZSTD references, versus no such object or symbols in the disabled
module. Both runs used the maintained frontend with explicit format-5 inputs
and 16 jobs. This is build/source-selection evidence, not decompression
runtime qualification. Disabled Make parity, installation and incremental
checks remain pending. The current batch has eighteen native module builds;
not all qualification gates are closed for each.

Frontend review: the previous change documents kernel_zstdio and the existing
typed setting transport handles this consumer without new C/backend options.
Next: qualify the disabled Make reference and both installation variants,
then continue remaining GEOM/module conversion. Whole-system/runtime and
resource/performance gates remain open; Make remains production/default.

### Uzip enabled/disabled Make parity and installation

Both ZSTDIO variants now pass Make artifact/debug and staged installation
comparisons. The disabled Make reference was configured independently with
the maintained built config utility over `include GENERIC; nooptions ZSTDIO`
(newline-separated directives), rather than by editing generated headers.
Reference: `/usr/obj/usr/src/bazel-geom_uzip-nozstd-make-20261028`, including
configuration input/log and build log. The enabled reference remains
`/usr/obj/usr/src/bazel-geom_uzip-make-20261028`.

Each native run retains qualification/variant-comparison.json:
`/usr/obj/usr/src/bazel-uzip-true-r2-20261028` and
`/usr/obj/usr/src/bazel-uzip-false-20261028`. Both match runtime symbols,
relocations, text/data/rodata and raw CTF; debug identity and CRC pass. Both
staged installs match path/owner/group/mode/type and package/debug tags.
No host module load or installation occurred.

The observed enabled-to-disabled transition spawned exactly one CppCompile,
for g_uzip.c, plus its CTF and downstream module actions. Unchanged zlib,
LZMA and worker translation units were reused. The Zstd object and symbols
were excluded. See the disabled run's qualification/option-invalidation.json.
This is concrete option invalidation evidence, not broad cache/performance
qualification. No decompression I/O, corruption/error-path or memory/disk
performance tests have been performed for uzip.

Frontend review: typed kernel_zstdio and maintained format-5 transport worked
for both variants; manual qualification wording updated without new C/backend
options. Continue remaining module/kernel/world migration and broader gates.

### Native GEOM RAID

Added all fifteen maintained translation units: g_raid/g_raid_ctl, generated
metadata/transform interface C sources, six metadata formats and five RAID
transforms. The generated interfaces consume the native bus/device header
actions, now exposed as CcInfo header targets. The first sandbox compile
correctly detected those missing generated dependencies; the r2 build fixes
the declarations. Generated C diagnostic identities use compiler macro-prefix
mapping from declared source locations to logical filenames; no output byte
rewriting or copied generated sources are used.

Evidence: `/usr/obj/usr/src/bazel-raid-r2-20261028/qualification`; Make reference
`/usr/obj/usr/src/bazel-geom_raid-make-20261028`. Runtime symbols/relocations,
text/data/rodata and raw CTF match. Debug identity/CRC and staged installation
metadata pass. No module load, host installation, array creation, resync or
failover was attempted. Runtime, corruption/error paths, invalidation and
performance remain unqualified.

The current native module batch has nineteen artifact-compared builds.
Existing maintained format-5 frontend targets cover the new generation and
compilation dependencies; no C frontend or publication change is needed.
Complete kernel/world/pkgbase/hardware and runtime/resource gates remain
open; Make remains production/default.

### GEOM ELI and native GEOM aggregate

Added all nine maintained ELI C sources and its declared crypto intake
header dependency, preserving existing userland crypto headers. Evidence:
`/usr/obj/usr/src/bazel-eli-20261028/qualification`; Make reference
`/usr/obj/usr/src/bazel-geom_eli-make-20261028`. Runtime symbols/relocations,
text/data/rodata and raw CTF match; debug identity/CRC and staged installation
metadata pass. No encrypted provider, key change, module load or host
installation was performed. Encrypted I/O/authentication/error behavior and
resource/performance remain unqualified.

Added native aggregate targets under //sys/modules/geom for generic_modules,
generic_debug and install_manifests. Their explicit inventory corresponds to
the maintained geom and geom_part Makefile selections (eleven direct modules
and four partition modules). The maintained frontend aggregate run at
`/usr/obj/usr/src/bazel-geom-aggregate-20261028` succeeds and retains fifteen
runtime modules and fifteen debug artifacts, plus installation records. This
is source-native metadata, not a Make invocation hidden behind Bazel.

Frontend assessment: existing format-5 target selection supports the whole
subtree without new C/backend options. The native module comparison batch
now contains twenty modules including the five filesystem modules. This
does not cover other source-present GEOM schemes or the rest of sys/modules.
Whole-kernel/world/pkgbase/hardware, runtime, performance and broader options
remain open. Make remains production/default.

### MAC DDB, priority and NTP modules

Added native mac_ddb, mac_priority and mac_ntpd with their maintained C
sources, shared mac_policy.h declarations and DDB command header dependency.
Evidence: `/usr/obj/usr/src/bazel-mac-modules-20261028/qualification`; Make
references `/usr/obj/usr/src/bazel-{mac_ddb,mac_priority,mac_ntpd}-make-20261028`.
All three match runtime symbols/relocations, text/data/rodata and raw CTF.
Separate debug identity/CRC and staged installation metadata pass.

These are compiled policy modules only. No host loading or installation,
privilege-grant test, DDB command restriction test, jail/VNET behavior or live
audit qualification was performed. The current native artifact-comparison
batch contains twenty-three modules. This does not qualify other MAC modules
or establish system-wide security policy correctness.

Frontend review: maintained format-5 selection supports these targets and
installation manifests; no new C frontend/signing/publication change is
required. Native kernel/world/pkgbase, source/header invalidation, live
behavior and performance gates remain open. Make remains production/default.

### MAC port ACL and PIM

Added native mac_portacl and mac_pimd plus declared PCB/route header targets.
Evidence: `/usr/obj/usr/src/bazel-mac-network-20261028/qualification`; Make
references `/usr/obj/usr/src/bazel-{mac_portacl,mac_pimd}-make-20261028`.
Both pass debug identity/CRC, runtime symbols, text/data/rodata, raw CTF and
staged installation metadata comparisons. PIM's raw relocation listing
matches as well. Port ACL's raw listing differs in physical section offsets;
relocation-records.json independently verifies identical relocation bytes,
entry sizes, linked symbol-table names and target-section names. Allocated
sections including BSS match type/flags/address/size/alignment and payload
(build-id excluded). The differing physical file layout is retained in the
evidence and no whole-file byte equality is claimed.

No policy module was loaded. Port binding grants/denials, PIM privilege grants,
jail/VNET behavior, auditing and performance remain unqualified. The current
artifact-comparison batch contains twenty-five modules. Existing maintained
format-5 frontend selection covers these targets; no C/backend publication
change is needed. Full-system gates remain open; Make remains production.

### Native mac_do

Added mac_do with its maintained source, generated vnode headers and shared
MAC policy dependencies. Evidence: `/usr/obj/usr/src/bazel-mac-do-20261028/qualification`;
Make reference `/usr/obj/usr/src/bazel-mac_do-make-20261028`. Runtime symbols
and relocations, text/data/rodata, raw CTF and all SDT provider/probe/argument/
tracepoint sections match Make. Debug identity/CRC and staged installation
metadata pass. Both configuration and rule-grant probes remain present.

No module load, credential transition, privilege grant/denial or live probe
firing was performed. Existing format-5 frontend selection covers this
addition without new C/backend policy. The current comparison batch has
twenty-six native module builds; complete kernel/world/pkgbase, live policy,
source/header invalidation and performance gates remain open. Make remains
production/default. Next MAC review includes mac_abac and capability modules.

### Native mac_abac and module package ownership

Added all fifteen maintained ABAC sources and declared local headers. The
shared module macro now accepts explicit package ownership, defaulting to
kernel; mac_abac selects mac-abac as its Makefile requires. This preserves
separate pkgbase ownership for runtime and debug payloads.

Evidence: `/usr/obj/usr/src/bazel-abac-20261028/qualification`; Make reference
`/usr/obj/usr/src/bazel-mac_abac-make-20261028`. Runtime symbols/relocations,
text/data/rodata, raw CTF and SDT provider/probe/argument/tracepoint sections
match. Debug identity/CRC and staged metadata pass, including package=mac-abac
and its debug tag. No policy source was altered, host module loaded, or
installation performed. Rule enforcement, label persistence, credentials,
object coverage, live tracing/audit and performance remain to be qualified.

Frontend review: package ownership is native target metadata consumed by
existing installation manifests, selectable through maintained format-5
targets without a new C option. Full pkgbase assembly/publication remains
a separate gate. The current batch has twenty-seven native module builds
with artifact comparisons; whole-system completion is not established.

### Native Veriexec fingerprint modules and cross-package CTF merging

Added mac_veriexec_sha1, mac_veriexec_sha256, mac_veriexec_sha384 and
mac_veriexec_sha512 using their maintained source inventories. Crypto objects
have native targets; SHA-384 and SHA-512 reuse the same sha512c compilation.
The initial execution log records seven C compilations for four modules.
No algorithm selection or security policy was changed.

Initial qualification found equal code/data, symbols, relocations and staged
metadata, but different raw CTF. ctfmerge.c sorts paths internally, so object
packages previously influenced type merge order. The shared merge rule now
declares basename-first symlinks under a common per-target input directory;
indices distinguish duplicate basenames. No object contents are copied. This
retains native object reuse and removes package path influence on ordering.
Duplicate-basename order follows declared input indices; it is not a promise
of equality with a Make build that uses a different collision naming scheme.

Evidence: `/usr/obj/usr/src/bazel-veriexec-hashes-r2-20261028/qualification`,
including the comparison script, raw dumps and per-module results. All four
match Make for text/data/rodata, symbols, relocations and raw CTF. Separate
debug identity/CRC checks and NO_ROOT staged metadata comparisons pass. Make
references are `/usr/obj/usr/src/bazel-mac_veriexec_sha*-make-20261028`.
The original mismatch remains in `bazel-veriexec-hashes-20261028`.

The CTF correction reran twenty merge/downstream spawned actions with no C
compilation. `bazel-veriexec-ctf-regression-20261028` reran nullfs CTF merging;
its full/runtime/debug hashes equal `bazel-five-modules-repeat-20261028`.
The existing nullfs Bazel artifact test reports cached PASS, not a new test
execution. This is build evidence, not runtime module loading or verification
policy qualification. Full CPU/memory/disk performance gates remain open.

Frontend review: existing format-5 target selection, toolchain receipt,
installation manifests and retained artifacts cover these additions; no new
build-bsd C option or backend selection is required. Make remains production
and default. The current module comparison batch now covers thirty-one
modules, not the complete kernel or system. The core Veriexec and capability
modules, remaining world/kernel closure and pkgbase/publication qualification
remain unfinished.

### Native core Veriexec module

Added all four core sources, explicit internal/public/crypto/nullfs/MAC
header dependencies, native config-derived opt_capsicum/opt_mac/opt_veriexec,
and the maintained three-symbol export policy. No verification policy source
was changed. The format-5 veriexec_debug boolean preserves Make's compiler
definition selection (default true, false = WITHOUT_VERIEXEC_DEBUG).
Current sources do not consume VERIFIED_EXEC_DEBUG; both modes produce the
same artifacts. This is a compiler-interface compatibility setting, not a
new runtime security switch. The maintained frontend manual documents it;
existing typed build-settings handling requires no C/backend option change.

Evidence: `/usr/obj/usr/src/bazel-veriexec-core-20261028/qualification` and
`/usr/obj/usr/src/bazel-veriexec-core-nodebug-20261028/qualification`.
Both variants match their corresponding Make references for code/data,
symbols, relocations, raw CTF, all SDT sections and staged install metadata.
Debug identity and CRC pass. Extracted native option headers match Make.
The core contains three fingerprint and two capimage verification probes;
these sections survive compilation and export processing unchanged.

The module comparison batch now covers thirty-two modules. These checks do
not demonstrate load/unload behavior, signature acceptance/rejection, key
rotation, vnode changes or invalidation, actual audit delivery or probe firing.
Whole-kernel linking/boot, capability modules, world/pkgbase/publication,
arbitrary KERNCONF, bootstrap and comparative performance gates remain open.
Make remains production/default; BIP remains out of scope.

### Capability accounting, identity and coalition modules

Added native module sources and explicit shared/local header dependencies for
mac_capability_accounting, mac_capability_identity and mac_capability_coalition.
All preserve package=mac-capability for runtime/debug staging. Policy sources
are unchanged. Existing format-5 targets and installation manifests cover the
frontend integration; no new C frontend or backend setting is required.

Coalition exposed a real diagnostic-path mismatch: assertions in jail.h
embedded Bazel virtual include paths. sys/sys:kernel_headers now uses its
natural source include root, retaining sys/sys/jail.h diagnostics. This is a
shared header declaration change, not binary rewriting or comparison masking.
The initial mismatch remains in `bazel-capability-services-20261028`;
`bazel-capability-services-r2-20261028/qualification` records corrected parity.

The shared change was exercised across all thirty-five modules in the current
batch through maintained build-bsd, with 16 jobs. Evidence and retained
comparison scripts: `/usr/obj/usr/src/bazel-module-header-regression-20261028`.
All 35 build, match Make code/data, symbols and raw CTF, pass debug identity/CRC,
and match NO_ROOT staged installation metadata. SDT sections match where
present; equal absent sections do not establish instrumentation coverage.
The existing nullfs Bazel artifact test executed and passed (not cached).
mac_portacl retains its previously recorded raw readelf relocation listing
difference from physical section offsets; all six binary relocation payloads,
entry sizes and linked/target section associations match. That exception is
retained explicitly in comparison.json and relocation-records.json.

This is an amd64 GENERIC module build regression, not complete world/kernel
or runtime qualification. Capability call authorization, accounting limits,
identity transitions, coalition process lifetime/cleanup and live audit/probe
behavior remain open. Shared-header impact outside this module batch, other
KERNCONF/architectures and resource/performance gates remain unqualified.
No host modules were loaded, system installed, or security policy altered.
Make remains production/default; BIP remains excluded.

### Capability node and channel modules

Added native mac_capability_node and mac_capability_channel targets with
explicit protocol/shared headers and mac-capability package ownership.
The existing generic module rule supplies native generated vnode interfaces
and the kernel/BSM header closure. No runtime source, protocol or policy was
changed. Existing format-5 target selection, installation metadata and
artifact collection handle both additions; frontend review found no new
build-bsd C/backend option required.

Evidence: `/usr/obj/usr/src/bazel-capability-node-channel-20261028/qualification`
contains the retained comparison script, raw dumps and staged metadata
results. Both modules match maintained Make for symbols, relocations,
text/data/rodata, raw CTF and all SDT sections. Debug identity/CRC and staged
NO_ROOT installation metadata pass. Node retains two SDT definitions and
channel four. This brings the current native module comparison batch to
thirty-seven modules. Runtime execution, authorization, descriptor lifecycle,
channel races, throughput/memory/disk measurements and complete kernel/world
qualification are still open; no host module was loaded or installed.
Make remains production/default and BIP remains excluded.

### Capability isolation, mount and system modules

Added native mac_capability_isolation, mac_capability_mount and
mac_capability_system sources with explicit local protocol, network, MAC and
Bluetooth header dependencies. The capability kernel headers expose their
natural source include root for qualified dev/mac_capability includes.
Runtime and debug metadata retain package=mac-capability. No module runtime
source, protocol or policy changed; these are conversions of existing
modules, not a reintroduction of BIP.

Evidence: `/usr/obj/usr/src/bazel-capability-isolation-system-20261028/qualification`
includes retained comparison code, raw dumps and metadata results. All three
match maintained Make symbols, relocations, text/data/rodata, raw CTF and all
SDT sections, with passing separate-debug identity/CRC and NO_ROOT staged
metadata checks. Existing probes retained: isolation twelve, mount two,
system three. The current module comparison batch reaches forty modules.

Frontend review: existing format-5 targets, native dependency graph and
installation manifests handle these inputs/outputs without a new C frontend
or backend option. Make remains production/default. Live policy enforcement,
jail/mount lifecycle, namespace/network restrictions, audit delivery, module
load/unload, complete world/kernel/pkgbase and performance remain open. No
host installation or module loading was performed.

### Core capability module and capprotect

Added the core module's four explicit sources and 22 maintained exports,
plus the capprotect module. Both preserve mac-capability pkgbase ownership.
The native opt_capsicum header feeds core compilation. Neither process nor
authority implementation is included in the loadable module: sys/conf/files
lists mac_capability_process.c and mac_capability_authority.c as standard
kernel sources, and their built-in conversion/whole-kernel integration is
still required. Module coverage must not be mistaken for that kernel closure.

Evidence: `/usr/obj/usr/src/bazel-capability-core-20261028/qualification`.
Both modules match maintained Make code/data, symbols, relocations, raw CTF
and SDT sections, pass separate-debug identity/CRC, and match NO_ROOT staged
metadata. Core preserves 42 SDT definitions across its sources; capprotect
preserves three. No runtime, protocol, authority or security policy source
was changed. This brings the current module artifact-comparison batch to
forty-two. All ten existing mac_capability module directories now have native
BUILD definitions, but kernel built-ins and live operation remain unqualified.

Frontend review: the existing format-5 selection, export processing and
installation manifests cover these targets without new C/frontend backend
options. Whole-kernel/world/pkgbase publication, bootstrap, runtime lifecycle,
cache-invalidation/performance gates remain incomplete. Make remains the
production/default backend. No host installation or loading was performed;
BIP remains excluded.

### Standard capability process and authority kernel objects

Added native generic_builtin_objects/generic_builtin_ctf and the public
//sys/dev/mac_capability:generic_builtin_object_files target. It compiles
mac_capability_process.c and mac_capability_authority.c as standard amd64
GENERIC kernel sources with explicit headers, generated vnode/offset inputs,
kernel printf annotation and CTF. No KLD_MODULE/KLD_TIED definitions are used.
These objects are separate from loadable module sources and do not receive
standalone installation entries: their eventual installed artifact is the
linked kernel. This does not yet connect a complete kernel link graph.

Evidence: `/usr/obj/usr/src/bazel-capability-builtins-r2-20261028/qualification`.
Maintained generated kernel Makefile targets built the reference objects using
the same SDK clang, 16 jobs, DEBUG=-g, WITH_CTF=yes and reproducible source
paths. Reference log: `/usr/obj/usr/src/bazel-capability-builtins-make-20261028.log`.
Both objects match symbol tables, text, data, rodata/string sections and raw
CTF. Exact allocated section contents/size/type/flags/alignment and their
relocation bytes/entry sizes/linked-symbol-table/target associations match
(14 authority and 13 process sections including relocations). Debug sections
and whole object bytes are not claimed identical. Reference object copies
are retained alongside native artifacts, independent of mutable build output.

Frontend review: existing format-5 target selection and retained artifacts
support these object outputs with no new C/frontend/backend option. Full
kernel linking, boot, lifecycle/authority runtime checks, installation/debug
qualification of the linked kernel and performance remain unfinished. The
module count remains forty-two; these are two additional built-in translation
units, not modules. Make remains production/default and BIP remains excluded.

### Native MAC framework control objects

Added seventeen explicitly inventoried amd64 GENERIC built-in sources:
mac_audit, mac_cred, mac_kdb, mac_framework, mac_label, mac_pipe,
mac_posix_sem, mac_posix_shm, mac_prison, mac_priv, mac_process, mac_socket,
mac_syscalls, mac_system, mac_sysv_msg, mac_sysv_sem and mac_sysv_shm.
A reusable amd64_generic_kernel_objects macro carries native compiler/CTF
inputs without module defines. opt_posix joins the native config-derived
header outputs. Socket policy dependencies include explicit BPF/interface/IP
headers; the initial missing bpfdesc header failure is retained in the first
run rather than bypassed. MAC network/IPv4/IPv6/VFS source groups remain open.

Evidence: `/usr/obj/usr/src/bazel-mac-framework-r2-20261028/qualification`,
including retained Make and Bazel object copies and comparison script.
All seventeen match Make symbols and raw CTF, allocated section contents,
size/type/flags/alignment and runtime relocation payloads/associations.
This includes allocated SDT sections. Reference objects were built through
the maintained generated kernel Makefile with the same SDK clang, 16 jobs,
DEBUG=-g, WITH_CTF=yes and reproducible source paths; log is
`/usr/obj/usr/src/bazel-mac-framework-make-20261028.log`.
Whole-object/debug-path identity is not claimed.

Frontend review: format-5 target selection, generated headers, compiler
receipt and artifact retention support the new target without C/frontend
interface changes. This is an explicitly scoped GENERIC object group, not
arbitrary kernel option selection or a completed kernel link. Object graph
coverage does not establish live MAC policy dispatch or audit delivery.
Module count remains forty-two. Full kernel/world/pkgbase, runtime and
comparative CPU/memory/disk gates remain open; Make stays production/default.

### Complete GENERIC MAC framework object inventory

Added native mac_net, mac_inet, mac_inet6 and mac_vfs objects with declared
interface/IP/IPv6/devfs headers. The aggregate target
//sys/security/mac:generic_object_files selects all twenty-one MAC framework
sources for amd64 GENERIC. Its inventory matches the MAC entries in
sys/conf/files. This is a GENERIC source inventory; conditional selection for
arbitrary KERNCONF remains unimplemented, not implicitly assumed equivalent.

Evidence: `/usr/obj/usr/src/bazel-mac-framework-all-20261028/qualification`.
All 21 objects match maintained kernel Make references for symbols, raw CTF,
complete allocated-section inventories and contents/size/type/flags/alignment,
and relocation bytes with their linked symbol-table and target associations.
Allocated SDT sets are included. Retained comparison code, both object sets,
and source-inventory.json make the scope reviewable. The four new references
were built with the same SDK compiler and 16 jobs using maintained recipes;
log: `/usr/obj/usr/src/bazel-mac-network-vfs-make-20261028.log`.
Whole-object/debug path identity is not claimed.

Frontend review: existing format-5 targets handle the aggregate, generated
inputs and artifact collection without a new C/frontend/backend option.
Kernel linking/boot, policy invocation and live tracing/audit remain separate
gates, along with world/pkgbase, bootstrap and CPU/memory/disk performance.
The current module count remains 42; these are built-in kernel objects.
Make stays production/default. No runtime policy code or BIP work was added.

### Native GENERIC audit kernel objects

Added the fourteen audit/BSM sources selected by the generated amd64 GENERIC
kernel Makefile under //sys/security/audit:generic_object_files. Internal
headers and network wire/PCB dependencies are explicit. The source inventory
matches the generated reference exactly. audit_dtrace.c is conditional on
DTAUDIT/DTRACEALL and uses the CDDL compilation recipe; that unselected variant
still requires separate conversion and qualification. No audit source or
configuration option was disabled to obtain this result.

Evidence: `/usr/obj/usr/src/bazel-audit-kernel-20261028/qualification`, with
retained comparison script, both object sets and source-inventory.json.
All fourteen match Make symbols, raw CTF, complete allocated section
inventories/content/size/type/flags/alignment and runtime relocation payloads
and associations. This includes the auditpipe SDT sections. The Make reference
uses maintained kernel targets, the same SDK compiler, 16 jobs, DEBUG=-g,
WITH_CTF=yes and reproducible source paths; its log is
`/usr/obj/usr/src/bazel-audit-kernel-make-20261028.log`.
Whole-object and debug-path byte equality is not claimed.

Frontend review: existing format-5 targets and artifact retention handle this
native kernel object group without new C/backend options. No standalone
installation entries are added for objects destined for the kernel. Live audit
selection, pipe/trail delivery, backpressure/drop behavior, rotation/failure
handling and DTAUDIT integration remain unqualified. Complete kernel linking,
world/pkgbase/publication, bootstrap and resource/performance gates remain
open. Make stays production/default; no host installation or BIP work occurred.

### Native MAC test modules

Added mac_test and mac_test_hooks native module targets with explicit
MAC/VM/CK/devfs/interface headers and generated vnode interfaces. Package
ownership remains kernel for mac_test and tests for mac_test_hooks, including
separate debug metadata. Runtime sources, counters and denial controls are
unchanged. These modules support later live tests; building them does not
execute those tests or establish hook coverage.

Evidence: `/usr/obj/usr/src/bazel-mac-test-modules-20261028/qualification`,
including retained comparison script, raw dumps and metadata results. Both
match Make symbols, relocations, text/data/rodata and raw CTF; debug identity
and CRC pass, as do NO_ROOT staged metadata comparisons. Neither defines SDT
probes; equal absent sections must not be interpreted as probe coverage.
Current module comparison batch: forty-four. No modules were installed or
loaded into the host.

Frontend review: existing format-5 targets, generated inputs, export/debug
processing and package tags support these additions without new C/backend
options. Live label lifecycle assertions, hook counters, denial injection,
complete kernel/world/pkgbase and resource/performance qualification remain
open. Make remains production/default; BIP remains out of scope.

### Native openES module

Added the complete maintained five-source oes module inventory, explicit
kernel/internal/capability-label/MAC/audit/network headers, native opt_mac
and generated vnode inputs. Existing userland header targets remain intact.
Runtime/debug metadata retain package=oes. No event protocol, authorization,
cache, timeout or enforcement policy source was changed.

Evidence: `/usr/obj/usr/src/bazel-oes-module-20261028/qualification`, including
the comparison script, raw dumps and staged metadata checks. The module
matches maintained Make symbols, relocations, text/data/rodata, raw CTF and
all SDT sections. Separate debug identity/CRC and NO_ROOT metadata checks
pass. The reference is `/usr/obj/usr/src/bazel-oes-make-20261028`.
Current module comparison batch: forty-five.

Frontend review: format-5 target selection and existing module/debug/install
processing cover these additions without new C/frontend/backend options.
This is artifact evidence only. Live openES authorization/notification,
client attach/detach, timeout/failure modes, cache invalidation, queue pressure,
ABAC interaction and audit delivery remain runtime gates. No host module was
loaded or installed. Full kernel/world/pkgbase/publication and performance
qualification remain open; Make stays production/default and BIP excluded.

### Built-in ABAC and openES kernel objects

Added generic_builtin_object_files targets for sys/security/mac_abac and
sys/security/oes: fifteen ABAC and five openES built-in translation units.
Each package shares one explicit source/header inventory between module and
built-in targets, while retaining their separate kernel versus KLD compile
settings. No policy source or protocol changed. The twenty-object inventory
matches the selected generated GENERIC Makefile targets exactly.

Evidence: `/usr/obj/usr/src/bazel-abac-oes-builtins-20261028/qualification`.
All twenty match Make symbols, raw CTF, allocated section inventories and
contents/size/type/flags/alignment, and runtime relocation records/associations.
Allocated probe sections are included. Both object sets and the comparison
script are retained. Make references use the same SDK compiler, 16 jobs,
DEBUG=-g, WITH_CTF=yes and reproducible paths; log:
`/usr/obj/usr/src/bazel-abac-oes-builtins-make-20261028.log`.
Whole-object/debug-path identity and linked-kernel identity are not claimed.

Frontend review: existing format-5 selection and native object artifact
retention cover both built-in targets, without new C/backend options or
standalone object installation metadata. Module count remains forty-five;
these are additional built-in variants. Complete kernel linking/boot, live
ABAC/openES interaction, world/pkgbase/publication, bootstrap, arbitrary
KERNCONF and CPU/memory/disk qualification remain open. Make remains
production/default. No host installation, loading or BIP work occurred.

### Complete GENERIC capability built-in object inventory

Expanded capability built-ins to the complete fifteen-source GENERIC set:
core/device/kern/label, nine service/policy sources, and the existing standard
process/authority sources. The ten module groups and their built-in variants
now share explicit source/dependency tuples. Module target names and separate
KLD compile settings are retained. Process/authority remain kernel-only.
Their earlier hand-expanded compilation target now uses the shared native
built-in macro. Public aggregate: //sys/dev/mac_capability:generic_object_files.

Evidence: `/usr/obj/usr/src/bazel-capability-all-builtins-20261028/qualification`.
All fifteen match maintained kernel Make symbols, raw CTF, complete allocated
section inventories and contents/size/type/flags/alignment, and runtime
relocation bytes/associations. The source inventory matches generated GENERIC
Make targets. Object copies and comparison script are retained; reference log:
`/usr/obj/usr/src/bazel-capability-all-builtins-make-20261028.log`.
`bazel-capability-module-refactor-20261028` additionally builds all ten module
runtime targets through maintained build-bsd after the inventory refactor.
That repeat is a build check, not a fresh live module execution test.

Frontend review: existing format-5 target selection, native artifact retention
and module packaging interfaces remain sufficient; no new C/backend option
is required. Whole-kernel linking/boot, arbitrary configuration selection,
capability lifecycle/enforcement, world/pkgbase/publication, bootstrap and
comparative resource/performance gates remain open. Module count remains 45;
this adds thirteen new built-in variants alongside the earlier two. Make
stays production/default, with no host installation/loading or BIP changes.

### GENERIC Veriexec, parser and SHA2 built-ins

Added native built-in targets for the four Veriexec core/capimage sources,
SHA256 registration, mac_veriexec_parser and sha256c/sha512c. The eight-source
inventory matches these packages' selected generated GENERIC kernel targets.
These use built-in compilation settings without KLD definitions or module-only
diagnostic flags. No parser, trust, signature or algorithm policy was changed.
Other algorithm registration/configuration combinations remain separate work.

Evidence: `/usr/obj/usr/src/bazel-veriexec-builtins-20261028/qualification`,
including both object sets, comparison script and source-inventory.json.
All eight match Make symbols, raw CTF, complete allocated-section inventories
and contents/size/type/flags/alignment, and runtime relocation bytes and
associations. Existing allocated SDT sections are included. Reference log:
`/usr/obj/usr/src/bazel-veriexec-builtins-make-20261028.log`; maintained kernel
recipes used the same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes and
reproducible source paths. Whole-object/debug path identity is not claimed.

Frontend review: existing format-5 targets, compiler/CTF tools and artifact
retention cover these built-ins without new C/backend options or object
installation entries. Full kernel linking/boot, live verification rejection
and acceptance, parser error behavior, key changes, cache invalidation and
performance remain unqualified, alongside world/pkgbase/publication and
bootstrap gates. Module count stays 45. Make remains production/default;
no host installation or BIP changes occurred.

### Native libkern common support objects

Added forty-eight explicit GENERIC libkern C sources under
//sys/libkern:generic_common_object_files, covering selected memory/string,
search/sort, checksums, address conversion and other support routines.
qsort_r includes qsort.c through a declared common implementation header
input. random.c's PCG dependency is explicitly declared; the initial missing
header failure remains in the first run. No source or feature was disabled.
The generated GENERIC libkern inventory has two remaining unconverted objects:
arc4random.o and x86 crc32_sse42.o, for separate provider/architecture groups.

Evidence: `/usr/obj/usr/src/bazel-libkern-common-r2-20261028/qualification`.
All 48 objects match Make symbols, raw CTF, complete allocated section
inventories/content/size/type/flags/alignment, and runtime relocation records
and associations. Retained script, native/reference objects and inventory
record the exact scope. Reference log:
`/usr/obj/usr/src/bazel-libkern-common-make-20261028.log`; maintained kernel
recipes use the same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes and
reproducible source paths. Whole-object/debug-path identity is not claimed.

Frontend review: existing format-5 target selection and native compiler/CTF
artifact retention require no new C/backend option or standalone installation
entries. Functional vectors, live kernel behavior, remaining source closure,
complete world/pkgbase/publication, bootstrap and resource/performance gates
remain open. Module count remains 45; these are built-in objects. Make stays
production/default with no host installation or BIP changes.

### Complete GENERIC libkern object inventory

Added arc4random and x86 crc32_sse42 as separate native object groups with
explicit ChaCha, SHA2 and random-provider headers. The CRC implementation
uses its maintained inline assembly under normal kernel compilation flags;
no global CPU feature flags were introduced. The initial missing _chacha.h
failure is retained in the first run and fixed by declaring that input.
//sys/libkern:generic_object_files now selects all fifty libkern objects in
the generated amd64 GENERIC Makefile. Other architecture/configuration sets
remain outside this inventory claim.

Evidence: `/usr/obj/usr/src/bazel-libkern-all-r2-20261028/qualification`.
All fifty match Make symbols, raw CTF, complete allocated-section inventories
and contents/size/type/flags/alignment, and runtime relocation records and
associations. Both object sets, comparison script and source-inventory.json
are retained. The two new references use maintained kernel recipes and the
same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes and reproducible paths;
log: `/usr/obj/usr/src/bazel-libkern-final-make-20261028.log`.
Whole-object/debug-path identity is not claimed.

Frontend review: existing format-5 selection and artifact retention support
the aggregate and declared headers without a new C/backend option. This
completes GENERIC libkern object coverage, not kernel linking/boot or live
entropy/reseed/CRC dispatch validation. Functional vectors, performance,
world/pkgbase/publication and bootstrap gates remain open. Module count
remains 45. Make stays production/default; no host installation or BIP changes.

### Native GENERIC devfs objects

Added //sys/fs/devfs:generic_object_files covering all five selected devfs
sources (devs, dir, rule, vfsops, vnops), with explicit internal/MAC/CK/VM
headers and native generated vnode/offset inputs. The source inventory matches
the generated GENERIC Makefile. Runtime filesystem, rules and label behavior
are unchanged.

Evidence: `/usr/obj/usr/src/bazel-devfs-kernel-20261028/qualification`,
including retained native/reference objects, comparison script and inventory.
All five match Make symbols, raw CTF, complete allocated-section inventories
and contents/size/type/flags/alignment, and runtime relocation bytes and
associations. Make uses maintained kernel recipes, the same SDK compiler,
16 jobs, DEBUG=-g, WITH_CTF=yes and reproducible paths; reference log:
`/usr/obj/usr/src/bazel-devfs-kernel-make-20261028.log`.
Whole-object/debug-path identity is not claimed.

Frontend review: existing format-5 target selection and native artifact
retention cover the added kernel objects without a new C/backend option or
standalone installation entries. Actual /dev startup, node creation/removal,
rulesets, jail visibility, MAC labels, open/read/write and teardown remain
runtime tests for the linked kernel. Complete world/kernel/pkgbase/bootstrap
and CPU/memory/disk performance gates remain open. Module count stays 45;
Make remains production/default, and no host installation or BIP work occurred.

### Native tmpfs and pseudofs built-in variants

Added generic_builtin_object_files for tmpfs and pseudofs, four sources each.
Module and built-in targets share explicit source/dependency inventories but
retain their different compilation settings. Native option/vnode/offset
headers are unchanged. The eight-object inventory matches selected generated
GENERIC Make targets; no filesystem implementation or policy source changed.

Evidence: `/usr/obj/usr/src/bazel-tmpfs-pseudofs-builtins-20261028/qualification`.
All eight match Make symbols, raw CTF, complete allocated-section inventories
and contents/size/type/flags/alignment, and runtime relocation records and
associations. Both object sets and the comparison script are retained.
Reference log: `/usr/obj/usr/src/bazel-tmpfs-pseudofs-builtins-make-20261028.log`;
maintained recipes use the same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes
and reproducible paths. Whole-object/debug-path identity is not claimed.

Frontend review: existing format-5 selection and native artifact retention
support the added built-in targets without new C/backend options or object
installation entries. Mount/unmount, vnode lifetime, quota/limits, memory
pressure, concurrent file operations and filesystem performance remain live
qualification work. Complete kernel/world/pkgbase/bootstrap gates stay open.
Module count remains 45; Make stays production/default. No host filesystem
was mounted or modified, and no BIP work was introduced.

### Native GENERIC System V IPC kernel objects

Added sysv_ipc, sysv_msg, sysv_sem and sysv_shm under
//sys/kern:generic_sysvipc_object_files with explicit MAC/audit/VM/CK
headers and native config-derived opt_sysvipc.h. The source inventory matches
the generated GENERIC kernel targets; the option header matches Make bytes.
No IPC implementation or configuration was altered. Initial source inspection
also confirmed this tree contains no fs/procfs or modules/procfs to convert.

Evidence: `/usr/obj/usr/src/bazel-sysvipc-kernel-20261028/qualification`.
All four match Make symbols, raw CTF, complete allocated-section inventories
and contents/size/type/flags/alignment, and runtime relocation records and
associations. Allocated SDT data are included. Both object sets, comparison
script and option-header/inventory evidence are retained. Make log:
`/usr/obj/usr/src/bazel-sysvipc-kernel-make-20261028.log`; maintained recipes
use the same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes and reproducible
paths. Whole-object/debug-path identity is not claimed.

Frontend review: existing format-5 target selection and generated inputs
support this kernel group without new C/backend options or installation
entries. Queue limits/blocking, semaphore wait/wake/undo, shared-memory
mapping/removal, jail visibility, MAC enforcement and audit delivery remain
runtime tests for the linked kernel. Complete world/kernel/pkgbase/bootstrap
and resource/performance qualification remain open. Module count stays 45;
Make remains production/default, with no host installation or BIP changes.

### POSIX shared memory and kernel synchronization objects

Added uipc_shm and seven selected GENERIC synchronization sources:
kern_condvar, kern_lock, kern_mutex, kern_rmlock, kern_rwlock, kern_sema,
kern_sx. uipc_sem.c is not selected by this GENERIC reference; its POSIX
semaphore configuration remains separate work. The native targets retain
actual generated adaptive-lock/scheduler/KTRACE/HWPMC/DDB/Capsicum options.
The initial missing HWPMC header was fixed with the existing declared header
target, not by disabling hooks. No synchronization or IPC source changed.

Evidence: `/usr/obj/usr/src/bazel-shm-sync-kernel-r2-20261028/qualification`.
All eight match Make symbols, raw CTF, complete allocated-section inventories
and contents/size/type/flags/alignment, and runtime relocation records and
associations. All eight consumed option headers match Make bytes. Retained
objects, comparison script and options-comparison.json document the scope.
Reference log: `/usr/obj/usr/src/bazel-shm-sync-kernel-make-20261028.log`;
maintained recipes use the same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes
and reproducible paths. Whole-object/debug-path identity is not claimed.

Frontend review: existing format-5 targets and native configuration outputs
support this group without new C/backend options or installation entries.
Live shared-memory behavior, lock contention/wakeup/ordering, scheduler
interaction and comparative CPU/memory/disk performance remain open. The
recorded 2026-10-03 ZFS/filedesc WITNESS trace was consulted; its open,
undiagnosed status is unchanged by object parity. Complete kernel/world/
pkgbase/bootstrap gates remain open. Make stays production/default with no
host installation or BIP changes; module count remains 45.

### Native sleepqueue and turnstile kernel objects

Added //sys/kern:generic_waitqueues_object_files for subr_sleepqueue and
subr_turnstile, using native generated scheduler, DDB, stack and queue-profiling
option headers with explicit CK/VM/DDB dependencies. No queue implementation,
profiling choice or synchronization behavior was changed.

Evidence: `/usr/obj/usr/src/bazel-waitqueues-kernel-20261028/qualification`.
Both objects match Make symbols, raw CTF, complete allocated-section inventories
and contents/size/type/flags/alignment, and runtime relocation records and
associations. All five consumed generated option headers match Make bytes.
Object copies, comparison script and options-comparison.json are retained.
Reference log: `/usr/obj/usr/src/bazel-waitqueues-kernel-make-20261028.log`;
maintained kernel recipes use the same SDK compiler, 16 jobs, DEBUG=-g,
WITH_CTF=yes and reproducible paths. Whole-object/debug-path identity is not
claimed; arbitrary profiling configurations remain separate qualification.

Frontend review: existing format-5 target selection and generated inputs
support these objects without new C/backend options or installation entries.
Wakeup/interruption, priority inheritance, contention, races and latency/CPU
measurements require the linked test kernel. The open WITNESS issue remains
undiagnosed. Full kernel/world/pkgbase/bootstrap and performance gates remain
open; Make stays production/default with no host loading or BIP changes.

### Native taskqueue, group taskqueue and epoch objects

Added //sys/kern:generic_deferred_work_object_files for subr_taskqueue,
subr_gtaskqueue and subr_epoch with explicit CK/VM and generated bus/device
interface dependencies. These are the maintained GENERIC source selections;
no queue, scheduling, epoch or instrumentation source was changed.

Evidence: `/usr/obj/usr/src/bazel-deferred-work-kernel-20261028/qualification`.
All three match Make symbols, raw CTF, complete allocated-section inventories
and contents/size/type/flags/alignment, and runtime relocation records and
associations. Existing allocated SDT data are included (seven taskqueue,
eight group taskqueue, four epoch definitions). Retained comparison code and
both object sets document the scope. Reference log:
`/usr/obj/usr/src/bazel-deferred-work-kernel-make-20261028.log`; maintained
recipes use the same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes and
reproducible paths. Whole-object/debug-path identity is not claimed.

Frontend review: existing format-5 target selection and native artifact
retention cover these objects without new C/backend options or installation
entries. Live scheduling/cancellation/drain, epoch reclamation, races and
throughput/latency/resource measurements remain unqualified. Full kernel/
world/pkgbase/bootstrap gates remain open. Make stays production/default;
no host installation or BIP work occurred, and module count remains 45.

### Native timecounter, timer and callout objects

Added //sys/kern:generic_timers_object_files for kern_tc, kern_time and
kern_timeout, with explicit CK/VM/debugger/interface headers and native
generated DDB/KTRACE/callout-profiling/FFCLOCK/NTP/RSS options. No timing,
clock-selection, scheduling or instrumentation source behavior changed.

Evidence: `/usr/obj/usr/src/bazel-timers-kernel-20261028/qualification`.
All three match Make symbols, raw CTF, complete allocated-section inventories
and contents/size/type/flags/alignment, and runtime relocation records and
associations. All six option headers match Make bytes. Native/reference
objects, comparison script and option evidence are retained. Reference log:
`/usr/obj/usr/src/bazel-timers-kernel-make-20261028.log`; maintained recipes
use the same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes and reproducible
paths. Whole-object/debug-path identity is not claimed.

Frontend review: existing format-5 targets and native generated inputs support
these kernel objects without new C/backend options or installation entries.
Clock accuracy/selection, timer delivery, callout drain/cancel races and
latency/resource measurements remain runtime qualification. Complete kernel/
world/pkgbase/bootstrap gates stay open. Make remains production/default,
module count stays 45, and no host installation or BIP changes occurred.

### Native kqueue event handling

Added //sys/kern:generic_events_object_files for kern_event.c using the
maintained GENERIC source selection, declared CK/VM headers, and generated
KTRACE/KQUEUE options extracted from native config output. No event-handling
source behavior or configuration substitute was introduced.

Evidence: `/usr/obj/usr/src/bazel-events-kernel-20261028/qualification`.
The object matches Make symbols, raw CTF, complete allocated-section inventory,
section bytes/size/type/flags/alignment and runtime relocation records and
associations. Both option headers match Make bytes. The retained comparison
includes allocated SDT data for the 16 kqueue probe definitions. Reference
log: `/usr/obj/usr/src/bazel-events-kernel-make-20261028.log`; maintained
recipes used the same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes and
reproducible paths. Whole-object/debug-path identity is not claimed.

Frontend review: existing format-5 target selection and generated inputs
cover this addition without new build-bsd C/backend options, staging or
manual changes. No runtime tests ran: event registration/delivery, filters,
cancellation, descriptor lifetime and concurrency need the linked test
kernel. Full kernel/world/pkgbase/bootstrap and performance gates remain
open. Make remains production/default; module count remains 45, with no host
installation or BIP changes.

### Native pipes, sockets and socket buffers

Added //sys/kern:generic_pipe_object_files and generic_socket_object_files
for sys_pipe.c, uipc_socket.c and uipc_sockbuf.c, matching the generated
GENERIC Makefile source selection. Dependencies declare CK/VM, MAC internal
headers (visibility limited to sys/kern), TCP/PCB headers and native config
KTRACE/INET/INET6/KERN_TLS/SCTP/PARAM options. No runtime source was changed.

Evidence: `/usr/obj/usr/src/bazel-sockets-kernel-20261028/qualification`.
All three objects match Make symbols, raw CTF, complete allocated-section
inventories, section bytes/size/type/flags/alignment and runtime relocation
records/associations. All six option headers match Make bytes. Maintained
Make recipes used the same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes and
reproducible paths; log: `/usr/obj/usr/src/bazel-sockets-kernel-make-20261028.log`.
Whole-object/debug-path identity is not claimed.

Unchanged frontend rerun: `/usr/obj/usr/src/bazel-sockets-kernel-cache-20261028`.
All retained artifact hashes match; execution.json is empty (zero spawned
actions, not a claim of zero internal write/symlink actions). No runtime
tests ran. Pipe/socket lifecycle, blocking/nonblocking I/O, descriptor passing,
MAC enforcement and network/TLS behavior still need linked-kernel tests.

Frontend review: existing format-5 targets and generated inputs cover these
additions without new build-bsd C/backend options, staging or manual changes.
Full kernel/world/pkgbase/bootstrap and CPU/memory/disk performance gates
remain open. Make stays production/default, module count remains 45, and no
host installation or BIP work occurred.

### Native UNIX-domain sockets and socket syscalls

Added //sys/kern:generic_unix_socket_object_files and
//sys/kern:generic_socket_syscalls_object_files for uipc_usrreq.c and
uipc_syscalls.c. Both are selected by the maintained GENERIC Makefile.
Declared dependencies include SipHash, CK/VM, networking, debugger, MAC,
audit and generated Capsicum/DDB/INET/INET6/KTRACE headers. Runtime source
and policy behavior are unchanged.

Evidence: `/usr/obj/usr/src/bazel-unix-sockets-kernel-20261028/qualification`.
Both objects match Make symbols, raw CTF, complete allocated-section
inventories, section bytes/size/type/flags/alignment and runtime relocation
records/associations. All five generated option headers match Make bytes.
Reference log: `/usr/obj/usr/src/bazel-unix-sockets-kernel-make-20261028.log`;
maintained recipes used the same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes
and reproducible paths. Whole-object/debug-path identity is not claimed.

Frontend review: existing format-5 target selection covers these native
objects without new build-bsd C/backend options, staging or manual changes.
No runtime tests ran. UNIX stream/datagram/seqpacket behavior, SCM_RIGHTS,
credential transfer, garbage collection, MAC denial and audit record delivery
remain linked-kernel qualification. Full kernel/world/pkgbase/bootstrap and
CPU/memory/disk performance gates remain open. Make remains production/default;
module count remains 45. No host installation or BIP work occurred.

### Native descriptor management and general I/O

Added //sys/kern:generic_descriptor_io_object_files for kern_descrip.c and
sys_generic.c, as selected by the maintained GENERIC Makefile. Dependencies
explicitly include CK/VM, MAC, audit, networking, debugger and generated
Capsicum/DDB/KTRACE headers. No descriptor, locking or I/O source was changed.

Evidence: `/usr/obj/usr/src/bazel-descriptor-io-kernel-20261028/qualification`.
Both objects match Make symbols, raw CTF, complete allocated-section
inventories, section bytes/size/type/flags/alignment and runtime relocation
records/associations. All three option headers match Make bytes. Maintained
reference recipes used the same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes
and reproducible paths; log:
`/usr/obj/usr/src/bazel-descriptor-io-kernel-make-20261028.log`.
Whole-object/debug-path identity is not claimed.

Frontend review: existing format-5 target selection supports these additions
without new build-bsd C/backend options, staging or manual changes. No runtime
tests ran. Descriptor lifetime, dup/fork/exec inheritance, ioctl, read/write,
poll/select, concurrency and audit/MAC behavior need linked-kernel tests.
The recorded 2026-10-03 filedesc/ZFS WITNESS trace was consulted; its lock-order
reversal remains undiagnosed, not fixed by build parity. Full kernel/world/
pkgbase/bootstrap and performance gates remain open. Make remains production/
default; module count remains 45, with no host installation or BIP work.

### Native Capsicum and process descriptors

Added //sys/kern:generic_capsicum_procdesc_object_files for sys_capability.c
and sys_procdesc.c, matching the maintained GENERIC source selection. CK/VM,
audit and generated Capsicum/KTRACE dependencies are declared. No runtime
source or security semantics changed.

Evidence: `/usr/obj/usr/src/bazel-capsicum-procdesc-kernel-20261028/qualification`.
Both objects match Make symbols, raw CTF, complete allocated-section
inventories, section bytes/size/type/flags/alignment and runtime relocation
records/associations. Both generated option headers match Make bytes.
Reference log: `/usr/obj/usr/src/bazel-capsicum-procdesc-kernel-make-20261028.log`;
maintained recipes used the same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes
and reproducible paths. Whole-object/debug-path identity is not claimed.

Frontend review: existing format-5 targets and generated inputs support these
objects without new build-bsd C/backend options, staging or manual changes.
No runtime tests ran. Rights reduction/transfer, ioctl/fcntl limits, capability
mode, process-descriptor transfer/close/kill and poll/kqueue lifecycle remain
linked-kernel qualification, including the previously recorded filedesc/ZFS
lock-order issue. Full kernel/world/pkgbase/bootstrap and performance gates
remain open. Make remains production/default; module count remains 45.
No host installation or BIP work occurred.

### Native fork and exit handling

Added //sys/kern:generic_process_lifecycle_object_files for kern_fork.c and
kern_exit.c, selected by the maintained GENERIC Makefile. Dependencies declare
CK/VM, MAC, audit, debugger and generated DDB/KTRACE/KSTACK_PAGES headers.
The stack-page header is extracted from native config, not synthesized.
No process or security source behavior changed.

Evidence: `/usr/obj/usr/src/bazel-process-lifecycle-kernel-20261028/qualification`.
Both objects match Make symbols, raw CTF, complete allocated-section inventories,
section bytes/size/type/flags/alignment and runtime relocation records and
associations. All three generated option headers match Make bytes. Reference
log: `/usr/obj/usr/src/bazel-process-lifecycle-kernel-make-20261028.log`;
maintained recipes used the same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes
and reproducible paths. Whole-object/debug-path identity is not claimed.

Frontend review: existing format-5 target selection and generated inputs cover
these additions without new build-bsd C/backend options, staging or manual
changes. No runtime tests ran. Fork/vfork/pdfork, failure cleanup, wait/reap,
credential/descriptor inheritance and process teardown require linked-kernel
qualification. Full kernel/world/pkgbase/bootstrap and performance gates stay
open. Make remains production/default; module count remains 45. No host
installation or BIP changes occurred.

### Native signals and process credentials

Added //sys/kern:generic_signal_credentials_object_files for kern_sig.c and
kern_prot.c, selected by the maintained GENERIC Makefile. Dependencies declare
CK/VM, MAC internal headers, audit and generated Capsicum/KTRACE/INET/INET6
headers. No signal, credential or policy source behavior changed.

Evidence: `/usr/obj/usr/src/bazel-signal-credentials-kernel-20261028/qualification`.
Both objects match Make symbols, raw CTF, complete allocated-section
inventories, section bytes/size/type/flags/alignment and runtime relocation
records/associations. All four generated option headers match Make bytes.
Reference log: `/usr/obj/usr/src/bazel-signal-credentials-kernel-make-20261028.log`;
maintained recipes used the same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes
and reproducible paths. Whole-object/debug-path identity is not claimed.

Frontend review: existing format-5 target selection supports these native
objects without new build-bsd C/backend options, staging or manual changes.
No runtime tests ran. Signal permissions, delivery/queueing, core dumps,
UID/GID/group transitions and MAC/audit outcomes require linked-kernel tests.
Full kernel/world/pkgbase/bootstrap and performance gates remain open. Make
remains production/default; module count remains 45. No host installation
or BIP work occurred.

### Native executable loading

Added //sys/kern:generic_exec_object_files for kern_exec.c, selected by the
maintained GENERIC Makefile. Dependencies declare CK/VM, MAC, audit, HWPMC
and HWT hooks, and generated Capsicum/KTRACE/HWPMC_HOOKS/HWT_HOOKS/VM headers.
HWT_HOOKS remains enabled according to native GENERIC config; no tracing
feature was disabled to compile. No exec or policy source behavior changed.

Evidence: `/usr/obj/usr/src/bazel-exec-kernel-20261028/qualification`.
The object matches Make symbols, raw CTF, complete allocated-section inventory,
section bytes/size/type/flags/alignment and runtime relocation records and
associations. All five generated option headers match Make bytes. Reference
log: `/usr/obj/usr/src/bazel-exec-kernel-make-20261028.log`; maintained recipes
used the same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes and reproducible
paths. Whole-object/debug-path identity is not claimed.

Frontend review: existing format-5 targets and generated inputs cover this
addition without new build-bsd C/backend options, staging or manual changes.
No runtime tests ran. Executable/interpreter activation, fexecve, set-id,
credential transitions, policy denial and failed-exec cleanup remain linked-
kernel qualification. Full kernel/world/pkgbase/bootstrap and performance
gates remain open. Make remains production/default; module count remains 45.
No host installation or BIP work occurred.

### Native thread management

Added //sys/kern:generic_threads_object_files for kern_thr.c and kern_thread.c,
selected by the maintained GENERIC Makefile. Dependencies declare CK/VM,
audit, HWPMC/HWT hooks and native generated KTRACE/POSIX/HWPMC_HOOKS/HWT_HOOKS/
WITNESS headers. No thread or instrumentation source behavior changed.

Evidence: `/usr/obj/usr/src/bazel-threads-kernel-20261028/qualification`.
Both objects match Make symbols, raw CTF, complete allocated-section
inventories, section bytes/size/type/flags/alignment and runtime relocation
records/associations. All five generated option headers match Make bytes.
Reference log: `/usr/obj/usr/src/bazel-threads-kernel-make-20261028.log`;
maintained recipes used the same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes
and reproducible paths. Whole-object/debug-path identity is not claimed.

Frontend review: existing format-5 targets and generated inputs support these
objects without new build-bsd C/backend options, staging or manual changes.
No runtime tests ran. Thread creation/exit, suspension/wakeup, signals,
resource accounting, contention and tracing require linked-kernel tests.
Full kernel/world/pkgbase/bootstrap and CPU/memory/disk performance gates
remain open. Make remains production/default; module count remains 45.
No host installation or BIP work occurred.

### Native user-mutex synchronization

Added //sys/kern:generic_umtx_object_files for kern_umtx.c, selected by the
maintained GENERIC Makefile. Dependencies declare CK/VM, MAC and the native
config-generated UMTX_PROFILING header. No synchronization source changed.

Evidence: `/usr/obj/usr/src/bazel-umtx-kernel-20261028/qualification`.
The object matches Make symbols, raw CTF, complete allocated-section inventory,
section bytes/size/type/flags/alignment and runtime relocation records and
associations. The generated profiling header matches Make bytes. Reference
log: `/usr/obj/usr/src/bazel-umtx-kernel-make-20261028.log`; maintained recipes
used the same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes and reproducible
paths. Whole-object/debug-path identity is not claimed.

Frontend review: existing format-5 targets and generated inputs cover this
addition without new build-bsd C/backend options, staging or manual changes.
No runtime tests ran. Pthread mutex/condition-variable behavior, robust and
process-shared synchronization, timeout/wakeup races and priority inheritance
require linked-kernel qualification. Alternate profiling configurations remain
separate qualification. Full kernel/world/pkgbase/bootstrap and CPU/memory/
disk performance gates stay open. Make remains production/default; module
count remains 45. No host installation or BIP changes occurred.

### Native resource limits and process accounting

Added //sys/kern:generic_resource_accounting_object_files for kern_resource.c
and kern_acct.c, selected by the maintained GENERIC Makefile. Dependencies
declare CK/VM and MAC headers. Neither source requires an additional local
option header. No limits, accounting or policy source behavior changed.

Evidence: `/usr/obj/usr/src/bazel-resource-accounting-kernel-20261028/qualification`.
Both objects match Make symbols, raw CTF, complete allocated-section inventories,
section bytes/size/type/flags/alignment and runtime relocation records and
associations. Reference log:
`/usr/obj/usr/src/bazel-resource-accounting-kernel-make-20261028.log`;
maintained recipes used the same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes
and reproducible paths. Whole-object/debug-path identity is not claimed.

Frontend review: existing format-5 targets support these additions without
new build-bsd C/backend options, staging or manual changes. No runtime tests
ran. Resource-limit enforcement, scheduling priority permissions, resource
usage reporting and accounting-file lifecycle/space handling remain linked-
kernel qualification. Full kernel/world/pkgbase/bootstrap and performance
gates remain open. Make remains production/default; module count remains 45.
No host installation or BIP work occurred.

### Native privilege checks, login classes and OS identity

Added //sys/kern:generic_identity_privilege_object_files for kern_priv.c,
kern_loginclass.c and kern_mib.c, selected by the maintained GENERIC Makefile.
Dependencies declare CK/VM, MAC and generated POSIX/CONFIG headers. No
privilege, login-class or identity source behavior changed.

Evidence: `/usr/obj/usr/src/bazel-identity-privilege-kernel-20261028/qualification`.
All three objects match Make symbols, raw CTF, complete allocated-section
inventories, section bytes/size/type/flags/alignment and runtime relocation
records/associations. Both generated option headers match Make bytes.
Reference log: `/usr/obj/usr/src/bazel-identity-privilege-kernel-make-20261028.log`;
maintained recipes used the same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes
and reproducible paths. Whole-object/debug-path identity is not claimed.

Frontend review: existing format-5 target selection covers these objects
without new build-bsd C/backend options, staging or manual changes. No runtime
tests ran. Privilege/MAC decisions, login-class transitions, resource-accounting
integration and jail-specific identity/sysctl behavior require linked-kernel
tests. Full kernel/world/pkgbase/bootstrap and performance gates remain open.
Make remains production/default; module count remains 45. No host installation
or BIP work occurred.

### Native RACCT and RCTL

Added //sys/kern:generic_resource_control_object_files for kern_racct.c and
kern_rctl.c, selected by the maintained GENERIC Makefile. Dependencies declare
CK/VM, MAC, generated scheduler options and bus/device interfaces required
through SMP headers. The first build exposed the missing generated interface
dependency; the corrected graph builds without runtime source changes.

Evidence: `/usr/obj/usr/src/bazel-resource-control-kernel-r2-20261028/qualification`.
Both objects match Make symbols, raw CTF, complete allocated-section inventories,
section bytes/size/type/flags/alignment and runtime relocation records and
associations. The scheduler option header matches Make bytes. Reference log:
`/usr/obj/usr/src/bazel-resource-control-kernel-make-20261028.log`;
maintained recipes used the same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes
and reproducible paths. Whole-object/debug-path identity is not claimed.

Frontend review: existing format-5 targets and generated inputs support these
objects without new build-bsd C/backend options, staging or manual changes.
No runtime tests ran. Rule add/remove, process/user/jail/login-class accounting,
deny/signal/throttle actions, concurrency and resource usage need linked-kernel
qualification. Full kernel/world/pkgbase/bootstrap and performance gates remain
open. Make remains production/default; module count remains 45. No host
installation or BIP work occurred.

### Native affinity and scheduling helpers

Added //sys/kern:generic_affinity_scheduling_object_files for kern_cpuset.c,
kern_switch.c and ksched.c, selected by the maintained GENERIC Makefile.
Dependencies declare CK/VM, debugger, generated bus/device interfaces and
DDB/KTRACE/POSIX/SCHED options. No scheduling source behavior changed.
This batch does not cover sched_ule.c or establish a complete scheduler build.

Evidence: `/usr/obj/usr/src/bazel-affinity-scheduling-kernel-20261028/qualification`.
All three objects match Make symbols, raw CTF, complete allocated-section
inventories, section bytes/size/type/flags/alignment and runtime relocation
records/associations. All four option headers match Make bytes. Reference log:
`/usr/obj/usr/src/bazel-affinity-scheduling-kernel-make-20261028.log`;
maintained recipes used the same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes
and reproducible paths. Whole-object/debug-path identity is not claimed.

Frontend review: existing format-5 targets and generated inputs cover these
additions without new build-bsd C/backend options, staging or manual changes.
No runtime tests ran. CPU/domain affinity, jail constraints, scheduling policy,
priority permissions, migration and latency require linked-kernel tests.
Full kernel/world/pkgbase/bootstrap and performance gates remain open. Make
remains production/default; module count remains 45. No host installation
or BIP changes occurred.

### Native ULE scheduler

Added //sys/kern:generic_ule_object_files for sched_ule.c, selected by the
maintained GENERIC Makefile. Dependencies declare CK/VM, bus/device interfaces,
HWPMC/HWT headers and native generated HWPMC_HOOKS/HWT_HOOKS/SCHED options.
No scheduler algorithm, tracing or source behavior changed.

Evidence: `/usr/obj/usr/src/bazel-ule-kernel-20261028/qualification`.
The object matches Make symbols, raw CTF, complete allocated-section inventory,
section bytes/size/type/flags/alignment and runtime relocation records and
associations. All three option headers match Make bytes. Reference log:
`/usr/obj/usr/src/bazel-ule-kernel-make-20261028.log`; maintained recipes used
the same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes and reproducible paths.
Whole-object/debug-path identity is not claimed.

Frontend review: existing format-5 targets and generated inputs support ULE
without new build-bsd C/backend options, staging or manual changes. No runtime
tests ran. Fairness, migration, affinity, priority inheritance, idle/preemption,
latency and CPU/resource measurements require the linked test kernel. Alternate
scheduler configurations remain separate qualification. Full kernel/world/
pkgbase/bootstrap and performance gates remain open. Make remains production/
default; module count remains 45. No host installation or BIP work occurred.

### Native synchronization and SMP coordination

Added //sys/kern:generic_synch_smp_object_files for kern_synch.c and subr_smp.c,
selected by the maintained GENERIC Makefile. Dependencies declare CK/VM,
generated bus/device interfaces and KTRACE/SCHED options. No synchronization
or SMP source behavior changed.

Evidence: `/usr/obj/usr/src/bazel-synch-smp-kernel-20261028/qualification`.
Both objects match Make symbols, raw CTF, complete allocated-section
inventories, section bytes/size/type/flags/alignment and runtime relocation
records/associations. Both generated option headers match Make bytes.
Reference log: `/usr/obj/usr/src/bazel-synch-smp-kernel-make-20261028.log`;
maintained recipes used the same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes
and reproducible paths. Whole-object/debug-path identity is not claimed.

Frontend review: existing format-5 targets and generated inputs cover these
objects without new build-bsd C/backend options, staging or manual changes.
No runtime tests ran. Sleep/wakeup, preemption, SMP rendezvous, CPU stop/restart,
interprocessor signaling and latency/resource use require linked-kernel tests.
Full kernel/world/pkgbase/bootstrap and performance gates remain open. Make
remains production/default; module count remains 45. No host installation
or BIP work occurred.

### Native sysctl handling

Added //sys/kern:generic_sysctl_object_files for kern_sysctl.c, selected by
the maintained GENERIC Makefile. Dependencies declare CK/VM, MAC, VNET,
debugger lexer headers and native Capsicum/DDB/KTRACE/SYSCTL options.
No sysctl or security source behavior changed.

Evidence: `/usr/obj/usr/src/bazel-sysctl-kernel-20261028/qualification`.
The object matches Make symbols, raw CTF, complete allocated-section inventory,
section bytes/size/type/flags/alignment and runtime relocation records and
associations. All four option headers match Make bytes. Reference log:
`/usr/obj/usr/src/bazel-sysctl-kernel-make-20261028.log`; maintained recipes
used the same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes and reproducible
paths. Whole-object/debug-path identity is not claimed.

Frontend review: existing format-5 targets and generated inputs support this
addition without new build-bsd C/backend options, staging or manual changes.
No runtime tests ran. Sysctl enumeration/read/write, Capsicum/MAC permissions,
jail/VNET behavior and concurrent registration/removal require linked-kernel
tests. Full kernel/world/pkgbase/bootstrap and performance gates remain open.
Make remains production/default; module count remains 45. No host installation
or BIP changes occurred.

### Native kernel environment and event handlers

Added //sys/kern:generic_environment_events_object_files for kern_environment.c
and subr_eventhandler.c, selected by the maintained GENERIC Makefile.
Dependencies declare CK/VM and MAC headers. No runtime source changed.

Evidence: `/usr/obj/usr/src/bazel-environment-events-kernel-20261028/qualification`.
Both objects match Make symbols, raw CTF, complete allocated-section inventories,
section bytes/size/type/flags/alignment and runtime relocation records and
associations. Reference log:
`/usr/obj/usr/src/bazel-environment-events-kernel-make-20261028.log`;
maintained recipes used the same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes
and reproducible paths. Whole-object/debug-path identity is not claimed.

Frontend review: existing format-5 targets support these objects without new
build-bsd C/backend options, staging or manual changes. No runtime tests ran.
Environment get/set/unset permissions and boot tunables, event registration/
invocation/deregistration and concurrent handler drain require linked-kernel
tests. Full kernel/world/pkgbase/bootstrap and performance gates remain open.
Make remains production/default; module count remains 45. No host installation
or BIP changes occurred.

### Native module registration and kernel linker management

Added //sys/kern:generic_module_linker_object_files for kern_module.c and
kern_linker.c, selected by the maintained GENERIC Makefile. Dependencies declare
CK/VM, MAC, VNET, debugger, HWPMC and the native generated linker interface,
plus DDB/KLD/HWPMC_HOOKS/HWT_HOOKS configuration headers. No loader source changed.

Evidence: `/usr/obj/usr/src/bazel-module-linker-kernel-20261028/qualification`.
Both objects match Make symbols, raw CTF, complete allocated-section inventories,
section bytes/size/type/flags/alignment and runtime relocation records and
associations. All four option headers match Make bytes. Reference log:
`/usr/obj/usr/src/bazel-module-linker-kernel-make-20261028.log`; maintained
recipes used the same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes and
reproducible paths. Whole-object/debug-path identity is not claimed.

Frontend review: existing format-5 targets and generated inputs support these
objects without new build-bsd C/backend options, staging or manual changes.
No runtime tests or host module loads ran. Module dependencies, registration,
load/unload, references, denial paths and tracing hooks require linked-kernel
VM qualification. ELF loader backends and final kernel linking remain separate
work. Full world/pkgbase/bootstrap and performance gates remain open. Make
remains production/default; converted module count remains 45. No host
installation or BIP changes occurred.

### Native kernel ELF loader backends

Added //sys/kern:generic_elf_loaders_object_files for link_elf.c and
link_elf_obj.c, selected by the maintained GENERIC Makefile. Dependencies
include the generated linker interface, native DDB/GDB options, MAC/VNET/VM,
zlib and debugger CTF headers. kern_ctf.c is an explicit textual dependency,
matching its inclusion by both loaders. No loader source behavior changed.

Evidence: `/usr/obj/usr/src/bazel-elf-loaders-kernel-20261028/qualification`.
Both objects match Make symbols, raw CTF, complete allocated-section inventories,
section bytes/size/type/flags/alignment and runtime relocation records and
associations. Both option headers match Make bytes. Reference log:
`/usr/obj/usr/src/bazel-elf-loaders-kernel-make-20261028.log`; maintained recipes
used the same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes and reproducible
paths. Whole-object/debug-path identity is not claimed.

Frontend review: existing format-5 targets and generated inputs support these
objects without new build-bsd C/backend options, staging or manual changes.
No runtime tests or host module loads ran. ELF validation, relocations, symbol
resolution, CTF loading, malformed-input cleanup and MAC denial require
linked-kernel VM qualification. Architecture relocation code and full kernel
linking remain separate work. Full world/pkgbase/bootstrap and performance
gates remain open. Make stays production/default; module count remains 45.
No host installation or BIP changes occurred.

### Native kernel object dispatch and preload metadata

Added //sys/kern:generic_kobj_preload_object_files for subr_kobj.c and
subr_module.c, selected by the maintained GENERIC Makefile. Dependencies
include CK/VM, debugger and generated DDB options. The normal kernel branch
is compiled; the separate subr_kobj TEST branch is not enabled. No dispatch
or preload source behavior changed.

Evidence: `/usr/obj/usr/src/bazel-kobj-preload-kernel-20261028/qualification`.
Both objects match Make symbols, raw CTF, complete allocated-section inventories,
section bytes/size/type/flags/alignment and runtime relocation records and
associations. The debugger option header matches Make bytes. Reference log:
`/usr/obj/usr/src/bazel-kobj-preload-kernel-make-20261028.log`; maintained
recipes used the same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes and
reproducible paths. Whole-object/debug-path identity is not claimed.

Frontend review: existing format-5 targets support these additions without
new build-bsd C/backend options, staging or manual changes. No runtime tests
ran. Class inheritance, method lookup/cache, class lifetime and boot preload
metadata processing require linked-kernel tests. Full kernel/world/pkgbase/
bootstrap and performance gates remain open. Make remains production/default;
module count remains 45. No host installation or BIP changes occurred.

### Native kernel startup and init-process creation

Added //sys/kern:generic_init_object_files for init_main.c, selected by the
maintained GENERIC Makefile. Dependencies declare CK/VM, MAC, audit, debugger
and native generated DDB/KDB/INIT_PATH/VERBOSE_SYSINIT options. Init-path policy
comes from config output; no replacement startup path or runtime source change
was introduced.

Evidence: `/usr/obj/usr/src/bazel-init-kernel-20261028/qualification`.
The object matches Make symbols, raw CTF, complete allocated-section inventory,
section bytes/size/type/flags/alignment and runtime relocation records and
associations. All four option headers match Make bytes. Reference log:
`/usr/obj/usr/src/bazel-init-kernel-make-20261028.log`; maintained recipes used
the same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes and reproducible paths.
Whole-object/debug-path identity is not claimed.

Frontend review: existing format-5 targets and generated inputs cover this
addition without new build-bsd C/backend options, staging or manual changes.
No boot/runtime tests ran. SYSINIT ordering, process-zero initialization,
root mounting and PID 1 startup require a linked kernel and normal-system VM
tests. Full kernel/world/pkgbase/bootstrap and performance gates remain open.
Make remains production/default; module count remains 45. No host installation
or BIP changes occurred.

### Native clock and clock-source handling

Added //sys/kern:generic_clocks_object_files for kern_clock.c and
kern_clocksource.c, selected by the maintained GENERIC Makefile. Dependencies
declare CK/VM, debugger, HWPMC, generated bus/device interfaces and native
DDB/KDB/HWPMC_HOOKS/NTP/DEVICE_POLLING/WATCHDOG options. No clock source changed.

Evidence: `/usr/obj/usr/src/bazel-clocks-kernel-20261028/qualification`.
Both objects match Make symbols, raw CTF, complete allocated-section inventories,
section bytes/size/type/flags/alignment and runtime relocation records and
associations. All six option headers match Make bytes. Reference log:
`/usr/obj/usr/src/bazel-clocks-kernel-make-20261028.log`; maintained recipes
used the same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes and reproducible
paths. Whole-object/debug-path identity is not claimed.

Frontend review: existing format-5 targets and generated inputs cover these
objects without new build-bsd C/backend options, staging or manual changes.
No runtime tests ran. Clock accuracy, periodic/oneshot events, idle transitions,
watchdog behavior and interrupt/CPU overhead require linked-kernel tests.
Alternate polling/watchdog configurations remain separate qualification.
Full kernel/world/pkgbase/bootstrap and performance gates remain open. Make
remains production/default; module count remains 45. No host installation
or BIP changes occurred.

### Native event timers and timer descriptors

Added //sys/kern:generic_event_timers_object_files for kern_et.c and
sys_timerfd.c, selected by the maintained GENERIC Makefile. Dependencies
declare CK/VM and audit headers. No timer source behavior changed. POSIX timer
handling in the previously converted kern_time.c is not counted again.

Evidence: `/usr/obj/usr/src/bazel-event-timers-kernel-20261028/qualification`.
Both objects match Make symbols, raw CTF, complete allocated-section inventories,
section bytes/size/type/flags/alignment and runtime relocation records and
associations. Reference log:
`/usr/obj/usr/src/bazel-event-timers-kernel-make-20261028.log`;
maintained recipes used the same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes
and reproducible paths. Whole-object/debug-path identity is not claimed.

Frontend review: existing format-5 targets cover these objects without new
build-bsd C/backend options, staging or manual changes. No runtime tests ran.
Event-timer registration/selection, timerfd expiration counts, periodic and
absolute timers, nonblocking reads, poll/kqueue and concurrent close require
linked-kernel tests. Full kernel/world/pkgbase/bootstrap and performance gates
remain open. Make remains production/default; module count remains 45.
No host installation or BIP changes occurred.

### Native event descriptors and filesystem notifications

Added //sys/kern:generic_notifications_object_files for sys_eventfd.c and
vfs_inotify.c, selected by the maintained GENERIC Makefile. Dependencies
declare CK/VM, audit and generated KTRACE options. No runtime source changed.

Evidence: `/usr/obj/usr/src/bazel-notifications-kernel-20261028/qualification`.
Both objects match Make symbols, raw CTF, complete allocated-section inventories,
section bytes/size/type/flags/alignment and runtime relocation records and
associations. The tracing option header matches Make bytes. Reference log:
`/usr/obj/usr/src/bazel-notifications-kernel-make-20261028.log`; maintained
recipes used the same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes and
reproducible paths. Whole-object/debug-path identity is not claimed.

Frontend review: existing format-5 targets cover these additions without new
build-bsd C/backend options, staging or manual changes. No runtime tests ran.
Eventfd counter/semaphore/nonblocking behavior, poll/kqueue, filesystem watch
permissions, rename/unlink/overflow and concurrent close/watch removal need
linked-kernel tests. Full kernel/world/pkgbase/bootstrap and performance gates
remain open. Make remains production/default; module count remains 45.
No host installation or BIP changes occurred.

### Native kernel threads and POSIX scheduling entry points

Added //sys/kern:generic_kthread_posix_object_files for kern_kthread.c,
p1003_1b.c and posix4_mib.c, selected by the maintained GENERIC Makefile.
Dependencies declare CK/VM and generated POSIX options. No runtime source
changed; the previously converted ksched.c is not counted again.

Evidence: `/usr/obj/usr/src/bazel-kthread-posix-kernel-20261028/qualification`.
All three objects match Make symbols, raw CTF, complete allocated-section
inventories, section bytes/size/type/flags/alignment and runtime relocation
records/associations. The POSIX header matches Make bytes. Reference log:
`/usr/obj/usr/src/bazel-kthread-posix-kernel-make-20261028.log`; maintained
recipes used the same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes and
reproducible paths. Whole-object/debug-path identity is not claimed.

Frontend review: existing format-5 targets support these additions without
new build-bsd C/backend options, staging or manual changes. No runtime tests
ran. Kernel-thread creation/suspend/resume/exit, scheduling-policy permissions,
parameter handling and POSIX sysctl reporting require linked-kernel tests.
Full kernel/world/pkgbase/bootstrap and performance gates remain open. Make
remains production/default; module count remains 45. No host installation
or BIP changes occurred.

### Native getrandom syscall and UUID generation

Added //sys/kern:generic_random_uuid_object_files for sys_getrandom.c and
kern_uuid.c, selected by the maintained GENERIC Makefile. Dependencies declare
CK/VM and network/interface/link-address headers. No entropy or UUID source
behavior changed. This batch does not qualify entropy provider implementations.

Evidence: `/usr/obj/usr/src/bazel-random-uuid-kernel-20261028/qualification`.
Both objects match Make symbols, raw CTF, complete allocated-section inventories,
section bytes/size/type/flags/alignment and runtime relocation records and
associations. Reference log:
`/usr/obj/usr/src/bazel-random-uuid-kernel-make-20261028.log`; maintained recipes
used the same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes and reproducible
paths. Whole-object/debug-path identity is not claimed.

Frontend review: existing format-5 targets cover these objects without new
build-bsd C/backend options, staging or manual changes. No runtime tests ran.
Early-boot entropy, blocking/nonblocking/error behavior, interrupted reads and
UUID generation under jail/concurrency conditions require linked-kernel tests.
Full kernel/world/pkgbase/bootstrap and performance gates remain open. Make
remains production/default; module count remains 45. No host installation
or BIP changes occurred.

### Native kernel logging and message buffers

Added //sys/kern:generic_logging_object_files for subr_log.c and subr_msgbuf.c,
selected by the maintained GENERIC Makefile. Dependencies declare CK/VM headers.
No logging source behavior changed.

Evidence: `/usr/obj/usr/src/bazel-logging-kernel-20261028/qualification`.
Both objects match Make symbols, raw CTF, complete allocated-section inventories,
section bytes/size/type/flags/alignment and runtime relocation records and
associations. Reference log:
`/usr/obj/usr/src/bazel-logging-kernel-make-20261028.log`; maintained recipes
used the same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes and reproducible
paths. Whole-object/debug-path identity is not claimed.

Frontend review: existing format-5 targets cover these objects without new
build-bsd C/backend options, staging or manual changes. No runtime tests ran.
Message delivery, wraparound, read/poll notification, asynchronous readers and
normal logging-service integration require linked-kernel tests. Full kernel/
world/pkgbase/bootstrap and performance gates remain open. Make remains
production/default; module count remains 45. No host installation or BIP changes.

### Native kernel formatted output and sbuf

Added //sys/kern:generic_formatted_output_object_files for subr_prf.c and
subr_sbuf.c, selected by the maintained GENERIC Makefile. Dependencies declare
CK/VM, debugger and generated DDB/PRINTF options. These compile the kernel
branches of shared sources; existing userland targets are unchanged.

Evidence: `/usr/obj/usr/src/bazel-formatted-output-kernel-20261028/qualification`.
Both objects match Make symbols, raw CTF, complete allocated-section inventories,
section bytes/size/type/flags/alignment and runtime relocation records and
associations. Both option headers match Make bytes. Reference log:
`/usr/obj/usr/src/bazel-formatted-output-kernel-make-20261028.log`; maintained
recipes used the same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes and
reproducible paths. Whole-object/debug-path identity is not claimed.

Frontend review: existing format-5 targets cover these additions without new
build-bsd C/backend options, staging or manual changes. No runtime tests ran.
Console/message output, formatting edge cases, sbuf growth/drain/error paths
and concurrent logging require linked-kernel tests. Full kernel/world/pkgbase/
bootstrap and performance gates remain open. Make remains production/default;
module count remains 45. No host installation or BIP changes occurred.

### Native UIO helpers and range locking

Added //sys/kern:generic_uio_rangelock_object_files for subr_uio.c and
kern_rangelock.c, selected by the maintained GENERIC Makefile. Dependencies
declare CK/VM, debugger and generated DDB options. No I/O or locking source
behavior changed.

Evidence: `/usr/obj/usr/src/bazel-uio-rangelock-kernel-20261028/qualification`.
Both objects match Make symbols, raw CTF, complete allocated-section inventories,
section bytes/size/type/flags/alignment and runtime relocation records and
associations. The debugger option header matches Make bytes. Reference log:
`/usr/obj/usr/src/bazel-uio-rangelock-kernel-make-20261028.log`; maintained
recipes used the same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes and
reproducible paths. Whole-object/debug-path identity is not claimed.

Frontend review: existing format-5 targets cover these additions without new
build-bsd C/backend options, staging or manual changes. No runtime tests ran.
UIO partial copies/faults, range overlap/contention, lock lifetime and concurrent
filesystem I/O require linked-kernel tests. Disk I/O and memory/CPU performance
are not established by object parity. Full kernel/world/pkgbase/bootstrap gates
remain open. Make stays production/default; module count remains 45. No host
installation or BIP changes occurred.

### Native SMR and pctrie helpers

Added //sys/kern:generic_smr_pctrie_object_files for subr_smr.c and
subr_pctrie.c, selected by the maintained GENERIC Makefile. Dependencies
declare CK/VM, debugger and generated DDB options. No reclamation or tree
algorithm source changed.

Evidence: `/usr/obj/usr/src/bazel-smr-pctrie-kernel-20261028/qualification`.
Both objects match Make symbols, raw CTF, complete allocated-section inventories,
section bytes/size/type/flags/alignment and runtime relocation records and
associations. The debugger option header matches Make bytes. Reference log:
`/usr/obj/usr/src/bazel-smr-pctrie-kernel-make-20261028.log`; maintained recipes
used the same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes and reproducible
paths. Whole-object/debug-path identity is not claimed.

Frontend review: existing format-5 targets cover these additions without new
build-bsd C/backend options, staging or manual changes. No runtime tests ran.
Concurrent lookup/update, grace periods, reclamation, memory pressure and
CPU/memory costs require linked-kernel tests. Full kernel/world/pkgbase/
bootstrap and performance gates remain open. Make stays production/default;
module count remains 45. No host installation or BIP changes occurred.

### Native counters and blist; machine-header diagnostic paths

Added //sys/kern:generic_counter_blist_object_files for subr_counter.c and
subr_blist.c, selected by the maintained GENERIC Makefile, with CK/VM headers.
Initial comparison caught a real counter-object mismatch: __FILE__ in the
machine/counter.h assertion contained Bazel's virtual-header path. Shared
amd64 kernel flags now map that virtual include root to the logical machine/
path using -fmacro-prefix-map and Bazel's configuration-derived BINDIR.
No literal output configuration or source-code substitute is used. Runtime
algorithms are unchanged; diagnostic paths now match Make.

Evidence: `/usr/obj/usr/src/bazel-counter-blist-kernel-r2-20261028/qualification`.
Both objects match Make symbols, raw CTF, complete allocated-section inventories,
section bytes/size/type/flags/alignment and runtime relocation records and
associations. Initial failed comparison remains in the non-r2 run. Reference:
`/usr/obj/usr/src/bazel-counter-blist-kernel-make-20261028.log`; maintained
recipes used the same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes and
reproducible paths. Whole-object/debug-path identity is not claimed.
Shared-flag regression: `/usr/obj/usr/src/bazel-machine-path-regression-20261028/qualification`;
kern_thr.o, kern_thread.o and sched_ule.o pass the same full object comparisons.
This is a bounded regression check, not a full-kernel/module rebuild.

Frontend review: existing format-5 targets and compiler action inputs cover
these changes without new build-bsd C/backend options, staging or manual
changes. No runtime tests ran. Counter aggregation/reset under concurrency,
blist fragmentation/exhaustion and resource costs require linked-kernel tests.
Full kernel/world/pkgbase/bootstrap and performance gates remain open. Make
remains production/default; module count remains 45. No host installation
or BIP changes occurred.

### Native hash tables and identifier allocation

Added //sys/kern:generic_hash_unit_object_files for subr_hash.c and subr_unit.c,
selected by the maintained GENERIC Makefile. Dependencies declare CK/VM,
debugger and generated DDB options. The kernel branch of subr_unit.c is built;
no allocator/hash algorithm source changed.

Evidence: `/usr/obj/usr/src/bazel-hash-unit-kernel-20261028/qualification`.
Both objects match Make symbols, raw CTF, complete allocated-section inventories,
section bytes/size/type/flags/alignment and runtime relocation records and
associations. The debugger option header matches Make bytes. Reference log:
`/usr/obj/usr/src/bazel-hash-unit-kernel-make-20261028.log`; maintained recipes
used the same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes and reproducible
paths. Whole-object/debug-path identity is not claimed.

Frontend review: existing format-5 targets cover these additions without new
build-bsd C/backend options, staging or manual changes. No runtime tests ran.
Hash lookup/update concurrency, identifier exhaustion/reuse and allocation
resource costs require linked-kernel tests. Full kernel/world/pkgbase/bootstrap
and performance gates remain open. Make remains production/default; module
count remains 45. No host installation or BIP changes occurred.

### Native NFSv4 ACL helpers and VFS ACL entry points

Added //sys/kern:generic_acl_object_files for subr_acl_nfs4.c and vfs_acl.c,
selected by the maintained GENERIC Makefile. Dependencies declare CK/VM,
MAC and audit headers. subr_acl_posix1e.c is conditional on ufs_acl in
sys/conf/files and is not selected by this configuration; that variant remains
pending. No ACL algorithm or permission source behavior changed.

Evidence: `/usr/obj/usr/src/bazel-acl-kernel-20261028/qualification`.
Both objects match Make symbols, raw CTF, complete allocated-section inventories,
section bytes/size/type/flags/alignment and runtime relocation records and
associations. Reference log: `/usr/obj/usr/src/bazel-acl-kernel-make-20261028.log`;
maintained recipes used the same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes
and reproducible paths. Whole-object/debug-path identity is not claimed.

Frontend review: existing format-5 targets cover these objects without new
build-bsd C/backend options, staging or manual changes. No runtime tests ran.
ACL inheritance/order, allow/deny, get/set/remove, descriptor/path operations
and MAC/audit outcomes need linked-kernel/filesystem tests. Full kernel/world/
pkgbase/bootstrap and performance gates remain open. Make stays production/
default; module count remains 45. No host installation or BIP changes occurred.

### Native VFS extended attributes

Added //sys/kern:generic_extattr_object_files for vfs_extattr.c, selected by
the maintained GENERIC Makefile. Dependencies declare CK/VM, MAC, audit and
generated Capsicum options. No extended-attribute or policy source changed.

Evidence: `/usr/obj/usr/src/bazel-extattr-kernel-20261028/qualification`.
The object matches Make symbols, raw CTF, complete allocated-section inventory,
section bytes/size/type/flags/alignment and runtime relocation records and
associations. The Capsicum header matches Make bytes. Reference log:
`/usr/obj/usr/src/bazel-extattr-kernel-make-20261028.log`; maintained recipes
used the same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes and reproducible
paths. Whole-object/debug-path identity is not claimed.

Frontend review: existing format-5 targets cover this addition without new
build-bsd C/backend options, staging or manual changes. No runtime tests ran.
Get/set/list/remove, namespace and MAC permissions, path/fd/symlink semantics,
persistence and audit output require linked-kernel/filesystem tests. Full
kernel/world/pkgbase/bootstrap and performance gates remain open. Make stays
production/default; module count remains 45. No host installation or BIP changes.

### Native VFS pathname lookup

Added //sys/kern:generic_lookup_object_files for vfs_lookup.c, selected by
the maintained GENERIC Makefile. Dependencies declare CK/VM, MAC, audit and
generated Capsicum/KTRACE options. No lookup or security source changed.

Evidence: `/usr/obj/usr/src/bazel-lookup-kernel-20261028/qualification`.
The object matches Make symbols, raw CTF, complete allocated-section inventory,
section bytes/size/type/flags/alignment and runtime relocation records and
associations. Both option headers match Make bytes. Reference log:
`/usr/obj/usr/src/bazel-lookup-kernel-make-20261028.log`; maintained recipes
used the same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes and reproducible
paths. Whole-object/debug-path identity is not claimed.

Frontend review: existing format-5 targets cover this addition without new
build-bsd C/backend options, staging or manual changes. No runtime tests ran.
Symlink/dotdot traversal, dirfd-relative lookup, jail/Capsicum/MAC boundaries,
rename/unmount races and lookup performance require linked-kernel/filesystem
tests. Full kernel/world/pkgbase/bootstrap and performance gates remain open.
Make remains production/default; module count remains 45. No host installation
or BIP changes occurred.

### Native VFS name cache

Added //sys/kern:generic_namecache_object_files for vfs_cache.c, selected by
the maintained GENERIC Makefile. Dependencies declare CK/VM, MAC, audit,
debugger and generated DDB/KTRACE options. No caching or lookup source changed.

Evidence: `/usr/obj/usr/src/bazel-namecache-kernel-20261028/qualification`.
The object matches Make symbols, raw CTF, complete allocated-section inventory,
section bytes/size/type/flags/alignment and runtime relocation records and
associations. Both option headers match Make bytes. Reference log:
`/usr/obj/usr/src/bazel-namecache-kernel-make-20261028.log`; maintained recipes
used the same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes and reproducible
paths. Whole-object/debug-path identity is not claimed.

Frontend review: existing format-5 targets cover this addition without new
build-bsd C/backend options, staging or manual changes. No runtime tests ran.
Positive/negative cache lookup, invalidation, rename/unlink/unmount races,
SMR reclamation, path permissions and lookup/memory costs require linked-kernel
filesystem tests. Full kernel/world/pkgbase/bootstrap and performance gates
remain open. Make stays production/default; module count remains 45. No host
installation or BIP changes occurred.

### Native VFS vnode operations

Added //sys/kern:generic_vnops_object_files for vfs_vnops.c, selected by
maintained GENERIC Make. Dependencies declare CK/VM, MAC, audit, HWPMC/HWT,
generated options, network address headers used by disk.h and PCG headers
used by prng.h. Extended the existing PCG target visibility to sys/kern.
No runtime source or security behavior changed.

Evidence: `/usr/obj/usr/src/bazel-vnops-kernel-r4-20261028/qualification`.
The object matches Make symbols, raw CTF, complete allocated-section inventory,
section bytes/size/type/flags/alignment and runtime relocation records and
associations. HWPMC/HWT option headers match Make bytes. Reference log:
`/usr/obj/usr/src/bazel-vnops-kernel-make-20261028.log`; maintained recipes
used the same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes and reproducible
paths. Earlier failed attempts retain evidence of undeclared network/PCG
headers; these were resolved with declared dependencies. Whole-object/debug-path
identity is not claimed.

Frontend review: existing format-5 target inputs cover this addition without
new build-bsd C/backend options, staging or manual changes. No runtime tests
ran. File read/write, mmap hooks, locking, copy operations, MAC/audit decisions
and concurrent filesystem performance still require a linked kernel and runtime
tests. Full kernel/world/pkgbase/bootstrap and performance gates remain open.
Make stays production/default; module count remains 45. No host installation
or BIP changes occurred.

### Native VFS defaults, hashing and initialization

Added //sys/kern:generic_vfs_defaults_object_files for vfs_default.c,
vfs_hash.c and vfs_init.c, selected by maintained GENERIC Make. Native rules
use declared CK/VM, MAC and audit headers. No runtime source changed.

Evidence: `/usr/obj/usr/src/bazel-vfs-defaults-kernel-20261028/qualification`.
All three objects match Make symbols, raw CTF, complete allocated-section
inventories, section bytes/size/type/flags/alignment and runtime relocation
records and associations. Reference log:
`/usr/obj/usr/src/bazel-vfs-defaults-kernel-make-20261028.log`; maintained
recipes used the same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes and
reproducible paths. Whole-object/debug-path identity is not claimed.

Frontend review: existing format-5 target inputs cover this addition without
new build-bsd C/backend options, staging or manual changes. No runtime tests
ran. Filesystem registration/unregistration, vnode hash concurrency, fallback
operation dispatch, access checks and VM-backed reads still require a linked
kernel and runtime tests. Full kernel/world/pkgbase/bootstrap and performance
gates remain open. Make stays production/default; module count remains 45.
No host installation or BIP changes occurred.

### Native VFS mount and root mount

Added //sys/kern:generic_mount_object_files for vfs_mount.c and
vfs_mountroot.c, selected by maintained GENERIC Make. Dependencies include
CK/VM, MAC/audit, GEOM, network address and radix headers. Root-device options
are extracted from native config output, not synthesized. No runtime source
or mounting policy changed.

Evidence: `/usr/obj/usr/src/bazel-mount-kernel-20261028/qualification`.
Both objects match Make symbols, raw CTF, complete allocated-section
inventories, section bytes/size/type/flags/alignment and runtime relocation
records and associations. opt_rootdevname.h matches Make bytes. Reference log:
`/usr/obj/usr/src/bazel-mount-kernel-make-20261028.log`; maintained recipes
used the same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes and reproducible
paths. Whole-object/debug-path identity is not claimed.

Frontend review: existing format-5 target inputs cover this addition without
new build-bsd C/backend options, staging or manual changes. No runtime tests
ran. Root filesystem discovery, mount option errors, privilege/jail/MAC checks,
mount/unmount races and filesystem I/O require linked-kernel qualification.
The recorded 2026-10-03 ZFS/filedesc WITNESS issue was consulted; this build
comparison neither diagnoses nor fixes it. Full kernel/world/pkgbase/bootstrap
and performance gates remain open. Make stays production/default; module
count remains 45. No host installation or BIP changes occurred.

### Native VFS system calls

Added //sys/kern:generic_vfs_syscalls_object_files for vfs_syscalls.c,
selected by maintained GENERIC Make. Dependencies declare CK/VM, MAC/audit,
network address headers, devfs headers and generated Capsicum/KTRACE options.
The devfs public-header target now permits its sys/kern consumer. No runtime
source or authorization behavior changed.

Evidence: `/usr/obj/usr/src/bazel-vfs-syscalls-kernel-20261028/qualification`.
The object matches Make symbols, raw CTF, complete allocated-section inventory,
section bytes/size/type/flags/alignment and runtime relocation records and
associations. Capsicum/KTRACE option headers match Make bytes. Reference log:
`/usr/obj/usr/src/bazel-vfs-syscalls-kernel-make-20261028.log`; maintained
recipes used the same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes and
reproducible paths. Whole-object/debug-path identity is not claimed.

Frontend review: existing format-5 target inputs cover this addition without
new build-bsd C/backend options, staging or manual changes. No runtime tests
ran. Open/stat/chmod/chown, chroot, directory operations, copy-range behavior,
MAC/Capsicum enforcement and emitted audit records require linked-kernel tests.
Full kernel/world/pkgbase/bootstrap and performance gates remain open. Make
stays production/default; module count remains 45. No host installation or
BIP changes occurred.

### Native VFS vnode lifecycle

Added //sys/kern:generic_vfs_lifecycle_object_files for vfs_subr.c, selected
by maintained GENERIC Make. Dependencies declare CK/VM, MAC, debugger headers
and generated DDB/watchdog options. No lifecycle or security source changed.

Evidence: `/usr/obj/usr/src/bazel-vfs-lifecycle-kernel-20261028/qualification`.
The object matches Make symbols, raw CTF, complete allocated-section inventory,
section bytes/size/type/flags/alignment and runtime relocation records and
associations. DDB/watchdog option headers match Make bytes. Reference log:
`/usr/obj/usr/src/bazel-vfs-lifecycle-kernel-make-20261028.log`; maintained
recipes used the same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes and
reproducible paths. Whole-object/debug-path identity is not claimed.

Frontend review: existing format-5 target inputs cover this addition without
new build-bsd C/backend options, staging or manual changes. No runtime tests
ran. Vnode allocation/reclamation, syncer work, detach races, watchdog/debugger
paths and filesystem CPU/memory/I/O costs require linked-kernel testing.
Full kernel/world/pkgbase/bootstrap and performance gates remain open. Make
stays production/default; module count remains 45. No host installation or
BIP changes occurred.

### Native buffered and clustered VFS I/O

Added //sys/kern:generic_vfs_buffer_io_object_files for vfs_bio.c and
vfs_cluster.c, selected by maintained GENERIC Make. Dependencies declare
CK/VM, GEOM, debugger headers and generated DDB options. No buffer-cache,
clustering or disk I/O algorithm changed.

Evidence: `/usr/obj/usr/src/bazel-vfs-buffer-io-kernel-20261028/qualification`.
Both objects match Make symbols, raw CTF, complete allocated-section
inventories, section bytes/size/type/flags/alignment and runtime relocation
records and associations. The DDB option header matches Make bytes. Reference
log: `/usr/obj/usr/src/bazel-vfs-buffer-io-kernel-make-20261028.log`;
maintained recipes used the same SDK compiler, 16 jobs, DEBUG=-g,
WITH_CTF=yes and reproducible paths. Whole-object/debug-path identity is not
claimed.

Frontend review: existing format-5 target inputs cover this addition without
new build-bsd C/backend options, staging or manual changes. No runtime tests
ran. Sequential/random buffered I/O, read-ahead, clustered writes, dirty-buffer
pressure, flush/error handling, latency/throughput, CPU and memory consumption
need linked-kernel measurements. Object parity does not establish performance.
Full kernel/world/pkgbase/bootstrap and performance gates remain open. Make
stays production/default; module count remains 45. No host installation or
BIP changes occurred.

### Native asynchronous VFS I/O

Added //sys/kern:generic_vfs_aio_object_files for vfs_aio.c, selected as
standard by sys/conf/files and the maintained GENERIC Makefile. Dependencies
declare CK/VM and GEOM headers. No AIO source, compatibility flags or scheduling
behavior changed; this source requires no additional per-file option header.

Evidence: `/usr/obj/usr/src/bazel-vfs-aio-kernel-20261028/qualification`.
The object matches Make symbols, raw CTF, complete allocated-section inventory,
section bytes/size/type/flags/alignment and runtime relocation records and
associations. Reference log:
`/usr/obj/usr/src/bazel-vfs-aio-kernel-make-20261028.log`; maintained recipes
used the same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes and reproducible
paths. Whole-object/debug-path identity is not claimed.

Frontend review: existing format-5 target inputs cover this addition without
new build-bsd C/backend options, staging or manual changes. No runtime tests
ran. AIO submit/cancel/reap, completion signals/kevents, queue/resource limits,
list I/O, fsync ordering, process exit races and CPU/memory/disk costs require
linked-kernel tests. Compatibility syscall wrappers require separate coverage.
Full kernel/world/pkgbase/bootstrap and performance gates remain open. Make
stays production/default; module count remains 45. No host installation or
BIP changes occurred.

### Native VFS exports

Added //sys/kern:generic_vfs_export_object_files for vfs_export.c, selected
by maintained GENERIC Make. Dependencies declare CK/VM, network address/radix,
kernel RPC authentication headers and generated INET/INET6 options. The first
attempt exposed a missing VM dependency through mbuf.h; the declaration was
corrected. No export authorization or runtime source changed.

Evidence: `/usr/obj/usr/src/bazel-vfs-export-kernel-r2-20261028/qualification`.
The object matches Make symbols, raw CTF, complete allocated-section inventory,
section bytes/size/type/flags/alignment and runtime relocation records and
associations. INET/INET6 headers match Make bytes. Reference log:
`/usr/obj/usr/src/bazel-vfs-export-kernel-make-20261028.log`; maintained
recipes used the same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes and
reproducible paths. Whole-object/debug-path identity is not claimed.

Frontend review: existing format-5 target inputs cover this addition without
new build-bsd C/backend options, staging or manual changes. No runtime tests
ran. NFS exports, client network matching, default exports, anonymous credential
mapping, update/removal races and export-policy failures require linked-kernel
and network tests. Full kernel/world/pkgbase/bootstrap and performance gates
remain open. Make stays production/default; module count remains 45. No host
installation or BIP changes occurred.

### Native file locking

Added //sys/kern:generic_file_locks_object_files for kern_lockf.c, selected
by maintained GENERIC Make. Dependencies declare CK/VM headers and the
lock-debug option extracted from native config output. No locking algorithm
or runtime source changed.

Evidence: `/usr/obj/usr/src/bazel-file-locks-kernel-20261028/qualification`.
The object matches Make symbols, raw CTF, complete allocated-section inventory,
section bytes/size/type/flags/alignment and runtime relocation records and
associations. opt_debug_lockf.h matches Make bytes. Reference log:
`/usr/obj/usr/src/bazel-file-locks-kernel-make-20261028.log`; maintained
recipes used the same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes and
reproducible paths. Whole-object/debug-path identity is not claimed.

Frontend review: existing format-5 target inputs cover this addition without
new build-bsd C/backend options, staging or manual changes. No runtime tests
ran. Advisory lock contention, range splitting/merging, deadlock detection,
interruption/cancellation, owner cleanup and remote lock interactions require
linked-kernel tests. DEBUG_LOCKF-enabled configurations need separate coverage.
Full kernel/world/pkgbase/bootstrap and performance gates remain open. Make
stays production/default; module count remains 45. No host installation or
BIP changes occurred.

### Native memory descriptors and scatter/gather lists

Added //sys/kern:generic_memory_descriptors_object_files for subr_memdesc.c
and subr_sglist.c, selected by maintained GENERIC Make. Dependencies declare
CK/VM headers. No runtime source or memory mapping algorithm changed.

Evidence: `/usr/obj/usr/src/bazel-memory-descriptors-kernel-20261028/qualification`.
Both objects match Make symbols, raw CTF, complete allocated-section
inventories, section bytes/size/type/flags/alignment and runtime relocation
records and associations. Reference log:
`/usr/obj/usr/src/bazel-memory-descriptors-kernel-make-20261028.log`;
maintained recipes used the same SDK compiler, 16 jobs, DEBUG=-g,
WITH_CTF=yes and reproducible paths. Whole-object/debug-path identity is not
claimed.

Frontend review: existing format-5 target inputs cover this addition without
new build-bsd C/backend options, staging or manual changes. No runtime tests
ran. Page boundaries, mbuf/uio translation, segment coalescing and exhaustion,
DMA consumers and CPU/memory/I/O costs require linked-kernel/driver tests.
Full kernel/world/pkgbase/bootstrap and performance gates remain open. Make
stays production/default; module count remains 45. No host installation or
BIP changes occurred.

### Native x86 bus DMA

Added //sys/x86/x86:generic_busdma_object_files for busdma_bounce.c and
busdma_machdep.c, selected by maintained GENERIC Make. The shared
kern/subr_busdma_bounce.c is a declared textual dependency, matching its
inclusion by the x86 source. Dependencies include CK/VM, generated bus/device
interfaces, the internal busdma header and generated ACPI options.
subr_busdma_bufalloc.c is not selected by this GENERIC configuration.
No DMA algorithm or runtime source changed.

Evidence: `/usr/obj/usr/src/bazel-busdma-kernel-20261028/qualification`.
Both objects match Make symbols, raw CTF, complete allocated-section
inventories, section bytes/size/type/flags/alignment and runtime relocation
records and associations. opt_acpi.h matches Make bytes. Reference log:
`/usr/obj/usr/src/bazel-busdma-kernel-make-20261028.log`; maintained recipes
used the same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes and reproducible
paths. Whole-object/debug-path identity is not claimed.

Frontend review: existing format-5 target inputs cover this addition without
new build-bsd C/backend options, staging or manual changes. No runtime tests
ran. Bounce allocation/exhaustion, deferred callbacks, DMA mapping/sync,
IOMMU integration and CPU/memory/disk costs require linked-kernel/driver tests.
Full kernel/world/pkgbase/bootstrap and performance gates remain open. Make
stays production/default; module count remains 45. No host installation or
BIP changes occurred.

### Native device statistics and resource manager

Added //sys/kern:generic_device_resources_object_files for subr_devstat.c
and subr_rman.c, selected by maintained GENERIC Make. Dependencies declare
CK/VM, network address headers, generated bus/device interfaces, debugger
headers and generated DDB options. No runtime source changed.

Evidence: `/usr/obj/usr/src/bazel-device-resources-kernel-20261028/qualification`.
Both objects match Make symbols, raw CTF, complete allocated-section
inventories, section bytes/size/type/flags/alignment and runtime relocation
records and associations. opt_ddb.h matches Make bytes. Reference log:
`/usr/obj/usr/src/bazel-device-resources-kernel-make-20261028.log`;
maintained recipes used the same SDK compiler, 16 jobs, DEBUG=-g,
WITH_CTF=yes and reproducible paths. Whole-object/debug-path identity is not
claimed.

Frontend review: existing format-5 target inputs cover this addition without
new build-bsd C/backend options, staging or manual changes. No runtime tests
ran. Device attach/detach statistics, concurrent I/O accounting, resource
reservation/alignment/conflicts and release require linked-kernel/driver tests.
Full kernel/world/pkgbase/bootstrap and performance gates remain open. Make
stays production/default; module count remains 45. No host installation or
BIP changes occurred.

### Native disk helpers and range sets

Added //sys/kern:generic_disk_ranges_object_files for subr_disk.c and
subr_rangeset.c, selected by maintained GENERIC Make. Dependencies declare
CK/VM, GEOM disk headers, debugger headers and generated DDB/GEOM options.
No disk or range-set runtime algorithm changed.

Evidence: `/usr/obj/usr/src/bazel-disk-ranges-kernel-20261028/qualification`.
Both objects match Make symbols, raw CTF, complete allocated-section
inventories, section bytes/size/type/flags/alignment and runtime relocation
records and associations. DDB/GEOM option headers match Make bytes. Reference
log: `/usr/obj/usr/src/bazel-disk-ranges-kernel-make-20261028.log`;
maintained recipes used the same SDK compiler, 16 jobs, DEBUG=-g,
WITH_CTF=yes and reproducible paths. Whole-object/debug-path identity is not
claimed.

Frontend review: existing format-5 target inputs cover this addition without
new build-bsd C/backend options, staging or manual changes. No runtime tests
ran. Disk control and boundary/error handling, range insertion/removal/lookup,
allocation failures and concurrent consumers require linked-kernel tests.
Full kernel/world/pkgbase/bootstrap and performance gates remain open. Make
stays production/default; module count remains 45. No host installation or
BIP changes occurred.

### Native buffer rings and mutex pools

Added //sys/kern:generic_buffer_mutex_pools_object_files for subr_bufring.c
and kern_mtxpool.c, selected by maintained GENERIC Make. Dependencies declare
CK/VM headers. No allocation, locking or runtime source changed.

Evidence: `/usr/obj/usr/src/bazel-buffer-mutex-pools-kernel-20261028/qualification`.
Both objects match Make symbols, raw CTF, complete allocated-section
inventories, section bytes/size/type/flags/alignment and runtime relocation
records and associations. Reference log:
`/usr/obj/usr/src/bazel-buffer-mutex-pools-kernel-make-20261028.log`;
maintained recipes used the same SDK compiler, 16 jobs, DEBUG=-g,
WITH_CTF=yes and reproducible paths. Whole-object/debug-path identity is not
claimed.

Frontend review: existing format-5 target inputs cover this addition without
new build-bsd C/backend options, staging or manual changes. No runtime tests
ran. Buffer ring allocation/lifetime, concurrent producer/consumer callers,
mutex pool hashing/contention and allocation failures require linked-kernel
tests. Full kernel/world/pkgbase/bootstrap and performance gates remain open.
Make stays production/default; module count remains 45. No host installation
or BIP changes occurred.

### Native helper hooks and object storage

Added //sys/kern:generic_helper_hooks_object_files for kern_hhook.c,
kern_khelp.c and kern_osd.c, selected by maintained GENERIC Make. Dependencies
declare CK/VM and VNET/network headers. No runtime source changed.

Evidence: `/usr/obj/usr/src/bazel-helper-hooks-kernel-20261028/qualification`.
All three objects match Make symbols, raw CTF, complete allocated-section
inventories, section bytes/size/type/flags/alignment and runtime relocation
records and associations. Reference log:
`/usr/obj/usr/src/bazel-helper-hooks-kernel-make-20261028.log`; maintained
recipes used the same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes and
reproducible paths. Whole-object/debug-path identity is not claimed.

Frontend review: existing format-5 target inputs cover this addition without
new build-bsd C/backend options, staging or manual changes. No runtime tests
ran. Hook registration/removal, helper module lifetime, VNET teardown, object
slot allocation/destructors and concurrent callbacks require linked-kernel
tests. Full kernel/world/pkgbase/bootstrap and performance gates remain open.
Make stays production/default; module count remains 45. No host installation
or BIP changes occurred.

### Native device hints and firmware loading

Added //sys/kern:generic_hints_firmware_object_files for subr_hints.c and
subr_firmware.c, selected by maintained GENERIC Make. Dependencies declare
CK/VM and generated bus/device interfaces. No runtime source or firmware
search/loading policy changed.

Evidence: `/usr/obj/usr/src/bazel-hints-firmware-kernel-20261028/qualification`.
Both objects match Make symbols, raw CTF, complete allocated-section
inventories, section bytes/size/type/flags/alignment and runtime relocation
records and associations. Reference log:
`/usr/obj/usr/src/bazel-hints-firmware-kernel-make-20261028.log`; maintained
recipes used the same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes and
reproducible paths. Whole-object/debug-path identity is not claimed.

Frontend review: existing format-5 target inputs cover this addition without
new build-bsd C/backend options, staging or manual changes. No runtime tests
ran. Boot hints, driver firmware module/binary lookup, missing images,
privilege failures, concurrent loading and unload/reference cleanup require
linked-kernel/driver tests. Separate hardware package publication remains a
required end-to-end gate. Full kernel/world/pkgbase/bootstrap and performance
gates remain open. Make stays production/default; module count remains 45.
No host installation or BIP changes occurred.

### Native device-control notifications

Added //sys/kern:generic_devctl_object_files for kern_devctl.c, selected
by maintained GENERIC Make. Dependencies declare CK/VM, generated bus/device
interfaces, debugger headers and generated BUS/DDB options. No device event
or authorization source changed.

Evidence: `/usr/obj/usr/src/bazel-devctl-kernel-20261028/qualification`.
The object matches Make symbols, raw CTF, complete allocated-section inventory,
section bytes/size/type/flags/alignment and runtime relocation records and
associations. BUS/DDB option headers match Make bytes. Reference log:
`/usr/obj/usr/src/bazel-devctl-kernel-make-20261028.log`; maintained recipes
used the same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes and reproducible
paths. Whole-object/debug-path identity is not claimed.

Frontend review: existing format-5 target inputs cover this addition without
new build-bsd C/backend options, staging or manual changes. No runtime tests
ran. Device event delivery, privilege failures, poll/kqueue wakeups, queue
pressure, reader lifecycle and concurrent notifications require linked-kernel
tests. Full kernel/world/pkgbase/bootstrap and performance gates remain open.
Make stays production/default; module count remains 45. No host installation
or BIP changes occurred.

### Native bus framework

Added //sys/kern:generic_bus_object_files for subr_bus.c, selected by
maintained GENERIC Make. Dependencies declare CK/VM, generated bus/device
interfaces, VNET, IOMMU/PCI headers, debugger headers and generated BUS/DDB/
IOMMU options. No driver lifecycle or authorization source changed.

Evidence: `/usr/obj/usr/src/bazel-bus-kernel-20261028/qualification`.
The object matches Make symbols, raw CTF, complete allocated-section inventory,
section bytes/size/type/flags/alignment and runtime relocation records and
associations. BUS/DDB/IOMMU option headers match Make bytes. Reference log:
`/usr/obj/usr/src/bazel-bus-kernel-make-20261028.log`; maintained recipes
used the same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes and reproducible
paths. Whole-object/debug-path identity is not claimed.

Frontend review: existing format-5 target inputs cover this addition without
new build-bsd C/backend options, staging or manual changes. No runtime tests
ran. Driver probing/attach/detach, resources, properties, suspend/resume,
IOMMU integration and concurrent device management require linked-kernel and
hardware tests. Full kernel/world/pkgbase/bootstrap and performance gates
remain open. Make stays production/default; module count remains 45. No host
installation or BIP changes occurred.

### Native device initialization and common DMA

Added //sys/kern:generic_device_init_dma_object_files for subr_autoconf.c
and subr_bus_dma.c, selected by maintained GENERIC Make. Dependencies declare
CK/VM, generated bus/device interfaces, crypto-buffer headers, debugger headers
and generated BUS/DDB/IOMMU options. Extended the existing cryptodev header
target visibility to its sys/kern consumer. No runtime source changed.

Evidence: `/usr/obj/usr/src/bazel-device-init-dma-kernel-20261028/qualification`.
Both objects match Make symbols, raw CTF, complete allocated-section
inventories, section bytes/size/type/flags/alignment and runtime relocation
records and associations. BUS/DDB/IOMMU option headers match Make bytes.
Reference log: `/usr/obj/usr/src/bazel-device-init-dma-kernel-make-20261028.log`;
maintained recipes used the same SDK compiler, 16 jobs, DEBUG=-g,
WITH_CTF=yes and reproducible paths. Whole-object/debug-path identity is not
claimed.

Frontend review: existing format-5 target inputs cover this addition without
new build-bsd C/backend options, staging or manual changes. No runtime tests
ran. Deferred initialization ordering, DMA mbuf/uio/crypto buffer mapping,
segment boundaries, callback errors and IOMMU integration require linked-kernel
and driver tests. Full kernel/world/pkgbase/bootstrap and performance gates
remain open. Make stays production/default; module count remains 45. No host
installation or BIP changes occurred.

### Native physical I/O dispatch

Added //sys/kern:generic_physio_object_files for kern_physio.c, selected
by maintained GENERIC Make. Dependencies declare CK/VM and GEOM headers.
No runtime source or buffer-mapping behavior changed.

Evidence: `/usr/obj/usr/src/bazel-physio-kernel-20261028/qualification`.
The object matches Make symbols, raw CTF, complete allocated-section inventory,
section bytes/size/type/flags/alignment and runtime relocation records and
associations. Reference log:
`/usr/obj/usr/src/bazel-physio-kernel-make-20261028.log`; maintained recipes
used the same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes and reproducible
paths. Whole-object/debug-path identity is not claimed.

Frontend review: existing format-5 target inputs cover this addition without
new build-bsd C/backend options, staging or manual changes. No runtime tests
ran. User-buffer mapping/unmapping, partial transfers, device errors, resource
limits and CPU/memory/disk I/O costs require linked-kernel and device tests.
Full kernel/world/pkgbase/bootstrap and performance gates remain open. Make
stays production/default; module count remains 45. No host installation or
BIP changes occurred.

### Native character-device lifecycle

Added //sys/kern:generic_character_devices_object_files for kern_conf.c,
selected by maintained GENERIC Make. Dependencies declare CK/VM, devfs
internal headers, debugger headers and generated DDB options. No device
lifetime or runtime source changed.

Evidence: `/usr/obj/usr/src/bazel-character-devices-kernel-20261028/qualification`.
The object matches Make symbols, raw CTF, complete allocated-section inventory,
section bytes/size/type/flags/alignment and runtime relocation records and
associations. opt_ddb.h matches Make bytes. Reference log:
`/usr/obj/usr/src/bazel-character-devices-kernel-make-20261028.log`;
maintained recipes used the same SDK compiler, 16 jobs, DEBUG=-g,
WITH_CTF=yes and reproducible paths. Whole-object/debug-path identity is not
claimed.

Frontend review: existing format-5 target inputs cover this addition without
new build-bsd C/backend options, staging or manual changes. No runtime tests
ran. Device create/destroy, aliases, open references, deferred destruction,
private data destructors and devfs interactions require linked-kernel tests.
Full kernel/world/pkgbase/bootstrap and performance gates remain open. Make
stays production/default; module count remains 45. No host installation or
BIP changes occurred.

### Native clock and FAT timestamp conversion

Added //sys/kern:generic_clock_conversion_object_files for subr_clock.c
and subr_fattime.c, selected by maintained GENERIC Make. Dependencies declare
CK/VM and generated bus/device interfaces. No timestamp conversion source
changed. subr_clockcalib.c remains pending: its maintained recipe uses special
-O3 and MMX/SSE/SSE2 flags and removes -nostdinc, requiring separate treatment.

Evidence: `/usr/obj/usr/src/bazel-clock-conversion-kernel-20261028/qualification`.
Both objects match Make symbols, raw CTF, complete allocated-section
inventories, section bytes/size/type/flags/alignment and runtime relocation
records and associations. Reference log:
`/usr/obj/usr/src/bazel-clock-conversion-kernel-make-20261028.log`;
maintained recipes used the same SDK compiler, 16 jobs, DEBUG=-g,
WITH_CTF=yes and reproducible paths. Whole-object/debug-path identity is not
claimed.

Frontend review: existing format-5 target inputs cover this addition without
new build-bsd C/backend options, staging or manual changes. No runtime tests
ran. Calendar/leap-year and range boundaries, FAT timezone/precision behavior
and driver clock consumers require runtime tests. Full kernel/world/pkgbase/
bootstrap and performance gates remain open. Make stays production/default;
module count remains 45. No host installation or BIP changes occurred.

### Native clock calibration with special compiler flags

Added //sys/kern:generic_clock_calibration_object_files for subr_clockcalib.c,
selected by the maintained amd64 recipe. The target uses source-specific
-O3, -mmmx, -msse and -msse2 through native cc_library copts. Unlike Make's
recipe, native compilation retains -nostdinc: the source uses declared kernel
headers and requires no implicit host include search. No calibration algorithm
changed and no global kernel SIMD flags changed. This resolves the previous
clock-calibration compilation follow-up for amd64 GENERIC only.

Evidence: `/usr/obj/usr/src/bazel-clock-calibration-kernel-20261028/qualification`.
The object matches Make symbols, raw CTF, complete allocated-section inventory,
section bytes/size/type/flags/alignment and runtime relocation records and
associations. Reference log:
`/usr/obj/usr/src/bazel-clock-calibration-kernel-make-20261028.log`; the
maintained special recipe used the same SDK compiler, 16 jobs, DEBUG=-g,
WITH_CTF=yes and reproducible paths. Whole-object/debug-path identity is not
claimed.

Frontend review: existing format-5 target inputs cover this addition without
new build-bsd C/backend options, staging or manual changes. No runtime tests
ran. Boot-time frequency calibration, counter wrap, failure/fallback behavior
and floating-point context assumptions require linked-kernel boot tests.
Full kernel/world/pkgbase/bootstrap and performance gates remain open. Make
stays production/default; module count remains 45. No host installation or
BIP changes occurred.

### Native real-time clock management

Added //sys/kern:generic_rtc_object_files for subr_rtc.c, selected by
maintained GENERIC Make. Dependencies declare CK/VM, generated bus/device
and clock interfaces and generated FFCLOCK options. The clock header is
exposed from the existing native .m generator. No RTC runtime source changed.

Evidence: `/usr/obj/usr/src/bazel-rtc-kernel-20261028/qualification`.
The object matches Make symbols, raw CTF, complete allocated-section inventory,
section bytes/size/type/flags/alignment and runtime relocation records and
associations. opt_ffclock.h matches Make bytes. Reference log:
`/usr/obj/usr/src/bazel-rtc-kernel-make-20261028.log`; maintained recipes
used the same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes and reproducible
paths. Whole-object/debug-path identity is not claimed.

Frontend review: existing format-5 target inputs cover this addition without
new build-bsd C/backend options, staging or manual changes. No runtime tests
ran. RTC registration/removal, invalid clock values, hardware reads/writes,
resolution selection and deferred synchronization require linked-kernel and
driver tests. Full kernel/world/pkgbase/bootstrap and performance gates remain
open. Make stays production/default; module count remains 45. No host
installation or BIP changes occurred.

### Native NTP and feed-forward clock support

Added //sys/kern:generic_clock_discipline_object_files for kern_ntptime.c
and kern_ffclock.c, selected by maintained GENERIC Make. Dependencies declare
CK/VM, generated bus/device interfaces and native NTP/FFCLOCK options.
GENERIC enables PPS_SYNC but leaves FFCLOCK undefined: evidence covers the
configured disabled branch, not FFCLOCK-enabled behavior. No runtime source
or clock adjustment policy changed.

Evidence: `/usr/obj/usr/src/bazel-clock-discipline-kernel-20261028/qualification`.
Both objects match Make symbols, raw CTF, complete allocated-section
inventories, section bytes/size/type/flags/alignment and runtime relocation
records and associations. NTP/FFCLOCK headers match Make bytes. Reference log:
`/usr/obj/usr/src/bazel-clock-discipline-kernel-make-20261028.log`;
maintained recipes used the same SDK compiler, 16 jobs, DEBUG=-g,
WITH_CTF=yes and reproducible paths. Whole-object/debug-path identity is not
claimed.

Frontend review: existing format-5 target inputs cover this addition without
new build-bsd C/backend options, staging or manual changes. No runtime tests
ran. Clock adjustment permissions, PPS/leap/status handling and clock stability
require linked-kernel tests; FFCLOCK-enabled configurations need separate
qualification. Full kernel/world/pkgbase/bootstrap and performance gates remain
open. Make stays production/default; module count remains 45. No host
installation or BIP changes occurred.

### Native CPU idle and memory barriers

Added //sys/kern:generic_idle_membarrier_object_files for kern_idle.c and
kern_membarrier.c, selected by maintained GENERIC Make. Dependencies declare
CK/VM headers. No scheduler, memory-ordering or runtime source changed.

Evidence: `/usr/obj/usr/src/bazel-idle-membarrier-kernel-20261028/qualification`.
Both objects match Make symbols, raw CTF, complete allocated-section
inventories, section bytes/size/type/flags/alignment and runtime relocation
records and associations. Reference log:
`/usr/obj/usr/src/bazel-idle-membarrier-kernel-make-20261028.log`;
maintained recipes used the same SDK compiler, 16 jobs, DEBUG=-g,
WITH_CTF=yes and reproducible paths. Whole-object/debug-path identity is not
claimed.

Frontend review: existing format-5 target inputs cover this addition without
new build-bsd C/backend options, staging or manual changes. No runtime tests
ran. Idle/wakeup behavior, CPU affinity, memory-barrier registration/query/error
paths, cross-CPU ordering and performance require linked-kernel SMP tests.
Full kernel/world/pkgbase/bootstrap and performance gates remain open. Make
stays production/default; module count remains 45. No host installation or
BIP changes occurred.

### Native CPU frequency and per-CPU storage

Added //sys/kern:generic_cpu_frequency_storage_object_files for kern_cpu.c
and subr_pcpu.c, selected by maintained GENERIC Make. Dependencies declare
CK/VM, generated bus/device/cpufreq interfaces, debugger headers and generated
DDB options. The cpufreq header comes from the existing native .m generator.
No frequency control or per-CPU allocation source changed.

Evidence: `/usr/obj/usr/src/bazel-cpu-frequency-storage-kernel-20261028/qualification`.
Both objects match Make symbols, raw CTF, complete allocated-section
inventories, section bytes/size/type/flags/alignment and runtime relocation
records and associations. opt_ddb.h matches Make bytes. Reference log:
`/usr/obj/usr/src/bazel-cpu-frequency-storage-kernel-make-20261028.log`;
maintained recipes used the same SDK compiler, 16 jobs, DEBUG=-g,
WITH_CTF=yes and reproducible paths. Whole-object/debug-path identity is not
claimed.

Frontend review: existing format-5 target inputs cover this addition without
new build-bsd C/backend options, staging or manual changes. No runtime tests
ran. Frequency levels/transitions, driver registration, per-CPU allocation/
free, CPU enumeration and concurrent access require linked-kernel and hardware
tests. Full kernel/world/pkgbase/bootstrap and performance gates remain open.
Make stays production/default; module count remains 45. No host installation
or BIP changes occurred.

### Native thread contexts and shared pages

Added //sys/kern:generic_context_sharedpage_object_files for kern_context.c
and kern_sharedpage.c, selected by maintained GENERIC Make. Dependencies
declare CK/VM headers and generated VM options. No context handling, shared
page mapping or runtime source changed.

Evidence: `/usr/obj/usr/src/bazel-context-sharedpage-kernel-20261028/qualification`.
Both objects match Make symbols, raw CTF, complete allocated-section
inventories, section bytes/size/type/flags/alignment and runtime relocation
records and associations. opt_vm.h matches Make bytes. Reference log:
`/usr/obj/usr/src/bazel-context-sharedpage-kernel-make-20261028.log`;
maintained recipes used the same SDK compiler, 16 jobs, DEBUG=-g,
WITH_CTF=yes and reproducible paths. Whole-object/debug-path identity is not
claimed.

Frontend review: existing format-5 target inputs cover this addition without
new build-bsd C/backend options, staging or manual changes. No runtime tests
ran. Context save/restore/swap, invalid user pointers, signal masks, shared-page
mapping, VDSO consumers and ABI variants require linked-kernel tests.
Full kernel/world/pkgbase/bootstrap and performance gates remain open. Make
stays production/default; module count remains 45. No host installation or
BIP changes occurred.

### Native process control

Added //sys/kern:generic_process_control_object_files for kern_procctl.c,
selected by maintained GENERIC Make. Dependencies declare CK/VM headers and
generated KTRACE options. No process control or authorization source changed.

Evidence: `/usr/obj/usr/src/bazel-process-control-kernel-20261028/qualification`.
The object matches Make symbols, raw CTF, complete allocated-section inventory,
section bytes/size/type/flags/alignment and runtime relocation records and
associations. opt_ktrace.h matches Make bytes. Reference log:
`/usr/obj/usr/src/bazel-process-control-kernel-make-20261028.log`;
maintained recipes used the same SDK compiler, 16 jobs, DEBUG=-g,
WITH_CTF=yes and reproducible paths. Whole-object/debug-path identity is not
claimed.

Frontend review: existing format-5 target inputs cover this addition without
new build-bsd C/backend options, staging or manual changes. No runtime tests
ran. Process permissions, reaper acquire/release/kill, tracing controls,
ASLR/WX/stackgap/no-new-privileges settings, inheritance and exit races require
linked-kernel tests. Full kernel/world/pkgbase/bootstrap and performance gates
remain open. Make stays production/default; module count remains 45. No host
installation or BIP changes occurred.

### Native process metadata and enumeration

Added //sys/kern:generic_process_metadata_object_files for kern_proc.c.
Dependencies declare CK/VM, MAC, capability labels, devfs, debugger and generated
DDB/KTRACE/KSTACK_PAGES/STACK options. Existing capability label header visibility
now includes sys/kern. No process metadata or authorization source changed.

Evidence: `/usr/obj/usr/src/bazel-process-metadata-kernel-20261028/qualification`.
The object matches maintained GENERIC Make symbols, raw CTF, complete allocated
section inventory, bytes/size/type/flags/alignment and runtime relocation
records/associations. All four option headers match Make bytes. Reference:
`/usr/obj/usr/src/bazel-process-metadata-kernel-make-20261028.log` using the
same SDK compiler, 16 jobs, DEBUG=-g, WITH_CTF=yes and reproducible paths.
Whole-object/debug-path identity is not claimed.

Frontend review: existing format-5 inputs cover this target without C/backend,
staging or manual changes. No runtime tests ran. Process enumeration, metadata
visibility, jail/MAC boundaries, stack inspection and lifecycle races require
linked-kernel tests. All world/kernel/pkgbase/bootstrap/performance gates remain
open. Make stays production/default. No installation or BIP changes occurred.

### Refreshed whole-world scope audit (2026-10-28)

The maintained world-inventory.py completed Make print-dir with 16 jobs and
the existing amd64 object profile/public loader trust anchor. Evidence:
`/usr/obj/usr/src/bazel-world-inventory-refresh-20261028/inventory.json`.
The traversal discovered 2,103 directories; build-presence.json alongside it
records a current local BUILD.bazel presence audit. This is not a count of
programs/libraries built or qualified. Parent-package ownership, generated
inputs, install metadata, options and runtime tests require further mapping.

| Configured subtree | Directories | Without local BUILD.bazel |
| --- | ---: | ---: |
| bin | 74 | 18 |
| sbin | 105 | 10 |
| usr.bin | 425 | 210 |
| usr.sbin | 462 | 369 |
| lib | 429 | 225 |
| libexec | 53 | 49 |
| tests | 234 | 230 |
| stand | 53 | 52 |
| rescue | 3 | 3 |

Userland and libraries are not complete. Remaining work spans programs,
helpers, tests, headers/data, bootstrap/loader/rescue, full aggregate builds,
installation and pkgbase publication. Prior bin test-presence records are
historical: some tests have since been added. Use this fresh inventory for
follow-up, and validate ownership before treating absent local BUILD files as
missing implementation. No full world target exists at the repository root.
Make remains production/default. This inventory does not change frontend
inputs or publication policy and requires no frontend implementation change.

### Native beep userland utility

Added //usr.bin/beep:beep, :install_manifest and :install_archive using native
cc_binary, native libm and maintained utility debug/strip/manual/archive rules.
Package ownership is sound, as in Make; no runtime source changed.
Evidence: `/usr/obj/usr/src/bazel-beep-20261028/qualification/parity.json` and
its retained verify.py; Make reference `/usr/obj/usr/src/bazel-beep-make-20261028`.
All five component installation records match (types, paths, owners, groups,
modes and package tags), including debug directories. Compressed manual bytes,
six defined global symbols, ordered NEEDED libraries and NOW/PIE flags match.
Whole executable/debug byte identity is not claimed.

Eight native/Make runtime cases match: help, low/high duration, low/high sample
rate, low/high gain and missing device. Both use native libm and SDK runtime
libraries. No audio hardware was accessed; playback, background operation,
Capsicum device setup and device ioctl failures remain unqualified. These
checks were run by the retained qualification script, not registered Bazel tests.

Frontend review: existing format-5 target selection handles these targets and
sound installation metadata without frontend C/backend/manual changes. Full
world aggregation, pkgbase publication, tests and performance remain open.
Make remains production/default; no host installation or BIP changes occurred.


## 2026-10-28: bintrans native build and installation candidate

Scope remains all userland, libraries, kernel, modules and drivers; none of
those whole-system categories is complete. Added native cc_binary compilation
of the four maintained bintrans sources, PIE linking, split debug, both manual
sections, five executable aliases and six manual aliases. No program source
or runtime security behavior changed. Test installation follows MK_TESTS via
the existing Bazel setting and includes both scripts, eleven fixtures and the
ATF/TAP Kyuafile; directory policy comes from BSD.tests.dist.

Evidence: `/usr/obj/usr/src/bazel-bintrans-build-20261028-r2` through the maintained
build-bsd frontend, 16 jobs, frozen SDK; Make reference at
`/usr/obj/usr/src/bazel-bintrans-make-20261028`. qualification/verify.py and
parity.json record 32 installation records matching type/path/owner/group/mode/
package tags after normalizing hardlinks, matching 11 global symbols and dynamic
metadata (libc.so.7, BIND_NOW, NOW PIE), byte-identical compressed manuals, six
fixture comparisons and all five argv[0] alias comparisons against Make. Direct
runtime checks use SDK libraries; they are not full installed-system tests.
No whole executable/debug byte identity or system performance claim.

Two native ATF cases are declared. Attempts retained at
bazel-bintrans-20261028-r2 and -r3 fail before either body with the capability
rights assertion in runtime tools, consistent with the previously recorded
source/host ABI discrepancy. These are failures, not passing/skipped tests.
Legacy TAP script is installed but its Bazel runner remains pending. Its
../regress.m4 dependency is provided by usr.bin/tests in the installed tree;
it must not be replaced by an ad hoc fixture. Build-only qualification uses
separate explicit inputs and does not erase failed runtime evidence. Initial
archive validation correctly rejected absent tests directory policy, fixed by
declaring the maintained tests mtree input.

Frontend review: format-5 explicit targets/tests and existing tests/split_manpages
settings express this addition; no frontend/backend contract change is required.
Make remains production default. BIP remains out of scope. Nothing installed on
the host, no reboot, and no complete-world/kernel/package/boot claim.


## 2026-10-28: bintrans legacy TAP integration

The pending legacy TAP runner is now integrated into bintrans/tests:tests.
Added optional normalized relative program_path to the existing Kyua adapter.
Nested programs use Kyua include() and a child Kyuafile, preserve sibling/parent
fixture layout, and retain full relative names in selection and typed result
reconciliation. Absolute paths, empty components and traversal are rejected;
existing fixture overlap validation includes the generated child Kyuafile.
Shared regression macros are declared by usr.bin/tests:support_manifest at the
maintained /usr/tests/usr.bin/regress.m4 location. Parent Kyuafile/world test
inventory assembly is still outstanding, explicitly not claimed complete.

Evidence: /usr/obj/usr/src/bazel-bintrans-tap-20261028-r2 passes the unchanged
legacy script's five TAP checks, zero failures or skips. Both multicall aliases
are pinned to the native bintrans executable through declared PATH targets.
Flat-layout regression /usr/obj/usr/src/bazel-kyua-layout-regression-20261028
passes lastcomm's existing suite. Logs, JUnit and result databases are copied
into each run's qualification directory. The first attempted layout was rejected
by Kyua (program names cannot contain path components); retained failure led to
the native include mechanism, not alteration of test scripts or test outcomes.

Qualification limits: Kyua adapter still uses host shell, m4, diff and other
ancillary execution tools, and this TAP run uses host loader libraries. This is
not hermetic-runtime or current-image qualification. The two ATF cases retain
the previously recorded startup assertion and are not counted as passing.
No host upgrade or installation occurred. Frontend review: existing explicit
format-5 target/test inputs carry these additions without a new frontend option.
Whole-world, kernel, package, boot and performance gates remain incomplete.


## 2026-10-28: native at utility candidate

Added native compilation of at.c, panic.c, parsetime.c and perm.c with declared
headers; shared configuration.bzl contains the Makefile.inc policy values for
at and future atrun integration. The generated manual uses Bazel template
expansion from that same policy, without invoking Make or parsing Make metadata.
Installation preserves three command/manual aliases, setuid mode 4555, debug
symbols, cron configuration mode/config tag and the utilities-owned cron.d
directory. No runtime source changes or host installation.

Evidence: /usr/obj/usr/src/bazel-at-20261028-r2, Make reference
/usr/obj/usr/src/bazel-at-make-20261028, and qualification/verify.py plus
parity.json. All 13 unique installation records match after octal mode and
hardlink normalization (Make records cron.d twice). Generated at.1 and gzip
manual bytes match; 19 defined global symbols and libc.so.7/BIND_NOW/NOW PIE
metadata match. Four invalid-option/queue/time cases exit identically before
permission/spool access, using declared SDK libraries. This does not qualify
setuid execution, scheduling, atrun, full executable/debug byte identity or an
installed system. First failed attempt exposed incorrectly escaped compiler
definitions; retry preserves quoted string/character constants and passed.

Frontend review: existing explicit format-5 targets and installation archive
rules cover this addition. No build-bsd option/backend contract change needed.
No test suite exists in this component's Make definition; the four comparisons
are retained qualification checks, not newly registered Bazel tests. atrun and
whole-system package/runtime/performance qualification remain outstanding.
Make remains production default and BIP remains out of scope.


## 2026-10-28: native atrun and at/atrun local reuse

Added native atrun.c/gloadavg.c compilation with declared gloadavg/privilege
headers and existing native PAM/libutil dependencies. LOGIN_CAP and PAM remain
enabled as in Make; shared at/configuration.bzl drives compiler constants,
manual substitutions and installation bindir. No runtime source changes.
The native graph retains enabled PAM/libutil DTrace generation. This establishes
build dependency preservation, not live probe or PAM-session qualification.

Evidence: /usr/obj/usr/src/bazel-atrun-20261028 and Make reference
/usr/obj/usr/src/bazel-atrun-make-20261028. qualification/verify.py and parity.json
establish five installation records, 13 defined globals, ordered dependencies
libpam.so.6/libutil.so.10/libc.so.7 and BIND_NOW/NOW PIE matching Make. Generated
atrun.8 and compressed manual bytes match. No runtime invocation: atrun changes
credentials before option parsing. Credential transitions, PAM account/session
handling, job execution and logging require installed VM qualification; no
whole-executable/debug byte identity or performance claim is made.

Unchanged combined at/atrun build at
/usr/obj/usr/src/bazel-at-atrun-cache-20261028 passed with 16 action-cache hits,
one internal action and no compiler/linker execution reported. This is a local
unchanged-build reuse check only; it does not prove remote cache correctness,
complete invalidation behavior, cold-build reproducibility or system performance.

Frontend review: existing format-5 inputs select both components and archives;
no frontend/backend contract change required. No Make backend/default change,
host installation, job execution or reboot. Full-system goals remain active.


## 2026-10-28: chat and comsat native candidates

Added unchanged-source native cc_binary targets and installation archives for
usr.bin/chat and libexec/comsat. Preserve PPP versus utilities package ownership,
section-8 manuals, binary/debug installation locations and PIE linking. Neither
Make component declares a test subdirectory. No program source changes.

Evidence: /usr/obj/usr/src/bazel-chat-comsat-20261028, with separate maintained
Make references bazel-chat-make-20261028 and bazel-comsat-make-20261028.
qualification/chat and qualification/comsat retain verification scripts/results:
five installation records each match Make, compressed manual bytes match, as
do 32 and six defined global symbols respectively and libc.so.7/BIND_NOW/NOW PIE.
qualification/runtime.py and runtime.json compare two early invalid chat option
paths and comsat stdin=/dev/null invocation, including exit status and output.
All three comparisons pass with SDK libraries. They exit before modem/mail
service operations and do not qualify those operations. No full executable/debug
byte identity, tty integration, mail notification, privilege or performance claim.

Frontend review: existing explicit format-5 inputs and archive rules cover both
components with no frontend/backend contract change. Standard /usr/obj storage
and 16-job execution preserved. No host install or service activation. Full
world/kernel/pkgbase/boot/runtime/performance gates remain incomplete.


## 2026-10-28: native c89 and c99 compiler frontends

Added unchanged-source native cc_binary targets, split debug/manual installation
and archive metadata for both toolchain-package programs. Neither Make component
has generated sources or declares tests. Their maintained /usr/bin/cc invocation
is preserved; conversion does not inject a private compiler pathname.

Evidence: /usr/obj/usr/src/bazel-c89-c99-20261028 and separate Make references
bazel-c89-make-20261028 / bazel-c99-make-20261028. Per-component qualification
verifiers show five installation records each, byte-identical compressed manuals,
six defined globals each and libc.so.7/BIND_NOW/NOW PIE metadata matching Make.
qualification/runtime.py and runtime.json record four compile-and-run comparisons:
C89/C99 __STDC_VERSION__ checks, macro forwarding, a 24-extra-argument C99 case,
and joined/separated pthread/rt/xnet library operands. Each native/Make pair
produces byte-identical test executable output and each executable exits zero.
Compiler version is recorded. These runtime checks use the maintained host
/usr/bin/cc and host libraries, not Bazel-built clang; they do not qualify a
complete installed image or whole frontend executable/debug byte identity.

Frontend review: explicit format-5 target inputs and current installation rules
cover the additions without frontend/backend contract changes. No new registered
Bazel tests claimed; retained comparisons qualify this conversion only. World,
kernel, pkgbase, boot, runtime and performance gates remain incomplete; Make
remains production default. No host installation or reboot.


## 2026-10-28: native killall with DTrace variants

Added native killall compilation and libjail dependency using the existing
DTrace header/object/provider rules. WITH_COVERAGE_DTRACE follows the configured
DTrace setting. Source and signal behavior remain unchanged. Installation keeps
the utilities package, section-1 manual, split debug and PIE linking.

Evidence: /usr/obj/usr/src/bazel-killall-20261028 and Make reference
/usr/obj/usr/src/bazel-killall-make-20261028. Five installation records, compressed
manual bytes, ten defined globals and ordered libjail.so.1/libc.so.7 dependencies
plus BIND_NOW/NOW PIE match Make. qualification/native-dof.json and make-dof.json
use the maintained DOF inventory/site verifier. Both provider schemas match:
signalall operation-start(int,int) and operation-done(int,int,int,int); both
ordinary and enabled sites pass function-range and patched-instruction checks.
This is offline site qualification, not registration or live firing.

Explicit DTrace-disabled build bazel-killall-notrace-20261028 passes and has no
.SUNW_dof section. qualification/variants.py compares signal-list and help output
for the enabled, disabled and Make executables; all agree. It uses byte-verified
private executable copies of saved artifact snapshots, native libjail and SDK
libraries. No signals are sent. Disabled variant lacks a separate Make-disabled
reference; no claim of full disabled-build parity. Host jail behavior and live
probe firing remain VM gates. First verifier attempts showed that the inventory
rejects absent metadata and saved snapshots are nonexecutable; final verification
uses readelf for absence and executable copies without mutating snapshots.

Frontend review: existing format-5 target selection and dtrace setting carry
both variants without frontend/backend contract change. No new system backend,
host installation or reboot. Full world/kernel/pkgbase/runtime/performance
qualification remains incomplete; Make remains production default.


## 2026-10-28: native lessecho

Added native lessecho compilation from declared contrib/less lessecho.c and
version.c, reusing the existing less configuration/header targets. Visibility
is extended only to the lessecho package. The maintained Make manual recipe
copies lessecho.nro unchanged; Bazel compresses that same input directly.
Installation preserves utilities package ownership and binary/debug/man paths.
No runtime source changes or Make metadata import.

Evidence: /usr/obj/usr/src/bazel-lessecho-20261028 with Make reference
/usr/obj/usr/src/bazel-lessecho-make-20261028. qualification/verify.py records
five matching installation records, seven defined globals, matching ordered
libc.so.7/BIND_NOW/NOW PIE metadata and identical compressed manual bytes.
qualification/runtime.py and runtime.json retain 19 behavior comparisons for
empty input, multiple arguments, quoting, numeric quote characters, metacharacter
escaping, numeric escaping, disabled escaping, option termination, help/version
and malformed options. All statuses/stdout/stderr match Make with expected
success/error exits. SDK runtime libraries are used; not full installed-image
or whole executable/debug byte identity qualification.

Frontend review: current format-5 explicit inputs and archive rules express this
addition without changing build-bsd or backend contracts. Make has no test suite
for this component; retained comparisons are conversion evidence, not a new
registered Bazel test suite. Whole-system gates remain incomplete and Make stays
production default. No host installation or reboot.


## 2026-10-28: native ctlstat

Added native ctlstat with existing declared CAM headers and native sbuf/bsdxml
libraries. Installation preserves ctl package ownership, section-8 manual,
split debug, binary location and PIE. No source or device behavior changes.
The existing sys/cam header target currently uses a recursive header glob;
this conversion reuses it rather than introducing another broad source include.
Header inventory refinement remains separate from complete-world qualification.

Evidence: /usr/obj/usr/src/bazel-ctlstat-20261028, Make reference
/usr/obj/usr/src/bazel-ctlstat-make-20261028. qualification/verify.py and parity.json
record five matching installation records, six defined globals, matching ordered
libsbuf.so.6/libbsdxml.so.4/libc.so.7 dependencies and BIND_NOW/NOW PIE, plus
byte-identical compressed manuals. qualification/runtime.py compares four
invalid/missing-option cases; all statuses and output match Make with native
libraries and SDK runtime. These read the max_luns sysctl but exit before CTL
device open. Storage ioctls, counters, CPU reporting, JSON/Prometheus formatting,
filtering and timing remain installed-VM qualification. No full executable/debug
byte identity or runtime performance claim.

Source review follow-up: existing LUN/port parsing uses atoi and rejects only
values greater than ctl_stat_bits before bit_set. Negative indices and an index
equal to the bit count merit a dedicated bounds review/test; not changed or
claimed fixed as part of this build conversion.

Frontend review: existing format-5 targets/archive rules cover the addition;
no frontend/backend contract change required. Make declares no component test
suite; retained comparisons are not registered Bazel tests. No host install,
service activation or reboot. Full world/kernel/pkgbase/boot/performance gates
remain incomplete and Make remains production default.


## 2026-10-28: native finger

Added native compilation of finger.c, lprint.c, net.c, sprint.c and util.c with
all three local headers. Installation includes finger.1 and finger.conf.5,
with the existing split-manpages setting applied to both manual package tags.
Preserves utilities package, PIE and split-debug metadata. No source changes.

Evidence: /usr/obj/usr/src/bazel-finger-20261028 with Make reference
/usr/obj/usr/src/bazel-finger-make-20261028. qualification/verify.py verifies six
installation records, 29 defined globals, libc.so.7/BIND_NOW/NOW PIE metadata and
both compressed manuals against Make. qualification/runtime.py records matching
invalid-option exit/output before user lookup, with SDK libraries. This does
not qualify local users, utmpx, finger.conf aliases, privacy options or remote
queries. No complete executable/debug byte identity or installed-image claim.

Frontend review: existing format-5 target selection and installation rules
express the addition without frontend/backend changes. Make declares no tests;
retained comparisons are not registered Bazel tests. Full-system/runtime gates
remain open; Make remains default. No installation or remote query performed.


## 2026-10-28: native fingerd, blocklist enabled and disabled

Added native fingerd with libutil and conditional native blocklist dependency
and USE_BLOCKLIST define selected by the existing blocklist_support setting.
No runtime source changes. Installation preserves utilities ownership,
section-8 manual, split debug and PIE.

Evidence: /usr/obj/usr/src/bazel-fingerd-20261028 and
bazel-fingerd-noblocklist-20261028, each compared with its own Make reference
(bazel-fingerd-make-20261028 and bazel-fingerd-noblocklist-make-20261028).
Both match five installation records, seven defined globals, compressed manual
bytes and ordered dynamic metadata. Enabled dependencies are libutil.so.10,
libblocklist.so.0, libc.so.7; disabled dependencies omit libblocklist as expected.
Both retain BIND_NOW/NOW PIE. Per-run qualification/verify.py and parity.json
retain checks. No whole executable/debug byte identity claim.

Disabled-run qualification/runtime.py and runtime.json record five protocol
comparisons using documented -d debug mode and -p with a private argument-recorder
fixture: normal username, /W mapping/multiple arguments, -k, empty secure request
refusal and forwarding refusal. Expected exit/output and Make comparison all
pass. No real user queries or blocklist reports are sent. Native libutil and SDK
runtime are used; the fixture uses host shell. This does not qualify inetd/TCP,
remote hostname handling, actual finger invocation or live blocklist reporting.
Enabled mode is artifact-qualified, not runtime-qualified by these disabled tests.

Frontend review: existing format-5 blocklist_support setting and target selection
express both variants without frontend/backend changes. Make has no component
test suite; retained protocol comparisons are conversion evidence. No host install,
service activation or reboot. Full world/kernel/pkgbase/boot/performance gates
remain open; Make remains production default.


## 2026-10-28: leave artifact candidate; runtime startup fails

Added native leave compilation and utilities-package installation metadata,
retaining source, Capsicum entry, split debug, section-1 manual and PIE.
Evidence: /usr/obj/usr/src/bazel-leave-20261028 and Make reference
/usr/obj/usr/src/bazel-leave-make-20261028. qualification/verify.py establishes
five installation records, six defined globals, libc.so.7/BIND_NOW/NOW PIE and
compressed-manual bytes matching Make. No complete executable/debug identity
claim and no runtime pass inferred from these artifact checks.

qualification/startup.py and startup.json record blank-input startup using SDK
libraries, with core dumps disabled and no timer requested. Both native and Make
executables terminate SIGABRT at cap_rights_intersect's cap_rights_is_valid(src)
assertion before prompt/input processing. Expected exit/output are not met;
passed=false. This matches the previously diagnosed source/host Capsicum ABI
mismatch. No bypass, source weakening or expected-failure conversion was added.
A matching system runtime must qualify blank input, time parsing, reminders and
terminal lifecycle. This runtime failure is an open gate, not successful parity.

Frontend review: existing format-5 target/archive rules suffice, no frontend or
backend contract change required. Make declares no component tests. No host
installation, reminder process or reboot. Other conversion work can proceed;
full world/kernel/pkgbase/boot/runtime/performance goals remain incomplete.


## 2026-10-28: native ipcrm and private IPC removal checks

Added native ipcrm with libkvm and declared ipc.c/ipc.h/ipcsnapshot_trace.h inputs
shared from ipcs. Exports are restricted to the ipcrm package. The maintained
ipcrm Makefile does not enable WITH_COVERAGE_DTRACE; the native target preserves
that trace-disabled compilation path rather than borrowing ipcs instrumentation.
No runtime source changes. Installation retains utilities ownership and PIE.

Evidence: /usr/obj/usr/src/bazel-ipcrm-20261028 and Make reference
/usr/obj/usr/src/bazel-ipcrm-make-20261028. qualification/verify.py verifies five
installation records, 17 defined globals, libkvm.so.7/libc.so.7/BIND_NOW/NOW PIE
metadata and compressed manual bytes. qualification/runtime.py and runtime.json
record six successful private-object removal checks: each build removes its own
new IPC_PRIVATE message queue, shared-memory segment and semaphore set using the
exact returned ID. Objects use mode 0600; follow-up removal reports EINVAL/EIDRM,
confirming deletion. Cleanup covers failed candidate invocations. No preexisting
objects or global-removal operation touched. Native libraries/SDK runtime used;
test allocation uses host libc. Key-based removal, -W, jail behavior and -y
kernel-memory access remain unqualified. No installed-image/full debug-byte or
performance claim.

Frontend review: existing explicit format-5 targets/archive rules suffice; no
frontend/backend contract change. Make declares no component tests, so retained
checks are conversion evidence, not new registered Bazel tests. Whole-system
gates remain open and Make remains default. No host installation or reboot.


## 2026-10-28: native ldd

Added native ldd with native libelf and the existing rtld_paths.h target, extending
its visibility only to ldd. The maintained source's runtime-loader selection is
preserved. No runtime source changes. Installation retains utilities ownership,
section-1 manual, split debug and PIE.

Evidence: /usr/obj/usr/src/bazel-ldd-20261028 and Make reference
/usr/obj/usr/src/bazel-ldd-make-20261028. qualification/verify.py verifies five
installation records, six defined globals, libelf.so.2/libc.so.7/BIND_NOW/NOW PIE
metadata and compressed manual bytes. qualification/runtime.py compares seven
cases: missing operands, invalid option, absent file, non-ELF input, formatted
executable dependencies, formatted shared-library dependencies and -a reporting.
Expected statuses and dependency names pass. Host loader emits a vDSO ASLR address
even with custom format; only that address is normalized and raw outputs are
retained. The initial exact-output mismatch and reason are explicit in the final
verifier. Known native ELF fixtures only, native libelf and SDK libraries; no
arbitrary executable input, complete newly built loader or installed-image
qualification. No whole executable/debug byte identity claim.

Frontend review: existing format-5 explicit targets and installation rules cover
the addition without frontend/backend contract changes. Make declares no tests;
retained behavior comparisons are conversion evidence. Whole-system gates remain
incomplete and Make stays production default. No host install or reboot.


## 2026-10-28: native lock and private-terminal checks

Added native lock with native PAM dependency and maintained setuid installation
mode 4555. Runtime source, temporary-key and PAM authentication paths are unchanged.
Evidence: /usr/obj/usr/src/bazel-lock-20261028 with Make reference
/usr/obj/usr/src/bazel-lock-make-20261028. qualification/verify.py verifies five
installation records (octal modes normalized), six globals, libpam.so.6/libc.so.7
and BIND_NOW/NOW PIE metadata, and identical compressed manual bytes.

qualification/terminal_check.py and pty.json record six private PTY checks:
Bazel/Make each cancel an empty key, reject mismatched keys and unlock with the
chosen fixture key. Every run disables echo while prompting and restores the
complete original terminal attributes on exit. Executables are uninstalled and
non-setuid; no account credentials or user terminal involved. No PAM authentication,
virtual-console locking, privileged install or timeout-expiry qualification.
Native PAM and SDK libraries used; no full executable/debug byte identity claim.
Initial harness naming shadowed Python pty; renamed. The next harness waited
without draining PTY output, blocking TCSADRAIN; corrected to drain while waiting.
No product behavior was changed to make tests pass; bounded cleanup kills only
the harness's own child on failure.

Frontend review: existing format-5 explicit target/archive rules handle this
addition without frontend/backend changes. Make declares no component tests;
retained terminal checks are conversion evidence, not registered Bazel tests.
Whole world/kernel/pkgbase/runtime/performance gates remain open. Make remains
default, no host installation, authentication attempt or reboot.


## 2026-10-28: native login, configuration DB and feature variants

Added native login/login_fbtab and optional login_audit compilation with libutil,
PAM and optional BSM. DTrace uses the existing native provider/object pipeline.
New typed setuid_login setting defaults true, matching MK_SETUID_LOGIN; enabled
installation preserves mode 4555 and the preexisting Make PRECIOUSPROG schg flag,
disabled uses 0555 without schg. This preserves existing metadata, not BIP work.
Four original configuration files are installed with runtime/config tags.

Existing bsd_capability_database rule runs cap_mkdb_bootstrap in the execution configuration on a
declared source file, with explicit output and little/big byte order. login
currently targets amd64 and selects little endian. It does not copy a host DB,
parse Make or write into /etc. Execution-platform portability and big-endian
qualification remain outstanding. Database install metadata matches Make,
including its currently untagged login.conf.db record; package ownership must
be resolved explicitly in full-world pkgbase reconciliation, not silently omitted.

Full-feature evidence: /usr/obj/usr/src/bazel-login-20261028-r2 against
bazel-login-make-20261028. Eleven unique installation records, 15 globals,
ordered libutil.so.10/libpam.so.6/libbsm.so.3/libc.so.7 and BIND_NOW/NOW PIE
match. Manual and generated login.conf.db bytes match. Offline DOF inventories
match two login auth/fail schemas and both builds pass amd64 probe instruction
site checks. No registration/live-authentication assertion is implied.

Disabled-feature evidence: bazel-login-minimal-20261028 against
bazel-login-minimal-make-20261028, with audit/dtrace/setuid disabled explicitly.
Eleven metadata records, ten globals, manual and database bytes match; libbsm,
.SUNW_dof and schg are absent as expected. Separate qualification/verify.py and
parity.json retained for each variant. Other combinations remain unqualified.
No login invocation or PAM/session/credential/terminal/audit runtime test performed;
those remain isolated-VM gates. No full executable/debug byte identity claim.

Frontend review: source_graph.setting_arguments already validates and forwards
typed format-5 source settings; both runs exercised setuid_login through build-bsd.
No C frontend or backend-contract change needed. README documents the setting
and database rule. No installed system, host configuration or credentials changed.
Whole-system gates remain incomplete and Make remains default.

Post-commit review correction: the first login change accidentally replaced an
existing bsd_capability_database API while adding a narrower duplicate. Restored
the original rule unchanged and switched login to its srcs/endian/compiler
interface, retaining multi-source and runtime-library support. Requalification
at /usr/obj/usr/src/bazel-login-capdb-reuse-20261028 passes the same full-feature
metadata and byte-identical database comparison. Existing rule consumers are
not required to migrate. This correction supersedes any description of a new
capability-database rule in the initial change.


## 2026-10-28: reconcile login package payload and generated database

Corrects the earlier provisional database-ownership concern: inspection of
packages/utilities/utilities.ucl found maintained post-install regeneration from
/etc/login.conf and a 5bsd.construction declaration for /etc/login.conf.db.
The untagged Make record represents generated state, not a missing package owner.
Do not assign a prebuilt database to a package and overwrite state derived from
local configuration. No Make recipe or package action changes are needed here.

Native login now exposes package-backed install_manifest separately from explicit
generated_manifest. install_archive includes both. A scope=component package_layout
uses the tagged payload only, with runtime/runtime-dbg and optional runtime-man.
This is an explicit partition; the database is not silently dropped from staging.
It does not produce a complete runtime package or qualify utilities post-install
execution, upgrades or config merge/regeneration across package updates.

Evidence: /usr/obj/usr/src/bazel-login-payload-20261028 and
bazel-login-payload-split-20261028. Normal full installation still matches all 11
Make records and generated DB bytes. qualification/partition.py reads saved
artifact manifests, not mutable bazel-bin links; normal and split-manpage layouts
account for every installed nondirectory file. Exactly login.conf.db is generated,
all four configurations retain config tags, and the manual moves to runtime-man
when selected. Counts: normal runtime=6/runtime-dbg=1; split runtime=5,
runtime-dbg=1/runtime-man=1; each also stages the single generated DB.

Frontend review: existing explicit targets expose both manifests and layout via
build-bsd; README corrected to describe actual package generation ownership.
No C/backend contract change, host update or login invocation. Full package
assembly/publication, post-install and upgrade qualification remain open.

## 2026-10-28: native chpass and NIS bootstrap gap

Adds native chpass sources, crypt/util dependencies, optional YP/ypclnt,
relative command aliases, manual aliases, debug staging and maintained 4555/schg
metadata. Shares libc pw_scan through narrowly extended source/header visibility.
The existing schg install flag follows PRECIOUSPROG; no BIP implementation added.
Comparison corrected command symlink metadata to Make's 0755.

Evidence: /usr/obj/usr/src/bazel-chpass-20261028-r2/qualification/parity.json,
using saved artifacts, matches the NIS-disabled Make reference's 26 global
symbols, ordered dynamic dependencies/flags, nine installation records including
permissions/flags/link destinations, manual hardlink identity in reference,
and compressed manual bytes. No executable/debug byte identity or account
modification/runtime qualification is claimed.

NIS-enabled qualification FAILED, not waived: bazel-chpass-nis-20261028 cannot
link libypclnt against the frozen SDK libc (missing yp_master, yperr_string and
YP XDR symbols). The independent bazel-chpass-nis-make-20261028 reference fails
compilation because its configured world sysroot lacks ypclnt.h. A coherent
NIS-enabled bootstrap/sysroot and subsequent native libc integration are needed
before this variant can be qualified. Do not add private copies of libc's YP
implementation to chpass or suppress undefined-symbol errors to pass this gate.
Account editing, privileged installation and NIS service interaction remain VM
coverage. This component is not evidence of completed userland or full world.

Frontend review: existing format-5 targets and typed nis setting expose this
component and variant through build-bsd; no new frontend/backend contract is
required. No host account, installed file, package repository or boot state changed.

## 2026-10-28: native libc YP object group

Adds lib/libc/yp:yp_objects with the maintained xdryp/yplib sources and declared
rpcgen -C header/XDR actions from include/rpcsvc/yp.x. Native protocol include
layout and narrow private-header dependencies preserve libc namespace handling.
Ordinary/PIC qualification archives are explicitly not installed libraries and
are not linked into chpass as a substitute for a configured libc. Preserves
libc revision/fortify defines, configured NLS, default exception-unwind setting
and initial-exec TLS model. The complete libc aggregate and its conditional NIS
selection are still to be implemented; NO_THREAD_STACK_UNWIND variants remain
unqualified. Symbol.map is available for that eventual aggregate.

Evidence: /usr/obj/usr/src/bazel-libc-yp-20261028-r2/qualification/parity.json
compares saved artifacts against freshly compiled maintained libc Make objects
in bazel-libc-yp-make-20261028 (WITH_NIS, unchanged world SDK). Both generated
files are byte-identical. All six ordinary/PIC objects match global and undefined
symbols and .text bytes. This does not compare all allocated sections/relocations,
full object/debug identity, final symbol versions, runtime or package installation.
It does not fix the existing SDK's missing NIS libc symbols or qualify chpass NIS.

Frontend review: build-bsd's format-5 explicit targets and existing typed NLS
setting cover this object qualification; no new frontend/backend contract.
Full native libc, bootstrap and final world linkage remain completion gates.

## 2026-10-28: native libc XDR object group

Adds all eight maintained lib/libc/xdr sources as native xdr_objects, with
explicit libc private-header and rpc_com.h dependencies. Ordinary/PIC archives
are qualification artifacts, not installed replacement libraries. Preserves
libc namespace handling, fortify/revision/NLS defines, default unwind and TLS
options; Symbol.map and xdr.3 are exposed to the future libc aggregate.

Evidence: /usr/obj/usr/src/bazel-libc-xdr-20261028/qualification/parity.json
compares saved native artifacts against fresh maintained Make objects in
bazel-libc-xdr-make-20261028. All 16 ordinary/PIC objects match global symbols,
undefined symbols and .text bytes. Comparison does not establish relocation,
all allocated-section, whole object/debug, final ABI or runtime equivalence.
The libc aggregate, final shared/static library links, xdr.3 and rpc_xdr.3 manual
aliases, installation/package integration and NO_THREAD_STACK_UNWIND variants
remain open. Existing lib/libc/tests/rpc includes NetBSD XDR tests and generated
h_testbits RPC fixtures; carrying that suite into Bazel is follow-up work, not
covered by these object comparisons.

Frontend review: current explicit format-5 targets and NLS configuration work
through build-bsd; no frontend/backend contract change needed for this group.
No host installation, network activity, credential changes or BIP work.

## 2026-10-28: existing XDR case under Bazel

Adds the unchanged NetBSD t_xdr.c case with declared h_testbits RPC header/XDR
fixture generation (-L -C), NetBSD compatibility and native ATF dependencies.
The xdr_objects_test executable consumes the native PIC archive explicitly via
cc_import: ordinary objects cannot be linked into this PIE executable. This
selects existing qualified PIC outputs without changing production object flags.
It is intentionally an object qualification executable, not the installed
xdr_test/rpc_test suite; native librpcsvc, complete libc linkage and installation
metadata must still be integrated before claiming that suite is converted.

Evidence: /usr/obj/usr/src/bazel-libc-xdr-test-20261028-r2 records one executed
passing native_xdr ATF case (double/enumeration decode and byte-exact encode).
qualification/fixture-and-link.json confirms both generated files match fresh
Make fixture output and required XDR functions are defined in the executable,
not merely resolved to SDK libc. SDK libc/libsys, host loader/kernel and native
ATF runtime remain dependencies. No record transport, malformed stream, failure
allocation, installed image or full libc runtime coverage is claimed.
The first run's ordinary-object/PIE link failure remains recorded separately.

Frontend review: build-bsd's format-5 targets/tests already express this case,
and its maintained qualification path captured the test reports. No C/backend
contract update required. No host installation or network activity.

## 2026-10-28: native librpcsvc and generated protocol headers

Adds native static/PIE archives and librpcsvc.so.5, optional NIS source selection,
14 declared rpcgen XDR actions and corresponding include/rpcsvc header actions.
The schema inventory is shared as reviewed source metadata in protocols.bzl.
Header generation preserves include/rpcsvc Make's -DWANT_NFS3; library XDR
sources preserve its separate -C generation without that define. Explicit
rpcsvc/ and local header views support handwritten and generated callers.
No Make invocation, source rewriting or implicit output discovery is used in
native compilation. Static/shared/debug files and development symlink carry
the maintained runtime package metadata; include installation remains the
separate include/rpcsvc component's unfinished responsibility.

Evidence: /usr/obj/usr/src/bazel-rpcsvc-complete-20261028/qualification/parity.json
against bazel-rpcsvc-make-20261028, NIS disabled. All 14 generated XDR C files
are byte-identical; static member inventory (19), archive/global symbols,
shared globals (143), dependency/SONAME/flags and six installation records match.
No whole archive/debug byte equivalence, generated-header comparison, package
archive construction, live RPC or installed-image qualification is claimed.
PIE archive builds but has not been independently compared in this run.
NIS-enabled source selection is declared but not qualified; the previously
recorded missing NIS SDK libc support remains unresolved. The native libc
aggregate and the installed RPC test suite remain subsequent integration work.

Frontend review: existing explicit targets and nis setting work through the
maintained build-bsd format-5 interface; staging metadata uses existing helpers.
No frontend/backend contract change, host installation or publication occurred.

## 2026-10-28: maintained RPC suite programs and staging

Adds native rpc_test and xdr_test from unchanged NetBSD sources, retaining
libnetbsd, ATF, librpcsvc and libutil dependencies. Installed variants retain
Make's no-RPATH PIE link contract. Separate native-runtime test variants use
$ORIGIN RPATH (not RUNPATH) to include libc's auxiliary libsys in the declared
runtime closure. Strict existing elf-runtime-check.py confirms all five selected
libraries before Kyua runs. No loader check was relaxed: intermediate failures
caught an incorrect ATF SONAME and nontransitive lookup of host libsys. Narrow
checker visibility and explicit Python/runtime inputs complete those dependencies.

Eight case targets preserve the maintained inventory. case_raw and case_xdr
are local; the six network/service cases carry manual/requires-network tags and
remain unexecuted. Installed Kyuafile still includes both complete ATF programs.
Installation stages both programs, debug files, Kyuafile and owned directories.

Evidence: /usr/obj/usr/src/bazel-libc-rpc-tests-20261028-r6: two Kyua cases executed
and passed, with five declared-library checks each. qualification/parity.json
compares saved installed-program artifacts against bazel-libc-rpc-tests-make-
20261028: rpc_test 6 globals, xdr_test 10 globals, matching ordered dependencies,
flags/no-RPATH and 11 unique installation records. Runtime variants are distinct
from these metadata-compared installed variants. SDK libc/libsys and host kernel
remain in use; this does not qualify native complete libc, all RPC cases, installed
image startup, full binary/debug bytes or package archive lifecycle.

Frontend review: existing targets/tests and per-case test selection work through
build-bsd format 5. No frontend/backend contract change or host installation.

## 2026-10-28: complete libc RPC object inventory

Adds all 58 configured RPC C sources (56 maintained plus generated crypt client
and XDR) as native rpc_objects, with declared crypt.h/client/XDR generation and
explicit RPC/libc private headers. Ordinary/PIC archives are qualification
artifacts; no replacement library is installed or linked into consumers.
Preserves BROKEN_DES, PORTMAP, DES_BUILTIN, libc namespace/fortify/revision/TLS
and default unwind options. NLS, NIS and IPv6-support use existing typed settings;
new ns_caching (default true) and hesiod (default false) follow src.opts.mk and
control NS_CACHING/HESIOD definitions. Configuration inventory remains native
Bazel source metadata, not a runtime Make parser.

Evidence: /usr/obj/usr/src/bazel-libc-rpc-20261028/qualification/parity.json
against freshly compiled bazel-libc-rpc-make-20261028. Selected profile has NIS
and Hesiod disabled, caching/NLS/IPv6 support enabled. All 116 ordinary/PIC
objects match global symbols, unresolved symbols and .text bytes; all three
generated files match byte for byte. The comparison checks all 58 members,
including secure RPC, transport, name-service and netlink sources.
No relocation/all-allocated-section, complete debug, final ABI-version-map,
libc-link, runtime or installed-image equivalence is claimed. Configuration
variants, default-unwind overrides, RPC manuals/aliases and netconfig/rpc config
installation remain integration work. Existing RPC tests still use SDK libc
until the complete native library and its private dependency closure are linked.

Frontend review: existing format-5 build-settings accepts typed ns_caching and
hesiod labels through source_graph.setting_arguments; existing targets cover
archives/generator outputs. No build-bsd C or backend contract change needed.
Make remains production default; no host installation or service changes.

## 2026-10-28: libc nameser and ISC object groups

Adds all six maintained nameser sources and both ISC event sources as native
libc object groups, with ordinary/PIC qualification archives. Declares the
maintained portability and private ISC event/list/platform headers explicitly;
_LIBC behavior comes from port_before.h, preserving the source's conditional
include paths. The first build exposed the missing private eventlib dependency;
no ambient header path or replacement header was introduced to bypass it.
Nameser Symbol.map is exposed for the eventual complete libc link.

Evidence: /usr/obj/usr/src/bazel-libc-nameser-isc-20261028-r2/qualification has
parity-nameser.json (12 objects) and parity-isc.json (4 objects), compared with
fresh maintained Make objects in bazel-libc-nameser-isc-make-20261028. All match
global symbols, unresolved symbols and .text bytes. No final libc link, ABI
versioning, relocation/all-allocated-section, full debug, installation or runtime
qualification is claimed. Resolver sources with name-resolution DTrace hooks
remain separate native integration work; these groups do not disable or replace
those sources or probes.

Frontend review: existing format-5 explicit targets and NLS setting cover these
object groups through build-bsd; no frontend/backend contract changes needed.
No network queries, host installation or service changes were performed.

## 2026-10-28: native resolver objects with preserved DTrace inputs

Adds all 14 maintained resolver C sources, explicit private/configuration headers,
and libc-owned nameres_provider header generation using declared native DTrace
bootstrap tools. The provider schema includes nameres and semwait and belongs to
the complete libc aggregate, not individual resolver/NSS/semaphore sublibraries.
Resolver objects retain configured WITH_COVERAGE_DTRACE probe references and
__bsd_dof_anchor_nameres_provider. Qualification archives are RAW compilation
objects; they are not final linkable libc archives. Final combined-group DTrace
rewriting/DOF/anchor retention must still be implemented once all contributors
are present. No standalone partial provider object was substituted for that work.

Evidence: /usr/obj/usr/src/bazel-libc-resolv-20261028/qualification/parity.json
against fresh bazel-libc-resolv-make-20261028: all 28 ordinary/PIC objects match
global and unresolved symbols and .text bytes with DTrace enabled. provider.json
also records a byte-identical generated provider header and all eight probe/
enabled references plus the static archive anchor in raw res_send.o. These are
pre-DOF checks, not final rewritten-site, provider registration or live firing
qualification. DTrace-disabled and other configurations, full debug/relocations,
full libc linkage/versioning, installation and runtime remain open.

Frontend review: existing explicit targets and dtrace setting cover the generated
header and object variants through build-bsd format 5. No frontend/backend
contract change needed. No DNS queries, host install or service changes occurred.

## 2026-10-28: complete libc inet object inventory

Adds all 14 maintained inet C sources as native inet_objects with ordinary/PIC
qualification archives and Symbol.map visibility for the future libc link.
Explicit private headers preserve port_before/after and the resolver context
interface used by nsap_addr. The initial compile exposed resolv_mt.h missing
from the declared dependency set; it was added without an ambient include path.

Evidence: /usr/obj/usr/src/bazel-libc-inet-build-20261028-r2/qualification/parity.json
against fresh bazel-libc-inet-make-20261028. All 28 ordinary/PIC objects match
Make global symbols, unresolved symbols and .text bytes. This does not qualify
full debug/allocated-section/relocation identity, final libc ABI, installation
or runtime. Existing NetBSD inet_addr_test and inet_network_test are identified
for later integration; they were not executed in this object-comparison run.
No address parsing behavior or source implementation was changed.

Frontend review: existing explicit targets and NLS setting cover the group via
build-bsd format 5. No frontend/backend contract update needed. No host installs,
network queries or service changes. Complete native libc remains unfinished.

## 2026-10-28: maintained inet parser cases against native objects

Adds unchanged NetBSD inet_addr and inet_network test sources as native Bazel
object-qualification programs. Explicit PIC archive selection supports PIE tests
without changing production object flags. Four ATF case targets preserve both
programs' basic/error cases; no assertions or test data were weakened.

Evidence: /usr/obj/usr/src/bazel-libc-inet-tests-20261028 records four executed
passing cases. qualification/link-ownership.json verifies saved executables define
inet_addr/inet_ntoa and inet_network from the native archive, rather than testing
SDK definitions of those functions. Existing SDK libc supplies remaining runtime
functions; native ATF and its declared runtime use the maintained Bazel adapter.
These are IPv4/parser cases, not coverage of all inet functions or live networking.
The complete installed libc test suite, metadata, native libc link and installed
image qualification remain open; no partial test executables replace that suite.

Frontend review: existing format-5 targets/tests express all four cases through
build-bsd; no frontend/backend contract update needed. No host install or network
operations were performed by these string/address conversion tests.

## 2026-10-28: native libc network/NSS object inventory

Adds configured network/NSS sources, native lex/yacc actions and generated parser
header dependencies. Preserves -p_nsyy/-P_nsyy and scopes YY_BUF_SIZE=1024 to a
separate lexer object target. Both groups retain libc private interfaces and
configured NIS, caching, Hesiod, NLS, IPv6 support and DTrace definitions. Optional
caching/Hesiod sources are selected by typed settings; raw NSS probe references
remain inputs to the still-pending combined libc DOF step. No runtime Make
parsing, generated-source patching or implicit source/header discovery is used.

Evidence: /usr/obj/usr/src/bazel-libc-net-20261028/qualification/parity.json
against fresh bazel-libc-net-make-20261028. Selected configuration (caching on,
Hesiod/NIS off, DTrace on) contains 41 C units including lexer/parser. All 82
ordinary/PIC objects match global symbols, unresolved symbols and .text bytes.
generation-and-probes.json separately verifies nsparser.h exact bytes and both
generated C files equal after normalizing ONLY enumerated #line source/output
paths. Original artifacts are unchanged. Two nsdispatch object variants retain
probe/enabled references and the static archive anchor.

This is not final libc linkage, DOF rewriting/registration, complete object/debug
identity, runtime NSS behavior or configuration-variant qualification. Generated
nsswitch.conf plus hosts/networks/protocols configuration and manual installation
remain separate required work; current targets do not claim to stage those files.
Full libc tests and installed image qualification remain open.

Frontend review: existing format-5 targets and typed settings cover objects and
generators via build-bsd; no frontend/backend contract changes required. No host
name-service configuration, installed software or network service was changed.

## 2026-10-28: complete libc configuration staging and generated-state partition

Adds libc:config_archive with all maintained libc configuration: group,
master.passwd, shells, hosts, hosts.equiv, networks, protocols, nsswitch.conf,
mac.conf, netconfig and rpc. Reuses gen-nsswitch.sh through existing bsd_template
with declared template, shell/sed/cat and typed NIS input. Audit found libc/gen's
global CONFSPACKAGE=runtime governs these files, not libc's PACKAGE=clibs.
master.passwd retains 0600; other configuration files retain 0644 and config tags.

Reuses existing etc:account_databases rather than introducing another generator.
Corrects its existing installation manifest: passwd/pwd.db/spwd.db are generated
state, untagged in Make and rebuilt by runtime.ucl construction/post-install
logic. They must not be packaged as prebuilt replacements for local account
configuration. The combined fresh-system staging archive contains both explicit
configuration manifests and that separate untagged generated-state manifest.
There are no existing source-graph consumers of the account manifest requiring
migration; its standalone archive also retains the corrected tags.

Evidence: bazel-libc-config-20261028-r2 and bazel-libc-config-nis-20261028-r2 under
/usr/obj/usr/src, each qualification/parity.json, against separate no/yes Make
configuration references. Both configurations match all 15 installation records
(11 configuration files, 3 generated files, /etc directory metadata) and all 14
file bytes, including account databases. Exactly passwd/pwd.db/spwd.db are
untagged. Checks read saved archive artifacts; no host accounts/configuration
were modified. Initial reference setup failed because it omitted the maintained
IMAKE_INSTALL unprivileged flags; corrected reference queries that contract and
uses NO_SUBDIR for this libc installconfig-only comparison.

This proves fresh staging, not package upgrade/config-merge behavior, existing
account migration, NSS/NIS service behavior or installed image startup. Native
complete libc, package lifecycle and system qualification remain open.

Frontend review: existing format-5 targets/NIS input and maintained template,
account-generation and staging helpers expose this through build-bsd. No new
frontend C or backend contract needed; no one-off replacement build path.

## 2026-10-28: complete libc ACL/MAC object inventory

Adds all 32 maintained posix1e compilation sources: ACL interfaces, extended
attributes, MAC interfaces and shared NFSv4 ACL implementation. Native Bazel
compiles //sys/kern:subr_acl_nfs4.c directly in userland mode rather than creating
an independently maintained copy; narrow source visibility permits that sharing.
Preserves _ACL_PRIVATE, libc private interfaces and ordinary/PIC variants.
Existing mac.conf staging remains part of libc:config_archive.

Evidence: /usr/obj/usr/src/bazel-libc-posix1e-build-20261028/qualification/parity.json
against fresh bazel-libc-posix1e-make-20261028. All 64 ordinary/PIC objects match
global symbols, unresolved symbols and .text bytes. Make's copied subr_acl_nfs4.c
also matches the declared kernel source byte for byte. This is userland object
qualification, not kernel module qualification or installed ACL/MAC enforcement.
Full debug/source-path/allocated-section/relocation identity, libc symbol-version
link, manuals, installed tests and runtime filesystem/security behavior remain
open. No ACL policy, MAC enforcement, host file labels or runtime code changed.

Frontend review: existing explicit targets and NLS setting cover this group via
build-bsd format 5; no frontend/backend contract change needed. The shared source
export does not change existing kernel target recipes or flags. No host install.

## 2026-10-28: libc database object inventory

Adds all 31 maintained database sources: btree (13), db dispatch (1), hash
and ndbm (7), mpool (2), recno (8). Explicit private headers preserve relative
includes and __DBINTERFACE_PRIVATE; no source copies or ambient include paths.
Ordinary/PIC archives are qualification artifacts for eventual complete libc.

Evidence: /usr/obj/usr/src/bazel-libc-db-build-20261028/qualification/parity.json
against fresh bazel-libc-db-make-20261028. All 62 objects match global symbols,
unresolved symbols and .text bytes. Builds used build-bsd explicit format-5
inputs and 16 jobs. Scripts and original reference logs remain under /usr/obj.
No complete libc link, ABI map, debug/data/relocation equality, database runtime,
manuals or installed tests are claimed. World, kernel and package completion
remain open.

Frontend review: existing explicit target and NLS settings cover these inputs;
no build-bsd C/backend contract change is needed. No host database modification,
installation or package publication was performed.

## 2026-10-28: native libc floating-point conversion objects

Adds the complete amd64 gdtoa inventory: four libc glue/conversion sources,
machdep_ldisx.c and sixteen netlib sources including strtorx.c. Native targets
consume contrib sources directly rather than recreating Make's gdtoa_ source
aliases. Separate cc_library groups apply -fno-strict-aliasing only to imported
sources. Declared headers cover architecture arith/gd_qnan, libc math/private
interfaces, locale and stdio floatio; architecture compatibility remains explicit.

Evidence: /usr/obj/usr/src/bazel-libc-gdtoa-build-20261028/qualification/parity.json
and fresh bazel-libc-gdtoa-make-20261028. All 42 ordinary/PIC objects match .text,
global and unresolved symbols. The comparison maps imported object names to
Make's gdtoa_ prefix; no output bytes are rewritten. Other architectures,
complete libc linking/version maps, data/relocation/debug identity and runtime
floating-point edge cases remain unqualified. This is not complete libc.

Frontend review: build-bsd format-5 targets and existing NLS setting carry the
inputs; native toolchain compile rules retain flags and headers in action inputs.
No frontend/backend contract change or host installation is needed.

## 2026-10-28: complete libc stdio compilation inventory

Adds all 111 maintained stdio compilation sources, including narrow/wide stream
I/O, memory streams, positional formatting, scanf and extended printf routines.
Private dependencies explicitly cover local stdio headers, locale/multibyte
interfaces, gdtoa declarations/architecture constants and libc private headers.
Initial native build exposed fclose's angle-bracket spinlock.h dependency; it
was added to the declared private header set. The failed run remains recorded.

Evidence: /usr/obj/usr/src/bazel-libc-stdio-build-20261028-r2/qualification/parity.json
against fresh bazel-libc-stdio-make-20261028. All 222 ordinary/PIC objects match
.text bytes, global symbols and unresolved symbols. Builds used 16 jobs. No
source edits, broad ambient include paths or runtime fallbacks were introduced.

This is compilation qualification only. Full libc linkage/ABI versioning,
data/relocation/debug parity, manual staging and installed stdio tests remain
open. The maintained lib/libc/tests/stdio suite contains 20 local and 10 NetBSD
ATF test programs; stream cancellation, EINTR, thread locking, floating-point,
locale and wide-character runtime behavior are not established by this result.

Frontend review: existing format-5 explicit targets and NLS configuration carry
the inputs through build-bsd. No new frontend/backend contract is required.
No host installation, upgrade, policy or account changes were performed.

## 2026-10-28: native libc locale with both iconv configurations

Adds all 60 common locale sources and explicit selection of four iconv-backed
or four independent C16/C32 conversion sources through the existing iconv build
setting. Declared dependencies cover locale private headers, timelocal.h and
Citrus interfaces. Iconv-disabled builds omit the Citrus dependency. The initial
build found timelocal.h's transitive xlocale_private.h include; the existing
locale header view now supplies it, without an ambient include directory.

Evidence: /usr/obj/usr/src/bazel-libc-locale-{yes,no}-build-20261028-r2/qualification/parity.json
against fresh bazel-libc-locale-{yes,no}-make-20261028. Both configurations match
all 128 ordinary/PIC objects in .text, global and unresolved symbols (256
comparisons). Artifacts are read from each run's saved manifest, not mutable
bazel-bin symlinks. Failed initial native output remains recorded.

This does not qualify complete libc linkage, data/relocation/debug identity,
manuals, locale database installation, Citrus runtime modules or locale runtime
semantics. The maintained locale ATF suite, including character conversion and
newlocale, remains to be integrated with the complete native library and data.

Frontend review: existing format-5 input targets and typed iconv/NLS settings
cover both configurations through build-bsd. No frontend/backend contract change
is required. No host locale settings, installation or upgrades were changed.

## 2026-10-28: libc iconv and static wrapper objects

Adds all 22 regular iconv/Citrus libc sources and the 11 wrappers selected by
libc_nonshared/Makefile.iconv for static libc. Wrappers have a separate source
group/archive and must not enter the shared libc link. Iconv-disabled targets
are incompatible, reflecting their absence from that configuration. Private
headers and normal libc compilation flags are explicit native dependencies.

Evidence: /usr/obj/usr/src/bazel-libc-iconv-build-20261028/qualification/parity.json
against fresh bazel-libc-iconv-make-20261028. All 55 objects match .text, global
and unresolved symbols: 22 ordinary, 22 PIC, and 11 static wrappers. Native
build ran through build-bsd using 16 jobs and the existing iconv setting.

The separate libc_nonshared library is not qualified here: it requires PIC,
hidden visibility and its own source/flag/install contract. Neither complete
libc linking, ABI maps, data/relocation/debug identity, manual installation nor
runtime loading of Citrus modules/data is established by these comparisons.
Those remain required for complete library and system qualification.

Frontend review: existing format-5 targets and typed iconv/NLS inputs cover the
new groups without frontend/backend contract changes. No host install or
conversion-module path overrides were introduced.

## 2026-10-28: libc_nonshared archive and installation metadata

Adds a native libc_nonshared archive with the maintained amd64 -fpic, PIC and
hidden visibility contract. __stub.c is always included; the eleven wrappers
are selected by iconv. A native nonshared_sources.bzl inventory is shared with
static libc's wrapper group to prevent those native declarations diverging.
Sources are consumed directly from libc/iconv; libc compilation flags are not
inherited into the separate library. One install manifest places the archive at
/usr/lib/libc_nonshared.a, root:wheel, mode 0444, package=clibs,dev.

Evidence: /usr/obj/usr/src/bazel-libc-nonshared-build-20261028-r3/qualification/
parity.json and archive-install-parity.json against the complete build/private
install reference bazel-libc-nonshared-make-20261028. All 12 members match .text,
global/unresolved symbols, and symbol binding/type/visibility. Archive member
inventory and the sole installation metadata record match. Initial candidates
used mode 0644 and -fPIC; final declarations match Make's 0444 and -fpic.

This qualifies the iconv-enabled archive and manifest only. Iconv-disabled
stub-only build, archive/debug byte identity, complete libc linker-script use,
installed package construction and runtime remain open. No host installation.
Frontend review: build-bsd's existing format-5 targets/iconv input and maintained
archive/install helpers cover this contract without new frontend options.

## 2026-10-28: disabled-iconv nonshared variant and reference closure fix

Qualified libc_nonshared with iconv disabled: the native and Make archives
contain exactly __stub.o, with matching code, global/unresolved symbols and
symbol visibility. The sole install record remains root:wheel 0444 at
/usr/lib/libc_nonshared.a with package=clibs,dev. Evidence:
/usr/obj/usr/src/bazel-libc-nonshared-noiconv-build-20261028/qualification/
parity.json and archive-install-parity.json, compared with the passed private
reference bazel-libc-nonshared-noiconv-make-20261028-r2.

The initial reference correctly refused certification, but exposed a helper
ordering defect: BuildEnvironment captured Make includes before component
option overrides. Disabling iconv removed Makefile.iconv from the legitimate
include closure, producing a false change-during-export failure after install.
install-reference.py now verifies baseline inputs, applies and checks overrides,
captures the selected include closure before building, and retains baseline
hashes in addition to selected inputs. End-of-build closure/hash verification
remains enabled. The initial failed reference is retained and not counted as
qualified. The actual option-dependent build/install now passes, and all six
existing install-reference CLI guard tests pass under
/usr/obj/usr/src/bazel-install-reference-guards-20261028.

Frontend/backend review: this fixes the maintained reference helper used for
qualification, without changing build-bsd inputs, staged SDK or world profile.
No host installation. Full archive/debug identity and native libc link/runtime
remain open even though both nonshared source-selection variants are checked.

## 2026-10-28: native libc time routines and timezone-detection option

Adds all seven stdtime sources, including direct contrib/tzcode sources. Native
groups preserve the forced tzconfig.h include for the six configured routines,
exclude it from time32.c, and limit ALL_STATE/THREAD_SAFE/DETECT_TZ_CHANGES to
localtime.c. The new typed detect_tz_changes setting defaults off, matching
src.opts.mk. Explicit headers cover tzcode, locale internals and libc interfaces.

Evidence: /usr/obj/usr/src/bazel-libc-{stdtime,stdtime-detect}-build-20261028/
qualification/parity.json against matching fresh Make references. Both disabled
and enabled timezone-detection configurations match all 14 ordinary/PIC objects
in .text, global and unresolved symbols (28 comparisons total). Native builds
run through build-bsd format 5 with 16 jobs; no host timezone changes.

Complete libc symbol-map generation must also apply DETECT_TZ_CHANGES to
Version.map as maintained Make does. That aggregate link remains open; this
object qualification does not claim ABI-version-map completion. Runtime timezone
reloads, DST/leap-second/locale behavior, installed zone data/manuals and full
data/relocation/debug identity remain unqualified.

Frontend review: source_graph.py already forwards typed source build settings;
build-bsd accepts the existing explicit input file. Both option values were
exercised through that path. No new frontend C argument or helper is needed.

## 2026-10-28: libc regular-expression object inventory

Adds all four libc regex sources with POSIX_MISTAKE and libc's locale/collation
path. This is distinct from the existing standalone libregex LIBREGEX build.
engine.c is a declared textual header, preserving its repeated inclusion under
different definitions in regexec.c; it is not compiled as an extra object.
Locale private headers are declared dependencies.

Evidence: /usr/obj/usr/src/bazel-libc-regex-build-20261028/qualification/parity.json
against fresh bazel-libc-regex-make-20261028. All eight ordinary/PIC objects
match .text, global and unresolved symbols. Both builds used 16 jobs.
Complete libc linkage/ABI versioning, data/relocation/debug identity, manuals and
runtime multibyte/collation qualification remain open. The maintained libc regex
suite includes multibyte, data-driven matching, exhaustion and ATT cases; the
existing SKIP_LEFTASSOC expectation is inherited test policy, not newly hidden
by this migration. Those libc runtime tests were not run in this comparison.

Frontend review: existing build-bsd format-5 explicit targets/NLS setting cover
the group; no new C/backend contract required. No host installation or locale
configuration changes were made.

## 2026-10-28: native non-allocator stdlib inventory

Adds the 74 sources selected by stdlib/Makefile.inc before its separate allocator
inventory. The amd64 default selects div.S/ldiv.S/lldiv.S; a typed default-on
machdep_optimizations setting selects portable C alternatives when disabled.
The qsort group preserves its specific -Wsign-compare flag. Shared algorithm
sources included textually by other functions are declared textual inputs.
_Exit.c is compiled directly; Make's C99_Exit alias is used only to locate the
reference object during comparison. Private headers cover blocks, locking,
locale, gdtoa and float formatting. No runtime source changes were introduced.

Evidence: /usr/obj/usr/src/bazel-libc-stdlib-build-20261028/qualification/parity.json
against fresh bazel-libc-stdlib-make-20261028. All 148 ordinary/PIC objects match
.text bytes, global and unresolved symbols, including the assembly divisions.
This qualifies default amd64 selection, not the portable-division option yet.
The two sized-free sources and selected allocator (including production/debug
and address-width configuration) remain a separate outstanding migration.

Full libc link/versioning, data/relocation/debug identity, installed manuals,
startup/exit/thread behavior, environment, sort and numeric runtime tests remain
open. Existing maintained stdlib tests must exercise the complete native libc.
Frontend review: existing format-5 typed build-settings input supports the new
source selection; build-bsd C/backend and manual interfaces need no new option.
No host installation, account/environment modification or upgrade performed.

## 2026-10-28: portable stdlib selection qualified; allocator integration boundary

Qualified machdep_optimizations=false against WITHOUT_MACHDEP_OPTIMIZATIONS.
All 148 ordinary/PIC non-allocator stdlib objects match Make .text, global and
unresolved symbols. The Make reference compiles div.c/ldiv.c/lldiv.c, matching
the native configured selection. Evidence:
/usr/obj/usr/src/bazel-libc-stdlib-portable-build-20261028/qualification/parity.json
and bazel-libc-stdlib-portable-make-20261028. This closes the portable-division
object comparison gap from the prior checkpoint; it does not establish other
architecture configurations, runtime arithmetic or complete libc linkage.

Allocator review identifies 62 imported jemalloc sources plus two libc sized-free
wrappers. Native integration must preserve the selected allocator, debug versus
production behavior, and JEMALLOC_LG_VADDR_WIDE configuration. Production builds
must carry configuration-derived evidence into the normal publication path:
release/scripts/check-malloc-production.sh currently checks the object stamp
and actual libc debug signature, or the packaged libc signature. A stand-alone
native allocator archive is not publishable-world evidence and must not create
a success stamp detached from the full linked libc artifact. Preserve the
explicit ALLOW_DEBUG_MALLOC test exception and existing package/identity checks.

Frontend review: build-bsd currently passes WITH_MALLOC_PRODUCTION=yes for
production Make builds and WITHOUT_MALLOC_PRODUCTION=yes otherwise. The native
qualification interface's typed inputs handle the verified optimization toggle.
No publication/helper changes were made before a native allocator/full-library
artifact exists to verify. Allocator, complete libc/runtime and publication
qualification remain outstanding; Make stays the production backend.

## 2026-10-28: native jemalloc debug and production object groups

Adds all 62 maintained jemalloc sources as direct contrib inputs, with the
maintained 5BSD platform headers and imported header tree declared in Bazel.
No configure-generated substitutes or copied source aliases are introduced.
Typed malloc_production (default false) and jemalloc_lg_vaddr_wide (default true)
settings select MALLOC_PRODUCTION and _USE_LG_VADDR_WIDE in compiler actions.
Headers use scoped include roots; sources are an explicit reviewed inventory.

Evidence: /usr/obj/usr/src/bazel-libc-jemalloc-build-20261028/qualification/parity.json
(debug) and bazel-libc-jemalloc-production-build-20261028/qualification/parity.json
(production). Each matches all 124 ordinary/PIC objects in .text, global and
unresolved symbols (248 comparisons). Explicit debug reference is
bazel-libc-jemalloc-debug-make-20261028; production reference is
bazel-libc-jemalloc-make-20261028. Initial comparison failed because that first
reference inherited WITH_MALLOC_PRODUCTION from the recorded profile while
native defaulted to debug. Its receipt's original debug scope label is incorrect;
actual commands and mode stamp show production. The failure was not relaxed:
an explicit debug reference and separate native production build resolved it.

qualification/modes.json in the production run also checks saved archives:
assertion signature present in both debug archives, absent in both production
archives. This is not a complete linked-libc production/publication check.
No success stamp is emitted from these component archives. Sized-free wrappers,
non-wide address configuration, complete libc ABI/linking, debug/data/relocation
identity, runtime allocation/utrace, concurrency and performance remain open.

Frontend review: existing format-5 typed settings pass both modes through
build-bsd. Make production/default behavior and publication gates remain intact.
Native publication integration still requires a complete verified libc artifact;
no premature marker or production-backend switch was added. No host install.

## 2026-10-28: sized-free wrappers and maintained ATF case

Adds native ordinary/PIC targets for free_sized.c and free_aligned_sized.c,
preserving internal implementations and weak public aliases. Allocator Symbol.map
is exported for eventual aggregate libc ABI linkage. Four objects match Make
.text, global and unresolved symbols: evidence under
/usr/obj/usr/src/bazel-libc-sized-free-build-20261028/qualification/parity.json
against bazel-libc-sized-free-make-20261028.

The unchanged maintained free_sized_test.c now has a native qualification binary
and Bazel ATF case. Evidence: bazel-libc-sized-free-test-20261028-r2/test-reports/0
reports one passed, no skips/failures. Null pointers, ordinary allocation sizes
1 through 65536 and 64-byte-aligned sizes 64 through 65536 are exercised.
qualification/link-proof.json verifies all four wrapper symbols are defined in
the native binary; malloc/aligned_alloc/__free still resolve to staged SDK libc.
This is wrapper runtime coverage, not native jemalloc or full libc runtime proof.
Initial test analysis failed on archive visibility; a narrow test-package grant
fixed it. No public visibility expansion or source behavior change was needed.

ATF executes through the maintained direct runner, which reports the standard
outside-Kyua warning; this does not qualify installed Kyua suite integration.
Full libc versioning/link, complete allocator runtime/performance, manual staging,
installed tests and publication remain open. Frontend review: existing format-5
targets/tests and maintained ATF adapter cover the changes through build-bsd.
No host installation or global allocator changes.

## 2026-10-28: native libc UUID objects

Adds all nine maintained UUID sources with explicit native ordinary/PIC targets
and exports the existing Symbol.map for eventual libc ABI linkage. Sources and
public UUID interfaces are unchanged; uuid_create continues to call uuidgen.
Evidence: /usr/obj/usr/src/bazel-libc-uuid-build-20261028/qualification/parity.json
against fresh bazel-libc-uuid-make-20261028. All 18 objects match .text, global
and unresolved symbols. Builds used 16 jobs through the maintained frontend.

Complete libc linkage/version maps, data/relocation/debug identity, manuals,
UUID parsing/endian/generation runtime tests and syscall error behavior remain
unqualified. Frontend review: existing format-5 targets/NLS setting carry this
group through build-bsd; no new backend/helper contract required. No host install.

## 2026-10-28: native libc message-catalog implementation

Adds msgcat.c ordinary/PIC objects alongside the existing catalog-data targets,
with declared libc and locale private headers. Existing catalog generation and
installation declarations are unchanged. Both objects match Make .text, global
and unresolved symbols: /usr/obj/usr/src/bazel-libc-msgcat-build-20261028/
qualification/parity.json against bazel-libc-msgcat-make-20261028.

This verifies compilation, not complete libc linkage, ABI maps, manual staging,
data/relocation/debug identity or runtime catalog loading/cache/error behavior.
Existing secure_getenv(NLSPATH) handling remains unchanged. Frontend review:
format-5 explicit targets and NLS setting cover the new group through build-bsd;
no frontend/backend contract change needed. No host locale changes or install.

## 2026-10-28: compatibility, fortified helpers and C23 bit operations

Adds complete inventories for compat-43 (8 sources), secure (19) and stdbit (14).
Separate formatter and stack-protector groups retain per-source flags. Initial
secure comparison found extra SSP instrumentation in libc_stack_protector.c;
libc/Makefile explicitly excludes this source from SSP_CFLAGS. Native compilation
now applies -fno-stack-protector only to that implementation. It does not disable
stack protection elsewhere. Initial mismatch evidence remains recorded.

Evidence: /usr/obj/usr/src/bazel-libc-smallgroups-build-20261028-r2/qualification/
{compat-43,secure,stdbit}-parity.json against bazel-libc-smallgroups-make-20261028.
All 82 ordinary/PIC objects match .text, global and unresolved symbols. No source
behavior changes. Full libc linkage/versioning, data/relocation/debug identity,
manuals, runtime signal/identity compatibility, overflow failure behavior and
C23 bit-operation edge cases remain unqualified. Maintained fortify tests are
present and must be integrated with the complete native library.

Frontend review: explicit format-5 targets and existing NLS input exercise these
groups through build-bsd; no new C/backend contract required. No host identity,
signals, installation or policy modifications were performed.

## 2026-10-28: profiling, libc startup and x86 context objects

Adds gmon.c/mcount.c, libc_start1.c and getcontextx.c native ordinary/PIC groups.
Startup preserves amd64 CRT_IRELOC_RELA and declares amd64/reloc.c as a textual
input with the appropriate include view. No source copies or runtime overrides.
Evidence: /usr/obj/usr/src/bazel-libc-startup-build-20261028/qualification/
{gmon,csu,x86-gen}-parity.json against bazel-libc-startup-make-20261028.
All eight objects match .text, global and unresolved symbols.

This does not qualify complete startup/linkage, full relocation/debug/data
identity, IFUNC/static executable startup, profiling output or extended CPU
context runtime. The separate profiled-object contract must preserve Make's
rule that mcount.po reuses an unprofiled mcount.o; no profiled archive is claimed
by the ordinary/PIC groups here. Other architectures remain unqualified.
Frontend review: existing format-5 explicit targets/NLS setting suffice through
build-bsd; no new frontend/helper contract required. No host install or profiling
state modification was performed.

## 2026-10-28: libc C system-interface wrappers

Adds the 40 maintained INTERPOSED wrappers and 21 pseudo-interface C sources.
Native declarations consume ptrace.c, recvmmsg.c and sendmmsg.c directly from
libsys, matching Make's source search; the other sources reside under libc/sys.
Initial inventory/build checks caught those shared origins, and failed setup/run
evidence remains recorded. No copied implementations or source modifications.

Evidence: /usr/obj/usr/src/bazel-libc-syswrappers-build-20261028-r2/qualification/
parity.json against bazel-libc-syswrappers-make-20261028. All 122 ordinary/PIC
objects match .text, global and unresolved symbols. Builds use 16 jobs.

This does not complete libc's syscall subsystem. Generated syscall assembly,
shared empty bodies/filter behavior, libc_stubs.c, static auxv/interposing table,
other common libsys sources, aggregate ABI/link and runtime interposition remain
separate requirements. Cancellation, fork/context, signal, I/O and process-control
behavior need runtime tests with the complete native libc/libsys combination.
Full data/relocation/debug identity and manual installation remain unqualified.

Frontend review: existing format-5 targets/NLS configuration cover the new C
groups through build-bsd; no frontend/backend contract change needed. Narrow
libsys source exports do not alter its existing compile flags. No host process
control, account/policy changes or installation performed.

## 2026-10-28: libc-specific static/shared libsys source variants

Adds distinct native groups for libc's static auxv.c/interposing_table.c and
shared PIC libc_stubs.c, consuming the maintained libsys sources directly.
The static and shared archive outputs select only their respective object group;
there is no combined archive or alternate implementation. This preserves the
variant split recorded by lib/libsys/Makefile.sys.

Evidence: /usr/obj/usr/src/bazel-libc-libsysvariants-build-20261028/qualification/
parity.json against bazel-libc-libsysvariants-make-20261028. All three selected
objects match .text, global and unresolved symbols. Native libsys itself still
has no complete implementation/link target; its existing BUILD previously only
provided headers and source exports. These libc-mode groups do not qualify the
libsys library or dynamic auxiliary-filter behavior.

Generated syscall assembly, common libsys sources, complete static/shared libc
linking and runtime interposition/filter verification remain outstanding. The
shared elf_aux_info trap stub must be resolved through the intended libsys
runtime mechanism; successful object comparison is not proof of that behavior.
Data/relocation/debug identity and installed package integration remain open.
Frontend review: format-5 explicit targets cover both variants through build-bsd;
no frontend/helper contract change required. No host installation.

## 2026-10-28: common libsys C implementations in libc mode

Adds clock_gettime, gettimeofday, __vdso_gettimeofday, __error, __getosreldate,
getpagesize, getpagesizes and libsys_sigwait as native libc-mode groups using the
maintained libsys source files. Static/PIC variants retain libc compilation flags
and private header dependencies; no standalone libsys library is claimed.

Evidence: /usr/obj/usr/src/bazel-libc-libsyscommon-build-20261028/qualification/
parity.json against bazel-libc-libsyscommon-make-20261028. All 16 ordinary/PIC
objects match .text, global and unresolved symbols. Full data/relocation/debug
identity, generated syscall assembly, architecture support, libc/libsys linking,
ABI maps and runtime time/errno/auxiliary-vector/signal behavior remain open.
The vDSO implementation comparison is not evidence of actual vDSO runtime use.

Frontend review: existing format-5 explicit targets/NLS setting covers these
objects through build-bsd; no new C/backend contract required. Source exports
are restricted to the libc sys package. No host installation or runtime changes.

## 2026-10-28: amd64 libc/libsys architecture support

Adds all ten sources from libsys/amd64/Makefile.sys: five FS/GS/TLS C helpers and
rfork_thread, pdrfork_thread, vfork, cerror and getcontext assembly. The native
assembly header view declares SYS.h. Ordinary and shared groups remain distinct;
the shared group carries libc's empty _SYSCALL_BODY macro even though these
handwritten routines use lower-level syscall instructions directly.

Evidence: /usr/obj/usr/src/bazel-libc-libsysamd64-build-20261028/qualification/
parity.json and text-relocations.json against bazel-libc-libsysamd64-make-20261028.
All 20 ordinary/shared PIC objects match .text, global/unresolved symbols, and
text relocations (offset/type/symbol value/name/addend, excluding symbol-table
indices). This does not establish full relocation/debug/data identity or runtime
FS/GS/TLS, IFUNC, fork/thread, errno or context behavior. Generated syscall stubs,
x86 common sources and complete libc/libsys linking remain outstanding.

Frontend review: existing format-5 target inputs/NLS setting and native toolchain
compile C and assembly through build-bsd; no new helper or C interface required.
Source/header exports have narrow libc sys visibility. No host TLS, process,
context or installation changes were performed.

## 2026-10-28: x86 libc support and Hyper-V selection

Adds __vdso_gettc.c, pkru.c and sched_getcpu_x86.c from the maintained libsys
sources, compiled in libc mode. The typed hyperv setting defaults on for the
current amd64 target, matching src.opts.mk. The timecounter group explicitly
excludes address/undefined sanitizer instrumentation as required for its early
IFUNC use; other sources do not inherit that exclusion.

Evidence: /usr/obj/usr/src/bazel-libc-libsysx86-{yes,no}-build-20261028/qualification/
parity.json against matching fresh Make references. Both Hyper-V configurations
match all six ordinary/PIC objects (12 comparisons) in .text, global and
unresolved symbols. The tested SDK/profile has sanitizers disabled; a complete
sanitized build and early-runtime sanitizer behavior remain unqualified.

This does not qualify runtime Hyper-V/TSC/HPET clock selection or performance,
PKRU/CPU-number operation, full data/relocation/debug identity, generated syscalls,
complete libc/libsys linking or ABI/filter behavior. Frontend review: the existing
format-5 typed build-settings path exercises hyperv true/false through build-bsd;
no new frontend C option or helper contract required. No host CPU/register or
clock configuration changes and no installation performed.

## 2026-10-28: libc string sources, optimized and portable selections

Native explicit source inventories now cover 88 amd64-optimized string sources
and 87 portable sources, including wide-character routines and explicit_bzero.
The existing machdep_optimizations flag selects the implementation; local textual
C/assembly includes and private header dependencies are declared. Early IFUNC
and page-reading sanitizer exclusions are scoped to the applicable groups.

The first comparison caught incorrectly selected portable bcopy/bzero: Make's
.PATH selects amd64 C wrappers even though those names are not in MDSRCS. The
native inventory now explicitly selects those wrappers when optimizations are
on. The original failed comparison and build remain available; no comparator
exception was added.

Evidence: /usr/obj/usr/src/bazel-libc-string-build-20261028-r2/qualification/
parity.json (176 ordinary/PIC objects) and bazel-libc-string-portable-build-20261028/
qualification/parity.json (174), each against its fresh corresponding Make
reference. All 350 comparisons match .text and global/unresolved symbols.
These are raw component archives, not a complete libc. Data/debug/relocation
identity, runtime string/locale/IFUNC behavior, sanitizer-enabled execution,
manual installation, full linking and performance remain unqualified.

Frontend review: build-bsd's existing bazel-test explicit inputs and typed
machdep_optimizations setting exercise both selections; no new CLI/backend or
publication contract is needed for these component targets. No host installation
or runtime configuration changes. The next libc work includes gen routines,
generated syscall assembly and the final aggregate/link/install/runtime gates.

## 2026-10-28: amd64 libc general routines and makecontext tests

Adds all 16 sources selected by amd64/gen/Makefile.inc as explicit native
ordinary/PIC component objects: jump/context handling, floating-point controls,
fabs/infinity and ldexp. ldexp remains the maintained gen source with its msun
s_scalbn.c textual input declared; no generated copy or source substitution.
SYS.h visibility is extended narrowly to this package. Existing libsys and
msun targets are preserved.

Evidence: /usr/obj/usr/src/bazel-libc-amd64gen-build-20261028/qualification/
parity.json against bazel-libc-amd64gen-make-20261028: all 32 ordinary/PIC objects
match .text and global/unresolved symbols. Full relocation/data/debug identity
and complete libc linking/install/ABI qualification remain outstanding.

Native Bazel ATF integration runs the unchanged makecontext_test.c, covering
one through six integer arguments and context return. All six cases pass with
no skips in bazel-libc-amd64gen-test-20261028/receipt.json. Its qualification/
link-proof.json confirms __makecontext is defined and makecontext is the native
weak alias, while getcontext/swapcontext remain SDK imports. This is native
makecontext component coverage with SDK support, not a complete native context
or libc runtime. Jump/signal state, floating-point control tests, invalid context
inputs and performance remain unqualified.

Frontend review: existing build-bsd bazel-test format-5 targets/tests, native
C/assembly toolchain and ATF reporting support these additions without a new
frontend option or backend contract. Make remains the production/default build.
No host installation, signal-policy or account changes were made.

## 2026-10-28: libc directory, traversal and glob objects

Adds 23 explicit gen sources for directory open/read/scan/seek/tell, fts, ftw,
nftw and glob, including the maintained compatibility implementations. fts.c
and glob.c retain their per-source -fblocks option; scandir_b.c's inclusion of
scandir.c is a declared textual input. Private directory/compatibility headers,
block ABI and locale collation headers are explicit dependencies. These targets
currently qualify the FreeBSD amd64 toolchain with Blocks support.

Evidence: /usr/obj/usr/src/bazel-libc-directory-build-20261028/qualification/
parity.json versus bazel-libc-directory-make-20261028: all 46 ordinary/PIC objects
match .text and global/unresolved symbols. Full relocation/data/debug identity,
versioned compatibility ABI, complete libc linking and installation remain open.

The unchanged opendir_test.c and dir2_test.c now run as seven native Bazel ATF
cases. All pass without skips in bazel-libc-directory-test-20261028/receipt.json:
normal and descriptor-based open, invalid descriptor/non-directory/FIFO rejection,
and seek/tell behavior across directory blocks. qualification/link-proof.json
confirms the invoked directory routines are defined in the test executables from
the native archive; other libc and syscall support remains SDK-provided. These
tests do not qualify fts/glob/Blocks traversal, compatibility callers, Capsicum,
threading, filesystem diversity or performance. Those maintained tests remain
required for the broader libc qualification.

Frontend review: existing build-bsd bazel-test explicit targets and tests, typed
NLS option, native compilation and ATF reporting handle this component; no new
frontend/backend contract required. Make remains production/default. Tests used
private working directories; no host installation or configuration changes.

## 2026-10-28: process/signal/time group; exception-flag audit required

Adds 42 explicit libc gen sources for process creation/execution, affinity,
signals, special descriptors, terminal and time helpers. All 84 ordinary/PIC
objects match .text and global/unresolved symbols against a fresh Make reference
in /usr/obj/usr/src/bazel-libc-process-build-20261028-r2/qualification/parity.json.
The original bazel-libc-process-build-20261028 comparison is retained: it failed
for both posix_spawn variants and was not accepted as passing evidence.

Root cause: libc/Makefile:231 scopes CANCELPOINTS_CFLAGS to cancelpoints_* sources.
Our native libc targets had copied -fexceptions from the earlier assignment
without carrying forward that final per-source restriction. This changes stack
protector code generation in posix_spawn's noreturn child path. The new process
group now omits -fexceptions, matching the effective Make recipe. No stack
protector disablement or comparator exception was introduced.

PRIORITY FOLLOW-UP: 31 existing libc BUILD files still contain broadly applied
-fexceptions. Correct those non-cancellation groups and renew their qualification
before proceeding to the libc aggregate. Earlier matching .text/global-symbol
results remain evidence for their saved artifacts, but do not prove flag parity
or unwind/exception-section parity. Cancellation-point sources must preserve
-fexceptions and the NO_THREAD_STACK_UNWIND option when they are migrated. This
finding also requires reviewing per-source conditional assignments as a whole,
not copying only the initial CFLAGS declaration.

The unchanged sigsetops_test.c and sig2str_test.c now have native Bazel ATF
integration. All ten cases pass without skips in the r2 receipt. Its qualification/
link-proof.json confirms all eight signal-set operations and sig2str/str2sig are
native executable definitions. Remaining libc/syscall support is SDK-provided.
These tests do not qualify spawn/exec, real signal delivery, terminal, affinity,
AIO, host/source syscall compatibility, full libc linking/install or performance.

Frontend review: the existing build-bsd format-5 target/test interface and ATF
reporting suffice; no frontend/backend contract change needed. Make remains
production/default. No host installation or process policy changes performed.

## 2026-10-28: correct broad libc exception flags and requalify objects

Corrects all 31 previously migrated libc BUILD files that applied -fexceptions
to non-cancellation sources. None currently contains cancelpoints_* sources.
The final libc/Makefile CANCELPOINTS_CFLAGS restriction, rather than its initial
assignment, determines the required behavior. Existing TLS, sanitizer, stack
protector and per-source optimization flags remain unchanged. Cancellation-point
migration must separately preserve its exception option and NO_THREAD_STACK_UNWIND.
This resolves the broad-flag correction identified in the previous entry.

Evidence: /usr/obj/usr/src/bazel-libc-exception-flags-build-20261028 builds 101
selected targets and passes 24 maintained ATF cases without skips. Its qualification
subdirectories contain renewed Make comparisons for 1,688 ordinary/PIC objects
across 34 component groups; all match .text and global/unresolved symbols.
The saved Make reference objects are reused, not rebuilt for this flag-only
correction. qualification/exception-sections.json also compares raw .eh_frame
and .gcc_except_table contents/presence for all 1,688 objects: all match.
Section relocation equivalence and actual unwind behavior are not established.

NIS-enabled YP evidence: bazel-libc-exception-nis-build-20261028/qualification/
parity.json and exception-sections.json compare six more objects successfully
(1,694 total). The original YP verifier requested generated files not selected
as top-level artifact outputs; that failed invocation is retained. The follow-up
verify-objects.py explicitly checks only archive objects. Neither it nor the RPC
object comparison claims renewed generated-file qualification. Generator rules
were unchanged; their prior evidence remains separately scoped.

The rebuilt default profile uses optimized amd64 sources, iconv on, Hyper-V on,
timezone-change detection off and debug jemalloc. Alternate portable, no-iconv,
no-Hyper-V, timezone-change-detection and production-jemalloc variants still need
renewed flag-corrected qualification. NIS-enabled RPC was compiled but not newly
compared with a matching NIS Make reference. No full native libc link/ABI/install,
world/kernel/package, actual cancellation/unwinding or performance gate is claimed.

Frontend review: build-bsd's existing format-5 target/test/settings interface
supports the combined and NIS checks; no CLI/backend contract changes needed.
All compilation uses 16 CPUs. Make remains production/default; no host install,
upgrade, reboot or policy changes occurred.

## 2026-10-28: renew alternate libc configurations after flag correction

The alternate configurations left open by the preceding exception-flag correction
have now been rebuilt through the maintained build-bsd bazel-test interface:

- Portable string: 174 ordinary/PIC objects.
- Portable stdlib: 148 ordinary/PIC objects.
- Locale with iconv disabled: 128 ordinary/PIC objects.
- x86 support with Hyper-V disabled: six ordinary/PIC objects.
- Timezone-change detection enabled: 14 ordinary/PIC objects.
- Production jemalloc: 124 ordinary/PIC objects.

All 594 match their original, configuration-specific Make references in .text,
global and unresolved symbols. Raw .eh_frame and .gcc_except_table presence and
contents also match for every object. Evidence is under
/usr/obj/usr/src/bazel-libc-exception-variants-20261028: status.json, each variant's
qualification/parity.json, and exception-sections.json. Exact orchestration and
section-reader scripts are retained in bazel-libc-exception-flags-20261028.
The original explicit inputs are reused without substituting configurations or
rebuilding the saved Make reference objects.

These six runs do not add runtime cases. They close the alternate object checks
listed in the previous entry, not whole-system configurations, installation,
production malloc publication, ABI/version maps, section relocations, cancellation,
actual unwinding or performance. NIS-enabled RPC comparison remains open.

Adjacent-library review: libthr and librt legitimately apply -fexceptions broadly
in their maintained Makefiles. Their existing native flags should not receive
the libc per-source correction. Preserve their distinct disable-option spellings
when modeling those variants: NO_THREAD_UNWIND_STACK in libthr versus
NO_THREAD_STACK_UNWIND in libc/librt. Those disable variants remain unqualified.

Next libc cancellation sources need the scoped exception option and sem_new.c's
semwait_trace.h dependency on the shared nameres provider. Preserve existing
DTrace probes and defer any claim of provider registration to the complete link
and runtime gates. Frontend review: existing format-5 inputs support all six
settings; no frontend/backend/manual contract change required. All compilation
used 16 CPUs; Make remains production/default and no host installation occurred.

## 2026-10-28: native semaphore cancellation-point objects

Adds sem.c and sem_new.c as native libc gen sources. The native graph compiles
the maintained sources directly; Make's cancelpoints_ source aliases select
flags and need no copied/generated source in Bazel. The typed boolean
//tools/build/bazel/config:thread_stack_unwind defaults true and controls
-fexceptions only for this cancellation group. False corresponds to libc's
NO_THREAD_STACK_UNWIND. It does not yet control librt or libthr targets.

semwait_trace.h has a declared private header target. With DTrace enabled it
depends on the existing libc nameres provider header, preserving SEMWAIT park/wake
probe references and its static anchor. The archives remain raw objects; final
DOF rewriting must process the entire libc provider contributor set once.

Evidence: /usr/obj/usr/src/bazel-libc-semaphore-20261028/status.json and each
bazel-libc-semaphore-{unwind,no-unwind}-{trace,no-trace}-build-20261028/qualification/
parity.json. All four combinations pass fresh native and Make builds; all 16
ordinary/PIC object comparisons match .text and global/unresolved symbols.
mode-checks.json additionally verifies all 16 actual compile actions have the
selected exception/DTrace flags, compares raw exception-section contents with
Make, and checks raw probe references appear only in tracing-enabled sem_new.
The archive member-name difference (sem versus cancelpoints_sem) is explicitly
mapped in the comparator; source semantics and compile flags match.

No semaphore/cancellation runtime tests, active DTrace registration, unwind
execution, versioned compatibility ABI, complete libc link/install or performance
qualification is claimed. These remain necessary for completion. Frontend review:
build-bsd's existing format-5 typed settings/targets handle the new setting in all
four runs; no new C frontend option or backend contract is required. Make remains
production/default. All builds use 16 CPUs; no host installation or policy change.

## 2026-10-28: native libc random and entropy components

Adds 14 sources: the ten rand48-family sources, arc4random, its compatibility
and uniform helpers, and getentropy. Source-owned ChaCha embedding inputs are
exposed through narrow header targets; no duplicated implementation or broad
sys include-directory dependency is introduced. Existing kernel header targets
are preserved. The generator implementations themselves are unchanged.

Evidence: /usr/obj/usr/src/bazel-libc-random-build-20261028/qualification/parity.json
versus bazel-libc-random-make-20261028: all 28 ordinary/PIC objects match .text and
global/unresolved symbols. No full data/debug/relocation or ABI parity is claimed.

Native getentropy runs all three unchanged maintained cases: requested-length
boundary, invalid pointer, and size limits including zero. All pass without skips
in bazel-libc-getentropy-test-20261028/receipt.json. qualification/link-proof.json
confirms native getentropy is defined in the test executable; getrandom remains
an SDK import using the host kernel. No entropy quality/performance claim follows.

The attempted arc4random runtime test failed to link because _elf_aux_info is a
private dependency absent from the SDK shared libc interface. Evidence remains
in bazel-libc-random-test-20261028/bazel.stderr. No stub, symbol rename, substitute
implementation or fallback was added. The unbuildable standalone arc4random test
target was removed; the unchanged maintained test remains to integrate with
native libc/libsys. Its fork-sequence and uniform-bound cases are NOT qualified.
Native rand48 runtime, RNG reseeding/thread/fork/kernel-version behavior, complete
libc linking/install and performance remain outstanding.

Frontend review: existing build-bsd format-5 targets/tests support the native
objects and getentropy cases; no new frontend/backend contract needed. Builds
used 16 CPUs. Make remains production/default; no host installation or entropy
configuration changes occurred.

## 2026-10-28: libc system/path/terminal helpers

Adds 57 explicit sources to system_helper_objects: pathname and filename matching,
system/device/mount queries, terminal helpers, diagnostics/syslog, shell expansion,
legacy compatibility and related gen routines. Private reentrancy, error-list,
collation and compatibility headers are declared. NLS/NIS/Hesiod settings are
explicit; this qualification uses NLS on, NIS off, Hesiod off. getusershell's
NIS/Hesiod paths still need alternate configuration checks.

Evidence: /usr/obj/usr/src/bazel-libc-helpers-build-20261028/qualification/parity.json
against bazel-libc-helpers-make-20261028. All 114 ordinary/PIC objects match .text,
global/unresolved symbols. exception-sections.json confirms matching raw .eh_frame
and .gcc_except_table presence/contents. No full data/debug/relocation, runtime,
versioned ABI or complete libc link/install qualification is claimed.

Source review: crypt.c is the existing legacy compatibility stub implementation,
not functional encryption. No new stub was introduced by this migration.
wordexp uses the maintained /bin/sh freebsd_wordexp builtin; runtime tests must
qualify that actual shell dependency. syslog socket/reconnect behavior, terminal
interaction, mounts, path edge cases and namespace/service behavior remain open.

Inventory caution: source exports such as pw_scan.c and getcap.c in gen/BUILD.bazel
serve other native consumers and must not be counted as native libc object groups.
The remaining libc inventory must distinguish exports from compiled source lists.
Frontend review: existing build-bsd format-5 targets/settings support these objects;
no new frontend/backend contract required. Builds used 16 CPUs; Make remains
production/default and no host installation or configuration changes occurred.

## 2026-10-28: libc general support and previously export-only sources

Adds 26 sources to native support_objects: existing thread stubs/initialization,
ELF support and interposition, floating-point helpers, login-record storage,
inotify, extended errors, allocation wrappers, pw_scan and getcap. The last two
previously had source exports for other consumers, not native libc compilation.
Private floating-point, spinlock, login-record and extended-error catalogue
headers are declared. No stub implementation or fallback was invented; the
existing libc sources and their normal linkage semantics are retained.

Evidence: /usr/obj/usr/src/bazel-libc-support-build-20261028/qualification/parity.json
against bazel-libc-support-make-20261028. All 52 ordinary/PIC objects match .text
and global/unresolved symbols. exception-sections.json also confirms matching
raw .eh_frame/.gcc_except_table contents/presence. Full relocation/debug/data,
ABI versioning and runtime behavior remain unqualified.

Thread stub replacement/interposition, initialization order, ELF-loader behavior,
login-record writes, extended-error handling and floating-point edge cases need
complete libc linking and maintained runtime tests. The pututxline test's Make
configuration requires static linkage; do not substitute shared-SDK execution
as its final qualification. No host login-record/account updates were performed.

Nine entries remain in gen's primary source list: dlfcn, getgrent, getgrouplist,
getnetgrent, getpwent, initgroups, sysconf, tls and unvis-compat. Separate imported
pwcache/vis/unvis sources and complete library install/link metadata also remain.
This is a component inventory checkpoint, not whole-libc completion.
Frontend review: build-bsd's existing format-5 targets support the additions;
no frontend/backend contract changes needed. All compilation uses 16 CPUs;
Make remains production/default, with no host installation or policy changes.

## 2026-10-28: libc loader interfaces and imported utilities

Adds seven native sources: dlfcn.c, tls.c, sysconf.c, unvis-compat.c, imported
vis.c/unvis.c and pwcache.c. Imported files remain in their maintained contrib
locations with narrow exports. Loader headers, timezone-directory constants,
atexit metadata and pwcache declarations are explicit dependencies. Existing
libthr loader-header consumers remain intact; rtld_malloc source visibility was
reviewed and kept restricted to its existing consumer.

Evidence: /usr/obj/usr/src/bazel-libc-loaderimports-build-20261028/qualification/
parity.json versus bazel-libc-loaderimports-make-20261028: all 14 ordinary/PIC
objects match .text and global/unresolved symbols. exception-sections.json also
confirms raw exception/unwind section contents/presence. Full relocation/data/debug
identity, installation/versioning and runtime linking remain unqualified.

dlfcn.c contains maintained weak stubs overridden by the dynamic linker; these
are existing source semantics, not newly invented fallbacks. tls.c retains its
bootstrap allocator and weak runtime-linker interface. Static/dynamic resolution,
TLS initialization/allocation, shell escaping, pwcache lookup behavior and sysconf
values still need complete native runtime tests. Compiling these sources does not
establish a native runtime linker or completed libc.

Five primary gen sources remain: getgrent, getgrouplist, getnetgrent, getpwent and
initgroups. Complete libc source reconciliation, generated syscall interfaces,
linking/DOF, ABI/install and runtime gates remain broader outstanding work.
Frontend review: existing build-bsd format-5 targets support these additions;
no new frontend/backend contract required. All compilation uses 16 CPUs; Make
remains production/default. No host installation or loader configuration changed.

## 2026-10-28: libc account/group lookup sources and optional Hesiod headers

Adds getgrent, getgrouplist, getnetgrent, getpwent and initgroups as native
account_objects. NIS, Hesiod and NSS caching are explicit existing typed settings;
private NSS/thread/cache and pw_scan headers are declared dependencies.

Three matching Make/native configurations pass: default (NIS/Hesiod off, cache
on), both optional backends on with caching, and both backends off without caching.
All 30 ordinary/PIC object comparisons match .text, global/unresolved symbols and
raw exception-section contents. Evidence: /usr/obj/usr/src/bazel-libc-accounts-
20261028/exception-sections.json and each bazel-libc-accounts-{default,backends,
no-cache}-build-20261028/qualification/parity.json (backends uses the -r2 run).
Other combinations and actual services are not qualified by this matrix.

The first backend-enabled native run failed because the prepared SDK omitted
hesiod.h. The source-owned include/hesiod.h now has a narrow native header target;
no SDK mutation, copied header or host-header fallback was used. All four libc
consumers (getgrent/getpwent/getusershell/hesiod) have conditional dependencies.
bazel-libc-hesiod-consumers-build-20261028 confirms their selected archives compile
with both backends enabled. The additional helper/network archives were not
newly compared against matching Make backend variants; that remains open.

primary-source-coverage.json confirms every one of the 170 entries in gen's
primary SRCS assignment belongs to a native cc_library srcs list. This excludes
exports-only declarations and is not a whole-libc completeness claim. Imported,
architecture-specific and generated inputs, final DOF/link/ABI/install metadata,
full library runtime and broader system gates still require reconciliation.
No account/authentication/NSS service runtime tests or host account/policy changes
were performed. Frontend review: existing build-bsd format-5 settings/targets
support these cases; no frontend/backend contract change required. Compilation
uses 16 CPUs, and Make remains production/default.

## 2026-10-28: libc capability-rights source and syscall-generation review

Adds libc/capability's subr_capability.c directly from the shared sys/kern source,
compiled without _KERNEL, with a narrow source export and Symbol.map export for
the future aggregate. Existing sys/kern native targets are preserved.

Evidence: /usr/obj/usr/src/bazel-libc-capability-build-20261028/qualification/
parity.json and exception-sections.json against a fresh Make reference. Both
ordinary/PIC objects match .text, global/unresolved symbols and raw exception
section contents/presence. This does not qualify capability enforcement, object
rights propagation, kernel isolation, complete libc ABI or runtime behavior.
No capability policy or host process rights were changed.

Next generated-interface work can reuse the maintained libsys/gen-syscall.sh and
tools/build/bazel/bsd_syscall_asm.bzl. Explicit native syscall inventory must
preserve normal versus PSEUDO/INTERPOSED selection, amd64 handwritten exclusions,
GNU stack notes and libc's empty shared syscall bodies. Existing configured
exporter metadata is reference evidence, not a substitute for native authoritative
Bazel targets. Final libc/libsys source reconciliation, version maps/filtering,
combined DTrace DOF, installation/debug/pkgbase and runtime gates remain open.

Frontend review: build-bsd's existing format-5 targets compile this component;
no new frontend/backend contract required. Builds use 16 CPUs and Make remains
production/default. No installation, upgrade or reboot occurred.

## 2026-10-28: syscall inventory generated for native Bazel

The maintained sys/tools/syscalls generator now emits syscall_symbols.bzl via
the optional sysbzl configuration output (default /dev/null). It shares the exact
native/compatibility/NODEF/NOLIB inclusion predicate with syscall.mk. Native
sys/kern/syscalls.conf selects ../sys/syscall_symbols.bzl and sys/kern/Makefile
lists it among GENERATED outputs, so normal sysent regeneration updates it.
The checked-in inventory is generated from syscalls.master, not a hand-maintained
second list and not a runtime Make parser. Standalone syscall_mk invocation also
emits the configured Bazel output.

Evidence: /usr/obj/usr/src/bazel-syscall-inventory-20261028/comparison.json. Running
the original generator and changed generator against the same native master and
output-isolated configurations produces all eight pre-existing files byte-equal.
The 452 Bazel symbols exactly equal syscall.mk in order and membership, with no
duplicates. This checks inventory generation only; no generated assembly objects,
new libc/libsys link or syscall runtime qualification is claimed.

Next native targets must load this inventory and explicitly model PSEUDO and
INTERPOSED syscall policy, amd64 handwritten exclusions, stack notes and separate
static/libsys versus empty shared-libc syscall bodies. The maintained per-stub
shell generator and bsd_syscall_asm rule already exist. Full ABI/cross-architecture,
cache, linking/package and runtime gates remain outstanding.

Frontend review: build-bsd continues through the maintained Make sysent backend;
the added generated output is part of that normal path. No new frontend option
or signing/publication contract is needed. No installed host files changed.

## 2026-10-28: native generated amd64 libc syscall assembly

Native libsys generation now consumes syscall_symbols.bzl and explicit ABI policy
in lib/libsys/syscall_policy.bzl. The interposed C wrappers use that same native
policy list. Each of the 450 stubs has its own declared generator action with
staged shell/runtime and the maintained gen-syscall.sh; no Make evaluation runs
inside the native graph. Architecture exclusions, PSEUDO versus RSYSCALL and
GNU-stack notes are preserved. Source-owned syscall.h and compat.h are declared
compilation dependencies. Static libc's full syscall bodies and shared libc's
empty, libsys-filtered bodies have distinct native compilation groups.

Evidence: /usr/obj/usr/src/bazel-libc-syscalls-build-20261028/qualification/parity.json
against fresh bazel-libc-syscalls-make-20261028. All 450 generated sources match
Make byte-for-byte and membership matches Make's configured inventory. All 900
ordinary/shared-PIC objects match .text bytes, global/undefined symbols (including
compatibility versions) and normalized .text relocations. Debug and non-text
relocations were not compared. Final shared-policy build
bazel-libc-syscalls-build-20261028-r2 also builds the existing C wrapper groups;
its 452 syscall outputs (450 sources and two archives) are byte-identical to the
first build, recorded in prior-artifact-parity.json. Qualification scripts and
full logs remain under /usr/obj/usr/src/bazel-libc-syscalls-20261028 and run dirs.

This is component qualification, not a complete libc/libsys link or syscall
runtime test. Full libsys, libc linking/filter maps/DOF, installation, pkgbase,
bootstrap, world/kernel/modules, cross-configurations and runtime/performance
remain required. No installed host files changed. Make remains production/default.

Frontend review: existing build-bsd bazel-test format-5 target inputs drive both
runs with 16 jobs. No new frontend input, signing, staging or publication contract
is introduced; no frontend/backend change is needed for these native targets.

## 2026-10-28: complete amd64 libsys object inventory and direct syscall smoke test

Source-owned libsys targets now compile all 477 configured amd64 sources with
LIBSYS, initial-exec TLS, no stack protection, typed HyperV selection and the
IFUNC sanitizer exceptions. Private memcpy/memset/strlcpy and memcpy's textual
bcopy dependency are explicit. These settings are independent of libc's groups.
The existing native version-map generator consumes libsys's ordered symbol maps
and libc Versions.def. No runtime Make query supplies native build metadata.

Evidence: /usr/obj/usr/src/bazel-libsys-native-build-20261028-r2/qualification/
parity.json against fresh bazel-libsys-native-make-20261028. All 954 ordinary/PIC
objects match text bytes, global/undefined symbols and normalized text relocations;
the complete Version.map is byte-identical. The first build failed because
version_gen.awk's visibility did not grant libsys access; the narrow export was
fixed, and the failed run is retained. Scripts live in bazel-libsys-native-20261028.

The maintained tests/libsys_runtime.c is now a native cc_test. One actual Bazel
test passes at bazel-libsys-native-test-20261028: process identity, pipe I/O,
closing descriptors and errno=EBADF. native-link-proof.json proves the exercised
__sys_* functions and __error are native executable definitions, not unresolved
SDK symbols. The final test build's two archives and map are byte-identical to
the compared run. The rest of the process runtime still uses SDK/host libc;
this is not full native libc/loader or threading qualification.

No libsys.so, installation or pkgbase result is claimed. Native compiler-rt is
the next linkage dependency: earlier configured exports are not a replacement
for source-owned Bazel definitions. libsys's -nodefaultlibs/-Bsymbolic linkage,
static compiler-rt selection, symbol versions, debug/install metadata and shared
runtime behavior still need qualification. Other architectures and full system
runtime/performance remain outstanding. Make remains production/default.

Frontend review: build-bsd.c and native-qualify.py's maintained format-5 path
already accept these targets and the cc_test, and were used with 16 jobs. No new
option or staging/signing/publication contract is introduced. No frontend change
or host installation is needed for this component step.

## 2026-10-28: native compiler-rt and libsys shared linkage

Added explicit source-owned amd64 compiler-rt targets for the staged Clang
configuration (Float16/BFloat16 enabled). The 165-source inventory preserves
x86_64 assembly selection and shared x86 CPU/FP implementations. Headers and
textual .inc dependencies are declared. The installed-library candidate is one
static archive of -fpic, hidden, non-stack-protected objects; cc_import preserves
that archive for DSO consumers. Other architectures/compiler configurations are
not qualified by this target.

Evidence: /usr/obj/usr/src/bazel-compiler-rt-native-build-20261028/qualification/
parity.json against fresh bazel-compiler-rt-native-make-20261028. All 165 members
match text, global/undefined symbols and normalized text relocations. One actual
Bazel arithmetic test passes, covering signed/unsigned 128-bit division/remainder
and amd64 integer/FP conversions. Native definitions of every called builtin are
verified. This does not establish the full compiler-rt behavioral test suite.

libsys.so.7 now links these native objects and native compiler-rt through
cc_shared_library, preserving -nodefaultlibs, -Bsymbolic, SONAME and ABI map.
The first linkage incorrectly placed compiler-rt under a source-less root:
cc_shared_library consequently whole-linked its archive, increasing allocated
size and introducing math dependencies. The shared runtime test failed to link.
Fixed the graph by making compiler-rt an implementation dependency of the object
group that needs it. No undefined-symbol suppression or extra math library was
added. Failed builds remain at bazel-libsys-native-shared-20261028 and
bazel-libsys-native-shared-test-20261028.

Final evidence: bazel-libsys-native-shared-test-20261028-r2/shared-parity.json.
All 1,271 dynamic-symbol entries match Make by size/type/binding/visibility,
name/version and defined/undefined state; section indices and addresses differ
with layout. Both libraries have no DT_NEEDED or TEXTREL, the same SONAME and
SYMBOLIC/BIND_NOW flags. Native size reports text/data/bss 110737/1000/3000 bytes
versus Make 110729/1000/3012; this is not byte-identical ELF or a performance test.
Two actual syscall tests pass (static objects and shared library). Loader tracing
and SHA-256 comparison prove the shared test loads the exact native libsys output;
host libc/loader still supply the rest of the process runtime. Verification
scripts are retained in bazel-compiler-rt-native-20261028.

Remaining: debug/install/pkgbase metadata, compiler-rt compatibility libgcc.a
symlink, libsys manual pages/headers, complete libc linkage/DOF, broader threading,
IFUNC and other runtime tests, cross-configurations and complete world/kernel/
modules/package/cache/performance gates. Frontend review: build-bsd's maintained
format-5 bazel-test path drove all runs with 16 jobs; no new option or publication
contract needs frontend changes. Make remains production/default. No host files
were installed and no upgrade/reboot was performed.

## 2026-10-28: native compiler-rt/libsys installation archives

Added source-owned installation targets for compiler-rt and libsys, consumed by
the maintained typed manifest/archive rules. Compiler-rt installs its archive and
libgcc.a compatibility symlink with libcompiler_rt/dev ownership. libsys installs
ordinary/PIC archives, libsys.so.7 and its development symlink, a split debug file,
two public headers, 236 compressed manuals and 181 manual hardlinks. The normal
Make schg metadata on libsys.so.7 is preserved as archive metadata. Ancestor
policy still comes from maintained mtree/account sources; only libsys's explicit
debug directory is declared by this component. Nothing is installed on the host.

Default evidence: /usr/obj/usr/src/bazel-runtime-install-20261028-r2/qualification/
installation-parity.json against bazel-compiler-rt-install-reference-20261028 and
bazel-libsys-install-reference-20261028, both produced by install-reference.py.
All 426 non-directory metadata records match, including ownership, modes, file
flags, package tags and symbolic/hardlink relationships. All 419 header/manual
payloads match Make bytes (including aliases); native archives retain the exact
previously qualified artifact bytes and contain 165/477/477 members. The shared
library's debug-link filename/CRC matches its companion, which contains DWARF.
This is not a debug-byte or full ELF identity comparison with Make.

Alternate manual ownership also passes: bazel-runtime-install-split-20261028/
qualification/installation-parity.json matches fresh Make WITH_MANSPLITPKG=yes
at bazel-libsys-install-split-reference-20261028. All 424 libsys metadata entries,
419 header/manual payloads and 182 links match. The initial reference invocation
incorrectly used WITH_SPLIT_MANPAGES; the helper rejected it before creating a
reference. Correcting to Make's actual MANSPLITPKG option produced the successful
comparison. Native split_manpages remains the existing typed frontend setting.
Verification scripts live at bazel-runtime-install-qualification-20261028.

Frontend review: build-bsd.c and native-qualify.py already support these native
targets and the typed split_manpages setting through format 5; all builds used
16 jobs. No new CLI, signing or publication contract is introduced. These archives
are component installation results, not a completed pkgbase repository or world.
Remaining gates include libc linkage/DOF, full installation/package composition,
other build configurations, runtime/kernel/modules and cache/performance testing.
Make remains production/default, with no host installation or upgrade performed.

## 2026-10-28: complete native amd64 libc composition and initial runtime proof

Added source-owned composition.bzl for ordinary groups, static-only iconv/libsys
implementations, shared-libc filtered syscall bodies, and typed iconv/NIS/string
optimization selection. Resolver/NSS/semaphore groups undergo one combined DTrace
rewrite per object variant; provider objects are included in each corresponding
archive. The native ABI map uses ordered source maps with iconv/NIS/Hesiod/timezone
options. Shared linkage uses native compiler-rt and libsys with -nodefaultlibs,
libsys auxiliary filtering, version map and normal hardening flags.

The first shared analysis correctly rejected compiler-rt's reuse across libsys
and libc under Bazel's default link-once policy. compiler_rt now declares
LINKABLE_MORE_THAN_ONCE: BSD deliberately links private hidden builtins into each
DSO that needs them. It is not falsely exported by libsys, and archive extraction
remains selective. The rejected r2 build remains available.

Evidence: /usr/obj/usr/src/bazel-libc-runtime-20261028/qualification/parity.json
against fresh bazel-libc-link-make-20261028. Native static/shared-object archives
have 1,455/1,443 members, matching Make. The full static global/undefined symbol
multisets match after normalizing only DTrace's generated path-derived identifier
on __res_nsend. Version.map is byte-identical. All 3,590 dynamic-symbol entries
match by name/version/type/binding/visibility/size and defined/undefined state.
Both DSOs require and auxiliary-filter through libsys.so.7, have the same SONAME
and BIND_NOW/STATIC_TLS flags, and have no TEXTREL. Archive member names/layout and
full ELF bytes differ; two native div members are disambiguated by archive symbol
index rather than Make's jemalloc_ filename prefix. No new per-object identity
claim is made here beyond earlier component checks and these aggregate checks.

DOF inventory and amd64 instruction-site validation match: 12 probe schemas,
14 ordinary sites and 15 enabled sites. Constructor/destructor order also matches
Make using DWARF names: __guard_setup, uexterr_ctr, jemalloc_constructor,
dtrace_dof_init; __clean_env_destructor, dtrace_dof_fini. This verifies metadata,
patching and ordering, not live probe firing. The Make link command uses staged
SDK -lcompiler_rt/-lsys; requested LIB* path overrides did not change those link
arguments. The native DSO uses the actual new native dependencies.

The maintained libc_runtime.c smoke checks pass with explicitly selected native
libc/libsys runfiles: allocation/text, streams, mmap/mprotect, fork/pipe I/O and
numeric getaddrinfo. Loader tracing resolves both libraries to the saved native
artifacts. A fully static executable also passes using native libc/compiler-rt
with -nodefaultlibs. Final bazel-libc-runtime-20261028-r2/static-runtime-proof.json
confirms no interpreter, native function definitions and valid DOF instruction
sites. The final library artifacts match the earlier checked hashes. Two tests
report passed (the unchanged shared test was cached in the final run).

These are the NIS-off, debug-malloc amd64 configuration and bounded smoke tests,
not all libc suites or all build modes. SDK startup objects and host kernel/loader
remain. Native libc install/debug/pkgbase, broader runtime suites, option variants,
live tracing, bootstrap/world/kernel/modules, cache and performance gates remain.
No production-world stamp, installation or upgrade is claimed. Frontend review:
existing build-bsd format-5 targets/tests/build-settings drove all runs at 16 jobs;
no new CLI or publication contract is needed for this step. Make remains default.

## 2026-10-28: existing libc ATF tests now exercise the complete native runtime

Converted gen/inet/stdlib qualification programs from component-object imports
and SDK runtime libraries to the complete native libc/libsys runtime. Shared
runtime labels are owned by lib/libc/test_runtime.bzl. Programs retain the staged
SDK header/link interface and native ATF support, while the static ATF supervisor
selects the declared native libc, libsys and private ATF DSOs in runfiles. Internal
program labels now use _runtime_program to reflect this scope; case labels remain
stable. No imported libc component archive masks calls into the new shared libc.

Also enabled the maintained arc4random cases, previously deferred when isolated
objects could not resolve the SDK's private auxv implementation. Full native
runtime composition resolves that dependency; no replacement symbol or stub was
added. The tests cover parent/child random output and uniform-result bounds.

Evidence: /usr/obj/usr/src/bazel-libc-suite-20261028-r2/receipt.json and
qualification/runtime-provenance.json. All 33 actual ATF cases passed, with no
skips: six makecontext, seven directory, ten signal conversion/set operations,
three getentropy, two arc4random, four inet conversion and one sized-deallocation
case. The provenance script verifies imported tested functions for all ten
programs and resolves native libc/libsys/private-ATF to the saved artifact paths.
The inet functions use the source header's __inet_* symbol aliases. Initial
frontend input validation rejected tests omitted from the explicit target set;
the corrected input includes every selected test. Verification scripts are under
bazel-libc-suite-qualification-20261028.

This remains 33 selected cases, not the complete libc suite or entropy/security
qualification. SDK headers/link interfaces, host kernel/loader, other libc tests,
thread/cancellation/locale/service behavior, options, install/pkgbase and whole
system/performance gates remain. Frontend review: build-bsd's existing format-5
explicit targets/tests path ran these tests with 16 jobs; no new CLI/backend or
publication contract is needed. No host installation/upgrade occurred.

## 2026-10-28: native libc public shared link interface

Added a public shared_link_interface combining the shared libc link objects and
libc_nonshared, with cc_shared_library dynamic dependencies selecting native libc
and libsys. The existing shared smoke program now links through that interface
with -nodefaultlibs. The maintained iconvctl test program also links through it;
its public iconv_open/iconv_close/iconvctl wrappers are defined locally and call
imported __bsd_* implementations. This program is link-qualified only: native
iconv conversion modules and data must be declared before runtime qualification.

For default amd64 installation, expand the maintained libc_nossp.ldscript and
record /usr/lib/libc.so and libxnet.so in a deliberately partial link-interface
manifest. The linker script is byte-identical to Make. Comparison caught and
corrected the libxnet symlink mode to 0444; its package tag is clibs without dev.
Both entries match Make's logical ownership, modes, type, tags and link target.
Other architectures/custom installation directories and complete libc installation
remain unqualified. No whole libc packaging claim follows from these two entries.

Evidence: /usr/obj/usr/src/bazel-libc-link-interface-20261028-r3/receipt.json and
qualification/link-interface-parity.json. Two static/shared smoke cases passed;
loader inspection resolves the shared probe to saved native libc/libsys artifacts.
Reference: bazel-libc-link-interface-reference-20261028-r2, using maintained
_libinstall with the top-level IMAKE_INSTALL rootless command. The initial
reference failed because NO_ROOT alone did not supply direct subdirectory install
flags; that failed run remains recorded. Scripts are retained under
bazel-libc-link-interface-qualification-20261028. No host installation occurred.

Frontend review: build-bsd.c's existing bazel-test --bazel-inputs path and backend
format-5 targets/tests handle these additions; no new inputs or publication
contract require frontend changes. Make remains the production default.

## 2026-10-28: all 23 Citrus modules build and load natively

Added explicit native cc_library/cc_shared_library targets for every module in
lib/libiconv_modules/Makefile. Shared module policy is in modules.bzl; the source
inventory is owned by BUILD.bazel and does not parse Make during Bazel builds.
Preserved SHLIB_MAJOR=5, bool=_Bool and mapper_parallel's deliberate reuse of
mapper_serial source. Private Citrus headers are declared through a restricted
header target. Dependencies select native libc/libsys with -nodefaultlibs. GCC
inlining knobs are not applied to the qualified Clang build. Qualification is
amd64 with iconv enabled; cross architectures remain outside this evidence.

All 23 modules built. Their dynamic symbols (including size, type, binding,
visibility, version and definition/import status) match fresh maintained Make
outputs. SONAMEs match, no TEXTREL is present. Bazel records explicit libc and
libsys dependencies; Make's default link may record only libc. This is not a
byte-identical ELF or performance claim. The module loader tests use RTLD_NOW,
resolve the expected Citrus getops entrypoint, and compare the loaded module's
realpath with its declared runfile, rejecting host module fallback. All 23 tests
passed with native libc/libsys runtime runfiles. Modules are byte-identical to
the artifacts whose ABI was compared before adding the tests.

Evidence: /usr/obj/usr/src/bazel-iconv-modules-20261028/qualification/shared-parity.json;
bazel-iconv-modules-runtime-20261028/receipt.json and
qualification/runtime-provenance.json. Fresh Make reference:
bazel-iconv-modules-make-20261028. Comparison/build scripts:
bazel-iconv-modules-qualification-20261028. No host installation occurred.

End-to-end iconv conversion remains pending native csmapper/esdb data and their
generators; module installation/debug/pkgbase integration also remains. Loader
success is not claimed as conversion correctness. Frontend review: existing
build-bsd.c bazel-test --bazel-inputs and format-5 backend carry the explicit
module targets/tests at 16 jobs without a new interface or publication change.
Make remains production/default; full world/kernel/pkgbase gates remain open.

## 2026-10-28: native Citrus database generators

Added native mkesdb and mkcsmapper targets with declared lexer/parser actions
using existing native lex/yacc/m4 targets in the execution configuration. Generated
parser headers are explicit C compilation inputs. Private Citrus and mapper file
format headers are exposed only to the consumers requiring them. Normal program
targets link native shared libc/libsys with PIE; separate *_tool targets link
native libc statically for data-generation execution without relying on an
installed runtime. The latter have no ELF INTERP segment. These are same-host
amd64 qualifications, not a cross-compilation/bootstrap closure claim. No Make
BOOTSTRAPPING source injection or installed generator substitute is used in the
native generator targets.

Evidence: /usr/obj/usr/src/bazel-citrus-generators-20261028/receipt.json and
qualification/generator-parity.json. Both normal and execution-tool variants build.
Fresh maintained Make generators were built under
bazel-citrus-generators-make-20261028. The complete maintained share/i18n all build
was run twice in isolated object directories: once with those Make generators,
once with copies of the saved native static tools. All 656 generated .esdb, .mps,
.db and .pvdb outputs are byte-identical, including map and pivot modes. Full
output inventories were compared before bytes; no mismatches were excluded.
Reference trees: bazel-citrus-data-make-20261028 and
bazel-citrus-data-native-20261028. Scripts:
bazel-citrus-generators-qualification-20261028.

The data comparison still uses Make orchestration. Migrating the data graph,
preprocessing, aliases, directory/pivot inventories and installation into declared
Bazel actions remains necessary; this evidence qualifies the generators, not the
complete i18n migration. Normal dynamically linked generator runtime and install
metadata remain to qualify separately. No host installation occurred. Frontend
review: build-bsd.c's existing format-5 targets and backend support these native
program targets at 16 jobs; no CLI/publication contract changes are needed.
Make remains the production default; the full migration goal remains active.

## 2026-10-28: native character-map database actions

The 415 binary character-map sources now have a Bazel-owned inventory in
share/i18n/csmapper/maps.bzl and one CitrusDatabase action per source. Actions
invoke mkcsmapper_tool through an executable cfg=exec dependency, declare source
and output files, and use a fixed locale without a shell or ambient environment.
The reusable rule also exposes explicit compile/lookup/pivot modes for subsequent
index generation. No Make parsing, reference-tree lookup, installed-tool fallback
or generated-result copying occurs in the native build. Adding maps requires
updating the owned source inventory, like other explicit Bazel source lists.

Build evidence: /usr/obj/usr/src/bazel-csmapper-data-20261028/receipt.json. This
first use in execution configuration builds native libc and the static tool for
that configuration separately from their previous target-configuration builds.
The full data graph remains incomplete: .646 files, mapper directory/pivot
indexes, aliases, esdb templates and installation still need native ownership.
The previous 656-output generator comparison does not establish that graph.

The JSON execution log from this first execution-tool build is approximately
2 GiB. This is diagnostic disk overhead, not a measured runtime or filesystem
regression. The action verifier streams records instead of loading the complete
log. Broad build CPU/memory/I/O and diagnostic-storage qualification remain open;
future full-world runs need a measured logging/storage policy. Frontend review:
build-bsd.c's maintained format-5 explicit-target backend executes the data
filegroup at 16 jobs without new CLI or publication inputs. Make remains default.

Qualification completed: all 415 output names and bytes match the full maintained
Make character-map inventory. Execution evidence confirms 415 successful database
actions, each declaring its source and the execution-configuration mkcsmapper
binary. Report: bazel-csmapper-data-20261028/qualification/database-parity.json;
script: bazel-csmapper-data-qualification-20261028/verify.py. The first reader
attempt assumed newline-separated JSON; Bazel emits adjacent objects. The reader
was corrected to stream that actual format without changing build evidence.
No warm-cache, input-invalidation or cross-platform claim follows from this run.

## 2026-10-28: native encoding database actions

All 237 encoding databases now have explicit native Bazel actions driven by the
owned encodings.bzl inventory. Of these, 55 use maintained source files directly
and 182 expand maintained templates. The template substitutions preserve UTF
module/variable settings, Georgian name/charset distinctions and the other
family naming rules. The six Big5 expansions declare Big5.variable as an input
and use the native execution-platform awk with a literal-substitution script;
values are read from that table rather than copied into Bazel metadata. Missing
or duplicate selected table entries fail generation. The first migration-time
comparison exposed Big5's separate variable-table contract before implementation
was accepted. No Make evaluation or reference-output copying occurs in Bazel.

Evidence: /usr/obj/usr/src/bazel-esdb-data-20261028-r2/receipt.json and
qualification/database-parity.json. Every one of the 237 .esdb outputs and 182
expanded .src outputs matches the complete maintained Make inventory and bytes.
Execution records confirm declared inputs for all 237 database actions and all
six Big5 variable-table actions. The verification script initially used an
incorrect expected count of eight variable expansions; it now compares their
output inventory directly against the reference's Big5 sources instead.
Scripts are retained under bazel-esdb-data-qualification-20261028. Reference:
bazel-citrus-data-make-20261028. Qualification is same-host amd64; this does not
establish cross-build behavior or runtime conversion semantics.

Together with the prior 415 character maps, 652 binary data files now have native
Bazel generation. The four compiled alias/directory/pivot indexes, their text
inventories, static .646 data and installation remain. The Make .part inventory
is not read at native build time: encoding membership is now owned explicitly in
Bazel metadata. Frontend review: build-bsd.c's existing format-5 explicit targets
and backend handled both filegroups at 16 jobs, without new CLI or publication
inputs. Make remains production/default. No host installation occurred.

## 2026-10-28: native encoding directory and alias indexes

Added native esdb.dir/esdb.alias generation from ordered Bazel-owned encoding
family metadata and declared maintained .alias files. The action uses native awk
in execution configuration, explicit script/layout/alias inputs, two declared
outputs and fixed locale. It preserves family/member/alias ordering, canonical
encoding names and colon-to-@ database paths. Index membership is checked during
analysis against encodings.bzl: duplicate/unbuilt members and omitted databases
fail rather than leave a silently inconsistent index. The ordered membership
metadata replaces Make .part reads for this native graph; alias file content
remains an input, so alias edits invalidate generation.

Both text indexes and their lookup-mode mkesdb databases now build natively.
All four outputs match maintained Make byte-for-byte and by output inventory:
esdb.dir, esdb.alias, esdb.dir.db, esdb.alias.db. Final evidence:
/usr/obj/usr/src/bazel-esdb-indexes-20261028-r2/receipt.json and
qualification/index-parity.json. Verification script:
bazel-esdb-indexes-qualification-20261028/verify.py. Reference:
bazel-citrus-data-make-20261028. No host installation occurred. This completes
native encoding database/index generation, but not its installation or runtime
conversion qualification. Character mapper directory/pivot indexes and static
.646 data remain, along with full i18n installation and iconv execution tests.

Frontend review: existing build-bsd.c format-5 target selection invokes the native
index filegroup with 16 jobs; no new CLI/backend publication input is required.
Make remains production/default and full world/kernel/pkgbase gates remain open.

## 2026-10-28: native mapper directory and pivot indexes

Added declared native generation of mapper.dir and charset.pivot, followed by
lookup/pivot-mode mkcsmapper actions. Ordered family metadata is owned by
csmapper/index_policy.bzl; maintained directory/pivot source fragments remain
explicit action inputs. The generator preserves generic mappings, reverse .646
mappings, CP additions, KOI parallel mappings and ISO-8859 GR/zone/serial rules.
It reads no Make files and does not copy reference outputs. Its Python executable,
standard library, script, metadata request and source fragments are declared;
the action uses a fixed locale and no default shell environment.

Final evidence: /usr/obj/usr/src/bazel-mapper-indexes-20261028-r2/receipt.json and
qualification/index-parity.json. Both text indexes and both compiled databases
match the full maintained Make output names and bytes: mapper.dir, mapper.dir.db,
charset.pivot and charset.pivot.pvdb. Reference:
bazel-citrus-data-make-20261028. Scripts:
bazel-mapper-indexes-qualification-20261028. The first native analysis rejected
an executable attribute that did not allow the staged Python source executable;
that declaration was corrected and the failed run retained. No fallback occurred.

Combined with the prior character maps and encoding data/indexes, all 656 binary
i18n files in the maintained build now have native generation with byte-parity
evidence. This does not yet establish installation coverage: static .646 data,
complete file metadata/package integration and end-to-end iconv runtime testing
remain. Frontend review: build-bsd.c's existing format-5 explicit-target backend
runs this filegroup at 16 jobs; no new CLI or publication contract is required.
Make remains production/default; no host installation occurred.

## 2026-10-28: complete share/i18n installation archive

Added native installation manifests for the complete csmapper and esdb payloads,
including 27 maintained static ISO646 maps. Package directories are derived from
the owned family metadata, while parent directory/account policy uses maintained
mtree/passwd/group inputs. The aggregate share/i18n:install_archive materializes
all generated and static inputs; it does not select a hand-picked runtime subset.
Files carry root/wheel 0444 and package=utilities. The 35 component directories
carry root/wheel 0755 and the same package tag, matching maintained Make.

Evidence: /usr/obj/usr/src/bazel-i18n-install-20261028/receipt.json and
qualification/installation-parity.json. All 687 installed file bytes and metadata
match the complete Make component inventory, and all 35 component directory
records match. Archive ownership/modes/types and empty file flags are checked
against the same inventory; unexpected file payloads fail comparison. Rootless
reference: bazel-i18n-install-reference-20261028, using maintained distrib-dirs
and share/i18n install with the top-level IMAKE_INSTALL contract. Its sources and
Make generators reuse the previously qualified independent Make data build.
Scripts: bazel-i18n-install-qualification-20261028. No host installation occurred.

This establishes share/i18n installation-archive coverage, not a complete
utilities pkgbase package or published repository. Citrus module installation,
end-to-end iconv conversion with native libraries/modules/data together, and
whole libc/world/kernel/package qualification still remain. Frontend review:
build-bsd.c's existing explicit format-5 targets and maintained backend built
these manifests/archive with 16 jobs. No new CLI/publication input was introduced.
Make remains the production default.

## 2026-10-28: complete Citrus module installation and debug handling

All 23 modules now have native debug extraction, stripped installation binaries,
development symlinks and installation manifests. sources.bzl owns the single
module source inventory used for both builds and archive assembly. The aggregate
archive preserves maintained Make's utilities/dev/dbg package tags, root/wheel
ownership, 0444 file modes and 0755 symlink/debug-directory modes. Existing mtree
policy supplies parent directories. No whole-system image is assembled here.

Evidence: /usr/obj/usr/src/bazel-iconv-install-20261028-r2/receipt.json and
qualification/installation-parity.json. All 72 unique component metadata records
match Make: 23 binaries, 23 debug files, 23 development links, three debug
directories. Make emits the same directory entries repeatedly during parallel
module installation; comparison checks the resulting unique path inventory.
All 23 debuglink names/CRCs match their separate files, which contain DWARF info.
Installed .text bytes match the previously ABI-qualified native full modules.
The existing native loader probe successfully loads all 23 stripped archive
copies with native libc/libsys and verifies the expected entrypoint comes from
the declared installed module path. This tests installation artifacts in a
private qualification directory without modifying host installed libraries.
The host readelf warns about absent dynamic-table contents in separate debug-only
ELFs; debug-link/DWARF checks and loader execution all succeeded.

Reference: bazel-iconv-install-reference-20261028, using rootless maintained Make
installation over the previously built independent module reference. Scripts:
bazel-iconv-install-qualification-20261028. Full end-to-end conversion with native
libc/modules/i18n data together remains, as do aggregate pkgbase publication and
whole-system gates. This is default amd64 installation qualification, not custom
LIBDIR/debug-option or cross-platform coverage. Frontend review: build-bsd.c's
existing format-5 targets/backend handle the archive and native loader inputs at
16 jobs; no CLI or publication change is required. Make remains default.

## 2026-10-28: complete native iconv runtime fixture prepared; execution pending

The existing iconv CLI now links through native libc's shared interface and
nonshared public wrappers with explicit native libc/libsys dynamic dependencies.
Native build evidence: bazel-iconv-complete-runtime-20261028/receipt.json;
cli-link-provenance.json verifies defined public wrappers and native library
resolution. This is linkage evidence, not conversion behavior.

Prepared a private root from both complete native i18n/module installation
archives, native libc/libsys/private ATF, the maintained iconvctl program and
native iconv CLI. The host /libexec/ld-elf.so.1 is copied explicitly as the loader;
the fixture manifest records hashes for all 762 file paths, including module
symlinks. Preparation script: bazel-iconv-complete-runtime-qualification-20261028/prepare.py.
Fixture: /usr/obj/usr/src/bazel-iconv-complete-runtime-20261028/test-root.
No mounted filesystem, host installation or host policy change was performed.

Maintained tools/build/bazel/iconv-chroot-check.py accepts explicit root, manifest,
output, uid and gid inputs, verifies fixture hashes and runs children through
host chroot after dropping user/group/supplementary groups to the requested
nonzero IDs. Its 20 intended checks cover the maintained iconvctl ATF case,
eight representative encoding round trips, invalid input/unknown encoding, and
encoding listing. Python codecs provide independent expected byte sequences.
The host kernel/loader remain dependencies and these samples do not cover every
encoding. The runner's syntax/help paths were checked; runtime cases are NOT yet
qualified or registered as a passing Bazel test suite.

The host has security.bsd.unprivileged_chroot disabled. A real chroot -n probe
failed with that explicit OS policy error. No sudo/doas executable is available,
and sandbox escalation does not grant root uid. The user was asked to run this
prepared command in a root shell (it drops privileges before testing):

    sh /usr/obj/usr/src/bazel-iconv-complete-runtime-qualification-20261028/run-root.sh

Expected report: bazel-iconv-complete-runtime-20261028/runtime-results.json.
Until that report is inspected, end-to-end conversion remains pending. Other
migration work can continue; this is not a whole-goal blocker. Frontend review:
all build inputs/artifacts use maintained build-bsd format-5 qualification;
privileged runtime execution is a separate explicit pending gate, not a claimed
new frontend feature or replacement build. Make remains production/default.

## 2026-10-28: installed native Citrus generators qualified

mkesdb and mkcsmapper now use the standard utility installation macro and archive
rules for the normal dynamically linked programs, separate debug files and
compressed manuals. Static *_tool execution binaries remain build tools and are
not substituted for installed user programs. Existing package/mtree/account
policy supplies utilities metadata and debug directory ownership.

Evidence: /usr/obj/usr/src/bazel-citrus-generator-install-20261028/receipt.json and
qualification/installation-parity.json. Both archives match their entire unique
Make component inventory, ownership, modes, flags, package tags and manual bytes.
Debuglink names/CRCs and DWARF-info presence pass; stripping preserves .text from
the corresponding native program artifact. Loader traces select native libc and
libsys. The stripped installed programs then regenerated every one of the 656
binary databases against the prepared maintained source inputs at 16 jobs; all
outputs match Make byte-for-byte. This qualifies dynamic installed generators in
addition to the previously qualified static execution tools.

Fresh independent Make references were produced by maintained install-reference.py:
bazel-mkesdb-install-reference-20261028 and bazel-mkcsmapper-install-reference-20261028.
Verification script: bazel-citrus-generator-install-qualification-20261028/verify.py.
No host installation occurred. This is default amd64 utility installation and
generator runtime evidence, not aggregate pkgbase publication or end-to-end iconv
conversion. The latter still awaits the previously requested root-shell run;
runtime-results.json was absent when checked this turn. Other migration work
continues independently. Frontend review: build-bsd.c's format-5 native targets
and maintained backend handle these archives at 16 jobs without new CLI or
publication inputs. Make remains the production default.

## 2026-10-28: libc core library installation and stripped runtime

Added native library_install_manifest/library_install_archive for libc.a,
libc_pic.a, libc.so.7, its separate debug file, libc.so linker script and libxnet.so
compatibility link. The installed PIC archive aliases the shared-object archive,
matching Make's SOBJS contract rather than the static-wrapper group. Existing
Make schg metadata on libc.so.7 is preserved in the archive; no host flag or BIP
policy is changed. The manifest intentionally names its library-only scope.

Evidence: /usr/obj/usr/src/bazel-libc-library-install-20261028/receipt.json and
qualification/library-installation-parity.json. All seven library/debug-directory
metadata records match Make, including ownership/modes/tags/flags and the link.
The linker script bytes match. Installed native archives retain their original
bytes and match Make member counts: libc.a 1455, libc_pic.a 1443. Stripped shared
libc retains identical .text and .SUNW_dof bytes from the qualified native full
library. Separate-debug name/CRC and DWARF-info presence pass. The existing
runtime smoke probe then passes against the stripped installed libc and native
libsys; loader paths are recorded. This does not prove live DTrace firing.

Reference: bazel-libc-install-reference-20261028-r3. The full maintained install
inventory with tests disabled contains 1494 unique paths, including manuals,
aliases and NLS catalogs; this commit qualifies only the seven library records.
The first reference lacked compressed manuals and attempted unbuilt tests. The
second used a nonexistent manbuild target. The final reference explicitly uses
WITHOUT_TESTS, WITHOUT_NIS and debug malloc, builds the maintained all-man target,
and performs rootless install. Failed runs are retained. Scripts and source/manual
inventory: bazel-libc-install-qualification-20261028. Remaining manual/catalog/
configuration coverage must be reconciled before whole-libc installation claims.

Frontend review: build-bsd.c's existing format-5 targets/tests/backend built the
new archives and existing smoke tests at 16 jobs; no CLI/publication inputs need
changing. The extra installed-library execution check uses saved artifacts. No
host installation occurred. Make remains production/default; pending privileged
iconv conversion and full world/kernel/pkgbase/performance gates remain open.

## 2026-10-28: libc catalog installation reconciled; native gencat

Reconciled the existing catalog rules with the full libc Make installation.
The /usr/share/nls parent directory was missing an explicit locales package tag;
it now carries maintained Make's package=locales metadata. Locale subdirectories
retain their utilities tags, and catalog files retain locales ownership. Native
catalog generation now uses gencat_tool linked statically against native libc.
The normal gencat target also uses the native shared libc interface and explicit
libc/libsys dependencies; the installed tool has not yet received separate runtime
or installation requalification in this step.

Evidence: /usr/obj/usr/src/bazel-libc-catalog-install-20261028/receipt.json and
qualification/installation-parity.json. All 27 catalog payload bytes and metadata
match Make; all 28 catalog directory metadata records match. The static execution
tool has no ELF INTERP segment (qualification/generator-proof.json). Reference:
bazel-libc-install-reference-20261028-r3. Script:
bazel-libc-catalog-install-qualification-20261028/verify.py.

Also qualified explicit nls=false input through the maintained frontend:
bazel-libc-catalog-disabled-20261028/disabled-proof.json. Its installation manifest
is empty, its archive has no file payload, and no BSDMessageCatalog action runs.
No disabled-build result is counted as a catalog runtime test. Catalog lookup
semantics, normal gencat installed execution, libc manuals/configuration, pending
privileged iconv conversion and whole-system gates remain. Frontend review:
build-bsd.c format-5 targets/settings/backend support both runs at 16 jobs without
new CLI/publication inputs. No host installation occurred; Make remains default.

## 2026-10-28: all libc manuals and aliases use native installation rules

Added owned manual_sources.bzl metadata for 459 source manuals and 972 aliases.
Twenty-four source packages expose restricted filegroup labels for their maintained
manual sources; runtime Bazel generation reads neither Make metadata nor staged
reference files. manual_installation.bzl uses declared compression, installation
and hardlink rules. Five iconv manuals and five aliases follow the typed iconv
setting. Runtime manuals retain clibs ownership, development manuals/aliases use
clibs-dev, and split_manpages selects clibs-man. Make inventory queries confirmed
NIS selection does not alter this amd64 manual inventory.

Default evidence: /usr/obj/usr/src/bazel-libc-manuals-20261028/receipt.json and
qualification/manual-parity.json. All 1431 output paths match maintained Make
metadata and compressed bytes; all 972 hardlinks match source inode identity.
Alias chains are resolved before comparing tar targets: e.g. regfree.3 points
through regexec.3 to regex.3 in metadata, while the archive links directly to the
canonical source. The initial verifier assumed only direct aliases; it was
corrected to check canonical resolution and Make inode identity without changing
archive behavior or relaxing byte checks.

Variant evidence: bazel-libc-manuals-variant-20261028/qualification/manual-parity.json.
With iconv=false and split_manpages=true, all 1421 paths match Make, including 967
hardlinks and the clibs-man tags. The independent variant reference uses
WITHOUT_ICONV/WITH_MANSPLITPKG and maintained all-man/maninstall targets; no stale
library binaries are installed as part of this manual-only reference.
References: bazel-libc-install-reference-20261028-r3 and
bazel-libc-manuals-variant-reference-20261028. Scripts:
bazel-libc-manuals-qualification-20261028. No host installation occurred.

This establishes library documentation payload coverage for these amd64 options;
other architectures, complete configuration handling, aggregate pkgbase packages
and whole-system qualification remain. Frontend review: build-bsd.c's format-5
targets/settings/backend handles both archives at 16 jobs without new CLI or
publication inputs. Make remains production/default. The previously requested
privileged iconv conversion gate remains separate from this evidence.

## 2026-10-28: aggregate libc package installation payload

Added //lib/libc:install_archive combining native libraries, manuals, catalogs
and maintained raw configuration manifests. Catalog inclusion follows nls; the
manifest is exposed only to its libc parent package. Account database generation
remains separate initial-system state, as in the existing config_archive target.
The aggregate excludes the test suite and does not install or migrate accounts.

Evidence: /usr/obj/usr/src/bazel-libc-complete-install-20261028/receipt.json and
qualification/complete-installation-parity.json. Compared against an independent
maintained Make install plus installconfig, all 1505 package-tagged metadata
records match (owners, groups, numeric IDs, modes, tags, flags and link targets),
including 30 component directories. All 1470 nonbinary file payloads match Make;
973 hardlink/symlink relationships pass. The four native library/debug binaries
are byte-identical to the separately qualified library installation archive.
Make's untagged /etc/passwd, /etc/pwd.db and /etc/spwd.db are explicitly accounted
for as initial state, outside this package payload. Reference:
bazel-libc-complete-install-reference-20261028. Comparison script:
bazel-libc-install-qualification-20261028/verify-complete.py.

Scope is amd64, NIS disabled, debug malloc, NLS/iconv enabled, tests excluded.
This is archive installation parity, not a built pkgbase repository, a fresh
bootable system, a runtime suite pass or whole-world completion. The frontend
receipt reports action success with no selected runtime tests; the separate
comparison supplies installation evidence. Reviewed build-bsd.c: its maintained
bazel-test --bazel-inputs path handles this aggregate at 16 jobs without new
inputs or publication behavior. No frontend change is needed for this target.
No host installation occurred. Make remains production/default. Privileged
iconv conversion, broader configurations, complete world/kernel/packages and
performance qualification remain open.

## 2026-10-28: native libc NOSSP PIC archive for rtld

Added //lib/libc:nossp_pic_archive. An internal bool_setting and incoming
configuration transition select a separate libc object graph. The existing
cc_library rules consume LIBC_VARIANT_FEATURES, disabling the bsd_ssp toolchain
feature only for libc; separately built dependencies retain their own policy.
This uses Bazel's documented configuration transitions and native C++ features,
not exported Make recipes or post-compilation rewriting. Reference:
https://bazel.build/extending/config

NOSSP source selection reuses common groups and shared syscall variants, but
excludes SOBJS-only libc_stubs and STATICOBJS-only implementations/wrappers.
The initial candidate incorrectly reused the complete shared inventory; its
comparison caught the extra libc_stubs object. The next candidate disabled SSP
through a global features transition, also changing drti. The final internal
libc-only setting preserves Make's separately built drti policy. Both rejected
candidates remain under bazel-libc-nossp-20261028 and its -r2 directory.

Evidence: /usr/obj/usr/src/bazel-libc-nossp-20261028-r3/qualification/object-comparison.json.
All 1442 object members map to the independent Make NOSSP archive; every mapped
member's executable sections match byte-for-byte. Global and undefined symbol
multisets match after normalizing DTrace path IDs. Stack-protector imports match
Make: drti retains its instrumentation and the compatibility wrapper explicitly
calls __stack_chk_fail. Do not describe the entire archive as lacking all SSP
symbols. Member aliases from gdtoa/jemalloc/cancellation sources are accounted
for; the two div.pic.o basenames are distinguished without dropping a member.
This check does not claim full ELF/debug bytes or relocation-table equivalence.
Reference: bazel-libc-nossp-reference-20261028/receipt.json and the independently
compiled libc_nossp_pic.a in bazel-libc-link-make-20261028/objects/usr/src/lib/libc.
Scripts: bazel-libc-nossp-qualification-20261028/{make-reference.py,verify.py}.

Regression evidence: bazel-libc-nossp-regression-20261028/qualification/regression.json.
The ordinary PIC archive is byte-identical to its previous qualified build;
the NOSSP archive is byte-identical to the object-comparison candidate. Both
maintained shared and static libc smoke tests pass through bazel-test. Reviewed
build-bsd.c: existing explicit format-5 targets/tests suffice, with 16 jobs and
no public option changes. This internal setting is not a new user CLI option.
Scope is native amd64, NIS off, debug malloc, current supported instrumentation
settings. Arbitrary sanitizer flags and other architectures are not qualified.

The runtime linker itself still needs native source rules, its replacement libc
code, selected syscall objects, lazy DTrace provider, linkage/install tests and
runtime qualification. NOSSP does not finish rtld or SDK/bootstrap closure.
Full world/kernel/packages/performance gates remain open; Make stays default.
No host installation occurred. The full execution diagnostic for the first
candidate was approximately 1.8 GiB; broad diagnostic disk/resource cost remains
a performance work item, not a passed gate.

## 2026-10-28: native runtime-linker core and lazy DTrace provider

Added native amd64 rtld core compilation: ten C translation units and two
startup assembly units, with declared architecture, startup-note, rtld-libc ABI,
capimage and veriexec syscall headers. policy.bzl records maintained freestanding,
no-SIMD, soft-float, hidden-visibility, no-SSP and zero-fortification requirements.
The core includes elf_signature.c; signature checks were not omitted to make
the build pass. No runtime source or security behavior changed.

rtld's DTrace header and object transformations use the maintained -xlazyload
policy. All rewritten objects are separate outputs; compilation outputs remain
immutable. Ten C objects are supplied to the transform; only probe-bearing code
changes. The lazy provider carries DOF and expected probe-site relocations, with
no init/fini constructor sections or other undefined runtime imports. A first
verifier incorrectly rejected the necessary $dtrace probe-site symbols; it was
corrected to distinguish those from external runtime imports, while retaining
the complete normalized symbol comparison with Make.

Evidence: /usr/obj/usr/src/bazel-rtld-core-20261028/qualification/object-parity.json.
All 12 core objects match independent Make executable-section bytes and global/
undefined symbols after normalizing DTrace path IDs; provider symbols also match.
Reference: bazel-rtld-core-reference-20261028. Disabled variant evidence:
bazel-rtld-core-no-dtrace-20261028/qualification/object-parity.json: all 12 core
objects match Make bytes/symbols, no DTrace symbols, no DTrace generation actions.
Independent reference: bazel-rtld-core-no-dtrace-reference-20261028. Scripts:
bazel-rtld-core-qualification-20261028.

Reviewed build-bsd.c's maintained bazel-test backend; existing format-5 explicit
targets and typed dtrace setting handle both runs with 16 jobs. No new frontend
input or publication behavior is needed. These are object comparisons, not
linked-loader or runtime tests; no host installation occurred. Next: native
rtld replacement-libc sources, selected libc/libsys object dependencies, final
link/version map and forbidden-dependency checks, installation and loader tests.
SDK/bootstrap closure and full world/kernel/package/performance gates remain
open. Make remains production/default.

## 2026-10-28: rtld replacement libc compilation

Added 42 native replacement-libc source targets under libexec/rtld-elf. Owned
libc_sources.bzl metadata declares the selected gen, stdlib and generic string
sources plus rtld_libc.c, their per-source warnings and textual dependencies.
Source packages expose restricted filegroup labels from this same inventory.
These sources compile with rtld's private namespace/libc_private headers and
freestanding compiler policy, not the ordinary libc object variants. Dedicated
dirent and errlst header targets avoid importing ordinary libc namespace policy.
Generic string implementations preserve Make's avoidance of IFUNC dispatch.

The first sandboxed build caught bzero.c's included memset.c as undeclared.
Added its textual dependency, alongside memcpy/memmove's included bcopy.c,
after checking the full selected source include inventory. No sandbox bypass
or broad source-tree input was introduced. Failed evidence remains in
bazel-rtld-libc-20261028; successful evidence is
/usr/obj/usr/src/bazel-rtld-libc-20261028-r2/qualification/object-parity.json.
All 42 replacement objects match Make executable-section bytes and global/
undefined symbols. None imports stack-protector instrumentation. Together with
the 12 previously qualified core objects and provider, their 55 ELF object
paths exactly reconcile with the independent Make reference. Make's textual
.depend.*.o files are explicitly distinguished from ELF compilation outputs.
Reference: bazel-rtld-core-reference-20261028; comparison script:
bazel-rtld-libc-qualification-20261028/verify.py.

Reviewed build-bsd.c's maintained bazel-test backend: existing format-5 explicit
target selection handles this target with 16 jobs, without new public inputs.
No host installation occurred. Scope is amd64 object compilation; final rtld
linkage still requires its selected libc/libsys archive objects and compiler
runtime, version script, dependency checks and installation/runtime tests.
No complete-loader, world/kernel/package or performance claim is made. Make
remains production/default.

## 2026-10-28: rtld's selected libc/libsys dependency objects

Added bsd_component_selected_objects, which selects named compiler outputs from
a component's own CcInfo linker inputs. It rejects empty/duplicate requests,
missing names and ambiguous basenames. Transitive link dependencies cannot
expand the selection; no archive extraction, filesystem search or staging-file
substitution is involved. Only the selected outputs are returned as build inputs.

libc exposes six rtld objects through its existing NOSSP configuration, now
named libc_nossp_variant to cover both archive and object consumers. The existing
nossp_pic_archive label retains its meaning. libsys exposes 32 selected PIC
objects. rtld imports these and constructs selected_runtime_archive using the
native toolchain archive action. Final linkage must use normal archive extraction
semantics, not whole-link libc or libsys.

Evidence: /usr/obj/usr/src/bazel-rtld-selected-20261028/qualification/selection-parity.json.
Queried Make's _libc_other_objects and _libsys_other_objects independently: the
38-member archive exactly matches their union. All 38 executable-section payloads
and global/undefined symbol sets match independently compiled Make objects.
The report records each reference object; comparisons use libc NOSSP objects
and libsys PIC objects, never host installed libraries. Script:
bazel-rtld-selected-qualification-20261028/verify.py.

Reviewed build-bsd.c's maintained bazel-test backend: existing format-5 targets
handle this archive with 16 jobs; no new public inputs or publication changes.
No runtime source or host installation changed. Next: final loader linkage,
version script, forbidden-dependency checks, installation/debug parity and
loader runtime tests. These dependency-object results do not establish loader
execution, full-world/kernel/pkgbase or performance qualification. Make remains
production/default.

## 2026-10-28: native rtld linking and direct execution

Added //libexec/rtld-elf:rtld and rtld_binary. The local link rule uses the
registered C/C++ toolchain and cc_common.link with explicit PIC compilation
outputs, ordinary archive dependencies, entry symbol, maintained version map,
-nostdlib, symbolic binding and defined-symbol enforcement. The link map is a
declared additional output, not an undeclared shell side effect. Version-map
generation reuses the maintained declared CPP/AWK actions.

A mandatory sandboxed check rejects the same four link-map patterns as Make:
__libsys_interposing, __libc_interposing, xlocale and fprintf. Only after these
checks does it copy the loader to its exported artifact and produce a hash
report. Installation consumers of rtld_binary therefore depend on the check.
The checker does not claim ELF verification beyond a magic check; independent
qualification below supplies ABI and runtime evidence.

Evidence: /usr/obj/usr/src/bazel-rtld-link-20261028-r3/qualification/link-parity.json.
The version map and all 29 dynamic symbol entries match independent Make. Both
loaders have the correct .rtld_start entry, symbolic/bind-now/RELRO properties,
no PT_INTERP, no DT_NEEDED and no init/fini constructors. Ten DTrace probe
schemas match; 12 ordinary and 14 enabled probe sites have validated instruction
bytes. This does not establish live probe firing. Whole ELF bytes differ due
to build paths/layout and are not claimed identical.

qualification/direct-runtime.json records successful direct execution of the
existing native-libc smoke executable through the new loader, with loader trace
confirming the explicit native libc.so.7 and libsys.so.7 paths. No installed
loader or program was replaced. The host kernel and prepared SDK headers/
startup objects remain. This smoke execution is not yet a maintained Bazel
loader test suite or a full-system boot qualification.

DTrace-disabled evidence: bazel-rtld-link-no-dtrace-20261028/qualification, with
the same ABI/properties and direct smoke pass and no DOF section. References:
bazel-rtld-link-reference-20261028 and bazel-rtld-link-no-dtrace-reference-20261028.
Make uses independently built libc NOSSP/libsys PIC archives; its compiler-rt
search still uses the prepared SDK, while native linkage declares compiler_rt.
Scripts: bazel-rtld-link-qualification-20261028. The enabled qualification also
records rejection of all four forbidden map patterns and an empty map in
link-check-rejections.json. Initial analysis failures (generator visibility and
SDK Python file acceptance) remain in the first two native run directories.

Reviewed build-bsd.c: existing format-5 targets support both runs at 16 jobs.
No public build/publication option changes are needed. Next: installation/debug
metadata parity, maintained Bazel loader runtime tests and broader dlopen/TLS/
libmap/preload/error handling. Full-world/kernel/pkgbase, bootstrap and resource
performance gates remain open. Make remains production/default.

## 2026-10-28: runtime-loader installation/debug payload

Added rtld install_manifest/install_archive through shared debug-split, strip,
compression, link and installation rules. Payload includes /libexec/ld-elf.so.1,
its separate debug file, /etc/libmap.conf, the /usr/libexec compatibility symlink,
rtld.1 and both maintained manual aliases. Configuration retains its config tag;
the loader retains Make's existing schg flag. This is ordinary installation
metadata, not a return of BIP. Manual ownership follows split_manpages.

Evidence: /usr/obj/usr/src/bazel-rtld-install-20261028/qualification/installation-parity.json.
All nine unique component metadata records match rootless Make install plus
installconfig, including two directories and three symlink/hardlink records.
Four nonbinary file payloads match Make byte-for-byte, including manual aliases.
The debug filename/CRC and DWARF checks pass; stripping preserves native .text
and .SUNW_dof bytes. The stripped loader directly executes the native-libc smoke
probe, with trace confirming native libc/libsys selection. No installed host
loader, configuration or files were changed.

Independent reference: bazel-rtld-install-reference-20261028. Scripts:
bazel-rtld-install-qualification-20261028/{make-reference.py,verify.py}. Scope is
amd64 default manual packaging with DTrace enabled and component tests excluded;
this does not establish complete pkgbase archives or full-system installation.
Reviewed build-bsd.c's maintained bazel-test backend: existing format-5 inputs
handle the archive with 16 jobs. No new frontend/publication setting is needed.
Next: maintained Bazel loader runtime tests covering dynamic loading, TLS,
libmap/preload and failure behavior. Broad world/kernel/pkgbase/bootstrap and
performance gates remain open. Make stays production/default.

## 2026-10-28: maintained ATF cases through the native loader

Added optional loader input to bsd_atf_test for program-interface cases. The
static adapter invokes the declared loader with -- and the ATF program for
both body and cleanup, retaining deadlines, status handling and XML reporting.
Missing loader execution fails; there is no host-loader fallback. Shell tests
cannot select this mode. Existing callers default to their previous behavior.
This intentionally does not redirect exec/fexecve calls made by test children;
such cases still need their interpreter/runtime paths qualified separately.

Converted the existing unmodified set_var_test and dlopen_hash_test programs
and libpythagoras fixture to native targets. Both maintained cases pass through
the native rtld: runtime LIBRARY_PATH_FDS changes and descriptor-qualified
dlopen names. The fixture remains in the suite data directory, outside the
initial runtime library path, preserving each test's initial missing-library
assertion. Native libm is a declared fixture dependency.

Evidence: /usr/obj/usr/src/bazel-rtld-tests-20261028/receipt.json, test-reports
and qualification/runtime-provenance.json. Exactly two reported ATF cases
passed, with native-loader bytes matched to the saved artifact and runtime
trace confirming native libc, libsys and private ATF selection. SDK headers
and link interfaces and the host kernel remain. Adapter regression evidence:
qualification/adapter-regression.log, 19 tests passed, including explicit-loader
body/cleanup dispatch and missing-loader failure without executing the body.
These controlled protocol fixtures test adapter behavior, not ELF loading.

Reviewed build-bsd.c's maintained bazel-test backend: existing format-5 targets/
tests handle both cases at 16 jobs; no frontend CLI change is needed. Native
Bazel runfiles carry the loader and fixtures. Remaining loader tests include
dlopen/libthr unload, deep binding, child fexecve/preload behavior, TLS, libmap,
parse-integer and signature-verifier cases. No host installation occurred;
whole-system/bootstrap/package/performance gates remain open. Make stays default.

## 2026-10-28: maintained rtld deep-binding case

Added native libval, libval2 and libdeep fixture targets plus the unmodified
rtld_deepbind ATF program. The fixture outputs live beside that program, matching
the installed test directory and preserving $ORIGIN lookup. libdeep.so is a
declared symlink to its versioned DSO. libval and libval2 remain separate shared
objects with separate state: the program depends on libval; libdeep depends on
libval2. The test's original RTLD_DEEPBIND and independent-value assertions remain.

The first analysis rejected an implicit cc_library shared-output collision with
the explicit libdeep alias; component cc_library rules now use linkstatic=True
and cc_shared_library owns the DSOs. The second run caught $$ORIGIN preserved
literally by cc_shared_library user_link_flags. Corrected that argument to
$ORIGIN; cc_binary linkopts retains its required $$ escaping. No source/test
assertion was changed. Both unsuccessful runs remain recorded.

Evidence: /usr/obj/usr/src/bazel-rtld-deepbind-20261028-r3/receipt.json and
qualification/fixture-and-runtime-parity.json. One actual ATF case passes under
the declared native loader. All four program/DSO NEEDED, SONAME and RPATH/RUNPATH
properties match independent Make outputs. Explicit checks preserve the separate
val/val2 dependency paths and literal $ORIGIN. Runfile fixture bytes match saved
artifacts, and loader tracing confirms declared native libc/libsys/private ATF
and libval selection. Reference: bazel-rtld-deepbind-reference-20261028; scripts:
bazel-rtld-deepbind-qualification-20261028. This establishes one deep-binding
case, not general loader completion or live DTrace behavior.

Reviewed build-bsd.c's maintained bazel-test backend: existing format-5 target/
test inputs qualify this case at 16 jobs without new CLI/publication behavior.
No host installation occurred. Remaining work includes libthr dlopen/unload,
child exec/fexecve/preload paths, TLS/libmap and other maintained loader tests,
then broad world/kernel/pkgbase/bootstrap/cache/performance qualification.
Make remains production/default.

## 2026-10-28: native libthr dlopen cases

Added the unchanged dlopen_test.c program and its two ATF cases. An explicit
libthr.so fixture alias resolves to the declared native libthr.so.3; both are
runfiles beside native libc/libsys/private ATF. The program is executed through
the declared native rtld, using the maintained explicit-loader adapter.

Evidence: /usr/obj/usr/src/bazel-rtld-dlopen-20261028/receipt.json and
qualification/runtime-provenance.json. Both dlopen_basic and dlopen_recursing
passed as actual Bazel/ATF cases. The first checks pthread_create lookup, close
and rejection of lookup through the closed handle; it does not prove physical
unmapping of libthr. The second checks RTLD_GLOBAL loading/close without the
previous recursion failure. Neither case starts threads or qualifies general TLS.

The provenance check confirms alias/versioned DSO bytes equal the saved native
libthr artifact, then independently reruns both cases with process-local ktrace
name lookups. Both return ATF passed; traces contain the declared libthr.so path
and no /lib or /usr/lib libthr lookup. Per-case ktrace.out/namei.txt and results
are retained in qualification. Script: bazel-rtld-dlopen-qualification-20261028/verify.py.
libthr still links against prepared SDK interfaces, with native libraries chosen
at runtime; this is not bootstrap closure. The host kernel remains.

Reviewed build-bsd.c's maintained bazel-test backend: existing format-5 targets/
tests handle these runs at 16 jobs, without new public options or publication
changes. No host installation occurred. Next loader work includes child fexecve/
preload behavior, parse-integer and signature-verifier cases, plus TLS/libmap
coverage. Full world/kernel/pkgbase/cache/bootstrap/performance gates remain
open. Make stays production/default.

## 2026-10-28 rtld parser and descriptor-verifier tests

Added native Bazel builds for the unchanged parse_integer_test.c and
signature_verify_test.c. The parser's textual C fragment is extracted from
production rtld.c by a declared staged sed action, matching the maintained
Make command byte for byte (819 bytes). It is a textual compilation input,
not a separately compiled replacement implementation. The verifier test
explicitly declares the production elf_signature.c and its header dependencies.

Both actual ATF cases (integers and same_descriptor) passed through native rtld
with native libc/libsys/private ATF selected by the existing test adapter.
Evidence: /usr/obj/usr/src/bazel-rtld-unit-20261028/receipt.json and
qualification/unit-parity.json; independent extraction check script at
/usr/obj/usr/src/bazel-rtld-unit-qualification-20261028/verify.py.
The verifier test injects classification and syscall transport. It checks the
same descriptor, preserved file offset, unsigned/required/malformed decisions,
and propagation of EAUTH/ECAPMODE/ENOSYS/EPERM/EIO. It does not authenticate a
real signed object or exercise the kernel verifier. No test C sources changed.

Reviewed build-bsd.c and its maintained format-5 bazel-test backend: the added
targets/tests use existing inputs, explicit runtime dependencies and 16 jobs;
no frontend option, staging, signing or publication change is required.
Seven maintained rtld ATF cases are now qualified across recorded runs. Child
exec/fexecve/preload behavior, TLS/libmap and full runtime qualification remain
open, as do world/kernel/pkgbase/bootstrap/cache/performance gates. Make stays
production/default. No host installation or BIP work occurred.

## 2026-10-28 descriptor-loading test builds

Added native targets for the unchanged ld_library_pathfds and ld_preload_fds
programs (including common.c), plus their target child executable. The
fd_loading_suite filegroup collects both parents, the child and libpythagoras.
The library's public header now uses a declared include prefix; the initial
sandbox compilation caught the missing include interface. That failed run is
retained at /usr/obj/usr/src/bazel-rtld-fd-build-20261028.

The corrected build passed at /usr/obj/usr/src/bazel-rtld-fd-build-20261028-r2.
Independent Make builds under bazel-rtld-fd-reference-20261028 establish matching
NEEDED, SONAME, RPATH/RUNPATH and PT_INTERP properties for all four artifacts.
The target requires libc.so.7 and libpythagoras.so.0, has no RPATH/RUNPATH and
uses /libexec/ld-elf.so.1. Thus the fixture does not bypass missing-library
checks through a Bazel build-directory search path. Evidence is in
qualification/elf-parity.json; commands and verification script are retained
under /usr/obj/usr/src/bazel-rtld-fd-qualification-20261028.

This is build qualification only: zero additional ATF cases ran. The unchanged
common helper invokes fexecve with only the test's selected environment entry.
The kernel therefore chooses the installed interpreter. Passing the parent
through native rtld cannot qualify the child loader. The eleven descriptor
cases (seven directory and four preload cases) need an isolated root/VM with
the native loader at its normal interpreter path and the native runtime
installed. Do not replace fexecve, inject a search path that defeats negative
cases, or report a host-loader run as native-loader qualification.

Reviewed build-bsd.c's bazel-test integration: existing format-5 target inputs
support this build-only suite at 16 jobs. No frontend, signing, installation or
publication change is required. Seven previously recorded rtld cases remain
runtime-qualified. Full world/kernel/pkgbase and performance gates remain open;
Make remains production/default, with no host installation or BIP changes.

## 2026-10-28 top-level rtld test installation

Added maintained installation/debug manifests for all seven top-level rtld test
programs, their generated Kyua index, and a component install archive. The index
retains the rtld_deepbind subdirectory reference. This archive covers only the
top-level test directory, not the referenced subdirectory or helper libraries;
it is not yet a standalone complete installed loader test suite.

The independent rootless Make reference used -DNO_SUBDIR to install exactly
this component. All 20 unique records match: 15 files and five package-owned
directories, including ownership, permissions, flags and package/debug tags.
The Kyua index is byte-identical to Make. All seven stripped executable/debug
pairs pass debug-link name, CRC and DWARF checks. ELF/debug byte identity with
Make is not asserted. Evidence:
/usr/obj/usr/src/bazel-rtld-tests-install-20261028-r3/qualification/installation-parity.json.
Make reference: bazel-rtld-tests-install-reference-20261028; retained scripts:
/usr/obj/usr/src/bazel-rtld-tests-install-qualification-20261028.
The r2 archive attempt failed BUILD syntax validation before compilation;
r3 corrected the directory comprehension and completed through build-bsd.

Reviewed build-bsd.c: existing format-5 targets and artifact/metadata collection
support these installation targets at 16 jobs. No new frontend option or
publication-policy change is needed. Tests remain explicit qualification
inputs; this does not enable them in production or publish packages. No host
installation occurred. No new runtime cases ran. The eleven descriptor cases
still require an isolated installed native loader, and the earlier root-only
iconv runtime report is still absent. Fixture/deepbind installation and complete
world/kernel/pkgbase/bootstrap/cache/performance qualification remain open.

## 2026-10-28 descriptor helper installation

The top-level rtld tests install archive now also includes target and all
libpythagoras payloads: the ordinary static archive, versioned shared library,
unversioned relative symlink and separate debug information. Ownership and
package tags follow Make's tests package, including the static library (no
invented development-package split). The ordinary archive uses component-owned
objects, so it does not absorb libm's transitive objects.

Evidence: /usr/obj/usr/src/bazel-rtld-helpers-install-20261028/qualification.
All 26 unique metadata records match the independent Make references: 20 files,
one symlink, and five directories. All nine runtime/debug pairs pass name, CRC
and DWARF checks. The ordinary archive contains exactly pythagoras.o; its .text
and global/undefined symbols match Make. The Kyua index remains byte-identical.
Scripts are under bazel-rtld-helpers-install-qualification-20261028. The initial
Make reference failed because it installed helpers before the parent test
directory; r2 installs the maintained parent first, preserving normal ordering.

Reviewed build-bsd.c's existing format-5 installation target support; no new
frontend option, staging policy or publication change is needed. Qualification
used build-bsd with 16 jobs and wrote only beneath /usr/obj. Deepbind installation
remains separate and is still needed to satisfy the Kyua subdirectory reference.
The eleven descriptor-loading runtime cases remain pending isolated native
loader installation. No new runtime cases ran, no host installation occurred,
and complete world/kernel/package/cache/bootstrap/performance gates remain open.

## 2026-10-28 complete rtld tests installation archive

The test install archive now includes rtld_deepbind, libval/libval2/libdeep,
their unversioned relative symlinks and debug files, and the nested Kyua index.
Together with the prior top-level programs and descriptor helpers, this covers
the maintained rtld test-directory installation for the qualified amd64/default
configuration. Library-only SHLIB fixtures do not acquire invented static
archives. Their existing $ORIGIN layout and separate dependency graphs remain.

All 40 unique metadata records match independent rootless Make references:
29 files, four symlinks, seven directories. Both Kyua indexes are byte-identical;
all 13 runtime/debug pairs pass filename, CRC and DWARF checks. Evidence:
/usr/obj/usr/src/bazel-rtld-complete-tests-20261028/qualification/installation-parity.json.
The additional Make reference is bazel-rtld-deepbind-install-reference-20261028;
scripts are in bazel-rtld-complete-tests-qualification-20261028.

The unchanged deepbind_simple case also passes using the actual stripped
program and three DSOs extracted from this archive into /usr/obj. Explicit
native rtld and native libc/libsys/private ATF come from the previously
qualified runfiles. Loader tracing confirms installed $ORIGIN/libval.so.0 and
native support libraries. Evidence: qualification/installed-runtime.json.
This is a rerun of an existing case, not an eighth distinct rtld case; the host
kernel remains. General child-exec qualification is not implied.

Reviewed build-bsd.c: the maintained format-5 target/artifact workflow builds
this archive with 16 jobs without new options or publication-policy changes.
No host installation or package publication occurred. The eleven descriptor
cases still require an isolated installed native loader. The full-system
world/kernel/pkgbase/bootstrap/cache/performance gates remain open and Make
remains production/default. BIP remains out of scope.

## 2026-10-28 configured rtld test inclusion

Connected //libexec/rtld-elf:install_archive to the existing tests build setting,
matching the maintained Makefile's SUBDIR.${MK_TESTS} selection. Before this
change the loader archive always excluded the separately declared test suite.
A shared source-owned tests/installation.bzl now supplies program names,
manifest labels and directory ownership to both archive entry points. This
avoids maintaining two divergent copies of the test installation inventory.

Both configurations passed through build-bsd with 16 jobs. With tests=false,
the entire archive is byte-identical to the previously Make-qualified rtld-only
archive. With tests=true, all files, links, modes, ownership and archive metadata
match the union of the independently qualified loader and full test archives;
all 49 explicit metadata records match. Evidence:
/usr/obj/usr/src/bazel-rtld-install-tests-true-20261028/qualification/configured-installation.json.
The disabled run is bazel-rtld-install-tests-false-20261028; verification script
is in bazel-rtld-configured-install-qualification-20261028/verify.py.

Reviewed build-bsd.c and its maintained format-5 inputs: the existing tests
setting already reaches native Bazel actions, so no new CLI option or backend
substitute is needed. The change affects declared component installation,
not production/default selection or publication. No runtime cases or host
installation occurred. Descriptor fexecve cases still need an isolated native
runtime; whole-world/kernel/pkgbase/bootstrap/cache/performance gates remain
open. Make stays production/default and BIP remains out of scope.

## 2026-10-28 native getty

Added a source-owned native getty target covering main.c/init.c/subr.c/chat.c,
local headers and the existing libutil CcInfo/shared-library dependency. The
installation archive includes the program, separate debug information,
gettytab configuration, all three sectioned manuals and Make-owned directories.
No program source or authentication behavior changed.

Through build-bsd at 16 jobs, the default amd64 candidate matches independent
Make across 96 global/undefined symbol entries, dynamic dependencies
(libc.so.7 and libutil.so.10, no RPATH), nine installation metadata records,
and all four nonbinary payloads. Debug filename/CRC/DWARF validates, and stripping
preserves the native candidate's .text bytes. This is not ELF/debug byte identity
with Make. Evidence: /usr/obj/usr/src/bazel-getty-20261028-r2/qualification/parity.json.
Reference: bazel-getty-reference-20261028, objects in
bazel-getty-reference-objects-20261028; scripts: bazel-getty-qualification-20261028.
The first archive omitted Make's /etc metadata; r2 includes its utilities owner.

Reviewed build-bsd.c: existing format-5 explicit target/settings/installation
collection supports this component, with no new frontend option or publication
contract. No host installation or terminal daemon startup occurred. The staged
SDK is still Make-prepared. PTY/serial interaction, login handoff, failure paths,
configuration/static/cross variants and resource/cache behavior remain to be
qualified. Complete world/kernel/pkgbase/runtime/performance gates remain open;
Make stays production/default and BIP remains out of scope.

## 2026-10-28 revnetgroup and phttpget

Added native source-owned targets and program/manual/debug installation archives
for revnetgroup (three C files plus hash.h) and phttpget (one C file). Neither
uses Make to discover or execute native build actions. Both passed through
build-bsd with 16 jobs. Make remains the independent reference and SDK supplier.

Each component matches Make's five installation records, compressed manual,
dynamic libc dependency and empty RPATH/RUNPATH. Global/undefined symbol entries
match (46 revnetgroup, 49 phttpget); both debug pairs validate and stripping
preserves native .text. Evidence: /usr/obj/usr/src/bazel-libexec-pair-20261028/
qualification/{revnetgroup,phttpget}/parity.json. Independent references:
bazel-revnetgroup-reference-20261028 and bazel-phttpget-reference-20261028;
scripts are in bazel-libexec-pair-qualification-20261028.

Four bounded runtime comparisons also match Make under native rtld/libc: stdin
user mapping, host mapping, nested netgroups, and phttpget's EX_USAGE diagnostic.
Native libc selection is traced. Evidence: qualification/runtime-parity.json.
These are retained qualification-script checks, not registered Bazel test cases.
No network requests, host installation or system-data writes occurred. HTTP
requests/proxies/timeouts/malformed replies, broader netgroup edge cases,
configuration/static/cross variants and performance remain open.

Reviewed build-bsd.c: existing format-5 explicit targets and installation
collection support both components without new CLI options or publication
changes. libulog still lacks a native target and must be implemented before
ulog-helper; no host-library substitute was added. Whole world/kernel/pkgbase,
bootstrap/cache and runtime/performance gates remain open. Make remains the
production/default build path; BIP is out of scope.

## 2026-10-28 native libulog and ulog-helper builds

Added native libulog compilation for all three maintained C files, public
ulog/utempter headers, component-only ordinary/PIC archives, declared version-map
generation, and the versioned DSO. ulog-helper consumes the native CcInfo/DSO.
The dependency is libmd's public md_link interface, not its archive-only md
label; the initial analysis rejected the latter and the corrected r2 passed.
No host-library substitute or C-source modification was introduced.

Independent Make comparison establishes identical generated Version.map,
31 dynamic symbol entries for libulog, 16 global/undefined helper entries,
and matching SONAME/NEEDED/empty RPATH layouts. All three ordinary and three PIC
objects match Make executable .text and global/undefined symbols. Make does not
produce libulog_pic.a in this configuration: the PIC comparison uses its three
ELF .pico objects (excluding non-ELF .depend metadata). The Bazel PIC archive is
a qualification output and has not been declared as an installation payload.
Evidence: /usr/obj/usr/src/bazel-ulog-20261028-r2/qualification/parity.json;
Make reference: bazel-ulog-reference-20261028; scripts: bazel-ulog-qualification-20261028.

Reviewed build-bsd.c: existing format-5 targets support these builds at 16 jobs;
no new frontend input or publication policy is required. Library/header/manual/
compatibility-link installation, helper setuid metadata, debug splitting and
isolated accounting runtime checks remain next. No helper was executed and no
host accounting database was modified. SDK bootstrap, full world/kernel/pkgbase,
cache and resource/performance qualification remain open. Make stays default.

## 2026-10-28 libulog and helper installation

Added source-owned libulog installation for its ordinary archive, stripped DSO,
separate debug file, two headers, two manuals/eight manual aliases and three
linker/utempter compatibility symlinks. The helper has a separate installation
archive preserving root ownership and 04555 mode in metadata. The PIC archive
remains qualification-only. No installed payload or side-effect implementation
was replaced by a host-library fallback.

All 23 combined metadata records match an independent rootless Make install.
Twelve header/manual payloads are byte-identical; eleven symlink/hardlink
relationships validate, including the two chained manual aliases. Both separate
debug pairs validate; the installed ordinary archive equals the already
qualified native static archive. Evidence:
/usr/obj/usr/src/bazel-ulog-install-20261028-r2/qualification/parity.json.
Make reference: bazel-ulog-install-reference-20261028; scripts:
bazel-ulog-install-qualification-20261028. The first native attempt failed
Starlark load ordering before compilation; r2 fixes the ordering and passes.

Reviewed build-bsd.c: existing format-5 targets and archive/metadata collection
support the additions at 16 jobs. No new frontend option or publication policy
is needed. This qualifies default amd64 installation, not INSTALLLIB/NO_PIC or
split-manual configuration variants, pkgbase publication or accounting runtime.
No helper was installed or executed, no host accounting records were changed,
and no setuid binary was placed on the host installation paths. Isolated PTY/
login/logout authorization checks remain next. Full world/kernel/pkgbase,
bootstrap/cache and resource/performance gates remain open; Make stays default.

## 2026-10-28 native RPC spray and quota daemons

Added native rpc.sprayd and rpc.rquotad targets with explicit librpcsvc/libutil
CcInfo/shared dependencies. The consumer protocol headers now have narrowly
visible CcInfo targets wrapping existing native rpcgen actions; neither consumer
silently depends on SDK copies of spray.h/rquota.h. Generated headers match the
Make-prepared SDK references byte for byte (1424 and 4162 bytes respectively).

Both program/installation candidates passed through build-bsd at 16 jobs and
match independent Make references: 28 global/undefined symbol entries for
rpc.sprayd, 35 for rpc.rquotad, matching NEEDED and empty RPATH/RUNPATH, five
installation records each, and byte-identical manuals. Both debug pairs validate
and stripping preserves the native executable .text. Package ownership remains
utilities for rpc.sprayd and nfs for rpc.rquotad. Evidence:
/usr/obj/usr/src/bazel-rpc-daemons-20261028/qualification, including per-program
parity.json and protocol-headers.json. References are
bazel-rpc.sprayd-reference-20261028 and bazel-rpc.rquotad-reference-20261028;
scripts are in bazel-rpc-daemons-qualification-20261028.

Reviewed build-bsd.c: existing format-5 targets/settings and installation
collection handle these components without new frontend inputs or publication
policy. No daemon was started, rpcbind registration made, host package installed
or quota state modified. Isolated inetd/standalone RPC startup, protocol errors,
authentication/quota replies, configuration/cross variants and performance
remain unqualified. Full world/kernel/pkgbase/bootstrap/cache/runtime gates
remain open; Make remains production/default and BIP is out of scope.

## 2026-10-28 native tcpd and IPv6 selection

Added tcpd with explicit contrib source/header/manual inputs and native libwrap
CcInfo/shared-library dependencies. Its maintained default daemon/hosts paths,
logging constants and timeout are compile definitions; the existing inet6_support
setting selects INET6. No runtime policy source changed. Arbitrary Make
LIBEXECDIR overrides are not yet exposed by this component and remain an input
configuration gap, rather than being claimed supported.

Both default and IPv6-disabled candidates pass independent Make comparisons:
24 and 23 global/undefined symbol entries respectively, matching libc/libwrap
NEEDED with no RPATH, five installation records each, byte-identical manual,
valid debug pairs, and preserved native .text through stripping. References
build the tcpd component against the prepared SDK; this is not independent
whole-libwrap variant/runtime qualification. Evidence:
/usr/obj/usr/src/bazel-tcpd-20261028-r2/qualification/parity.json and
/usr/obj/usr/src/bazel-tcpd-noinet6-20261028/qualification/parity.json.
Scripts: bazel-tcpd-qualification-20261028; references:
bazel-tcpd-reference-20261028 and bazel-tcpd-noinet6-reference-20261028.
The initial native compile rejected an unquoted path macro; r2 preserves C
string literals through Bazel tokenization, matching the established libwrap
consumer convention. No fallback or source substitution was used.

Reviewed build-bsd.c: existing format-5 configuration/targets carry this input
selection at 16 jobs; no new CLI or publication contract was introduced. No
wrapper was executed, service launched, network listener opened or host files
installed. Allow/deny policy, IPv4/IPv6 requests, syslog and daemon handoff remain
runtime gates. Full world/kernel/pkgbase/bootstrap/cache/performance work stays
open, Make remains production/default, and BIP remains out of scope.

## 2026-10-28 native rbootd

Added all six maintained rbootd C sources and four local headers to a native
Bazel program target, with program/manual/debug installation metadata. The
source files and runtime path definitions are unchanged. Qualification used
build-bsd with 16 jobs and an independent rootless Make reference.

All six executable object .text bodies and global/undefined symbol sets match
Make. The linked program matches 118 global/undefined symbol entries and its
libc-only dependency/empty RPATH layout. Five installation records and the
compressed manual match; debug name/CRC/DWARF validates and stripping preserves
native .text. Evidence: /usr/obj/usr/src/bazel-rbootd-20261028/qualification/
parity.json and object-parity.json. Make reference: bazel-rbootd-reference-20261028,
objects: bazel-rbootd-reference-objects-20261028; scripts:
bazel-rbootd-qualification-20261028. Debug bytes are not asserted identical.

Reviewed build-bsd.c: existing format-5 native target and installation collection
supports this component without new frontend options or publication policy.
No daemon was started, BPF device opened, boot packet sent or host files
installed. Interface selection, configuration parsing/reload, client permissions,
boot/read/error replies, resource behavior and cross/static variants remain
runtime/configuration gates. Complete world/kernel/pkgbase/bootstrap/cache/
performance qualification remains open; Make stays production/default.

## 2026-10-28 native TFTP client/server

Added native tftpd and tftp program/installation targets. One source-owned
TFTP_SOURCES inventory supplies the five shared implementation files; a declared
header interface serves both programs. Each compiles its own source objects,
matching Make's separate program builds. Server LIBWRAP and libwrap dependency
selection uses the existing tcp_wrappers setting; the client consumes native
libedit. Default configuration is qualified; wrapper-disabled qualification
remains open.

Both candidates passed through build-bsd at 16 jobs and match independent Make
references: 146 global/undefined entries for tftpd, 157 for tftp, expected
libc/libwrap or libc/libedit dependencies with no RPATH, five installation
records each and byte-identical manuals. Both debug pairs validate and stripping
preserves native .text. Evidence: /usr/obj/usr/src/bazel-tftp-20261028/qualification/
{tftpd,tftp}/parity.json. References: bazel-tftpd-reference-20261028 and
bazel-tftp-reference-20261028; retained scripts: bazel-tftp-qualification-20261028.

Client status, binary/ascii mode changes and quit match Make under native
rtld/libc/libedit, including stdout/stderr and exit status. The runtime trace is
retained in qualification/client-runtime.json. This is a bounded retained script
check, not a registered Bazel test and not a transfer test. No server was started
or transfer attempted. The maintained server functional test execs the installed
/usr/libexec/tftpd and includes root-required cases; qualify it in an isolated
installed runtime rather than accidentally exercising the host daemon. Both
client and server test builds/installation are still outstanding.

Reviewed build-bsd.c: existing format-5 native targets/settings/install outputs
handle these additions without new options or publication changes. No host
installation occurred. Transfer modes/options/retries/access policy, IPv4/IPv6,
configuration variants and performance remain gates, alongside complete world/
kernel/pkgbase/bootstrap/cache qualification. Make stays production/default.

## 2026-10-28 TFTP test builds and installation

Added the unchanged server functional.c native ATF program with libutil/private
ATF dependencies, plus the maintained client shell-test wrapper. Installed Kyua
metadata preserves timeout=15 for the server and is_exclusive="true" for the
client. Each parent exposes test_install_archive separately from its ordinary
program archive. These are explicit qualification targets; configured full-world
test aggregation remains to be connected.

Make records /usr/lib/debug/usr for both utilities and tests packages. Keeping
separate package archives preserves both ownership records instead of letting
last-record wins erase one. The initial combined candidate is retained as
bazel-tftp-tests-20261028; r2 separates the inventories. Rootless Make comparison
covers all eight server-test and three client-test records. Both Kyua indexes
and the shell wrapper are byte-identical, and the functional debug pair validates.
Evidence: /usr/obj/usr/src/bazel-tftp-tests-20261028-r2/qualification/installation-parity.json.
References: bazel-tftpd-tests-reference-20261028 and bazel-tftp-tests-reference-20261028;
scripts: bazel-tftp-tests-qualification-20261028. The client shell test has no
ELF/debug pair; the report's false debug flag means not applicable, not a failure.

Reviewed build-bsd.c: existing format-5 explicit target/artifact collection
supports these test archives at 16 jobs, with no new frontend or publication
policy. Zero ATF transfer cases ran. The server tests exec installed tftpd and
include root-required cases; the client tests start installed inetd/tftpd and
use privileged service ports. Use an isolated installed runtime to qualify these
without testing the host programs or changing test semantics. No host daemon,
listener, installation or transfer was started. Full-system/cache/performance
and configured test aggregation remain open; Make remains production/default.

## 2026-10-28 TFTP without TCP wrappers

Qualified the existing tcp_wrappers=false server configuration through build-bsd
at 16 jobs against an independent WITHOUT_TCP_WRAPPERS Make reference. The
candidate matches 143 global/undefined symbol entries, libc-only NEEDED and
empty RPATH/RUNPATH, five installation records and the manual bytes. Its debug
pair validates and stripping preserves native .text. Compared with the default
native server, the linked artifact removes hosts_access, request_init and
request_set, exactly the calls in tftpd.c's LIBWRAP branch; no new symbols appear.
An initial ad hoc comparison incorrectly expected sock_host; source inspection
confirmed the actual request_set call and the retained comparison checks it.

Evidence: /usr/obj/usr/src/bazel-tftpd-nowrap-20261028/qualification/tftpd/parity.json
and qualification/wrapper-symbols.json. Reference:
bazel-tftpd-nowrap-reference-20261028; scripts:
bazel-tftpd-nowrap-qualification-20261028. No implementation change was needed:
the existing declared dependency/define selection produces the correct variant.
Reviewed build-bsd.c's existing format-5 setting transport; no frontend changes
are needed for this qualification. No transfer, wrapper policy decision, daemon
startup or host installation was performed. Disabled wrappers intentionally
remove hosts-access checks; this is a build option parity result, not proof of
network policy correctness. Full-system/runtime/cache/performance gates remain
open and Make remains production/default.

## 2026-10-28 native ntalkd

Added the maintained talk daemon's six-source native program, including the
explicitly exported wall/ttymsg.c source and a narrow ttymsg.h interface. The
installation correctly keeps executable ntalkd and manual talkd(8), without
inventing an ntalkd manual alias. Runtime code and path definitions are unchanged.

At 16 jobs through build-bsd, all six object executable .text bodies and global/
undefined symbol sets match independent Make. The linked program matches 65
symbol entries and libc-only dependency/empty RPATH. Five installation records,
manual bytes and debug name/CRC/DWARF checks pass; stripping preserves native
.text. Evidence: /usr/obj/usr/src/bazel-talkd-20261028/qualification/parity.json
and object-parity.json. Reference: bazel-talkd-reference-20261028; objects:
bazel-talkd-reference-objects-20261028; scripts: bazel-talkd-qualification-20261028.

Reviewed build-bsd.c: existing format-5 explicit targets and installation
collection support the component without new frontend or publication changes.
No daemon started, invitation sent, terminal written or host installation made.
Invitation lifetime/replay, hostname lookup, terminal permissions and delivery,
configuration/static/cross variants and resource behavior remain unqualified.
Full world/kernel/pkgbase/bootstrap/cache/performance gates remain open; Make
stays production/default and BIP stays out of scope.

## 2026-10-28 native mknetid with explicit NIS libc

Added mknetid's three unchanged sources and both maintained manuals. The target
is incompatible when nis=false, matching libexec/Makefile's MK_NIS exclusion.
The disabled configuration is verified to reject the explicit target during
analysis: /usr/obj/usr/src/bazel-mknetid-disabled-20261028/bazel.stderr.
Initial Make and Bazel links against the NIS-disabled SDK failed with missing
yp_get_default_domain; no stub or host-library fallback was introduced.

The enabled target declares libc:shared_link_interface and dynamic c_shared /
sys_shared dependencies, with -nodefaultlibs. The native graph builds the
NIS-enabled libc including its existing rpcgen actions. Through build-bsd at
16 jobs, bazel-mknetid-nis-20261028 completed successfully. All three component
object .text bodies and global/undefined symbols match independent Make
compilation. Linked comparison matches 53 symbols, libc/libsys dependencies,
empty RPATH, six installation records, both compressed manuals, and debug
name/CRC/DWARF; stripping preserves native .text.

Evidence: /usr/obj/usr/src/bazel-mknetid-nis-20261028/qualification/{parity.json,
object-parity.json}. Scripts: bazel-mknetid-qualification-20261028. Reference:
bazel-mknetid-nis-reference-20261028-r2; objects:
bazel-mknetid-reference-objects-20261028. The Make link explicitly uses the same
native NIS libc/libsys as Bazel; it is NOT independent libc qualification.
An initial reference command overrode LDFLAGS without retaining -pie; its
weak-symbol mismatch was investigated, corrected and the reference relinked.

Reviewed build-bsd.c: format-5 settings and explicit targets already support
this configuration; no frontend change required. No runtime NIS query or host
installation occurred. Independent NIS-enabled libc comparison, map-generation
runtime fixtures, service integration and full-system/cache/performance gates
remain open. Make remains production/default; BIP remains out of scope.

## 2026-10-28 mknetid explicit-file runtime qualification

Six runtime cases now pass both independent expected-output assertions and
byte-for-byte exit/stdout/stderr comparison with the Make-built component:
supplementary groups plus host/netid records, duplicate UID warning, quiet
suppression, absent optional netid file, malformed passwd record, and absent
required group file. Every database path and domain is supplied explicitly;
no host account database, NIS service, or system configuration is modified.

The frontend collected mknetid, native rtld, NIS-enabled libc and libsys as
explicit targets in /usr/obj/usr/src/bazel-mknetid-runtime-20261028. Runtime
checks copy the saved artifacts into an isolated qualification directory and
retain their hashes. LD_TRACE_LOADED_OBJECTS confirms the intended libc/libsys
paths. Both the native and Make executables use those same libraries, so the
comparison still does not independently qualify libc or the NIS service.

Evidence: bazel-mknetid-runtime-20261028/qualification/runtime-parity.json.
Retained script: bazel-mknetid-qualification-20261028/runtime.py. These six cases
are external qualification checks, NOT registered Bazel tests or ATF cases.
Native Bazel test registration remains to be implemented. Default-domain
lookup, broader malformed-input cases and live NIS integration remain open.
Existing build-bsd explicit-target collection suffices; no frontend or backend
change is required for this evidence-only qualification. Full-system gates
remain open and Make remains production/default.

## 2026-10-28 maintained mknetid ATF suite: runtime gate open

Added six shared ATF shell cases and Make test traversal, native Bazel test
registration, wrapper/Kyua generation and installation manifests. Fixtures
cover the six previously qualified explicit-file cases; installed tests use
/usr/libexec/mknetid, while build tests receive executable/loader/library paths
through declared ATF configuration. No production source behavior changed.

Make built the suite in bazel-mknetid-atf-reference-20261028. Bazel wrapper and
Kyua bytes match exactly: bazel-mknetid-test-install-20261028/qualification/
test-artifact-parity.json. This does not establish aggregate test packaging.

Both native test attempts FAILED before their bodies: bazel-mknetid-tests-
20261028 and -r2. ATF shell initialization calls dirname; that helper aborts
in cap_rights_intersect on cap_rights_is_valid(src). Source inspection identifies
caph_limit_stream's intersection with rights returned by cap_rights_get as the
path requiring investigation. The first attempt used native libc for all
helpers; r2 explicitly separates SDK harness libraries from native mknetid
libraries, but reproduces the assertion. Thus blaming only new libc selection
is not supported. Host/source rights compatibility remains undiagnosed.
No helper replacement, assertion suppression, skip or expected-success rewrite
was introduced. Six external qualification checks from the prior entry still
pass; ZERO registered ATF cases pass here. Test runtime remains an open gate.

Reviewed build-bsd.c: existing format-5 test/artifact collection supports this
suite and records failures; no frontend change needed. Next work: diagnose
rights returned to the helper and qualify a compatible runtime, then rerun
all six tests and complete installation aggregation/parity. Make remains
production/default; whole-system and performance qualification remain open.

## 2026-10-28 confirmed host Capsicum rights ABI mismatch

The mknetid ATF helper failure is now explained by a read-only runtime probe,
not just inferred from differing headers. The running kernel identifies as
Oct 7 f4db9ce01f15-dirty. A newly opened /dev/null descriptor returns rights
02000fffffffffff,040000006fffffff. Host headers/libc accept these (valid=1).
Current SDK headers and native libc expect CAP_ALL index 1
05fc000001ffffff; returned unknown bits are 000000006e000000 and valid=0.
Thus caph_limit_stream's intersection of inherited rights triggers libc's
validity assertion before dirname can execute the requested operation.

There is also semantic reassignment: host CAP_JAIL_ATTACH is
0400000000800000 whereas source uses 0500000000000000; the former position is
now CAP_PDDUPFD. Timerfd rights have likewise moved. Ignoring unknown bits or
suppressing assertions would not establish correct authority semantics.
No such compatibility workaround was added.

Evidence and probe source: /usr/obj/usr/src/bazel-cap-rights-host-20261028/
{probe.c,host-probe,sdk-probe,host.txt,native.txt}. The SDK probe runs with the
saved native loader/libc/libsys from bazel-mknetid-runtime-20261028. The probe
only opens /dev/null and reads its rights; no cap_rights_limit, installation,
upgrade or reboot occurred. This is independent of Bazel program generation.

Removed the unsuccessful r2 harness-runtime split and its extra library-path
configuration. The maintained suite again declares native runtime libraries
consistently; existing first-attempt evidence applies to this configuration.
The matching-kernel runtime gate is still OPEN. A VM with matching source
kernel/userland is the next qualification route; do not classify current-host
failures as passing or alter installed-host rights to accommodate testing.
Review of build-bsd.c finds no build-input or packaging change required by this
diagnosis. Full migration and runtime/performance gates remain incomplete.

## 2026-10-28 QEMU confirms matching capability-rights ABI

The maintained tools/test/daemon-runtime/run-vm.py runner booted the existing
Oct 24 GENERIC object kernel in a disposable networkless QEMU guest, with
2 GiB RAM, four vCPUs and a disk-backed 256 MiB UFS root (not a RAM disk).
The rebuilt maintained runtime_init helper enforced the fixture test protocol.
A static ATF probe compiled against the current staged SDK opened /dev/null
and read its rights without limiting them. The guest returned exactly
02000fffffffffff,05fc000001ffffff and current libc accepted them. The three
libservice cases and namespace delivery-hardening case also passed. QEMU exited
0 after guest poweroff, with no forced termination. No host upgrade occurred.

Evidence: /usr/obj/usr/src/bazel-rights-vm-20261028/run/{result.json,inputs.json,
serial.log,host-resources.jsonl}. Probe source, preparation script, private
fixtures, and helper build log are retained in the parent directory. Kernel
SHA256: 785a65a10d230a47a868d5619d1fa8765253e9593ad2e1abfc57e0334a033003.
The first preflight failed because installed QEMU could not locate libusb.so.4;
the successful run explicitly used a private copy from the current object tree
via LD_LIBRARY_PATH. No host library was installed or replaced.

The sampled QEMU-only RSS peak was 353779712 bytes and last observed CPU time
18.87 seconds across 16 samples; these exclude unsampled peaks and host page
cache. They are fixture observations, not disk-I/O measurements or a Bazel/Make
performance comparison. Loader emitted missing optional-module warnings from
inherited boot defaults; this is a mechanism fixture, not complete-system boot
qualification. The kernel is Make-built, not proof of a Bazel kernel build.

This proves an available guest kernel accepts current rights, resolving the
host-ABI prerequisite for further isolated execution. It does NOT run the six
mknetid ATF cases; staging and executing those unchanged Bazel tests is next.
Reviewed build-bsd.c: no build input or packaging policy changed here, and the
native bazel-test frontend remains unchanged. Full goal remains incomplete.

## 2026-10-28 all six mknetid ATF cases pass in matching-kernel guest

The current registered tests were rebuilt/captured through build-bsd at 16
jobs in bazel-mknetid-tests-20261028-r3. Their host executions still fail at
the known old-kernel rights mismatch; those failures are retained. Six actual
TestRunner test-setup actions were selected from execution.json, separately
from the six XML-generation actions that share the same mnemonic. The first
preparation attempt rejected that distinction instead of silently staging
extra actions; failed preparation work/logs remain retained.

Captured BSD_ATF environment settings and complete dereferenced runfiles were
staged with per-file SHA256 provenance: 367 paths, 33 unique payloads, with
identical payloads hardlinked. A small static ATF launcher forks/execs the
unchanged Bazel atf_runner with relocated TEST_SRCDIR/TEST_TMPDIR/XML paths and
checks its exit status. It does not reproduce the test assertions. Native rtld
is supplied at /libexec/ld-elf.so.1 for ordinary child execs; the suite's explicit
mknetid loader selection also remains unchanged. No host helpers, rights masks,
assertion suppressions, skips or rewritten expected results were substituted.

The maintained VM runner booted the previously qualified GENERIC kernel using
2 GiB RAM, four vCPUs and a disk-backed 512 MiB UFS root. All six original
shell test bodies reported passed: supplementary groups/host/netid records,
duplicate warning, quiet suppression, missing optional netid, malformed passwd,
and missing required group. Four baseline fixture cases also passed. The guest
powered off, QEMU exited 0, and no forced termination occurred.

Evidence under /usr/obj/usr/src/bazel-rights-vm-20261028:
- mknetid-run-r3/result.json, serial.log and host-resources.jsonl
- mknetid-payload.json: captured actions and copied file hashes
- stage-mknetid.py, mknetid_guest.c and fixtures/mknetid_guest: replay mechanics

This is guest replay of Bazel-built tests, NOT a Bazel scheduler running in the
VM, native-host success, a maintained frontend VM backend, or whole-system
qualification. Captured replay should become reusable tooling before broad
VM qualification. The sampled QEMU RSS maximum was 384843776 bytes; last CPU
sample was 21.44 seconds, across 18 samples. Neither proves disk-I/O or build
performance parity. Live NIS/default-domain lookup remains untested. Reviewed
build-bsd.c: no input/security/packaging policy changed; the existing frontend
recorded the host failures correctly. Make remains production/default.

## 2026-10-28 mknetid test installation archive qualified

Added //libexec/mknetid:test_install_archive using the existing shell-test
manifest and maintained archive/mtree rules. It retains separate package=tests
ownership and leaves the ordinary utilities installation archive separate.
Three records match independent rootless Make installation: directory
/usr/tests/libexec/mknetid (0755), mknetid_test (0555), and Kyuafile (0444).
Owner/group, uid/gid, flags, tags, archive membership, and both file payloads
match exactly. Shell tests have no ELF/debug counterpart to qualify.

Evidence: /usr/obj/usr/src/bazel-mknetid-test-archive-20261028/qualification/
test-install-parity.json. Reference: bazel-mknetid-test-reference-20261028-r2.
Retained scripts: bazel-mknetid-qualification-20261028/{make-test-reference.py,
verify-test-install.py}. build-bsd performed the native archive build at 16
jobs. Reviewed build-bsd.c and existing collection/backend rules: explicit
archive targets already work, so no frontend change is required.

This qualifies the component test archive, not configured-world test aggregation,
pkg creation/publication, or installed-system test discovery. Prior six-case
guest runtime evidence remains unchanged. General VM replay integration and
full-world/kernel/package/performance qualification remain outstanding; Make
remains production/default. No host files were installed.

Verification correction for the preceding entry: the first archive comparison
incorrectly expected tar membership to contain only component records; the tar
also contains four required ancestor directories. A second check exposed that
the original Make reference enabled tests only for the component, leaving
WITH_TESTS disabled during distrib-dirs. The r2 reference enables tests for both
steps. Verification now checks exact membership including ancestors, comparing
all four ancestor modes/owners against Make distribution metadata as well as
the three component records and two payloads. It passes and emits the cited
report. The initial documentation commit ran despite verification failure due
to missing shell fail-fast handling; subsequent commands fail immediately on
errors. No archive implementation or expected file contents changed to pass.

## 2026-10-28 three native rcmds RPC daemons

Added rpc.rwalld (one C source), rpc.rstatd (two C sources), and rpc.rusersd
(two C sources/local header), with explicit native util/devstat/rpcsvc library
edges as required by their maintained Makefiles. Added narrow public wrappers
for generated rwall.h, rstat.h and rnusers.h; all reuse existing native rpcgen
actions. No source behavior or historic wall-command path was altered.
Installation uses the maintained rcmds package, /usr/libexec, manuals and split
debug payloads. The dormant XIDLE conditional remains disabled as in Make.

At 16 jobs through build-bsd, all three build/install targets pass. Independent
Make comparison matches 44/59/42 global-and-undefined entries respectively,
expected NEEDED libraries and empty RPATH/RUNPATH, five installation records
per daemon, each manual's bytes, debug name/CRC/DWARF, and strip-preserved .text.
All five object .text bodies and symbol sets match Make. The three generated
protocol headers match the staged SDK byte-for-byte.

Evidence: /usr/obj/usr/src/bazel-rcmd-rpc-20261028/qualification/{rpc.rwalld,
rpc.rstatd,rpc.rusersd}/parity.json and object-header-parity.json. References:
bazel-rpc.rwalld-reference-20261028, bazel-rpc.rstatd-reference-20261028,
bazel-rpc.rusersd-reference-20261028; corresponding reference-objects trees.
Scripts: bazel-rcmd-rpc-qualification-20261028. No daemon was started, no terminal
message delivered, and no host installation or RPC registration performed.

Reviewed build-bsd.c and existing backend collection: format-5 explicit targets
support these builds/install archives without frontend changes. Inetd/standalone
startup, RPC requests, user/session disclosure, wall authorization/delivery,
statistics behavior, nondefault configurations and performance remain open.
Whole-world/kernel/pkgbase/publication/runtime qualification is incomplete;
Make remains production/default and BIP remains out of scope.

## 2026-10-28 native pppoed

Added the unchanged PPPoE daemon as a native cc_binary with explicit netgraph
CcInfo/shared-library dependencies and its ppp package installation archive.
At 16 jobs through build-bsd, the build and archive complete. Independent Make
comparison matches the single compiled object's .text and global/undefined
symbols, 57 linked symbol entries, libc/libnetgraph dependencies, empty RPATH,
five installation metadata records, compressed manual bytes, and debug
name/CRC/DWARF. Stripping preserves native executable .text.

Evidence: /usr/obj/usr/src/bazel-pppoed-20261028/qualification/{parity.json,
object-parity.json}. Reference: bazel-pppoed-reference-20261028 and corresponding
reference-objects tree. Scripts: bazel-pppoed-qualification-20261028. Existing
format-5 frontend target/installation collection supports this component;
reviewed build-bsd.c, with no frontend/backend change required.

No daemon was executed, interface changed, or module loaded. The maintained
program can load netgraph modules and execute a configured session command;
these paths, PPPoE discovery/negotiation, failure cleanup and authorization need
isolated guest qualification. Nondefault compile configurations, full world,
kernel, package publication, cache and performance gates remain open. Make
remains production/default and BIP remains out of scope.

## 2026-10-28 native mail.local and smrsh

Added native sendmail helper targets using unchanged contributed sources and
the existing libsm:sm_pie dependency, including its declared generated sm_os.h
and maintained header interfaces. Narrowly exported the two sources/manuals.
Installation preserves package=sendmail, /usr/libexec, manuals and split debug.
At 16 jobs through build-bsd both programs and archives build successfully.

Independent Make comparison matches 272 linked global/undefined entries for
mail.local and 209 for smrsh, libc-only dependencies, empty RPATH/RUNPATH,
five metadata records each, both manual payloads, debug name/CRC/DWARF and
strip-preserved .text. The two program object bodies (9237 and 2016 .text bytes)
and their symbol sets match Make exactly.
Evidence: /usr/obj/usr/src/bazel-sendmail-helpers-20261028/qualification/
{mail.local,smrsh}/parity.json and object-parity.json. References:
bazel-mail.local-reference-20261028 and bazel-smrsh-reference-20261028, with
corresponding reference-objects trees. Scripts are retained under
bazel-sendmail-helpers-qualification-20261028.

Reviewed build-bsd.c: explicit format-5 target/artifact support suffices for the
default component qualification. Make's arbitrary SENDMAIL_CFLAGS/DPADD/LDADD/
LDFLAGS customization is not represented here and remains an explicit migration
gap; this is not complete configuration parity. No mail delivery or restricted
command execution occurred. Mailbox locking/ownership, LMTP behavior, smrsh
command rejection/execution, and logging require isolated runtime qualification.
Inspection also found tftp-proxy's native libevent dependency still missing;
that prerequisite remains on the remaining-libexec list. Full-system, package,
cache and performance gates remain open; Make stays production/default.

## 2026-10-28 native private libevent1 prerequisite

Added native cc_library/component archives/shared library for the eight
maintained contrib/pf/libevent sources, explicit private headers, and public
event.h interface. Feature defines and VERSION=1.3b match lib/libevent1/Makefile.
The DSO retains the private SONAME libprivateevent1.so.1; no public libevent ABI
or ports-library substitution was introduced. This supplies the native build
dependency needed by PF proxy consumers, whose conversion remains pending.

Through build-bsd at 16 jobs, ordinary/PIC archives and the DSO build. All
16 ordinary/PIC object .text bodies and global/undefined symbol sets match
independent Make. The DSO matches 136 dynamic entries, libc-only NEEDED,
private SONAME and empty RPATH/RUNPATH. Evidence:
/usr/obj/usr/src/bazel-event1-20261028/qualification/parity.json. Make reference
and retained verifier: bazel-event1-reference-20261028/{objects,verify.py};
build command and output are retained there. Runtime source was unchanged.

Reviewed build-bsd.c: existing explicit-target qualification and artifact
collection handle these outputs; no frontend change required at this step.
Library installation/header/symlink/debug/pkg metadata, backend runtime tests,
consumer linking and incremental/cache qualification still need completion.
No event-loop runtime or PF/network operation was executed. Full world/kernel,
pkgbase/publication and performance gates remain open; Make stays default.

## 2026-10-28 native tftp-proxy consumer

Added the two unchanged contributed tftp-proxy/filter sources and local header,
with explicit native libevent1 and OpenBSD compatibility-header dependencies.
Forced compatibility inclusion and NOPRIV_USER="proxy" match maintained Make.
Narrow source/manual exports and compatibility visibility were added; no PF
policy, privilege-drop code or daemon behavior was changed. Installation keeps
package=pf, /usr/libexec, the manual and split debug payload.

At 16 jobs through build-bsd, both compiled object .text bodies/global+undefined
symbol sets match independent Make. Linked comparison matches 110 symbol
entries, libc plus libprivateevent1 dependencies, empty RPATH/RUNPATH, five
metadata records, manual bytes, debug name/CRC/DWARF, and strip-preserved .text.
Evidence: /usr/obj/usr/src/bazel-tftp-proxy-20261028/qualification/{parity.json,
object-parity.json}; reference: bazel-tftp-proxy-reference-20261028 and matching
reference-objects tree; scripts: bazel-tftp-proxy-qualification-20261028.

Reviewed build-bsd.c: existing format-5 targets and artifact collection support
this component; no frontend change required. No daemon started and no /dev/pf
access, rule changes or traffic were exercised. Rule lifetime, session cleanup,
privilege separation, transfer/error paths and event-loop backend behavior still
need guest qualification. The new libevent1 installation archive remains open,
as do configured-world integration, pkgbase/publication and performance gates.
Make remains production/default; BIP remains out of scope.

## 2026-10-28 private libevent1 installation qualified

Added native installation/debug rules and archive for libevent1. Paths follow
independent Make staging: event.h under /usr/include/private/event1, ordinary
libprivateevent1.a and DSO/link under /usr/lib, with split debug under
/usr/lib/debug/usr/lib. Tags preserve package=libevent1 and its dev/dbg splits.
No public include path or third-party libevent ABI is substituted.

Through build-bsd at 16 jobs, all seven component metadata records match Make,
including modes, owners, tags and symlink target. Header bytes match exactly.
The installed static archive equals the native archive and its member inventory
matches Make; prior 16 ordinary/PIC object comparisons establish code parity.
Debug name/CRC/DWARF checks pass, and stripping preserves native DSO .text.
Evidence: /usr/obj/usr/src/bazel-event1-install-20261028/qualification/
installation-parity.json. Make reference: bazel-event1-install-reference-20261028.
Retained install/verifier scripts: bazel-event1-reference-20261028/{install.py,
verify-install.py}. No host library was installed.

Reviewed build-bsd.c: existing format-5 archive collection supports these rules;
no frontend/backend changes required. This completes default component library
installation evidence, not configured-world/pkg publication or runtime coverage.
Event-loop backend behavior, consumer traffic, cache/incremental performance and
whole-world/kernel/publication gates remain open. Make remains production/default.

## 2026-10-28 native ftp-proxy

Added ftp-proxy's two unchanged contributed sources/local header, native
libevent1 dependency, explicit forced OpenBSD compatibility header, and the
maintained NOPRIV_USER="proxy" definition. Source exports and compatibility
visibility are limited to the new consumer. Installation follows Make's pf
package and /usr/sbin location, with manual and split debug metadata.

Through build-bsd at 16 jobs, both object .text bodies and global/undefined
symbol sets match independent Make. Linked comparison matches 133 entries,
libc/libprivateevent1 dependencies, empty RPATH/RUNPATH, five installation
records, manual bytes, debug name/CRC/DWARF, and strip-preserved .text.
Evidence: /usr/obj/usr/src/bazel-ftp-proxy-20261028/qualification/{parity.json,
object-parity.json}; reference: bazel-ftp-proxy-reference-20261028 and matching
reference-objects tree. Scripts: bazel-ftp-proxy-qualification-20261028.

Reviewed build-bsd.c: current explicit format-5 target and archive handling
supports this component without frontend changes. No daemon or host PF rule
operation ran. Active/passive FTP, address rewriting, malformed commands,
privilege changes, timeout/error cleanup, and concurrent session behavior still
need isolated runtime qualification. Configured-world selection, pkgbase
publication and full-system/performance gates remain open. Make stays default.

## 2026-10-28 complete BOOTP subtree native build candidates

Added bootpd, bootpgw, bootpef and bootptest as native targets with explicit
per-program source lists and a shared header interface. Only bootpd receives
ETC_ETHERS/SYSLOG/DEBUG/VEND_CMU, matching its Makefile; children retain their
own defaults. Sandbox compilation caught an undeclared bootptest.h in the
first run; the local header was added rather than widening filesystem access.

At 16 jobs through build-bsd, all four programs build. Independent recursive
Make comparison matches linked global/undefined entries: bootpd 128, bootpgw
77, bootpef 97, bootptest 85, with matching NEEDED and RPATH/RUNPATH properties.
All 31 compiled objects (11/5/10/5 respectively) match .text and symbol sets.
The inventory verifier initially included Make .depend.*.pieo text files;
it now identifies ELF objects explicitly and checks each program's complete
object count. No production source changed.

Evidence: /usr/obj/usr/src/bazel-bootp-20261028-r2/qualification/build-parity.json.
Reference, command log and verifier: bazel-bootp-reference-20261028/{objects,
command.txt,build.log,verify.py}. Initial failure: bazel-bootp-20261028.
Reviewed build-bsd.c: existing explicit targets support this build-only stage;
no frontend change required. Manuals, hardlinks, installation/debug metadata
and aggregate subtree installation still require migration and qualification.
No daemon/client network operation occurred. Complete-world/kernel/pkgbase,
runtime, cache and performance gates remain open; Make remains default.

## 2026-10-28 BOOTP subtree installation qualified

Added installation for all four native programs: bootpd/bootpgw in /usr/libexec
and bootpef/bootptest in /usr/sbin, matching recursive Make. The aggregate
archive includes four split debug pairs, bootptab(5), all section-8 manuals,
and the maintained bootpgw(8) hardlink to bootpd(8). Utilities ownership and
manual split configuration use existing installation rules.

Through build-bsd at 16 jobs, 16 unique component metadata records match
independent rootless Make staging. Repeated Make directory records are checked
for equality before deduplication. All five manual payloads match; tar hardlink
identity/target and Make inode identity are verified. All four debug pairs pass
name/CRC/DWARF checks; stripping preserves each native .text section.
Evidence: /usr/obj/usr/src/bazel-bootp-install-20261028/qualification/
installation-parity.json. Reference: bazel-bootp-install-reference-20261028.
Scripts: bazel-bootp-reference-20261028/{install.py,verify-install.py}.

Reviewed build-bsd.c: current format-5 target/archive collection supports this
subtree without frontend changes. No host installation or network execution
occurred. Split-manual variant, runtime behavior, configured-world/pkgbase
aggregation, full-system publication and performance gates remain open. Make
remains production/default; this is component installation evidence only.

## 2026-10-28 libexec maintenance scripts

Added native install archives for save-entropy and makewhatis.local. Their
maintained shell source bytes are installed directly under the extensionless
/usr/libexec names, with 0555 script and 0444 compressed manual permissions.
Make's package-specific /usr/libexec directory record is preserved separately
for utilities and mandoc. The first archive build omitted those directory
ownership records; the r2 graph adds them based on independent Make staging.

At 16 jobs through build-bsd, both archives pass exact script/manual byte and
three-record metadata comparison (six component records total). Evidence:
/usr/obj/usr/src/bazel-libexec-scripts-20261028-r2/qualification/
installation-parity.json. References: bazel-save-entropy-reference-20261028 and
bazel-makewhatis.local-reference-20261028. Scripts:
bazel-libexec-scripts-qualification-20261028. No ELF/debug transformation is
applicable to these shell scripts; no replacement scripts were generated.

Reviewed build-bsd.c: existing format-5 archive support suffices, with no
frontend changes required. Neither script executed: no host entropy files,
random-device reads, or manual databases were changed. Runtime permissions,
rotation/error cases, manual database traversal and split-manual configurations
remain unqualified. World/pkgbase/publication/runtime/cache/performance gates
remain open; Make stays production/default.

## 2026-10-28 blocklist helper installation

Added native archive installation for both the contributed blocklistd-helper
and maintained blacklistd-helper compatibility script. These remain separate
source payloads, not an invented alias. Both install at /usr/libexec with
0555 permissions and package=blocklist; the package-owned directory record is
preserved. The contributed source export is limited to this consumer.

Through build-bsd at 16 jobs, all three component metadata records and both
script payloads match independent rootless Make exactly. Evidence:
/usr/obj/usr/src/bazel-blocklist-helper-20261028/qualification/
installation-parity.json. Reference: bazel-blocklistd-helper-reference-20261028.
Scripts: bazel-blocklist-helper-qualification-20261028. Reviewed build-bsd.c:
existing explicit archive collection supports this installation without frontend
changes. No script ran and no host firewall operation or installation occurred.

The scripts retain existing firewall selection and legacy-IPFW rejection
behavior. PF table/rule lifetime, failed commands, address/protocol handling,
compatibility entry behavior and other backend branches still need isolated
runtime tests. Configured-world/package/publication/cache/performance gates
remain incomplete; Make remains production/default.

## 2026-10-28 native pkg-serve build/install

Added unchanged pkg-serve as a native cc_binary and utilities installation
archive under /usr/libexec. Through build-bsd at 16 jobs, its object .text and
global/undefined symbols match independent Make. Linked comparison matches 36
symbol entries, libc-only dependency, empty RPATH/RUNPATH, five installation
records, compressed manual bytes, debug name/CRC/DWARF and strip-preserved .text.
Evidence: /usr/obj/usr/src/bazel-pkg-serve-20261028/qualification/{parity.json,
object-parity.json}; reference: bazel-pkg-serve-reference-20261028 and matching
reference-objects tree; scripts: bazel-pkg-serve-qualification-20261028.

Reviewed the existing 14-case ATF shell suite: greeting, unknown command,
missing file, ordinary/leading-slash/up-to-date/subdirectory retrieval,
directory request, missing/bad age, empty argument, path traversal, multiple
gets and invalid base directory. Native test registration/execution and test
installation remain next; none was run as part of this build comparison.
It already permits explicit PKG_SERVE executable selection. Preserve its
assertions when integrating with the compatible guest runtime.

Reviewed build-bsd.c: current explicit targets and archive collection suffice;
no frontend change needed. No repository data was served, installed or changed.
This helper conversion does not establish SSH transport, signed repository
publication, source authentication or update acceptance. Full-system/runtime,
configured packaging, cache and performance gates remain open; Make stays
production/default.

## 2026-10-28 pkg-serve's 14 maintained ATF cases pass in guest

Registered all 14 existing pkg_serve_test cases with declared native shell,
ATF, utility, libc/libsys and loader inputs. The only shell-suite changes add
an ATF pkg_serve configuration lookup at its two execution sites, retaining the
PKG_SERVE environment/default fallback and all existing assertions. Added script/
Kyua metadata and a standalone test installation archive; exact Make installation
comparison for that new archive remains pending.

build-bsd at 16 jobs captured the tests in bazel-pkg-serve-tests-20261028. Host
execution still aborts in the shell helper's cap_rights_intersect assertion,
consistent with the independently diagnosed old-kernel rights allocation. This
host run remains FAILED; no assertions, privileges or containment were bypassed.

Replayed all 14 captured test-setup environments/runfiles through the maintained
networkless QEMU fixture runner and its matching GENERIC kernel. The static ATF
launcher only executes each unchanged Bazel runner and checks exit status.
Relocated runfile/tmp/XML paths are explicit; payload provenance covers 883 paths
and 42 unique file payloads. The guest uses native rtld for child execution.
All 14 bodies reported passed, as did four baseline fixture cases. QEMU exited
0 after guest poweroff, without forced termination, using 2 GiB RAM/four vCPUs
and a disk-backed 512 MiB UFS fixture.

Evidence: /usr/obj/usr/src/bazel-rights-vm-20261028/pkg-serve-run/{result.json,
serial.log,host-resources.jsonl}; payload manifest pkg-serve-payload.json and
stage-pkg-serve.py/pkg_serve_guest.c in the parent. This is guest replay of
Bazel-built tests, not an in-guest Bazel scheduler or passing native-host run.
The inherited assertions are exercised as written, not a comprehensive security
proof. SSH transport, repository authentication, full update acceptance and
additional adversarial cases remain unqualified. Reviewed build-bsd.c: existing
format-5 test handling records host failures correctly; maintained generic VM
backend integration is still open. Make remains production/default.

## 2026-10-28 pkg-serve test archive parity

The existing //libexec/pkg-serve:test_install_archive now has independent
Make installation qualification. Three component records match (test directory,
pkg_serve_test executable script, Kyua index), including owners, modes and
package=tests tags. Both payloads match byte-for-byte. Exact tar membership
includes four ancestor directories, whose ownership/modes match Make's
test-enabled distribution staging. No graph correction was needed.

Evidence: /usr/obj/usr/src/bazel-pkg-serve-test-archive-20261028/qualification/
test-install-parity.json. Reference: bazel-pkg-serve-test-reference-20261028-r2;
objects: bazel-pkg-serve-atf-reference-20261028/objects. Retained scripts:
bazel-pkg-serve-qualification-20261028/{make-test-reference.py,
verify-test-install.py}. Archive collection ran through build-bsd at 16 jobs.
Reviewed build-bsd.c: current explicit targets suffice; no frontend change.

Combined with the preceding 14-case guest result, this qualifies component test
payload installation and bounded execution. It does not establish configured-
world test discovery, package publication, host ABI compatibility, or a generic
VM test backend. No host installation or additional runtime execution occurred.
Whole-system/kernel/pkgbase/cache/performance gates remain open; Make stays
production/default.


## 2026-10-28: nuageinit installation candidate

Added native Bazel installation declarations for nuageinit, nuage.lua and the
compressed section-7 manual. Rootless Make installation and the Bazel archive
match all five component records (including package-owned /usr/libexec and
/usr/share/flua), all three payloads byte-for-byte, ownership, modes and package
tags. Exact archive membership and ancestor directory metadata are also checked.
The first archive omitted the package-owned Lua directory; the reference exposed
that omission and the corrected r2 archive passed. Both runs are retained.

Evidence: /usr/obj/usr/src/bazel-nuageinit-20261028-r2/qualification/
installation-parity.json. Make reference: bazel-nuageinit-reference-20261028.
Retained scripts: bazel-nuageinit-qualification-20261028/{make.py,verify.py}.
Qualification used build-bsd explicit inputs with 16 jobs. Reviewed build-bsd.c:
existing target collection supports these outputs; no frontend change required.

This establishes installation parity only. flua and its modules still need native
Bazel integration, and nuageinit's existing ATF suites and isolated configuration
runtime checks remain open. The script's interpreter/modules are runtime package
dependencies, not bundled substitutes. Split-manpage configuration, complete
pkgbase construction, world/kernel, cache and performance gates remain open.
Make remains production/default. No host configuration was changed.


## 2026-10-28: internal liblua ordinary and PIE archives

Added explicit native cc_library source declarations for all 32 liblua C files,
ordinary and PIE consumer variants, and component archives. Header dependencies
use contrib/lua/src/luaconf.h and its maintained lib/liblua/luaconf.local.h;
the older lib/liblua/luaconf.h is not substituted. The math dependency is native
CcInfo. Make's INTERNALLIB contract is preserved: no installation manifest or
installed liblua DSO is invented.

All 64 ordinary/PIE objects match the isolated Make reference in .text bytes
and global symbols. Make archive member inventories drive the comparison and
native object counts must match. Rootless Make install produces zero component
records, as expected. Evidence: /usr/obj/usr/src/bazel-lua-20261028-r2/
qualification/parity.json; reference objects under
bazel-lua-reference-objects-20261028/usr/src/lib/liblua. Retained scripts:
bazel-lua-qualification-20261028/{make.py,verify.py}. Both Bazel builds used the
maintained build-bsd frontend with 16 jobs. Reviewed build-bsd.c explicit input
handling: these targets require no frontend or publication behavior change.

Only the amd64 target-library configuration is qualified here. Bootstrap Lua's
BOOTSTRAPPING definitions and search paths, flua and its loadable modules,
interpreter runtime tests, dependency invalidation/cache behavior and performance
remain open. No host installation occurred. Whole-world/kernel/pkgbase gates
remain open and Make stays production/default.


## 2026-10-28: flua interpreter build/install and bounded runtime

Added native flua cc_binary and installation targets with explicit liblua PIE,
libedit, math and readline header dependencies. Make's custom linit_flua and
built-in lposix are compiled unchanged. Exported executable symbols (-Wl,-E)
are preserved for future loadable modules. The contributed interpreter is
exported narrowly to this package. No Make invocation or prebuilt interpreter
is used by the native target.

Three object bodies/global symbols, 281 executable global/undefined symbols,
NEEDED libraries (c/edit/m), empty RPATH/RUNPATH, five installation records and
the compressed manual match Make. Debug CRC/DWARF and stripped executable text
checks pass. The first archive omitted Make's implicit flua.1 manual; the
corrected r2 includes it. Both runs are retained.

Five bounded cases (language/table/UTF-8, math, coroutine, built-in POSIX helpers,
error propagation) pass with matching output/status for Bazel and Make binaries
using copied native rtld, libc/libsys, libedit, libm and libtinfo. The first
runtime harness used an unsupported --library-path loader option and failed
before executing Lua; corrected runtime-r2 uses LD_LIBRARY_PATH. That initial
failure remains recorded. These are external qualification cases, not yet
Bazel-owned tests, and do not qualify loadable modules, REPL/readline interaction,
bootstrap Lua or nuageinit behavior.

Evidence: /usr/obj/usr/src/bazel-flua-20261028-r2/qualification/{flua/parity.json,
object-parity.json,runtime-r2/results.json}. Scripts:
bazel-flua-qualification-20261028/{make.py,verify.py,objects.py,runtime.py}.
Reference: bazel-flua-reference-20261028, with NO_SUBDIR explicitly selecting
the interpreter; its modules remain pending, not silently included in this
claim. Builds used build-bsd with 16 jobs. Reviewed build-bsd.c: existing
explicit target collection suffices; no frontend change needed. No host
installation/configuration changes. Full world/kernel/pkgbase/cache/performance
qualification remains open; Make remains production/default.


## 2026-10-28: flua lfs/fbsd loadable modules

Added native targets for lfs.so and fbsd.so, using explicit Lua/bootstrap headers
and leaving Lua API references for the interpreter to resolve. Neither module
embeds another Lua runtime. A flua-specific installation helper splits debug
files and installs the existing /usr/lib/flua layout with package=flua metadata.
The helper currently covers modules without manuals or additional Lua payloads;
other module types still need their declared additional installation inputs.

Both PIC objects match Make's .text and global symbols. The DSOs match 42/39
symbols respectively, libc-only NEEDED, SONAME and empty RPATH/RUNPATH. Five
installation records per module match Make in owners/modes/package tags, and
both debug pairs validate with stripped .text unchanged. Three external runtime
cases pass for native and Make builds using the previously qualified flua and
native loader/libraries: load/create/stat/enumerate/remove temporary files,
missing-file errors, and fbsd loading/argument rejection. Subprocess execution,
pipes and lifecycle behavior remain unqualified; passing argument rejection is
not a process-execution test. All mutations stayed in private qualification dirs.

Evidence: /usr/obj/usr/src/bazel-flua-modules-20261028-r2/qualification/
{parity.json,runtime/results.json}. Scripts:
bazel-flua-modules-qualification-20261028/{make-lfs.py,make-lfbsd.py,verify.py,
runtime.py}. Make references: bazel-flua-{lfs,lfbsd}-reference-20261028.
Native builds ran through build-bsd at 16 jobs. Reviewed frontend explicit input
handling; current collection supports these targets without frontend changes.
Remaining flua modules, Bazel-owned runtime tests, bootstrap variants, nuageinit,
full world/kernel/pkgbase/cache/performance gates remain open. Make stays default.


## 2026-10-28: flua hash module

Added native hash.so with declared libmd CcInfo/shared dependency and unchanged
Lua API resolution from flua. Extended the flua module installation helper with
explicit extra_entries; the hash target declares its compressed hash.3lua manual.
The Make reference exposed the initial manual path/tag mismatch: corrected to
/usr/share/man/man3lua and package=flua-dev (non-split-man configuration).
The initial build and corrected r2 remain under /usr/obj.

Qualification matches the PIC object .text/global symbols, 24 DSO symbols,
libc/libmd dependencies, SONAME and empty RPATH/RUNPATH, six installation records
and compressed manual bytes. Debug validation and unchanged stripped text pass.
Four external runtime vectors (empty, abc, embedded NUL, 10000-byte string)
pass one-shot, bytewise incremental and binary-digest checks against Python
hashlib results for both native and Make modules, using native libmd and the
previously qualified flua/loader/libraries. The verifier initially named the
wrong reference directory; corrected before any successful qualification claim.

Evidence: /usr/obj/usr/src/bazel-flua-hash-20261028-r2/qualification/
{parity.json,runtime/results.json}. Scripts: bazel-flua-hash-qualification-20261028/
{make.py,verify.py,runtime.py}. Reference: bazel-flua-hash-reference-20261028.
Builds used maintained build-bsd with 16 jobs. Reviewed build-bsd.c: existing
explicit inputs/artifact collection cover this target without frontend changes.
Other modules, Bazel-owned runtime tests, bootstrap and split-man variants,
full world/kernel/pkgbase/cache/performance qualification remain open. No host
installation or configuration change. Make remains production/default.


## 2026-10-28: flua jail module build/install qualification

Added native jail.so with declared Lua/bootstrap headers and native libjail
CcInfo/shared dependency. The unchanged lua_jail.c resolves its Lua API from
the interpreter. Installation includes jail.3lua in man3lua, package=flua-dev
for the tested non-split-man configuration, and normal split-debug artifacts.

The PIC object .text and symbols, 54 DSO global/undefined symbols, libc/libjail
NEEDED, SONAME and empty RPATH/RUNPATH match Make. All six installation records
and compressed manual bytes match; debug pair and stripped-text checks pass.
Seven argument-validation cases pass for both native and Make modules using
native libjail and the previously qualified flua/loader/libraries. These prove
module loading and rejection of invalid argument types only. No jail creation,
attachment, removal, listing or parameter syscall behavior is qualified here.
Those operations require further isolated VM coverage; no host jail was changed.

Evidence: /usr/obj/usr/src/bazel-flua-jail-20261028/qualification/
{parity.json,runtime/results.json}. Scripts: bazel-flua-jail-qualification-20261028/
{make.py,verify.py,runtime.py}; reference: bazel-flua-jail-reference-20261028.
Builds used maintained build-bsd with 16 jobs. Reviewed frontend explicit input
handling: existing artifact collection suffices with no frontend change. Other
modules, Bazel-owned runtime tests, bootstrap/configuration variants and complete
world/kernel/pkgbase/cache/performance gates remain open. Make stays default.


## 2026-10-28: flua UCL module

Added native ucl.so with the original contributed lua_ucl.c, explicit Lua and
bootstrap headers, and native libucl CcInfo/shared dependency. Internal UCL and
uthash headers are narrowly visible to this binding; no implicit source-tree
include fallback or embedded second Lua runtime was introduced.

The PIC object .text/global symbols, 86 DSO symbols, libc/privateucl dependencies,
SONAME and empty RPATH/RUNPATH match Make. Five installation metadata records,
split-debug validation and unchanged stripped text pass. Three external runtime
cases pass with matching output for native/Make modules: typed UCL configuration,
nested JSON parse/serialization roundtrip, and malformed-input rejection. Runs
use copied native libprivateucl and the previously qualified flua/loader/libraries.
File includes, schema validation and the broader binding API remain unqualified.

Evidence: /usr/obj/usr/src/bazel-flua-ucl-20261028/qualification/
{parity.json,runtime/results.json}. Scripts: bazel-flua-ucl-qualification-20261028/
{make.py,verify.py,runtime.py}. Reference: bazel-flua-ucl-reference-20261028.
Builds used maintained build-bsd at 16 jobs. Reviewed frontend explicit input
handling: current targets/artifact collection need no frontend change. Remaining
flua modules, Bazel-owned tests, bootstrap and complete world/kernel/pkgbase/
cache/performance gates remain open. No host installation/configuration changes;
Make remains production/default.


## 2026-10-28: native private libyaml dependency

Flua's YAML module had no native libyaml dependency available. Added all eight
maintained libyaml source files with declared public/private headers and the
Make version definitions (0.2.5). Targets provide ordinary/PIC archives, native
CcInfo and libprivateyaml.so.1. Installation preserves private yaml.h, the static
archive, DSO/symlink, split debug file and package=libyaml metadata.

All 16 ordinary/PIC object .text/global-symbol comparisons pass against isolated
Make. The DSO matches 79 dynamic symbols, libc-only NEEDED, SONAME and empty
RPATH/RUNPATH. All seven installation records, header bytes, archive member
inventory, symlink and debug checks pass; installed static archive equals the
native archive and stripping preserves executable text.

Evidence: /usr/obj/usr/src/bazel-yaml-20261028/qualification/{parity.json,
installation-parity.json}. Reference: bazel-yaml-install-reference-20261028;
objects/scripts: bazel-yaml-reference-20261028/{objects,install.py,verify.py,
verify-install.py}. Builds ran through maintained build-bsd with 16 jobs.
Reviewed build-bsd.c: existing explicit targets and collection cover the new
outputs without frontend changes. This is build/install qualification only;
parser runtime, flua YAML module and its Lua payloads remain pending. Full world,
kernel/pkgbase/cache/performance gates remain open. Make remains default, with
no host installation or configuration changes.


## 2026-10-28: flua YAML binding and Lua payloads

Added all four lyaml C sources with explicit headers, native libyaml dependency
and the maintained VERSION=6.2.8 definition. Installation includes yaml.so,
split debug, and explicit/functional/implicit/init.lua in /usr/share/flua/lyaml.
Initial archive creation correctly rejected missing directory policy; added the
package-owned directory with Make's ownership/mode/tags. Failed run retained.

All four PIC object .text/global-symbol comparisons, 78 DSO symbols, dependencies,
SONAME and empty RPATH/RUNPATH match Make. Ten installation metadata records and
all four Lua payloads match; debug/stripped-text checks pass. Four external runtime
cases pass for native/Make builds: typed mapping, dump/load roundtrip, YAML alias,
and malformed-input rejection. Native runs use Lua payloads extracted from the
qualified archive, copied native libprivateyaml, and previously qualified flua/
loader/libraries. The initial runtime harness had incorrectly escaped Lua string
newlines; fixed runtime-r2 passes and initial failure remains recorded.

Evidence: /usr/obj/usr/src/bazel-flua-lyaml-20261028-r2/qualification/
{parity.json,runtime-r2/results.json}. Scripts:
bazel-flua-lyaml-qualification-20261028/{make.py,verify.py,runtime.py}.
Reference: bazel-flua-lyaml-reference-20261028. Builds used build-bsd at 16 jobs.
Reviewed frontend explicit input handling: existing artifact collection needs no
frontend change. This is bounded module qualification, not exhaustive YAML parser
coverage, resource-limit testing or nuageinit runtime. Remaining FreeBSD modules,
Bazel-owned tests, bootstrap and complete world/kernel/pkgbase/cache/performance
gates remain open. No host installation. Make remains production/default.


## 2026-10-28: flua FreeBSD kernel-environment/linker modules

Added native freebsd.kenv and freebsd.sys.linker modules with unchanged sources,
explicit Lua/bootstrap headers, nested installed module/debug paths and their
section-3lua manuals. Both PIC object .text/global-symbol comparisons pass.
DSOs match 22/18 symbols respectively, libc-only dependencies, SONAME and empty
RPATH/RUNPATH. Seven/eight installation metadata records and both compressed
manual payloads match Make; debug validation and stripped-text preservation pass.

Evidence: /usr/obj/usr/src/bazel-flua-freebsd-20261028/qualification/parity.json.
References: bazel-flua-{kenv,linker}-reference-20261028. Retained scripts:
bazel-flua-freebsd-qualification-20261028/{make-kenv.py,make-linker.py,verify.py}.
Builds used maintained build-bsd at 16 jobs. Reviewed frontend explicit target
handling; no frontend change needed. No runtime syscall qualification is claimed:
kernel environment changes and module load/unload need isolated VM testing.

All modules in the current non-bootstrap flua Make list now have native build
and component installation targets (lfbsd, lfs, libhash, libjail, libucl,
liblyaml, and libfreebsd's kenv/sys.linker). This is component coverage, not a
qualified combined installation or full flua runtime suite. Next consolidate
installation and Bazel-owned runtime tests, then bootstrap/configuration coverage.
Nuageinit and whole-world/kernel/pkgbase/cache/performance gates remain open.
Make remains default; no host installation or kernel state changes occurred.


## 2026-10-28: combined non-bootstrap flua installation

Added //libexec/flua:complete_install_archive composing interpreter and all eight
loadable-module component manifests. Module manifests are exposed narrowly to the
flua parent package. Explicit directory ownership covers shared debug ancestors
and lyaml's Lua directory. Component install_archive targets remain available
for isolated parity checks; the complete target supplies the combined payload.

Strict comparison against the union of nine isolated Make component references
matches 34 unique records and 27 file payloads. Duplicate Make directory records
must agree. Payloads equal the previously qualified component archives byte for
byte; exact tar membership and all ancestor ownership/modes are checked.
A bounded integration run uses the interpreter and every module extracted from
the combined archive, native dependent libraries and previously qualified native
loader/libc: all nine imports (including lyaml's Lua wrapper) succeed, as does a
YAML-to-UCL serialization/parsing interchange. No privileged operations run.

Evidence: /usr/obj/usr/src/bazel-flua-complete-20261028/qualification/
{combined-parity.json,runtime/results.json}. Scripts:
bazel-flua-complete-qualification-20261028/{verify.py,runtime.py}. Build used
maintained build-bsd at 16 jobs. Reviewed build-bsd.c: existing explicit inputs
collect this target without frontend changes. This is component-union parity,
not an independent recursive Make build, pkg publication, or a self-contained
system image; dependent DSOs/loader remain separately provided native artifacts.
Bazel-owned tests, privileged VM checks, bootstrap/configuration variants and
whole world/kernel/pkgbase/cache/performance gates remain open. Make stays default.


## 2026-10-28: Bazel-owned flua runtime tests

Added four native cc_test targets in libexec/flua/tests: modules, hash, formats,
and filesystem. A static test-only C launcher resolves declared runfiles, selects
the native rtld/interpreter and explicit native library paths, clears inherited
environment, and executes Lua assertions in TEST_TMPDIR. It propagates flua's
exit status directly. Lua preloads exactly the declared native modules/support
files and empties package.path/cpath, preventing host Lua module search fallback.
Tests exercise all module imports, SHA-256 one-shot/incremental known answer,
YAML/UCL interchange and malformed YAML, and temporary filesystem operations.
Privileged jail/kenv/linker operations are not called.

All four tests actually executed and passed under Bazel through maintained
build-bsd at 16 jobs. Evidence: /usr/obj/usr/src/bazel-flua-tests-20261028-r3/
{bazel.stdout,test-inventory.json,test-reports/manifest.json,execution.json}.
The first two frontend invocations were rejected before build because qualification
inputs omitted build targets and then omitted tests from targets; corrected r3
selects the complete archive plus all tests as targets and the four tests as tests.
Rejected logs remain retained. Reviewed frontend input validation: no code change
needed; these tests use the existing supported explicit-target workflow.

This replaces reliance on external-only flua smoke checks with maintained native
Bazel tests for the stated cases. It does not cover all binding methods, hostile
input limits, subprocess lifecycle, privileged VM operations, bootstrap variants,
installed Kyua integration, cache invalidation or performance. Full world/kernel/
pkgbase qualification remains open and Make stays production/default. No host
installation or configuration change occurred.


## 2026-10-28: flua local cache and test-input invalidation

Repeated the same combined archive/four-test qualification with unchanged inputs.
All four BEP test results report cachedLocally=true and the execution log is empty.
Then added the binary SHA-256 digest assertion to the maintained Lua hash test.
All four tests sharing runtime.lua actually reran and passed; BEP reports no cached
results. Execution log contains only eight TestRunner actions (four test setup
executions and their result generation), with no compiler/linker/archive actions.
Every collected artifact hash matches the original run and the unchanged repeat.

Evidence: /usr/obj/usr/src/bazel-flua-cache-qualification-20261028/
{verify.py,results.json}; runs bazel-flua-tests-cache-20261028 and
bazel-flua-tests-invalidation-20261028 retain events/execution/artifact manifests.
Both used maintained build-bsd at 16 jobs. Reviewed frontend input handling: no
change required. This establishes local cache reuse and declared Lua test-input
invalidation only. Native source/header invalidation, remote/cache portability,
bootstrap variants and full world/kernel/pkgbase/performance gates remain open.
No benchmark or system-wide caching claim follows from these bounded checks.


## 2026-10-28: complete nuageinit test installation payload

Added native installation targets for all three maintained ATF shell scripts,
all fourteen Lua fixtures, sorted Kyua index, and the crypt helper built from
usr.sbin/pw/tests/crypt.c with native libcrypt. Source export is narrow to this
test package. Test assertions remain unchanged; no test cases were omitted.

Make comparison matches all 25 metadata records and all 18 nonbinary payloads
byte-for-byte. The crypt helper matches its Make object .text/global symbols,
11 executable symbols and libc/libcrypt dependencies with empty RPATH/RUNPATH.
Debug validation and unchanged stripped text pass. Initial archive build rejected
missing test/debug directories; added standard BSD.tests.dist and Make's debug
metadata. The next comparison caught unsorted Kyua entries; corrected to Make's
sorted order. Both unsuccessful runs are retained before passing r3.

Evidence: /usr/obj/usr/src/bazel-nuageinit-tests-20261028-r3/qualification/
{crypt/parity.json,object-parity.json}. Reference:
bazel-nuageinit-test-reference-20261028-r2. Scripts:
bazel-nuageinit-tests-qualification-20261028/{make.py,verify.py,objects.py}.
Builds used maintained build-bsd at 16 jobs. Reviewed build-bsd.c: existing explicit
target collection suffices; no frontend change. This is test payload/build
qualification only. ATF execution, configurable native runtime paths, root-only
pw/pwd_mkdb operations and isolated nuageinit configuration scenarios remain open.
Whole world/kernel/pkgbase/cache/performance gates remain open; Make stays default.
No host installation or user/configuration changes occurred.


## 2026-10-28: native nuageinit Lua fixture execution

Added Bazel-owned tests executing five existing, unchanged self-checking Lua
fixtures: dirname, addfile, decode_base64, sethostname, update_sshd_config.
The shared static flua test launcher accepts an explicit --temp-env=NAME input
mapping a fixture-root variable to TEST_TMPDIR. Nuageinit tests request the
existing NUAGE_FAKE_ROOTDIR interface; the Lua adapter requires an absolute,
non-root value before loading any fixture. Declared native flua/rtld/libraries,
lfs and nuage.lua are used; package.path/cpath are empty after exact preloading.
No mock implementation or replacement fixture assertions were introduced.

All five fixture tests and all four flua regression tests actually executed and
passed through build-bsd at 16 jobs. File/hostname/SSH configuration mutations
were redirected into the test temporary root. These cases need no pw, sysctl,
pwd_mkdb or timezone helper subprocesses. Evidence:
/usr/obj/usr/src/bazel-nuageinit-runtime-20261028/{bazel.stdout,
test-inventory.json,test-reports/manifest.json,execution.json}.
Reviewed build-bsd.c: existing explicit build/test selection handles these tests;
no frontend change required. This verifies the Lua fixtures only, not the ATF
shell wrappers' additional stdout/stderr checks, installed test paths, live SSH,
user creation or full nuageinit startup. Remaining fixture/shell scenarios need
native helper integration and isolated VM coverage. Bootstrap and complete world/
kernel/pkgbase/cache/performance gates remain open; Make remains default.


## 2026-10-28: native pw build and installation

Added native pw target with all fifteen maintained C sources, explicit local
headers, native libcrypt/libutil dependencies, both manuals and split-debug
installation in package=runtime. This supplies a missing build dependency for
nuageinit's user/group management tests without substituting the host pw binary.

All fifteen object .text/global-symbol comparisons pass against isolated Make.
The executable matches 220 global/undefined symbols, libc/crypt/util NEEDED and
empty RPATH/RUNPATH. All six installation metadata records and both compressed
manual payloads match. Debug validation and stripped-text preservation pass.

Evidence: /usr/obj/usr/src/bazel-pw-20261028/qualification/{pw/parity.json,
object-parity.json}; reference: bazel-pw-reference-20261028; scripts:
bazel-pw-qualification-20261028/{make.py,verify.py,objects.py}. Builds used maintained
build-bsd at 16 jobs. Reviewed build-bsd.c: existing explicit inputs/artifact
collection support this target, no frontend change required. This establishes
build/install parity only. User/group mutations, password database updates,
rollback/locking/failure behavior and existing pw ATF suites remain unqualified.
No host accounts/configuration were changed. Whole-world/kernel/pkgbase/cache/
performance gates remain open and Make remains production/default.


## 2026-10-28: pw native ATF unit suite

Confirmed pwd_mkdb already has a native build/install target; did not duplicate
it. Added native pw_unit_test using the existing test C source plus pw_utils.c
and strtounum.c, declared pw headers, native libutil and ATF-C. All seven existing
ATF cases are exposed individually through the maintained program adapter with
explicit native rtld/libc/libsys/libutil/ATF runtime inputs. Existing assertions
and the upstream test's read_userconfig stub are unchanged; no new production
stub or substitute implementation was introduced.

All seven cases actually executed and passed: dash, zero, valid descriptor,
INT_MAX, invalid text, negative value and overflow. Failure cases retain their
fork/exit-status and exact diagnostic checks. Evidence:
/usr/obj/usr/src/bazel-pw-unit-20261028/{bazel.stdout,test-inventory.json,
test-reports/manifest.json,execution.json}. Qualification ran via build-bsd at
16 jobs. An accidental nonexistent command after writing the target returned
127 before qualification; the subsequent maintained frontend invocation above
completed successfully. Reviewed build-bsd.c: existing explicit targets/tests
handle these cases, no frontend change needed.

This is existing unit-suite coverage only, not user/group database mutation,
locking, user homes, installed test metadata or the thirteen root-required shell
suites. Those and nuageinit user-management scenarios still need isolated runtime
qualification. No host accounts changed. Full world/kernel/pkgbase/cache/
performance gates remain open and Make stays production/default.


## 2026-10-28: pwd_mkdb native runtime and child generator selection

Existing pwd_mkdb ATF targets still selected SDK libc/libsys. Switched runtime
inputs to native libc/libsys and declared native rtld for the test program.
Added optional pwd_mkdb_loader ATF configuration for generator subprocesses;
all existing argument vectors and assertions are preserved. Without that option
the installed suite still executes its configured/default pwd_mkdb directly.
No generator implementation or database comparison was replaced.

All six cases actually executed and passed with native test/generator/runtime:
alternate UID update, duplicate UID, malformed update preserving databases,
in-place input metadata, symlinked directory updates, and explicit shell policy.
Database comparisons use real pwd.db/spwd.db records, not only flat-file output.
Mutations stay in test temporary directories; host account databases are only
read by pre-existing fixture preconditions, never rewritten.

Evidence: /usr/obj/usr/src/bazel-pwd-mkdb-native-20261028/{bazel.stdout,
test-inventory.json,test-reports/manifest.json,execution.json}. Maintained
build-bsd ran at 16 jobs. Reviewed frontend explicit input handling: existing
selection/collection supports these tests; no frontend changes required. This
qualifies these six scenarios, not all account-management or locking behavior,
installed default-loader execution, root-only pw/nuageinit integration or full
world/kernel/pkgbase/cache/performance. Make remains production/default.


## 2026-10-28: pwd_mkdb ATF installation and Make-warning correction

Added install_archive for alternate_test, its Kyua index, split debug file and
runtime-tests metadata. The independent Make reference exposed a real defect in
the previous turn's optional-loader helper: casting const arguments to char *
failed Make's -Wcast-qual/-Werror gate. Fixed by duplicating each exec argument
and checking allocation failures; no warning suppression was added. Initial
failed Make log remains in bazel-pwd-mkdb-test-reference-20261028-r2. Corrected
Make build/install succeeds in r3.

Eight installation records and Kyua bytes match Make; 54 executable symbols,
libc/privateATF dependencies, empty RPATH/RUNPATH, debug pair and stripped text
checks pass. All six database ATF cases actually executed and passed again with
the corrected helper. Evidence:
/usr/obj/usr/src/bazel-pwd-mkdb-test-install-20261028-r2/qualification/
alternate_test/parity.json plus bazel.stdout/test-reports. Reference:
bazel-pwd-mkdb-test-reference-20261028-r3; scripts:
bazel-pwd-mkdb-test-install-qualification-20261028/{make.py,verify.py}.

Maintained build-bsd ran at 16 jobs. Reviewed frontend explicit input selection:
no frontend change required. Installation parity and these runtime cases do not
establish configured-world test aggregation, published pkgbase output, installed
default-loader execution or full account-management coverage. Full world/kernel/
cache/performance gates remain open. Make stays default; host accounts unchanged.


## 2026-10-28: DMA mailbox helper native build/install

Added native dma-mbox-create from the unchanged contributed source with explicit
dma.h and maintained feature/path/version/account definitions. Installation
preserves root:mail mode 04554 and mail-group debug ownership; archive UID/GID
checks use the source account database rather than the builder's local accounts.
No setuid helper was installed or executed on the host.

The executable object .text/global symbols, 31 executable symbols, libc-only
NEEDED and empty RPATH/RUNPATH match isolated Make. Four installation records,
debug validation and stripped-text preservation pass. Evidence:
/usr/obj/usr/src/bazel-dma-mbox-20261028/qualification/{dma-mbox-create/parity.json,
object-parity.json}. Reference: bazel-dma-mbox-reference-20261028; scripts:
bazel-dma-mbox-qualification-20261028/{make.py,verify.py,objects.py}.
Builds used maintained build-bsd at 16 jobs. Reviewed frontend explicit targets:
no change required. Privileged mailbox ownership/creation, Capsicum transitions,
failure cleanup and hostile-path behavior require isolated VM qualification.
DMA's main agent/generators remain unconverted. Full world/kernel/pkgbase/cache/
performance gates remain open and Make remains production/default.

## 2026-10-28: DMA native parser/scanner output qualification

The direct bsd_yacc rule now declares its optional -i interface output, exposes
an interface output group, and checks the generator-derived filename. Raw -i
flags must use the explicit interface attribute. DMA declares aliases_parse.c,
.h and .i plus aliases_scan.c using native yacc, lex and m4 targets. This does
not add interface support to the separate configured metadata exporter.

Maintained build-bsd at 16 jobs succeeded in
/usr/obj/usr/src/bazel-dma-generators-20261028. All four collected artifacts match
isolated Make after mapping only exact known source/output path spellings in
preprocessor line/include directives; line numbers and all other contents remain
checked. Evidence: generator-parity.json and artifacts/manifest.json in that run;
comparison script: bazel-dma-generators-qualification-20261028/verify.py;
Make evidence: bazel-dma-generators-reference-20261028/generators.log.

Reviewed frontend explicit target selection and default artifact collection:
the interface is a declared default output and is retained without frontend
changes. Main DMA executable compilation, installation, runtime and interface
validation edge cases are still pending. Generator parity alone does not prove
include resolution in a consuming compile action. Full world/kernel/pkgbase and
performance gates remain open. Make remains production/default.

## 2026-10-28: DMA native executable compilation

The DMA agent now consumes declared parser source/header/interface outputs and
scanner source, ten unchanged contributed C sources, and native SSL/crypto
libraries. Its feature/account/path/version definitions follow Makefile.inc;
OPENSSL_API_COMPAT and PIE follow the component Makefile. The first sandboxed
build caught an omitted dfcompat.h dependency; declaring that source header
fixed the build without broadening sandbox filesystem access. Failed evidence
remains in bazel-dma-agent-20261028.

Successful maintained frontend run:
/usr/obj/usr/src/bazel-dma-agent-20261028-r2 (16 jobs).
All twelve object .text bodies and global/undefined symbol sets match isolated
Make. The executable's 249 global symbols and libc/ssl/crypto NEEDED entries
match, with no RPATH/RUNPATH. Evidence: qualification/{object-parity,binary-parity}.json;
reference: bazel-dma-agent-reference-20261028; scripts:
bazel-dma-agent-qualification-20261028/{make.py,objects.py,binary.py}.
This also verifies generated include resolution in consuming compile actions.

Reviewed maintained frontend: explicit targets and artifact collection already
support this executable, so no frontend change is needed. DMA installation,
debug packaging, configurations/manual links and runtime delivery remain pending.
No host mail was submitted or configuration changed. Full world/kernel/package/
runtime/performance gates remain open; Make remains production/default.

## 2026-10-28: DMA agent installation/debug archive

Added the native DMA installation archive: root:mail 02555 executable,
root:mail 0444 debug file, two root:mail 0640 configuration files with config
tags, mailer.conf example, manual and cross-section dma.conf.5 hardlink.
Package-owned directories follow Make, including /etc/dma's utilities tag.
The manual link follows split_manpages selection; this run checks default
unsplit packaging, not every option combination.

Maintained build-bsd at 16 jobs succeeded:
/usr/obj/usr/src/bazel-dma-agent-install-20261028.
Eleven distinct metadata records and five nonbinary payloads match rootless
Make; the manual alias is verified as a hardlink to dma.8.gz. Debug pairing and
stripped-text preservation pass. Executable symbols and NEEDED/RPATH/RUNPATH
still match Make. Evidence: qualification/dma/parity.json; reference:
bazel-dma-agent-install-reference-20261028; scripts:
bazel-dma-agent-qualification-20261028/{install.py,verify-install.py}.
Make emits /etc/dma twice with identical metadata; comparison coalesces that
record. No host installation or mail delivery occurred.

Reviewed frontend and backend artifact handling: existing explicit targets and
installation archive support handle these outputs without frontend changes.
Runtime delivery/TLS/queue/privilege qualification and aggregate world/pkgbase
publication remain open, as do full kernel and performance gates. Make stays
production/default.

## 2026-10-28: ypxfr native conversion in progress (not qualified)

Added a candidate native ypxfr graph with explicit rpcgen header and two client
outputs, preserving -I/-C and YPSERV_ONLY/YPPUSH_ONLY selections, source/header
exports from ypserv, generated rpcsvc/ypxfrd header and librpcsvc dependency.
The executable is incompatible when NIS is disabled. No installed payload or
successful executable is claimed yet.

Both build attempts expose the existing SDK's WITHOUT_NIS libc: Make ypxfr
fails with unresolved yp/XDR symbols, and Bazel fails linking NIS-enabled
librpcsvc with unresolved yp_get_default_domain/yp_master. Logs:
/usr/obj/usr/src/bazel-ypxfr-20261028/bazel.stderr and
/usr/obj/usr/src/bazel-ypxfr-reference-20261028/build.log.
An attempted full object comparison also stopped because Bazel aborted before
producing ypxfr_main.o; no all-object parity claim is valid. Scripts remain in
bazel-ypxfr-qualification-20261028. Next: qualify against matching NIS-enabled
native libc and Make reference inputs; do not substitute NIS stubs or disable
the requested option to get a link. Candidate edits remain uncommitted.

Reviewed frontend: explicit inputs already select NIS, but selecting an option
does not rebuild the imported SDK. This needs consistent dependency/reference
qualification, not a one-off frontend fallback. DMA delivery checks remain
pending isolated execution because its normal paths use system mail config and
queue state. Full goal remains active and Make remains production/default.

## 2026-10-28: ypxfr native NIS dependency graph builds

The successful candidate run is bazel-ypxfr-20261028-r3. librpcsvc now declares
native libc as a shared dependency, and ypxfr selects the native executable libc
interface; both disable implicit default-library linking. This propagates NIS
selection to the actual libc link dependency instead of relying on the imported
WITHOUT_NIS SDK libc. An intermediate r2 analysis failed because placing the
executable libc interface under librpcsvc caused shared-library ownership of
libc_nonshared. The DSO now uses shared_link_objects, with narrow visibility from
libc; ypxfr retains the executable interface. Review/regression of this change
for other rpcsvc consumers and static archives remains required before commit.

All nine ypxfr object bodies and global/undefined symbol sets match the Make
objects, including generated RPC clients. Evidence:
/usr/obj/usr/src/bazel-ypxfr-20261028-r3/qualification/object-parity.json.
A fresh isolated Make libc with WITH_NIS also built successfully in
bazel-ypxfr-libc-reference-objects-20261028; command/receipt and log are in
bazel-ypxfr-libc-reference-20261028. Script:
bazel-ypxfr-qualification-20261028/make-libc.py.
The Make ypxfr executable still needs relinking against matching reference
libraries; no final executable ABI/install/runtime parity claim yet. All changes
remain uncommitted pending this dependency/reference qualification.

Frontend review: maintained explicit inputs select the configuration and collect
the completed native executable without additional frontend options. The graph
fix belongs in native dependencies. No SDK or host installation was modified.

## 2026-10-28: ypxfr executable parity and direct dependency correction

The Make reference now links using the maintained libc_nossp.ldscript template
expanded to the fresh NIS-enabled Make libc and SDK libc_nonshared archive in a
private reference link directory. No installed SDK files changed. The relink
command retains the Make PIE/relro/now flags; logs/receipt:
bazel-ypxfr-reference-20261028-r2. Script: ypxfr qualification/relink.py.

Strict comparison caught an extra direct libsys NEEDED entry in native ypxfr.
An --as-needed trial (r4) was ineffective because rules_cc emits those target
flags after library operands; it was removed. Corrected the graph by removing
redundant direct libsys dynamic_deps from ypxfr and librpcsvc: libc already owns
that transitive shared dependency. Successful run:
/usr/obj/usr/src/bazel-ypxfr-20261028-r5. All nine objects match Make .text and
symbols. All 120 executable global symbols and NEEDED libc/librpcsvc entries
match; no RPATH/RUNPATH. Evidence: qualification/{object-parity,binary-parity}.json.

Five existing RPC consumers (rquotad, sprayd, rwalld, rstatd, rusersd) and both
rpcsvc static archive variants built in bazel-rpcsvc-native-libc-regression-20261028
before the final redundant-dependency correction. That run is compile/link
regression evidence only, not runtime or final-graph verification. Repeat it
against the final graph and compare archives/dependencies before committing.
The component archive rule selects only each group's own objects, excluding
transitive libc from installed rpcsvc archives. Installation and runtime ypxfr
qualification remain pending. Frontend explicit inputs continue to suffice;
Make remains default and the full goal remains incomplete.

## 2026-10-28: ypxfr installation and final RPC regression qualification

Native ypxfr now has an installation archive preserving package yp, executable
and debug metadata and its section-8 manual. Five metadata records and the
manual payload match isolated Make. Debug pairing, stripped-code preservation,
120 executable symbols and libc/rpcsvc NEEDED entries match; RPATH/RUNPATH are
empty. Evidence: /usr/obj/usr/src/bazel-ypxfr-install-20261028/qualification/ypxfr/parity.json.
Make stage: bazel-ypxfr-install-reference-20261028. Scripts:
bazel-ypxfr-qualification-20261028/{install.py,verify-install.py}.

Final graph regression run:
/usr/obj/usr/src/bazel-rpcsvc-native-libc-regression-20261028-r2.
Both rpcsvc archives are byte-identical to the prior qualified artifacts in
bazel-rpcsvc-complete-20261028. All five RPC consumers (rquotad, sprayd, rwalld,
rstatd, rusersd) match their independent Make references for global symbols and
NEEDED/RPATH/RUNPATH/SONAME. Evidence: regression-parity.json; comparison script:
bazel-ypxfr-qualification-20261028/regression.py. These are build/link checks,
not running-daemon tests. Native source code is unchanged.

Frontend review: maintained build-bsd explicit inputs, native configuration and
artifact/archive collection support this work without a new frontend option or
fallback. Builds use 16 jobs. Live NIS map transfers, RPC failure behavior,
privileged destination handling and ypxfr installation/runtime on an image are
still pending. This component qualification does not establish whole-system
completion, publication, performance or the NIS SDK bootstrap path. Make stays
default and no host installation occurred.

## 2026-10-28: Hyper-V helper script installation

Added native installation targets for all five maintained libexec/hyperv scripts:
hv_set_ifconfig, hv_get_dns_info, hv_get_dhcp_info, hyperv_vfattach and hyperv_vfup.
Sources are exported with narrow package visibility from contrib/hyperv/tools/scripts.
All five payloads match Make byte-for-byte. Six metadata records match, including
the package-owned /usr/libexec/hyperv directory, root:wheel ownership, 0555
script modes and hyperv-tools tags. Evidence:
/usr/obj/usr/src/bazel-hyperv-scripts-20261028/qualification/hyperv/parity.json.
Reference: bazel-hyperv-scripts-reference-20261028; scripts:
bazel-hyperv-scripts-qualification-20261028/{make.py,verify.py}.

Reviewed maintained frontend explicit targets/archive collection: no frontend
change required. Qualification used build-bsd at 16 jobs. Script runtime depends
on system rc configuration, network tools and Hyper-V devices; no network or
rc.conf mutation was attempted on the host. This establishes installation parity,
not functional Hyper-V or complete package aggregation. Full world/kernel/runtime/
publication/performance gates remain open and Make stays production/default.

## 2026-10-28: main rc files and defaults installation

Added native installation for six /etc rc source files, four executable /etc
configuration scripts, /etc/defaults/rc.conf and three /libexec shell helpers.
All fourteen payloads match Make byte-for-byte; seventeen distinct metadata
records match, preserving config tags, 0644/0755 modes, rc payload ownership and
utilities ownership of /etc and /etc/defaults. The first comparison caught missing
explicit /etc directory records; the corrected archive includes them. Failed
run bazel-rc-core-20261028 remains available.

Successful evidence:
/usr/obj/usr/src/bazel-rc-core-20261028-r2/qualification/rc/parity.json.
Reference: bazel-rc-core-reference-20261028 (NO_SUBDIR); scripts:
bazel-rc-core-qualification-20261028/{make.py,verify.py}. Duplicate identical
Make directory records are coalesced. This deliberately covers the main directory,
not the rc.d service collection or rc tests. The previously existing rc.d target
covers a ZFS-specific subset; broader service selection and startup tests remain.

Reviewed maintained build-bsd explicit input/archive support: no frontend change
required. Used 16 jobs. No startup scripts were executed on the host and no host
configuration was installed. This proves installation parity, not normal boot.
Full world/kernel/pkgbase/runtime/performance gates remain open; Make stays default.

## 2026-10-28: always-installed rc.d groups

Added native metadata for all fifteen unconditional rc.d groups: ninety scripts
with per-group package ownership and config tags. The checked-in Starlark table
owns the graph; Makefile translation was an authoring step only, with no runtime
Make parsing or source-directory glob. The existing ZFS-specific target remains
separate; this archive is explicitly named unconditional_install_archive.

All ninety script payloads and ninety-one metadata records match a nonrecursive
Make reference with every optional rc.d selector disabled. This includes package
ownership for devd, mac-abac, devmatch, dhclient, cron, ctl, geom, ggate, newsyslog,
nfs, powerd, ppp, syslogd, resolvconf and rc. Evidence:
/usr/obj/usr/src/bazel-rc-services-20261028/qualification/rc/parity.json.
Reference: bazel-rc-services-reference-20261028; scripts:
bazel-rc-services-qualification-20261028/{make.py,verify.py}.
Only table formatting changed after the successful build; payloads/selection
are unchanged. No service startup was executed.

Reviewed maintained frontend: existing explicit target and archive handling is
sufficient; used 16 jobs. Conditional service groups, architecture restrictions,
Kerberos alternatives, configured aggregate packaging and rc runtime tests are
still pending. These results do not establish all rc.d coverage or normal boot.
Full world/kernel/pkgbase/performance qualification remains open; Make stays default.

## 2026-10-28: shared-setting rc.d selections

Added eighteen service scripts controlled by six existing native settings:
audit, jail, pf, nis, ns_caching and kerberos_support (gssd). Each group uses
select() on the shared build setting and preserves its maintained package/config
tags. The partial aggregate selected_install_archive combines these groups with
the ninety unconditional scripts. It does not represent the full rc.d set.

Enabled qualification matches Make for 108 payloads and 109 records; disabled
qualification matches the unconditional Make reference for 90 payloads and 91
records. Evidence:
/usr/obj/usr/src/bazel-rc-selected-services-20261028/qualification/rc/parity.json
and bazel-rc-selected-services-off-20261028/qualification/rc/parity.json.
Reference: bazel-rc-selected-services-reference-20261028 (other optional groups
disabled); disabled reference: bazel-rc-services-reference-20261028. Scripts:
bazel-rc-selected-services-qualification-20261028/{make.py,verify.py,verify-off.py}.
Only formatting of the native table changed after the builds.

Reviewed frontend: source_graph.py accepts typed format-5 build-settings, and
build-bsd forwards them without a new option or one-off workflow. Both runs use
16 jobs. Remaining conditional groups, architecture/Kerberos combinations and
runtime startup tests remain pending; this validates these six settings together,
not every mixed configuration. Make stays default and full-system gates remain open.

## 2026-10-28: all single-option rc.d groups

Extended the native selected-service table to all 31 single-option groups,
including independently selected accounting/utx and wireless's distinct hostapd
and wpa package groups. Reused existing settings and added 24 shared bool settings
for remaining component selectors. Defaults were checked against Make with
SRCCONF and __MAKE_CONF set to /dev/null on amd64; recorded in
bazel-rc-options-qualification-20261028/settings.json. Source builds do not query
Make or parse its metadata: the checked-in native table and settings own the graph.

All groups enabled match Make for 158 script payloads and 159 metadata records;
all disabled match the unconditional Make reference for 90 payloads and 91
records. Evidence: /usr/obj/usr/src/bazel-rc-options-20261028/qualification/rc/parity.json
and bazel-rc-options-off-20261028/qualification/rc/parity.json. Reference:
bazel-rc-options-reference-20261028; scripts:
bazel-rc-options-qualification-20261028/{make.py,verify.py,verify-off.py}.
The enabled Make reference enables OpenSSL so OpenSSH is not implicitly disabled;
KTLS scripts remain off. These checks cover explicit all-on/all-off settings,
not every mixed/default or architecture-dependent option combination.

Reviewed build-bsd and source_graph.py: typed format-5 settings already expose
these selectors through the maintained frontend; no CLI changes needed. Used
16 jobs. ACPI architecture rules, Kerberos alternatives/directory metadata and
KTLS conjunction remain missing from this partial aggregate. Native option
implications and broader default configurations still need qualification.
Runtime, complete-world/pkgbase and performance gates remain open; Make stays default.

## 2026-10-28: compound rc.d selections and complete archive candidate

Added the remaining rc.d selection expressions: ACPI on x86_64/x86_32/aarch64,
Kerberos-enabled MIT versus Heimdal alternatives, and OpenSSL AND OpenSSL_KTLS.
The native install_archive aggregates unconditional, single-option and compound
manifests. Heimdal installs /var/heimdal root:wheel 0700 tagged utilities; MIT
omits that directory and tags kadmind/kdc kerberos-kdc rather than kerberos.
New shared acpi/kerberos selectors follow maintained default-on settings.

All-enabled amd64 Heimdal qualification matches Make for 167 payloads and 169
records; MIT matches for 163 payloads and 164 records. Evidence:
/usr/obj/usr/src/bazel-rc-heimdal-20261028/qualification/rc/parity.json and
bazel-rc-mit-20261028/qualification/rc/parity.json. Independent references:
bazel-rc-{heimdal,mit}-reference-20261028. Scripts:
bazel-rc-complete-qualification-20261028/{make-heimdal.py,verify-heimdal.py,
make-mit.py,verify-mit.py}. No service execution occurred.

Reviewed build-bsd/source_graph typed settings: existing frontend inputs suffice,
with 16 jobs used. The candidate remains uncommitted until disabled conjunctions
and architecture selection receive focused verification. All-on variants do not
prove default-option implication handling, other architectures, complete rc test
execution or normal system startup. Full goal gates remain open; Make stays default.

## 2026-10-28: compound rc selection exclusion and architecture checks

Complete install_archive now passes independent Make comparisons with OpenSSL
only and OPENSSL_KTLS only, with ACPI/Kerberos and single-option groups disabled.
Both yield exactly 90 payloads/91 records: no TLS service scripts, either Kerberos
variant or Heimdal directory. The two cases also vary MITKRB5 while KERBEROS is
disabled. Evidence: bazel-rc-{ssl-only,ktls-only}-20261028/qualification/rc/parity.json;
references: bazel-rc-{ssl-only,ktls-only}-reference-20261028. Together with prior
MIT/Heimdal all-enabled checks, this qualifies the compound selections exercised.

Analysis-only platform fixtures in libexec/rc/rc.d/tests check the actual configured
compound manifest dependency graph: ACPI's power_profile is selected on x86_64,
x86_32 and aarch64 and absent on riscv64. Evidence:
/usr/obj/usr/src/bazel-rc-architecture-20261028/selection.json plus per-platform
cquery logs. Script: bazel-rc-complete-qualification-20261028/architecture.py.
This is metadata analysis, not cross compilation or cross-architecture runtime.
It reuses the recorded frontend command/toolchain inputs and changes target
platform for cquery only; normal frontend qualification remains native.

Reviewed build-bsd and source_graph.py: normal installation and typed settings
use the maintained frontend, without new options. No host service execution or
installation occurred. All rc.d groups now have native installation expressions;
full default/option-implication semantics, system package aggregation, rc tests,
normal boot and full-system performance gates remain unqualified. Make stays default.

## 2026-10-28: complete maintained rc ATF script installation

Added native wrapping and installation of all eleven ATF_TESTS_SH entries from
libexec/rc/tests/Makefile, preserving unchanged assertions and the installed
/usr/libexec/atf-sh interpreter. Sorted Kyua metadata matches Make exactly.
Thirteen installation records and twelve payloads (eleven wrappers plus Kyuafile)
match rootless Make. Evidence:
/usr/obj/usr/src/bazel-rc-tests-20261028/qualification/rc/parity.json.
Reference: bazel-rc-tests-reference-20261028; scripts:
bazel-rc-tests-qualification-20261028/{make.py,verify.py}.

This is installation evidence only; no ATF case ran. rc_subr/svcj cases include
root requirements and installed /etc dependencies. Several source-oriented
cases expose fixture overrides suitable for declared runtime inputs. Integrity-
named tests already exist in the maintained Make list; preserving their bytes
here does not restore BIP or qualify their applicability. Review before runtime
execution; BIP remains out of scope. No tests were omitted from installation to
make the comparison pass.

Reviewed frontend artifact collection and typed inputs: no frontend change
required; used 16 jobs. Next work is actual Bazel-owned rc test execution with
explicit source/runtime inputs and isolated system tests where required.
Full boot/world/kernel/pkgbase/performance gates remain open; Make stays default.

## 2026-10-28: safe_eval native ATF cases and matching-kernel replay

Added safe_set_reject and safe_set_xtras as native bsd_atf_test targets with
declared safe_eval source, native tools and libraries. The existing test now
accepts the standard ATF safe_eval configuration path, retaining SAFE_EVAL and
/libexec/safe_eval.sh defaults; assertions are unchanged. Host execution failed
before assertions on the known cap_rights_intersect assertion with the older
host kernel. Evidence: bazel-rc-safe-eval-20261028 test reports/execution log.
No host-tool fallback or rights masking was used.

Both cases passed in QEMU replay of the recorded Bazel test environments and
runfiles, along with the fixture's baseline checks. Evidence:
/usr/obj/usr/src/bazel-rights-vm-20261028/safe-eval-run-r3/{result.json,serial.log}.
Captured payload hashes/actions: safe-eval-payload.json; staging script:
stage-safe-eval.py. Guest configuration: 2 GiB, 4 CPUs, networkless disk-backed
512 MiB UFS root. The launcher is a static ATF replay adapter; guest execution
uses the native Bazel test runner/payloads, not a guest Bazel scheduler. It does
not prove general shell tests run on the host or normal installed system startup.
VM exited and powered off successfully.

Preparation initially used the wrong ATF library spelling; the SDK library is
libprivateatf-c. Two VM launches were rejected before boot because the runner's
default GENERIC-NODEBUG did not match the staged GENERIC kernel. Fresh private
inputs plus explicit --kernconf GENERIC passed identity validation; those rejected
logs are retained. This was a launch configuration error, not a bypass of checks.

Reviewed build-bsd/ATF helpers: existing config_files and maintained frontend
inputs support the new test parameter without changes. Installation wrappers need
recomparison after the source-path parameter change. Remaining rc runtime cases,
world/kernel/pkgbase and performance gates stay open; Make remains default.

## 2026-10-28: os-release rc tests and wrapper revalidation

Added native ATF targets for installed_metadata, denied_install and failed_inputs.
The maintained test accepts a standard rc_script configuration path while retaining
its RC_TEST_SRCDIR/installed defaults. Existing fixtures/assertions remain unchanged:
they use temporary files and pre-existing failure-injection shell functions.
The native os-release source and runtime binaries/libraries are declared inputs.

Host execution again fails before assertions due to the older host Capsicum ABI.
During integration, an incorrectly prefixed ATF case identity was caught during
replay staging and corrected. First VM execution passed installed_metadata but
failed two cases because native env lacked libutil in its runtime. Added declared
native libutil; no host-library fallback. Corrected actions:
bazel-rc-osrelease-20261028-r3. All three pass in matching-GENERIC QEMU replay:
/usr/obj/usr/src/bazel-rights-vm-20261028/osrelease-run-r2/{result.json,serial.log}.
Captured actions/payload hashes: osrelease-payload.json; stage-osrelease-r3.py.
Earlier failed runs and logs remain. Guest is networkless, 2 GiB/4 CPUs with a
512 MiB disk-backed UFS root; exited and powered off successfully. This is replay
of Bazel actions/runfiles, not guest Bazel scheduling or normal system boot.

Revalidated complete rc test installation after both source-path parameter changes:
bazel-rc-tests-20261028-r3/qualification/rc/parity.json. All thirteen metadata
records and twelve payloads match Make reference bazel-rc-tests-reference-20261028-r3.
Scripts: bazel-rc-tests-qualification-20261028/{make-r3.py,verify-r3.py}.
The preceding r2 comparison also passed after safe_eval alone.

Frontend/adapter review: maintained build-bsd and existing config_files support
these parameters; no frontend change required. Builds used 16 jobs. Five rc cases
now have native payloads passing guest replay, not whole-suite or installed-system
qualification. Remaining tests, default option implications, full world/kernel/
pkgbase and performance gates stay open. Make remains default.

## 2026-10-28: SSH/syslog startup fixture runtime

Added seven native ATF cases: SSH key_failure, success_and_disabled, precheck;
syslog prepare_failure, list_read_failure, default_and_chroot, explicit_paths.
Both maintained test scripts accept an optional rc_script file parameter while
preserving rc_source/installed defaults. Existing assertions and temporary-file
seams remain unchanged. No real keys, host sockets or daemon configuration were
modified. The SSH keygen fixture is a stub already present in the maintained test,
so these results do not establish actual key generation, login or daemon execution.

Host run bazel-rc-daemon-scripts-20261028 hits the known old-kernel Capsicum ABI
failure. Matching-GENERIC guest replay initially exposed missing /bin/sh for the
fixture's shebang. The revised private VM root supplies the declared native sh
payload at that standard path; no host shell substitution or test rewrite.
All seven cases are explicitly recorded passed in
/usr/obj/usr/src/bazel-rights-vm-20261028/daemon-scripts-run-r2/result.json (some
initial serial lines are absent from the console summary; result.json and serial
record the per-case markers). VM shut down successfully. Evidence also includes
serial.log, daemon-scripts-payload.json, stage-daemon-scripts-r2.py. The failed
first guest run is retained. Guest: 2 GiB/4 CPUs, disk-backed 512 MiB root,
networkless; recorded Bazel action replay, not a guest Bazel scheduler.

All rc test installation records and payloads recompare successfully after these
source parameter additions: bazel-rc-tests-20261028-r4/qualification/rc/parity.json;
reference bazel-rc-tests-reference-20261028-r4. Twelve rc fixture cases now pass
native-payload guest replay across safe_eval, os-release, SSH and syslog tests.
Remaining rc cases and actual installed-system behavior are still unqualified.

Frontend review: maintained build-bsd and existing config_files/runtime inputs
suffice; compilation uses 16 jobs. No production/default change. Full-world,
kernel, pkgbase, boot, option-implication and performance gates remain open.

## 2026-10-28: clean default rc selection and NIS default correction

Compared native rc.d installation with no feature-setting overrides against Make
using SRCCONF, __MAKE_CONF and SRC_ENV_CONF=/dev/null, with test installation off.
The initial comparison found eight extra NIS scripts. Native nis had defaulted
true, contrary to share/mk/bsd.opts.mk's __DEFAULT_NO_OPTIONS. Corrected the shared
native setting default to false; explicit nis=true configurations remain supported.
This affects all consumers that previously relied on the incorrect implicit value,
including libc, so it is a configuration correction beyond rc packaging.

Corrected evidence:
/usr/obj/usr/src/bazel-rc-default-20261028-r2/qualification/rc/parity.json:
151 byte-identical script payloads and 152 metadata records match the independent
Make stage bazel-rc-default-reference-20261028. Initial failed evidence remains in
bazel-rc-default-20261028. Scripts:
bazel-rc-complete-qualification-20261028/{make-default.py,verify-default.py,
verify-default-r2.py}. No runtime/boot claim follows from installation parity.

Reviewed frontend: typed explicit settings already override defaults; no build-bsd
change is required. Qualification used 16 jobs. Inspection also confirms remaining
native implication gaps: src.opts.mk disables dependent features when CRYPT,
OPENSSL, CDDL, MAIL, NETGRAPH, LDNS or OFED are disabled. Current native selectors
do not consistently encode these implications. Correct default installation is
not proof of arbitrary mixed-option compatibility. This is next configuration
work, before claiming complete package/world selection. Make remains default.

## 2026-10-28: crypt/OpenSSL prerequisite selection

Shared enabled config_settings now require maintained prerequisites: crypt for
OpenSSL; crypt+OpenSSL for SSH, KTLS/FIPS, Kerberos/support/MIT and LDNS; LDNS plus
those prerequisites for unbound; CDDL plus those prerequisites for ZFS. Local
compound rc selectors and four SSH Heimdal incompatibility selectors include the
same crypt/OpenSSL prerequisites. These are ordinary native config_setting
conjunctions, not frontend flag rewriting or a separate rc-only policy.
Raw bool settings remain requested values; enabled selectors express effective
availability. Directly requesting a component target is not whole-world inclusion.

Independent clean Make WITHOUT_OPENSSL and WITHOUT_CRYPT references both match
native rc installation for 136 payloads and 137 metadata records. Other feature
settings remain at defaults, proving dependent entries disappear through the
shared prerequisites. Evidence:
/usr/obj/usr/src/bazel-rc-no-openssl-20261028/qualification/rc/parity.json and
bazel-rc-no-crypt-20261028/qualification/rc/parity.json. References:
bazel-rc-{no-openssl,no-crypt}-reference-20261028. Scripts:
bazel-rc-implications-qualification-20261028/{make-no-openssl.py,make-no-crypt.py,
verify-no-openssl.py,verify-no-crypt.py}.

Reviewed frontend/source_graph: no new inputs or interpretation needed; build-bsd
passes typed requested settings and the native graph resolves prerequisites.
Used 16 jobs; no host install or service execution. These checks qualify rc
selection, not all compiled consumers under disabled-feature configurations.
MAIL/NETGRAPH/OFED and further option dependencies, configured aggregate builds,
full runtime/pkgbase/performance gates remain open. Make stays default.

## 2026-10-28: MAIL/NETGRAPH/OFED service prerequisites

Added native default-on mail/netgraph requested bool flags. Shared Sendmail,
Bluetooth and OFED_EXTRA enabled selectors now require mail, netgraph and ofed
respectively, following src.opts.mk. No runtime Make parsing or frontend rewriting.

Four independent rootless Make installation references match native rc.d archives
exactly for payload bytes and metadata (owners, groups, permissions, tags, flags):

| Configuration | Payloads | Metadata records |
| --- | ---: | ---: |
| MAIL off, SENDMAIL explicitly on | 151 | 152 |
| NETGRAPH off, BLUETOOTH explicitly on | 143 | 144 |
| OFED off, OFED_EXTRA explicitly on | 151 | 152 |
| SENDMAIL and OFED_EXTRA on, parents default on | 153 | 154 |

Evidence under /usr/obj/usr/src/bazel-rc-{no-mail,no-netgraph,no-ofed,mail-ofed}-20261028/qualification/rc/parity.json;
independent references use corresponding -reference-20261028 directories.
Reproduction scripts make-<variant>.py and verify-<variant>.py are retained in
bazel-rc-implications-qualification-20261028, with format-5 inputs adjacent to
the run directories. All runs used the maintained build-bsd bazel-test frontend
and 16 jobs. Reviewed source_graph typed settings transport: existing format-5
inputs suffice, with no frontend C/backend protocol change required.

This qualifies rc service selection only, not live Bluetooth, Sendmail or OpenSM.
Other MAIL children (mailwrapper/dmagent), remaining src.opts.mk implications,
compiled aggregate selection, complete world/kernel/pkgbase and performance
qualification remain open. No host installation or services started. Make remains
the production default; BIP remains excluded.

## 2026-10-28: native DMA installation aggregation

Added //libexec/dma:install_archive with both declared child installation
manifests. The native archive action receives their payload depsets directly;
there is no extraction/repacking of child tar files and no Make subprocess.
The maintained format-5 build-bsd path built the target with 16 jobs.

Exact composition verification against the two previously Make-qualified child
archives passed: 13 installation records, 24 archive members and 8 regular-file
payloads. Comparison includes binary/debug bytes, all metadata record fields,
archive ownership/modes/timestamps, hardlinks and directory overlap consistency.
Evidence: /usr/obj/usr/src/bazel-dma-complete-20261028/composition.json; verifier
verify-composition.py in that directory; frontend inputs adjacent to it. This
is composition evidence, not a new recursive Make reference or mail runtime test.

Frontend review: existing target selection/artifact capture handles this parent
target without a new input or backend protocol. No host installation occurred.

Aggregation review found root BUILD.bazel only exports COPYRIGHT and libexec
has no parent BUILD target. Component coverage must not be called a world build.
Next aggregation work must account for every maintained libexec child, options,
tests, architecture selections and directory policy before claiming completeness.
DMA world selection still needs DMAGENT gated by MAIL/OpenSSL/CRYPT; directly
requesting this explicit archive includes both children. Full world/kernel,
pkgbase publication and runtime/performance gates remain open. Make remains default.

## 2026-10-28: native ATF pytest wrapper

The libexec aggregation audit found atf-pytest-wrapper lacked a native BUILD
file. Added ordinary cc_binary and installation targets for atf_pytest_wrapper,
with declared native libc++/libcxxrt/libm dependencies and source-matching
GNU C++20, HAVE_CONFIG_H and PIE settings. No source changes or Make subprocess.

Independent rootless Make and maintained build-bsd format-5 builds used 16 jobs.
Qualification passed: four installation metadata records, 77 global/undefined
symbols, identical NEEDED libraries, no RPATH/RUNPATH, valid stripped/debug pairing
and preserved executable text. All 38 executable object sections (15,080 bytes),
including C++ COMDAT functions, match Make byte-for-byte; the .text-only check
also passed but is insufficient alone for this C++ program.

Evidence: /usr/obj/usr/src/bazel-pytest-wrapper-20261028/qualification/
atf_pytest_wrapper/parity.json, object-parity.json and executable-sections.json
(the latter two are directly under qualification). Reproduction scripts:
bazel-pytest-wrapper-qualification-20261028/{make.py,verify.py,objects.py,sections.py}.
Independent Make objects/stage are under bazel-pytest-wrapper-reference*-20261028.
Native full ELF was copied into the qualification directory before comparison.

The existing frontend target input, declared installation rules and artifact
capture require no new frontend/backend protocol. Runtime pytest invocation,
ATF tests and libexec/world aggregation remain open. This component build adds
no host pytest dependency or installation. Make remains production/default;
complete world/kernel/package/runtime and resource gates are still outstanding.

## 2026-10-29: ATF shell tests and discovery installation

Added native install_archive targets for libexec/atf/atf-check/tests,
libexec/atf/atf-sh/tests, libexec/atf/tests and libexec/tests. Eight existing
ATF shell programs and misc_helpers use declared script-wrapper actions; the
integration test's __ATF_SH__ substitution uses the native template action.
The two hierarchy Kyuafiles install the maintained tests/Kyuafile verbatim,
preserving discovery instead of inventing a fixed child list. Source exports
are limited to their libexec consumers. Archives are visible to libexec parents.

Independent rootless Make installation and native build-bsd format-5 comparison
passed for all four components:

| Component | Payload files | Metadata records |
| --- | ---: | ---: |
| atf-check/tests | 2 | 3 |
| atf-sh/tests | 9 | 10 |
| atf/tests discovery | 1 | 2 |
| libexec/tests discovery | 1 | 2 |

Every payload is byte-identical to Make, including generated scripts, helper,
interpreter substitution and Kyuafiles. Owners/groups, modes, tags, flags and
archive types also match. These are installation tests, not execution of ATF
cases. Runtime registration and execution remain required.

Evidence: /usr/obj/usr/src/bazel-atf-{check,shell,atf-index,libexec-index}-20261028/
qualification/rc/parity.json. The inherited rc directory name is only an evidence
location. Reproduction scripts are in bazel-atf-tests-qualification-20261028;
independent stages use corresponding -reference-20261028 directories. All builds
used 16 jobs. Runs straddled UTC midnight; retained run paths keep their start date.

Frontend review: existing format-5 targets, script/template rules and artifact
capture suffice; no C frontend change or one-off build backend. No host install,
module loading or service execution. Complete libexec/world aggregation, kernel,
pkgbase publication, runtime and performance gates remain open. Make is default.

## 2026-10-29: ATF parent aggregation investigation (resolved below)

Added an uncommitted //libexec/atf:install_archive candidate containing all three
program manifests, shell support, the parent discovery file and option-selected
check/shell test installations. Both tests-on/off frontend builds and recursive
Make references completed using 16 jobs. Make's unconditional parent discovery
file is preserved with tests disabled. Existing frontend inputs suffice.

Qualification is NOT complete: the tests-enabled metadata/file-set comparison
passed before the verifier rejected differing linked .text bytes in atf-check.
NEEDED dependencies match. Inspection found an embedded source-path difference
in .rodata, which changes subsequent addresses, but has not yet established
that it explains all binary differences. No equality assertion was removed.
Evidence: /usr/obj/usr/src/bazel-atf-aggregate-tests-20261029/qualification/
linked-text-investigation.json and native-rodata.txt/make-rodata.txt. Reproducer
and unchanged failing assertion: bazel-atf-aggregate-qualification-20261029/verify.py.
The no-tests archive comparison still needs to run after resolving this issue.
Next: compare object sections/relocations and source-path handling, then finish
both variants and commit only once the evidence supports qualification.

## 2026-10-29: ATF aggregate qualification and source-path diagnosis

The linked-text difference was resolved without modifying program sources or
Bazel code generation. Fresh independent recursive Make references add only
CXXFLAGS_LAST=-fmacro-prefix-map=/usr/src/=, derived from the source root. This
normalizes Make's absolute __FILE__ paths to Bazel's source-relative spelling.
The original failing references and assertion remain intact. With that mapping,
all three programs' linked .text and .rodata bytes match exactly; NEEDED, RPATH
and RUNPATH also match. Each native stripped/debug pair validates. Diagnostic
source paths intentionally remain relative in Bazel; whole ELF/debug byte
identity with unmodified Make is not claimed.

Both native aggregate variants pass recursive Make installation comparison:

| Variant | Metadata records | Nonbinary payloads | Manual hardlinks |
| --- | ---: | ---: | ---: |
| tests enabled | 50 | 38 | 22 |
| tests disabled | 37 | 27 | 22 |

Payloads include the unchanged generated test scripts, helpers, manuals and
discovery files. Hardlinks agree with the actual Make staging inode relations.
The parent discovery file is present in both variants, matching Make.

Evidence: /usr/obj/usr/src/bazel-atf-aggregate-{tests,no-tests}-20261029/
qualification/{mapped-parity.json,mapped-data-parity.json}. Fresh references:
bazel-atf-aggregate-{tests,no-tests}-mapped-reference-20261029; scripts
make-<variant>-mapped.py and verify-mapped.py are in
bazel-atf-aggregate-qualification-20261029. Original failed proof retained.

Frontend review: //libexec/atf:install_archive uses existing format-5 targets and
tests bool selection, with declared child manifests and payload dependencies.
No frontend C or backend protocol changes needed. This qualifies native ATF
installation aggregation, not execution of its newly installed tests, a complete
world, or repository publication. Make remains production/default.

## 2026-10-29: recursive native rc installation

Added //libexec/rc:recursive_install_archive, composing the existing core,
unconditional/selected/compound service manifests and optional test manifest.
The existing core-only install_archive remains available for component checks.
rc.d directory policy is now shared by its own archive and the recursive target,
so the conditional Heimdal directory is not independently duplicated. Narrow
visibility permits the parent to consume the test manifest and Heimdal selector.

Independent recursive rootless Make references match native installation exactly:

| Configuration | Payload files | Metadata records |
| --- | ---: | ---: |
| default services, tests off | 165 | 169 |
| default services, tests on | 177 | 182 |
| Heimdal, tests on | 181 | 187 |

Compared every payload byte, record path, owner/group, mode, flags, package/config
tag and file/directory archive type. The Heimdal case includes /var/heimdal with
root:wheel 0700 and the corresponding six service scripts. No live services or
new tests were executed by these installation comparisons.

Evidence: /usr/obj/usr/src/bazel-rc-aggregate-{default,tests,heimdal}-20261029/
qualification/rc/parity.json. Scripts: bazel-rc-aggregate-qualification-20261029/
make-<variant>.py and verify-<variant>.py; independent stages use corresponding
-reference-20261029 directories. All used maintained build-bsd format-5 targets,
typed tests/mitkrb5 settings and 16 jobs. Frontend/backends need no new protocol
for this composition; documentation records the recursive target.

Remaining libexec aggregation must include conditional test payloads for its
other children and all parent option/architecture gates. This is not complete
world/kernel/pkgbase or runtime qualification; Make stays production/default.

## 2026-10-29: native libexec parent selection and archive metadata

Added //libexec:installation_archives with explicit maintained child dependencies
and native option selection, including recursive ATF/rc, complete flua modules,
DMA, and separate optional test payload archives. Narrow child archive visibility
now permits the libexec parent. No runtime Make parsing, tar repacking or source
substitution. New native flags cover the missing libexec selectors; DMAGENT
requires mail/openssl/crypt. tests_support has auto/yes/no semantics, matching
Make's default-from-tests plus explicit overrides.

The first generic filegroup build exposed missing metadata output groups: it
returned only 20 tar files. Replaced it with bsd_install_archive_set, which
requires the archive provider and forwards default files plus both metadata
output groups using transitive depsets. The rule adds no execution actions.
The first run remains as diagnostic evidence.

Maintained build-bsd format-5 builds with 16 jobs passed:
- Tests disabled: 20 archives, 60 saved artifacts including both metadata groups.
- Tests enabled: 25 archives, 75 saved artifacts; exact equality with configured
  archive labels and paired metadata filenames checked. This builds test
  installation payloads; it does not execute their test cases.

Evidence under /usr/obj/usr/src/bazel-libexec-aggregate-20261029-r2 and
bazel-libexec-with-tests-20261029: metadata-forwarding.json, artifacts/manifest.json,
receipt, commands, execution and time/resource logs. The existing frontend
requests metadata/directory_metadata output groups; forwarding them in the native
rule fixes integration without a C frontend/protocol change.

Five independent Make SUBDIR/native configured-label comparisons passed:
default (22 direct children), tests off (20), tests off with support explicitly
on (21), tests on with support explicitly off (21), and extra optional legacy
components/NIS/Sendmail enabled (31). Configured selections include the extra
test archives while child comparisons collapse them to their parent directories.
Evidence: bazel-libexec-selection-20261029-r2/selection.json, reproducible query
script /usr/obj/usr/src/libexec-selection-20261029-r2.py. Initial diagnostic
query lacked the declared Java environment and failed local-JDK detection;
corrected query uses the same declared JAVA_HOME/LC_ALL/toolchain environment
as source_graph. Original failed query retained; actual frontend builds were
not affected.

This proves aggregation build and selected children for these configurations,
not full recursive installed-tree/pkgbase equivalence, all compiled option
combinations, or runtime. Legacy NO_PIC/NO_RTLD selection and MAN-dependent
man_utils defaulting have not been implemented in the native parent. Kernel,
other world subtrees, merged package construction/publication, complete runtime,
bootstrap independence and performance gates remain open. Make stays default.

## 2026-10-29: recursive libexec installation comparison

A fresh recursive Make build/install of libexec with clean defaults plus
WITHOUT_TESTS, WITHOUT_NIS and WITHOUT_MALLOC_PRODUCTION matches the previously
built native tests-disabled aggregate for all 293 distinct metadata records and
210 non-ELF payloads. Compared ownership, modes, package/config/debug tags, flags,
symlinks, hardlink relationships and payload bytes. Directory records preserve
different package tag combinations rather than dropping all but one owner.

All 23 executable/shared-module debug pairs validate. Their global/undefined
symbol lists and NEEDED/RPATH/RUNPATH/SONAME properties match the fresh Make
reference. This does not assert byte-identical ELF/debug files or runtime
behavior; previous component qualifications remain separate evidence.

Evidence: /usr/obj/usr/src/bazel-libexec-recursive-qualification-20261029/
clean-installation-parity.json and elf-parity.json; preserved native ELF payloads
in native-elf/. Reproducers: make-clean.py, verify-clean.py and elf.py. Independent
reference: bazel-libexec-recursive-clean-reference-20261029, with a separate
-reference-objects tree. Native source artifacts: bazel-libexec-aggregate-20261029-r2.

The initial reference inherited WITH_TESTS_SUPPORT=1 from the SDK profile, so
it installed 37 extra ATF records absent from the native auto/tests-off graph.
Receipt inspection identified the mismatched inputs. Rebuilt in a fresh directory
with clean explicit options; no files were excluded from comparison and no
assertion was weakened. Initial stage and installation-parity.json remain as
diagnostic evidence.

All compilation used 16 jobs; Make commands retain time -l CPU/RSS/block-I/O
logs. These runs are not a controlled performance comparison against the warm
Bazel cache and must not be presented as one. No host install or services run.
No frontend implementation change was needed: this qualifies output already
produced by the maintained format-5 path, not a separate build backend.

Tests-enabled full-tree comparison, other options/architectures, semantic/runtime
checks, complete world/kernel/pkgbase publication, reproducible bootstrap and
controlled memory/disk/CPU performance gates remain open. Make is still default.

## 2026-10-29: recursive libexec with test payloads and missing-source fix

Fresh recursive Make WITH_TESTS installation and native aggregate now match
all 428 metadata records and 284 noncompiled payloads. The installed static
libpythagoras.a fixture was compared separately: member names, every allocated
section's bytes/size, allocated-section relocations and global/undefined symbols
match. Whole archive bytes differ; its compiled-object/debug contents must not
be treated as plain data. The proof is bound to both archive SHA256 values, and
the original byte-comparison failure is retained.

The ELF audit found a real omission: native set_var_test compiled only its main
source, but Make also links common.c. It linked without those unused helpers,
so prior successful builds did not reveal the incomplete source closure. Added
explicit extra sources (common.c/common.h) to its native target. No Make command
or source workaround. After rebuilding the aggregate, all 41 executable/module
debug pairs validate; their global/undefined symbol lists and dynamic properties
(NEEDED/RPATH/RUNPATH/SONAME) match the fresh Make reference.

Evidence under /usr/obj/usr/src/bazel-libexec-recursive-qualification-20261029:
- tests-r2-installation-parity.json and tests-r2-elf-parity.json: passing full checks.
- pythagoras/parity.json and member-comparison.json: static fixture proof.
- tests-elf-parity.json: original missing-common.c mismatch, retained.
- make-tests.py, verify-tests-r2.py, tests-r2-elf.py and pythagoras-check.py:
  retained reproduction work. Native outputs: bazel-libexec-with-tests-20261029-r2;
  reference: bazel-libexec-recursive-tests-reference-20261029.

All builds used 16 jobs through maintained Make/build-bsd paths. Source dependency
correction uses ordinary cc_binary inputs; frontend format-5/artifact handling
requires no change. No host install or runtime test execution occurred. These
results qualify installed outputs and ELF interface/debug properties, not full
instruction equivalence, all option variants, tests actually passing at runtime,
complete world/kernel/packages or performance. Make remains default.

## 2026-10-29: twelve /bin shell-test installation suites

Added native test install_archive targets for chmod, cp, date, hostname, ln, ls,
mkdir, mv, pwd, rm, rmdir and test. Eleven ATF scripts use the declared wrapper
action; the legacy test TAP script installs its existing bytes without adding
a second interpreter line. Kyua metadata preserves the unprivileged-user
requirements for ls/test and ls's required awk/nc/sort files. These source-declared
paths are test runtime requirements, not substitutions for undeclared build inputs.

All twelve targets built in one maintained build-bsd invocation. Twelve independent
rootless Make installations match every payload byte, mode, owner/group, tag,
flag and archive type: 24 payload files and 36 metadata records total. Each suite
has its script, Kyuafile and test directory record. Tests themselves have not
been executed or registered as native Bazel cases in this change.

Evidence: /usr/obj/usr/src/bazel-bin-shell-installs-20261029/qualification/
summary.json and <component>/parity.json. Reproduction scripts and component list:
bazel-bin-shell-install-qualification-20261029; reference stages:
bazel-bin-<component>-tests-reference-20261029. All builds use 16 jobs.

Frontend review: existing typed target inputs, script/installation rules and
artifact capture suffice. No new frontend C/backend protocol or build replacement.
No host installation, test mutation of host files, or services executed. More /bin
test installations (including imported NetBSD suites and data/Perl fixtures),
parent discovery/aggregation and runtime remain before complete /bin qualification.
Full world/kernel/pkgbase/performance gates remain open; Make stays default.

## 2026-10-29: imported dd/expr/sleep test installations

Added native test install_archive targets for dd (local dd2_test plus imported
dd_test), expr and sleep. Imported files are explicit exports to their consuming
packages. expr retains Make's two sed expressions through a declared sed action;
the generated body then receives the normal ATF interpreter wrapper.

Found and corrected a Make-side omission in bin/sleep/tests: NETBSD_ATF_TESTS_SH
contained sleep_test, but ATF_TESTS_SH and _TESTS were empty because the Makefile
never included netbsd-tests.test.mk. Added the maintained include before
bsd.test.mk. The actual imported suite is now registered and installed by both
build systems; no fabricated empty-suite baseline.

Independent Make installations match every native payload byte and metadata
record: dd 3 payloads/4 records, expr 2/3, sleep 2/3. This includes expr's
transformed source, sorted Kyua metadata, modes and package tags. The new sleep
registration contains the existing fractional/hex/nonnumeric cases; cases were
not executed in this installation qualification.

Evidence: /usr/obj/usr/src/bazel-bin-imported-installs-20261029/qualification/
{dd,expr,sleep}/parity.json. Reproducers: bazel-bin-imported-install-qualification-
20261029; independent stages: bazel-bin-<component>-imported-tests-reference-20261029.
All use 16 jobs. Frontend review: existing target inputs and declared
script/filter/install rules suffice; normal Make test packaging automatically
picks up sleep's corrected registration. No frontend C/backend protocol changes.

No host installation or runtime execution. Remaining /bin aggregation/fixtures,
complete world/kernel/pkgbase, runtime and performance gates remain unfinished.
Make stays production/default.

## 2026-10-29: configurable pax Perl test and /bin discovery

Added pax/tests and bin/tests native installation archives. Pax's runtime
interpreter is the typed string flag tap_perl_interpreter (default
/usr/local/bin/perl from tap.test.mk). The script-wrapper rule accepts either
a literal interpreter or a BuildSettingInfo interpreter input; exactly one is
required. Configured interpreter values require an absolute path without
whitespace. Existing literal interpreter arguments remain supported.
Kyua generation can obtain required_programs from that same setting, avoiding
independent shebang/metadata policy. Existing metadata field order is preserved
when no configured override is used. The discovery file is the maintained
tests/Kyuafile, not a manually enumerated child list.

Independent Make comparisons pass for the default Perl path and the alternate
/opt/test-tools/bin/perl: two byte-identical payloads and three metadata records
each. Parent discovery: one payload/two records. Explicit Make
TAP_PERL_INTERPRETER input matches the native override. Perl was not executed.

Evidence: /usr/obj/usr/src/bazel-bin-pax-install-20261029-r2/qualification/pax,
bazel-bin-pax-alt-install-20261029/qualification/pax-alt, and
bazel-bin-index-install-20261029/qualification/index. Scripts/references use
bazel-pax-install-qualification-20261029 and bazel-bin-<variant>-install-reference-20261029.
A focused regression confirms the ls test archive remains byte-identical and
the ping pytest wrapper retains its literal interpreter arguments. Evidence:
bazel-script-settings-regression-20261029-r2/regression.json. Initial failed
Starlark escape and metadata-order checks remain in their original run directories.

All builds use the maintained frontend with 16 jobs. Existing typed settings
transport handles the new flag; no frontend C/backend protocol change. Shared
rules propagate declared settings into generated artifacts and cache keys.
Runtime Perl/pytest execution, remaining test integration, /bin/world/kernel
aggregation, pkgbase and performance gates remain open. Make stays default.

## 2026-10-29: native /bin aggregation and recursive installation

Added //bin:installation_archives using the native archive-set rule. It selects
39 unconditional children plus tcsh by default, with NIS/Sendmail/test gates.
Added the tcsh bool (default true, matching src.opts.mk), narrow child archive
visibility and missing chflags test installation. Existing cat/echo/ed/pkill/
pwait/timeout archives already include their test manifests; the parent does
not redundantly select separate test archives for these. Other test suites and
parent discovery are selected explicitly. No runtime Make interpretation.

Both maintained frontend builds and fresh recursive Make references passed:

| Variant | Native archives/artifacts | Metadata records | Non-ELF payloads | ELF/debug pairs |
| --- | --- | ---: | ---: | ---: |
| tests disabled | 40 / 120 | 1467 | 1318 | 39 |
| tests enabled | 59 / 177 | 2168 | 1977 | 41 |

Compared every metadata record and non-ELF byte, symlink target and hardlink
inode relation. Every ELF/debug pair validates; global/undefined symbols and
NEEDED/RPATH/RUNPATH/SONAME properties match Make. Declared hardlink aliases
(e.g. /bin/[) resolve to the canonical debug pair with byte/inode assertions.
Whole ELF/debug byte identity and runtime behavior are not claimed. Aggregate
metadata groups are complete and non-directory payload destinations are unique.

The audit caught an extra direct libelf NEEDED edge in native pkill. Removed
libelf from pkill's dynamic_deps; libkvm retains ownership of that dependency,
matching Make's LIBADD=kvm jail. Both rebuilt variants pass all comparisons.
Original mismatched ELF report remains retained.

Four Make SUBDIR/configured native selection comparisons passed: default 41
direct children, tests disabled 40, tcsh disabled 40, NIS/Sendmail enabled 43.
Selection evidence: /usr/obj/usr/src/bazel-bin-selection-20261029/selection.json
(script bin-selection-20261029.py). This query preceded removing redundant test
archive edges, which did not alter direct child coverage; final aggregate
uniqueness was checked independently.

Evidence: bazel-bin-aggregate-{no-tests,tests}-20261029-r2/aggregation-check.json
and frontend artifacts/logs; bazel-bin-recursive-qualification-20261029/
{r2-installation-parity.json,r2-elf-parity.json,tests-installation-parity.json,
tests-elf-parity.json}. Reproducers in that directory include make.py,
make-tests.py, verify-r2.py, verify-tests.py, elf-fixed.py and elf-tests.py.
References: bazel-bin-recursive-reference-20261029 and
bazel-bin-recursive-tests-reference-20261029. All compilation used 16 jobs.

Frontend review: existing format-5 target/setting/output groups handle the parent;
no C frontend or protocol change. No host installation or runtime tests performed.
Remaining world subtrees/kernel/modules, option/cross-architecture coverage,
pkgbase/publication, bootstrap independence and runtime/performance qualification
remain open. Make stays production/default.

### 2026-10-29 /sbin shell test installation coverage

Added native installation archives for existing md5, mdconfig, nvmecontrol,
route, bectl and growfs test suites, plus the /usr/tests/sbin discovery file.
Preserved mdconfig's required root user, route's exclusive execution metadata
and utils.subr, and growfs's configured TAP Perl interpreter (the same typed
setting controls its wrapper and Kyua requirement). All sources are declared;
no Make execution or metadata extraction occurs in the native build graph.

Qualification through maintained build-bsd bazel-test, 16 jobs:
`/usr/obj/usr/src/bazel-sbin-shell-installs-20261029`.
Fresh rootless Make references and comparison scripts:
`/usr/obj/usr/src/bazel-sbin-shell-install-qualification-20261029`.
The seven per-component qualification/parity.json reports prove 14 installed
payloads byte-identical and 21 metadata records equal to Make (paths, types,
ownership, permissions, flags and package tags). These are installation checks,
not execution of the privileged filesystem/network/ZFS tests. No host services,
disks or boot environments were modified.

Frontend review: existing format-5 target selection, typed interpreter setting,
artifact capture and metadata output groups cover these additions. No frontend
C/protocol change is needed; this batch exercised the maintained frontend.
Remaining /sbin work includes the devd compiled test, recursive archive and
option selection reconciliation, full parent installation comparison and
matching-kernel runtime qualification. No complete world/kernel/pkgbase claim;
Make remains production/default and BIP remains excluded.

### 2026-10-29 devd compiled test installation

Added //sbin/devd/tests:install_archive with native cc_binary and declared ATF
library dependencies. Preserved required_files=/var/run/devd.pid,
required_programs=devd, required_user=root and timeout=15 in installed Kyua
metadata. No program-source changes. This is a VM-only runtime candidate:
its cases connect to live devd sockets and create/destroy md devices.

Maintained frontend qualification:
`/usr/obj/usr/src/bazel-devd-test-install-20261029-r2`.
Fresh Make reference: `bazel-sbin-devd-tests-reference-20261029` under the same
object root. Scripts: `bazel-devd-test-qualification-20261029`.
The qualification/devd reports establish eight equal installation metadata
records, exact Kyuafile bytes, a valid split-debug pair, and equal global/undefined
symbols and NEEDED/RPATH/RUNPATH/SONAME. Instruction equivalence and runtime
execution are not claimed. Initial archive failure is retained: missing debug
parent-directory policy was fixed by declaring Make's owned directory records,
without weakening the archive validator.

Frontend review: existing format-5 target/artifact handling covers this target;
no build-bsd C or protocol change required. No production backend switch.
Further source inspection found sbin/devd/BUILD.bazel exports only the NVMe
configuration: devd itself is still unmigrated. The next dependency is a native
devd executable including lex/yacc generation, its DTrace provider, option-selected
configuration groups and manuals, before complete /sbin aggregation can qualify.
A BUILD file's existence alone must not be counted as a migrated program.

### 2026-10-29 native devd executable and generators

Added //sbin/devd:devd using native cc rules, source-built yacc/lex/m4 execution
tools, explicit generated parser source/header/report outputs, declared C++ and
libutil dependencies, and the existing DTrace object transformation. DTrace is
selected by the maintained typed build setting; no generated source is checked
in or imported from a prior Make build. Production sources are unchanged.

Maintained frontend builds (16 jobs) succeeded in both configurations:
`/usr/obj/usr/src/bazel-devd-native-20261029` and
`/usr/obj/usr/src/bazel-devd-native-no-dtrace-20261029`.
The first contains dof.json and make-comparison.json. Fresh rootless Make
reference is bazel-devd-native-reference-20261029 under the same object root.
Provider attributes and complete probe schemas/site counts match Make. Both
binaries pass function-address/range and patched-instruction checks for nine
ordinary and twelve enabled sites. Dynamic dependencies and search paths match.
The disabled variant's no-dof.json proves no embedded DOF section. No live probe
firing, daemon execution, instruction equivalence or full installation claim.

The DTrace-enabled qualification uses the existing experimental section archive
setting; it does not promote that feature or Bazel to a production default.
Configuration groups, two manuals, debug installation and full /sbin parent
selection remain to be integrated and compared. Existing NVMe configuration
manifest stays available to its package consumer. Frontend review: existing
format-5 native targets and typed DTrace settings suffice; no C/protocol change.

### 2026-10-29 devd installation and configuration selection

Added //sbin/devd:install_archive for the native executable/debug pair, both
manuals and configuration groups. Configuration inventory declares source,
destination, package owner and option once; selections use maintained native
build settings. NVMe's existing manifest remains available to its consumer.
The archive is amd64-compatible like its executable. On that architecture,
power_profile.conf is installed independently of MK_ACPI, matching Make.
Other architecture expansion must reconcile Make's architecture selections
(including apple.conf on powerpc) before removing that compatibility constraint.

Qualification through maintained build-bsd, 16 jobs:
`/usr/obj/usr/src/bazel-devd-install-20261029`: 18 non-ELF payloads byte-equal to
fresh Make and 23 distinct metadata records equal; valid installed debug pair,
matching global/undefined symbols and dynamic dependencies/search paths.
`/usr/obj/usr/src/bazel-devd-install-minimal-20261029`: ACPI, AUTOFS, BLUETOOTH,
HYPERV, SOUND, USB and ZFS disabled; 10 payloads and 15 metadata records equal
to a fresh Make stage with those options. power_profile.conf remains present.
Scripts are in bazel-devd-install-qualification-20261029 under the object root;
per-run reports in qualification/devd. Comparisons include package/config tags,
owner/group, mode, flags and directory records. No live devd execution claimed.

The separate devd test archive is not duplicated in this program archive;
/sbin aggregation must select it when tests are enabled. Integration of the
parent and full recursive comparison remain pending. The frontend's existing
format-5 target selection and typed options were exercised; no C/protocol or
production-backend change required. This does not complete world/pkgbase,
full runtime qualification, cross-compilation or performance gates.

### 2026-10-29 /sbin audit: md5 archive and Casper option

Added //sbin/md5:install_archive around its existing native installation
inventory. Corrected unconditional Casper dependencies/defines in both dynamic
md5 and its static consumption candidate to follow the maintained casper setting.
The dynamic target selects Casper shared libraries only when enabled. No utility
source changed; Make remains the default production backend.

Both maintained frontend runs (16 jobs) passed:
`/usr/obj/usr/src/bazel-md5-install-20261029` and
`/usr/obj/usr/src/bazel-md5-no-casper-20261029`.
Fresh Make stages: bazel-md5-install-reference-20261029 and
bazel-md5-no-casper-reference-20261029 under the same object root.
Scripts: bazel-md5-install-qualification-20261029; reports in each run's
qualification/md5. Each variant matches 50 metadata records and 24 non-ELF
manual payloads, with all 46 binary/manual hardlink relationships checked against
Make stage inode identity. Installed debug linkage, global/undefined symbols,
and NEEDED/RPATH/RUNPATH/SONAME match. Disabled output needs only libc/libmd;
enabled output also needs libcasper/libcap_fileargs. Static candidate's option
selection changed consistently but was not separately rebuilt in this batch.
No runtime or full instruction equivalence claimed.

Parent audit: reroot_seed is an INTERNALPROG, consumed by init's declared payload
edge, and should not receive a standalone installation archive. nvmecontrol's
archive already includes all four modules. Existing program archives that
include tests must not be combined with duplicate standalone test archives.
/sbin parent integration and full recursive comparison remain pending.
Frontend review: format-5 target handling and the existing typed casper option
cover this work; no frontend C/protocol change required.

### 2026-10-29 /sbin native parent archive graph

Added //sbin:installation_archives with explicit native component selection,
optional program groups and test archives. Existing recursive program archives
retain their tests; separately installed suites are selected only once. Internal
reroot_seed is reached through init, not installed separately. Child archive
visibility is narrowly extended to //sbin:__pkg__.

Added quotas and bearssl settings (defaults yes/no respectively), veriexec
tri-state auto/yes/no following BearSSL by default, and an IP-any selector for
ping. Initial run incorrectly enabled BearSSL and hit the existing explicit
libsecureboot policy requirement; fixed the default against src.opts.mk and
retained the failed evidence. Enabling veriexec still needs a supplied policy;
that variant has not been qualified in this batch.

Maintained build-bsd runs with 16 jobs succeeded:
/usr/obj/usr/src/bazel-sbin-aggregate-20261029-r2 (tests disabled) and
/usr/obj/usr/src/bazel-sbin-aggregate-tests-20261029 (test installation enabled).
The disabled run contains 73 archives/219 artifacts and 352 distinct non-directory
payload paths, with no duplicates. Per-run aggregation-check.json records counts
and duplicate-path checks. Building installed tests does not execute them.

This is graph/build integration evidence, not full /sbin qualification. Fresh
recursive Make references, full payload/debug/metadata comparison, option-selection
matrix, matching-kernel runtime and resource/performance qualification remain.
Frontend review: existing format-5 typed build-settings and metadata output groups
cover the aggregate without C/protocol changes. Make remains production/default.

Tests-enabled inventory: 81 archives, 243 artifacts, 988 distinct non-directory paths; no duplicate payload paths.

### 2026-10-29 recursive /sbin Make parity

Fresh recursive rootless Make builds and installation comparisons now pass for
both test configurations. Tests disabled: 377 distinct metadata records, 152
non-ELF payloads and 78 executable/module split-debug pairs. Tests enabled:
1048 metadata records, 774 non-ELF payloads and 85 split-debug pairs. Metadata
covers paths, types, owner/group, mode, package tags and flags; non-ELF bytes,
symlinks and Make hardlink inode identity are checked. ELF checks validate debug
linkage, global/undefined symbols and NEEDED/RPATH/RUNPATH/SONAME; they do not
establish complete instruction equivalence or runtime behavior.

Real discrepancies fixed without weakening comparisons:
- devfs configuration directory package ownership for /etc/defaults;
- NVMe program/module debug directory package ownership;
- bectl/zfsbootcfg debug directory package ownership;
- dhclient test debug parent directory missing dbg tag;
- mdconfig redundant direct libbsdxml/libsbuf dependencies (libgeom retains its
  own declared dependencies; Make LIBADD is util geom).

Evidence roots under /usr/obj/usr/src:
- bazel-sbin-recursive-reference-20261029 and
  bazel-sbin-recursive-tests-reference-20261029: fresh Make stages and time -l logs.
- bazel-sbin-aggregate-20261029-r3 and
  bazel-sbin-aggregate-tests-20261029-r3: final maintained frontend artifacts.
- bazel-sbin-recursive-qualification-20261029: scripts, original failing reports,
  r3-installation-parity.json, r3-elf-parity.json,
  tests-r3-installation-parity.json and tests-r3-elf-parity.json.

No host installation or privileged tests performed. Resource logs are retained
but not a controlled Make/Bazel performance comparison. Option-selection matrix,
veriexec policy input variants, matching-kernel runtime tests, complete world,
kernel, pkgbase publication and performance gates remain. Existing format-5
frontend target/metadata handling covered these corrections; no C/protocol change
required. Make remains production/default; BIP remains excluded.

### 2026-10-29 /sbin option selection and next parent audit

Twelve configured archive-selection comparisons now match Make's evaluated
SUBDIR: default, tests disabled, IPv4-only, IPv6-only, no IP, OpenSSL disabled,
crypt disabled, CDDL disabled, HAST/DUMMYNET/PF/QUOTAS/ZFS disabled together,
BearSSL enabled, explicit veriexec enabled, and BearSSL enabled with veriexec
explicitly disabled. Internal reroot_seed and .WAIT are excluded from the
installed-child comparison because init consumes the former and the latter is
a Make ordering marker. This checks selected children, not installation or
runtime behavior under every combination.

Evidence: /usr/obj/usr/src/sbin-selection-20261029.py and
/usr/obj/usr/src/bazel-sbin-selection-20261029/{selection.json,*.stdout,*.stderr}.
Veriexec analyses explicitly selected libsecureboot/tests:trust-policy.json and
bearssl-root.pem, both public test fixtures. No implicit trust was added and no
production verified-boot qualification is implied. The no-policy analysis failure
remains recorded in the earlier aggregate run.

Next parent is /usr/bin. Make's default evaluated SUBDIR contains 242 direct
components in this configuration. Audit evidence is
/usr/obj/usr/src/bazel-usr-bin-audit-20261029.json. Fifty selected directories
lack a local BUILD.bazel, including su/passwd/newgrp, netstat/sockstat, mkimg,
mkuzip, bmake, clang, kyua and other programs or recursive groups. Some may have
native implementations elsewhere; do not count them as converted until those
edges and recursive installation contents are reconciled. Eight more BUILD files
have no literal archive name; macros and aggregate structure need inspection.
BUILD presence or a regex count alone is not conversion evidence.

No implementation changed in this audit turn; existing frontend typed settings
were exercised via the recorded configured-query commands. No new frontend
protocol requirements identified. Make remains production/default. Full world,
kernel, packaging, runtime and performance gates remain incomplete.

### 2026-10-29 /usr/bin resizewin, runat, mdo, pom and mididump

Added five native cc_binary and installation archive targets with source-owned
manual/debug/package metadata. pom and mididump declare libm; pom additionally
declares Capsicum helper headers. No production source changes or Make invocation
in native actions. Parent /usr/bin integration remains pending.

Maintained frontend build, 16 jobs:
/usr/obj/usr/src/bazel-usr-bin-small-20261029.
Fresh rootless Make references are bazel-<program>-native-reference-20261029
under /usr/obj/usr/src; scripts are in bazel-usr-bin-small-qualification-20261029.
Per-program qualification/<program>/{parity.json,elf-parity.json} records five
equal metadata records, exact compressed manual bytes, a valid split-debug pair,
and matching global/undefined symbols and NEEDED/RPATH/RUNPATH/SONAME. Across
the batch: 25 per-component records, five manuals and five ELF/debug pairs.
Shared directory records are counted separately here, not as distinct aggregate
paths. Full instruction equivalence and runtime behavior are not claimed.

mdo, terminal interaction and MIDI/device operations were not executed on the
host. Those need appropriate runtime qualification. No host installation,
credential changes or service actions occurred. Existing format-5 target/artifact
handling covers this batch; no frontend C/protocol change required. Make remains
production/default; complete /usr/bin, world/kernel/pkgbase and performance gates
remain open.

### 2026-10-29 command, lorder and ssh-copy-id installation

Added native script/manual installation archives for command, lorder and
ssh-copy-id. Existing script bytes are installed verbatim with maintained names,
permissions and package ownership. lorder includes its existing ATF shell suite
when tests are enabled, retaining required_programs=nm metadata. No SSH connection,
key installation or host account change was performed.

Maintained frontend qualification, 16 jobs:
/usr/obj/usr/src/bazel-usr-bin-scripts-20261029-r2.
Fresh Make reference roots are bazel-<component>-scripts-reference-20261029 under
/usr/obj/usr/src. Scripts are in bazel-usr-bin-scripts-qualification-20261029;
per-component qualification reports prove all seven payload files byte-identical
and eleven per-component metadata records equal. The initial comparison caught
missing package-owned /usr/bin directory records; fixed these in the native
archives and retained the initial run and comparison script. These scripts have
no compiled ELF payloads. lorder's test body, wrapper and discovery file are
installation-qualified, not runtime-qualified.

Frontend review: existing format-5 target capture and metadata output groups
cover these targets, with no C/protocol change needed. /usr/bin parent assembly,
remaining utilities, runtime and performance qualification are still open; Make
remains production/default and ports retain Make.

### 2026-10-29 newgrp and passwd native installation

Added native newgrp (crypt/util) and passwd (PAM) build/install targets. Preserved
passwd's 4555/schg installation metadata and NIS-selected yppasswd symlink/manual
hardlink. Added explicit enable_suid_newgrp boolean (default false), matching
Make's ENABLE_SUID_NEWGRP opt-in: default 0555/no flag, enabled 4555/schg.
No production source change. Installation is staged, never applied to the host.
Make's beforeinstall removal of old immutable flags is not performed by archive
construction; actual upgrade/install application remains a separate gate.

Maintained frontend builds, 16 jobs, under /usr/obj/usr/src:
- bazel-account-utils-20261029-r2: default; five metadata records and one exact
  manual payload per utility, valid debug pairs, matching global/undefined symbols
  and dynamic interfaces.
- bazel-account-utils-options-20261029: NIS and setuid newgrp enabled; five/seven
  metadata records for newgrp/passwd, exact manual payloads, symlink target and
  manual hardlink identity, plus the same ELF/debug checks against fresh Make.
Scripts: bazel-account-utils-qualification-20261029. Fresh references:
bazel-{newgrp,passwd}-{native,options}-reference-20261029. Initial failed build
is retained: conditional manual aliases cannot be passed to the utility macro's
static alias parameter; explicit conditional link entries use the existing
chpass pattern without broadening the shared macro.

Frontend review: existing format-5 typed settings accept enable_suid_newgrp and
NIS; normal target/artifact handling was exercised, no C/protocol change needed.
No authentication, password modification or group switching was executed. Runtime
PAM/audit/credential semantics, actual upgrade handling and complete /usr/bin
integration remain unqualified. Make remains production/default.

### 2026-10-29 native su with audit and DTrace

Added //usr.bin/su:install_archive, using native compilation with declared
PAM/util dependencies, optional libbsm and USE_BSM_AUDIT, and optional su provider
header/object transformation and WITH_DTRACE. Preserved root-owned 4555/schg
installation metadata. No production sources changed; no su execution or host
installation performed.

Maintained frontend qualification (16 jobs) under /usr/obj/usr/src:
bazel-su-20261029 and bazel-su-no-observability-20261029. Fresh Make references
are bazel-su-native-reference-20261029 and bazel-su-no-observability-reference-20261029.
Scripts: bazel-su-qualification-20261029. Both variants match five installation
metadata records, compressed manual bytes, debug linkage, global/undefined
symbols and dynamic dependencies/search paths. Default provider attributes and
probe schemas match Make; both native and Make binaries validate two ordinary
probe sites against function bounds and patched instructions. Disabled output
has no DOF section, no audit_submit undefined symbol and no direct libbsm need.
Reports are in each run's qualification/su directory.

The DTrace run uses the existing experimental section archive setting. This does
not promote that mechanism or Bazel to production default. No live probe firing,
audit event emission, PAM authentication, session setup or credential transition
has been qualified. Full /usr/bin integration and system/runtime/performance
qualification remain incomplete. Frontend review: existing format-5 targets and
audit/DTrace settings cover the change; no frontend C/protocol change required.

### 2026-10-29 rctl, who and gcore native migration

Added native build/install archives for rctl, who and gcore, retaining declared
libutil/libsbuf dependencies and manuals (rctl in section 8). The amd64 gcore
target compiles both native and ELF32 writers, matching Make. Its elf32core.c
textually includes elfcore.c; an explicit textual_hdrs dependency supplies that
input to the sandbox while elfcore.c remains separately compiled. The initial
missing-include failure is retained; no ambient include path or sandbox bypass.

Maintained frontend build (16 jobs):
/usr/obj/usr/src/bazel-query-utils-20261029-r2.
Fresh Make reference roots: bazel-{rctl,who,gcore}-native-reference-20261029 under
/usr/obj/usr/src. Comparison scripts: bazel-query-utils-qualification-20261029.
Per-component reports in qualification/<program> prove five equal metadata
records, one byte-identical compressed manual, a valid split-debug pair and
matching global/undefined symbols and dynamic dependencies/search paths for each
program. Three programs total; per-component shared directory records are not a
unique aggregate path count. No complete instruction equivalence claim.

No resource-limit modification, process attachment/core dumping, login database
query or host installation performed. Runtime system interactions remain pending.
Frontend review: format-5 target/artifact handling suffices; no C/protocol change
required. /usr/bin parent integration, remaining world/kernel/pkgbase work and
runtime/performance gates remain open. Make remains production/default.

### 2026-10-29 w and uptime native build/install

Added //usr.bin/w:install_archive, compiling local w/pr_time/proc_compare sources
and the declared //bin/ps:fmt.c source with its ps.h/extern.h inputs. Source exports
are restricted to //usr.bin/w:__pkg__. The first sandbox build exposed the missing
transitive ps extern.h; declared it explicitly without broadening include paths.
Preserved uptime as a hardlink to w and installed its distinct manual source.

Maintained frontend, 16 jobs: /usr/obj/usr/src/bazel-w-20261029-r2.
Fresh rootless Make reference: bazel-w-native-reference-20261029 under that object
root. Scripts: bazel-w-qualification-20261029. qualification/w reports establish
seven equal metadata records, both manual payloads byte-identical, Make hardlink
inode identity and equal native alias bytes, valid debug linkage, and matching
global/undefined symbols and dynamic dependency/search-path properties. Initial
failed sandbox evidence is retained. No instruction or live process/session-query
behavior equivalence claimed, and no host installation performed.

Frontend review: existing format-5 target/artifact path covers this change;
no C/protocol update needed. /usr/bin parent assembly, remaining components,
world/kernel/pkgbase, runtime and performance qualification remain incomplete.
Make remains production/default.

### 2026-10-29 sockstat executable, Casper and DTrace

Added native sockstat compilation and program installation with jail/libxo,
explicit Casper service headers, conditional Casper/service linkage and
WITH_CASPER, and socketsnapshot provider transformation with
WITH_COVERAGE_DTRACE. Header-only requirements remain declared when Casper is
disabled, matching the command's unconditional service-header includes. No
production source modifications. Existing compiled test suite still needs native
migration and installation before the complete component is qualified.

Maintained frontend builds (16 jobs) under /usr/obj/usr/src:
bazel-sockstat-20261029 and bazel-sockstat-disabled-20261029. Fresh Make roots:
bazel-sockstat-native-reference-20261029 and bazel-sockstat-disabled-reference-20261029.
Scripts: bazel-sockstat-qualification-20261029. Each variant matches five metadata
records, exact manual bytes, valid debug linkage, global/undefined symbols and
dynamic dependencies/search paths. Enabled provider schemas/attributes match
Make; two ordinary and two enabled sites validate against function bounds and
patched instructions in both builds. Disabled output has no DOF or direct
Casper/service shared-library dependencies. Reports in qualification/sockstat.

DTrace qualification uses the existing experimental section archive setting.
No live sockets, Casper IPC, tracing or audit behavior tested. Full instruction
parity, compiled tests, /usr/bin parent integration and broader runtime/performance
gates remain. Frontend review: existing format-5 settings/artifact capture cover
this target; no C/protocol change required. Make remains production/default.

### 2026-10-29 sockstat compiled tests and recursive installation

Added the maintained sockstat_test program and eleven individual native Bazel
ATF tests, compiling the real shared sockstat.c parsing implementation with
explicit libxo/ATF inputs. All eleven cases executed and passed in
/usr/obj/usr/src/bazel-sockstat-tests-20261029. Final archive layout run
bazel-sockstat-tests-20261029-r2 reused all eleven successful cached results;
it is not counted as a second execution. Cases cover single/multiple ports,
ranges, endpoints and malformed/out-of-range inputs. No live socket service
or host credentials are used by these parsing cases.

Added //usr.bin/sockstat:installation_archives, collecting the existing program
archive and optional test archive. Separate archives preserve both utilities and
tests package ownership for shared debug directories; the initial combined
dictionary overwrote one owner and failed full Make comparison. Retained that
failure and fixed structure without weakening metadata checks. Future /usr/bin
parent must consume installation_archives for recursive coverage.

Fresh recursive Make reference: bazel-sockstat-tests-reference-20261029 under
/usr/obj/usr/src. Scripts/reports: bazel-sockstat-tests-qualification-20261029.
Final r2-installation-parity.json matches all thirteen distinct metadata records
and both non-ELF payloads; r2-elf-parity.json validates two debug pairs and matching
global/undefined symbols and dynamic interfaces. Test assertions/source unchanged.

Frontend review: maintained format-5 test inventory/execution, target selection,
and archive metadata capture exercised with 16 jobs; no C/protocol changes needed.
Live socket snapshots, Casper behavior, full instruction equivalence, /usr/bin
parent, world/kernel/pkgbase and performance gates remain incomplete. Make remains
production/default.

### 2026-10-29 native netstat and generated symbol tables

Added native netstat with declared AWK actions over nlist_symbols, explicit
generated-header dependencies and optional IPv4/IPv6, OFED, PF, Netgraph,
Netlink and jail sources/defines/libraries. Added netgraph_support setting,
independent from the Netgraph build-selection setting, matching the Make
MK_NETGRAPH_SUPPORT branch. Native symbol/definition AWK scripts preserve Make's
transformation; no Make parsing or generated-file import occurs during builds.

Maintained frontend default build, 16 jobs:
/usr/obj/usr/src/bazel-netstat-20261029. Fresh Make reference:
bazel-netstat-native-reference-20261029 under the same object root. Scripts:
bazel-netstat-qualification-20261029. Five metadata records, exact compressed
manual bytes, debug linkage, global/undefined symbols and dynamic dependencies
match Make. generated-parity.json proves byte-identical nl_symbols.c and nl_defs.h
from the two independent builds, including hashes. No production source changes.

No Casper or DTrace feature exists in this command's maintained Makefile; none
was introduced. Default configuration only is qualified here. Reduced protocol
and support combinations, live network/kernel queries, complete /usr/bin parent,
world/kernel/pkgbase and performance gates remain outstanding. Frontend review:
existing typed settings/native target handling cover the change; no C/protocol
update required. Make remains production/default; no host installation performed.

### 2026-10-29 reduced netstat and native mkuzip

Qualified netstat with INET_SUPPORT, INET6_SUPPORT, NETGRAPH_SUPPORT,
NETLINK_SUPPORT, JAIL, OFED and PF disabled together. Maintained frontend run:
/usr/obj/usr/src/bazel-netstat-minimal-20261029. Fresh Make reference:
bazel-netstat-minimal-reference-20261029; scripts in bazel-netstat-qualification-20261029.
Five metadata records, exact manual bytes, valid debug linkage, symbols and
dynamic interfaces match; direct jail/netgraph dependencies are absent as expected.
This qualifies the default and all-disabled endpoints, not every mixed combination
or live networking behavior.

Added //usr.bin/mkuzip:install_archive with all ten maintained C sources,
explicit headers and lzma/md/z/zstd/threading dependencies. Maintained frontend
run (16 jobs): /usr/obj/usr/src/bazel-mkuzip-20261029. Fresh rootless Make reference:
bazel-mkuzip-native-reference-20261029; scripts in bazel-mkuzip-qualification-20261029.
qualification/mkuzip reports establish five matching metadata records, exact
manual bytes, valid debug pairing, equal global/undefined symbols and matching
dynamic dependencies/search paths. No source changes or host installation.
Compression round trips, output image compatibility/mounting, resource/performance
and complete /usr/bin integration remain pending.

Frontend review: existing format-5 native targets/settings and metadata capture
cover both qualifications; no C/protocol changes needed. Make stays production/
default, and world/kernel/pkgbase/runtime/performance gates remain open.

### 2026-10-29 etdump shared CD9660 inputs

Added //usr.bin/etdump:install_archive with local sources and explicit shared
makefs cd9660_conversion.c. Narrow header providers expose makefs/CD9660 and
El Torito include layouts without broad source include paths. New
usr.sbin/makefs/BUILD.bazel exposes shared inputs only; makefs itself remains
unmigrated and must not be counted as complete from BUILD-file presence.

Maintained frontend run (16 jobs): /usr/obj/usr/src/bazel-etdump-20261029.
Fresh Make reference: bazel-etdump-native-reference-20261029 under the object
root. Scripts: bazel-etdump-qualification-20261029. qualification/etdump reports
prove five equal metadata records, exact compressed manual bytes, valid debug
pairing, global/undefined symbol equality and matching dynamic interfaces.
No production source edits, host installation or image/device operations.

Actual El Torito image parsing, malformed image handling and boot-media integration
remain runtime gates. Existing format-5 target/artifact capture covers the new
target; no build-bsd C/protocol change needed. /usr/bin parent, remaining world,
kernel, pkgbase and performance qualification remain incomplete; Make remains
production/default.

### 2026-10-29 mkimg native program

Added //usr.bin/mkimg:install_archive with all five format backends (qcow, raw,
vhd, vhdx, vmdk), all five schemes (apm, bsd, ebr, gpt, mbr), common sources,
sparse-write definition and maintained version constant. Explicit disk header
provider in sys/sys preserves its existing package/glob boundaries. No generated
backend substitutes, omitted format sources or production source changes.

Maintained frontend run (16 jobs): /usr/obj/usr/src/bazel-mkimg-20261029.
Fresh rootless Make reference: bazel-mkimg-native-reference-20261029 under the
object root; scripts in bazel-mkimg-qualification-20261029. qualification/mkimg
reports establish five matching metadata records, exact compressed manual bytes,
valid debug linkage, matching global/undefined symbols and dynamic dependencies.
No host installation, disk writes or image creation performed in this batch.

The existing mkimg shell tests, transformed hex fixtures and generated 4MiB
partition fixture are NOT yet migrated. They must be native declared generation
and test actions, preserving assertions rather than rebasing expected outputs.
Image compatibility, boot-media behavior and resource/performance gates remain
pending. Future /usr/bin parent must include that recursive test installation.
Frontend review: existing format-5 target/artifact handling suffices for this
program target; no C/protocol change needed. Make remains production/default;
complete world/kernel/pkgbase integration remains unfinished.

### 2026-10-29 mkimg test migration in progress: execution ABI gate

Added native declarations for both maintained shell test programs, Kyuafile,
all 160 wildcard-selected .hex fixtures (same sed transformation as Make), and
the 4 MiB partition fixture using source-built jot. Separate program and test
installation archives preserve package directory ownership. The recursive
installation_archives target selects tests through the existing tests setting.
Declared 160 image matrix cases plus all 10 partition-offset regression cases;
the baseline-mutating rebase case is deliberately not a test target. Expected
image files and production sources have not been changed.

This work is NOT qualified. Fresh rootless Make reference completed at
/usr/obj/usr/src/bazel-mkimg-tests-reference-20261029, with orchestration and
pending comparison scripts in bazel-mkimg-tests-qualification-20261029.
Frontend run bazel-mkimg-tests-20261029 failed because execution jot required
cap_rights_intersect from newer libc. Added explicit source-built libc/libsys
runtime inputs. Run bazel-mkimg-tests-20261029-r2 then reached the documented
host/source Capsicum ABI incompatibility: cap_rights_is_valid(src) assertion
in cap_rights_intersect. bazel-mkimg-runtime-20261029 reproduces that failure
before tests execute. No tests passed, no completed test archive exists, and
installation parity is still pending. All three failure records are retained.

Next: qualify a host-compatible execution-toolchain input for generators
rather than treating a target-sysroot executable as universally host-runnable;
then finish archive parity and run the native suite with a matching kernel.
Do not disable Capsicum, suppress the assertion, substitute generated expected
images, or count an analysis/build attempt as runtime proof. The earlier
2026-10-28 Capsicum probe documents the semantic rights reassignment.

Frontend review: existing format-5 explicit targets/tests/settings and SDK
receipt handling support these declarations; no build-bsd C/protocol changes
are needed for this batch. Any execution SDK changes must go through the
maintained preparation path and receipts. Make stays production/default.

### 2026-10-29 mkimg test installation parity; runtime still open

Resolved the generator execution ABI problem through the existing explicit
SDK additional_execution_tools input. The fixture action now requires
@bsd_sdk//toolchain:extra_jot and its inspected runtime closure; it does not
search PATH or switch automatically to a host command. The fresh SDK at
/usr/obj/usr/src/bazel-mkimg-exec-sdk-20261029 selects /usr/bin/jot in tools.json
and fingerprints it and its host dependencies. This is a bootstrap execution
input, not a Bazel-built jot runtime qualification. Native tests still select
the source-built jot and other source-built programs. The general native exec
C++ toolchain still uses the target SDK; separating compatible bootstrap tools
from target-program execution remains necessary beyond this specific generator.

Frontend archive run bazel-mkimg-tests-20261029-r3 found exact fixture/script
bytes but a Kyuafile ordering mismatch. Corrected ordering without relaxing
comparison. Final bazel-mkimg-tests-20261029-r4 passes 170 distinct metadata
records, 165 non-ELF payloads and one program/debug ELF pair against fresh
rootless Make. Reports: bazel-mkimg-tests-qualification-20261029/
r4-installation-parity.json and r4-elf-parity.json. fixture-inventory.json
confirms the maintained matrix corresponds to all 160 source fixtures and
records the 10 offset cases. Prior failed reports remain intact.

Native runtime attempt bazel-mkimg-runtime-20261029-r2 builds the complete
native_size_absolute_offset target but fails in ATF startup before its body:
cap_rights_is_valid(src) assertion, followed by failure to determine the test
source directory. The failure-test-reports directory retains the test result.
This is the previously diagnosed source/host Capsicum rights ABI mismatch;
none of the 170 runtime cases is qualified by this batch. Do not repeat all
cases on this incompatible host or count archive parity as image correctness.
A matching-kernel VM remains the runtime gate. No host installation occurred.

Frontend review: the maintained SDK staging helper and format-5 input flow
already support the extra execution tool. Updated bsd-build(8) to document the
explicit jot selection and bootstrap/runtime distinction. No C protocol
change is needed. Resource logs are retained, but this is not a controlled
CPU/memory/disk-I/O comparison. Make remains production/default.

### 2026-10-29 recursive bsdiff installation aggregation

Added //usr.bin/bsdiff:installation_archives for both existing native child
programs, bsdiff and bspatch. Their archive targets now expose narrow parent
visibility. This closes recursive installation coverage, not two new binary
conversions. The maintained parent Makefile installs exactly those children;
its separate Bazel roundtrip tests are not part of Make's installed subtree.
No program, library, probe, audit or runtime policy changed.

Maintained frontend run /usr/obj/usr/src/bazel-bsdiff-aggregate-20261029
(16 jobs) passed. Fresh recursive Make reference is
bazel-bsdiff-native-reference-20261029; orchestration/comparison reports are in
bazel-bsdiff-aggregate-qualification-20261029. Comparison establishes eight
distinct metadata records, exact bytes for both compressed manuals, and two
program/debug ELF pairs with valid debug linkage and matching global/undefined
symbols and dynamic dependencies. Shared directory records are reconciled;
no per-package metadata is discarded. No additional runtime or performance
qualification was performed. Existing roundtrip tests remain unchanged.

Frontend review: existing format-5 explicit targets, saved artifacts and
archive-set handling cover this integration; no build-bsd C/manual/protocol
change is needed. Future usr.bin aggregation must consume this parent target.
Make remains production/default and whole-world/kernel/pkgbase/runtime gates
remain open. No host install, upgrade, reboot or publication occurred.

### 2026-10-29 morse, random and vtfontcvt native installation

Added native program/install targets for morse, random (including randomize_fd
and its header), and vtfontcvt. The latter uses the exact maintained common
LZ4 source and an explicit header provider, with narrow source visibility;
there was no existing BUILD package at that path or ancestor below the root.
Manual sections remain 6, 6 and 8 respectively. No program sources changed.

Initial bazel-usr-bin-misc-20261029 analysis caught a rule-edit error: the LZ4
header provider was incorrectly duplicated in dynamic_deps. Removed that
invalid shared-library dependency; retained the ordinary compilation dependency.
Successful maintained frontend run (16 jobs) is
/usr/obj/usr/src/bazel-usr-bin-misc-20261029-r2. Each fresh rootless Make
reference is bazel-<program>-native-reference-20261029. Scripts are retained in
bazel-usr-bin-misc-qualification-20261029. Each program passes five installed
metadata records, exact compressed manual bytes, valid separate debug linkage,
and matching global/undefined symbols and dynamic dependency fields (libc only).
Saved comparison reports are under the successful run's qualification/<program>.
This establishes installation/ELF interface parity, not instruction identity.

No runtime tests or device operations were performed. Morse speaker/TTY output,
locale behavior, randomization semantics and font conversion/compression remain
runtime gates. Resource logs do not constitute comparative performance proof.
Frontend review: existing format-5 explicit target/artifact handling suffices;
no C/protocol/manual change is required. Make remains production/default.
Whole-world/kernel/pkgbase integration remains unfinished.

### 2026-10-29 wg native program/install target

Added //usr.bin/wg:install_archive with all 12 maintained C sources and explicit
local headers, including both curve25519 implementation headers and the FreeBSD
IPC backend. Uses native libnv and its shared implementation. RUNSTATEDIR stays
_PATH_VARRUN via forced paths.h inclusion, matching Make rather than embedding a
runtime directory string in Bazel. The maintained section-8 manual is installed.
No production or cryptographic source changes were made.

Maintained frontend run /usr/obj/usr/src/bazel-wg-20261029 (16 jobs) passes.
Fresh rootless Make reference: bazel-wg-native-reference-20261029; scripts:
bazel-wg-qualification-20261029. Saved qualification/wg reports establish five
matching installed metadata records, exact compressed manual bytes, valid ELF
separate-debug linkage, matching global/undefined symbols and dynamic fields.
Both implementations require libc.so.7 and libnv.so.1. No instruction-level,
cryptographic-vector, tunnel, IPC, live interface or performance proof follows
from these checks. No network/interface mutation or host installation occurred.

Frontend review: the existing format-5 target/artifact pathway supports this
program without a C/protocol/manual change. Make remains production/default;
whole-world/kernel/pkgbase and runtime qualification remain incomplete.

### 2026-10-29 iscsictl and internal iscsiutil native integration

Added native iscsictl, its declared yacc source/header/report and case-insensitive
lex generation, both maintained manuals, and iscsi package ownership. Added the
seven-source internal libiscsiutil with regular/PIE variants and explicit iSCSI
protocol/ioctl headers. No installed shared library is introduced. Existing
kernel-interface generation in sys/dev/iscsi is preserved.

First build bazel-iscsictl-20261029 found the missing PIE variant at link time.
The fresh Make link explicitly uses libiscsiutil_pie.a; native iscsictl now uses
the separately declared iscsiutil_pie variant (-fPIE and PIC). Successful frontend
run /usr/obj/usr/src/bazel-iscsictl-20261029-r2 used 16 jobs. Fresh rootless Make
reference: bazel-iscsictl-native-reference-20261029. Scripts and retained generated
outputs: bazel-iscsictl-qualification-20261029. Installation comparison passes six
metadata records, exact compressed bytes for both manuals, valid debug linkage,
matching global/undefined symbols and dynamic dependencies (libc, md, util, xo).
The library PIE consumer is qualified at this level; independent regular/archive
variant parity and full library runtime coverage are not established here.

Complete parse.c, token.c and y.tab.h comparisons pass with only explicitly
listed #line filename aliases normalized; line numbers and all other contents
remain compared. y.tab.h is byte-identical. generated-parity.json retains hashes
and scope. Both generators emit the maintained undefined-PCP grammar warning;
no grammar correction or suppression was introduced as part of migration.

No live iSCSI/CAM/session operations were performed. Authentication, session
management, config error paths and runtime/performance qualification remain open.
Frontend review: existing format-5 target/artifact pathway and declared generator
rules support this integration without build-bsd C/protocol/manual changes.
Make remains production/default; whole-system completion is not claimed.

### 2026-10-29 genl and quota native installation

Added native genl (both maintained sources and local header) and quota. Quota
uses native rpcsvc/util and the existing generated rquota public header, with
narrow visibility extended to its new consumer. Root ownership and mode 4555
are preserved in installation metadata. No production source changes occurred.
Future usr.bin parent selection must retain Make's NETLINK/QUOTAS conditions.

Initial bazel-genl-quota-20261029 analysis correctly rejected the missing quota
header visibility; the corrected run is
/usr/obj/usr/src/bazel-genl-quota-20261029-r2 (maintained frontend, 16 jobs).
Fresh rootless references: bazel-genl-native-reference-20261029 and
bazel-quota-native-reference-20261029. Scripts are in
bazel-genl-quota-qualification-20261029. Both pass five metadata records, exact
compressed manual bytes, separate-debug linkage, global/undefined symbols and
dynamic dependency comparison. Genl requires libc; quota requires libc/rpcsvc/util.
Saved per-program reports are under the successful run's qualification directory.

No installed setuid execution, live netlink, local quota or remote RPC testing
was performed. These runtime/authorization gates remain open. No host install,
upgrade or reboot occurred. Resource logs do not establish comparative performance.
Frontend review: existing format-5 explicit targets and artifact handling suffice;
no build-bsd C/protocol/manual change is needed. Make remains production/default.

### 2026-10-29 xo native CLI installation

Added //usr.bin/xo:install_archive using the maintained contrib CLI source,
libxo/util shared dependencies, and explicit CLI/configuration header providers.
The initial bazel-xo-20261029 run rejected nonexistent xoversion.h, which had
been inferred from a stale Makefile comment. Removed the unnecessary declaration;
actual source includes xo_config.h, xo.h and xo_explicit.h. No replacement or
synthetic version header was introduced, and production source is unchanged.

Successful maintained frontend run /usr/obj/usr/src/bazel-xo-20261029-r2 used
16 jobs. Fresh rootless Make reference: bazel-xo-native-reference-20261029.
Scripts: bazel-xo-qualification-20261029. Saved qualification/xo reports establish
five matching metadata records, exact compressed manual bytes, valid debug
linkage and matching global/undefined symbols and dynamic dependencies
(libc/util/xo). No runtime or comparative performance claim follows.

Remaining next step: migrate usr.bin/xo/tests' functional_test wrapper, xo_01
script, all sixteen explicitly maintained saved output/error fixtures and
Kyuafile installation, then qualify the eight format cases with their declared
locale/configured xo input. Those are not covered by this program-only run.
Frontend review: format-5 target/artifact handling already covers this target;
no build-bsd C/protocol/manual change is needed. Make remains production/default.

### 2026-10-29 xo recursive test installation and native declarations

Added the maintained functional_test wrapper, unchanged executable xo_01 script,
all sixteen selected output/error fixtures and Kyuafile. Recursive target
//usr.bin/xo:installation_archives includes a separate tests archive when tests
are enabled. All eight format cases have native ATF declarations with explicit
locale data and usr.bin.xo.test_xo bound to the native CLI, preserving the test
body and expected outputs.

/usr/obj/usr/src/bazel-xo-tests-20261029 passes recursive installation comparison
with fresh rootless Make at bazel-xo-tests-reference-20261029: 25 distinct metadata
records, 20 exact non-ELF payloads and one program/debug ELF pair. Scripts and
reports: bazel-xo-tests-qualification-20261029 (r4-installation-parity.json and
r4-elf-parity.json; inherited report naming only, not four xo attempts).

Runtime attempt bazel-xo-runtime-20261029 builds native_T but fails during ATF
startup with cap_rights_is_valid(src), before the test body. Failure reports are
retained under failure-test-reports. This matches the already diagnosed host
Capsicum ABI mismatch. None of the eight cases is runtime-qualified here; a
matching-kernel replay remains required. No host-library substitution, weakened
assertion, expected-output regeneration or automatic skip was introduced.

Frontend review: existing format-5 targets/tests/settings and failure report
capture cover these additions; no C/protocol/manual change is needed. Make stays
production/default. The next userland work can proceed independently of this
open runtime gate; whole-system completion remains unproven.

### 2026-10-29 pkgconf native library build and CLI installation

Added all 21 maintained libpkgconf C sources, explicit public/internal headers
and maintained configuration header, plus native static/shared build targets.
The shared name remains libprivatepkgconf.so.5 (PRIVATELIB and lib/Makefile.inc
version). Added pkgconf's four CLI sources, native library dependency, section-1
manual, pkgconf package ownership and relative pkg-config -> pkgconf symlink.
SYSTEM_INCLUDEDIR and SYSTEM_LIBDIR match maintained Make's /usr/include and
/usr/lib settings; no host search fallback was introduced.

Initial bazel-pkgconf-20261029 compilation exposed incorrect string macro quoting.
Corrected escaping; successful frontend run is
/usr/obj/usr/src/bazel-pkgconf-20261029-r2 (16 jobs). Fresh rootless Make CLI
reference: bazel-pkgconf-native-reference-20261029. Scripts/reports:
bazel-pkgconf-qualification-20261029. Six metadata records, symlink target/mode,
compressed manual bytes, separate-debug linkage, global/undefined symbols and
dynamic fields match Make. Original failure evidence remains available.

Scope remains partial: private-library installation (headers, static archive,
DSO/debug/link, three manuals), independent archive/ABI parity, bomtool and
spdxtool are still pending. Building the CLI against native libpkgconf does not
qualify its complete library payload. Real .pc resolution, sysroot/cross-build
behavior, environment overrides and Make/ports consumer tests also remain open.
No host installation or repository publication occurred.

Frontend review: existing format-5 explicit targets/artifact path supports the
CLI candidate; no build-bsd C/protocol/manual change is needed for it. Library
and whole-system packaging must be completed before any production/default
switch. Make remains production/default.

### 2026-10-29 libpkgconf complete default installation candidate

Added native private-library installation: five maintained headers, static
archive, libprivatepkgconf.so.5, debug companion, linker symlink and all three
manuals. Preserved pkgconf/dev/dbg ownership and MAN versus MANNODEV package
semantics. The initial archive had an extra component-owned include directory;
Make relies on mtree for it. Removed the duplicate record without weakening
comparison. No production library sources or public ABI name changed.

Final frontend run /usr/obj/usr/src/bazel-libpkgconf-20261029-r2 (16 jobs) passes
against fresh rootless Make at bazel-libpkgconf-reference-20261029. Evidence in
bazel-libpkgconf-qualification-20261029: r2-installation-parity.json establishes
14 distinct metadata records, symlink parity and eight byte-identical header/
manual payloads. r2-archive-parity.json compares all 21 static members (only
.nopic filename suffix normalized) and global/undefined symbol names/types.
r2-elf-parity.json establishes valid shared-library debug linkage and matching
symbols/dynamic fields. These checks do not establish instruction identity or
ABI type-layout equivalence. Initial failure report remains retained.

Make's ordinary install already installs the headers; the explicit reference
installincludes repeats identical metadata, reconciled as distinct records.
Native manifest contains each payload once. No host install or publication
occurred. Bomtool, spdxtool and runtime .pc/cross-build/Make-consumer tests remain
pending. Split-manpage configuration is declared but not separately qualified.
Frontend review: maintained format-5 targets/artifacts and stage helpers already
support this payload; no build-bsd C/protocol/manual change is required. Make
remains production/default, with whole-system/package/performance gates open.

### 2026-10-29 bomtool and spdxtool normal installation

Added native rules for bomtool's two maintained sources and spdxtool's eight,
explicit local/CLI headers, native private pkgconf dependency and maintained
manuals/package ownership. Shared getopt source is reused through a declared
label. No production source or document output changes were introduced.

Maintained frontend /usr/obj/usr/src/bazel-pkgconf-tools-20261029 (16 jobs)
passes against fresh rootless Make references bazel-bomtool-native-reference-
20261029 and bazel-spdxtool-native-reference-20261029. Scripts are under
bazel-pkgconf-tools-qualification-20261029. Each program passes five installed
metadata records, exact compressed manual bytes, valid separate-debug linkage,
and matching global/undefined symbols and dynamic fields. Both use libc and
libprivatepkgconf.so.5. Saved per-program reports are in qualification/<program>.

Scope is the normal installed build. Spdxtool's Make TOOLS_PREFIX-defined
NO_SHARED mode is NOT modeled/qualified by these targets yet; it remains an
explicit bootstrap/cross-tool requirement. Functional BOM/SPDX output and .pc
resolution, downstream Make/ports use and comparative performance remain open.
No host installation, package publication or live metadata modification occurred.
Frontend review: format-5 targets and artifacts already support these normal
candidates. Future bootstrap mode must be connected through maintained frontend
inputs, not a one-off override. No frontend C/protocol/manual change is needed
for this batch; Make remains production/default.

### 2026-10-29 spdxtool static bootstrap variant

Added //usr.bin/spdxtool:bootstrap_spdxtool sharing the maintained CLI sources,
with native static libpkgconf/libc, fully_static_link and no PIE flags. Make
query and fresh TOOLS_PREFIX-defined reference confirm this mode uses -static
without PIE. Existing dynamic installed target is unchanged.

Native run bazel-spdxtool-bootstrap-20261029 and rootless Make reference
bazel-spdxtool-bootstrap-reference-20261029 both produce EXEC ELF without INTERP
or NEEDED and identical --version/--help output. Initial global-symbol mismatch
was allocator configuration: native development malloc versus production malloc
in the reused Make SDK libc. The reference builds the tool afresh, not libc.
Explicit malloc_production=true run
/usr/obj/usr/src/bazel-spdxtool-bootstrap-production-20261029 also passes complete
global/undefined symbol comparison. No flags or assertions were weakened and
development defaults were not changed. Reports and scripts are retained in
bazel-spdxtool-bootstrap-qualification-20261029 (parity.json records the initial
mismatch; production-parity.json records the matching-configuration pass).

Runtime checks use byte-identical executable copies of immutable saved artifacts,
with PATH=/nonexistent; no installed tool or shared-library fallback. These are
version/help smoke checks, not SPDX generation or cross-host qualification.
The native build uses all 16 CPUs. No host install occurred. Frontend review:
format-5 explicit targets and allocator settings support selection; updated
bsd-build(8) to document this mode. Staged-tool replacement and complete bootstrap
remain pending. Make stays production/default.

### 2026-10-29 mail program, installation and signal tests

Added native mail sources/headers, Mail/mailx program and manual aliases,
help files and /etc/mail.rc configuration metadata. Initial program comparison
caught missing package ownership for /usr/share/misc; corrected the directory
record without changing the verifier. Program-only evidence is retained under
bazel-mail-20261029-r2 and bazel-mail-qualification-20261029.

Added the maintained four ATF C signal cases, installed Kyuafile/test/debug
payloads and a tests-selectable installation_archives aggregate. Runtime uses
an explicitly declared executable copy named mailx, preserving execlp identity
without changing test sources or searching host PATH. Native libc/libsys and
ATF libraries are declared runtime dependencies.

/usr/obj/usr/src/bazel-mail-tests-20261029 passes against the fresh isolated
Make reference bazel-mail-tests-reference-20261029: 22 metadata records,
seven byte-identical nonbinary payloads, aliases and two ELF/debug pairs with
matching global/undefined symbols and dynamic properties. Scripts/reports are
in bazel-mail-tests-qualification-20261029. The r2 report names are inherited
from the program-only comparator, not evidence of two test-install attempts.

/usr/obj/usr/src/bazel-mail-runtime-20261029-r2 executed all four native tests:
interactive/noninteractive SIGHUP and SIGINT all PASS, including maintained
dead.letter assertions. Initial runtime request was rejected before execution
because tests were not selected targets; corrected explicit inputs are retained
separately. Build/test runs use the maintained frontend and all 16 CPUs.

No program/test sources changed, host installation or mail delivery performed.
These tests do not qualify mailbox permissions, delivery, editor/shell commands,
cross-platform behavior or comparative performance. Frontend review: existing
format-5 target/test selection, tests setting, artifact/debug/stage handling
support this component; no build-bsd C, backend or manual change is required.
Make remains production/default and complete world/kernel/package gates remain.

### 2026-10-29 whois and FTP client installation

Added native whois and FTP rules. FTP declares all ten maintained tnftp sources,
five upstream headers, the maintained tnftp_config.h and native libedit;
INET6 follows the existing inet6_support build setting. Installation preserves
FTP package ownership and pftp/gate-ftp executable/manual hardlinks. No runtime
sources changed. WHOIS currently covers the ordinary build; Make's optional
external SOCKS library/remapped-symbol mode remains a migration requirement.

Maintained frontend /usr/obj/usr/src/bazel-network-clients-20261029 (16 jobs)
passes fresh rootless Make reference comparisons: whois has five metadata
records, one exact manual payload and one matching ELF/debug pair; FTP has
nine metadata records, three exact manual payloads/aliases and one matching
ELF/debug pair. Native /usr/obj/usr/src/bazel-ftp-noinet6-20261029 independently
matches the MK_INET6_SUPPORT=no Make reference on the same nine records and
ELF/debug checks. Global/undefined symbols and dynamic fields are compared;
instruction identity and runtime equivalence are not asserted.

Scripts and reports are in bazel-network-clients-qualification-20261029,
with whois, ftp and ftp-noinet6 report directories. Report names r2-* are
inherited comparator names, not evidence of repeated attempts. WHOIS retains
an existing CHOPSPAM+4 compiler warning; no production source changes were
introduced to silence it. Network transactions, FTP active/passive/proxy modes,
credentials, transfers and WHOIS referrals remain runtime qualification work.
No live network operations, installation or repository publication occurred.

Frontend review: maintained format-5 targets/artifacts and inet6_support input
already cover these ordinary configurations; no build-bsd C, backend, signing,
staging or manual change is needed. The optional SOCKS mode is not represented
as qualified. Whole-world/kernel/bootstrap/pkgbase and performance gates remain
open; Make stays production/default.

### 2026-10-29 fortune group and declared index generation

Added native fortune, strfile and unstr with shared strfile.h, fortune DEBUG
configuration, maintained manuals and the unstr.8 manual alias. Aggregate
installation includes both freebsd-tips and 5bsd-tips and their generated
indexes. fortune_database is a declared action: source input, output, explicit
-C s flags (-Cs), LC_ALL=C, no shell/PATH discovery, and strfile selected in the
execution configuration. Index format is emitted by the maintained strfile.
No production sources or data were rewritten.

Initial analysis caught a header provider incorrectly listed in dynamic_deps;
corrected it to the ordinary header dependency. First installation comparison
caught missing package ownership of /usr/share/games/fortune; added that record
without weakening the comparator. Final maintained frontend run
/usr/obj/usr/src/bazel-fortune-20261029-r3 (16 jobs) matches recursive rootless
Make reference bazel-fortune-reference-20261029: 16 distinct metadata records,
seven exact nonbinary payloads (including both generated indexes), and three
valid ELF/debug pairs with matching global/undefined symbols/dynamic fields.

Evidence lives in bazel-fortune-qualification-20261029. r2-installation-parity
retains the directory mismatch; r3 reports establish the corrected result.
An evidence-script stale artifact path was corrected before ELF comparison.
Make's maintained index rule searches PATH, so fresh-index.py additionally
invokes the freshly built reference strfile by absolute path with
PATH=/nonexistent and confirms both index bytes against the compared installed
payloads; fresh-index-parity.json records commands and hashes. This avoids
attributing host-tool output to the new reference generator.

Frontend review: existing format-5 targets/artifacts and execution-toolchain
selection cover this group; no build-bsd C/backend/manual change is required.
No host installation/publication occurred. Random selection, regex, locale,
malformed databases, cross-host generator behavior and comparative performance
remain runtime/configuration coverage gaps. These component comparisons do not
qualify complete world/kernel/pkgbase; Make remains production/default.

### 2026-10-29 locate group

Added native locate, locate.code and locate.bigram with maintained MMAP build
configuration and declared shared headers. fastfind.c is explicitly a textual
header input, preserving its four inclusions from locate.c rather than compiling
it as a separate translation unit. Installation includes locate.rc, all three
unmodified maintenance scripts, both manuals and the updatedb.8 hardlink.

Maintained frontend /usr/obj/usr/src/bazel-locate-20261029-r2 (16 jobs) matches
fresh recursive rootless Make reference bazel-locate-reference-20261029:
18 distinct metadata records, seven exact nonbinary payloads and three ELF/debug
pairs with matching global/undefined symbols and dynamic fields. Initial
comparison caught missing package ownership of /usr/libexec for the scripts;
added the directory record without changing the verifier. Initial failure and
final reports remain in bazel-locate-qualification-20261029.

runtime.py in that evidence directory executes disposable copies of saved
native artifacts and Make reference binaries with host shared libraries and
PATH=/nonexistent. Fifteen comparisons succeed: encoding plus seven query modes
in each mmap/stdio reader (full output, substring, case-insensitive, count,
NUL-separated, limit and glob). Separate roundtrip.json confirms exact recovery
of all four fixture paths. The full runtime script intentionally remains FAILED:
locate.bigram from BOTH builders cannot load against host libc, which lacks
cap_rights_intersect@FBSD_1.9. This is not a passing bigram test or complete
runtime qualification; matching-library/kernel testing remains necessary.

No maintenance script was executed, no filesystem scan or host database update
occurred. Periodic updates, compressed-bigram round trips, malformed databases,
locale/cross-platform behavior and performance remain open. Frontend review:
existing format-5 target/artifact staging covers the complete payload; no
build-bsd C/backend/manual change is required. Make remains production/default;
complete world/kernel/pkgbase/runtime/performance gates remain open.

### 2026-10-29 tip/cu group

Added native tip/cu with all 23 maintained C sources, two local headers and
Make's DEFBR/DEFFS/ACULOG/PRISTINE/CONNECT and modem-selection defines. The
libacu source provider exports only the nine compiled modem sources; biz31.c
is not part of the maintained Make SRCS. cu is an executable hardlink to tip,
but has its own distinct manual. Both /etc/phones and /etc/remote retain their
maintained configuration metadata. Source UID/GID handling is unchanged; the
actual default executable installation is 0555, not setuid.

Maintained frontend /usr/obj/usr/src/bazel-tip-20261029 (16 jobs) passes against
fresh rootless recursive Make reference bazel-tip-reference-20261029. Evidence
in bazel-tip-qualification-20261029 establishes ten distinct metadata records,
four exact nonbinary payloads, executable hardlink identity, valid separate
debug linkage and matching global/undefined symbols and dynamic fields. The
r2 report names are inherited from the comparator, not repeated build attempts.

Make's beforeinstall hook clears schg on a pre-existing cu as historical direct
installation cleanup. Native archive construction operates on a fresh payload
and does not mutate a pre-existing installation. Existing-system replacement
and flags behavior belong to pkgbase upgrade qualification, still outstanding;
this component check does not claim to establish that behavior.

No serial device/session, transfer, shell escape, lock or accounting-log runtime
operation was performed. These remain qualification gaps, along with custom
modem/baud options and cross-platform behavior. Frontend review: existing
format-5 target/artifact/configuration staging supports this group; no build-bsd
C/backend/manual change is required. Make remains production/default and
complete world/kernel/bootstrap/pkgbase/runtime/performance gates remain open.

### 2026-10-29 man frontend and mandoc formatter

Added native man script/manpath hardlink and three maintained manuals. Added
mandoc's explicit 61 C sources, local headers/textual .in inputs, source config.h,
PIE libopenbsd and native zlib dependencies. Source inventories are declarations
in BUILD files; builds do not parse Make. Default installation includes the
maintained mandoc.ucl package trigger, manuals/aliases and apropos/whatis/
makewhatis hardlinks. Existing man_utils setting controls optional utilities and
their manuals, matching MK_MAN_UTILS; formatter sources are unchanged in both
configurations, as in Make. No runtime sources or package-trigger policy changed.
The man.conf manual is installed here; this component does not invent a new
/etc/man.conf payload. Neither component Makefile defines a test subdirectory.

Maintained frontend /usr/obj/usr/src/bazel-manual-tools-20261029 (16 jobs)
matches isolated fresh rootless Make references bazel-man-reference-20261029
and bazel-mandoc-reference-20261029: man has six distinct metadata records and
five exact nonbinary payloads; mandoc has 21 records, 13 exact nonbinary payloads
and one matching ELF/debug pair. The independent
bazel-mandoc-no-utils-20261029 run matches MK_MAN_UTILS=no on 15 records, ten
nonbinary payloads and ELF/debug checks. Global/undefined symbols, dynamic
properties, ownership/modes/tags and hardlinks were compared.

Scripts/reports are in bazel-manual-tools-qualification-20261029. First host
runtime attempt failed for both builders because host libc lacks
fts_open@FBSD_1.9; original failure is retained. runtime-sdk.py explicitly
copies and hashes SDK libc/libsys/libz into a disposable directory, preserving
the mandoc executable name, then runs both saved-artifact/reference copies
with LD_LIBRARY_PATH set to those libraries and PATH=/nonexistent. Fifteen
comparisons match: three maintained manuals (man.1, man.conf.5, cu.1) across
ascii/html/lint/tree/man formats. Twelve rendering cases return zero with
matching output; lint of man.conf.5 returns zero, and the other two lint cases
return identical status 1 diagnostics. This is SDK-library host-kernel runtime
evidence, not proof against installed host libraries or a native full system.

Package-trigger execution, database construction/search/update, full shell man
lookup/pager integration, cross-host bootstrap and performance remain open.
No host installation, package trigger or manual database update was run.
Frontend review: existing format-5 targets/artifacts and man_utils input cover
these configurations; no build-bsd C/backend/manual change is required. Make
remains production/default; complete world/kernel/pkgbase gates stay open.

### 2026-10-29 host and drill DNS clients

Added native host from maintained ldns-host.c and drill from all eight maintained
sources, using existing native ldns/crypto dependencies. Narrow source/header
providers declare drill's local headers and config.h mapping. The configured
LDNS_TRUST_ANCHOR_FILE remains /etc/unbound/root.key as specified by Make;
no runtime trust policy changed. Host's manual is generated by the existing
declared sed-filter rule with exactly the maintained s/ldns-//gI transformation,
explicit staged sed/runtime and input/output, not a precomputed replacement.

Maintained frontend /usr/obj/usr/src/bazel-dns-clients-20261029 (16 jobs) passes
against fresh rootless Make references bazel-host-reference-20261029 and
bazel-drill-reference-20261029. Each passes five metadata records, exact
compressed manual content and one valid ELF/debug pair with matching global/
undefined symbols and dynamic properties. Scripts/reports live under
bazel-dns-clients-qualification-20261029 with host/drill subdirectories. r2
report names are inherited comparator names, not repeated build attempts.

These are build/installation checks. DNS packets, referrals, DNSSEC validation,
trust-anchor loading, transport/timeouts and resolver configuration remain
runtime qualification work. No DNS queries, host installation or trust-file
changes occurred. Frontend review: format-5 explicit targets and existing
staged generator tools cover this addition; no build-bsd C/backend/manual
change is required. Make stays production/default; complete world/kernel/
pkgbase/bootstrap/runtime/performance gates remain open.

### 2026-10-29 gprof installation

Added native gprof's nine maintained C sources and both local headers, the
manual, and gprof.flat/gprof.callg explanatory data. Installation preserves
package=toolchain, /usr/share/misc ownership, and debug metadata. Maintained
frontend /usr/obj/usr/src/bazel-gprof-20261029 (16 jobs) matches fresh rootless
Make reference bazel-gprof-reference-20261029: eight distinct metadata records,
three exact nonbinary payloads and one valid ELF/debug pair with matching
global/undefined symbols and dynamic properties. Evidence/scripts are retained
under bazel-gprof-qualification-20261029; r2 report names are inherited from the
comparator rather than repeated attempts.

This does not qualify profile generation/collection, kernel profiling, malformed
profile input, call-graph reconstruction, or output correctness on real profiles.
No profiling workload or host installation occurred. Frontend review: existing
format-5 targets/artifacts and staging cover the payload; no build-bsd C/backend/
manual change is required. Make stays production/default and complete world/
kernel/pkgbase/bootstrap/runtime/performance gates remain open.

Next inspected component is truss: four maintained C sources, libsysdecode,
source-tree kernel header precedence and an ATF shell syscall-filter suite.
Its native rule/test migration remains outstanding; no completed truss claim
is implied by this checkpoint.

### 2026-10-29 truss and syscall-filter test integration

Added native truss's four maintained sources/three headers and native
libsysdecode dependency. Inspected fresh Make compiler dependency files to
identify the amd64 source-kernel-header closure behind Make's -I${SRCTOP}/sys.
Explicit narrow truss_headers providers in sys/bsm, netinet, netinet6, netlink
and sys/sys preserve source-header precedence. This closure is scoped to the
currently supported amd64 native target; other architectures require their own
qualification. Builds do not parse Make or compiler dependency snapshots.

Added the maintained ATF shell wrapper/Kyuafile installation and all 17 native
case declarations with explicit tools/libraries. The test's hardcoded true
executable now accepts ATF configuration usr.bin.truss.test_true, defaulting to
/usr/bin/true for ordinary installed tests; native cases supply the declared
true target. readlink's declared runtime alias preserves stat's argv[0] behavior.
No assertions, ptrace checks or application capability behavior were removed.
Shell syntax validation passes. Production C sources are unchanged.

/usr/obj/usr/src/bazel-truss-install-20261029-r3 (16 jobs) matches fresh
rootless tests-enabled Make reference bazel-truss-tests-r2-reference-20261029:
eight distinct metadata records, three exact nonbinary payloads and one valid
ELF/debug pair with matching global/undefined symbols and dynamic properties.
Evidence/scripts are in bazel-truss-qualification-20261029. Earlier program-only
reference and initial tests installation remain retained separately.

Runtime run bazel-truss-tests-20261029-r2 built all targets but FAILED all 17
cases at ATF source-directory startup with cap_rights_is_valid(src) assertion in
cap_rights_intersect, matching the documented source/host Capsicum ABI issue.
The input mistakenly selected all native test targets while intending only the
list case; Bazel test executes selected test targets, so all 17 were attempted.
No test body is qualified. Original failure-test-reports and per-case
runtime-failure-summary.json are retained. Installation-only qualification was
run separately; no runtime failure was converted to a pass or skip.

Matching-kernel tests remain required for tracing, ABI decode, syscall filters,
process lifecycle and capability handling. No existing host process was attached
or host installation performed. Frontend review: existing format-5 target/test
selection, archive and tests-option support cover this component; no build-bsd
C/backend/manual change is required. Make stays production/default; whole-world/
kernel/pkgbase/bootstrap/runtime/performance gates remain open.

### 2026-10-29 native bmake program and regression evidence

Added native base make/bmake from all 23 maintained C sources, source config.h,
explicit headers and filemon kernel interface. Separate native source groups
preserve main-specific defaults/version inclusion and job/meta/filemon defines.
Version header is generated from contrib/bmake/VERSION with a declared sed action;
no duplicated numeric version is embedded in the BUILD file. Maintained default
meta mode, filemon dev mode, system mk search path, no dollar-saving default and
NO_PWD_OVERRIDE are retained. Production C sources and unit fixtures unchanged.

Maintained frontend /usr/obj/usr/src/bazel-bmake-20261029 (16 jobs) matches
fresh rootless Make reference bazel-bmake-reference-20261029: seven metadata
records, two exact manual payloads, make/bmake hardlinks and one valid ELF/debug
pair with matching global/undefined symbols and dynamic properties. Runtime
version query returns 20260704. Evidence/scripts in bazel-bmake-qualification-
20261029; r2 comparator report names are inherited, not repeated build attempts.

Executed the maintained contrib/bmake/unit-tests suite with the saved native
binary, 16 jobs and fresh disposable source copies. First run's output
comparisons passed but final Lua check failed because lua was absent from PATH.
Second run explicitly selected LUA=/usr/libexec/flua but its unit-tests-r2
basename violated two maintained path assertions. Third run preserves the
unit-tests basename under a fresh r3 parent and selects the same explicit flua;
it exits zero, passes all 398 selected output comparisons and the final Lua
expectation check. runtime/suite-summary.json records results; original failures
remain. No expectations or assertions were altered. The maintained suite skips
filemon-dependent tests when /dev/filemon is unavailable; those remain untested.

This suite uses host shell/utilities/shared libraries and the native make binary;
it is not yet a Bazel-native test graph. Recursive installed tests from
usr.bin/bmake/tests, explicit alternative filemon/bootstrap/cross-host settings,
ports builds, pkgbase consumer builds and performance remain migration gates.
No host installation or /dev/filemon activation occurred. Frontend review:
format-5 targets/artifacts and existing generator staging cover the default
program; no build-bsd C/backend/manual change is required for this batch. Make
remains production/default; native world/kernel/pkgbase completion is unproven.

### 2026-10-29 bc/dc generators, NLS and runtime suites

Added native bc/dc with 21 maintained C sources, four generated C inputs,
source headers and native libedit. Preserved maintained compiler defaults,
amd64 LTO, bc/dc executable alias and distinct manuals. VERSION.txt is a declared
version-header input. Native source-generator action invokes unmodified
strgen.sh/functions.sh with original gen/ relative input names and arguments,
explicit execution tools, deterministic locale and action-output temporary
storage. All four generated C files match Make byte-for-byte; copies/hashes
are in bazel-bc-qualification-20261029/generated-source-parity.json.

NLS catalogue inventory/relative aliases are explicit package declarations.
Existing nls_catalogs selection controls catalog installation, compiler define
and A/N manual variants. Maintained frontend final default run
/usr/obj/usr/src/bazel-bc-20261029-r4 matches fresh Make reference
bazel-bc-reference-20261029: 102 metadata records, 27 exact nonbinary payloads
(including generated catalogs), links and one valid ELF/debug pair with matching
global/undefined symbols/dynamic fields. Independent no-NLS run
bazel-bc-no-nls-20261029 matches MK_NLS_CATALOGS=no on seven records, two manual
payloads and ELF/debug parity. Builds use all 16 CPUs.

Earlier failures are retained: incorrect staged rm label; generator attributes
initially disallowing staged file tools; incorrect one-time alias inventory
retaining '+' from Make += syntax; missing /usr/share/nls directory ownership.
Corrected declarations/attributes rather than changing verifiers. Build graphs
do not parse Make. Original failure report is retained beside final r4 reports.

Execution SDK bazel-bc-exec-sdk-20261029 adds explicitly selected /usr/bin/dirname
via maintained additional_execution_tools staging, including hashes/runtime
closure. Existing staged rm is used. Frontend review: format-5 target/settings
and maintained staging helper already support these inputs; bsd-build(8) now
documents the dirname requirement. No build-bsd C/backend replacement needed.

Disposable copies of the maintained bc test tree and saved native executable
pass both tests/all.sh suites with installed-wrapper options bc/dc 1 1 0 0,
plus -n for serial execution per suite. bc and dc suites ran independently.
Both return zero and report all tests passed; runtime/summary.json/logs retain
evidence. This covers selected arithmetic, script, stdin/error and extra-math/
stack cases through host libraries/tools. Generated/problematic tests are off
as in maintained wrappers; locale/history/terminal behavior is not qualified.
No host installation or source fixture modifications occurred.

Recursive test installation and Bazel-native test registration remain to be
migrated, as do cross-target LTO behavior, bootstrap and performance gates.
The passing host suites do not complete those tasks. Make remains production/
default; complete world/kernel/pkgbase/runtime qualification remains open.

### 2026-10-29 bc/dc complete test installation

Added the recursive calculator test payload: maintained bc_tests/dc_tests
wrappers, plain-test Kyuafile, shared functions.sh and every fixture selected
by the maintained Make directory patterns. The native macro runs in contrib/bc
and uses matching nonrecursive glob patterns, so future fixtures in these groups
are included without a hand-maintained file list. Source scripts/expectations
are unchanged; 0755 script groups versus 0444 data groups remain explicit.
The normal tests setting selects a separate test archive through the parent
installation_archives target, preserving package ownership.

Maintained frontend /usr/obj/usr/src/bazel-bc-tests-20261029 (16 jobs) matches
fresh recursive rootless Make reference bazel-bc-tests-reference-20261029:
989 distinct metadata records and 905 exact nonbinary payloads, including all
catalogs/fixtures/wrappers/manuals and plain Kyuafile entries. Program aliases
and one ELF/debug pair also match global/undefined symbols/dynamic fields.
Scripts/reports are retained in bazel-bc-tests-qualification-20261029; r4 report
names are inherited from the previous comparator, not repeated attempts.

This completes this component's default tests-enabled installation comparison;
it does not register its plain suites as native Bazel test targets. The prior
maintained bc/dc runtime suites passed separately; this batch did not rerun them.
Native test registration, installed-image execution, interactive/locale cases
and performance remain open. No host installation or source fixture changes.
Frontend review: existing tests selection and format-5 archive/artifact staging
cover the new payload, with no build-bsd C/backend/manual change needed.
Make remains production/default and full-system qualification is incomplete.

### 2026-10-29 Bluetooth libraries and clients

Added native libbluetooth/libsdp static and shared libraries, explicit source
kernel-header dependencies, and bthost/btsockstat/rfcomm_sppd. The parent client
archive set covers all three maintained Make subdirectories. Installation keeps
shared-library versions, development headers/links, manuals and aliases,
/etc/bluetooth configuration, and btsockstat group kmem/mode 2555.

Maintained frontend run /usr/obj/usr/src/bazel-bluetooth-20261029 built with
16 jobs. Fresh isolated Make references and reports in
/usr/obj/usr/src/bazel-bluetooth-qualification-20261029 establish matching
installation metadata (clients 11, libbluetooth 43, libsdp 28), exact nonbinary
payloads (3, 36, 22), five valid ELF/debug pairs with matching dynamic fields
and global/undefined symbols, and both static-library member/symbol inventories.
These are structural comparisons, not instruction identity or runtime proof.
Reference client dependency libraries include staged SDK inputs; not every
reference dependency was rebuilt. Existing compiler warnings are not a clean
warning qualification. Hardware operations, privileged socket inspection,
service discovery, serial sessions, cross-target builds and performance remain
unqualified. No host installation or hardware access was performed.

Frontend review: existing format-5 targets, installation archives and staged
SDK inputs cover this batch; build-bsd.c and its backend/manual require no new
interface. Package construction/publication remains a separate gate. Make is
still production/default; full world/kernel/pkgbase qualification is incomplete.

### 2026-10-29 lutok dependency for Kyua

Added native internal lutok library with all six maintained C++ sources,
explicit upstream wrapper headers, and native Lua dependencies. Ordinary and
PIE variants match Make's liblutok.a/liblutok_pie.a model; neither is installed.
The first build exposed lua.hpp missing from Lua's declared headers. Added that
real source header to the existing provider; the failure remains recorded.

Maintained frontend /usr/obj/usr/src/bazel-lutok-20261029-r3 builds both variants
with 16 jobs. Fresh Make reference bazel-lutok-reference-20261029 and reports in
bazel-lutok-qualification-20261029 establish matching six-member inventories and
global/undefined symbols for both archives (only PIE object suffix normalized).
This does not prove runtime or instruction equivalence. Kyua still requires
native sqlite3, its own source graph/install payload and runtime qualification.

Frontend review: existing format-5 target and artifact support handles these
internal archives; no build-bsd.c/backend/manual interface change is needed.
Make remains production/default; complete world/kernel/pkgbase is unfinished.

### 2026-10-29 SQLite prerequisite for Kyua

Added native sqlite3 compilation from the maintained amalgamation, explicit
public headers and compile options, native libthr dependency, static archive,
private shared library and full private development/debug installation.
The target currently supports FreeBSD amd64; PowerPC byte-order configuration
is not claimed. No generated amalgamation regeneration is implemented here;
the maintained Make build also consumes the checked-in sqlite3.c.

Maintained frontend /usr/obj/usr/src/bazel-sqlite3-20261029-r2 (16 jobs) matches
fresh isolated Make reference bazel-sqlite3-reference-20261029: eight distinct
metadata records, both exact header payloads, static member/global/undefined
symbol inventory and one valid ELF/debug pair with matching dynamic fields and
symbols. Reports/scripts reside in bazel-sqlite3-qualification-20261029/r2.
Initial compilation succeeded but archive comparison detected an extra symbol:
a one-time transcription incorrectly included a truncated PowerPC-only byte-order
option. Removed that option from the amd64 declaration; retained initial failure
reports and used unchanged comparison criteria for the corrected build.

Frontend review: existing format-5 targets, artifact staging and private-library
installation helpers cover this addition; no build-bsd.c/backend/manual interface
change is required. No host installation occurred. Database transactions, locking,
WAL/recovery, Kyua consumption, cross-target builds and performance remain
unqualified. Structural parity does not assert instruction or runtime equivalence.
Make remains production/default; full world/kernel/pkgbase qualification is open.

### 2026-10-29 Kyua default native build and installation

Added native Kyua with 115 common C++ sources plus selectable jail implementation
(two sources) or the maintained no-jail stub. Dependencies are native lutok/Lua,
SQLite, libutil, optional libjail, libm, libc++ and libcxxrt. Source libc++ headers
are declared explicitly with -nostdinc++; lutok now uses that same header set.
Initial runs retained in bazel-kyua-20261029 and subsequent install run directories
exposed static libm/PIE linking, missing explicit C++ runtimes, and duplicate SDK/
source C++ header search paths. Corrected dependencies/header selection without
changing program sources or suppressing compiler/runtime checks.

Maintained frontend /usr/obj/usr/src/bazel-kyua-install-20261029-r3 (16 jobs)
matches fresh isolated Make reference bazel-kyua-reference-20261029 on 36 metadata
records, 27 exact nonbinary payloads and one valid ELF/debug pair with matching
global/undefined symbols and dynamic fields. Reports/scripts are in
bazel-kyua-qualification-20261029. Payload includes maintained default config,
manuals, report templates, SQL schema/migrations, documentation and selectable
examples. This is default jail-enabled installation parity, not runtime proof.

No-jail/no-examples configuration comparisons, runtime test execution/database
operations, isolated jail execution, and rechecking standalone lutok archive
parity after source-header selection remain open. No host installation, jail
creation, module loading or test execution occurred. Native compilation uses
existing format-5 frontend target/settings and installation helpers; no
build-bsd.c/backend/manual interface change is required. Make remains the
production/default system builder; full world/kernel/pkgbase is incomplete.

### 2026-10-29 Kyua configuration and runtime follow-up

No-jail/no-examples frontend run bazel-kyua-minimal-20261029 matches fresh Make
MK_JAIL=no/MK_EXAMPLES=no reference: 33 metadata records, 25 nonbinary payloads
and one ELF/debug pair. Both lutok archive variants rebuilt with source libc++
headers retain matching Make members/symbols. Reports reside in
bazel-kyua-qualification-20261029/minimal and lutok-source-header-parity.json.
Existing frontend settings cover these variants; no C/backend/manual change.

Disposable native Kyua runs help, list, two plain shell tests, result storage,
text/JUnit/HTML reports and db-exec PRAGMA integrity_check. One deliberate pass
and one deliberate failure are correctly reported; JUnit has two cases/one
failure and database integrity reports ok. Evidence is runtime/smoke.json and
runtime/smoke/validation.json. Initial --version was invalid (usage status 3),
retained in startup.json. Python lacks _sqlite3, so database validation used
Kyua's own db-exec command. Runtime uses host libraries/shell and Make-staged
schema/report assets verified byte-identical to native installation payloads.
Full native-library runtime, jail execution, old-database migrations, maintained
ATF suites and performance remain unqualified. No host installation occurred.

### 2026-10-29 mlx4 OFED provider dependency

Added native mlx4 provider with all seven maintained sources, explicit private
headers and native ibverbs/pthread dependencies. Preserves /usr/lib shared-library
placement (unlike mlx5 in /lib), static archive, development link and debug files.
Make does not specify a version map for mlx4; no mlx5 version-map substitution.

Maintained frontend bazel-mlx4-20261029 (16 jobs) matches fresh isolated Make
reference bazel-mlx4-reference-20261029 on six installation metadata records,
static archive members/global/undefined symbols and one valid ELF/debug pair
with matching symbols/dynamic fields. Evidence/scripts:
/usr/obj/usr/src/bazel-mlx4-qualification-20261029. No RDMA hardware operations,
device discovery, traffic, provider loading or performance testing occurred.

Dependency review: all seven libibverbs utilities require ibverbs, mlx4, mlx5,
bnxtre, cxgb4, irdma and pthread under maintained Make. Native cxgb4/irdma remain
missing before migrating these consumers; do not silently omit providers.
Frontend review: current format-5 library targets/archive staging suffice;
no build-bsd.c/backend/manual interface change required. Make remains the
production/default builder and whole-system qualification remains incomplete.

### 2026-10-29 cxgb4 and irdma provider dependencies

Added native cxgb4 (four sources) and irdma (three sources), native ibverbs and
pthread dependencies, static/shared artifacts and installation. Fresh Make
.depend files identified cxgb4's t4_msg.h/t4fw_interface.h source-kernel headers
and irdma's libibverbs config.h; explicit providers declare these inputs.
Preserved cxgb4 /usr/lib and irdma /lib placement and irdma's maintained symbol
version map. Kernel header provider additions do not claim kernel driver builds.

Maintained frontend bazel-rdma-providers-20261029 uses 16 jobs. Fresh references
bazel-cxgb4-reference-20261029 and bazel-irdma-reference-20261029 match six and
five installation metadata records respectively, both static member/symbol
inventories and both ELF/debug pairs (global/undefined symbols, dynamic fields).
Reports/scripts: bazel-cxgb4-qualification-20261029 and
bazel-irdma-qualification-20261029 under /usr/obj/usr/src.

This supplies the previously missing native providers required by all seven
libibverbs utilities; consumer migration remains next. No device discovery,
RDMA traffic, hardware/provider loading or performance tests were performed.
Frontend review: existing format-5 targets/artifact staging and installation
helpers cover these libraries; no build-bsd.c/backend/manual interface change.
No host installation. Make remains production/default; full system unqualified.

### 2026-10-29 seven libibverbs utilities

Added native ibv_asyncwatch, ibv_devinfo, ibv_devices, ibv_rc_pingpong,
ibv_srq_pingpong, ibv_uc_pingpong and ibv_ud_pingpong. Parent archive set covers
all maintained libibverbs utility subdirectories. Explicit sources include the
shared pingpong.c where Make selects it, with declared config/pingpong headers.
All consumers retain ibverbs, mlx4, mlx5, bnxtre, cxgb4, irdma and pthread native
link dependencies. Upstream sources/manuals were not modified.

Maintained frontend /usr/obj/usr/src/bazel-ibverbs-clients-20261029 (16 jobs)
matches fresh recursive Make reference bazel-ibverbs-clients-reference-20261029:
23 distinct installation metadata records, seven exact compressed manuals and
seven valid executable/debug pairs with matching global/undefined symbols and
dynamic fields. Evidence/scripts in bazel-ibverbs-clients-qualification-20261029.
Reference consumer builds reuse staged dependency libraries; this does not claim
all Make dependencies were freshly rebuilt. Comparison is structural, not
instruction identity or RDMA runtime equivalence.

No device discovery, queue setup, RDMA traffic, provider hardware operations or
performance tests were performed. Remaining OFED groups include librdmacm,
infiniband diagnostics and optional opensm. Frontend review: existing format-5
archive sets and target staging cover these consumers, requiring no build-bsd.c/
backend/manual interface change. Make remains production/default; complete
world/kernel/pkgbase/runtime/performance qualification remains open.

### 2026-10-29 librdmacm and all four consumers

Added native librdmacm (acm, addrinfo, cma, indexer), declared public/private
headers and native ibverbs dependency, maintained symbol-version map, static/
shared/debug artifacts and 49 manuals. Public header installation remains owned
by the existing OFED include package. Shared library remains in /usr/lib.
Added ucmatose, mckey, rping and udaddy with exact maintained sources/common.c
selection and full native RDMA/provider/pthread dependencies. Parent archive set
covers all four maintained consumer subdirectories. No upstream source changes.

Maintained 16-job frontend runs bazel-rdmacm-20261029 and
bazel-rdmacm-clients-20261029 match fresh isolated Make references. Library:
55 metadata records, 49 exact manuals, static member/global/undefined-symbol
inventory and one ELF/debug pair. Consumers: 14 records, four exact manuals and
four ELF/debug pairs. All checked dynamic fields and symbols match. Evidence
and scripts live in bazel-rdmacm-qualification-20261029 and
bazel-rdmacm-clients-qualification-20261029 under /usr/obj/usr/src.

Make reference consumers reuse staged dependency libraries; not every reference
dependency was rebuilt. No RDMA device operations, connections, multicast,
traffic, privileged configuration or performance checks were run. Structural
parity does not establish runtime equivalence. Next OFED work is the diagnostics
and their remaining libraries, plus optional opensm. Frontend review: current
format-5 targets/archive sets and staging helpers cover this addition; no
build-bsd.c/backend/manual interface change. Make remains production/default;
whole-system world/kernel/pkgbase/runtime/performance qualification remains open.

### 2026-10-29 management datagram library prerequisites

Added native libibumad (three sources) and libibmad (14 sources), explicit public/
private header providers, maintained version maps, static/shared/debug outputs
and /usr/lib installation. libibmad retains HAVE_CONFIG_H=1 and native ibumad
dependency. Header installation stays with the existing OFED include package.

Maintained frontend bazel-mad-libraries-20261029 (16 jobs) matches fresh isolated
Make references bazel-ibumad-reference-20261029 and bazel-ibmad-reference-20261029:
six metadata records each, both static archive member/global/undefined-symbol
inventories, and both shared ELF/debug pairs with matching symbols/dynamic fields.
Evidence/scripts in bazel-ibumad-qualification-20261029 and
bazel-ibmad-qualification-20261029 under /usr/obj/usr/src.

The diagnostics' maintained common Make include links osmcomp, ibmad and ibumad,
even for default ibstat. Native osmcomp and consumers remain next; ofed_extra
already has a maintained configuration setting for optional diagnostics. No
management datagrams, device operations, traffic or performance tests occurred.
Frontend review: existing format-5 targets/staging cover these libraries; no
build-bsd.c/backend/manual interface change required. Make remains production/
default, and full world/kernel/pkgbase/runtime qualification is incomplete.

### 2026-10-29 OpenSM common library and default ibstat

Added native osmcomp with all 17 maintained sources, native pthread dependency,
HAVE_CONFIG_H, symbol version map and static/shared/debug installation. Shared
OpenSM complib/IBA header providers support both maintained include spellings
(complib/iba and infiniband/complib/iba), without duplicating installed headers.
Added ibstat with inherited ibdiag_common.c/ibdiag_sa.c, declared diagnostic and
ibnetdisc headers, and native osmcomp/ibmad/ibumad dynamic dependencies.

Maintained frontend bazel-osmcomp-20261029 matches fresh Make reference on six
metadata records, static member/global/undefined-symbol inventory and one valid
ELF/debug pair. ibstat run bazel-ibstat-20261029-r2 matches five metadata records,
one exact manual and one ELF/debug pair. Both use 16 jobs and match checked
symbols/dynamic fields. Evidence/scripts: bazel-osmcomp-qualification-20261029
and bazel-ibstat-qualification-20261029/r2 under /usr/obj/usr/src.

Initial ibstat comparison rejected package=rdma metadata; maintained Make uses
package=utilities. Corrected target/package tags and retained the failed report.
No program source changes, device discovery, network operations or performance
testing. Native optional diagnostics and complete parent aggregation remain
unfinished. Frontend review: existing format-5 targets/archive helpers suffice;
no build-bsd.c/backend/manual interface change. Make remains production/default;
complete world/kernel/pkgbase/runtime/performance qualification remains open.

### 2026-10-29 libibnetdisc and complete diagnostic selection

Added native libibnetdisc with four C sources and one C++ source, source libc++
headers selected only for C++ compilation, explicit C++ runtime and OFED library
dependencies, maintained symbol map, static/shared/debug installation and all
three manuals/five manual hardlinks. Maintained frontend bazel-ibnetdisc-20261029
matches fresh Make on 14 metadata records, eight exact manual payloads, static
member/global/undefined-symbol inventory and one valid ELF/debug pair.

Added all 20 optional diagnostics beside existing ibstat, preserving inherited
common source files, per-program ibnetdisc dependencies and utilities package
ownership. Parent installation_archives selects optional targets through existing
ofed_extra_enabled setting. No manual is invented for ibmirror.
Frontend bazel-ib-diags-20261029 with ofed_extra=true matches fresh recursive Make
MK_OFED_EXTRA=yes reference: 64 metadata records, 20 exact manuals and 21 valid
ELF/debug pairs with matching symbols/dynamic fields. Default aggregate run
bazel-ib-diags-default-20261029 selects only ibstat and matches its five records,
one manual and one ELF/debug pair. All builds use 16 jobs.

Evidence/scripts: bazel-ibnetdisc-qualification-20261029 and
bazel-ib-diags-qualification-20261029 (default subdirectory for default aggregate),
under /usr/obj/usr/src. No hardware discovery, traffic, port changes, management
operations or performance tests were run. Make consumer references reuse staged
dependency libraries. These comparisons establish structural installation/binary
parity, not instruction or runtime equivalence. Optional opensm and remaining
base-library coverage are still incomplete.

Frontend review: existing ofed_extra/ofed settings and format-5 archive sets
cover both configurations; no build-bsd.c/backend/manual interface change needed.
Make remains production/default; full world/kernel/pkgbase and runtime/performance
gates remain open. No host installation or privileged device operation occurred.

### 2026-10-29 OpenSM vendor and core libraries

Added native osmvendor (two maintained sources) and opensm library (three sources),
reusable declared subnet/vendor headers, maintained HAVE_CONFIG_H configuration,
symbol-version maps, native pthread/ibumad dependencies where selected by Make,
and static/shared/debug installation. Header installation remains in the OFED
include package. No source changes or new runtime policy.

Maintained frontend bazel-opensm-libraries-20261029 uses 16 jobs and matches fresh
isolated Make references bazel-osmvendor-reference-20261029 and
bazel-opensm-reference-20261029: six metadata records each, both static archive
member/global/undefined-symbol inventories, and both ELF/debug pairs with
matching symbols/dynamic fields. Evidence/scripts in the corresponding
bazel-osmvendor-qualification-20261029 and bazel-opensm-qualification-20261029
directories under /usr/obj/usr/src.

The OpenSM executable remains unconverted: it also requires native lexer/parser
actions for osm_qos_parser_l.l and osm_qos_parser_y.y. Existing bsd_lex_yacc rules
are available; integrate declared outputs instead of importing generated object
tree files. No subnet-manager execution, device operations, traffic or performance
checks occurred. Frontend review: current format-5 library targets/archive helpers
cover this batch; no build-bsd.c/backend/manual interface change needed. Make
remains production/default and full-system qualification remains incomplete.

### 2026-10-29 OpenSM executable and native generators

Added OpenSM executable with all 84 maintained C sources and two generated C
sources. Native bsd_lex/bsd_yacc actions use native lex/m4/yacc execution tools,
declared grammar inputs, parser header/source output groups and source header
providers. Preserves native opensm/osmvendor/osmcomp/wrap/pthread dependencies,
HAVE_CONFIG_H, PIE, utilities package and section-eight manual.

Maintained frontend bazel-opensm-program-20261029-r3 (16 jobs) matches fresh Make
reference on five metadata records, exact manual payload and one valid ELF/debug
pair with matching global/undefined symbols and dynamic fields. Generated lexer
C, parser C and parser header all match after only source-root and generated-
output-directory path normalization; raw snapshots/hashes and normalization scope
are saved under bazel-opensm-program-qualification-20261029/generated.

Initial build linked unsuccessfully because one-time source transcription omitted
the digit-containing osm_vl15intf.c. Corrected complete source inventory against
Make. Follow-up edit temporarily malformed a filegroup; corrected declaration.
Both failed runs remain recorded, with unchanged qualification criteria. No
upstream program sources or generator expectations were changed.

No subnet manager was started and no device/network/port changes occurred.
Runtime QoS parsing, subnet behavior and performance remain unqualified. Frontend
review: existing native generator rules and format-5 staging cover this build;
no build-bsd.c/backend/manual interface change required. Top-level OFED aggregation
and remaining library coverage still need completion. Make remains production/
default and full world/kernel/pkgbase/runtime/performance gates remain open.

### 2026-10-29 complete OFED program aggregates

Added //usr.bin/ofed:installation_archives mirroring maintained subgroup selection:
libibverbs, librdmacm, diagnostics, plus OpenSM when ofed_extra_enabled. Like the
Make subdirectory target, the world parent decides whether OFED itself is enabled.
Extended bsd_install_archive_set with a distinct BsdInstallArchiveSetInfo provider
and typed alternatives accepting either leaf archives or nested sets. All payload,
metadata and directory-metadata output groups propagate as transitive depsets.
Collections do not impersonate BsdInstallArchiveInfo; bsd_pkg_create continues to
require one leaf archive and its directory metadata.

Maintained 16-job frontend runs bazel-ofed-programs-default-20261029 and
bazel-ofed-programs-extra-20261029 match fresh recursive Make references with
MK_OFED_EXTRA=no/yes respectively. Default: 12 ELF/debug pairs, 40 metadata records,
12 exact manuals. Extras: 33 ELF/debug pairs, 102 records, 32 manuals (ibmirror has
none). All checked symbols and dynamic properties match. Reports/scripts reside
in bazel-ofed-programs-qualification-20261029/default and /extra under /usr/obj/usr/src.
These runs exercise nested collections through the normal frontend and establish
recursive installation coverage, not hardware runtime or whole-system coverage.

OFED library audit finds libibcm still lacks a native BUILD target; library parent
aggregation remains pending. No daemon/device operations or performance tests ran.
Frontend review: format-5 artifacts already collects transitive output groups;
the maintained archive backend changed in this batch, with no build-bsd.c interface
or manual option change required. Package creation/publication was not exercised.
Make remains production/default; full world/kernel/pkgbase/runtime gates are open.

### 2026-10-29 complete OFED library/header aggregate

Added native libibcm with cm.c, declared public/config headers and source
ib_user_cm.h dependency, native ibverbs dependency, maintained symbol map and
static/shared/debug installation. Added //lib/ofed:installation_archives covering
all 15 maintained directories (14 libraries plus the OFED header installation).
Granted only the OFED parent visibility to each installation archive; initial
analysis failure identifying private leaf targets is retained.

Maintained frontend bazel-ofed-libraries-20261029-r2 (16 jobs) matches fresh
recursive Make reference bazel-ofed-libraries-reference-20261029: 318 distinct
metadata records, 259 exact nonbinary header/manual payloads, all 14 static
archive member/global/undefined-symbol inventories, and 14 valid shared ELF/debug
pairs with matching symbols/dynamic fields. Verifier saves each static archive
and its own report rather than overwriting a single-library report. Evidence:
bazel-ofed-libraries-qualification-20261029 under /usr/obj/usr/src.

Together with the earlier default/extra program aggregates, this qualifies
recursive build/installation comparisons for the maintained OFED program/library
subtrees. It does not qualify RDMA hardware operations, kernel drivers, runtime
provider behavior, ports consumers or performance. No host installation occurred.
Frontend review: current format-5 transitive output collection and maintained
archive backend cover the aggregate; no build-bsd.c/manual interface change.
Whole-system world/kernel/pkgbase/bootstrap/runtime/performance gates remain open;
Make stays production/default.

### 2026-10-29 LLVM compiler graph foundation: Demangle

Compiler subtree audit found no native libllvm/libclang/TableGen build graph.
Added the reusable six-source LLVM Demangle component at
//contrib/llvm-project/llvm/lib/Demangle:demangle with explicit source/public
headers, source libc++ headers, C++17, no RTTI/exceptions, inline visibility and
function/data sections. A PIC archive target supports structural qualification;
this component does not install an extra library. Full libllvm linkage remains
unimplemented. Compiler target triples, target backends, TableGen and bootstrap
must be modeled for the remaining LLVM graph; this header-independent component
does not consume those macros.

Added llvm_assertions=true and llvm_full_debuginfo=false native settings matching
maintained defaults, with NDEBUG selection and line-table/full debug flags.
Maintained frontend bazel-llvm-demangle-20261029-r2 builds all six sources with
16 jobs. Fresh Make Demangle/*.pico targets in an isolated object tree match all
six global/undefined symbol inventories. Reference/copies/repeatable verify.py
and reports are in bazel-llvm-demangle-qualification-20261029 under /usr/obj/usr/src.
This is component object parity, not a compiler executable, installed library,
full debug qualification, runtime demangling or performance result. Alternate
assertion/full-debug configurations remain to be qualified.

Frontend review: existing typed format-5 build-settings passes the new flags;
bsd-build(8) documents their defaults and limited current scope. No build-bsd.c
parser/backend change is needed. Make remains production/default and complete
LLVM/Clang/world/kernel/pkgbase/runtime/performance qualification is open.

### 2026-10-29 native LLVM minimal Support/TableGen archive

Added //contrib/llvm-project/llvm/lib:llvmminimal with the explicit 78-source
lib/clang/libllvmminimal inventory and minimal_archive for structural comparison.
Declared upstream C/C++ headers, maintained FreeBSD LLVM configuration/VCS headers,
private Support/TableGen includes and source libc++ headers. C++17/no RTTI/no
exceptions flags apply only to C++ actions; assertion/debug settings retain the
maintained defaults. No Make execution or prebuilt LLVM objects enter this target.
The selected sources do not consume LLVM host/default-target triple or native
backend macros; full compiler triple/backend configuration remains future work.

Maintained frontend bazel-llvm-minimal-20261029-r3 (16 jobs) builds the archive.
Fresh isolated Make libllvmminimal.a matches all 78 archive member names and
aggregate global/undefined symbol multiplicities. Scripts and archive-parity.json:
/usr/obj/usr/src/bazel-llvm-minimal-qualification-20261029. Comparison is not
instruction identity, per-member symbol attribution, runtime, full-debug or
performance qualification. The internal archive has no installed package payload.

First run rejected a nonexistent Support/*.def glob; second caught undeclared
llvm-c headers in the sandbox. Removed the nonexistent pattern and declared the
actual upstream C API headers; both failed runs remain retained. No source code,
sandbox restrictions or comparison expectations were relaxed.

Frontend review: existing format-5 targets, LLVM settings, archive artifacts and
source_graph.py setting handling cover this addition; build-bsd.c/backend/manual
need no new interface. TableGen executable/actions, full LLVM/Clang, world/kernel,
pkgbase/bootstrap/runtime/performance gates remain open. Make stays production/
default; no host installation, VM or publication occurred.

### 2026-10-29 native llvm-min-tblgen and first TableGen action

Added //usr.bin/clang/llvm-min-tblgen:bootstrap with the maintained three-source
bootstrap inventory and native llvmminimal, C++, execinfo, terminfo and threading
dependencies. This is explicitly a build-time generator, not the installed
full-libllvm compiler utility. Added bsd_tablegen with cfg=exec tool selection,
FilesToRunProvider executable/runfiles, declared .td inputs/includes/output and
argument-vector invocation without a shell. The value_types target generates
llvm/CodeGen/GenVT.inc from the real ValueTypes.td input.

First executable build succeeded, but first execution action failed because
source libthr requires __uexterr_set_ue absent from host libc. Declared matching
native libc/shared_link_interface and libc/libsys dynamic dependencies; retained
failure evidence. The bootstrap tool opts into the existing runtime-search-path
feature so execution uses its declared build libraries. No host library fallback
or source patch was introduced.

Maintained frontend bazel-llvm-min-tblgen-generated-20261029-r2 (16 jobs) succeeds
including the sandboxed BSDTableGen action and separate execution-configuration
tool build. Exact 44,357-byte GenVT.inc matches a fresh invocation of the existing
Make bootstrap generator, SHA256
7c495b06287ade97e34af8967228c93df905793a3688412c94c83f5282a2d431.
Reference tool/input hashes, scripts, output and generator-parity.json are under
/usr/obj/usr/src/bazel-llvm-min-tblgen-qualification-20261029. The Make reference
generator itself was not rebuilt in this batch. This verifies one real generated
header, not all TableGen modes, installed compiler metadata, cross-architecture
execution, complete bootstrap independence, or system performance.

Frontend review: normal format-5 targets/settings and artifact collection support
the new tool/action; no new build-bsd.c/backend/manual interface is required.
Full llvm-tblgen/clang-tblgen, compiler graph, world/kernel/pkgbase/runtime/cache/
performance qualification remain open; Make stays production/default.

### 2026-10-29 full native llvm-tblgen bootstrap

Added //usr.bin/clang/llvm-tblgen:bootstrap with all 72 maintained Make source
entries, declared TableGen headers/fold definitions and the generated GenVT.inc
provider from native llvm-min-tblgen. Execution actions retain native library
runtime dependencies and cfg=exec generator selection. Added real attributes and
intrinsic_enums actions; the latter declares the Intrinsics*.td family plus
ValueTypes/SDNodeProperties inputs and its include root. No prebuilt generated
header is substituted for the minimal-to-full generator dependency.

Maintained 16-job frontend bazel-llvm-tblgen-generated-20261029 succeeds for the
target and execution configurations and both sandboxed generation actions.
Attributes.inc (17,018 bytes) and IntrinsicEnums.inc (37,170 bytes) match fresh
invocations of the existing Make bootstrap tool exactly. Evidence and repeatable
verify.py: /usr/obj/usr/src/bazel-llvm-tblgen-qualification-20261029. The reference
generator itself was not freshly rebuilt. Initial build failure for undeclared
X86ManualFoldTables.def is retained; the actual source definition was added to
the header dependency without changing source or sandbox policy.

This qualifies these two generation modes and their input closure, not every
backend, cross-architecture execution, installed utility/package metadata or
complete compiler bootstrap. Frontend review: existing format-5 target/settings,
artifact collection and maintained TableGen backend need no new build-bsd.c or
manual interface. Full Clang/LLVM, world/kernel/pkgbase/runtime/cache/performance
gates remain open; Make stays production/default. No host installation occurred.

### 2026-10-29 native clang-tblgen bootstrap

Added the 22-source //usr.bin/clang/clang-tblgen:bootstrap and single-source
clangminimal support component (RISCVVIntrinsicUtils.cpp), with source headers,
maintained LLVM assertion/debug settings and native library/runtime dependencies.
Clang uses ncursesw as in clang.prog.mk. The first real Clang TableGen action
produces clang/Basic/AttrList.inc with explicit AttrDocs, DeclNodes, StmtNodes and
transitive ASTNode definitions. No staged generated definitions are imported.

Maintained frontend bazel-clang-tblgen-20261029-r2 (16 jobs) succeeds in target and
execution configurations and the sandboxed attribute generation action.
AttrList.inc is 16,387 bytes and matches a fresh invocation of the existing Make
bootstrap generator exactly. Evidence/scripts/reference tool hash:
/usr/obj/usr/src/bazel-clang-tblgen-qualification-20261029. Initial failure for
undeclared ASTNode.td is retained; adding the actual transitive input fixes it
without relaxing sandboxing. The Make generator itself was not freshly rebuilt.

This qualifies one Clang generation mode and execution path, not all diagnostics,
architecture emitters, installed compiler metadata, compiler behavior or cross
execution. No source files were changed. The selected sources do not consume
CLANG_ENABLE_STATIC_ANALYZER; full Clang feature configuration remains to model
when building components that use it. Frontend review: existing format-5 settings,
native action backend and artifacts suffice; build-bsd.c/manual need no interface
change. Complete compiler/world/kernel/pkgbase/bootstrap/runtime/performance gates
remain open; Make stays production/default, with no host installation.

### 2026-10-29 complete Clang diagnostic generated-header family

Added lib/clang/libclang native diagnostic generation: 13 maintained components
(AST, Analysis, Comment, Common, CrossTU, Driver, Frontend, InstallAPI, Lex, Parse,
Refactoring, Sema, Serialization), four modes each (CompatIDs, Enums, Kinds,
Interface), plus AllCompatIDs, Groups and IndexName. Each of 55 outputs is a
separate native TableGen action with declared Diagnostic*.td input family and
include root. diagnostic_headers exports generated headers for future compiler
consumers; diagnostic_outputs supports artifact inventory/qualification. The
Bazel declarations own this inventory and do not parse Make at build time.

Maintained frontend bazel-clang-diagnostics-20261029 (16 jobs) succeeds. Compared
all 55 output names and 2,195,560 bytes exactly against fresh invocations of the
existing Make bootstrap generator. Qualification reference selection is derived
independently from maintained Make diagnostic recipes. Scripts, reference tool
hash and per-output hashes: /usr/obj/usr/src/bazel-clang-diagnostics-qualification-
20261029. All outputs match. Reference generator was not freshly rebuilt.

This establishes diagnostic generation coverage, not compiled Clang diagnostics,
installed compiler/package behavior or other generated families. Frontend review:
existing format-5 targets/artifacts and maintained TableGen backend suffice; no
build-bsd.c/manual interface change required. Compiler/world/kernel/pkgbase/runtime/
cache/performance gates remain open; Make stays production/default. No host
installation or publication occurred.

### 2026-10-29 Clang attribute generated-header family

Added 18 libclang generation recipes consuming Attr.td (coverage corrected
to 21 in the subsequent AST/inventory audit): AST
classes/implementation/visitors/dumps, Basic attribute lists/spellings, Sema tables
and serialization readers/writers. Each has a native TableGen action and declared
transitive definitions; attribute_headers supplies the compiler include namespace.
Moved the earlier generator demonstration to an alias of the maintained AttrList
output, avoiding a duplicate producer. Explicit mappings are native Bazel metadata;
Make recipe extraction was used only to prepare the independent comparison.

Maintained frontend bazel-clang-attributes-20261029 (16 jobs) succeeds. All 18
relative output paths and 4,537,357 bytes match fresh invocations of the existing
Make bootstrap generator exactly. Comparison preserves directories (Basic and Sema
both have AttrParsedAttrList.inc); it does not collapse duplicate basenames.
Evidence: /usr/obj/usr/src/bazel-clang-attributes-qualification-20261029, including
recipe inventory, tool hash, reference commands and per-output hashes. Reference
generator itself was not freshly rebuilt. This qualifies generated definitions,
not compiled attribute semantics, PCH interoperability or full compiler behavior.

Frontend review: format-5 artifact collection and existing TableGen action backend
cover this change; no new build-bsd.c/manual interface. Remaining generated families,
compiler libraries, world/kernel/pkgbase/bootstrap/runtime/performance gates are
open. Make stays production/default; no host installation or publication occurred.

### 2026-10-29 AST definitions and corrected attribute inventory

Added 14 native AST definition actions: property readers/writers, comment commands/
HTML tables, node lists and statement data collectors. Source inputs and recursive
.td include closure are explicit Bazel declarations. Added three previously missed
attribute actions: Parse/AttrParserStringSwitches, Parse/AttrSubMatchRulesParser-
StringSwitches and Sema/AttrTemplateInstantiate. Earlier claim that 18 outputs were
all maintained attribute recipes was incorrect: the transcription regex omitted
multiline prerequisite declarations. The correct attribute count is 21. The 18
previously compared outputs remain valid; their coverage claim was incomplete.

Reference inventory now normalizes Make line continuations before selecting recipes.
The independent count assertion exposed the third omission after the first two were
identified during review; implementation was completed rather than excluding the
extra reference. Maintained frontend bazel-clang-ast-20261029-r2 (16 jobs) succeeds.
All 35 relative outputs (21 attributes plus 14 AST definitions), totaling 4,976,622
bytes, match fresh invocations of the existing Make bootstrap generator exactly.
Scripts, complete recipe-derived reference inventory, tool hash and per-output
comparisons: /usr/obj/usr/src/bazel-clang-ast-qualification-20261029. Reference tool
was not freshly rebuilt. First build and inventory-failure evidence are retained.

Frontend review: current format-5 targets/artifacts and TableGen backend suffice;
no build-bsd.c/manual interface change. Generated definition parity does not qualify
compiled compiler behavior or installation. Remaining compiler definitions/libraries,
world/kernel/pkgbase/bootstrap/runtime/performance gates remain open. Make stays
production/default; no host installation or publication occurred.

### 2026-10-29 ARM/RISC-V Clang builtin definitions

Added 30 maintained architecture builtin generation actions covering ARM CDE/MVE,
FP16/NEON, SVE/SME and RISC-V base/Andes/SiFive vector definitions. Each action has
its actual command source and explicit recursive TableGen input closure. The
architecture_builtin_headers provider exposes the generated compiler include tree.
Corrected Make arm_immcheck_types.inc prerequisite from arm_mve.td to arm_sve.td,
matching the input its existing command actually reads; emitted command unchanged.

Maintained frontend bazel-clang-arch-20261029 (16 jobs) succeeds. All 30 output paths
and 8,596,615 bytes match fresh invocations of the existing Make bootstrap generator
exactly. Evidence: /usr/obj/usr/src/bazel-clang-arch-qualification-20261029, including
recipe-derived inventory, reference tool hash/commands and per-output comparison.
Initial reference helper incorrectly used the general include root; corrected to
clang/Basic as maintained recipes specify, retaining its failed command receipt.
Native build needed no source or sandbox changes. Reference tool not freshly rebuilt.

Frontend review: existing format-5 inputs, native TableGen action and artifact
collection cover this change; no build-bsd.c/manual interface change. Output parity
does not qualify target machine-code generation, execution, ABI or CPU features.
Remaining compiler definitions/libraries, world/kernel/pkgbase/bootstrap/runtime/
performance gates stay open; Make remains production/default. No host installation
or publication occurred.

### 2026-10-29 Clang builtin tables

Added twelve native builtin-table generation actions: general Builtins, ten
maintained architecture tables (BPF, DirectX, Hexagon, NVPTX, RISCV, SPIRVCommon,
SPIRVCL, SPIRVVK, X86, X86_64), and BuiltinTemplates. Each source has an explicit
recursive include closure rather than depending on all compiler definitions.
Corrected Make's architecture-table prerequisite to Builtins${arch}.td, matching
its existing command input instead of the unrelated general Builtins.td. Commands
and generated semantics were not changed.

Maintained 16-job frontend bazel-clang-builtins-20261029 succeeds. All twelve output
paths and 1,663,881 bytes match fresh invocations of the existing Make bootstrap
generator exactly. Reference independently checks the architecture list against
the maintained Make loop. Evidence/scripts/tool hash/per-output comparisons:
/usr/obj/usr/src/bazel-clang-builtins-qualification-20261029. Reference generator
itself was not freshly rebuilt. This establishes generated-table parity, not
compiled builtin lowering, target ABI behavior or execution.

Frontend review: existing format-5 targets/artifacts and TableGen backend suffice;
no build-bsd.c/manual interface change. Remaining checker/opcode/OpenCL/driver
outputs and compiler libraries still need integration, followed by full world/
kernel/pkgbase/bootstrap/runtime/performance qualification. Make stays production/
default; no host installation or publication occurred.

### 2026-10-29 complete libclang generated-header aggregate

Added checker registration, constexpr opcodes, OpenCL builtin definitions and
LLVM-generated driver options with explicit source/includes and execution tools.
Added generated_headers/generated_outputs aggregates over every maintained
libclang definition family. Driver options uses native llvm-tblgen; the other
three use native clang-tblgen. No imported generated header substitutes are used.

Maintained frontend bazel-clang-generated-20261029 (16 jobs) succeeds. Independently
queried Make's expanded ${TGHDRS} through BuildEnvironment: 136 unique paths. The
Bazel aggregate matches exactly that full path set, closing the loop/multiline
inventory risk exposed earlier. All 136 outputs, totaling 20,890,780 bytes, match
recorded fresh invocations of existing Make bootstrap generators. Prior family
references are reused without regenerating unchanged source inputs; four new
references are freshly generated here. Reference tools themselves were not rebuilt.
Evidence, expanded Make inventory, scripts and per-file hashes:
/usr/obj/usr/src/bazel-clang-generated-qualification-20261029.

This closes libclang generated-header inventory/parity for the queried configuration,
not library compilation/linkage, compiler behavior, installed metadata, cross builds
or complete LLVM generated definitions. Frontend review: current format-5 aggregate
artifacts and native TableGen backend cover this addition; no build-bsd.c/manual
interface changes. Compiler/world/kernel/pkgbase/bootstrap/runtime/performance
qualification remains open; Make stays production/default. No host installation
or publication occurred.

### 2026-10-29 native Clang lexer component

Added the explicit 25-source Clang Lex component and PIC archive qualification
target, consuming native generated Clang headers through declared providers and
maintained source/configuration headers. C++17, assertion/debug settings, no RTTI/
exceptions, section flags and shared -UPIC behavior match maintained component
flags. This is a component of libclang, not an additional installed library.

Added typed clang_full=true build setting matching maintained MK_CLANG_FULL,
selecting CLANG_ENABLE_STATIC_ANALYZER for components consuming it. Existing
format-5 source_graph setting handling already accepts it; documented scope in
bsd-build(8). No C frontend parser change is needed. Full compiler feature/variant
coverage remains unqualified.

Maintained frontend bazel-clang-lex-20261029 (16 jobs) succeeds. Built 25 fresh Make
Lex/*.pico objects plus required Clang generated headers in an isolated reference
object tree. All 25 individual global/undefined symbol inventories match native
PIC objects. Evidence/scripts: /usr/obj/usr/src/bazel-clang-lex-qualification-20261029.
Make reference uses existing bootstrap generators and staged SDK dependencies;
this is not a fresh complete toolchain build. No source modifications or comparison
exceptions were required. Matching symbols does not establish instruction identity,
lexer runtime semantics, full compiler linkage or performance.

Remaining compiler libraries/configuration, world/kernel/pkgbase/bootstrap/runtime/
performance gates remain open. Make stays production/default. No host installation
or publication occurred.

### 2026-10-29 native Clang parser and LLVM directive definitions

Added the explicit 18-source Clang Parse component/PIC archive, preserving the
lexer component's maintained compile settings and declaring generated LLVM
OpenMP/OpenACC headers. Added native actions for ACC.inc, OMP.h.inc and OMP.inc,
with DirectiveBase.td declared as input. Extended Clang source headers to include
the clang-c API required by CodeCompleteConsumer.h; initial sandbox failure for
undeclared clang-c/Index.h is retained. No compiler sources were changed.

Maintained frontend bazel-clang-parse-20261029-r2 (16 jobs) succeeds. All 18 native
PIC objects match fresh isolated Make Parse/*.pico global/undefined symbol
inventories. Three directive generated files match fresh invocations of existing
Make llvm-tblgen exactly. Evidence/scripts/reports:
/usr/obj/usr/src/bazel-clang-parse-qualification-20261029. Make reference uses
existing bootstrap tools and staged LLVM/SDK headers; not a complete fresh
compiler bootstrap. Object-symbol equality does not prove instruction identity,
parser runtime semantics, diagnostic correctness or full compiler linkage.

Frontend review: existing documented LLVM/Clang settings, format-5 artifacts and
TableGen backend suffice; no build-bsd.c/manual interface change required. Remaining
compiler components, world/kernel/pkgbase/bootstrap/runtime/performance gates stay
open; Make remains production/default. No host installation/publication occurred.

### 2026-10-29 native Clang serialization component

Added the explicit 17-source Serialization component and PIC archive, including
AST readers/writers, module index/cache management, PCH containers and template
argument hashing. Declared private headers and native generated Clang/LLVM directive
providers; compile configuration preserves maintained shared-library behavior.
This is a component of libclang, not an extra installed library.

Maintained frontend bazel-clang-serialization-20261029 (16 jobs) succeeds. All 17
individual PIC global/undefined symbol inventories match fresh isolated Make
Serialization/*.pico objects. Evidence/scripts:
/usr/obj/usr/src/bazel-clang-serialization-qualification-20261029. Reference uses
existing bootstrap generators/staged SDK dependencies. No source patches or
comparison exceptions were needed. This does not qualify module/PCH read-write
round trips, compatibility across compiler versions, malformed PCH handling,
instruction identity or performance; those require the linked compiler.

Frontend review: current documented LLVM/Clang settings and format-5 artifacts
cover the component; no build-bsd.c/backend/manual interface change. Remaining
compiler libraries/linkage and whole-system world/kernel/pkgbase/bootstrap/runtime/
performance gates remain open. Make stays production/default; no host installation
or publication occurred.

### 2026-10-29 native LLVM target-parser definitions

Basic component review identified generated target-parser dependencies. Added
AArch64TargetParserDef.inc, ARMTargetParserDef.inc, RISCVTargetParserDef.inc and
PPCGenTargetFeatures.inc as native llvm-tblgen actions, matching the maintained
Make modes. Declared recursive input closures explicitly: AArch64 49 target/40
shared files, ARM 29/39, RISCV 77/39, PowerPC 36/38. Target input filegroups and
shared definitions are regular Bazel dependencies; no runtime Make parsing or
undeclared source-directory access is used. A header provider exposes the results.

Maintained frontend bazel-llvm-targetdefs-20261029 (16 jobs) succeeds in the sandbox.
All four outputs total 129,521 bytes and match fresh invocations of existing Make
llvm-tblgen exactly. Evidence/scripts/tool hash:
/usr/obj/usr/src/bazel-llvm-targetdefs-qualification-20261029. Reference generator
was not freshly rebuilt. This qualifies generated target definitions, not backend
machine-code generation, architecture execution or broad cache invalidation tests.
Basic component compilation remains next; its version header must be declared as
a source input rather than copying the version constant into build rules.

Frontend review: existing format-5 settings/artifacts and native TableGen backend
suffice; no build-bsd.c/manual interface change. Compiler/world/kernel/pkgbase/
bootstrap/runtime/performance gates remain open; Make stays production/default.
No host installation/publication occurred.

### 2026-10-29 native Clang Basic component

Added 74 maintained Basic sources, including target-specific implementations.
Targets.cpp is a separate compile group with the source freebsd_cc_version.h
force-included as a declared header; the version value is not copied into Bazel.
Other sources retain ordinary flags. Declared maintained VCSVersion.inc and Clang
source .inc headers alongside existing version/config headers. Initial sandbox
failure identified AllDiagnosticKinds.inc absent from the source header provider;
corrected the provider without importing generated outputs or changing source.

Maintained frontend bazel-clang-basic-20261029-r2 (16 jobs) succeeds. All 74 native
PIC object global/undefined symbol inventories match fresh isolated Make objects,
including the Basic/Targets subdirectory and special Targets.cpp object. Evidence:
/usr/obj/usr/src/bazel-clang-basic-qualification-20261029. Source inventory maps
basenames back to actual Make object paths and verifies uniqueness. Reference uses
existing bootstrap generators and staged LLVM/SDK dependencies. No compiler source
patches or comparison exceptions were needed. Object parity does not establish
linked compiler target selection, predefined macro correctness, runtime behavior,
instruction identity or performance.

Frontend review: current documented settings and format-5 artifacts suffice; no
build-bsd.c/backend/manual interface change. Compiler/world/kernel/pkgbase/bootstrap/
runtime/performance qualification remains open. Make stays production/default;
no host installation or publication occurred.

### 2026-10-29 native Clang AST component and LLDB source selection

Added 109 unconditional AST sources plus ExternalASTMerger.cpp selected by the
new typed lldb setting (default true for the supported amd64 configuration).
Includes bytecode interpreter, ASTContext, expression evaluation, layouts and
printing. Updated opcode source ownership for the new Bazel package boundary.
Promoted existing LLVM attribute/intrinsic generation into libllvm header providers;
old generator labels alias the maintained outputs. Declared IR, directive and
target-parser generated headers required by AST compilation. Initial missing IR
and target-parser header failures remain recorded; no source patches/fallbacks.

Maintained frontend bazel-clang-ast-component-20261029-r3 (16 jobs) succeeds. All
110 individual PIC global/undefined symbol inventories match fresh isolated Make
AST objects. LLDB-disabled frontend bazel-clang-ast-component-nolldb-20261029 also
succeeds: 109 objects match independently queried Make MK_LLDB=no source selection
and the unchanged default-reference objects. The reference excludes only
ExternalASTMerger.cpp; no alternate Make object rebuild is claimed. Evidence:
/usr/obj/usr/src/bazel-clang-ast-component-qualification-20261029.

Reference compilation uses existing bootstrap tools and staged LLVM/SDK headers.
Results qualify compilation structure and this source-selection branch, not AST
runtime behavior, constexpr interpreter correctness, object instruction identity,
compiler linkage, debugger execution or performance. Documentation now describes
the lldb setting and its limited scope. Frontend review: format-5 typed settings
and artifacts already support it; no build-bsd.c parser change required.

Remaining compiler components/linkage and world/kernel/pkgbase/bootstrap/runtime/
performance gates remain open. Make stays production/default. No host installation
or publication occurred.

### 2026-10-29 native Clang semantic analysis

Added all 86 unconditional Sema sources as a native component/PIC archive, with
private headers and generated Clang definitions plus LLVM IR/directive/target
providers. Updated OpenCLBuiltins.td ownership for the new Sema package boundary;
the existing native generation action still consumes the same maintained input.
No compiler sources or semantic behavior were changed.

Maintained frontend bazel-clang-sema-20261029 (16 jobs) succeeds. All 86 individual
PIC global/undefined symbol inventories match fresh isolated Make Sema objects.
Evidence/scripts: /usr/obj/usr/src/bazel-clang-sema-qualification-20261029. Both
builds completed; long expression/template/OpenMP compilation was observed live,
not restarted on observation timeouts. Reference uses existing bootstrap tools
and staged LLVM/SDK headers. No comparison exceptions were required. Object parity
does not qualify language conformance, diagnostic output, template behavior,
instruction identity or complete compiler execution/performance.

Frontend review: existing documented settings, generated-header providers and
format-5 artifacts cover this component; no build-bsd.c/backend/manual interface
change. Basic/Lex/Parse/Serialization/AST/Sema now cover 330 default source objects
qualified structurally; this is not a whole-userland completion metric. Remaining
compiler components/linkage and whole-system world/kernel/pkgbase/bootstrap/runtime/
performance gates stay open. Make remains production/default; no host installation
or publication occurred.

### 2026-10-29 LLVM intrinsic and runtime-call generated definitions

CodeGen dependency review identified architecture intrinsic headers. Added all 18
maintained intrinsic-prefix header actions plus IntrinsicImpl.inc and
RuntimeLibcalls.inc, with explicit Intrinsics family and RuntimeLibcalls/SetTheory
input dependencies. intrinsic_headers exposes these and existing IR definitions
for consuming compiler components. Architecture mappings are native Bazel metadata;
Make parsing is confined to independent qualification inventory checks.

Maintained frontend bazel-llvm-intrinsics-20261029 (16 jobs) succeeds. All 20 output
names and 5,112,007 bytes match fresh invocations of existing Make llvm-tblgen
exactly. Reference independently checks the architecture list against maintained
Make recipes. Evidence/scripts/reference tool hash:
/usr/obj/usr/src/bazel-llvm-intrinsics-qualification-20261029. Reference tool was not
freshly rebuilt. This qualifies generated intrinsic definitions, not LLVM IR
execution, target lowering or runtime-call ABI correctness.

Frontend review: current format-5 inputs/artifacts and maintained TableGen backend
suffice; no build-bsd.c/manual interface change. CodeGen compilation remains next;
full compiler/world/kernel/pkgbase/bootstrap/runtime/performance qualification is
open. Make stays production/default; no host installation/publication occurred.

### 2026-10-29 native Clang code generation

Added all 100 maintained CodeGen sources with private headers and native generated
Clang/LLVM IR/intrinsic/directive/target/machine-value-type dependencies. Initial
missing GenVT.inc dependency is retained; fixed by declaring the existing native
provider, without importing staged generated headers or modifying sources.

Added bsd_component_objects, forwarding only the selected component's own declared
objects with full artifact paths and rejecting empty/duplicate artifact sets.
CodeGen has 11 repeated source basenames across Targets and TargetBuiltins. Initial
verifier incorrectly assumed Bazel object paths preserve source subdirectories;
Bazel uses numbered collision directories. Corrected verification to map each
object using recorded CppCompile -c/-o arguments, with full source-set equality
and uniqueness assertions, rather than guessing collision numbering or extracting
an archive into a flat directory.

Maintained frontend bazel-clang-codegen-20261029-r2 (16 jobs) succeeds. All 100
individual PIC global/undefined symbol inventories match fresh isolated Make
objects through that source mapping. Archive member-name multiplicities also
match all 100 sources, retaining duplicate basenames. Evidence/scripts/report:
/usr/obj/usr/src/bazel-clang-codegen-qualification-20261029. Reference uses existing
bootstrap tools and staged LLVM/SDK headers. No compiler sources or symbol
comparison exceptions changed. This does not qualify emitted machine code, LLVM
optimization behavior, runtime ABI correctness or performance.

Frontend review: the maintained object-export backend changed; normal format-5
artifacts already preserve the exported file names. No build-bsd.c/manual interface
change needed. Seven qualified default Clang components now cover 430 sources;
compiler linkage and remaining components/world/kernel/pkgbase/bootstrap/runtime/
performance gates remain open. Make stays production/default; no host installation
or publication occurred.

### 2026-10-29 native Clang Driver

Added all 75 maintained Driver sources as a native component with declared
private/public headers and generated dependencies. Added a CcInfo configuration
provider: llvm_host_triple and llvm_default_target_triple default to the selected
C++ toolchain target triple, while llvm_default_sysroot defaults to empty. These
are independent typed string inputs; the produced compiler does not inherit the
SDK path. The manual documents them. Cross-compiler override behavior remains
unqualified; these settings currently apply to Driver, not a complete compiler.

Maintained frontend bazel-clang-driver-20261029 (16 jobs) succeeds. All 75 individual
PIC global/undefined symbol inventories match fresh isolated Make objects;
archive member multiplicities match. Recorded native compile arguments confirm
all 75 use x86_64-unknown-freebsd16.0 for both default triples and an empty runtime
sysroot, matching this Make configuration. The triple is supplied by the selected
toolchain, not a literal in the rule. Evidence and scripts:
/usr/obj/usr/src/bazel-clang-driver-qualification-20261029.
Reference compilation uses existing bootstrap generators and staged SDK headers.
This establishes object structure/default definitions, not instruction identity,
compiler execution, cross compilation, tool discovery or performance.

Frontend review: source_graph.py already validates and forwards typed format-5
settings. Existing build-bsd.c dispatch and artifacts suffice; updated the
maintained backend rule and manual together. Eight qualified default Clang
components now cover 505 sources. Remaining compiler components/linkage and
world/kernel/pkgbase/bootstrap/runtime/cache/performance gates remain open.
Make remains production/default. No host installation or publication occurred.

### 2026-10-29 native Clang Frontend

Added all 38 maintained Frontend sources, including six Rewrite sources, as a
native component with private headers, generated definitions and declared
compiler defaults. FrontendActions consumes LLVM_HOST_TRIPLE; it uses the same
configuration provider as Driver. Updated the manual to describe both consumers.
No compiler sources or source-selection behavior were changed.

Maintained frontend bazel-clang-frontend-20261029 (16 jobs) succeeds. All 38 PIC
object global/undefined symbol inventories match fresh isolated Make objects.
Source-to-object correspondence comes from recorded compile actions, preserving
both FrontendActions.cpp sources in different directories; archive member
multiplicities also match. Evidence/scripts:
/usr/obj/usr/src/bazel-clang-frontend-qualification-20261029.
Reference uses existing bootstrap generators and staged SDK headers. This does
not qualify compiler invocation, diagnostics, module loading, instruction identity,
complete compiler linkage, alternate settings or performance.

Frontend review: existing typed format-5 inputs and native component/object backend
cover this addition; no build-bsd.c interface change needed. Nine qualified default
Clang components now cover 543 sources. FrontendTool and other remaining Clang/LLVM
components, compiler linkage and world/kernel/pkgbase/bootstrap/runtime/cache/
performance gates remain open. Make remains production/default. No host
installation or publication occurred.

### 2026-10-29 native Clang Analysis and reduced configuration

Added 22 core Analysis sources plus eight selected by the existing clang_full
setting. Both selections use native cc_library compilation and declared generated
header dependencies. Initial package loading failed on a copied private-header
glob: this directory has no private .h files. Removed the invalid declaration;
no empty-glob exception, compiler source patch or sandbox relaxation was added.
The failed run is retained at bazel-clang-analysis-20261029.

Default frontend run bazel-clang-analysis-20261029-r2 succeeds; all 30 PIC object
global/undefined symbol inventories and archive member multiplicities match fresh
isolated Make objects. Separate clang_full=false run
bazel-clang-analysis-minimal-20261029 succeeds; all 22 selected objects and archive
members match a separately compiled Make MK_CLANG_FULL=no reference. Both use
16 jobs and the maintained frontend. Evidence/scripts:
/usr/obj/usr/src/bazel-clang-analysis-qualification-20261029 and
/usr/obj/usr/src/bazel-clang-analysis-minimal-qualification-20261029.
References use existing bootstrap generators and staged SDK headers. These checks
qualify compilation/source selection, not analysis diagnostics, algorithm behavior,
instruction identity, compiler linkage or performance.

Frontend review: existing documented clang_full selection and format-5 artifact
handling suffice; no new build-bsd.c/backend interface/manual setting required.
Ten qualified default Clang components now cover 573 sources. Remaining Clang/LLVM
components and whole-system world/kernel/pkgbase/bootstrap/runtime/cache/performance
gates remain open. Make stays production/default; no host installation/publication.

### 2026-10-29 native Clang StaticAnalyzer

Added all 190 maintained StaticAnalyzer sources with explicit source inventory,
private headers and native generated checker/Clang/LLVM definitions. The component
is incompatible when clang_full=false, preserving its SRCS_FUL-only selection;
future aggregate consumers must select the dependency accordingly. Existing
maintained configuration headers retain disabled Z3 support. No compiler sources,
configuration headers or sandbox restrictions were changed.

Maintained frontend bazel-clang-static-analyzer-20261029 (16 jobs) succeeds.
All 190 individual PIC global/undefined symbol inventories match fresh isolated
Make objects, mapped by recorded compile actions; archive member multiplicities
also match. Evidence/scripts:
/usr/obj/usr/src/bazel-clang-static-analyzer-qualification-20261029.
Reference compilation uses existing bootstrap generators and staged SDK headers.
The separate bazel-clang-static-analyzer-disabled-20261029 run with clang_full=false
fails as expected at analysis: the explicitly requested component is incompatible,
with the dependency chain identifying static_analyzer. This is a negative selection
check, not a successful build of an empty analyzer.

Results establish compilation/source-selection structure, not analyzer execution,
checker diagnostics, Z3 support, emitted instruction identity, full compiler linkage
or performance. Frontend review: documented clang_full and current format-5 native
backend/artifacts cover this addition; no new build-bsd.c/manual interface required.
Eleven qualified default Clang components now cover 763 sources. Remaining Clang/
LLVM components, compiler linkage and world/kernel/pkgbase/bootstrap/runtime/cache/
performance gates remain open. Make stays production/default. No host installation
or publication occurred.

### 2026-10-29 native Clang Tooling

Added all 21 maintained SRCS_MIN Tooling sources, including dependency scanning,
compilation databases, refactoring and inclusion handling, as a native component.
Sources outside the maintained base selection are not silently added. Public
headers and generated dependencies are declared; this directory has no private
.h inputs. No compiler sources or sandbox restrictions were changed.

Maintained frontend bazel-clang-tooling-20261029 (16 jobs) succeeds. All 21 PIC
object global/undefined symbol inventories match fresh isolated Make objects;
archive member multiplicities match. Evidence/scripts:
/usr/obj/usr/src/bazel-clang-tooling-qualification-20261029.
Reference uses existing bootstrap generators and staged SDK headers. This qualifies
compilation structure, not dependency-scanner runtime, compilation-database parsing,
refactoring behavior, instruction identity or performance.

Frontend review: existing format-5 inputs, generated providers and object/archive
backend suffice; no build-bsd.c/manual interface change needed. Twelve qualified
default Clang components now cover 784 sources. Remaining Clang/LLVM components,
compiler linkage and world/kernel/pkgbase/bootstrap/runtime/cache/performance gates
remain open. Make stays production/default. No host installation/publication.

### 2026-10-29 nine native Clang support components

Added APINotes (4), ASTMatchers (7), CrossTU (1), Edit (3), ExtractAPI (6),
FrontendTool (1), Index (8), InstallAPI (1), and Rewrite (3): 34 maintained sources.
Each component has native compilation, declared generated/public/private headers
where applicable, and its own PIC archive/object outputs. CrossTU is compatible
only with clang_full enabled, matching its SRCS_FUL selection. The already native
Support/clangminimal component is not duplicated or counted in this batch.
No compiler sources or sandbox restrictions changed.

Maintained frontend bazel-clang-support-components-20261029 (16 jobs) succeeds.
All 34 individual PIC global/undefined symbol inventories match fresh isolated
Make objects; all nine archive member inventories match. Verifier maps saved
objects through recorded compile actions and asserts full source-set equality.
Evidence/scripts:
/usr/obj/usr/src/bazel-clang-support-components-qualification-20261029.
Reference uses existing bootstrap generators and staged SDK headers. This qualifies
compilation structure, not AST matching, indexing, API extraction, rewriting,
frontend dispatch runtime, instruction identity or performance. CrossTU-disabled
selection was implemented but not separately exercised in this batch.

Frontend review: existing clang_full input, format-5 artifacts and native backend
support these components; no build-bsd.c/manual interface change required.
Twenty-one qualified default Clang components now cover 818 sources, excluding the
separately integrated minimal Support component. Format source selection and full
libclang linkage remain open, along with LLVM completion and world/kernel/pkgbase/
bootstrap/runtime/cache/performance gates. Make stays production/default; no host
installation or publication occurred.

### 2026-10-29 native Clang Format configuration

Added 20 core Format sources and MatchFilePath.cpp selected when clang_format OR
clang_extras is enabled. Both new typed boolean settings default false, matching
share/mk/src.opts.mk. Native select uses a config_setting_group match_any; source
inventory is explicit. Private/public/generated headers are declared. Manual
states current component scope without claiming complete optional tool coverage.
No compiler source or configuration-header changes.

Default frontend bazel-clang-format-20261029 succeeds; all 20 PIC object symbol
inventories/archive members match a fresh Make reference with both options off.
bazel-clang-format-enabled-20261029 succeeds with clang_format=true; all 21 objects
and archive members match a separate fresh Make MK_CLANG_FORMAT=yes reference.
bazel-clang-format-extras-20261029 succeeds with only clang_extras=true; all 21
objects match that same enabled reference (no independent extras Make rebuild).
All runs use 16 jobs. Evidence/scripts:
/usr/obj/usr/src/bazel-clang-format[-enabled|-extras]-qualification-20261029.

Initial enabled verifier wrongly assumed every compile action appears in a warm
execution log. Bazel reused the core objects and compiled MatchFilePath.cpp.
Corrected verification combines retained default/enabled action records, rejects
conflicting mappings, and still requires exact full source/object sets plus all
symbol comparisons. No compiler assertion or comparison exception was relaxed.
Enabled run reports 5075 cache hits/two sandbox processes; extras run reports one
total action. This is observed reuse, not complete cache correctness qualification.
References use existing bootstrap generators/staged SDK headers. Formatting runtime,
style behavior, instruction identity, linkage and performance remain unqualified.

Frontend review: typed format-5 settings already cover both booleans; updated source
settings/manual together, no build-bsd.c parser change. Twenty-two default Clang
components now cover 838 qualified sources, plus one separately integrated minimal
Support source; optional Format adds one more. Complete aggregate inventory/linkage,
LLVM completion and world/kernel/pkgbase/bootstrap/runtime/cache/performance gates
remain open. Make stays production/default; no host installation/publication.

### 2026-10-29 complete default libclang PIC object aggregate

Added //lib/clang/libclang:pic_archive selecting all maintained native components,
including both Basic source groups. StaticAnalyzer and CrossTU dependencies are
selected only with clang_full. Added a distinct Support/support compilation target
for libclang's -UPIC/full-component contract; bootstrap clangminimal retains its
existing contract. Basic target_selection visibility is restricted to the libclang
package. The archive is not the installed shared library and supplies no claim of
resolved LLVM linkage or executable compiler behavior.

Added bsd_component_sources using an analysis aspect over each explicitly selected
group's resolved srcs. It emits source_inventory.json without parsing BUILD/Make
text and rejects empty groups/duplicate source paths. Normal format-5 artifacts
export it through build-bsd. Default frontend runs bazel-clang-aggregate-20261029
and bazel-clang-aggregate-inventory-20261029 succeed with 16 jobs. All 839 unique
native source paths match independently expanded Make ${SRCS}; archive member-name
multiplicities and aggregate global/undefined symbol multiplicities match all 839
Make reference objects. References reuse retained fresh component compilations;
Support was freshly compiled for this batch. Existing bootstrap generators/staged
SDK headers remain reference inputs. Evidence/scripts/reference list:
/usr/obj/usr/src/bazel-clang-aggregate-qualification-20261029.

Reduced inventory run bazel-clang-aggregate-reduced-inventory-20261029 sets
clang_full=false, lldb=false, clang_extras=true. All 640 resolved source paths match
expanded Make for those choices. This run qualifies source selection only, not a
compiled reduced aggregate. Default total is now 839 including Support; enabling
Format/extras adds MatchFilePath.cpp. Complete source coverage here means the
maintained libclang selection, not all vendor-tree sources or LLVM libraries.

Frontend review: updated native aggregation/inventory backend; current build-bsd.c
format-5 artifacts and documented settings suffice, no new CLI/manual interface.
Remaining work includes LLVM libraries/backends, shared/static linkage/install,
compiler execution and world/kernel/pkgbase/bootstrap/runtime/cache/performance
qualification. No instruction equivalence or full compiler claim. Make remains
production/default; no host installation/publication occurred.

### 2026-10-29 native LLVM IR component

Added all 77 maintained IR sources as a native libllvm component with explicit
private/public headers and native generated IR/intrinsic/runtime-call/value-type/
directive/target definitions. Compilation uses libllvm's LLVM_BUILD_LLVM_DYLIB
and -UPIC contract with existing assertion/debug settings. No LLVM sources or
configuration headers changed, and no staged generated headers were imported into
the native build.

Maintained frontend bazel-llvm-ir-20261029 (16 jobs) succeeds. All 77 PIC object
global/undefined symbol inventories match fresh isolated Make IR objects;
archive member multiplicities also match. Evidence/scripts:
/usr/obj/usr/src/bazel-llvm-ir-qualification-20261029.
Reference generated definitions use existing Make bootstrap tools; compilation
uses the staged SDK. Results qualify compilation structure, not IR verifier
behavior, optimization semantics, instruction identity, complete LLVM linkage or
performance. Alternate shared/static compile contracts remain unqualified.

Frontend review: existing typed settings, generated providers and format-5 artifact
backend suffice; no build-bsd.c/manual interface change required. Default libclang
object coverage remains 839; LLVM IR is a separate 77-source component and must not
be counted as more Clang sources. Most LLVM libraries/backends and complete compiler/
world/kernel/pkgbase/bootstrap/runtime/cache/performance qualification remain open.
Make stays production/default; no host installation/publication occurred.

### 2026-10-29 native LLVM Analysis component

Added all 119 maintained Analysis sources as a native libllvm component, with
public/generated dependencies and the shared LLVM_BUILD_LLVM_DYLIB/-UPIC compile
contract. The directory has no private header inputs. No LLVM source or sandbox
changes were required.

Maintained frontend bazel-llvm-analysis-20261029 (16 jobs) succeeds. All 119 PIC
object global/undefined symbol inventories match fresh isolated Make objects;
archive member multiplicities also match. Evidence/scripts:
/usr/obj/usr/src/bazel-llvm-analysis-qualification-20261029.
Reference uses existing bootstrap generators and staged SDK headers. This qualifies
compilation structure, not analysis semantics, optimization correctness, instruction
identity, LLVM linkage or performance. Alternate build contracts remain unqualified.

Frontend review: current typed settings, generated providers and format-5 object/
archive artifacts suffice; no build-bsd.c/manual interface change required. LLVM IR
and Analysis now cover 196 component sources; this is separate from the default
839-source libclang aggregate and is not total LLVM completion. Most LLVM libraries/
backends, compiler linkage and world/kernel/pkgbase/bootstrap/runtime/cache/performance
qualification remain open. Make stays production/default. No host installation or
publication occurred.

### 2026-10-29 native LLVM Transforms and extras

Added 311 maintained core transform sources plus four selected by clang_extras.
Native dependencies include private headers, ValueProfilePlugins.inc and the
SandboxVectorizer PassRegistry.def textual input. The first sandboxed build exposed
that missing .def declaration; added the actual source input without source patches,
SDK header imports or sandbox relaxation. Failed run retained at
bazel-llvm-transforms-20261029. Updated the manual for this existing setting consumer.

Corrected frontend bazel-llvm-transforms-20261029-r2 (16 jobs) succeeds. All 311 PIC
object global/undefined symbol inventories and archive member multiplicities match
fresh isolated Make references. bazel-llvm-transforms-extras-20261029 succeeds with
clang_extras=true; all 315 objects/archive members match the retained 311 core
references plus four fresh Make MK_CLANG_EXTRAS=yes objects. This is not a separate
315-object Make rebuild. Evidence/scripts:
/usr/obj/usr/src/bazel-llvm-transforms[-extras]-qualification-20261029.
References use existing bootstrap generators and staged SDK headers. Compile-action
provenance combines retained logs, rejects conflicting mappings, and requires full
source/object sets. Results do not establish optimization semantics, instruction
identity, full compiler execution/linkage or performance.

Verifier resource correction: loading whole execution logs used about 4 GB RSS per
process. The initial default comparison completed successfully; stopped the still
running extras comparison and changed both evidence scripts to stream JSON records.
Both complete comparisons then passed. Recorded /usr/bin/time -l maxima are 59,124
and 73,284 KB, with elapsed 27.87 and 27.40 seconds respectively. These measure the
comparison scripts only, not compiler/build memory or system performance. Preserve
streaming for future large-log qualification.

Frontend review: existing clang_extras input and format-5 backend/artifacts suffice;
manual updated, no build-bsd.c parser change. LLVM IR/Analysis/Transforms now cover
507 default component sources (four optional additions), separate from the default
839-source libclang aggregate. Remaining LLVM libraries/backends, linkage and world/
kernel/pkgbase/bootstrap/runtime/cache/performance gates stay open. Make remains
production/default. No host installation/publication occurred.

### 2026-10-29 native installed LLVM CodeGen component

Added 309 core CodeGen sources plus the installed-world MIW source and the default
LLD-dependent CommandFlags source: 311 default. Five EXT sources select on
clang_extras; CommandFlags selects on clang_extras OR lld. New lld boolean defaults
true, matching src.opts.mk. The component explicitly models installed libllvm;
TOOLS_PREFIX/LLD_BOOTSTRAP variants remain a separate unqualified contract. Private
headers and AsmPrinter/DIEHashAttributes.def are declared, alongside native generated
dependencies. No compiler source or sandbox changes were required.

Maintained frontend bazel-llvm-codegen-20261029 (16 jobs) succeeds. All 311 PIC object
global/undefined symbol inventories and archive member multiplicities match fresh
isolated Make references. Resolved source_inventory matches expanded Make ${SRCS}
for default (311), lld=false/extras=false (310), and lld=false/extras=true (316).
The two alternate runs request source_inventory only; they do not qualify compiled
alternate objects or their runtime behavior. Evidence/scripts:
/usr/obj/usr/src/bazel-llvm-codegen-qualification-20261029.
Reference uses existing bootstrap generators/staged SDK headers. Streaming verifier
completed in 24.73 seconds with 70,772 KB maximum RSS; these are verifier-only
measurements, not compiler performance. Source/object parity is not emitted-machine-
code equivalence, correctness of code generation, LLVM linkage or runtime validation.

Frontend review: added typed lld selection and updated maintained manual with its
current scope; existing format-5 build-bsd.c/backend/artifact support suffices.
LLVM IR/Analysis/Transforms/CodeGen now cover 818 default component sources, separate
from libclang's 839-source object aggregate. Remaining LLVM libraries/target backends,
linkage and world/kernel/pkgbase/bootstrap/runtime/cache/performance gates stay open.
Make remains production/default; no host installation/publication occurred.

### 2026-10-29 native installed LLVM MC component

Added 81 core MC sources, two XDW sources always selected for installed libllvm,
and the XDL disassembler entry source selected by clang_extras OR lld OR lldb:
84 default sources. Uses native generated/public/private headers and the installed
shared-library compile contract. Bootstrap TOOLS_PREFIX selection remains outside
this component's qualification. No compiler source/sandbox changes were required.

Maintained frontend bazel-llvm-mc-20261029 (16 jobs) succeeds. All 84 PIC object
global/undefined symbol inventories and archive member multiplicities match fresh
isolated Make references. Resolved native source inventories match expanded Make
for default (84) and all three selectors disabled (83). The reduced run requests
inventory only, not compiled alternate objects. Evidence/scripts:
/usr/obj/usr/src/bazel-llvm-mc-qualification-20261029.
References use existing bootstrap generators/staged SDK headers. Streaming verifier
reports 5.83 seconds and 57,056 KB maximum RSS; verifier-only measurements, not build
performance. Results do not qualify assembler/disassembler behavior, instruction
encoding, full linkage, runtime or performance.

Frontend review: added a group of existing typed selectors and updated the maintained
manual; current build-bsd.c format-5 backend/artifacts suffice. LLVM IR/Analysis/
Transforms/CodeGen/MC now cover 902 default component sources, separately from
libclang's 839-source aggregate. Remaining LLVM libraries/target backends and compiler/
world/kernel/pkgbase/bootstrap/runtime/cache/performance gates stay open. Make stays
production/default; no host installation/publication occurred.

### 2026-10-29 native LLVM IR support components

Added Bitcode (7 default), Bitstream (1), AsmParser (3), IRReader (1), IRPrinter (1),
Linker (2), and CodeGenTypes (1): 16 default sources in seven native components.
BitcodeAnalyzer.cpp is selected by clang_extras. Sources/private headers and native
generated/public dependencies are explicit; no LLVM source or sandbox changes.

Maintained frontend bazel-llvm-ir-support-20261029 (16 jobs) succeeds. All 16 PIC
object global/undefined symbol inventories match fresh isolated Make objects;
all seven archive inventories match. Separate bazel-llvm-bitcode-extras-20261029
succeeds; all eight Bitcode objects/archive members match a separately compiled
Make MK_CLANG_EXTRAS=yes reference. Evidence/scripts:
/usr/obj/usr/src/bazel-llvm-ir-support-qualification-20261029 and
/usr/obj/usr/src/bazel-llvm-bitcode-extras-qualification-20261029.
Verifiers stream execution records and retain complete source/object checks.
References use existing bootstrap generators/staged SDK headers. These checks do
not qualify bitcode round trips, IR parsing/linking, instruction identity, complete
compiler linkage, runtime or performance.

Frontend review: existing clang_extras setting and format-5 backend/artifacts suffice;
manual updated for Bitcode consumer, no build-bsd.c parser change. This adds 16 core
sources to the recent LLVM component coverage (918 across these and IR/Analysis/
Transforms/CodeGen/MC), separately from libclang's 839-source aggregate. Remaining
LLVM libraries/target backends, compiler linkage and world/kernel/pkgbase/bootstrap/
runtime/cache/performance qualification remain open. Make stays production/default;
no host installation/publication occurred.

### 2026-10-29 native LLVM Object and BinaryFormat

Added installed Object (32 default) and BinaryFormat (13 default) components.
Object includes its two installed-world MIW sources and selects Object.cpp with
clang_extras. BinaryFormat selects ELF.cpp with clang_extras OR lldb. Public/private
and native generated dependencies are declared. Bootstrap selection is not qualified.
No LLVM source or sandbox changes were required.

Maintained frontend bazel-llvm-object-formats-20261029 (16 jobs) succeeds. All 45 PIC
object global/undefined symbol inventories match fresh isolated Make references;
both archive member inventories match. Resolved source selections match expanded
Make for default (45), extras=false/lldb=false (44), and extras=true/lldb=false (46).
Alternate runs request inventory only; they do not qualify alternate compiled objects.
Evidence/scripts: /usr/obj/usr/src/bazel-llvm-object-formats-qualification-20261029.
References use existing bootstrap generators/staged SDK headers; verification streams
execution records. Results do not qualify object-file parsing, malformed-input
handling, relocation correctness, archive writing, instruction identity or runtime.

Frontend review: added a group of existing typed selectors and updated maintained
manual; existing build-bsd.c format-5 backend/artifacts suffice. Remaining LLVM
libraries/target backends, compiler linkage and world/kernel/pkgbase/bootstrap/
runtime/cache/performance gates remain open. Make stays production/default.
No host installation/publication occurred.

### 2026-10-29 native LLVM profiling, remarks and codegen data

Added ProfileData (23 installed-world sources), Remarks (9), and CGData (7): 39
sources. ProfileData includes the installed-world MIW source and unconditional COV
source, matching the maintained retirement of the separate LLVM_COV choice. Public
.inc definitions and generated dependencies are declared through native providers;
private Remark parser headers are declared. No LLVM source/sandbox changes.

Maintained frontend bazel-llvm-profile-20261029 (16 jobs) succeeds. All 39 PIC object
global/undefined symbol inventories match fresh isolated Make objects; all three
archive member inventories match. Resolved native source_inventory artifacts match
expanded Make ${SRCS} exactly. Evidence/scripts:
/usr/obj/usr/src/bazel-llvm-profile-qualification-20261029.
References use existing bootstrap generators/staged SDK headers; verification streams
execution records. This does not qualify profile/coverage file round trips, PGO,
memory profiling, remark serialization, codegen-data semantics, instruction identity,
complete linkage, runtime or performance. Bootstrap variants remain unqualified.

Frontend review: existing typed settings, generated dependencies and format-5
backend/artifacts suffice; no build-bsd.c/manual interface change needed. Remaining
LLVM libraries/target backends, compiler linkage and world/kernel/pkgbase/bootstrap/
runtime/cache/performance gates remain open. Make stays production/default.
No host installation/publication occurred.

### 2026-10-29 native LLVM DebugInfo default and extras

Added 93 default installed-world DebugInfo sources (77 MIN plus 16 MIW), with 95
additional sources selected by clang_extras. Public/generated dependencies are
native. First package load exposed an invalid copied private-header glob: this
directory has no private .h files. Removed the declaration, retaining the failed
bazel-llvm-debug-20261029 run; no empty-glob exception or sandbox/source patch.

Corrected frontend bazel-llvm-debug-20261029-r2 (16 jobs) succeeds. All 93 PIC objects'
global/undefined symbol inventories and archive member multiplicities match fresh
isolated Make objects. Separate bazel-llvm-debug-extras-20261029 succeeds; all 188
objects and archive members match a separate fresh Make MK_CLANG_EXTRAS=yes build.
Both resolved inventories match expanded Make ${SRCS}. Evidence/scripts:
/usr/obj/usr/src/bazel-llvm-debug[-extras]-qualification-20261029.

Extras verifier initially counted 189 historical output paths for 188 current
artifacts: adding another EnumTables.cpp moved the previous unnumbered CodeView
object into Bazel's collision layout. Corrected provenance selection to require a
recorded source for every current manifest artifact, with complete source equality
and count assertions. The unused historical EnumTables.pic.o path is retained in
source-map-history.json. No object or symbol comparison was excluded; all 188 pass.
References use existing bootstrap generators/staged SDK headers; execution-log
parsing streams records. Results do not establish DWARF/PDB/CodeView parser behavior,
symbolization, malformed-input handling, instruction identity, debugger runtime or
performance. Bootstrap variants remain unqualified.

Frontend review: existing clang_extras/format-5 backend covers this component;
manual updated for the setting consumer, no build-bsd.c parser change. Remaining
LLVM libraries/target backends, full compiler linkage and world/kernel/pkgbase/
bootstrap/runtime/cache/performance gates stay open. Make stays production/default.
No host installation/publication occurred.

### 2026-10-29 native LLVM SandboxIR and TextAPI

Added SandboxIR (15 core sources) and installed TextAPI (13 MIN plus three MIW
sources): 31 default sources. Native generated/public dependencies and TextAPI
private headers are declared; SandboxIR has no private header inputs. SandboxIR
here is LLVM's IR abstraction, not the Bazel execution sandbox. No LLVM source or
sandbox-policy changes were required.

Maintained frontend bazel-llvm-sandbox-textapi-20261029 (16 jobs) succeeds. All 31 PIC
object global/undefined symbol inventories match fresh isolated Make references;
both archive member inventories match. Resolved source inventories match expanded
Make ${SRCS} exactly. Evidence/scripts:
/usr/obj/usr/src/bazel-llvm-sandbox-textapi-qualification-20261029.
References use existing bootstrap generators/staged SDK headers; verification streams
execution records. This does not qualify IR mutation/tracking semantics, text-stub
parsing/writing, symbol behavior, instruction identity, linkage, runtime or performance.
Bootstrap library selection remains unqualified.

Frontend review: existing typed inputs, generated providers and format-5 backend/
artifacts suffice; no build-bsd.c/manual interface change needed. Remaining LLVM
libraries/target backends, full compiler linkage and world/kernel/pkgbase/bootstrap/
runtime/cache/performance gates remain open. Make stays production/default.
No host installation/publication occurred.

### 2026-10-29 native LLVM frontend, options and tool drivers

Added installed Frontend (13 sources), Option (4), WindowsDriver (1), and llvm-lib/
llvm-dlltool driver components (one each): 20 sources. Tool drivers use distinct
Bazel packages and separate native TableGen Options.inc outputs, preventing include
name collisions. Each generation action declares its Options.td, shared OptParser.td
and execution-configured native llvm-tblgen tool. OptParser.td visibility now permits
only the additional driver packages. No LLVM sources or sandbox policy changed.

Maintained frontend bazel-llvm-frontend-drivers-20261029 (16 jobs) succeeds. All 20 PIC
object global/undefined symbol inventories match fresh isolated Make objects; all
five archive member inventories match. Both generated Options.inc files match fresh
Make generation bytewise (16,653 bytes combined). Reference generation uses the
existing Make bootstrap tool; compilation uses staged SDK headers. Evidence/scripts:
/usr/obj/usr/src/bazel-llvm-frontend-drivers-qualification-20261029.
Verification streams compile-action records. This does not qualify option parsing,
driver execution, import/static-library output, OpenMP/offload behavior, instruction
identity, full linkage, bootstrap variants or performance.

Frontend review: maintained native TableGen/component backends and format-5 artifacts
cover this addition; no build-bsd.c/manual interface change required. Remaining LLVM
libraries/target backends, compiler linkage and world/kernel/pkgbase/bootstrap/
runtime/cache/performance gates stay open. Make stays production/default.
No host installation/publication occurred.

### 2026-10-29 native LLVM TargetParser

Added all 13 maintained TargetParser sources with generated architecture definitions
and explicit Unix/Host.inc input for the supported FreeBSD target. Host.cpp consumes
the existing compiler-default CcInfo provider; no literal host triple or SDK sysroot
is introduced. Updated the manual to include this provider consumer. No LLVM source
or sandbox-policy changes.

Maintained frontend bazel-llvm-targetparser-20261029 (16 jobs) succeeds. Initial
isolated Make helper requested generated headers and PIC objects in one parallel
invocation; objects raced generation and failed on missing target-parser definitions.
Retained the failed reference directory and make-r1.py. Corrected the helper to
complete generated-header targets before a separate parallel object invocation,
using fresh bazel-llvm-targetparser-reference[-objects]-20261029-r2 directories.
Future direct-object reference helpers should retain this ordering.

All 13 PIC object global/undefined symbol inventories and archive member
multiplicities match the corrected fresh Make references. Resolved native source
inventory matches expanded Make ${SRCS}. Evidence/scripts:
/usr/obj/usr/src/bazel-llvm-targetparser-qualification-20261029.
Reference generation uses existing bootstrap tools; compilation uses staged SDK
headers. These checks do not qualify runtime CPU/feature detection, cross triples,
OS-version adaptation, instruction identity, full compiler linkage or performance.

Frontend review: existing typed compiler-default settings/format-5 artifacts suffice;
manual updated, no build-bsd.c parser change required. Remaining LLVM libraries/
target backends, linkage and world/kernel/pkgbase/bootstrap/runtime/cache/performance
gates remain open. Make stays production/default; no host installation/publication.

### 2026-10-29 native LLVM LTO and pass pipeline components

Added installed LTO (three core plus three clang_extras-or-lld sources) and Passes
(five sources): 11 default. Reused the existing selector and declared private
PassRegistry.def plus native public/generated dependencies. No LLVM source/sandbox
changes. Bootstrap TOOLS_PREFIX/LLD_BOOTSTRAP selection remains unqualified.

Maintained frontend bazel-llvm-lto-passes-20261029 (16 jobs) succeeds. All 11 PIC
object global/undefined symbol inventories match fresh isolated Make objects;
both archive member inventories match. The reference helper completes generated
headers before object compilation. Resolved native inventories match expanded Make
for default (11) and lld=false/clang_extras=false (8). Reduced run is inventory-only,
not alternate compiled/runtime qualification. Evidence/scripts:
/usr/obj/usr/src/bazel-llvm-lto-passes-qualification-20261029.
Reference uses existing bootstrap generators/staged SDK headers; verification streams
execution records. Results do not establish LTO/ThinLTO execution, pipeline semantics,
plugin loading, optimization correctness, instruction identity, linkage or performance.

Frontend review: existing typed lld/extras selection and format-5 backend suffice;
manual updated for LTO consumer, no build-bsd.c parser change. Remaining LLVM
libraries/target backends, full compiler linkage and world/kernel/pkgbase/bootstrap/
runtime/cache/performance qualification stay open. Make remains production/default.
No host installation/publication occurred.

### LLVM ObjectYAML component (2026-10-29)

Added native ObjectYAML cc_library, PIC archive/object exports and resolved source
inventory for the 11 default installed libllvm sources. Maintained frontend run
`/usr/obj/usr/src/bazel-llvm-objectyaml-20261029` succeeds with 16 jobs. All 11
PIC global/undefined symbol inventories match fresh isolated Make objects; archive
member multiplicities and resolved native source inventory match Make. Evidence:
`/usr/obj/usr/src/bazel-llvm-objectyaml-qualification-20261029`. Reference headers
use existing bootstrap generators and the staged SDK. No source/sandbox workaround.

This establishes component compilation, not instruction identity, YAML conversion
runtime behavior, complete compiler linkage, bootstrap independence or performance.
Frontend review: build-bsd.c and format-5 backend already accept these native targets;
no input, staging, signing, packaging or manual contract changes are needed.
Full LLVM Support/backends, compiler linkage and system qualification remain open.
Make remains production/default; no installation or publication occurred.

### LLVM DWARFLinker component (2026-10-29)

Added native DWARFLinker cc_library with declared private headers, PIC archive/object
exports and resolved source inventory. Its 17 sources require clang_extras, matching
Make selection; the component is incompatible when that option is disabled.
Maintained frontend run `/usr/obj/usr/src/bazel-llvm-dwarflinker-20261029` succeeds
with 16 jobs and clang_extras enabled. All 17 PIC global/undefined symbol inventories
match fresh isolated Make objects; archive member multiplicities and resolved native
source inventory match Make. Evidence/scripts:
`/usr/obj/usr/src/bazel-llvm-dwarflinker-qualification-20261029`. Reference headers
use existing bootstrap generators and the staged SDK. No source/sandbox workaround.

These checks establish component compilation, not instruction identity, debug-info
linking runtime behavior, complete compiler linkage, independent bootstrap or
performance. Frontend review: existing build-bsd.c format-5 input/backend supports
this target and clang_extras setting; manual documents its new consumer.
Remaining LLVM components, complete compiler and world/kernel/package qualification
remain open. Make remains production/default. No host installation/publication.

### LLVM ObjCopy component (2026-10-29)

Added native ObjCopy cc_library with 22 explicit default installed-libllvm sources,
declared private headers/include root, PIC archive/object exports and resolved source
inventory. ELF, COFF, Mach-O, XCOFF, wasm and archive implementation sources are
covered. Maintained frontend run `/usr/obj/usr/src/bazel-llvm-objcopy-20261029`
succeeds with 16 jobs. All 22 PIC global/undefined symbol inventories match fresh
isolated Make objects; archive member multiplicities and resolved native source
inventory match expanded Make. Evidence/scripts:
`/usr/obj/usr/src/bazel-llvm-objcopy-qualification-20261029`. The Make reference
generates headers before parallel object compilation using existing bootstrap
generators and the staged SDK. No source or sandbox workaround was introduced.

This does not establish instruction identity, llvm-objcopy executable linkage,
file transformation/debug stripping correctness, independent bootstrap or performance.
Those linked-tool/runtime tests remain necessary before system qualification.
Frontend review: build-bsd.c and format-5 source_graph.py already support these
native targets; no input, staging, signing, packaging or manual contract changed.
Remaining LLVM components, compiler linkage and full world/kernel/package gates
remain open. Make remains production/default; no installation/publication occurred.

### Installed LLVM Support component (2026-10-29)

Added a separate native installed Support target in the existing llvm/lib package.
This preserves llvmminimal bootstrap source labels/header globs. AMD64 contract
includes C/C++ sources and four BLAKE3 assembly implementations, BLAKE3_USE_NEON=0,
declared private platform headers, and explicit zlib/zstd/SipHash header providers.
C++-only flags use cxxopts. LLD selects BalancedPartitioning/TarWriter, clang_full
selects Z3Solver, and clang_extras selects SystemUtils. Non-AMD64 builds are explicitly
incompatible; no cross-architecture implementation is claimed.

Maintained frontend `/usr/obj/usr/src/bazel-llvm-support-20261029` succeeds with
16 jobs. All 155 default PIC object global/undefined symbol inventories match fresh
isolated Make objects, including assembly and C objects. Resolved source inventories
and archive member multiplicities match expanded Make. Evidence/scripts:
`/usr/obj/usr/src/bazel-llvm-support-qualification-20261029`. An initial inventory
helper used the generic source_inventory suffix rather than support_source_inventory;
corrected helper now reads the actual target and passes. Native compilation did not
require source or sandbox changes. References use the staged SDK/existing generators.

This qualifies compilation only: no complete LLVM link, compression/hash runtime
checks, bootstrap independence, alternate-option compilation or performance claim.
Frontend review: build-bsd.c/format-5 backend already accept these targets/settings;
manual updated for additional setting consumers. Remaining components/backends and
complete compiler/world/kernel/pkgbase/runtime/performance gates stay open.
Make remains production/default. No installation/publication occurred.

### LLVM ExecutionEngine, ORC and JITLink (2026-10-29)

Added native ExecutionEngine component with two installed-world bridge/EH-frame
sources, 19 extras-or-lldb sources, and 87 extras sources. Default selects 21;
clang_extras selects 108. Private headers are declared. JITLink COFFOptions.inc
is produced by the native llvm-tblgen rule with declared .td/include inputs;
OptParser.td visibility was extended only to this new consumer package.

Maintained frontend `/usr/obj/usr/src/bazel-llvm-executionengine-20261029` succeeds
with 16 jobs and clang_extras. All 108 PIC global/undefined symbol inventories
match fresh isolated Make objects; archive member multiplicities and expanded
Make/resolved Bazel source inventories match. Native COFF option table bytes match
Make. Separate default source-inventory run selects exactly the expected 21
(inventory-only; not a separate default compiled/runtime qualification). Evidence:
`/usr/obj/usr/src/bazel-llvm-executionengine-qualification-20261029`. Fresh Make
reference generates headers before objects and uses existing bootstrap generators
and staged SDK. No source/sandbox changes or runtime fallback.

Execution, relocations, memory permissions, remote ORC behavior, unwinding and debugger
registration remain unqualified at runtime. Object symbol comparison is not
instruction equivalence, full compiler linkage, bootstrap independence or performance.
Frontend review: existing format-5 target/settings transport suffices; manual
documents extras/lldb consumers. No build-bsd.c input/staging/publication change.
Remaining LLVM/backends and compiler/world/kernel/pkgbase/runtime/performance
gates remain open. Make remains production/default; no installation/publication.

### LLVM shared target and tool-support components (2026-10-29)

Added six native component targets: shared Target (5), XRay (10), DWARFCFIChecker
(4), DWP (2), Debuginfod (4), MCA (23). Target and Debuginfod are installed-world
components; the other four require clang_extras. Target includes only shared
Target/*.cpp sources; architecture-specific backends/MCA extensions remain separate
and unqualified. Private unwind-checker headers are declared.

Maintained frontend `/usr/obj/usr/src/bazel-llvm-toolsupport-20261029` succeeds
with 16 jobs and clang_extras. All 48 PIC global/undefined symbol inventories match
fresh isolated Make objects, six archive member inventories match, and resolved
native sources match expanded Make. Evidence/scripts:
`/usr/obj/usr/src/bazel-llvm-toolsupport-qualification-20261029`. Reference headers
use existing bootstrap generators and staged SDK; no source/sandbox modifications.

The maintained llvm-config.h disables LLVM_ENABLE_CURL and LLVM_ENABLE_HTTPLIB:
Debuginfod compilation is not evidence of working HTTP downloads/server. Runtime
trace parsing, unwind verification, debug-package writing and machine-code analysis
remain unqualified. Symbol comparison does not prove instruction identity, full
compiler linkage, independent bootstrap or performance.
Frontend review: build-bsd.c and format-5 source_graph.py already accept these
targets/settings; manual records optional consumers. No staging/publication change.
Architecture backends, full linkage and world/kernel/pkgbase/runtime/performance
gates remain open. Make remains production/default; no installation/publication.

### Native X86 backend TableGen outputs (2026-10-29)

Added 15 native X86 generator actions using declared llvm-tblgen: assembly matching/
writers, calling conventions, DAG/fast/global instruction selection, disassembly,
fold/instruction/mnemonic tables, register banks/registers and subtargets. Preserved
special writer-number flags and X86 operand-expansion flag. Explicit inventories
declare 61 target and 38 shared .td files (primary input plus 98 includes).
A dependency audit initially expected the Make depfile to contain the primary input;
it contains only the 98 includes. Inspection found the sole difference was X86.td,
which both build rules explicitly name as the primary input. No missing include.

Maintained frontend `/usr/obj/usr/src/bazel-llvm-x86-tables-20261029` succeeds with
16 jobs. All 15 outputs match freshly generated Make tables byte-for-byte:
76,393,918 bytes. Evidence/scripts:
`/usr/obj/usr/src/bazel-llvm-x86-tables-qualification-20261029`. Make uses its
existing llvm-tblgen; Bazel uses the native target and staged SDK/runtime dependencies.
No runtime Make metadata parsing or pre-generated table substitution.

Backend compilation, target configuration, linkage, runtime code generation, cache
invalidation, independent bootstrap and comparative performance remain open.
Frontend review: build-bsd.c/format-5 backend accepts these targets; no input/staging/
security/manual contract change. Full world/kernel/pkgbase gates remain open.
Make remains production/default. No installation/publication occurred.

### X86 backend compilation in progress (2026-10-29)

Native target now declares 86 installed-world sources plus one clang_extras MCA
source, private headers/defs and qualified generated tables. Added native-AMD64
llvm_target_x86 bool (default true), incompatible component when disabled; full
compiler target registration/cross defaults remain open. Manual updated. Existing
build-bsd.c/format-5 backend transports this setting without a parser change.

Initial native `/usr/obj/usr/src/bazel-llvm-x86-backend-20261029` compilation
finished, but review of Make commands exposed missing -fvisibility=hidden used
for all Target/*/* sources. It is NOT qualified. Corrected target is rebuilding
in `bazel-llvm-x86-backend-20261029-r2`. Fresh Make reference is running separately.
Qualification scripts in `bazel-llvm-x86-backend-qualification-20261029` now compare
ELF symbol type/binding/visibility/defined state/name rather than just nm names.
No result claimed until both builds finish and checks pass. Pending work is uncommitted.
Concurrent builds do not provide comparative performance evidence. Goal remains active;
Make remains production/default. No installation/publication occurred.

### X86 backend corrected build qualified (2026-10-29)

Continuation of the preceding pending entry: corrected frontend run
`/usr/obj/usr/src/bazel-llvm-x86-backend-20261029-r2` completed. All 87
extras-enabled PIC objects match fresh Make ELF symbol type, binding, visibility,
defined/undefined state and name. Archive member multiplicities and resolved
source inventories match. Stronger ELF verifier rejects all 87 objects from the
initial run lacking -fvisibility=hidden, demonstrating the check detects this
actual regression. Initial run is retained and remains unqualified.

Evidence/scripts: `/usr/obj/usr/src/bazel-llvm-x86-backend-qualification-20261029`.
The installed-world target includes 85 core sources, the disassembler and optional
MCA extension, generated-table dependencies and private .h/.def files. Native AMD64
llvm_target_x86 defaults true; final aggregate compiler target registration and
cross-platform/default target-all semantics remain unfinished. Bootstrap TOOLS_PREFIX
selection is separate and unqualified. No compiler source/sandbox workaround.

ELF parity is not instruction identity or runtime code-generation qualification.
Other backends, whole-compiler linkage/bootstrap, world/kernel/pkgbase/runtime and
comparative CPU/memory/disk gates remain open. Concurrent reference/native builds
are not performance comparisons. Frontend review: existing build-bsd.c/format-5
backend accepts the new boolean; manual updated. Make remains production/default;
no installation/publication occurred.

The separate `bazel-llvm-x86-default-20261029` inventory-only run resolves 86
sources matching expanded Make with clang_extras disabled. It is not a separate
default compiled/runtime qualification.

### Native ARM backend tables (2026-10-29)

14 native TableGen outputs now match fresh Make bytes (20,767,577 bytes), including
ARM assembly/disassembly, instruction selection, register, emitter and system-register
tables. Existing declared inventories cover 29 ARM and 39 shared .td files; source
include closure matches Make depfiles plus primary ARM.td (68 total inputs).
Evidence: `/usr/obj/usr/src/bazel-llvm-arm-tables-qualification-20261029`; maintained
frontend run `bazel-llvm-arm-tables-20261029`, 16 jobs. Make reference uses existing
bootstrap generator; native generator still depends on staged SDK/runtime.

This does not establish ARM backend compilation/runtime, cross-building a system,
independent bootstrap or comparative performance. Backend compilation is in progress
separately. Existing build-bsd.c/format-5 backend accepts generator targets without
parser/staging changes; Make remains production/default.

### ARM backend component compilation qualified (2026-10-29)

Continuation of the preceding table entry: native ARM backend now compiles all
66 installed-world sources with hidden visibility, declared private headers and
qualified generated tables. Maintained frontend `bazel-llvm-arm-backend-20261029`
completed with 16 jobs. All 66 PIC objects match fresh Make ELF global/weak symbol
type, binding, visibility, defined/undefined state and name. Source inventory and
archive member multiplicities match expanded Make. Evidence/scripts:
`/usr/obj/usr/src/bazel-llvm-arm-backend-qualification-20261029`. No compiler source
or sandbox modifications. Reference uses staged SDK and existing bootstrap generators.

Added llvm_target_arm boolean (default true for current native AMD64 world target-all
selection); disabling makes explicit component incompatible. Full aggregate target-all
semantics/registration and cross-platform defaults remain unfinished. This builds
an AMD64-hosted compiler component, not an ARM system. Hidden visibility is applied
from the start following the X86 correction.

No instruction identity, ARM code execution, full compiler linkage, independent
bootstrap or performance claim. Other backends and world/kernel/pkgbase/runtime/
CPU/memory/disk gates remain open. Frontend review: existing build-bsd.c and format-5
backend transport the setting; manual updated, no staging/publication change.
Make remains production/default; no host installation/publication occurred.

### Native PowerPC backend TableGen outputs (2026-10-29)

Added 12 declared native TableGen actions for PowerPC backend assembly/disassembly,
calling conventions, DAG/fast/global instruction selection, instruction/emitter tables,
register banks/registers and subtargets. Existing inventories cover 36 target-specific
and 38 shared .td inputs. Make depfiles plus primary PPC.td match the transitive
source include closure (74 total inputs).

Maintained frontend `/usr/obj/usr/src/bazel-llvm-powerpc-tables-20261029` succeeds
with 16 jobs. All 12 tables match fresh Make outputs byte-for-byte: 16,694,167 bytes.
Evidence/scripts: `/usr/obj/usr/src/bazel-llvm-powerpc-tables-qualification-20261029`.
Make uses its existing bootstrap llvm-tblgen; native generator uses the declared
Bazel target and staged SDK/runtime. No pre-generated table substitution or runtime
Make source-metadata parsing.

Backend C++ compilation, hidden-visibility ELF parity, target registration, linkage,
PowerPC code execution, independent bootstrap and comparative performance remain
open. Frontend review: build-bsd.c/format-5 source_graph.py already accepts these
targets; no new input, staging, security or manual contract. Other backends and full
world/kernel/pkgbase/runtime qualification remain open. Make stays production/default;
no host installation/publication occurred.

### PowerPC backend component (2026-10-29)

Added native installed-world PowerPC cc_library for 54 explicit sources with declared
private headers/.def files, qualified native generated-table dependencies and hidden
symbol visibility. llvm_target_powerpc boolean defaults true for current native
AMD64 world target-all selection; disabling makes explicit component incompatible.
Aggregate target-all/registration and cross-platform defaults remain unfinished.

Maintained frontend `/usr/obj/usr/src/bazel-llvm-powerpc-backend-20261029` succeeds
with 16 jobs. All 54 PIC objects match fresh Make global/weak ELF symbol type, binding,
visibility, defined/undefined state and name. Source inventories and archive member
multiplicities match expanded Make. Evidence/scripts:
`/usr/obj/usr/src/bazel-llvm-powerpc-backend-qualification-20261029`. Reference
headers are generated before objects using existing bootstrap tools and staged SDK.
No compiler source/sandbox changes.

This builds an AMD64-hosted compiler component; it does not demonstrate PowerPC
system builds, generated-code execution, full compiler linkage, independent bootstrap
or comparative CPU/memory/disk performance. Other backends and world/kernel/pkgbase/
runtime gates remain open. Frontend review: existing build-bsd.c/format-5 backend
transports the new setting; manual updated. Make remains production/default.
No host installation/publication occurred.

### Native AArch64 backend TableGen outputs (2026-10-29)

Added 20 native TableGen actions for AArch64 assembly/disassembly, calling
conventions, instruction selection, emitter/pseudo-lowering tables, register banks,
registers, SDNodes, subtargets and system operands. Four GlobalISel combiner/lowering
actions preserve Make's exact named combiners. Existing inventories declare 49
target-specific and 40 shared .td inputs. Make depfiles plus primary AArch64.td
match the transitive source include closure (89 total inputs).

Maintained frontend `/usr/obj/usr/src/bazel-llvm-aarch64-tables-20261029` succeeds
with 16 jobs. All 20 outputs match fresh Make tables byte-for-byte: 74,348,214 bytes.
Evidence/scripts: `/usr/obj/usr/src/bazel-llvm-aarch64-tables-qualification-20261029`.
Make uses its existing bootstrap llvm-tblgen; native generation uses the declared
Bazel execution target and staged SDK/runtime. No pre-generated table substitution.

Backend C++ compilation, ELF parity, target registration, complete compiler linkage,
generated-code execution, independent bootstrap and comparative performance remain
open. Frontend review: build-bsd.c/format-5 backend accepts these targets with no new
input, staging, security or manual contract. Other backends and full world/kernel/
pkgbase/runtime gates remain open. Make remains production/default; no installation
or publication occurred.

### AArch64 backend component (2026-10-29)

Added native installed-world AArch64 cc_library for 77 explicit sources: 75 core
plus disassembler/external symbolizer. Private headers/.def and native generated
tables are declared; hidden visibility follows Make. llvm_target_aarch64 boolean
defaults true for current native AMD64 world target-all selection; disabling makes
explicit component incompatible. Aggregate target-all/registration and cross-platform
defaults remain unfinished; bootstrap TOOLS_PREFIX selection remains separate.

Maintained frontend `/usr/obj/usr/src/bazel-llvm-aarch64-backend-20261029` succeeds
with 16 jobs. All 77 PIC objects match fresh Make global/weak ELF symbol type, binding,
visibility, defined/undefined state and name. Resolved source inventories and archive
member multiplicities match expanded Make. Evidence/scripts:
`/usr/obj/usr/src/bazel-llvm-aarch64-backend-qualification-20261029`. Reference
headers generated before objects using existing bootstrap tools/staged SDK. No
compiler source or sandbox modification.

These are AMD64-hosted compiler objects, not a qualified AArch64 system build or
generated-code execution test. Full compiler linkage, independent bootstrap and
comparative CPU/memory/disk qualification remain open, as do remaining backends and
world/kernel/pkgbase/runtime gates. Frontend review: build-bsd.c/format-5 backend
accepts the new setting; manual updated. Make remains production/default.
No host installation/publication occurred.

Next dependency finding: RISCV GlobalISel generators use RISCVGISel.td, which includes
RISCV.td and RISCVCombine.td. Existing target-parser input inventory does not expose
that entry point; backend generation must declare its additional closure explicitly.

### Native RISC-V backend TableGen outputs (2026-10-29)

Added 20 distinct native backend table actions. The duplicate DAGISel entry in Make's
TGHDRS yields one output. Regular actions use RISCV.td (116 transitive inputs);
GlobalISel and its three combiner actions use RISCVGISel.td (119). Declared supplemental
inputs are RISCVGISel.td, RISCVCombine.td and llvm/Target/GlobalISel/Combine.td, only
attached to those four actions. Existing target-parser input closure is preserved.
All flags, named combiners and entry-point selection follow maintained Make rules.

Maintained frontend `/usr/obj/usr/src/bazel-llvm-riscv-tables-20261029` succeeds
with 16 jobs. All 20 generated tables match fresh Make bytes: 211,739,403 total.
Each Make depfile plus primary input matches its appropriate source closure, rather
than checking only the union. Evidence/scripts:
`/usr/obj/usr/src/bazel-llvm-riscv-tables-qualification-20261029`. Make uses existing
bootstrap llvm-tblgen; native generation uses the declared Bazel target and staged
SDK/runtime. No pre-generated table substitution or runtime Make metadata parsing.

Backend C++ compilation, ELF parity, target registration, full compiler linkage,
generated-code execution, independent bootstrap and comparative CPU/memory/disk
qualification remain open. Frontend review: build-bsd.c/format-5 backend accepts
these targets; no new input/staging/security/manual contract. Other backends and
world/kernel/pkgbase/runtime gates remain open. Make remains production/default;
no host installation/publication occurred.

### RISC-V backend component (2026-10-29)

Added native installed-world RISC-V cc_library: 62 core sources plus MCA custom
behavior selected by clang_extras. Private headers and generated tables declared;
hidden visibility follows Make. llvm_target_riscv defaults true for current native
AMD64 world target-all selection; disabling makes explicit component incompatible.
Aggregate target-all/registration and cross-platform defaults remain unfinished.

Maintained frontend `/usr/obj/usr/src/bazel-llvm-riscv-backend-20261029` succeeds
with 16 jobs and clang_extras. All 63 PIC objects match fresh Make global/weak ELF
symbol type, binding, visibility, defined/undefined state and name. Archive member
multiplicities and resolved source inventory match. Separate default inventory run
`bazel-llvm-riscv-default-20261029` matches Make's 62 sources; that run is inventory-only.
Evidence/scripts: `/usr/obj/usr/src/bazel-llvm-riscv-backend-qualification-20261029`.
Reference uses staged SDK and existing bootstrap generators; no compiler source/
sandbox modification.

These are AMD64-hosted backend objects, not a qualified RISC-V system or generated-code
execution test. BPF/LoongArch backends, complete compiler linkage, independent bootstrap
and world/kernel/pkgbase/runtime/CPU/memory/disk qualification remain open. Concurrent
builds do not provide comparative performance evidence. Frontend review: build-bsd.c/
format-5 backend transports new setting; manual updated. Make remains production/
default; no host installation/publication occurred.

### Optional BPF and LoongArch generators/backends (2026-10-29)

Added native generator inputs/actions and backend components for BPF (11 tables,
33 sources) and LoongArch (9 tables, 28 sources). Explicit .td inventories contain
44 and 53 transitive inputs respectively. Every generated output's Make depfile
plus primary input matches its source include closure. All 20 tables match Make
byte-for-byte: 6,357,782 bytes. Maintained frontend run:
`/usr/obj/usr/src/bazel-llvm-optional-tables-20261029`; evidence/scripts in matching
`bazel-llvm-optional-tables-qualification-20261029` directory.

Backend targets declare generated/private headers, BPF's pass registry .def, hidden
visibility and explicit source lists. llvm_target_bpf/llvm_target_loongarch booleans
default false, matching src.opts.mk. Qualification explicitly enables both.
Maintained frontend `bazel-llvm-optional-backends-20261029` succeeds with 16 jobs.
All 61 objects match fresh Make global/weak ELF symbol type, binding, visibility,
defined/undefined state and name. Both archive member inventories and resolved
sources match expanded Make. Evidence/scripts:
`/usr/obj/usr/src/bazel-llvm-optional-backends-qualification-20261029`. No compiler
source or sandbox workaround. Reference uses existing bootstrap tools/staged SDK.

All seven backend families in the maintained LLVM Makefile now have component
compilation evidence, but aggregate source reconciliation/target selection, full
compiler linkage and runtime code generation remain unqualified. Component results
do not establish BPF program loading/execution or a LoongArch system build.
Independent bootstrap and world/kernel/pkgbase/runtime/CPU/memory/disk gates remain
open. Frontend review: build-bsd.c/format-5 backend accepts new booleans; manual
updated. Make remains production/default; no installation/publication occurred.

### Installed LLVM aggregate source reconciliation (2026-10-29)

Added explicit installed-library component selection, source_inventory and pic_archive
targets in lib/clang/libllvm. The aggregate selects common groups, extras-only groups,
extras-or-lldb Telemetry, and individually enabled backends. Uses resolved Bazel srcs
from declared components; no build-time Make metadata parsing. Archive target is
declared but not built/qualified in this batch; shared linkage/install remain open.

Initial reconciliation found Telemetry/Telemetry.cpp missing in default (1739 versus
1740) and also optional Analysis/Analysis.cpp missing with extras (2052 versus 2054).
Added Telemetry guarded by extras-or-lldb, and Analysis entry source guarded by extras.
Both new sources compile and match fresh Make ELF symbol type/binding/visibility/
defined state/name. Telemetry archive inventory matches. Earlier Analysis component
comparisons cover its other 119 sources; this batch's fresh reference covers only
the added entry point. No source/sandbox workaround.

Corrected source multisets match expanded Make exactly:
- Default: 1740, no missing/extra sources.
- Extras plus all seven backends: 2054, no missing/extra sources.
These are whole-libllvm SOURCE inventories, not a whole-compiler linkage/runtime
claim or world completion count. Results/scripts:
`/usr/obj/usr/src/bazel-llvm-aggregate-qualification-20261029`,
`bazel-llvm-telemetry-qualification-20261029`, and
`bazel-llvm-analysis-entry-qualification-20261029`. Maintained frontend corrected
runs: `bazel-llvm-aggregate-default-fixed-20261029` and
`bazel-llvm-aggregate-all-fixed-20261029`. Initial all-options attempt was rejected
by the frontend build lock; rerun after default finished. No running job restarted.

Aggregate archive/shared linkage, target registration and complete selection policy
(including target-all/cross defaults/zero-backend rejection), independent bootstrap,
world/kernel/pkgbase/runtime/cache/performance gates remain open. Frontend review:
existing build-bsd.c/format-5 backend supports targets; manual documents Telemetry
selection. Make remains production/default. No installation/publication occurred.

### Full default LLVM archive and shared-library candidate (2026-10-29)

Maintained frontend `bazel-llvm-aggregate-archive-20261029` built the default native
PIC aggregate: 1740 sources/members, 544,919,658 archive bytes. Source multiset equals
reconciled Make inventory; member basename multiplicities match, including duplicate
stems. Evidence/scripts: `/usr/obj/usr/src/bazel-llvm-aggregate-archive-qualification-20261029`.
This is artifact size, not runtime memory or comparative performance evidence.

Added standard cc_import for the native aggregate and cc_shared_library target
llvm_shared producing libprivatellvm.so.21, with native C++/C++ ABI/math dynamic
dependencies. Compression/terminal libraries remain executable dependencies as in
llvm.prog.mk. Make query confirms SONAME/name and --gc-sections/-znow/-zrelro flags.
First shared candidate linked but ELF review found missing libm.so.5; added explicit
native msun dependency. Initial candidate retained; corrected frontend run:
`/usr/obj/usr/src/bazel-llvm-shared-20261029-r2`.

Corrected candidate (323,809,912 bytes) has SONAME libprivatellvm.so.21, BIND_NOW,
GNU_RELRO, non-executable stack, no RPATH/RUNPATH and no TEXTREL. Its ordered NEEDED
list is libc++.so.1, libcxxrt.so.1, libm.so.5, libgcc_s.so.1, libc.so.7. Both that list
and ALL global/weak dynamic symbol records (type/binding/visibility/defined state/name)
match the PRE-EXISTING Make libprivatellvm.so.21.full, with zero additions/removals.
Evidence: `/usr/obj/usr/src/bazel-llvm-shared-qualification-20261029/elf-inspection.json`.
This diagnostic comparison is not fresh full-library link parity, runtime validation,
independent bootstrap, install/debug/package qualification or performance evidence.
Existing component comparisons supply fresh per-component references.

Frontend review: existing build-bsd.c/format-5 backend accepts archive/shared targets;
manual documents artifact scope. Full target-registration/selection policy, complete
Clang linkage/execution and world/kernel/pkgbase/runtime/cache/CPU/memory/disk gates
remain open. Make remains production/default; no installation/publication occurred.

### Clang shared candidate linked (2026-10-29)

Added clang/clang_shared providers in lib/clang/libclang using the selected native
PIC aggregate and explicit native LLVM, C++, C++ ABI and math dependencies.
Maintained frontend run /usr/obj/usr/src/bazel-clang-shared-20261029 passes
with 16 jobs. The library is 245,541,016 bytes. Its ordered NEEDED entries
(libprivatellvm.so.21, libc++.so.1, libcxxrt.so.1, libm.so.5, libc.so.7) and all
global/weak dynamic symbol records (type, binding, visibility, defined state, name)
match the PRE-EXISTING Make libprivateclang.so.21.full with zero differences.
SONAME, BIND_NOW, GNU_RELRO, non-executable stack, absence of RPATH/RUNPATH and
absence of TEXTREL were checked. Evidence and script:
/usr/obj/usr/src/bazel-clang-shared-qualification-20261029/elf-inspection.json
and inspect.py. This is diagnostic ELF parity, not a fresh complete Make link,
compiler execution, independent bootstrap or package/runtime/performance proof.
Frontend review: build-bsd.c and format-5 source_graph.py already accept the new
explicit target; manual documents its scope. Make remains production/default.
Target registration/selection, compiler executable, world/kernel/pkgbase and
CPU/memory/disk/cache qualification remain open. No installation occurred.

### Native Clang driver and default code generation (2026-10-29)

Added an explicit five-source native compiler target //usr.bin/clang/clang:clang.
The bsd_llvm_targets provider derives backend-enable definitions from the existing
seven boolean settings and native initialization definitions from Bazel platform
CPU constraints, only when that backend is enabled. It rejects zero backends.
Aggregate target-all/cross default policy and reduced/zero selection tests remain
open. Compiler defaults use the existing typed defaults provider.

The first new run name was already occupied and frontend rejected it before build.
The r2 run exposed missing generated OpenMP headers; added explicit LLVM generated
header dependencies. Corrected maintained frontend run
/usr/obj/usr/src/bazel-clang-driver-20261029-r3 succeeds with 16 jobs.
This is a runtime qualification executable using declared native libc/libsys and
Bazel runfile paths, not an installation-ready compiler artifact.

Verified executable digest against its saved artifact before executing --version
and --print-targets. Reports 5BSD Clang 21.1.8 and the five default backend families.
Compiled C and C++ probes to objects for x86_64, AArch64, ARMv7, PowerPC64 and
RISCV64; saved readelf headers for all ten outputs. Evidence/script:
/usr/obj/usr/src/bazel-clang-driver-qualification-20261029/{runtime.json,check.py}.
These tests do not exercise system headers, linker integration, generated-program
execution, non-native kernel boot or performance. Fresh Make object/install parity,
Bazel test integration and full bootstrap/world/kernel/pkgbase remain open.
Frontend review: build-bsd.c and source_graph.py format-5 already accept this target
and existing settings; manual updated. Make remains production/default.

### Maintained compiler code-generation test and selection checks (2026-10-29)

Added //usr.bin/clang/clang:codegen_test, a native Bazel cc_test that executes the
produced compiler with declared runfiles. For each enabled backend it compiles C
and C++ probes, checks successful exit and verifies the emitted ELF e_machine
value in either byte order. Fixed triples in this test are representative fixtures,
not compiler defaults. No shell/host compiler or generator stand-in is used.
Default frontend run bazel-clang-codegen-test-20261029 passes one Bazel test
containing ten compile/object checks. X86-only run bazel-clang-codegen-x86-20261029
passes the same test with two checks. Other backends' optional test branches
(BPF/LoongArch) have not yet executed.

Additional reduced-configuration inspection verifies exactly x86 and x86-64 in
--print-targets and confirms AArch64 compilation fails without producing an object.
Compiler digest before/after and diagnostic are saved in the reduced run's
selection-check.json. Zero-backend run bazel-clang-zero-backends-20261029 fails
analysis with the intended 'requires at least one enabled backend' diagnostic;
that retained failed run is a negative-policy result, not a passing build.
All runs and inputs are under /usr/obj/usr/src. The normal build-bsd format-5
frontend accepts explicit test labels and existing backend flags without changes;
manual documents the test. CPU/memory/disk benchmarking, installed compiler,
system headers/linker and produced-program execution remain unqualified. Make
remains production/default; independent bootstrap/world/kernel/pkgbase remain open.

### Compiler headers, static linkage and produced-program execution (2026-10-29)

The X86-only native compiler now has diagnostic system-header/link/run evidence.
Using explicit --sysroot, -resource-dir and -fuse-ld inputs from the existing
Make-prepared SDK, it compiled and statically linked a C allocation/string/stdio
probe and a C++ vector/numeric/iostream probe. Both executed successfully with
expected output. The C++ run uses --driver-mode=g++ so the compiler chooses its
normal C++ libraries; the earlier exploratory run supplied explicit libraries and
is not the driver-default evidence. Corrected commands/results/sources/script:
/usr/obj/usr/src/bazel-clang-sdk-execution-20261029-r2.

Compiler SHA256: 4b7e8f672cbbe014b9594411b8f9c160e641e333856a5af1393dea3d3de8b8bc.
This is explicit-SDK static-link evidence, not independent bootstrap, dynamic
runtime, installation defaults, broad language conformance or performance proof.
Promoting link/run coverage to a maintained Bazel test with declared SDK inputs
remains next work. Existing codegen_test covers compilation only.
Frontend review: no input or packaging semantics changed; the diagnostic uses
existing compiler flags and SDK inputs, so no build-bsd/backend/manual interface
change is required. Make remains production/default; full migration remains open.

### Maintained compiler SDK link/run tests, initial implementation (2026-10-29)

Added bsd_compiler_probe and C/C++ self-checking programs exposed as
//usr.bin/clang/clang:sdk_c_test and sdk_cc_test. Compilation is an explicit Bazel
action using the candidate compiler in execution configuration, declared SDK
files and the selected linker. Resource/sysroot paths are resolved from SDK
artifacts; no host include/linker fallback. Static outputs are executed by the
existing bsd_program_test adapter. These tests deliberately qualify a prepared
SDK, not an independent bootstrap.

The initial run rejected an incorrect resource-header anchor: FreeBSD supplies
stddef.h through system headers. Corrected to the installed Clang resource
__stddef_size_t.h. Run /usr/obj/usr/src/bazel-clang-sdk-tests-20261029-r2 built the execution-tool
compiler, then failed the relative linker-path check; corrected results follow below. The first
failure remains retained. Review SDK input breadth after the run: the initial
rule uses all SDK inputs, and should narrow to compilation/link inputs where
possible. Frontend review: existing format-5 targets/tests support the new labels;
manual documents test scope. Make remains production/default.

### Compiler installation contract review (2026-10-29, pending correction)

Fresh expanded Make variables are saved at
/usr/obj/usr/src/bazel-clang-install-contract-20261029/make-variables.json.
Make requires -fPIE/-pie for the installed driver. Inspection of the saved native
candidate from bazel-clang-driver-20261029-r3 shows ELF type EXEC: the initial
runtime candidate omitted PIE. Correct compilation/link flags and verify ELF type
before claiming driver artifact or installation parity. Existing execution tests
remain execution evidence only. Apply the correction after the live SDK-test run
finishes so its inputs remain stable.

The installation contract includes /usr/bin/clang mode 0555, five binary hardlinks
(clang++, clang-cpp, cc, c++, cpp), six manual aliases (also CC), and the separate
CC.sh script installed as CC, mode 0555, package clang. A separate installed link
target must omit qualification runtime search paths; preserve normal source and
library dependencies. Debug split and complete installation comparison remain open.

Installation preparation: usr.bin/clang/clang/installation.bzl now defines the
compiler manifest/archive using maintained utility/debug/install helpers, the
five binary aliases, six manual aliases and CC script. It was initially prepared without loading it into the active build. The corrected
system-link target and archive validation described below now use this macro.

Resource-header installation contract captured separately in
/usr/obj/usr/src/bazel-clang-header-contract-20261029/make-variables.json:
256 default headers, including nine generated ARM/RISCV headers, installed under
/usr/lib/clang/21/include as root:wheel 0444. bsd.incs.mk adds package=clang
and dev installation tags under NO_ROOT; preserve both in native manifests. The conditional
INSTALL_CONFLICTING_CLANG_HEADERS group must remain an explicit option; it is not
part of that default count. Native resource-header installation is still pending.

Generator input closures for all nine resource headers are saved beside that
contract in generator-inputs.json. In particular, arm_vector_types.h consumes
arm_neon.td (and its included definitions), despite Make naming arm_sme.td in the
target prerequisite. Native actions must declare the actual consumed inputs;
generator output parity remains to be checked after implementing the actions.

### Maintained SDK tests and installed-driver candidate (2026-10-29)

The execution-configuration compiler build completed. Its first SDK probe failed
because -fuse-ld rejects a relative artifact path. Corrected to --ld-path with
-fuse-ld=lld, matching Clang's supported path/flavor interface. No shell wrapper,
absolute sandbox path or host linker fallback. Narrowed SDK dependencies to its
existing compile_inputs/link_inputs groups, excluding unrelated Python tools.

Applied Make's -fPIE/-pie contract to both driver targets. Added clang_installed
without qualification runtime paths/native-runtime overrides and wired the
installation macro. The first installed link explicitly included libelf; removed
that unnecessary direct dependency (libexecinfo owns it). The runtime target
retains declared library paths needed for build-tree execution.

Corrected run /usr/obj/usr/src/bazel-clang-install-tests-20261029-r2 passes both
sdk_c_test and sdk_cc_test: two reported cases, neither skipped. They compile,
statically link and execute C allocation/string/stdio and C++ vector/numeric/iostream
probes with the native compiler and declared staged SDK/linker inputs. This remains
a Make-prepared SDK test, not independent bootstrap or dynamic runtime qualification.

Installed candidate has ELF DYN/PIE, BIND_NOW, GNU_RELRO, non-executable stack,
no RPATH/RUNPATH and no TEXTREL. Its NEEDED set matches the pre-existing Make
clang.full; order differs and remains part of fresh link review. Installation
archive has 15 records. Owners/groups/modes/hardlinks match declared metadata;
CC script and decompressed manual match source. Evidence/scripts:
/usr/obj/usr/src/bazel-clang-install-qualification-20261029.
Fresh Make driver object/link/install/debug comparisons remain pending. The 256
resource headers are not included in this driver archive; their native generation
and installation remain separate required work. No host installation occurred.
Frontend review: existing build-bsd format-5 transports the target/test selections;
manual updated for installed target and test scope. Make stays production/default;
world/kernel/pkgbase/cache/performance gates remain open.

### Fresh compiler-driver and installation comparison (2026-10-29)

Fresh Make built the five driver sources and linked/installed them into an
isolated /usr/obj stage with 16 jobs; no host installation. Reference uses existing
staged SDK, generated headers and LLVM/Clang libraries, not a fresh whole-toolchain
bootstrap. Commands/logs: /usr/obj/usr/src/bazel-clang-driver-make-20261029;
reference objects: bazel-clang-driver-make-objects-20261029 under the same root.

Comparison with the corrected native clang_installed candidate passes:
- All global/weak ELF symbol type/binding/visibility/defined-state/name records
  match the fresh Make driver, with zero additions/removals.
- All 15 installed payload paths, owner/group/mode/package tags and hardlink
  relationships match Make's staged installation.
- Eight nonbinary payloads (CC script and seven compressed manual names) match
  byte-for-byte. Native .gnu_debuglink names clang.debug and its CRC matches the
  packaged debug payload.
The verifier subtracts unchanged distrib-dirs baseline entries (including its two
NLS symlinks), rather than counting them as compiler payloads. Evidence/scripts:
/usr/obj/usr/src/bazel-clang-driver-reference-qualification-20261029.

This does not establish machine-code identity, exact dependency ordering,
resource-header installation, independent bootstrap, dynamic installed runtime,
world/kernel/pkgbase or comparative performance. Native resource headers remain
next. Frontend review: qualification-only evidence; no new build-bsd inputs,
staging/signing/publication semantics or manual contract change. Make stays default.

### Native Clang resource headers and installation (2026-10-29)

Added native lib/clang/headers targets with explicit maintained inventories:
247 source headers plus nine generated headers, installed root:wheel 0444 under
/usr/lib/clang/21/include with package=clang and dev tags. Generation uses native
clang-tblgen actions and declared primary/include inputs. arm_vector_types.h
correctly declares arm_neon.td, the actual generator input. No runtime Make parser
or staged generated-header substitute. Source exports and input-group visibility
are limited to the consuming packages.

Default frontend run /usr/obj/usr/src/bazel-clang-resource-headers-20261029 passes.
All 256 installed header payloads match fresh Make byte-for-byte (14,747,091 bytes),
as do payload paths, owner/group/mode/package tags. The nine generated input
closures, including primary files, match fresh Make depfiles. The reference uses
an existing staged clang-tblgen; this is not independent generator bootstrap.

Added boolean install_conflicting_clang_headers, default false. Enabled run
bazel-clang-resource-conflicting-20261029 passes and matches fresh Make with
INSTALL_CONFLICTING_CLANG_HEADERS=yes: 272 headers, 14,883,615 bytes. It adds exactly
16 headers; all 256 default payloads remain unchanged. Verification/reference
scripts and reports: /usr/obj/usr/src/bazel-clang-resource-reference-qualification-20261029.
Reference stages: bazel-clang-resource-make-20261029 and
bazel-clang-resource-conflicting-make-20261029 under /usr/obj/usr/src.

Frontend review: build-bsd.c and format-5 source_graph.py already transport the
new boolean and explicit targets; manual documents them. Resource-header archive
is separate from driver/runtime libraries; complete toolchain composition and
installed execution still need qualification. Make remains production/default;
independent bootstrap, world/kernel/pkgbase/cache and performance gates remain open.

### Composed compiler installation candidate (2026-10-29)

Added shared-library installation manifests for native LLVM and Clang: versioned
private shared library, separate debug file and development symlink. Make's installed
configuration has no static LIB archive; native PIC aggregation remains a build
input, not an extra installed artifact. Expanded Make installation variables are
recorded at /usr/obj/usr/src/bazel-clang-libraries-install-contract-20261029.

//lib/clang:compiler_install_archive composes driver, resource headers and both
private libraries. Maintained run /usr/obj/usr/src/bazel-clang-composed-20261029
passes. All 277 payload records match the union of independent Make installation
references: driver and headers freshly built, libraries pre-existing Make artifacts
freshly staged. Owner/group/mode/package tags, hardlinks and symlinks match;
264 nonbinary payloads match byte-for-byte. All three debuglink names and CRCs
match packaged debug files (CRC validation streams large files in 1 MiB chunks).
Evidence/script: /usr/obj/usr/src/bazel-clang-libraries-reference-qualification-20261029.
No library machine-code identity or fresh full-library rebuild is claimed.

The archive is not a complete sysroot: system runtime libraries, CRT objects,
linker and compiler runtime packages remain separate dependencies. Installed-layout
execution, dynamic runtime, independent bootstrap and world/kernel/pkgbase/cache/
performance gates remain open. No host installation, upgrade or publication.
Frontend review: existing build-bsd.c/format-5 backend accepts composed target;
manual updated with artifact boundaries. Make remains production/default.

### Execution from composed compiler layout (2026-10-29)

Extracted the authenticated-by-receipt composed archive into an isolated /usr/obj
stage using tar data filtering; no host installation or chroot. Executed its actual
stripped driver and native private libraries. PATH is /nonexistent; explicit
--sysroot/--ld-path inputs select the recorded SDK and linker. LD_LIBRARY_PATH
selects staged compiler libraries and the SDK execution runtime. Host kernel and
rtld remain in use; this is not a booted/installed-system qualification.

Resource discovery automatically resolves the staged usr/lib/clang/21 directory,
without -resource-dir. All six compiler aliases share the expected inode. clang,
cc, clang++ and c++ compile, link and execute C/C++ probes in both static and
dynamic modes (eight cases). C includes packaged xmmintrin.h; C++ uses vector,
numeric and iostream. Both preprocessor aliases produce the expected major version.
Compiler and all four generated dynamic programs' loader traces resolve libraries
only from the stage or declared SDK runtime, apart from host rtld; the two private
compiler libraries resolve specifically to the staged native artifacts. No host
compiler/linker fallback. The CC shell script's absolute /usr/bin/c++ invocation
was not run outside a matching root; its payload was previously byte-verified.

Commands, archive/compiler context and outputs are retained at
/usr/obj/usr/src/bazel-clang-staged-execution-qualification-20261029-r2/results.json;
check.py reproduces the run in a fresh directory. The initial run without output-
program loader checks remains separately retained. These are diagnostic staged-
layout checks, not yet a maintained Bazel installed-layout test. Existing maintained
SDK C/C++ tests cover direct action compilation/link/execution. Integrating this
layout coverage, native linker/runtime composition, independent bootstrap and full
world/kernel/pkgbase/cache/performance qualification remain open.
Frontend review: no new build inputs/policy/publication semantics; existing composed
artifact is exercised. Make remains production/default.

### Native ELF LLD build, installation and compiler integration (2026-10-29)

Added native LLD's 55 maintained sources with explicit dependencies, PIE compilation,
native LLVM registration/default providers, LLD version configuration and generated
Options.inc. Runtime and installed variants share one object target. The first
analysis rejected nonexistent header glob patterns; corrected inventory includes
actual ELF .h/.def and public .h/.inc files. No source or sandbox workaround.
The resolved 55-source inventory matches expanded Make exactly.

Corrected build bazel-lld-native-20261029-r2 and build/test/install run
bazel-lld-install-tests-20261029 pass under /usr/obj/usr/src with 16 jobs. Fresh
Make reference generates Options.inc then builds/links/stages LLD using the existing
SDK and LLVM library (not independent bootstrap). Option table matches all 139,009
bytes, and its included OptParser.td matches Make's depfile. Global/weak ELF symbol
records match the fresh Make linker with zero additions/removals. All five
installation records, both compressed manuals, links, metadata and debuglink CRC
match. Installed ELF is PIE with BIND_NOW/RELRO/non-executable stack and no
RPATH/RUNPATH/TEXTREL. Evidence/scripts:
/usr/obj/usr/src/bazel-lld-reference-qualification-20261029.

The compiler probe rule now declares the linker's files_to_run, preserving native
linker runtime dependencies. New native_link_c_test/native_link_cc_test compile,
link and execute probes with native Clang AND native LLD. Both pass, alongside the
two original staged-linker SDK tests (four passing reported cases, none skipped).
System headers/libraries/CRT still come from the declared Make-prepared SDK.

Frontend review: existing build-bsd.c/format-5 transports new targets; manual
updated. Cross-link/platform/configuration variants, LTO and broader linker tests,
installed compiler/linker composition, independent bootstrap and full system/cache/
performance gates remain open. Make remains production/default; no host install.

### Native Clang/LLD LTO execution (2026-10-29)

Added maintained full-LTO and ThinLTO C/C++ compiler probes. The lto rule attribute
accepts only none/full/thin and contributes the corresponding compiler argument.
All four tests in /usr/obj/usr/src/bazel-clang-native-lto-20261029 passed with no
skipped cases. The execution log confirms four uncached processwrapper-sandbox
compiler actions, using native Clang and native LLD with -flto=full or -flto=thin;
each action exited zero and its generated static executable passed the runtime test.
These are single-translation-unit smoke tests, not inter-module optimization,
ThinLTO cache, dynamic-library LTO or performance qualification. System headers,
CRT and runtime libraries still come from the declared Make-prepared SDK.

Frontend review: build-bsd.c and the format-5 source_graph.py backend already carry
explicit targets/tests; no new frontend option is required. Manual documents all
four test labels. Independent bootstrap, complete system/package/runtime/cache and
performance gates remain open. Make remains production/default; no host install.

### Native llvm-ar and llvm-ranlib candidate (2026-10-29)

Added explicit llvm-ar-driver.cpp and upstream llvm-ar.cpp native targets, sharing
one object library between runtime and installed variants. Uses native LLVM target
registration/defaults, private LLVM and declared runtime dependencies. The current
candidate supports the default shared-library configuration on amd64 FreeBSD;
LLVM_LINK_STATIC_LIBRARIES and cross-host variants are not qualified.
Runs bazel-llvm-ar-native-20261029 and bazel-llvm-ar-install-20261029 under
/usr/obj/usr/src pass. Fresh Make reference builds both sources, links and installs
using the pre-existing SDK/private LLVM library. Global/weak ELF records match
with no additions/removals. All five payload records match installation ownership,
modes, tags and hardlinks; both compressed manuals match byte-for-byte and debuglink
CRC is valid. llvm-ranlib is a binary hardlink with its own distinct manual payload.

Diagnostic runtime checks exercise create/list, deterministic timestamps, ranlib
argv0 dispatch, native LLD relocatable-link resolution of an archive member,
byte-identical extraction and deletion. Runtime executable digest is checked
against its saved artifact receipt. Native Clang and LLD build-tree tools supply
the fixture; PATH is /nonexistent, with absolute readelf for symbol inspection.
These are not yet maintained Bazel archive-operation tests. Reports and scripts:
/usr/obj/usr/src/bazel-llvm-ar-reference-qualification-20261029.

Frontend review: existing build-bsd.c and format-5 source_graph.py support the
explicit runtime/installed/inventory/archive targets; manual records the scope.
No host installation or publication. Independent bootstrap, complete system,
configuration coverage, cache and performance qualification remain open.
Make remains production/default.

### Four native LLVM utilities (2026-10-29)

Added llvm-nm, llvm-cxxfilt, llvm-size and llvm-strings using shared llvm_utility.bzl
for common default-shared LLVM compilation/link/installation policy. Each BUILD
owns explicit sources and option-table input; native llvm-tblgen generates Opts.inc
with the declared OptParser.td include. Resolved source counts 2/2/2/1 match expanded
Make exactly, and each fresh Make depfile confirms the declared TableGen include.
Runtime and installed variants share compiled objects; installed variants omit
build-tree runtime search paths. Current supported qualification is native amd64
FreeBSD/default shared LLVM, not LLVM_LINK_STATIC_LIBRARIES or cross-host variants.

Maintained build /usr/obj/usr/src/bazel-llvm-utilities-20261029 passes. Fresh Make
references build all seven sources and four option tables, then link/install using
the existing SDK/private LLVM library. Each utility has zero global/weak ELF symbol
record differences. All twelve installation payload records match ownership,
modes/tags, four manuals match bytes, and all four debuglink CRCs validate.
Generated tables match respectively 20,946 / 6,638 / 7,872 / 6,023 bytes.
Reports/scripts: /usr/obj/usr/src/bazel-llvm-utilities-reference-qualification-20261029.

Maintained //lib/clang:utilities_test passes in bazel-llvm-utilities-test-20261029
(one reported case, none skipped). Native Clang creates a relocatable object;
native utilities check its defined code/data symbols, C++ name demangling, section
reporting and extraction of a known string. All executable paths are declared
runfiles; PATH is /nonexistent. This is smoke coverage, not exhaustive options or
numeric size validation. Test harness still builds with the Make-prepared SDK.

Frontend review: build-bsd.c and format-5 source_graph.py already support these
explicit target/test selections; manual updated. No host installation/publication.
Independent bootstrap, remaining tools/system targets, static/cross configuration,
cache and performance qualification remain open. Make stays production/default.

### Native readobj/readelf and symbolizer/addr2line (2026-10-29)

Added native llvm-readobj (12 sources) and llvm-symbolizer (2 sources), extending
the common LLVM utility macro with declared private-header dependencies and
binary aliases with distinct manual payloads. Source inventories match expanded
Make; generated Opts.inc tables match fresh Make (36,749 and 22,590 bytes), and
Make TableGen depfiles confirm the explicit OptParser.td include. Build run:
/usr/obj/usr/src/bazel-llvm-inspect-20261029, including the previous utilities test.
Both installed candidates match fresh Make global/weak ELF symbol records with
zero differences. All ten installation records, four compressed manuals and both
debuglink CRCs match. Reference builds reuse the existing SDK/private LLVM library;
this is not independent bootstrap. Reports and scripts are under
/usr/obj/usr/src/bazel-llvm-inspect-reference-qualification-20261029.

Extended //lib/clang:utilities_test exercises ELF headers/symbols, linked debug-line
lookup and readelf/addr2line argv0 dispatch, alongside the prior four utilities.
The first extended run (bazel-llvm-inspect-test-20261029) failed symbol-name lookup
on a relocatable object with overlapping section addresses. Diagnostics retained
under symbolizer-diagnostic show exactly the same behavior in the fresh Make
symbolizer: name lookup is unknown and address zero selects the data symbol.
Native LLD now links the fixture to give sections distinct addresses; symbol and
source-line assertions remain strict. Corrected r2 passes, and final r3 adds both
alias dispatch checks and passes (one reported case, none skipped). Relocatable
symbol-name lookup remains a recorded upstream/reference limitation, not a claimed
supported case. These tests do not execute the freestanding linked fixture.

Frontend review: build-bsd.c/format-5 source_graph.py already carry explicit targets
and tests; manual updated. Native amd64/default shared LLVM remains the qualified
configuration; static LLVM, cross-host, independent bootstrap, full system/package,
cache and performance gates remain open. Make stays production/default. No host
installation, upgrade or publication.

### Native llvm-objcopy/llvm-strip (2026-10-29)

Added the three maintained objcopy sources, private ObjcopyOptions.h, and explicit
native TableGen actions for BitcodeStripOpts, InstallNameToolOpts, ObjcopyOpts and
StripOpts. CommonOpts.td is declared only for its two users; all include closures
match fresh Make depfiles. Common LLVM utility macro accepts either one table
source or explicit generated outputs, and aliases may omit a separate manual.
llvm-strip is a binary hardlink; Make installs only the llvm-objcopy manual here.

The first output path was already occupied and build-bsd rejected it. New run
/usr/obj/usr/src/bazel-llvm-objcopy-native-20261029 passes, including the existing
utilities test. Fresh Make driver/link/install comparison finds zero global/weak
ELF symbol differences, all four installation records match, manual bytes match,
and debuglink CRC validates. Four generated tables match all 79,446 bytes; expanded
Make and Bazel source inventory both contain three sources. Reference scripts and
reports: /usr/obj/usr/src/bazel-llvm-objcopy-driver-reference-20261029.
Make reference still uses the existing SDK/private LLVM library.

Extended //lib/clang:utilities_test uses native objcopy to split debug data and
add its debuglink, invokes native strip through argv0, checks that .debug_info and
.symtab are absent, verifies .text bytes unchanged, then resolves the original
function/source line through the separate debug file using native symbolizer.
Initial bazel-llvm-objcopy-test-20261029 failed because name lookup was requested
after removing the symbol table. Corrected test discovers the linked address with
native nm before stripping and uses it for lookup; r2 passes (one reported case,
none skipped). No fixed fixture address and no relaxed symbol/line assertions.

Frontend review: build-bsd.c/format-5 source_graph.py already transport targets and
tests; manual updated. Installation helpers still use declared SDK objcopy/strip;
using native tools throughout installation requires bootstrap dependency review
and remains open. Static LLVM/cross-host variants, complete system/bootstrap,
cache/performance/package gates remain open. Make stays production/default;
no host installation or publication.

### Native llvm-objdump (2026-10-29)

Added all nine maintained driver sources, explicit private headers and native
ObjdumpOpts/OtoolOpts generation. Both tables include only OptParser.td; fresh
Make depfiles confirm the closure. The unused llvm-objcopy include directory in
the Make command is not needed by these actions. Resolved sources match expanded
Make. Native build /usr/obj/usr/src/bazel-llvm-objdump-native-20261029 passes.
Fresh Make driver/link/install comparison has zero global/weak ELF symbol record
differences; all three installation records, compressed manual and debuglink CRC
match. Both generated tables match all 52,239 bytes. Reference/scripts/reports:
/usr/obj/usr/src/bazel-llvm-objdump-driver-reference-20261029.

Extended //lib/clang:utilities_test passes in bazel-llvm-objdump-test-20261029
(one reported case, none skipped), checking native disassembly of the linked
answer function and its expected AMD64 move/return instructions, plus code/debug
section reporting. Existing compiler/linker/inspection/debug-split checks remain.
This does not establish other architectures, COFF/Mach-O/Wasm/XCOFF runtime
behavior or exhaustive option coverage, despite those sources being built.

Frontend review: existing build-bsd.c/format-5 source_graph.py supports the explicit
targets/tests; manual updated. The fresh reference reuses Make SDK/private LLVM
libraries. Independent bootstrap, remaining system/tool targets, static/cross
configuration, cache/performance and complete pkgbase gates remain open. Make
stays production/default; no host installation, upgrade or publication.

### Native coverage and profile-data utilities (2026-10-29)

Added llvm-profdata (two sources) and llvm-cov (twelve sources), including declared
private coverage headers. The common LLVM utility macro now permits utilities
without option-table generation; it creates no artificial option action for them.
Resolved inventories match expanded Make. Maintained native build
/usr/obj/usr/src/bazel-llvm-profiles-native-20261029 passes, including the existing
utilities test. Fresh Make driver/link/install comparisons show no global/weak
ELF symbol record differences. All six installation records, both manuals and
both debuglink CRCs match. References/scripts/reports are under
/usr/obj/usr/src/bazel-llvm-profiles-reference-20261029. Reference builds use the
existing SDK/private LLVM library, not a fresh independent bootstrap.

Added the coverage attribute to bsd_compiler_probe and a native Clang/LLD static
coverage probe. Its headers, CRT, libraries and libclang_rt.profile archive are
explicit staged SDK inputs. //lib/clang:profiles_test executes this instrumented
program with an isolated LLVM_PROFILE_FILE, merges it with native llvm-profdata,
checks main's invocation count is one, then checks native llvm-cov reports the
probe source and a 100% metric. It does not assert every coverage metric is 100%.
Run /usr/obj/usr/src/bazel-llvm-profiles-test-20261029 passes (one reported case,
none skipped). PATH is /nonexistent; tools/probe are declared runfiles. This is
real instrumentation/profile/report smoke coverage, not a native profile-runtime
build or exhaustive gcov/PGO/instrumentation-format qualification.

Frontend review: build-bsd.c/format-5 source_graph.py already transport these
explicit targets/tests; manual updated. Static LLVM/cross-host variants, complete
native SDK/bootstrap, remaining system targets, cache/performance and pkgbase
qualification remain open. Make stays production/default; no host installation,
upgrade or publication.

### Native Clang scanner and formatter candidates (2026-10-29)

Added clang-scan-deps (two sources) and clang-format (one source) using a shared
Clang utility macro with explicit native private Clang/LLVM dependencies and no
manual payload, matching their Makefiles. Scanner option generation declares
OptParser.td. Initial native run failed on clang-format's private MatchFilePath.h;
added its narrow header dependency. Formatter target requires the existing
clang_format_or_extras setting so libclang contains MatchFilePath.cpp. Corrected
run bazel-clang-utilities-native-20261029-r2 with clang_format=true passes.

Scanner fresh Make driver/link/install reference matches global/weak ELF records,
both payload records and debuglink CRC. Its option table matches all 10,894 bytes.
Both resolved source inventories match expanded Make. Formatter Make reference
FAILED to link because the pre-existing Make libclang lacks matchFilePath; it is
NOT qualified for fresh Make binary/install parity. Next reference step must use
a Make Clang library built with formatting support, not patch the link command
with a substitute object. Reference/scripts/reports/failure:
/usr/obj/usr/src/bazel-clang-utilities-reference-20261029 and
/usr/obj/usr/src/bazel-clang-format-make-20261029/all.log.

Diagnostic host runtime checks pass for nested include discovery, replacing a
nested include and seeing the new dependency/removing the old one, explicit LLVM
formatting, idempotence and dry-run validation. Tool digests match saved artifact
receipts, PATH is /nonexistent and compiler input is explicit. First diagnostic
used unsupported -j=1 and failed; corrected run omits it, using default parallelism,
and keeps the original fixture. Evidence in runtime.json/runtime-r2. These are
not yet maintained Bazel tests or proof of Bazel cache invalidation. Formatter
runtime success does not close the missing Make reference qualification.

Frontend review: build-bsd.c/format-5 source_graph.py already transport clang_format
and explicit targets; manual updated. Static LLVM/cross-host, native SDK/bootstrap,
remaining system targets, full pkgbase/cache/performance gates stay open. Make
remains production/default; no host installation/upgrade/publication.

### Formatter reference rebuild and maintained tests in progress (2026-10-29)

Started a full isolated Make libclang build with WITH_CLANG_FORMAT=1 and 16 jobs:
/usr/obj/usr/src/bazel-clang-format-library-make-20261029/build.log, object tree
bazel-clang-format-library-make-objects-20261029. It retains the existing SDK,
LLVM library and bootstrap generators, but rebuilds all Clang library objects.
Driver reference script clang-format-make-r2.py under
bazel-clang-utilities-reference-20261029 waits for that complete library and
selects it by replacing the exact maintained libclang path in LDADD/DPADD;
it does not inject a standalone substitute object. Neither reference is yet
claimed complete here.

Added //lib/clang:clang_tools_test for command-line dependency scanning across a
nested-header change, formatting idempotence and dry-run validation. Existing
utilities/profile tests now share tool_test.h helpers. Qualification run
bazel-clang-tools-test-20261029 requests all three tests with clang_format=true;
result remains pending at this checkpoint. Frontend review: existing build-bsd.c
and format-5 backend already transport the setting/targets/tests. No frontend
input or publication policy changed. Do not infer passing tests from this entry.

### Maintained Clang tool tests pass (2026-10-29)

Run /usr/obj/usr/src/bazel-clang-tools-test-20261029 passes all three maintained
tests: utilities_test, profiles_test and clang_tools_test (three reported cases,
none skipped). New scanner test uses the supported per-file command after --,
checks nested header discovery, changes the include, then verifies replacement
and removal of the old dependency. Formatter checks explicit LLVM style,
byte-identical second formatting and dry-run validation. All tools are declared
runfiles and PATH is /nonexistent. Common fork/exec/output checks now live in
lib/clang/tool_test.h rather than duplicated in the test programs.

This closes the prior maintained-test gap for the tested scanner/formatter cases.
It does not prove compilation-database/module/PCH variants or cache invalidation.
Formatter fresh Make parity still awaits the full format-enabled library rebuild
recorded above. Frontend review: existing build-bsd.c/format-5 supports these test
labels and clang_format=true; manual updated. Make remains production/default.

### Tool-test same-input replay (2026-10-29)

Replayed identical configured targets/tests into fresh qualification directory
/usr/obj/usr/src/bazel-clang-tools-replay-20261029. All three test results were
cached, all three saved target output-name/SHA256 mappings match the prior run,
and execution.json is empty (no spawn execution). Bazel reports three action
cache hits and one internal action. This establishes reuse for these unchanged
inputs only, not dependency invalidation, clean-build reproducibility, remote
cache correctness or a controlled performance comparison. Formatter full Make
library rebuild remains independently active; no reference completion claimed.

### Toolchain manual-alias correction (2026-10-29)

While reviewing installation composition, expanded Make metadata exposed two
MLINKS= assignments in usr.bin/clang/toolchain/Makefile that replaced earlier
aliases. MK_LLVM_BINUTILS=yes produced eleven executable aliases but only four
manual aliases. Changed the gcov and objdump assignments to MLINKS+=, preserving
all eleven intended manual aliases. Expanded metadata now has matching basename
coverage for all eleven binaries/manuals; MK_LLVM_BINUTILS=no emits neither set.
Evidence: /usr/obj/usr/src/bazel-toolchain-alias-audit-20261029/results.json.
This is metadata verification, not an installed-image qualification. Existing
Make-based package builds consume this corrected Makefile normally.

Frontend review: no build-bsd.c option/backend/helper change is required; normal
world/package installation already uses this maintained target. Native Bazel
composition of these optional default-name aliases remains to be implemented.
Formatter's full isolated Make library build remains active, not yet qualified.

### Formatter disabled-configuration rejection (2026-10-29)

Explicitly requested //usr.bin/clang/clang-format:clang-format with clang_format
and clang_extras both false. Run bazel-clang-format-disabled-20261029 terminates
with the expected analysis error: the target is incompatible and cannot be built
when explicitly requested. Only an internal action ran; this is not a successful
build or test. This confirms the formatter cannot silently omit its required
library-support component in this configuration. The full format-enabled Make
library rebuild is still active and formatter parity remains open.

### Formatter fresh Make parity completed (2026-10-29)

The full isolated Make libclang rebuild with WITH_CLANG_FORMAT=1 completed
successfully (840 actual object files; .depend.* files are not objects). It uses
existing SDK/LLVM/bootstrap generators and creates its own complete Clang library.
Receipt/log: /usr/obj/usr/src/bazel-clang-format-library-make-20261029.

The first driver attempt with this library (clang-format-make-20261029-r2) failed
Make's LIBADD validation because re-injecting expanded LDADD carried -l flags.
Preserved that failure. Corrected r3 uses a private object-tree view: all existing
object dependencies remain selected except libclang, which points to the fresh
complete library. The normal Make library resolution/validation runs unchanged;
no standalone substitute object or validation bypass. Driver script requires the
library's successful receipt and checks its SHA256 before and after the build.

Fresh driver/build/install r3 succeeds. Saved Bazel formatter from
bazel-clang-utilities-native-20261029-r2 matches all global/weak ELF symbol records
with zero differences. Both installation payload records and debuglink CRC match;
there is no manual payload for this utility. Comparison scripts/report:
/usr/obj/usr/src/bazel-clang-utilities-reference-20261029/clang-format-verify-r3.py
and clang-format-r3-comparison.json. This closes the previously recorded formatter
binary/install parity gap for the tested configuration. It is not machine-code
identity, independent bootstrap, cross-host/static-LLVM or performance evidence.

Maintained scanner/formatter runtime tests were already verified in
bazel-clang-tools-test-20261029. Frontend review: no input/schema or backend changes
needed; manual removes obsolete pending-parity wording. Complete world/kernel,
SDK/bootstrap, pkgbase/publication, cache-invalidation and performance gates remain
open. Make stays production/default; no host installation or publication.

### Native LLVM utility installation composition and aliases (2026-10-29)

Added //usr.bin/clang/toolchain:install_archive, composing ten native LLVM utility
installation manifests and optional default-name aliases. The llvm_binutils bool
(default true, matching native src.opts.mk) controls eleven executable symlinks
and eleven manual hardlinks. Alias package tags remain toolchain; original utility
payloads retain their original tags. Disabled aliases do not remove the LLVM-named
utilities. This artifact is not a complete compiler/sysroot or package repository.

bsd_install_manifest can now import other manifests. Their records/payload depsets
are preserved, duplicate destination checks apply to imported and new records,
and the existing hardlink validator checks the composed namespace. No external
or dangling hardlink exception was introduced.

Maintained runs bazel-binutils-install-20261029 and bazel-binutils-disabled-20261029
pass under /usr/obj/usr/src. Enabled archive contains 59 records, disabled contains
37. All 22 alias records match an isolated normal Make toolchain install, including
owner/group/mode/package tags, symlink targets, hardlink inodes and manual bytes.
The reference supplies previously qualified Make manual payloads for the normal
MLINKS install. Disabling aliases removes exactly those 22 records; remaining
metadata and file bytes are identical. Evidence/scripts/reports:
/usr/obj/usr/src/bazel-binutils-reference-20261029.

Frontend review: build-bsd.c/format-5 source_graph.py already transports the new
boolean and target; manual updated. No host installation/publication. Cross-arch,
split-manpage variant, complete toolchain/system composition, native SDK/bootstrap,
cache invalidation, pkgbase/publication and performance gates remain open. Make
stays production/default.

### Composed compiler/linker/utility installation (2026-10-29)

Added //lib/clang:compiler_tools_install_archive, reusing the existing compiler
manifests and composing native LLD, the LLVM utility/alias manifest, scanner and
profile-data utility. clang-format is included only with clang_format or extras.
The prior compiler_install_archive keeps its existing narrower contents. New
artifact excludes debugger/optional LLVM extras, system headers/runtime/CRT and
compiler-runtime packages; it is not a complete SDK or installed operating system.

Build /usr/obj/usr/src/bazel-compiler-tools-install-20261029 with clang_format=true
passes and produces 348 payload records. Extracted the saved archive into an
isolated stage after matching its SHA256 to the artifact manifest. Diagnostic
/usr/obj/usr/src/bazel-compiler-tools-runtime-20261029/check.py passes 38 commands:
automatic resource-header and adjacent ld.lld discovery, compiler aliases, eight
C/C++ static/dynamic compile-link-run cases using the staged native linker,
preprocessor aliases and thirteen tool version invocations. Eleven executable
alias resolutions are checked. Compiler/output loader checks constrain resolution
to stage or explicit SDK runtime except the host rtld. PATH is /nonexistent.
The CC shell wrapper is not executed outside a matching root, as before.

This strengthens the prior staged compiler check by replacing its SDK linker with
the packaged native linker. System headers/CRT/runtime still use the explicit
Make-prepared SDK; host kernel/rtld remain in use. These staged-layout checks remain
diagnostic scripts, not maintained Bazel installed-layout tests. No whole-system,
independent bootstrap, cache invalidation or performance claim.

Frontend review: build-bsd.c/format-5 backend already supports composed targets and
settings; manual updated with exact artifact boundaries. Make stays production/
default. No host installation, upgrade, reboot or publication.

### Native compiler profiling runtime (2026-10-29)

Added lib/libclang_rt/profile native PIC archive from 14 C sources and one C++
source, with declared compiler-rt headers and source inventory. Installation
provides libclang_rt.profile-x86_64.a and the two profile .inc headers with
package=clang,dev metadata and standard mtree/account directory policy. This
candidate is constrained to native FreeBSD amd64; other CRTARCH variants remain.

Qualification bazel-profile-runtime-qualified-20261029-r3 passes through build-bsd
with 16 jobs. Fresh Make build/install reference is bazel-profile-runtime-make-
20261029. The preserved comparison under bazel-profile-runtime-reference-20261029
checks all 15 archive members, 381 global/weak symbol records including per-object
membership, all three installation records and both header payloads. No symbol
record differences; header bytes and installation metadata match. This is not
machine-code identity. Initial qualification attempts failed on missing archive
policy inputs and are preserved; corrected target uses existing archive policy.

The maintained //lib/clang:profiles_test reports one passing case. Coverage probes
now require a declared profile_runtime archive, compile instrumentation separately,
and link that archive without a driver flag that would select the SDK profile
runtime. Execution log confirms native compile and native LLD link actions under
processwrapper-sandbox. Instrumented execution, native profdata merge and native
cov reporting pass. System headers/CRT/other runtime still use the prepared SDK;
this does not establish independent bootstrap, exhaustive gcov behavior, complete
world/kernel/pkgbase, or performance. No host installation/publication.

Frontend review: build-bsd.c and format-5 source_graph.py already pass these targets
and tests without a new input contract; manual updated. Make stays production.

### Native amd64 startup objects (2026-10-29)

Added lib/csu/amd64 native startup objects: crt1/Scrt1/gcrt1, crti/crtn,
crtbegin/crtbeginS/crtbeginT, and crtend/crtendS. Common and architecture headers
are declared. Separate compilation identities preserve PIC, SHARED, GCRT and
LOCORE variants; ordered relocatable links use native LLD with Make's znow/relro
flags. The new bsd_relocatable_link action takes explicit object inputs and linker
runfiles, rejects empty/duplicate inputs, and performs no source discovery.

Fresh Make comparison under /usr/obj/usr/src/bazel-csu-reference-20261029 passes
for all ten objects: 30 global/weak symbol records, ELF note bytes, .text bytes,
and non-debug relocation records (ignoring symbol-table numbering). Eleven
installation records match, including the /usr/lib package=clibs-dev directory
record found missing in the initial candidate and corrected. Debug bytes are not
claimed identical. Build/install evidence is bazel-csu-runtime-20261029-r2;
fresh Make reference is bazel-csu-make-20261029.

Two maintained native_startup_c_test/native_startup_cc_test cases pass under
//usr.bin/clang/clang. bsd_compiler_probe accepts declared startup_objects, checks
unique names in one directory and requires the complete five-object static set,
then passes the directory through Clang's -B interface. Separate saved driver
traces confirm both C and C++ choose native crt1/crti/crtbeginT/crtend/crtn; all ten
live object hashes match saved qualification artifacts. Native compiler and LLD
are used, with SDK system headers/libraries. Existing SDK-only tests remain.

This qualifies static C/C++ smoke execution, not dynamic/PIE/GCRT startup,
constructor/destructor coverage, other architectures or independent bootstrap.
The full csu tests and configured system graph remain to qualify. Make remains
production/default. No host installation, upgrade, reboot or publication.
Frontend review: build-bsd.c/format-5 source_graph.py already accept these explicit
targets and tests; no CLI/schema change needed. Manual and audit updated.

### Maintained static csu tests through rules_cc (2026-10-29)

Added //lib/csu/amd64:startup, a CcInfo adapter exposing declared native startup
objects through the compiler driver's -B interface. Ordinary cc_binary consumers
receive startup artifacts as linker additional_inputs; filename/directory and
required-object validation runs during analysis. This avoids separate compilation
or link logic for test programs. The existing compiler-probe targets remain.

Added all eight existing static cases from lib/csu/tests/init_test.c, fini_test.c
and cxx_constructors.cc through the maintained ATF runner. Qualification
bazel-csu-static-tests-20261029-r2 reports eight passed cases, no skips: .ctors,
preinit/init ordering, .dtors, .fini_array, __dso_handle, and C++ construction and
destruction. All three test programs use normal rules_cc builds and native ATF;
C++ uses declared native libc++ headers/libraries. Initial C++ build failure from
mixed default/native headers is preserved and corrected with the existing native
-nostdinc++ convention. Runtime source files were not changed.

Saved atf-driver-check.py/atf-driver-selection.json under bazel-csu-reference-
20261029 confirm all three compiler-driver links select native crt1/crti/
crtbeginT/crtend/crtn. Action logs declare all ten CRT inputs. The registered
compiler and system libraries still use the explicit prepared SDK. This does not
qualify independent bootstrap, dynamic/PIE/DSO/GCRT startup, test installation,
complete world/kernel/pkgbase or performance. No host installation/publication.
Frontend review: build-bsd.c/format-5 backend accept the existing explicit target
and test lists; no new user input contract. Manual updated; Make stays production.

### Full maintained csu startup matrix and final-link correction (2026-10-29)

Expanded the three unchanged ATF sources across static, dynamic, dynamicpie and
dynamiclib modes, including the native DSO_LIB helper and DSO_BASE programs.
Added all four existing errno startup programs (static/dynamic, with/without
pthread). Native shared ATF/C++ dependencies are used for dynamic tests; an initial
PIE failure selecting non-PIC static ATF was corrected by modeling these shared
dependencies. Runtime libraries are declared runfiles, with SDK libc/libsys/
libgcc_s and native ATF/C++/math/pthread/helper libraries as required.

Driver inspection found that CcInfo-only startup flags were dropped during
shared-dependency linking, despite passing runtime cases. The prior adapter is
superseded: //lib/csu/amd64:startup now supplies validated startup artifacts, and
startup_link_flags supplies a generated compiler response file in a separate
output group. Each cc_binary/cc_shared_library final link explicitly declares
both as additional_linker_inputs and passes the response file in linkopts or
user_link_flags. This keeps -B and object dependencies at the final link, outside
dynamic_deps pruning. No hardcoded Bazel output directory or copied SDK CRTs.

Final run bazel-csu-all-tests-20261029-r2 reports 36 passed cases and no skipped
cases. Saved modes-check-r2.py under bazel-csu-reference-20261029 verifies all 17
final links choose native startup objects: ordinary, PIC/PIE, static, and shared
helper variants. Loader checks cover all eleven dynamically linked test programs
and require each resolved library to match a declared runfile (host rtld remains).
ELF type checks distinguish non-PIE/PIE in six dynamic/dynamicpie programs.
Initial failures and pre-correction passing tests are retained and must not be
cited as native dynamic-startup qualification.

These are the cases in the current maintained csu test sources; this does not
establish exhaustive startup behavior, GCRT execution, other architectures,
installed-test/package parity, independent bootstrap, complete world/kernel or
performance. SDK compiler and remaining system libraries still apply. No host
installation/publication. Frontend review confirms build-bsd.c and format-5
source_graph.py accept the explicit test matrix without schema changes; manual
updated. Make remains production/default.

### Packaged csu test suite (2026-10-29)

Added //lib/csu/tests:install_manifest and install_archive for the full maintained
suite: 17 binaries, 15 separate debug payloads, six Kyuafiles and nine directory
metadata records. Source-owned installation policy preserves package=tests,
permissions, directory/debug tags, installed names and Kyua subdirectory order.
bsd_kyuafile now accepts an output path (default Kyuafile unchanged) so one Bazel
package can compose multiple suite registrations without output collisions.

Fresh Make build/install reference: bazel-csu-tests-make-20261029. Final frontend
run bazel-csu-test-install-20261029-r4 passes with all 36 runtime cases. Comparison
scripts/reports under bazel-csu-tests-reference-20261029 establish 47 matching
installation records, six byte-identical Kyuafiles, 15 debuglink CRCs, and matching
global/weak symbol records for all 15 debug payloads. Installed binaries contain
no Bazel output/solib runtime search paths. DSO programs preserve Make's installed
/usr/tests/lib/csu/dynamiclib RUNPATH and link ATF C++ in all three programs.

Corrections from reference evidence: two errno binaries with explicit -static
omit separate debug files under bsd.prog.mk (unlike NO_SHARED static ATF tests).
The helper DSO now has header-only dependencies, matching Make's unresolved
symbols for the executable to supply, instead of extra DSO dependencies. Initial
archive output collision, debug inventory differences and four helper symbol-type
differences are preserved in earlier evidence; final checks pass without ignoring
them. Runtime fixtures remain unchanged.

These checks do not establish executable byte identity, execution from a fully
installed system/package repository, other configurations/architectures, GCRT,
independent bootstrap or complete world/kernel/publication/performance. Tests
still use the prepared SDK compiler and remaining runtime. No host installation,
upgrade or publication. Frontend review: build-bsd.c/format-5 backend already
accept the archive and test labels; no CLI/input schema change. Manual updated.

### Extracted csu archive execution (2026-10-29)

Ran SDK Kyua against the unmodified Kyuafiles extracted from the saved native
install_archive (SHA256 52ce4e84624e251ab716f1f36e2e123203ccfdf06b4f645eb4873e180d4461c5).
All 36 cases passed with zero broken/failed/skipped cases. JUnit report independently
confirms 36 successful cases. Post-run comparison verifies all 38 payload files
remain byte-identical to the archive. Loader traces check all eleven dynamic test
programs plus Kyua: every resolved library matches a declared runtime artifact,
and DSO tests load libh_csu.so from the extracted archive itself.

Evidence: /usr/obj/usr/src/bazel-csu-packaged-runtime-20261029 contains results.db,
junit.xml, logs, invocation and receipt. Preserved packaged-run.py and packaged-
audit.py are under bazel-csu-tests-reference-20261029. The diagnostic stage uses
explicit native library runfiles and SDK execution libraries through
LD_LIBRARY_PATH; host kernel/rtld and SDK Kyua remain. This establishes execution
of the packaged test payload/layout, not a booted installed OS, pkgbase transaction,
independent bootstrap, or hermetic runtime. No host installation/upgrade/reboot.
The diagnostic is not yet a maintained Bazel archive-execution test.

### Sanitizer interfaces and minimal UBSan runtime (2026-10-29)

Added native lib/libclang_rt/include installation for the 16 sanitizer interface
headers in its maintained Makefile, and lib/libclang_rt/ubsan_minimal archive,
source inventory and installation targets. Sanitizer common/public headers are
declared source dependencies; the minimal archive preserves common compiler-rt
flags, its extra define and PIC object selection. Runtime candidate is native
FreeBSD amd64; installed header inventory is source-owned, not discovered from
host installations.

Fresh Make references under bazel-compiler-rt-include-make-20261029 and
bazel-compiler-rt-ubsan_minimal-make-20261029 match all 17 installation records.
All 16 header payloads are byte-identical. Minimal UBSan has one matching archive
member and 53 matching global/weak symbol records. Comparison scripts/report
are retained under bazel-compiler-rt-next-reference-20261029.

Final frontend run bazel-compiler-rt-next-test-20261029-r2 reports one passing
maintained runtime_test. The test uses actual compiler-generated signed-overflow
instrumentation: clean input emits no diagnostic, recoverable overflow emits the
minimal runtime diagnostic and exits normally, and nonrecoverable overflow emits
that diagnostic and terminates with SIGABRT. Core dumps are disabled in the child.
No handler is stubbed or replaced. Saved runtime-link.params selects the native
archive without sanitizer-driver link flags that could select an SDK runtime.
The first test build omitted linkstatic and failed to find static probe libraries;
this was corrected in Bazel dependency selection, with failed evidence retained.

SDK compiler, CRT and system libraries remain; other sanitizer runtimes,
other architectures, additional UBSan handlers/concurrency and independent
bootstrap remain unqualified. This is not machine-code identity or complete
world/kernel/package/performance qualification. No host installation/publication.
Frontend review: build-bsd.c and format-5 backend already support explicit labels;
manual updated, no new input schema. Make stays production/default.

### Shared compiler-runtime archive policy and support components (2026-10-29)

Added lib/libclang_rt/runtime.bzl for source-owned native amd64 compiler-rt
archive policy: common C/C++ flags/defines, separately compiled assembly,
explicit PIC object archives, source inventories and installation metadata.
Callers declare exact sources and extra definitions; no Make query, host library
selection or source-discovery fallback. Minimal UBSan now uses the macro, with
its archive SHA256 unchanged (0f67d4b56287c86d52b15c3aff5ac261d248b33534c6fcd648fed7c3eea0e8b1).
The existing mixed-C/profile component retains its separate implementation.

Added asan-preinit, asan_static and stats_client candidates with declared ASan/
stats headers. Fresh isolated Make references and verification scripts under
bazel-compiler-rt-support-reference-20261029 compare installed metadata, archive
member inventories and global/weak symbols. Counts: asan-preinit one object/three
symbols; asan_static two objects/163 symbols; stats_client one object/eight symbols.
All match. Refactored UBSan also retains one object/53 symbols and its passing
runtime-test report. Final run: bazel-compiler-rt-support-20261029-r2. Initial
analysis failed on an empty stats *.inc glob; removed the nonexistent pattern.

These support archives have artifact/install comparisons, not full ASan or stats
runtime qualification. No instrumentation claims for ASan startup/shadow memory,
assembly access checks or stats reporting until the complete runtimes and their
consumers are built and tested. SDK compiler/system dependencies, other runtime
components/architectures, world/kernel/pkgbase/bootstrap and performance gates
remain open. No host installation/publication. Frontend review: build-bsd.c and
format-5 backend already accept these target lists; manual updated. Make stays
production/default.

### Main ASan and compiler-runtime PIC correction (2026-10-29)

Native amd64 ASan and its C++ companion now have explicit source, archive and
installation targets. Fresh Make comparisons pass: main ASan 77 archive members,
5615 global/weak symbol records; companion one member, 32 records. The ignorelist
payload is byte-identical and its parent-directory package metadata matches Make.
Support archives and minimal UBSan also retain matching inventories/symbols and
installation metadata. Profiling retains 15 members, 381 symbol records, three
installation records and two byte-identical installed headers.

The initial ASan runtime test exposed a real flag mismatch: toolchain PIC objects
added -DPIC, selecting ASAN_DYNAMIC semantics for a static archive. Compiler-rt
now uses ordinary objects explicitly compiled with Make's -fpic, without -DPIC.
The profile archive received the same correction. No ASan runtime checks were
disabled to make the test pass. Native archives are explicitly linked without a
sanitizer driver flag at link time that could select the SDK sanitizer archive.

Frontend run bazel-asan-runtime-20261029-r4 passed all three maintained tests:
ASan clean/heap-overflow/use-after-free, minimal UBSan clean/recover/abort, and
compiler profiling. Comparisons and scripts are in
/usr/obj/usr/src/bazel-asan-main-reference-20261029. The C++ companion has archive
comparison only; C++ instrumentation, concurrency, leak detection, other platforms
and independent bootstrap remain unqualified. SDK compiler/system libraries and
host kernel/rtld remain. No full world/kernel/pkgbase or performance claim.

Frontend review: build-bsd.c and format-5 source_graph.py already accept these
explicit targets and tests; no new input or CLI contract is required. Make remains
the production default. The final rerun includes initialization of the test harness wait-status error
diagnostic. Its three tests and all artifact comparisons pass. Saved link
parameters select native ASan archives; loader-audit.json verifies every resolved
shared library is a declared SDK artifact. Host kernel and rtld remain.
