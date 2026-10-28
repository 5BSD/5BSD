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
