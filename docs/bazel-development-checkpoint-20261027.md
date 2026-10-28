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
