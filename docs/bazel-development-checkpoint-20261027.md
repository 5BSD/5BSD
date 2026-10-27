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
