# syslogd native Bazel candidate

2026-11-01. This is a component migration and review record. Make remains the
production backend. Full world/kernel/pkgbase, installed-system behavior and
performance qualification remain open.

## Declared inputs and installation

The native `//usr.sbin/syslogd:syslogd` graph owns the maintained program sources,
ttymsg source/header from wall, actual DTrace provider, Casper dependencies, and
INET/INET6 definitions. Native typed settings select the source/link variants
and LPR/PPP configuration files. Native public Casper headers remain declared
independently of optional library linkage because syslogd_cap.h includes them
unconditionally. No source copy or generated BUILD substitute is used.

`:install_archive` includes the program, separate debug file, both manuals,
configuration and the maintained four ATF shell programs, two helper scripts and
Kyuafile when tests are enabled. The installed suite preserves its VNET jail
metadata. It is not registered as a host daemon test: it requires an isolated
installed-system harness with the actual candidate tools. No daemon, jail,
network reconfiguration, host installation, upgrade or VM was started.

The existing format-5 `build-bsd bazel-test` interface and typed configuration
inputs select these targets. No frontend option, security policy, signing,
publication or manual contract changed; maintained backend helpers are used.

## Findings fixed before committing the candidate

The first native link compiled syslogd_cap.c but omitted its constructor-only
object during archive extraction. The independent ELF comparison caught the
missing service_register import. This would have broken Casper service
registration even though the build action succeeded. Both program-source
branches now use rules_cc's `alwayslink=True`: cc_library for ordinary sources
and cc_import for DTrace-rewritten objects. The separately generated provider
also retains its existing alwayslink policy. Ordinary dependency libraries keep
normal extraction. No custom linker wrapper or synthetic symbol was added.

`//tools/build/bazel/tests/program_objects:constructor_registration_test` is a
native cc_test whose constructor-only translation unit sets a value checked by
main. No externally referenced symbol can pull that translation unit from an
ordinary archive. The regression exercises the actual ordinary and rewritten
object-group patterns in the two configurations. Its initial disabled-tracing
attempt exposed cc_test's dynamic dependency selection despite a `-static`
system-link flag; explicit native `linkstatic=True` fixes that declaration.
The failed attempt remains at the local r3 qualification directory.

A bounded C constructor/CREATE_SERVICE source scan also reviewed rtsold,
ifconfig, nvmecontrol, hastd, mkimg and flua. Their program sources are declared
directly in cc_binary.srcs, so this intervening program-archive omission was not
found there. This is not an exhaustive C++/linker-set audit. Inputs and exact
review scope are retained in
`/usr/obj/usr/src/bazel-syslogd-review-20261101/constructor-consumer-review.json`.

The independent local-only Make build failed with -Werror because `port` was set
but unused when both IP families compiled out. The source fix declares and
initializes it within each family case. Enabled-family behavior is preserved;
no warning was suppressed. The failed original reference remains at
`/usr/obj/usr/src/bazel-syslogd-local-make-20261101/`.

An attempted WITHOUT_CASPER reference was rejected before building:
share/mk/src.opts.mk requires Casper. The valid local variant retains it. The
existing native casper=false setting is not qualified by this work; its common
configuration-policy mismatch needs reconciliation before production. The
observed rejection and policy hash are recorded in the review directory.
No local MK override was forced.

## Final comparison evidence

Fresh independent Make references, after the port-variable source fix:

- `/usr/obj/usr/src/bazel-syslogd-make-r2-20261101/`
- `/usr/obj/usr/src/bazel-syslogd-local-make-r2-20261101/`

Both maintained install-reference.py receipts pass with input rechecks. The
native default and local-option runs are:

- `/usr/obj/usr/src/bazel-syslogd-qualification-r4-20261101/`
- `/usr/obj/usr/src/bazel-syslogd-local-qualification-r4-20261101/`

The local variant disables DTrace, INET/INET6 support, installed tests and PPP,
and enables the LPR configuration. Casper remains enabled. Comparison reports
are at `bazel-syslogd-parity-r3-20261101` and
`bazel-syslogd-local-parity-r3-20261101` under `/usr/obj/usr/src/`.

All eighteen default and ten local component installation records match Make:
destination, type, owner, group, mode and pkgbase tags. All eleven default and
four local non-ELF payloads match bytes, including complete installed test
scripts/helpers/Kyuafile and the selected configurations. Both debuglink names
and CRCs validate against their actual separate debug files in both variants.
Whole DWARF identity and source-level debugger resolution remain unqualified.

Imported/exported symbols, ordered dynamic dependencies and checked ELF
hardening contracts match in both configurations. The first failing native
import comparison is retained in `bazel-syslogd-parity-20261101`; it was not
replaced with a passing report. In the final outputs, service_register is
present as in Make.

Default DTrace provider attributes and normalized probe schemas match, and each
binary has one valid patched amd64 probe site. Raw DOF bytes differ with linked
addresses. The disabled variant has no DOF section on either side. These checks
do not establish live provider registration or probe firing.

Whole executable byte identity does not pass. Full section differences remain
in program-elf.json. Printable read-only-data inventories differ only in three
assert source paths: native uses source-relative paths, Make absolute /usr/src
paths. This string inventory is a bounded observation, not proof that every
machine-code/data byte difference is explained. No executable was rewritten or
filtered to obtain parity. Matching source-path policy, full binary/debug
reproducibility and comparative performance still require qualification.

## Remaining gates

The small native constructor regression runs under both DTrace configurations;
it does not substitute for exercising real syslogd/Casper registration, local
and forwarded messages, rotation, reload, IPv4/IPv6 and the maintained VNET
suites in an installed candidate environment. ARM/RISC-V execution, mutation and
remote-cache behavior, independent bootstrap, pkgbase publication and CPU,
memory, disk I/O/disk-usage comparisons remain open. BIP remains out of scope.

Final default r4 executed both native test targets: the constructor regression
and the maintained module-inventory test. The latter ran its final seven
Python unittest cases. Local r4 executed the constructor regression and the
then-current six-case module-inventory version; the final default run qualifies
the subsequently added architecture-rejection case. Neither test suite executes
syslogd itself. Final default program/install artifact hashes, sizes and modes
match the r3 artifacts used by the comparison reports exactly; the review
directory retains `final-artifact-identity.json`.
