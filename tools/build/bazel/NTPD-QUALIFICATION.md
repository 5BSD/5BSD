# Native ntpd with maintained time-discipline probes

Subsequent documentation and family install evidence is recorded in
[NTP-DOCUMENTATION-QUALIFICATION.md](NTP-DOCUMENTATION-QUALIFICATION.md).

2026-11-01. Make remains the production/default backend. All seven NTP programs
and all four private libraries now have native build/install candidates. NTP
documentation, complete package aggregation and full service/protocol/runtime
qualification remain open. This is amd64 component qualification, without a
complete code-equivalence, cross-architecture, live clock-control or performance
claim. No host daemon, clock, account or installation was changed.

## Native source and instrumentation ownership

The literal source list retains all 64 maintained daemon/refclock C files plus
the original generated version source. The parser C/header are checked-in
sources consumed by Make; no replacement parser generator is invented. The GPSD
clock textually includes the maintained libjsmn C/header, which are declared
inputs rather than independent translation units. All program objects are
retained with supported rules_cc alwayslink attributes, matching Make's explicit
program objects; ordinary private-library extraction remains unchanged.

The maintained timediscipline_provider.d drives actual native DTrace header and
object generation. The typed DTrace setting selects WITH_COVERAGE_DTRACE,
rewritten objects and the provider. DTRACE_STATIC_ANCHOR semantics are retained
through the genuine hidden __bsd_dof_anchor_timediscipline_provider symbol.
Disabled builds use the original source macros' no-op branch. There are no
substitute probe headers, source rewrites or disabled default instrumentation.
Original parse/ntp/opts libraries, math/digest, optional crypto and pthread edges
retain the exact Make NEEDED order. PIE and the original version action remain.

## Independent Make and native evidence

All paths below are under /usr/obj/usr/src. Final frontend receipts pass three
targets and one safe option test in each profile:

- bazel-ntpd-qualification-r2-20261101 (default)
- bazel-ntpd-noopenssl-qualification-r1-20261101
- bazel-ntpd-nodtrace-qualification-r1-20261101

Independent references are bazel-ntpd[-noopenssl,-nodtrace]-fresh-libraries-
make-r1-20261101. Recorded scripts/commands retain baseline SDK/profile checks,
original LDFLAGS and documented LIBPARSEDIR/LIBNTPDIR/LIBOPTSDIR assignments to
fresh independently built archives. Both dependency and search selections are
checked; actual linker --trace proves fresh archive member selection and
rejects staged old archives. Original install and installconfig both run under
NO_ROOT staging, with 16 compilation jobs and no host installation.

bazel-ntpd-{default,noopenssl,nodtrace}-parity-r2-20261101 holds three passing
receipt/manifest/hash-bound ELF comparisons and install/probe summaries.
PIE/interpreter, hardening, dynamic imports/exports/versions and exact NEEDED
order match Make. Each profile matches eight unique install records, two actual
native/Make debug CRC checks and the exact ntp.conf/leap-seconds payload bytes.
The retained Make METALOG repeats /etc identically; only identical directory
metadata is deduplicated. /etc/ntp stays 0700 and utilities-owned, as Make
actually specifies; files retain package ntp and ntp.conf its config tag.
Complete executable bytes differ, so these contracts are not full code parity.

All four timediscipline probe schemas and site counts match Make in default and
OpenSSL-disabled executables. Each has five ordinary and nine is-enabled sites;
actual AMD64 function bounds, addresses and patched instruction bytes validate
in both native and Make files. Both retain the hidden static anchor. The
DTrace-disabled pair has no DOF section, no timediscipline schemas and no anchor.
This proves emitted metadata/sites, without loader registration or live firing.

bazel-ntpd-compile-audit-r2-20261101 audits all 195 actual successful program
compilations: 65 per profile, with the exact Make source set, source digests,
matching generated version bytes, PIE flags, three OpenSSL definitions and
WITH_COVERAGE_DTRACE selection. The native toolchain emits one PIE object group
with ordinary .o names, while Make uses .pieo names. Enabled runs check all 65
original object digests against actual DTrace rewrite inputs. Final source
records come from passed profiles, not the initial failed run.

## Retained failures and remaining gates

Initial native r1 rejected the missing libjsmn textual input; r2 declares the
real C/header and preserves the upstream include. Fresh Make installation also
corrected the new native directory metadata before qualification. An initial
supplementary audit used the wrong DOF JSON field; its output is retained in
the parity-r1 directory. The initial compile audit expected an unused second
PIC group; the corrected audit requires the actual 65-source PIE group Make
builds, every flag and every rewrite-input digest. Earlier evidence is retained.

Source review confirms --help/--version exit during command-line parsing before
daemon logging, priority changes, privilege checks, sockets or clock control.
The native test uses private empty HOME/current directory, explicit native
runtime libraries, the declared generated Version and asserts no created files.
It does not start the daemon. Upstream contrib/ntp tests outside the maintained
usr.sbin/ntp Make graph are not migrated or claimed by this component tranche.

The normal format-5 target/test lists and typed OpenSSL/DTrace settings already
express these inputs; no frontend C/backend API change is needed. The maintained
frontend and new tests were used; manual and observability log are updated.
NTP documentation/package aggregation, isolated live service/auth/refclock and
probe-firing tests, and efficient rebuild/performance qualification remain open.
Large exec-config OpenSSL rebuilds are retained observations, not a cache claim.
