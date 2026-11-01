# Native ntpdate, ntp-keygen and sntp

2026-11-01. Make remains the production backend. Six of seven NTP programs and
all four private libraries now have native candidates. ntpd, documentation and
complete package aggregation remain open. This tranche qualifies native amd64
build/install contracts and option exits, without NTP protocol, key-generation,
clock-control, cross-architecture or performance qualification.

## Maintained build and version contracts

ntpdate uses its original C source and its own original mkver action.
ntp-keygen uses its two maintained C sources; sntp uses all eight maintained C
sources and the private event library. Source/header owners and supported
rules_cc targets declare the graph. The maintained Makefiles do not generate
per-program version.c for ntp-keygen or sntp: both obtain Version from libntp's
ntpd version object. Native declarations and tests preserve that ownership;
no invented version constants or extra version generator changes it.

All three retain PIE objects, shared NTP option definitions, optional OpenSSL,
/usr/sbin installation and package ntp. Each component's MAN is empty; the
separate documentation component remains open. The native package archives
retain four file/directory records per program, including separate debug files.
No production C or maintained Makefile changed.

The original sntp declaration listed md before ntp, whose transitive math edge
then placed libm after libmd. Symbols and other ELF contracts passed, but the
supplementary exact NEEDED-order assertion rejected both configurations. The
corrected declaration lists private archive dependencies before shared math and
digest roots, allowing supported rules_cc dependency ordering to retain Make's
m-before-md order. It introduces no custom link command or raw-link fallback.
Original reports, the hash-verified original link parameters and order-gap.json
remain in bazel-ntp-remaining-clients-parity-20261101 under /usr/obj/usr/src.

## Build, install and runtime evidence

All evidence below is under /usr/obj/usr/src. The final maintained build-bsd
bazel-test runs each complete nine targets and three tests:

- bazel-ntp-remaining-clients-qualification-r3-20261101
- bazel-ntp-remaining-clients-noopenssl-qualification-r2-20261101

Fresh references are bazel-{ntpdate,ntp-keygen,sntp}[-noopenssl]-fresh-libraries-
make-r1-20261101. Each records its full script/commands, original Make
LDFLAGS and baseline SDK/profile checks. Documented LIBNTPDIR, LIBOPTSDIR and
LIBNTPEVENTDIR overrides select fresh independently built private archives as
needed. Both DPADD and LDADD are checked, linker --trace proves their actual
member selection, and staged old private archives are rejected. Compilation
uses 16 jobs; NO_ROOT staging performs no host installation.

bazel-ntp-remaining-clients-parity-r2-20261101 contains six passing immutable
capture-selected ELF comparisons, six install comparisons and compile-audit.json.
Each candidate is bound to its completed receipt's artifact manifest, target,
output suffix and hashes. PIE/interpreter, hardening, dynamic imports/exports
and versions, exact NEEDED order, 24 install records and twelve actual native
and Make debuglink CRC checks pass. Full executable bytes differ, so these
contracts do not establish complete code equivalence.

Actual retained execution records establish all twelve program compilations
per setting (two ntpdate, two ntp-keygen, eight sntp), their successful status,
source digests, PIE flags and all three OpenSSL define selections. Successful
earlier records are retained for cached actions; later records take precedence
in the audit. This is not a claim that every action reruns on every invocation.

The native tests use private empty HOME/working directories and explicit native
runtime libraries. ntpdate's missing arguments exit 2 with usage before server
queries or clock changes. ntp-keygen and sntp --help/--version exit successfully,
with the exact Version derived from the declared libntp generated source. The
tests assert no files were created. Normal initialization can read time, probe
network availability or initialize randomness; key generation, server queries
and clock changes are not exercised. No adjacent maintained test subdirectories
are declared by these three Make components. Protocol/authentication, actual
key generation and daemon behavior remain runtime gates.

## Frontend and observability review

The normal format-5 target/test lists and typed OpenSSL setting already express
this scope, so frontend C/backend APIs need no change. The tests run through
build-bsd; Make remains production/default, with no publication or host install.
The bounded selected-source scan found no direct DTrace/SDT provider or explicit
BSM submission in these clients. Transitive instrumentation is not qualified.
ntpd's timediscipline provider, static anchor and WITH_COVERAGE_DTRACE remain
requirements for the daemon migration.

Large exec-config OpenSSL closures rebuilt during several profile runs; logs
are retained. Cache/action-key behavior needs separate investigation before
claiming efficient rebuilds. No cache or controlled performance qualification
is inferred from these successful component builds.
