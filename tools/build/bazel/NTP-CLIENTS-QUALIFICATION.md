# Native NTP control clients and AutoOpts

2026-11-01. Make remains the production backend. This tranche adds native
libopts, ntpdc and ntpq. Together with the earlier libntp/ntptime tranche,
three of seven NTP programs and two of four private libraries have candidates.
ntpd, ntpdate, ntp-keygen, sntp, libparse, libntpevent, documentation and complete
package aggregation remain open. No protocol, daemon or clock-control runtime
qualification is claimed.

## Maintained source and package contracts

The private AutoOpts library retains Make's single libopts.c translation unit,
its maintained textual C fragments (including nested compat sources), headers,
and ordinary/PIE variants. It does not compile the amalgamation's fragments as
independent translation units. The clients use three direct maintained C sources
plus each original generated version source. Their checked-in AutoOpts option
tables are the same sources Make consumes; no invented replacement generator or
production Make interpretation is used. The public ssl_applink.c fragment is an
explicit textual input in its actual include namespace.

Each program has its own version action with the previously qualified serial
and CSET settings. ntpdc retains /usr/sbin; ntpq retains /usr/bin. Package remains
ntp; private libraries are not installed. These component Makefiles have MAN
empty: NTP's documentation component, which owns the manuals, remains open.
Both programs select PIE private libraries. Edit, math, digest, optional crypto
and pthread edges/order follow the actual expanded Make link command, including
crypto before its pthread dependency.

## Build and comparison evidence

All evidence is under /usr/obj/usr/src. Fresh libopts references are
bazel-ntp-libopts[-noopenssl]-make-r1-20261101. Each client has separate
bazel-ntp{dc,q}[-noopenssl]-fresh-libraries-make-r1-20261101 directories.
The recorded command overrides LIBNTPDIR and LIBOPTSDIR with fresh independent
Make libraries. Both DPADD and actual LDADD are checked; linker --trace proves
member selection from both archives and rejects the old staged archives. All
original expanded LDFLAGS are retained. SDK/profile/compiler identity checks
remain intact, including for OpenSSL disabled. Compilation uses 16 jobs;
NO_ROOT staging does not install on the host.

The maintained frontend completes ten targets and two tests in each setting:
bazel-ntp-clients-qualification-r4-20261101 and
bazel-ntp-clients-noopenssl-qualification-r1-20261101. Both archive variants match
Make member/symbol contracts; each client's ELF identity, PIE/interpreter,
hardening, dynamic imports/exports/versions and exact NEEDED order match Make.
Across the two settings all 16 file/directory install records and eight actual
native/Make installed debug CRC checks pass. Executables and archives are not
byte-identical to Make; these contracts do not prove complete code equivalence.

Actual compile records cover all ten translation units per setting: one per
private object variant and four per program. Default successful records are
retained across r2/r3/r4 (some later actions are cached); the disabled run has
separate records. PIE flags and all three conditional OpenSSL defines are
checked. Program source, header, generator and Make input hashes were rechecked
after the concurrent HyperTrace merge; all recorded hashes still match.

The tests run each native --help and --version with private empty HOME/current
directory and explicit native shared libraries. They check real AutoOpts usage
output and the exact Version string read from the declared generated source,
without duplicating the upstream version constant. These options exit before
remote-host queries; normal initialization includes network/crypto readiness
probes. There are no host service, account or clock changes and no maintained
component test subdirectories in these three Make components.

## Evidence selection correction and regression protection

Initial comparisons used bazel-bin aliases. Those aliases point at shared outputs
and must not establish which configuration produced an artifact. All fourteen
old/new NTP archive/program comparison hashes were checked against the proper
receipt's captured manifest; no wrong-configuration result was found. Default
r7/r8 payload equality and default/custom version equality were independently
rechecked from those captures. Earlier reports remain intact.

All fourteen comparisons were then rerun through the maintained
elf-artifact-check.py --qualification/--target/--output-suffix interface. Current
reports and exact commands are in bazel-ntp-receipt-selected-parity-20261101.
Every result contains candidate_binding with receipt, manifest and payload
hashes. All six old/new program/configuration installation and debug comparisons
were also rerun from captured JSON/tar payloads in
bazel-{ntptime,ntpdc,ntpq}-{default,off}-captured-install-parity-20261101.
These are the authoritative artifact/install reports, including for the earlier
NTP tranche. The raw --candidate interface remains available for explicit object
or reference files and labels its result as unbound to a qualification.

qualification_artifacts.py rejects failed/incomplete receipts, changed manifests
or payloads, path/symlink escapes, duplicate target configurations and ambiguous
output selection. The comparison checks payload content again after inspection.
All twelve focused regressions pass through the normal frontend in
bazel-qualification-artifacts-test-20261101. This test is selectable through the
existing format-5 target/test lists; no frontend C API or SDK restage is needed.

## Retained failures and remaining review

Client r1 exposed the missing nested compat/pathfind.c textual source; r2 exposed
the public ssl_applink.c input. Both are now declared at their actual owners,
without source changes or stubs. r3 builds passed but the new help tests wrongly
expected literal '--' prefixes in the AutoOpts option table; the tests now check
the real table form and still execute/check both actual options. Failed logs and
the initial comparison-driver variable-shadowing failure remain retained.

No selected client/AutoOpts source declares a component provider or BSM hook.
Remote-control authentication/denial and network behavior require separate
runtime review. The remaining ntpd component does declare timediscipline_provider.d,
DTRACE_STATIC_ANCHOR and WITH_COVERAGE_DTRACE; its eventual migration must retain
those choices. Cross-userland, remaining family/package closure and controlled
performance remain open. The separate complete makefs fixture qualification does
not establish NTP daemon operation or normal Capsule startup.
