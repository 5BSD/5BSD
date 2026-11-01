# Native NTP parse and event libraries

2026-11-01. Make remains the production backend. This tranche adds the two
remaining NTP private libraries, libparse and libntpevent, bringing the private
library candidates to four of four. Three of seven NTP programs have candidates;
ntpd, ntpdate, ntp-keygen, sntp, documentation and complete package aggregation
remain open. This is native amd64 archive qualification, without a runtime,
complete code-equivalence, cross-architecture or performance claim.

## Source and build ownership

libparse owns the 21 literal maintained Make sources in their original order.
libntpevent owns all 24 base translation units and the conditional 25th OpenSSL
unit, with the actual checked-in event2/event-config.h and adjacent private
headers. The maintained conditional arc4random.c textual fragment is declared
as an input rather than compiled separately. No generated BUILD files, Make
interpretation, host resource fallback or replacement configuration is used.

Both libraries declare ordinary and PIE source groups, preserving -fpie/-DPIC
on PIE objects and the shared NTP option defines. Supported rules_cc libraries
own compilation; the existing component archive rule consumes only the group's
own objects in source order. Dependency libraries retain ordinary extraction.
Both Make components are INTERNALLIB with package ntp; none of the four fresh
component.METALOG files contains an installed record. The native declarations
likewise do not install these archives. No production C or Makefile changed.

## Qualification evidence

All paths below are under /usr/obj/usr/src. The maintained build-bsd bazel-test
frontend built four archive targets with no test targets in each configuration:

- bazel-ntp-private-libraries-qualification-r1-20261101
- bazel-ntp-private-libraries-noopenssl-qualification-r1-20261101

The four fresh independent references are
bazel-ntp-{libparse,libntpevent}[-noopenssl]-make-r1-20261101. Their exact commands
and successful receipts are retained in
bazel-ntp-private-libraries-make-matrix-20261101. They use the maintained
install-reference helper, baseline SDK/profile checks, 16 compilation jobs,
NO_ROOT staging and explicit WITHOUT_OPENSSL for the disabled variant.

bazel-ntp-private-libraries-parity-20261101 contains the comparison commands,
eight passing reports and compile-audit.json. Every candidate is selected from
its completed receipt's immutable captured artifact manifest through the
maintained resolver, with label, output suffix, manifest and payload hash checks.
Archive member symbol contracts and member order match Make. PIE member names
use Bazel's .o spelling versus Make's .pieo; the ordered-name check accounts for
only that suffix difference. Complete archive bytes differ; no byte-parity claim
is made. The initial supplementary ordered-member assertion rejected that
spelling difference; the retained audit script explicitly models it.

Actual execution records cover 92 default and 90 OpenSSL-disabled compilations:
21 libparse and 25/24 libntpevent sources in each ordinary/PIE group. The audit
checks each source digest, successful status, PIE flags and presence/absence of
all three OpenSSL defines. Both source counts include the maintained platform
conditional translation units; none is omitted because it is empty here.

## Integration and remaining gates

The format-5 frontend already accepts these native labels and typed OpenSSL
setting, so no frontend C or backend API change is needed. The normal frontend,
source-owned target lists, SDK and capture mechanism are used. Make remains the
production/default backend and no package publication or host installation was
performed. No adjacent maintained test subdirectory is declared by either
component; consumer/runtime coverage remains pending the remaining NTP programs.
The bounded source scan found no component DTrace/SDT provider or explicit BSM
audit submission in these source trees. That does not establish transitive
observability. ntpd's maintained timediscipline provider, static anchor and
WITH_COVERAGE_DTRACE selection remain explicit requirements for its migration.
