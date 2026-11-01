# Native OpenBSD tcpdump component qualification

2026-11-01. Make remains production/default. The maintained system uses the
OpenBSD tcpdump implementation plus 5BSD compatibility and privileged-operation
glue. The native amd64 candidate owns all 87 actual Make C sources, the original
PCAP/crypto dependencies, option selection, program/manual/debug installation
and meaningful offline packet tests. This is not live capture or complete-system
qualification.

## Source and physical header ownership

Literal rules_cc source declarations preserve the maintained source closure:
85 vendor tcpdump units, the actual sys/net/pf_osfp.c owner and local
privsep_5bsd.c. They include all IPv6 printer units in both configurations,
matching Make. The INET6_SUPPORT option selects the original INET6 define; the
vendor printers do not contain conditional compilation that removes IPv6 decode
when that define is absent. No source is omitted merely because it is unused
in a small fixture.

The original forced include order is lib/libpcap/config.h followed by the actual
5BSD tcpdump openbsd_compat.h. The unused legacy tcpdump/config.h is not substituted
for the maintained forced PCAP configuration. The existing source-only header
rule preserves physical wrapper locations and original include-root precedence;
relative wrapper referents are declared by their owning packages. Existing
exports are widened only for required consumers. The PF printer/state and userland OS-fingerprint helper
sources selected by Make remain in the vendor tcpdump owner; pf_osfp.c retains
its distinct kernel-source owner. No production source, wrapper, Makefile or
configuration constant was rewritten.

The program uses native pcap and crypto shared targets. Offline tests declare
pcap/crypto/thr runtime libraries and the same conditional OFED libraries as
native pcap; OFED was not disabled to avoid a dependency. Installation preserves
/usr/sbin/tcpdump, utilities package tags, separate debug symbols and the literal
compressed vendor manual. The maintained component declares no test subtree;
these new focused offline tests supplement build/install comparison.

## Independent and immutable evidence

All paths below are under /usr/obj/usr/src:

- bazel-tcpdump[-noinet6]-make-r1-20261101: fresh maintained Make components with
  unchanged SDK/profile checks, 16 compilation jobs and NO_ROOT staging. The
  disabled reference uses explicit WITHOUT_INET6_SUPPORT.
- bazel-tcpdump-qualification-r3-20261101 and
  bazel-tcpdump-noinet6-qualification-r2-20261101: final maintained build-bsd
  bazel-test receipts, selecting program, installation archive and offline test.
- bazel-tcpdump-parity-r2-20261101: final comparison commands/reports and
  compile-audit.json. Candidates come from the immutable capture resolver with
  receipt/target/output selection, containment, size and SHA checks.

Both program ELF contracts and exact NEEDED order match fresh Make. All ten
install records, both literal manual payloads and four actual native/Make
separate-debug CRCs pass. Full ELF bytes differ; this is not complete code or
ABI equivalence. Actual source records cover 174 compile combinations, all 87
units in each configuration. They check source SHA, success, PIE/C17 flags,
all six maintained defines, option selection and forced-header order. Every
original Make source/header prerequisite under /usr/src is present with the
same digest: 2,754 checks across those actions. SDK/header snapshot verification
remains separate from these source-tree checks.

## Actual packet tests and retained failure

Each selected offline Python test runs five unittest methods: numeric IPv4/IPv6
UDP decode, real BPF filter exclusion, truncated Ethernet handling and malformed
PCAP rejection. Every command uses -r with a private capture and numeric output;
no live capture interface is opened. Input bytes remain unchanged and no extra
working-directory files are accepted. Each profile's retained test log reports
five passing methods; the Bazel receipt reports one test target, with normal
cache reuse allowed. No host network, service, capture or installation state is
changed.

Initial default r1/r2 and disabled r1 builds/offline tests passed, but a deeper
Make-header audit rejected two source wrappers missing from seven native actions
each: user/sys/refcnt.h and user/sys/timeout.h. The native include context had
resolved SDK variants instead. The retained failure is
bazel-tcpdump-parity-r1-20261101/make-header-audit-failure.json, with the original
failed audit script and comparisons. A physical source header provider now
matches Make's actual include root; both full profiles and all header checks
were rerun successfully. The failure was not suppressed or counted as qualified.

## Integration and remaining gates

Existing typed inet6_support and normal format-5 target/test inputs suffice;
no frontend C, backend API, SDK or source-graph helper change was needed. The
manual and native declaration metadata stay with this tranche. Native package
creation/dependencies/publication, complete world/kernel and cross userland
remain unqualified.

Live BPF capture, interface/direction/drop controls, PF log/state decoding,
OS-fingerprint lookup, ESP decryption, all protocol/corrupt-input combinations,
concurrency and performance need further qualification. Existing 5BSD glue
implements privileged operations directly and does not start the upstream
OpenBSD privileged subprocess; this migration preserves that behavior rather
than establishing a new privilege-separation design. The bounded compiled-source
scan found no direct DTrace/SDT provider or explicit BSM submission. Review live
capture authorization, privileged failures, drop/error reporting and actual
callers for observability; the offline tests do not prove those properties.
