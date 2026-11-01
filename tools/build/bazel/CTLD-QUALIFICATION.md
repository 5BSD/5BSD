# Native CTL daemon component qualification

2026-11-01. Make remains production/default. ctld now has a source-owned native
amd64 candidate for all ten C++ units and two generated C units, installation
and one safe usage test. This completes declarations for the ctladm/iscsid/ctld
program family, not working storage-service qualification.

## Source and generator ownership

The maintained parse.y and token.l feed native yacc and lex execution tools.
The existing declared generator rules preserve y.tab.c, y.tab.h, y.output and
token.c. A standard skylib copy_file produces parse.c from y.tab.c, matching the
maintained Make source filename without replacing parser contents or importing
a prebuilt generated file. Source/header and verbose report outputs are declared.

Nine ordinary C++ program units, uclparse.cc and the two C parser/lexer units
have separate rules_cc groups. Only C++ receives GNU C++17 and the declared
libc++ header context. Only uclparse.cc receives the maintained -Wno-shadow and
-Wno-cast-qual exceptions. Program groups use native alwayslink to retain all
program translation units; dependencies keep ordinary archive extraction.
The original source list order is represented as nine C++ units, parser/lexer,
then uclparse. No production source, generator, parser grammar, lexer or Makefile
was changed. The default deliberately does not define ICL_KERNEL_PROXY, matching
ctld's commented-out Make definition rather than iscsid's different selection.

A narrow libucl C++ facade header provider declares original ucl++.h and its
existing C/libc++ headers. Existing CAM, iSCSI, private iscsiutil/nvmf/util++ and
shared library providers supply the other actual dependencies. Package ctl
keeps /usr/sbin/ctld, separate debug symbols and ctld.8/ctl.conf.5 compressed
manuals. No /etc configuration payload was invented; this Make component does
not install one. A split-manpages selection uses the existing ctl-man policy.

## Independent Make and captured native evidence

All paths below are under /usr/obj/usr/src:

- bazel-ctld-libnvmf-make-r1-20261101 and
  bazel-ctld-libutilpp-make-r1-20261101 are fresh maintained Make references.
- bazel-ctl-libiscsiutil-make-r1-20261101 is the fresh independently built
  private-library reference from the preceding CTL tranche.
- bazel-ctld-fresh-libraries-make-r1-20261101 uses maintained Make with explicitly
  documented LIBISCSIUTILDIR, LIBNVMFDIR and LIBUTIL++DIR assignments. Exact
  commands, resolved archive/DPADD/LDADD values, original LDFLAGS plus --trace,
  actual selected fresh archive members and before/after source/archive hashes
  are retained. No permissive production reference-helper variable API was added.
- bazel-ctld-qualification-r1-20261101 passed the maintained build-bsd bazel-test
  route with nine selected targets, including one safe usage test. Parser/lexer and ordinary/PIE
  nvmf/util++ archives are included in the selected captured outputs.
- bazel-ctld-parity-r1-20261101 retains comparison commands, reports and
  compile-generation-audit.json. Every candidate uses the maintained immutable
  capture resolver with receipt, target/output, containment, size and SHA checks.

The program ELF contract and exact NEEDED order match the fresh Make program.
Four private archive symbol/member-order contracts, six program installation
records, two literal manual payloads and both actual debuglink CRCs pass. Complete
ELF/archive bytes differ: no full machine-code equivalence is claimed. Only the
.pieo versus .o archive member suffix is normalized in the member-order check.
The nvmf private Make component installs nothing; util++ has its own maintained
manuals/tests, whose complete installation/runtime is not newly qualified here.

Actual records cover 26 compilations: all twelve program units, six nvmf units
in each ordinary/PIE configuration, and one util++ unit in each configuration.
The audit checks every source hash and successful status, generated C hashes
against captured yacc/lex outputs, C versus C++ language flags, PIE flags,
uclparse-only warning exceptions, CRC-source exception and proxy define absence.
Two real generator actions are source-hash-bound. y.tab.h and y.output are
literal Make matches. Generated parser/lexer C matches after normalization of
only an explicit set of #line filename aliases; line numbers and all other
content remain exact. Raw hashes and the limited normalization are retained.

## Frontend and runtime boundaries

Existing normal format-5 inputs express these native targets. No frontend C,
backend API, SDK, source-graph helper or build policy change is required. Make
remains the default system backend. This does not qualify native package
creation, dependency closure, binary repository publication or cross userland.

The help test supplies an unknown -h option and asserts exit 1, expected usage,
empty stdout and no private working-directory files. Source inspection verifies
this exits before log_init and kernel_init. In contrast, ctld -t invokes
kernel_init before parsing configuration; it is not a host-safe parser test.
Real configuration parsing, UCL/legacy syntax, reload, authentication, service
startup/shutdown, iSCSI/NVMe sessions, error recovery and the eleven original
CTL root cases require an isolated guest with matching kernel support. No host
CTL, device, service, account, mount or installation operation was performed.

A bounded scan found no direct DTrace/SDT provider or explicit BSM submission in
these CTL daemon sources. Review privileged configuration/port changes,
authentication and session lifecycle/failure visibility against actual callers;
this is not proof of transitive observability or a reason to add cosmetic probes.
Runtime instrumentation and performance remain unqualified.
