# Native ctladm and iscsid component qualification

2026-11-01. Make remains production/default. Native amd64 rules_cc now own
ctladm's five C translation units and iscsid's three, with original sources,
private libiscsiutil PIE linkage, shared dependencies, manuals, debug files and
package ownership. No production C or original test body changed. ctld's C++
parser/service migration and real CTL/iSCSI session qualification remain open.

## Source, options and installation

ctladm uses the existing CAM package's three explicitly exported CTL sources;
no new package boundary hides existing headers or glob ownership. Its declared
WANT_ISCSI selection follows the existing typed iscsi setting. iscsid retains
ICL_KERNEL_PROXY and the existing seven-source private libiscsiutil PIE target.
Both ordinary and PIE private archives were independently checked. They remain
INTERNALLIB: the fresh Make component installs no public archive or header.

The normal format-5 build-bsd bazel-test route built programs, installation
archives and safe help tests. Existing typed setting support already carries
iscsi, so no frontend C, backend API or SDK change is needed. Installation
records preserve /usr/sbin, ctl/iscsi package tags, separate debug payloads and
compressed manuals. Original CTL port/Kyuafile payloads and tests package tags
are byte-identical to Make. This is installation metadata, not native package
creation, dependency closure or repository publication qualification.

## Reproducible evidence

All paths below are under /usr/obj/usr/src:

- bazel-ctl-qualification-r2-20261101: six build/install/archive targets and two
  safe help tests passed through the maintained frontend.
- bazel-ctl-noiscsi-qualification-r1-20261101: ctladm/program/archive/help targets
  passed with typed iscsi=false.
- bazel-ctladm[-noiscsi]-make-r1-20261101: fresh independent Make component and
  NO_ROOT installation references; the off variant uses WITHOUT_ISCSI.
- bazel-ctl-libiscsiutil-make-r1-20261101: fresh ordinary/PIE private archives.
- bazel-iscsid-fresh-library-make-r1-20261101: maintained Make reference with
  explicit LIBISCSIUTILDIR pointing to that fresh archive directory. The receipt
  retains full commands, resolved LIBISCSIUTIL/DPADD/LDADD, original LDFLAGS plus
  linker tracing, actual fresh archive member selection and before/after source
  and archive hashes. No permissive Make-variable production API was introduced.
- bazel-ctl-parity-r1-20261101: comparison commands/reports and compile-audit.json.
  Every native candidate is resolved from its completed receipt's immutable
  capture, verifying target/output selection, containment, size and payload SHA.

Three program ELF contracts and exact NEEDED order, two private archive symbol
contracts and original member order, 21 install records, all literal manual/test
payloads and six actual native/Make debuglink CRCs passed. Full ELF/archive bytes
differ; these are bounded contracts, not complete machine-code equivalence.
The actual compile audit covers 27 source/configuration combinations: 22 default
(five ctladm, three iscsid, seven ordinary plus seven PIE library) and five
ctladm ISCSI-disabled. Each source digest and successful action is checked,
including PIE flags, WANT_ISCSI and ICL_KERNEL_PROXY selection. Only Make's
.pieo versus Bazel .o archive member suffix is normalized for ordering.

The initial r1 frontend invocation rejected an input whose tests were not also
listed as selected targets; its failed build-runs log is retained. Corrected r2
inputs select them explicitly. No source/compiler failure was bypassed.

## Runtime and observability limits

The source-verified ctladm help command and iscsid unknown-option usage path exit
before device opening, module loading, pidfile or service work. Their native
Bazel tests assert expected exit/output and no files created in a private working
directory; three executions passed across the two configurations.

All eleven original CTL port cases remain declared and installed unchanged,
including require.user=root, require.progs=ctladm, five cfiscsi requirements,
service-state guard and cleanup bodies. They were not executed on the host.
A disposable guest with matching CTL/cfiscsi kernel support is still required;
these help tests do not establish storage sessions, port creation/removal,
service startup, failure recovery or cleanup correctness. No host CTL state,
clock, account, service or installation was modified.

A bounded scan of these programs' C/header sources found no direct DTrace/SDT
provider or explicit BSM audit submission. Review privileged command denials,
port mutations, daemon authentication/session lifecycle and failure visibility
with actual service callers. This scan does not establish transitive coverage.
Cross-architecture userland, runtime instrumentation and performance remain open.
