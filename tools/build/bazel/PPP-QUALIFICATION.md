# Native PPP family qualification (2026-11-01)

## Source and configuration ownership

The checked-in native declarations own PPP's 51 maintained prefix C sources,
explicit feature sources and private headers, plus pppctl's unchanged C source.
They preserve actual WARNS=3/2, WERROR, PIC/PIE and dependency selections.
The default PPP profile compiles 57 C units; the global reduced profile compiles
53; all seven local PPP_NO_* exclusions compile 51. These lists are native
source metadata, with no production Make query, generated BUILD replacement,
prebuilt program substitution or host library fallback.

Existing typed settings select OPENSSL, INET6_SUPPORT and NETGRAPH. Added
`//tools/build/bazel/config:{pam_support,radius_support}` booleans default true.
PPP's `//usr.sbin/ppp:no_{nat,suid,kldload,des,radius,netgraph,pam}` booleans
represent the actual presence-only PPP_NO_* switches and default false. Local
exclusions combine with the corresponding global settings. These are build
inputs, not new runtime authorization APIs. Custom PPP_CONFDIR and
EXPERIMENTAL_NETGRAPH are not yet exposed/qualified; they remain explicit
configuration-completeness gates. Cross userland remains unqualified.

The normal maintained `build-bsd bazel-test --bazel-inputs <format-5.json>`
route builds `//usr.sbin/ppp:{ppp,install_archive}` and
`//usr.sbin/pppctl:{pppctl,install_archive,usage_test}`. Existing typed validation,
source receipt binding, archive verification and test reporting cover these
inputs; no frontend C, SDK, signing or publication changes are required.
Make remains production/default and BIP remains out of scope.

## Independent checks

Four fresh maintained Make reference builds pass: PPP default; NETGRAPH,
PAM_SUPPORT, RADIUS_SUPPORT, INET6_SUPPORT and OPENSSL disabled together; all
seven local exclusions; and pppctl default. The first local reference invocation
incorrectly supplied NAME=1 to the bare-name --make-define interface and was
rejected before building. It is retained; fresh r2 uses the supported API.
No variable gate or baseline binding was relaxed.

All three native five-target profiles and the pppctl usage test pass. Its
three unprivileged methods cover absent endpoint, unknown option and verbose
without endpoint, returning before sockets/remote commands. The unchanged
pppctl artifact is hash-identical across profiles; reused link provenance and
test results are retained instead of inventing new execution records. PPP
itself was not run on the host: its initialization and privileged/device paths
require the separate isolated runtime gate.

PPP's seven unique installation records per profile match Make, including the
identical repeated `/etc/ppp` directory entry. Default and global reduced modes
remain 04554 root:network; local no_suid mode is 0554 root:network. Debug files
remain root:network, the configuration stays 0600 root:wheel with config tags,
and `/etc/ppp` retains utilities directory ownership. pppctl's five records
match Make. All literal configuration/manual payloads match, and eight actual
installed debug-link/CRC checks pass (Make/native for three PPP and one pppctl
products). The mode metadata is archived, never applied to host programs.

Program ELF contracts, hardening, imports/exports and dependency order match
Make for all four independently reviewed products. pppctl differs only in
seven DWARF sections. PPP is deliberately not claimed byte-identical: its
sig.c __FILE__ diagnostic uses Bazel's stable relative `usr.sbin/ppp/sig.c`
versus Make's absolute source path. The nine-byte literal change changes
alignment and final runtime section offsets/payloads, alongside DWARF changes.
The precise original section bytes and all final differences are retained.
No absolute checkout path or source-prefix trick was added to the program.

A stronger object review compares all 162 actually linked C objects to their
Make equivalents across profiles: every runtime section and nondebug relocation
matches except that one diagnostic string section in sig.c in each PPP profile.
No object or ELF was rewritten for the comparison. Actual compile audits check
ordered warnings, feature definitions, ten required compile flags and 12,489
Make prerequisite hashes represented in declared native inputs. This is not a
syscall read trace or proof that every unused declared header was read. Each
copied object is bound both to its actual compiler output digest and actual
link input digest. Link parameters are captured immediately and hash-checked. Every original
Make object order matches the actual native link, including all three PPP
profiles and the unchanged cached pppctl bindings.

## Retained evidence

All paths below are under `/usr/obj/usr/src/`:

- `bazel-ppp-{default,reduced}-make-20261101/`,
  `bazel-ppp-local-make-r2-20261101/`, and
  `bazel-pppctl-default-make-20261101/`: independent receipts, source bindings,
  actual build commands, dependency files, METALOG and stages.
- `bazel-ppp-{default,reduced,local}-qualification-r1-20261101/`: passed native
  receipts, immutable artifact captures, original tests and complete logs.
- `bazel-ppp-{default,reduced,local}-link-r1-20261101.{json,jsonl}` and per-program
  params: receipt/log-bound actual or explicitly retained cached link evidence.
- `bazel-ppp-{default,reduced,local}-compile-audit-20261101/`: actual commands,
  flags/header hashes and preserved original linked objects. pppctl's unchanged
  compile is recorded once in the default capture.
- `bazel-ppp-{default,reduced,local}-object-section-audit-20261101.json`: all
  original object sections, including the three exact diagnostic differences.
- `bazel-ppp-{default,reduced,local}-install-audit-20261101/report.json`,
  `bazel-pppctl-default-install-audit-20261101/report.json`, and corresponding
  `*-elf-audit-20261101.json`: immutable ELF/install/debug comparisons.
- `bazel-ppp-link-order-audit-20261101.json`: all six source-object order
  comparisons, with actual parameter-file hashes.
- `bazel-ppp-*-20261101.py` retain independent audit implementations. The
  original default object-audit implementation is separately preserved after
  adding variant support. Native dependency-file copies are diagnostic only;
  their separate copy manifest does not establish execution-output binding.

All three disk guards exit zero without reserve interruption. Expanded JSON
logs are approximately 1.7/2.1/2.1 GiB and were read with the maintained streaming
parser, not loaded whole. The local progress reports show many [for tool] actions, but their total
execution/cache-hit count was not audited. One actual local OpenSSL exec C
compile is retained (processwrapper-sandbox, cacheHit=false, 0.150 seconds);
default evidence retains an actual BSDDTraceHeader action consuming the cached
bootstrap. Both use the same exec output root, and no actual default exec
compile for that chosen source exists in its log. Therefore configuration/root
propagation is not established as a cause. Raw records, tool/output bytes and
failed strict pair selectors are preserved in bazel-ppp-exec-observation* for a
future configured-action comparison. Compact official logging and execution
configuration/cache isolation remain full-system tooling gates, not a claim of
controlled performance or a diagnosed runtime regression.

## Remaining qualification

Exercise real installed PPP privilege transitions, configuration/secrets,
tun/tty devices, negotiation, NAT, IPv6, netgraph, PAM/radius, logging and
pppctl remote-command behavior in an isolated guest/network. Qualify individual
option interactions, custom configuration directory, experimental netgraph,
MANSPLITPKG, cross userland and final world/install/pkgbase aggregation. Full
boot/services and controlled CPU/memory/disk-I/O/cache measurements remain open.
No host PPP session, account, network, configuration, authentication service,
installation or tracing activation was changed by this work.
