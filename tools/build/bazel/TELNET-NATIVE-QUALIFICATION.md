# Native Telnet and shared baud command correction (2026-11-04)

The AMD64 Telnet consumer now declares the original source/manual and private
headers, the <libtelnet/...> interface, native PIE libtelnet, terminfo and IPsec.
OpenSSL adds authenc, mp/crypto/PAM and the original authentication/encryption
definitions. INET6 follows its maintained option. The default MIT configuration
preserves Make's omission of the separate Heimdal Telnet code; the existing
libtelnet guard still rejects that unfinished non-MIT dependency graph.
TELNET selects its production archive; disabled TELNET excludes the contribution
and makes the program incompatible. The remaining root optional guard now names
the unfinished Heimdal compile_et profile directly, without obsolete scaffolding.
No source is replaced by a fixture and no requested unsupported path is omitted.

## Actual source defect and correction

The first native compile exposed an existing baud routine's undefined
COMPORT_SET_BAUDRATE identifier; neither current source nor SDK headers define
it. Review also found a trailing NUL queued as protocol data, an argument-end
pointer passed to the trace routine, missing IAC data escaping and integer
truncation before speed validation. These are shared source defects, not reasons
to inject a build-only definition or select an older SDK implementation.

The production comport.c/h codec owns the RFC command value, writes four baud
octets in network order, doubles IAC data bytes and returns the actual bounded
frame length without a NUL. Its caller checks range before conversion, preserves
accepted leading '+' and whitespace numeric forms, keeps the existing positive
terminal-speed table, checks ring capacity and traces the actual frame. Both
Make SRCS and native source declarations include the same new implementation.
The encoder supports the full uint32 wire value; the CLI does not newly expose
the RFC's zero-rate query or claim complete negotiation support.

Protocol references: [RFC 2217](https://www.rfc-editor.org/rfc/rfc2217.html),
section 2 and command registry; [RFC 854](https://www.rfc-editor.org/rfc/rfc854.html),
Telnet command structure and IAC data escaping. The numeric command/option values
are protocol constants; the selected baud rate and capacity remain inputs.

The native C regression calls the production codec with five independent wire
vectors, including zero, 9600, escaped data bytes and UINT32_MAX. Every insufficient
capacity must leave canaries/data untouched; exact capacities must produce exact
frames and preserve surrounding bytes. Real CLI tests check usage before any
connection, reject a value that previously wrapped to 9600, and accept existing
signed/whitespace numeric syntax. The CLI cases stop before connection dispatch and do not change a
user account. No test-only production branch or packet normalization is used.

## Final evidence under /usr/obj/usr/src

- bazel-telnet-final-default-native-r1-20261104 and
  bazel-telnet-final-plain-native-r1-20261104: normal sixteen-job build-bsd format-5
  passes each profile's five tests. The three CLI tests execute; codec and source
  settings reuse cached results. The earlier codec execution is retained in
  bazel-telnet-native-r2-20261104. The plain profile explicitly disables OpenSSL,
  Kerberos support, MIT and IPv6. Default retains OpenSSL/IPv6 and MIT selection.
- bazel-telnet-library-make-r1-20261104 and
  bazel-telnet-plain-library-make-r2-20261104: independent original internal
  libraries pass. A forced WITH_MITKRB5 with WITHOUT_OPENSSL was rejected before
  building because Make disables the effective option; it was not called passing.
- bazel-telnet-final-default-make-r1-20261104 and
  bazel-telnet-final-plain-make-r1-20261104: fresh original consumer builds/stages
  pass with explicitly bound original internal PIE archives, matching target
  and compiler identity. The final shared-source inventory is frozen/rechecked
  in bazel-telnet-final-original-inputs-r1-20261104.
- bazel-telnet-final-{default,plain}-object-review-r1-20261104: all nineteen
  consumer contexts are reconciled; seventeen raw allocated/relocation/symbol
  contracts match. Each commands.c assertion filename differs with the source
  root. bazel-telnet-final-filename-controls-r1-20261104 reruns those two original
  compiler recipes with explicit source-root macro-prefix policy and private
  outputs; both contracts match. No output bytes are edited or normalized.
- bazel-telnet-library-object-review-r1-20261104: all eleven internal-library
  contexts (eight default, three plain) match raw original contracts and member
  order. Immutable default materialization in
  bazel-telnet-archive-capture-native-r1-20261104 matches its earlier actual link
  input hash; a cached final archive need not materialize an unrequested .a.
- bazel-telnet-final-stage-review-r1-20261104: both profiles match all three files
  and two explicit directories, types/modes/owners/flags/tags, exact manual bytes,
  independent debug CRCs and ordered direct runtime-library dependencies.
- Final capture roots retain current compiler records with their actual cache
  status and explicitly reused older witnesses where necessary. Every copied
  raw object matches the passing current link input hash. A failed default
  capture-count assumption left the copied objects intact; the corrected report
  reads those frozen copies, not another profile's mutable output tree.
- bazel-usrbin-converted-optionals-final-native-r1-20261104: the complete current
  production parent passes with NIS/Hesiod/Sendmail/Telnet enabled, 273 archives
  and five cached selected test results. Its final review verifies all 813
  preceding NIS/Hesiod products unchanged and adds only vacation/Telnet. All
  member paths are canonical and there are no duplicate non-directory paths or
  file/directory conflicts. Aggregate Telnet products exactly match the separately
  compared component. Relative to the preliminary 273-archive profile, the final
  parser refinement changes only Telnet's tar; all other 818 products are exact.

The configured checks in bazel-telnet-final-gates-r1-20261104 separately verify
that direct Telnet with the unfinished Heimdal graph, the root Heimdal profile,
and the incomplete full installed-tests parent remain explicitly incompatible.
These queries execute no compilation or runtime and do not qualify those paths.

## Remaining scope and integration

This is a production-family/component result, not complete installed tests or
world/pkgbase qualification. Whole linked/debug byte equality, debugger source
lookup, live TCP/terminal/serial negotiation, PAM/authentication/encryption,
other architectures and further feature combinations remain unqualified.
The new native codec regression is not a claim about installed Make test coverage.
Full bootstrap, hardware/publication, mutation/cache/sandbox, VM/service runtime
and comparative CPU/memory/disk gates remain. Make stays default; BIP excluded.

The maintained generic build-bsd dispatcher/backend carries existing typed
settings and targets unchanged. Make's normal source list, native declarations,
tests, manual, roadmap and observability ledger are updated in the same change.
No production signing/publication policy, SDK substitution, host installation,
module loading, upgrade, reboot or VM operation is performed.
