# Native DWATCH script/profile qualification (2026-11-02)

The configured world selects this previously undeclared family under
`cddl/usr.sbin/dwatch`. Native targets now install the unchanged executable
script at `/usr/sbin/dwatch`, its compressed manual, 28 profiles and 99 hardlink
aliases under `/usr/libexec/dwatch`, and the EXAMPLES-controlled template.
Source payloads are literal inputs; Make performs no script transformation.
Existing native installation/compression/archive rules produce the artifacts;
there is no production Make parsing, source rewrite or new execution wrapper.

`//cddl/usr.sbin/dwatch:installation_archives` preserves the root/libexec/examples
component contexts and original SUBDIR order. `:all_products` includes 31 files
with EXAMPLES or 30 without it. Direct component targets remain available,
matching direct Make leaf builds; the enclosing world must honor the original
DTRACE/architecture parent selection. Fifteen actual parent/leaf Make queries
confirm default/EXAMPLES-off/DTRACE-off selection and no ancestor exported,
MAKE_ENV or SUBDIR_ENV delta. This is scoped component selection evidence, not a
replacement for full world aggregation.

## Final evidence

All evidence is under `/usr/obj/usr/src/`:

- `bazel-dwatch-reference-native-matrix-r5-20261102.json` records fresh original
  Make staging and normal build-bsd native qualification for default and
  EXAMPLES-off, using 16 CPUs with the 18 GiB initial / 16 GiB reserve guard.
  `bazel-posthypertrace-sdk-20261102/toolchain-inputs.json` SHA256 is
  `f5efce0dacfcde4956fbe77dff91329dc6be969b290c22dc5960259828745346`.
  No guard stop occurred. The maintained format-5 typed settings/target/test API
  suffices; frontend C/backend/stager/manual/security APIs need no extension.
- `bazel-dwatch-install-audit-r1-20261102/report.json` resolves every capture
  through its immutable receipt-bound manifest. Default has three component
  archive sets and 133 unique installation records; EXAMPLES-off has two sets and
  131 records. All 259 installed-path payload comparisons are byte-identical to
  Make, including compressed manual, original script and profiles. Owners,
  groups, modes, tags and explicit directories match; the script is 0555,
  profiles/template/manual 0444 and directories root:wheel 0755. All 99 native TAR
  hardlink entries per configuration match actual Make source/alias inode pairs,
  preserving shared inode metadata rather than materializing unrelated copies.
- `:syntax_test` adds one opt-in syntax-only ATF case; the original Make family
  declares no tests. It invokes the declared native `//bin/sh:sh` through the
  explicit SDK loader with `-n` on all 30 original shell/profile/template inputs.
  No script or profile body is evaluated. It does not call DTrace, sudo or mdo.
- `bazel-dwatch-action-audit-r2-20261102/report.json` streams both compact logs
  through the original upstream converter with all 189 tool bindings checked
  before/after. Default has one actual uncached processwrapper test action:
  constructor-time DOF initialization opt-out, all 32 configuration input hashes
  (native shell, SDK loader, 30 source inputs), 30 logged parser commands, and
  captured XML hash pass. EXAMPLES-off explicitly reports cachedLocally=true;
  its XML and log are byte-identical to that actual result. It is not a second
  observed invocation. Final build actions also reuse ordinary local outputs;
  this is not a persistent-cache or performance qualification.
- `bazel-dwatch-make-discovery-r1-20261102/report.json` retains all fifteen
  metadata controls. `bazel-userland-world-posthypertrace-inventory-r1-20261102`
  refreshes world recursion to 2,128 directories (previous 2,127), adding exactly
  `sbin/mount_virtiofs`, with no diagnostics. These are selection metadata counts,
  not native compilation coverage.

## Retained failures and remaining gates

Earlier attempts retain an invalid SDK loader label, a missing declared native
ATF shell runtime and an incorrect shell ATF configuration getter. Only the new
syntax-test declaration/body was corrected; production payloads stayed unchanged.
Attempt r3 was rejected before Bazel because an external committed merge changed
`sys/cap_authority.h`, reached through a recorded SDK input symlink. The old
receipt was not rebound. The complete old SDK/config audit checks 16,812 hashes,
with exactly that header and AMD64 GENERIC changed; immutable SDK snapshot bytes
and host dependencies remain unchanged. The parent prepared the fresh SDK above.
The first action observer also rejected its assumption of a fresh EXAMPLES-off
test execution; explicit cached result/output binding replaces that assumption.

All original DTrace code, pragmas, provider/probe patterns and shell behavior are
preserved byte-for-byte. Syntax/install checks do not qualify kernel probe
availability, D compilation, privilege escalation, live event delivery, profile
functionality or authentication. No host tracing activation, service/configuration
change, installation, kernel upgrade or reboot occurred. Normal installed-path
tracing, cross userland execution, full inherited world selection, final pkgbase
construction, bootstrap independence and controlled performance remain open.
Make remains production/default.
