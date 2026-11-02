# Native PAM family qualification (2026-11-02)

`//lib/libpam:all_products`, `:installation_archives` and `:safe_tests` compose
shared libpam, selected shared/static modules, policies, the combined static
archive, and the original test programs. The module selector follows maintained
modules.inc order; old static selection entry points delegate to this common
source-owned selector. Parent Make metadata records no MAKE_ENV, SUBDIR_ENV or
exported-variable delta for this family. The root retains Make SUBDIR order.

Installation uses the existing archive-set provider, retaining each component's
separate directory/package context. It is not a flattened archive or final
pkgbase package producer. Default has five root components and 24 modules;
reduced has four root components and 20 modules. TESTS selects program/install
products; actual safe tests carry compatibility requirements inside a fixed
suite. KERBEROS-disabled krb5/ksu wrappers are explicit exclusions, not passes.

The older shared-core declaration omitted Make's PIC macro and warning policy.
Its 54 PIC compiles now use the original policy, without a shared toolchain
change. The shared archive also now records Make's two debug directories
`/usr/lib/debug/usr` and `/usr/lib/debug/usr/lib`, root:wheel 0755, package=pam,dbg.
Original C, PAM modules, test assertions, provider schemas and requirements are
unchanged. Existing typed format-5 settings suffice; no frontend C, backend,
SDK, staging, signing or publication interface change is required here.
Configured-exclusion handling is qualified separately in
[CONFIGURED-TEST-COMPATIBILITY-QUALIFICATION.md](CONFIGURED-TEST-COMPATIBILITY-QUALIFICATION.md).

## Final evidence

All paths below are under `/usr/obj/usr/src/`. Native jobs used 16 CPUs and the
18 GiB initial / 16 GiB reserve guard; no disk stop occurred.

- `bazel-pam-family-final-native-matrix-r1-20261102.json` records two passing
  normal frontend profiles. Default captures 73 product files, 28 component
  archive sets (84 output bindings), and 15 passing safe wrappers. Reduced
  disables DTRACE, TESTS, KERBEROS, OPENSSH, RADIUS_SUPPORT, AT and FTP; it captures
  55 products and 23 component archive sets (69 bindings), with no tests requested.
  Results may use Bazel's retained local test/action cache; these counts are not
  claims that every final action executed again.
- `bazel-pam-family-final-make-matrix-r1-20261102.json` records two fresh original
  shared-library Make references under the final source binding, using supported
  metadata mode and explicit reduced options. The final compiler binding audit
  verifies 108 retained actual native compiler records against these recipes,
  including exact ordered warnings, definitions, PIC, optimization, language,
  stack protection and 3,756 consumed input hashes (1,880 default / 1,876 reduced).
  Raw compiler outputs and traced private-copy outputs were independently bound
  to actual action digests before preservation. See
  `bazel-pam-family-final-compiler-binding-r1-20261102/report.json`.
- `bazel-pam-family-shared-final-{default,reduced}-elf-audit-r1-20261102` passes
  the maintained strict shared ELF contract, including ordered NEEDED. Every ELF
  section matches fresh Make except `.SUNW_dof` plus `.gnu_debuglink` in default,
  and `.gnu_debuglink` alone in reduced. Thus text, relocations and other runtime
  sections are byte-identical; debug CRCs are checked separately.
- `bazel-pam-family-shared-dof-audit-r3-20261102/report.json` resolves all DOF
  sections and independently checks the exact dt_link.c FNV hash_obj derivations
  for native relative and Make absolute object paths. Only those alias strings
  and resulting string-table indices, length and load boundary differ. All other
  section values, including provenance, match. Provider attributes, four probe
  records, actual linked addresses, six ordinary sites and six enabled sites
  match. This does not establish loader registration, live delivery or load bias.
- `bazel-pam-family-shared-install-audit-r2-20261102/report.json` proves 65 unique
  Make installation records in each configuration: modes, owners/groups, package
  tags, directories and links. Sixty ordinary file payloads per profile are exact
  (headers/manuals including the hardlink alias); both native and Make debug-link
  CRCs validate, four checks total. Library/debug payload differences are covered
  by the separate ELF/DOF evidence above.
- `bazel-pam-family-composition-audit-r3-20261102/report.json` resolves every
  selected output through its immutable receipt-bound artifact manifest. It
  reproduces 146 default and 120 reduced output bindings from earlier qualified
  static/module/policy/test captures, preserving component metadata and payloads.
  The new shared component is qualified separately as above. Default's seven full
  test executable outputs have identical installed test-archive counterparts;
  their original program/compiler proof is in PAM-TESTS-QUALIFICATION.md.
- `bazel-pam-family-kerberos-off-tests-qualification-r1-20261102` passes 13 active
  safe wrappers and retains the exact two configured/BEP exclusions. This is a
  test-selection control, not complete Make package parity for a third profile.
  Default original runtime cases and static registry checks retain constructor-time
  DOF initialization opt-out; no host tracing or authentication configuration changed.
- `bazel-pam-family-make-inventory-r1-20261102/report.json` retains configured
  parent/leaf metadata and ordering. It is metadata evidence, not compilation.

## Retained failures and limits

The first suite declaration used select in nonconfigurable test_suite.tests and
was rejected. Fixed suite membership plus compatibility on actual tests replaces
it. The earlier frontend BEP snapshot failed on a genuine incompatible SKIPPED
event; that separate helper fix preserves the failure and has negative controls.

The initial reduced family kept DTRACE enabled while the previous reduced static
reference disabled it. Its build passed, but the composition comparison correctly
failed; that profile is not the final reduced parity baseline. Matching trace-off
inputs and a fresh Make reference replace it. Earlier source receipts were also
rejected after the shared directory declaration changed their tracked BUILD hash;
both references were rebuilt, not silently rebound. Observer failures for lexical
sysroot paths, actual provider header spelling and raw DOF load length are retained.
The final checks above resolve these exact causes without changing artifacts or
weakening production comparators.

Ten original execution cases remain guest gates: nine installed-path policy cases
and one root lastlog/session accounting case with five child chroots. The family
suite does not pretend these cases passed. Final package construction, aggregate
world selection, cross architecture userland, installed authentication, live
tracing/audit delivery, bootstrap independence and controlled performance remain
open. Make remains production/default; no host installation or reboot occurred.
