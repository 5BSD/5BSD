# Configured test compatibility qualification (2026-11-02)

The normal format-5 frontend expands the requested suites through configured
Bazel cquery and records each test's explicit compatibility. `test-inventory.json`
keeps compatible labels in `expanded` and excluded labels in `incompatible`.
Every active label must have exactly one PASSED summary and a valid captured XML
report; an excluded test is not a pass or an XML runtime skip. Unexpected executed
labels, duplicate inventory entries and an entirely incompatible request fail.

The BEP artifact snapshot accepts SKIPPED target completions only for that exact
configured exclusion set. It preserves their configuration identities, reasons
and descriptions in `incompatible_targets`, requires every exclusion to be
observed, and rejects unknown aborts, other reasons, duplicate exclusions or a
completed excluded target. Its default empty exclusion set remains strict.
Artifacts continue to require complete output groups and contained regular-file
captures. Existing artifact manifest format 1 gains the explicit exclusion list.

Evidence under `/usr/obj/usr/src/`:

- `bazel-source-test-compatibility-native-matrix-r2-20261102.json` records three
  normal frontend controls. Default passes 15 wrapper tests; disabling the
  fixture's conditional member passes 14 active wrappers and records one
  incompatible member. Those counts include two Python wrappers running 14
  inventory and 22 BEP unittest methods, plus 13 or 12 fixture tests. An
  all-incompatible request is rejected without a passed receipt.
- `bazel-source-test-compatibility-disabled-qualification-r1-20261102` preserves
  the earlier failed snapshot: 13 active wrappers passed, but the former snapshot
  assumed every targetCompleted event had a completed payload. The actual
  incompatible SKIPPED event exposed that error; this run is not qualified.
- `bazel-pam-family-kerberos-off-tests-qualification-r1-20261102` passes exactly
  13 active PAM safe wrappers. Original krb5 and ksu cases are explicitly
  incompatible; both actual SKIPPED target/configuration identities are retained.
  This is test-selection evidence, not independent complete Make parity for that
  additional package configuration or an installed authentication claim.

PAM uses a fixed suite and compatibility on actual tests; original case bodies
and requirements remain unchanged. This follows the documented Bazel platform
[compatibility and suite semantics](https://bazel.build/versions/9.2.0/extending/platforms).
The existing typed format-5 settings and build-bsd C entry point suffice. Backend,
BEP capture, regression tests and manual were updated together. No staging,
publication, signing, verified-boot or host authentication policy changed.
