# Heimdal roken platform-header generator

## Implementation

The source-owned make-roken target retains the original two-stage generation:
native AWK processes the original roken.awk and roken.h.in, then the configured
C compiler builds that output with the maintained kerberos5/include/config.h.
A declared execution-platform action runs the executable through the SDK stdout
redirect tool to generate roken.h. No Make-produced header or precomputed header
contents enter the native graph. Source/header visibility is limited to the
consuming package or kerberos5 subtree. The initial target supports AMD64;
foreign target platform header generation has not been qualified.

## Evidence (2026-11-04)

Under /usr/obj/usr/src:

- bazel-make-roken-native-r1-20261104/receipt.json: maintained format-5
  build-bsd bazel-test, 16 jobs; selected generator executable/header and
  source_settings_test pass. That test does not establish consumer correctness.
- bazel-make-roken-make-r1-20261104/receipt.json: fresh original Make build and
  private installation reference, using original recipes and Make metadata.
- bazel-make-roken-native-r1-20261104/original-header-review/review.json:
  the original Make-built executable exits successfully without stderr; its
  output matches all 7,027 bytes of the hash-verified native captured header.
  Original executable hashes before/after execution match; the original header
  and native receipt/manifest binding are retained.

The frontend's existing explicit target selection supports this generator without
C/backend/schema changes. Its manual describes this bounded qualification.
No new publication, staging policy or installed package selection is introduced.

## Remaining work

Convert and qualify libroken, libvers and compile_et consumers and their
installation metadata. Preserve explicit rejection of unfinished Heimdal world
profiles. Whole generator executable/debug parity, foreign-platform generation,
full bootstrap independence, installed system tests and performance remain open.
Make remains the default and BIP remains excluded.
