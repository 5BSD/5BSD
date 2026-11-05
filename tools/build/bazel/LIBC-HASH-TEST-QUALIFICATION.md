# Native hash tests and requested-selector validation (2026-11-05)

## Original hash contribution

The original h_hash helper, OpenSSL-controlled sha2_test, hash_test shell program
and all five original fixtures now build/install through native declarations.
Sources are unchanged. The disabled original hmac program remains disabled.
Header-only SHA1 spelling compatibility belongs to h_hash without adding unused
libnetbsd code; sha2_test retains the original NetBSD compatibility surface.
ABI imports and the final-consumer sequence preserve ATF, md, crypto, libc order,
including original Make's unreferenced libcrypto NEEDED entry. No runtime-path
injection, host digest helper or manually substituted test vector is used.

The original shell MD5/SHA1 cases run with declared native sh/ATF/dirname/jot and
native C/C++/MD runtimes. SHA1 includes the original million-byte input scenario.
The three original SHA256/384/512 cases preserve their original vector/alignment
checks. SHA2's installation, Kyua registration and compatible runtime availability
follow the maintained OpenSSL/crypt setting. Fixed native test_suite membership
allows Bazel to record disabled SHA2 tests as incompatible; no configurable suite
alias is used to conceal unexpanded tests.

## Qualification runner correction

Review found a real acceptance gap: tests(set(requested selectors)) can omit a
suite alias while still returning another valid requested test. The old runner
accepted the combined nonempty inventory, so a source-settings pass hid the missing
hash suite. That diagnostic is retained and explicitly not hash runtime evidence.

The maintained source_graph backend now validates every requested selector.
A direct test already present in the combined inventory needs no extra query.
Suites, aliases and patterns receive their own configured expansion; each must
contain a compatible test and stay within the combined compatible/incompatible
inventory. Empty/non-test selectors, unexpanded suite aliases and entirely
incompatible selectors fail even when another test passes. Mixed compatible and
incompatible suite membership remains supported. Existing host-artifact-only
execution restrictions remain in force. Per-selector results and query hashes
are bound by test-inventory.json and its receipt hash.

There is one additional configured query per indirect selector, not per direct
test case. Query commands/timings remain recorded. This fixes acceptance criteria;
it does not change compiler caching, linker behavior or installed system software.

## Evidence

All directories below are under /usr/obj/usr/src:

- bazel-libc-hash-native-r3-20261105: all five original hash cases freshly pass,
  plus source-settings and source-test-inventory targets. The latter executes
  twenty-three regression methods, including empty selectors hidden by an unrelated
  pass, all-incompatible selectors, divergent membership and cross-host restrictions.
  Per-selector inventory proves the requested hash suite expands to five tests.
- bazel-libc-hash-review-r1-20261105: all eleven installed regular file records,
  exact shell/fixture/Kyua bytes, physical suite/data/debug directory attributes,
  two distinct original program ELF/interface/dependency-order/hardening contracts
  and native/Make debug filename/CRCs match the independent Make libc parent stage
  from bazel-libc-installation-make-r1-20261105.
- bazel-libc-hash-noopenssl-native-r1-20261105: OpenSSL disabled with the same
  maintained suite. Inventory records two compatible shell cases and three
  incompatible SHA2 cases. Four selected targets pass (cache hits, including the
  two policy targets); the three incompatible targets are not counted as passes.
- bazel-libc-hash-noopenssl-make-r1-20261105: original component is independently
  built/staged with --without-option OPENSSL using the recorded baseline SDK.
  Receipt explicitly records the component override; SDK reconfiguration is not
  claimed.
- bazel-libc-hash-noopenssl-review-r1-20261105: complete nine-file disabled inventory,
  exact scripts/data/Kyua, directory attributes and the original helper's ELF/debug
  contracts match that disabled Make stage. The audit queries original program
  inventory with the same recorded component option; no manually reduced expected
  filename list is substituted.
- bazel-libc-hash-selector-rejection-r1-20261105: actual formerly accepted suite
  alias is rejected before build by the corrected maintained frontend, despite an
  unrelated compatible source-settings target. FAILED.json, query outputs,
  alias-declaration.bzl and the backend source snapshot retain the real negative
  control. No passing receipt is produced.

Retained attempts: native r1 fails because native test_suite tests are not
configurable. Native r2 changes to an alias and passes only source settings under
the old runner; REVIEW.json marks it unaccepted as hash runtime proof. The old
receipt is preserved with its actual one-test result rather than rewritten.
The real negative control verifies the runner fix. Native r3 uses a fixed suite
and proves all requested runtime work. Original ELF/debug bytes are not asserted
identical; interface/metadata/debug-link contracts are the compared evidence.

## Maintained integration and remaining acceptance

Existing explicit inputs and C frontend suffice; its maintained source_graph
backend and inventory regression tests are updated together. The manual documents
stronger selector validation; no schema, signing or publication change is needed.
Typed installation providers retain leaf contributions for parent composition.

This qualifies selected AMD64 hash construction/installation and five original
runtime cases, including the disabled OpenSSL inventory control. It does not
qualify the complete installed hierarchy, other ABIs, whole-system bootstrap,
performance, live DTrace/audit delivery or publication. Make remains default,
full-tests parent guards remain and BIP remains excluded.
