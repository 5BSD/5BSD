# Native eighty-application rescue construction

## Source declarations (2026-11-05)

The selected AMD64 core adds reboot, shutdown, dumpon, savecore, mount, mdmfs,
nos-tun, nc and fetch: 80 of 103 default applications. Source-owned compiler
variants retain original nested rescue warning/define policies, including
conditional dumpon crypto, nc IPSEC without ordinary WITH_STATS, and savecore
without ordinary WITH_CASPER. Mount retains its anchored DTrace provider.
Native lazy static imports preserve selected original archive order, adding
IPsec, Fetch and conditional SSL/crypto without expanding ordinary program objects.

Initial native r1 failed analysis: nos-tun's stub group used its filename where
crunchgen requires its C identifier. The shared crunchgen_identifier helper now
matches original genident for output groups and kept symbols; original hyphenated
filenames remain unchanged. The failed run is retained. Original generated Make
on identical inputs independently verifies this behavior through the final ELF.

## Retained evidence

All evidence directories below are under `/usr/obj/usr/src/`.

- `bazel-rescue-80-native-r2-20261105`: maintained frontend, sixteen jobs;
  89 runtime methods and separate 28 source-settings methods pass. New cases
  include private file/HTTP Fetch transfers and binary Netcat TCP exchange over
  ephemeral loopback ports. Lifecycle/storage/tunnel tests reject invalid requests
  before mutation; no valid host reboot, mount or crash-dump request is issued.
- `bazel-rescue-80-without-openssl-native-r1-20261105`: the same wrappers pass
  with target openssl=false. `bazel-rescue-80-ssl-selection-review-r1-20261105`
  binds the actual final link/output and commands: SSL/crypto archives are absent,
  and selected SSL/crypto symbols present in the enabled ELF disappear. Host
  execution tools still require crypto. This is selected-core qualification,
  not independent alternate-library/full-world or HTTPS acceptance. Exec-config
  crypto recompilation was observed; comparative configuration/cache cost remains
  a performance audit item, without a measured regression claim.
- `bazel-rescue-lifecycle-transfer-more-make-r1-20261105/report.json`: fresh
  original generated child Make builds, 13 C objects and one mount provider,
  with 4713 source/policy/tool/header bindings checked before and after.
- `bazel-rescue-80-action-review-r1-20261105`: actual successful native compiler
  actions match all thirteen original warning/define/optimization/C17/debug/SSP/
  non-PIE policies; copied objects/dependencies bind to execution digests, and
  all 409 upstream converter/runtime bindings are checked before/after.
- `bazel-rescue-80-dependency-review-r1-20261105`: 943 consumed dependency
  occurrences match declared executed input digests and independent original
  payload name/byte multisets. Relative parent spelling requires bounded lexical
  checks and source identity. No mutable execroot is retained-content evidence.
  Full logical namespace and incremental invalidation remain separate gates.
- `bazel-rescue-80-object-review-r1-20261105`: eleven C contracts agree directly;
  mount aliases and mdmfs assertion filenames remain explicit differences.
  `bazel-rescue-80-provider-review-r1-20261105` verifies mount provider schemas,
  actual function/patch sites and path-derived aliases against actual objects.
  `bazel-rescue-80-filename-controls-r1-20261105` independently reproduces mdmfs
  diagnostic differences using original compiler arguments plus macro-prefix
  mapping. Original baselines/native flags and bytes remain unchanged. These
  controls do not establish raw DWARF/DOF equality or live probe registration.
- `bazel-rescue-80-pipeline-review-r1-20261105`: fresh original crunchgen and
  generated Make on identical captured application/archive/startup inputs match
  main C and all 162 whole-byte outputs, including eighty stubs, eighty combined
  objects, main object and executable. Static AMD64, no INTERP/DYNAMIC,
  nonexecutable stack and RELRO checks pass. This is identical-input pipeline
  parity, not independent full-library/world reconstruction.

## Integration and remaining work

The maintained format-5 target/settings API already supports this change. The
manual, completion plan and observability ledger are updated; no frontend C,
schema, staging, signing or publication-helper changes are required. Evidence is
unsigned development construction, not verified boot or compromised-root protection.
No host installation, upgrade or reboot occurred. Make stays default; BIP excluded.

Finish 23 remaining default applications, actual rescue library overrides,
configuration/cross/full installation/aliases/helper paths and independent library/
debug/header/pkgbase parity. Privileged lifecycle/storage/network, HTTPS, IPsec,
live DTrace and audit delivery need appropriate runtime/VM evidence. Full world,
kernel/modules refresh, bootstrap, separate hardware/combined publication,
sandbox/cache and CPU/memory/disk gates remain open. The earlier ncurses raw
header provenance difference remains recorded rather than promoted to equality.
