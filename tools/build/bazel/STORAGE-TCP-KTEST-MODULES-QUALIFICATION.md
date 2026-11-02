# NVMe-oF, TCP and kernel-test module qualification

## Implemented scope

Thirteen selected amd64 GENERIC leaves now use existing native C/module stages:
four NVMe-oF modules, four TCP modules and five kernel-test modules. Twenty-nine
compiler contexts cover twenty-seven physical C files; shared BBR/RACK sources
retain distinct MODNAME/STACKNAME contexts. Fifty-five physical header contexts
include twenty-six exact reused providers. All source/option dependencies and
original object orders are explicit. The original nvmf_transport EXPORT_SYMS=YES
and other EXPORT_SYMS=NO policies are retained. No runtime C, original Makefile,
common helper, compiler policy or protocol/test behavior is changed.

The five ktest modules preserve package=tests from original Make KMODTAGS; eight
other modules retain package=kernel. This is real installation metadata, not a
name-based classification. Building these modules does not run their kernel
tests. Their loader prerequisites, registration and behavioral cases require a
matching guest kernel; no host loading is authorized or performed.
The static registration inventory verifies 34 compiled cases, including twenty
HPTS functional cases enabled by the consumed opt_inet.h. This verifies the real
case bodies/registrations are present rather than only a disabled warning case.
The existing example Python wrapper skips two intentional failures; VM results
must report those skips separately and explicitly exercise failure reporting.

## Evidence and filename controls

All paths below are under /usr/obj/usr/src:

- bazel-storage-tcp-ktest-module-make-references-r1-20261102 retains all 26 original
  build/install controls: thirteen leaves in plain/CTF-debug, one Make workload
  at a time using all sixteen CPUs. Selected Makefile hashes are checked before
  building against the captured original source inventory.
- bazel-storage-tcp-ktest-modules-{plain,ctf-debug}-native-r1-20261102 qualify 45
  targets through the normal build-bsd format-5 workflow, including six existing
  provider tests per profile. Those tests do not execute ktest or network/storage
  protocol behavior.
- bazel-storage-tcp-ktest-module-filename-controls-r1-20261102 retains four fresh
  original Make controls for BBR/RACK. Their original .PATH operands contain
  ../../../; native compilation uses canonical physical source paths. Ordinary
  runtime-string/relocation differences are retained in ordinary diagnosis files.
  Each control includes the original Makefile unchanged plus one explicit
  -fmacro-prefix-map from its original source directory to its canonical directory.
  Policies derive from actual recorded source operands and checked physical
  identity. Sixteen actual recipes and their consumed prerequisites differ only
  by that declared flag; original target-dependent MD/MF/MT flags are retained.
- bazel-storage-tcp-ktest-modules-review-r1-20261102 retains actual compiler/link
  records, exact parameter bytes captured before later profiles, input hashes,
  ordinary/control/artifact/metadata proofs, source snapshots and review drivers.

All thirteen plain modules match respective Make references byte-for-byte:
eleven untouched originals and two independently verified filename controls.
CTF/debug section inventories, metadata and payloads agree except GNU build-ID
and debug-link values; CTF bytes agree exactly and both debug CRC sets validate.
All 39 installation records match, including the tests/kernel package distinction.
Whole DWARF byte identity is not claimed. Twenty-nine actual compiler actions
agree in SDK compiler, defines, warning order, code-generation flags and 4,803
consumed prerequisite occurrences. Thirteen actual ordered initial links pass.
No finished artifact is normalized or production rule changed to reproduce
noncanonical paths. Parameter capture remains observer ordering, not automatic
maintained frontend capture. Source-owned declarations need explicit updates
when source/configuration input relationships change.

## Observability and remaining gates

The bounded scan of twenty-seven C files records seven explicit DTrace marker
lines in NVMe-oF disconnect/reconnect/capsule-pressure paths. A separate scan
records 72 TCP_LOG_EVENT-family call lines in HPTS/LRO/BBR/RACK/common code.
Complete compiled section/payload comparisons preserve selected probes/logging.
Other scanned sources lack explicit markers under those patterns; shared header/
subsystem instrumentation and actual event firing remain separate questions.
Track missing useful lifecycle/error events and test-case failures, while avoiding
per-packet logs or protocol/key/payload disclosure. No new runtime probes are
added as part of this migration. Native ktest modules remain tests to run, not
passing behavioral results merely because compilation succeeds.

The existing build-bsd C interface, format-5 backend, module helpers and install
metadata inputs express this composition, including tests package membership;
no new CLI/manual behavior, security/signing, staging or publication contract is
needed. The default-loader/strict-export distinction remains documented separately.

All ARM64/RISC-V and alternate KERNCONF/options, actual loading, ktest execution,
NVMe-oF reconnect/target/storage behavior, TCP congestion/pacing/authentication,
live probes/audit, full world/rescue/pkgbase/hardware/bootstrap/publication,
VM/runtime, real cache/sandbox and CPU/memory/disk I/O/disk-use performance gates
remain open. Resource records are bounded build observations. Make remains
production/default; BIP is excluded. No host module loading, installation,
upgrade or reboot was performed.
