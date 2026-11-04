# Freestanding compiler inputs (2026-11-04)

## Implemented selection

The maintained SDK stager emits three freestanding C++ toolchains and platforms
alongside its normal userland toolchain. Their compiler, linker, archiver,
objcopy and strip runtimes remain explicit inputs. The target-owned source/header
providers supply all further headers. Kernel toolchains already excluded userland
SDK headers and are unchanged by this addition.

The standalone toolchains default to -nostdinc/-ffreestanding and -nostdlib, omit
the userland sysroot/resource search flags and builtin include whitelist, and do
not enable userland SSP or RISC-V hard-float defaults. Component-owned ABI flags
remain explicit. The same verified native compiler SDK can target AMD64, ARM64
and RISC-V while cfg=exec tools resolve the native userland platform. Userland
and standalone environment constraints prevent falling back to the normal SDK
toolchain for a standalone target. A matching composite SDK remains supported
by backend selection; this turn's native builds use one native SDK.

Format-5 inputs select `target-kind: standalone`. The backend requires receipt
capability `freestanding_toolchains: 1` and snapshot-bound toolchain declarations;
missing, malformed and old capability inputs are rejected. Whole SDK inventories
and bytes still undergo normal before/after verification. No source SDK has been
edited in place to obtain the new declarations. The C frontend was reviewed: its
existing typed JSON backend dispatch needs no new switch. Backend, stager, tests
and maintained manual change together; Make remains production/default.

## Current evidence

A fresh SDK was produced by maintained libmd-stage-tools.py under
`/usr/obj/usr/src/bazel-standalone-native-sdk-r1-20261104`. Earlier frozen SDKs
and reference artifacts remain unchanged. All twenty frontend contract methods
pass in one native Bazel wrapper. Native EFI/resource profiles pass five wrappers
each on ARM64/RISC-V and six on AMD64: sixteen artifact wrappers total, in
addition to the settings wrapper. The resource consumer declares the actual
Clang C23 checked-arithmetic header and verifies freestanding mode, target object
ABI and a real function without executing foreign code.

All 498 raw entry objects across the five selected EFI programs per architecture
retain exact whole-file bytes from the previously qualified builds (156 each on
ARM64/RISC-V and 186 on AMD64). All fifteen complete PE images remain byte-identical.
This does not compare every unused archive member or qualify a complete system.

Configured compiler-input reviews cover all registered target C/C++ compile
variants in the selected boot dependency graphs (984 ARM64, 992 RISC-V, 1,024
AMD64). Those include unrequested PIC registrations; they are not spawn counts.
No default SDK sysroot headers remain in the boot compiler inputs. The explicit
resource consumer has exactly its declared stdckdint.h resource. The regular
Forth boot object lists 262 ARM64 / 260 RISC-V / 295 AMD64 inputs in the configured
graph; the previous executed cross producers listed 4,467 / 4,348. These are
input-set observations, not physical I/O, memory or whole-system speed benchmarks.

The first ARM64 analysis failed in a new test fixture that assumed Clang installed
stdint.h in its resource directory. That header is absent from this SDK resource inventory. The fixture now consumes the actual installed stdckdint.h API and asserts
__STDC_HOSTED__ is zero. No target implementation was changed for that correction;
the failed analysis is retained.

Evidence under `/usr/obj/usr/src/`:

- `bazel-standalone-settings-r1-20261104`
- `bazel-standalone-aarch64-r2-20261104` (r1 retains the fixture failure)
- `bazel-standalone-{riscv64,amd64}-r1-20261104`
- `bazel-standalone-{aarch64,riscv64,amd64}-code-review-r1-20261104`
- `bazel-standalone-{aarch64,riscv64,amd64}-actions-r1-20261104`

The complete comparison of 900 prior captured output records has zero whole-file
differences, including selected archives, generated assets, installation manifests
and test wrappers as well as the code/images above. Captures may repeat the same
payload through more than one target; this is not 900 distinct program binaries.

The manual negative target fails with the precise stdlib.h-not-found diagnostic
under the standalone toolchain. It is tagged manual and constrained to this ABI
so ordinary wildcard success suites cannot build it accidentally. The positive
consumer declares only its real stdckdint.h resource, with no builtin include
whitelist or host include-search exemption.

The resource-consumer cache experiment uses a separate fully inventoried test SDK
fixture with one explicitly recorded unused hosted-header change. The original SDK
is unchanged. A first fixture setup failed because copied SDK headers retain 0444
mode; the corrected fixture changes only its owned copy temporarily and restores
the mode. Source mutation is guarded by finally and the test source is restored.

The observed executed-compile counts are [0, 0, 1, 1, 0] for warm baseline, unused
SDK header change, consumed source change, source restoration and unchanged repeat.
The source change produces different object bytes; restoration and repeat produce
the original object bytes. An initial harness assumption expected zero compiles
on restoration and failed. That expectation was invalid: this frontend currently
configures Bazel's ordinary local action cache, without persistent disk/remote CAS.
The corrected review preserves this distinction, the failing expectation helper
and all original logs. No cache was enabled or compiler predicate weakened to
force the expected result.

Additional evidence under `/usr/obj/usr/src/`:

- `bazel-standalone-all-captures-review-r1-20261104`
- `bazel-standalone-hosted-rejection-review-r1-20261104`
- `bazel-standalone-cache-{baseline,unused-header,used-source,restored,repeat}-r1-20261104`
- `bazel-standalone-header-fixture-r1-20261104` (setup failure)
- `bazel-standalone-header-fixture-r2-20261104` (explicit fixture derivation)
- `bazel-standalone-cache-review-r1-20261104`
- `bazel-standalone-final-review-r1-20261104`

The consolidated review binds reports, successful qualification receipts and source
hashes. There are seventeen primary wrappers plus five cache-case wrappers. These
are component tests, not whole-system qualification. Persistent CAS integration,
installation link-identity cache safety and full sandbox qualification remain open.

## Remaining work

The full world graph still needs to select the boot ABI through its aggregate
boundary rather than require a separate qualification invocation. Complete
bootloader contributions, remaining profiles/options (including shared warning
policy), world/kernel/pkgbase, bootstrap/output-query/reproducibility, sandbox,
runtime/debugger/VM, combined publication and fair CPU/memory/disk I/O/storage
qualification remain open. This change does not certify boot signatures or
integrity against compromised root. BIP remains excluded.
