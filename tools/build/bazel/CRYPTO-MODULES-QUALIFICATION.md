# Crypto module qualification

## Scope (2026-11-02)

Four selected amd64 GENERIC leaves now use native declared Bazel compilation,
CTF, ordered linking, export, debug and installation actions: aesni, blake2, ccp
and crypto. Their complete 80-object inventory contains 77 physical C sources,
two assembly sources and the existing cryptodev_if generated C source, in 75
compiler groups. Eighty exact physical header contexts reuse 62 existing providers.
Generated KOBJ/option/offset inputs use their owning native producers.

Five AESNI/Intel SHA custom C recipes retain their effective O3 policy and explicit
instruction features. Ten BLAKE2 SIMD variants retain O2, ordered instruction flags,
SUFFIX and MM-allocation-header guard policy. Skein preserves its selected C/assembly
split and per-source loop/assembly flags, including the assembler no-executable-stack
option. Native rules use standard cc_library compilation/assembly and private
local_defines; no custom compiler, Make wrapper or runtime graph discovery is added.
The optional local_defines parameter defaults to [] and does not propagate to other
groups/consumers. All four original module export policies remain unchanged.

## Explicit SDK headers

Original accelerated Make recipes remove -nostdinc and consume compiler resources
and /usr/include/ssp/ssp.h. Native rules keep -nostdinc and provide the selected SDK
resource/system header contexts explicitly. Across 820 consumed occurrences, all
132 unique original headers match selected SDK and actual native input hashes.
No installed host headers are used by native compilation. The existing SDK-header
provider derives its versioned resource root from the selected SDK, not a newly
hardcoded compiler version/path. Migration evidence retains original physical paths.

## Evidence

Paths below are under /usr/obj/usr/src.

- bazel-crypto-module-source-facts-r1-20261102 preserves original module selection,
  parent exports, source inventories and Makefile hashes.
- bazel-crypto-module-make-references-r1-20261102 contains eight passing untouched
  original Make build/install controls. Each control uses all sixteen logical CPUs;
  controls run sequentially to bound total compilation concurrency.
- bazel-crypto-modules-{plain,ctf-debug}-native-r1-20261102 are accepted normal
  build-bsd profiles. Each passes all six existing module-provider regressions and
  captures the 24 previously qualified HID module files for helper regression.
- bazel-crypto-modules-review-r1-20261102 retains 80 actual compiler actions,
  source/compiler digests, exact define/warning contracts, effective optimization,
  ordered target/ISA flags, independent leaf-frame policy and 6,798 original Make
  consumed prerequisite-occurrence checks. Generated KOBJ inputs differ only by
  the exact checked single provenance-comment source path. Four actual initial-link
  actions retain all original ordered object inputs/hashes.
- All four plain files match untouched Make byte for byte. CTF/debug runtime section
  inventories, metadata and payloads agree except GNU build-ID/debug-link values;
  CTF bytes agree exactly. Native and Make debug CRC checks and twelve file-install
  records across both configurations agree. No filename-policy controls or
  post-build artifact normalization are needed; whole DWARF equality is not claimed.
- helper-default-regression.json binds 48 byte-identical prior HID artifacts across
  the two profiles. This and the twelve existing provider-test executions qualify
  the additive private-define helper change; they are not crypto algorithm tests.
- compiled-probe-preservation.json binds actual OpenCrypto SDT provider/probe/argument/
  tracepoint sections and relocations, all exact Make. Live registration and event
  delivery remain unqualified. Raw source marker matches are retained separately.

The first compiler-policy observer incorrectly required the independent leaf-frame
flag at the same position among ISA flags. The corrected observer separately checks
that setting and preserves the entire ordered target/ISA vector. The rejected
observer and explanation are retained; no build/artifact policy changed to pass it.

## Loader and configuration limits

These modules retain ordinary Make's original local/global symbol policies. The
[loader contract](MODULE-LOADER-EXPORT-CONTRACT.md) explains why global/weak-only
static tests do not emulate default local-symbol compatibility lookup. The six
provider regressions exercise previously qualified families, not a new strict
export requirement for crypto. Module loading/dependency behavior under either
compatibility setting, especially without built-in crypto providers, remains open.

The selected optimized GENERIC profiles cover plain and CTF/debug-symbol outputs,
not every optimization, CPU, KERNCONF or architectural variant. Crypto known-answer
tests, acceleration dispatch, session/error behavior and throughput remain untested
in VMs. ARM64/RISC-V and other source selections need separate native declarations
and qualification.

## Maintained workflow and remaining gates

The existing build-bsd C interface and maintained format-5 backend carry selected
SDK/kernel settings, targets, native test inventory and all sixteen jobs. Source
rules, helper API, regression artifacts, tests and docs are updated together. No
new user-facing configuration field, signing/stage/publication policy or kernel
runtime authority is introduced. No one-off script replaces the maintained frontend.

The running observability log records source markers and required session/dispatch/
completion/error, hardware/FPU ownership, acceleration fallback, key-buffer cleanup
and audit review without exposing secrets. Static preservation is not runtime
coverage. Remaining modules, complete world/pkgbase/hardware publication, bootstrap,
VM/runtime and controlled CPU/memory/disk I/O/disk-use/cache/sandbox performance gates
remain open. Make remains production/default; BIP is excluded. No host crypto
module loading, installation, upgrade or reboot occurred.
