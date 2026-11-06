# FDT kernel option and I2C/GPIO module parents (2026-11-06)

## Source-owned option authority

The string setting //tools/build/bazel/config:kernel_fdt accepts auto/yes/no and is
separate from the userland fdt setting. Auto emits no override: the native parser
reads the actual GENERIC source default. Explicit values emit ordinary nooptions/
options directives. KERNEL_OPTION_DEFAULTS in kernel_option_settings.bzl declares
GENERIC's analysis-time defaults (AMD64 off, ARM64/RISC-V on); both the platform
selectors and native configuration rule consume this one declaration.

Normal configuration actions validate all actual generated opt*.h files against
the declared resolved option values before publishing their identity and selected
input inventory. Thus a changed GENERIC default cannot silently disagree with the
module selectors, including when no tests were requested. Auto defaults are explicit
source-owned Bazel metadata, not inferred from userland options or root-writable
runtime state. A configuration/default change must reconcile that declaration or
supply an explicit supported option value. All generated headers are required:
opt_global.h alone does not contain options such as FDT, ZSTDIO and NFS_ROOT.

This action also checks the existing boolean ZSTDIO/NFS_ROOT/TCP_HHOOK overrides.
The expected-value JSON is a declared action input and captured metadata. No Make
query, global frozen module list, fabricated header or host fallback is introduced.

## Module and dependency implementation

Three source parents now compose AMD64 I2C, I2C mux and GPIO modules. I2C consumes
the existing typed controller parent. Ten formerly cross-only FDT module producers
also have AMD64 producers using the original sources, object order and policy.
There are 45 unique products under auto/no and 55 under yes; the mux products are
already included in I2C and must not be counted twice.

The original recipes require more than adding module names: FDT adds ofw_gpiobus.o
and ofw_iicbus.o, and selects gpioled_fdt.o instead of gpioled.o. Native selects
preserve these alternatives and complete linker order. FDT-dependent source header
prerequisites are declared. GPIO contexts exposing gpiobusvar.h own their conditional
OFW dependency; the OFW header provider owns its generated interface and VM header
prerequisites. The CK physical header group includes the two x86 atomic headers
needed by the added AMD64 consumers. No runtime C source or linker policy changed.

Each module link now exposes typed recipe metadata from the same ordered File list
used by its actual link action. Typed products/sets forward its recipe path and
metadata output group. Recipes are qualification/build metadata, not installed
payload; runtime/debug files, aliases and installation attributes retain their
existing providers and package ownership. Text fixture products explicitly have
no recipe; genuine module_product targets require the typed link provider.

## Qualification and retained corrections

All evidence roots below are under /usr/obj/usr/src. Final normal build-bsd
bazel-test requests use the maintained explicit package SDK and all 16 CPUs:

- bazel-fdt-module-parents-auto-native-r5-20261106: 45 unique runtime/debug pairs.
- bazel-fdt-module-parents-yes-native-r10-20261106: 55 pairs, exactly ten additions.
- bazel-fdt-module-parents-no-native-r4-20261106: 45 pairs, byte-identical to auto.

Each reports 16 test targets passed; existing cached results are not new test
executions. The permanent FDT test checks requested selection against the actual
platform option header, actual member inventories and the three conditional source
alternatives via link recipes. The kernel-options test checks changed defaults,
malformed expectations and options split across generated headers. Default fixture
collision, nesting, installation-path and empty-selection checks continue passing.

bazel-fdt-module-parents-review-r2-20261106/review.json compares original Make root/
parent exports, complete recursive membership, each leaf's owner/group/mode/package/
debug/alias policy, complete install records and exact resolved ordered OBJS with
native link recipes. All 145 selected runtime/debug pairs across the three profiles
pass actual ELF identity/loader-symbol/debug CRC inspection. Auto and no products
are byte-identical. This is not full machine-code/DWARF equality against fresh Make
compilation. Review SHA256:
cb3be930a65138ce7626017183508e2a8ac523d69f8d09d6b47db4c5b08fe70f

The final guard/test additions preserve every artifact used by that review.
bazel-fdt-final-evidence-r1-20261106/review.json independently verifies 338/368/338
distinct old-to-final artifact bindings, all final 16-test receipts and resolved
option expectations. SHA256:
484ac8a5285a431ff3640b918548acce7bd0ab5047c1895e889d174430d3ca46

bazel-fdt-final-guard-review-r1-20261106/review.json runs the actual configuration
wrapper with a captured native parser/runtime and actual enabled override. The
valid expectation succeeds; an intentionally stale FDT expectation fails before
identity/inventory publication. No tracked source is edited for this negative
check. SHA256:
4b0eff19b0ee00ecd0e93749b1a6f481a3afe40cb175d7f8f0b08617d2a21d22

The maintained parser inventory test passes 18 cases across AMD64, ARM64 and
RISC-V, including FDT disabled, with original Make OBJS order, deterministic
outputs and negative parser modes. Evidence:
bazel-kernel-fdt-parser-inventory-r1-20261106/receipt.json. These cases configure
kernels; they do not compile or boot complete ARM64/RISC-V kernels.

Failed enabled profiles r1-r6 retain missing physical/architecture prerequisites
and one copied nonexistent option-header alias. The corrections declare actual
prerequisites and reuse the equivalent existing AMD64 option providers. r7 passes;
r8 adds permanent source-alternative regression coverage. r9 retains the incorrect
opt_global-only guard; r10 passes with the complete generated header set. The first
Make observer lacked inherited OPT_FDT and is retained under review-r1; review-r2
uses the maintained export parser to propagate original parent state. The expected
membership was not weakened to match that misconfigured observer. One controller
attempt stopped on missing request files after r9 failed; remaining explicit input
files were created before their final runs. No failed attempt is completion proof.

## Frontend, performance and remaining scope

The existing build-bsd format-5 build-settings/target/test APIs carry the new string
and all profiles. Maintained backend rules, parser wrapper, metadata capture, tests,
source declarations, manual and plan change together; frontend C and signing/
staging/publication protocols need no changes. Recipes are not extra compilation
configurations or payload copies. Header/default validation runs during build
configuration, not on filesystem or device I/O. These structural facts are not a
controlled CPU/memory/disk/cache performance result.

Make remains production/default; BIP stays excluded. This cohort does not prove
FDT-enabled AMD64 full-kernel catalog/link/boot or physical device operation. The
new parent scope is AMD64; ARM64/RISC-V parent selection and custom configurations
remain open. Remaining root selection/other source options/optional producers,
coherent kernel/GDB/modules/directories/aliases/linker.hints/pkgbase, refreshed
whole-system parity, normal startup/login/PAM/SSH/capability services and genuine
version upgrades remain. All bootstrap/cache/sandbox/reproducibility/debug/resource/
hardware/combined-publication gates retain their separately bounded evidence.
No host installation, module loading, upgrade or reboot was performed.
