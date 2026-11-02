# GPIO module qualification

## Scope (2026-11-02)

Six selected amd64 GENERIC module leaves now have native source-owned Bazel
compile, CTF, link, export, debug and install rules: gpioaei, gpiobus, gpioiic,
gpioled, gpiospi and gpioths. Ten objects cover eight physical C sources and the
gpio_if/gpiobus_if schema-generated C sources. Eleven exact physical header
contexts reuse six existing providers. Seven existing KOBJ schemas supply consumed
interface headers; option headers come from the actual selected config(8) output,
including the new opt_gpio view. No installed-header imports, empty stand-ins,
production Make discovery or Make build fallback is used.

The original complete object order and warning/define/code-generation contracts
are explicit. gpiobus retains its original pre-include EXPORT_SYMS=YES policy;
the five clients retain NO. This batch requires no change to kernel export policy.

## Artifact and input evidence

All paths below are under /usr/obj/usr/src.

- bazel-gpio-module-source-facts-r1-20261102 captures original selected leaves,
  inherited parent Make exports, configuration and source Makefile hashes.
- bazel-gpio-module-make-references-r1-20261102 contains twelve passing independent
  ordinary Make build/install controls. These untouched baselines remain available.
- bazel-gpio-modules-{plain,ctf-debug}-native-r1-20261102 are accepted normal
  build-bsd format-5 profiles. Each passes three registered host artifact tests.
- bazel-gpio-modules-review-r1-20261102 records ten actual native compiler actions
  and 1,100 original Make prerequisite-occurrence checks, exact compiler/source
  digests and warning/define/code-generation contracts. Generated KOBJ input bytes
  differ only by the explicitly checked single provenance-comment source path.
  Six actual initial-link actions retain all original ordered object inputs/hashes.
- Plain module files match their Make references byte for byte. Four references
  are untouched Make; two use the explicit filename control described below.
  All six CTF/debug modules agree in runtime section inventory/metadata/payloads,
  except GNU build-ID/debug-link values. CTF bytes agree exactly. Both native and
  Make debug-link CRC checks and eighteen file-install records across the two
  profiles agree. Whole DWARF/debug-file equality is not claimed.

### Explicit filename control, with rejected evidence retained

Ordinary Make embeds /usr/src/sys/dev/gpio//gpiobus.c, //gpioc.c and //gpioled.c
through a trailing slash in its .PATH entry. Native rules use their existing
canonical single-slash source filename policy. The resulting ordinary gpiobus
and gpioled string/relocation differences are recorded in ordinary-make-baseline.json;
they are not described as exact original Make parity or normalized after build.

For these two modules only, bazel-gpio-module-filename-controls-r2-20261102 includes
the unchanged original Makefile and appends one explicit compiler macro prefix
mapping from the double-slash GPIO prefix to the canonical single-slash prefix.
All twelve actual original/control compiler recipes differ only by that one flag;
1,280 consumed prerequisite occurrences retain identical inventories and bytes.
Rebuilt outputs then satisfy the strict comparisons above. Native source policy
and the source Makefiles are unchanged. These are independent migration controls,
not a production wrapper or an installed artifact rewrite.

The first filename-control attempt (r1) used command-line literal CFLAGS and lost
-MD/-MF/-MT dependency arguments. Its audit rejected it. The rejected controls and
actual argv defects remain recorded separately; only r2 supports final parity.

## Provider regression and remaining boundaries

broadcom_gpio_providers_test inspects the actual eighteen-module Broadcom/GPIO
artifacts and requires bhnd -> gpiobus:gpiobus_add_bus and
if_bwn -> gpiobus:gpio_pin_config_32_desc. Missing or localized definitions fail.
The prior broadcom_known_providers_test and real localized-BCMA negative fixture
also pass. The explicit required-edge assertions prevent an absent GPIO boundary
from producing a vacuous pass. These are static host artifact tests, not module
loading or hardware execution.

A separate direct ELF binding review against the qualified native GENERIC kernel
and all eighteen modules finds no localized supplied provider. The former Broadcom
GPIO imports now resolve. gpiospi still requires spibus_driver and
spibus_transfer_desc from the next SPI cohort. Full module dependency loading,
hardware operation and detach/error behavior remain unqualified.

## Maintained workflow and remaining gates

The existing build-bsd C interface, maintained format-5 backend and host artifact
test contract carry this batch without a new CLI/config field. Native targets,
provider regression tests and these docs are updated together. No signing,
staging security or repository-publication requirement changes in this batch.

The bounded source scan and follow-up questions are retained in observability-audit.md.
Other KERNCONF/FDT variants, ARM64/RISC-V, complete modules/world/pkgbase/hardware
publication, bootstrap, VM/runtime and controlled CPU/memory/disk I/O/disk-use,
cache and sandbox performance gates remain open. Make remains production/default;
BIP remains excluded. No host modules were loaded and no host installation,
upgrade or reboot occurred.
