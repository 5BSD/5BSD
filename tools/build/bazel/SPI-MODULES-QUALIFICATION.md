# SPI module qualification

## Scope (2026-11-02)

Six selected amd64 GENERIC module leaves now use native declared Bazel compile,
CTF, link, export, debug and install actions: intelspi, at45d, atopcase, mx25l,
spibus and spigen. Eleven objects cover ten physical C sources and the existing
spibus_if schema-generated C source. Twenty-two exact physical header contexts
reuse sixteen existing providers. Seven existing KOBJ schemas supply consumed
interface headers; selected option headers, including opt_spi, come from actual
config(8) outputs. Original warning/define/code-generation policies and complete
ordered object inventories are preserved. spibus and spigen keep their original
pre-include EXPORT_SYMS=YES; the four clients keep NO. No source export-policy
repair, installed-header import, empty stand-in or production Make discovery/
wrapper/fallback is added.

Make also emits usbdevs.h for atopcase, but the selected compiler prerequisite
inventories do not consume it. The existing source-owned USB device-ID producer
remains available; this batch does not claim qualification of other HID/SPI/FDT
option variants merely because the producer exists.

## Evidence

Paths below are under /usr/obj/usr/src.

- bazel-spi-module-source-facts-r1-20261102 retains original selected recursion,
  parent-export context, source inventories and source Makefile hashes.
- bazel-spi-module-make-references-r1-20261102 contains twelve passing isolated
  original Make build/install references. No filename-policy controls are needed
  for these six modules; ordinary source filenames already match native policy.
- bazel-spi-modules-{plain,ctf-debug}-native-r1-20261102 are the accepted normal
  build-bsd profiles. Each passes four registered host artifact tests.
- bazel-spi-modules-review-r1-20261102 retains eleven actual native compiler
  actions, compiler/source digests, exact warnings/defines/code-generation
  contracts and 1,564 original Make consumed prerequisite-occurrence checks.
  Generated KOBJ input differences are restricted to the exact checked single
  provenance-comment source path. Six actual initial-link actions preserve the
  complete original ordered object inventory and recorded input hashes.
- All six plain module files match untouched Make byte for byte. All six CTF/debug
  files agree in runtime section inventory/metadata/payloads except GNU build-ID/
  debug-link values; CTF bytes agree exactly. Native and original Make debug-link
  CRC checks pass. Eighteen file-install records across the two profiles match
  paths, owners/groups, modes and package/debug tags. Whole DWARF/debug-file byte
  equality is not claimed.

Source-owned declarations, profiles, migration/reference/review drivers and raw
source scan results are retained with the review. Make is a migration oracle,
never runtime graph discovery or the native build backend.

## Provider boundary

broadcom_gpio_spi_providers_test uses the actual twenty-four Broadcom/GPIO/SPI
module artifacts. It requires the prior Broadcom GPIO edges and both
gpiospi -> spibus:spibus_driver and gpiospi -> spibus:spibus_transfer_desc.
Missing or localized supplied definitions fail. All three prior provider tests,
including the real localized-BCMA negative fixture, also pass in both profiles.

A separate direct ELF binding review against the qualified native amd64 GENERIC
kernel and these twenty-four modules finds no localized supplied providers and
no remaining unprovided strong imports. GNU IFUNC binding is handled correctly.
This closes this cohort's static symbol-name boundary, not runtime ABI compatibility,
module metadata/dependency-loader correctness, hardware operation or module loading.
Other modules and alternate configurations are outside that closure result.

## Maintained workflow, observability and remaining gates

The normal build-bsd format-5 C/backend interface, declared SDK platform, typed
CTF/debug settings and native host artifact test contract carry this work with
all sixteen compilation jobs. Targets, provider test and docs are updated together;
no new CLI/config field or security/signing/stage/publication policy is needed.

Ten physical C sources and one interface schema have a bounded call-shaped
observability scan recorded with source hashes and matched lines. Follow-up work
in observability-audit.md covers pin/transfer ownership, DMA/interrupt completion,
flash writes, ACPI/HID events, error/timeout recovery and detach/lifetime behavior.
The scan does not prove generic FBT/framework or live probe/audit delivery.

Other KERNCONF/FDT variants, ARM64/RISC-V, remaining modules, complete world/
pkgbase/hardware publication, bootstrap, VM/runtime and controlled CPU, memory,
disk I/O/disk-use, cache and sandbox performance gates remain open. Make remains
production/default; BIP remains excluded. No host module loading, installation,
upgrade or reboot occurred.
