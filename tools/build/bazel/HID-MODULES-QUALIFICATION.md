# HID and evdev module qualification

## Scope (2026-11-02)

Twenty-four selected amd64 GENERIC leaves now use native source-owned compile,
CTF, link, export, debug and install actions: evdev and the twenty-three selected
hid/ modules. Their complete inventory has 28 objects, comprising 27 physical C
sources and the existing hid_if schema-generated C source, in 27 compiler groups.
Twenty-five exact physical header contexts reuse sixteen existing providers.
Generated interface/USB device-ID headers use their existing owning producers;
option headers come from actual selected config(8) outputs. Original warnings,
defines, code-generation policy and complete ordered object inventories agree.
No imported Make outputs, installed-header substitutes, production graph discovery,
Make wrapper/fallback or new build frontend option is added.

## Shared hgame callback export defect

The untouched original Make hgame module localized three public callbacks declared
in hgame.h: hgame_hat_switch_cb, hgame_dpad_cb and hgame_final_cb. Four strong
references from ps4dshock, ps5dsense and xb360gp could not use those definitions.
Each consumer explicitly declares MODULE_DEPEND on hgame. This is an original
source export-policy defect, not a difference to copy into native rules.

The Makefile now explicitly lists exactly these three exports before including
bsd.kmod.mk; the native module uses the identical three-name export list. Private
symbols retain the original policy. Source callback bodies/signatures and the
global kernel export default are unchanged. All other twenty-three module export
policies remain as originally selected. The old Make baselines, original provider
findings and source API/dependency declarations are retained.

hid_known_providers_test reads actual native module ELF bindings and requires all
four controller callback references to resolve to hgame. Its companion processes
the real hgame full artifact through the existing empty-export transform and
requires the old localization failure to be detected using the actual consumers.
Both tests pass in both native profiles; neither executes a kernel module.

## Evidence

Paths below are under /usr/obj/usr/src.

- bazel-hid-module-source-facts-r1-20261102 preserves original selection, parent
  export context, source inventories and source Makefile hashes.
- bazel-hid-module-make-references-r1-20261102 contains 48 passing isolated original
  Make build/install controls, including the old hgame export defect. Its two
  corrected references are in bazel-hgame-export-make-references-r1-20261102.
- bazel-hid-modules-{plain,ctf-debug}-native-r1-20261102 are accepted normal
  build-bsd profiles, each passing the two registered actual-provider tests.
- bazel-hid-modules-review-r1-20261102 retains 28 actual compiler actions, exact
  compiler/source digests, warning/define/code-generation contracts and 3,179
  original Make consumed prerequisite-occurrence checks. The only generated input
  difference is the exact checked single KOBJ provenance-comment path. Twenty-four
  actual initial-link actions preserve every original ordered object/hash.
- All twenty-four plain modules match Make byte for byte: twenty-three untouched
  references and the corrected hgame reference. No filename-policy controls or
  post-build artifact normalization are needed. All CTF/debug runtime section
  inventories, metadata and payloads agree except GNU build-ID/debug-link values;
  CTF bytes agree exactly. Native and Make debug-link CRC checks and 72 file-install
  records across the two profiles agree in path, owner/group, mode and package/debug
  tags. Whole DWARF/debug-file byte equality is not claimed.

A separate direct ELF review against the qualified native kernel and all 48
Broadcom/GPIO/SPI/HID modules finds no hidden supplied providers and no unprovided
strong imports. This establishes static symbol-name coverage for this cohort,
not module-loader behavior, runtime ABI compatibility, event delivery or hardware
operation. Source-owned declarations, original and corrected policy evidence,
profiles and migration/reference/review drivers are retained with the review.

## Maintained workflow, observability and remaining gates

The normal build-bsd C interface, maintained format-5 backend, typed CTF/debug
settings, declared SDK and host artifact test contract carry this cohort with all
sixteen jobs. Module source declarations, Make/native callback export policy,
provider tests and docs are updated together. No signing, protected-path, stage
security or repository-publication requirement changes.

The bounded source scan and follow-up list in observability-audit.md cover evdev
read/write/ioctl/mmap/revoke/grab permissions and ownership, input injection,
HID report decoding, controller callbacks, hotplug and detach/lifetime handling.
The seven matched lines comprise four hidbus report start/done DTrace call sites
and the Bluetooth vhid provider/probe definition and report-injection call site.
Their compiled SDT provider/probe/argument/tracepoint descriptor sections and
relocations match original Make exactly; compiled-probe-preservation.json records
these actual section contracts. Live registration and event delivery remain open.
A source scan does not establish generic FBT/framework coverage or live probe/audit
delivery. No host input devices or modules were exercised.

Other KERNCONF/FDT/USB/HID option variants, ARM64/RISC-V, remaining modules,
complete world/pkgbase/hardware publication, bootstrap, VM/runtime and controlled
CPU/memory/disk I/O/disk-use/cache/sandbox performance gates remain open. Make
remains production/default; BIP stays excluded. No host installation, upgrade,
module loading or reboot occurred.
