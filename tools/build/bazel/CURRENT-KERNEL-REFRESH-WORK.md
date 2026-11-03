# Current full-kernel refresh (2026-11-03)

The subsequent [full-kernel qualification](CURRENT-KERNEL-REFRESH-QUALIFICATION.md)
now completes the native/Make build and object/runtime comparison steps below.
Aggregate modules, standalone DWARF and the broader system gates remain open.

The full-system goal requires current compiled evidence. The earlier controlled
amd64 GENERIC result remains valid for its recorded inputs; it cannot establish
parity for a subsequently changed source.

## Fresh independent inventory

A new GENERIC configuration reads current /usr/src configuration sources into
/usr/obj/usr/src/bazel-kernel-current-config-reference-r1-20261103/amd64.
The existing Make-built config tool is an explicitly hashed input. Configuration
inputs and tool hashes remain unchanged before/after. This is configuration and
read-only inventory evidence, not a kernel build or toolchain bootstrap proof.

The maintained kernel_inventory.py audit passes. It selects 2,462 link products
in exactly the prior product-name order. Fifty-four not-yet-generated source
files and thirteen custom/version products without a unique ordinary source-list
binding remain explicit; these are not silently dropped from the native graph.
The historical native graph has separate producers for them, requiring renewed
actual build/input reconciliation.

Current hashes of all 2,514 prior bound physical inputs find one changed file:
sys/kern/init_main.c. The separate eda743fc763 change lifts/restores CR0.WP while
patching the AMD bhyve hypercall stubs at startup. This work does not modify that
runtime fix. No prior bound path is missing. This bounded hash check does not
establish complete transitive dependency closure for a fresh build.

An initial comparison compared whole location-bearing inventory records and
reported inequality because generated source candidates use the new independent
object root. The corrected observer compares ordered object identities, which
are unchanged, while retaining the raw differing records. The initial report is
preserved separately; no compiled payloads are normalized or accepted here.

## Requirements identified at the inventory checkpoint

- Run the complete native kernel through normal build-bsd format-5 with the
  current qualified staged SDK and explicit source revision.
- Capture actual generated configuration/version bodies, ordered link inputs,
  response files and changed compiler prerequisites before another profile.
- Build a fresh independent Make control using the same declared configuration,
  version and previously documented filename policy. Retain raw baseline data.
- Require full object/runtime/CTF comparisons and debug CRC checks against it.
- Aggregate all 729 selected module producers and their installation/package
  closure; declaration counts alone are insufficient.

The prepared native profile has explicit kernel_source_revision
2c6c2e76e97bc08b42eb9980bdbd38ba369312fe and current compat-services SDK inputs.
It has not run as part of this inventory checkpoint. Stand boot-image work owns
the shared native profile window first. No new frontend/API option is needed.

Evidence root:
/usr/obj/usr/src/bazel-kernel-current-config-reference-r1-20261103/
contains configuration command/output, before/after hashes, full maintained
inventory, initial-record-comparison.json and corrected prior-control-input-audit.

Complete world/rescue/pkgbase/hardware/publication, ARM64/RISC-V/configurations,
bootstrap, debugger source lookup, sandboxing, VM/runtime and measured resource/
cache qualification remain required. Make stays production/default; BIP remains
excluded. No host kernel installation, module loading, upgrade or reboot occurs.
