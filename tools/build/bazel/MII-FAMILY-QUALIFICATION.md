# Native MII-family module qualification

2026-11-01. Native GENERIC-tied candidates now cover miibus, mdio and miiproxy
on amd64, ARM64 and RISC-V64, in plain and CTF/debug configurations. These are
component build/install checks, not hardware or full-system qualification.

## Source graph and independent references

Permanent BUILD declarations compile the original source units, generated
miibus_if/mdio_if interfaces, and architecture-selected FDT sources. They retain
Make's source/object order and export policy. Header providers are explicit,
source-owned and limited to consumers identified in actual Make dependencies.
Genuine target GENERIC option outputs provide configuration inputs. No C source,
warning policy, substitute option contents or SDK kernel-header fallback changed.
The native build does not invoke Make to discover sources or compile products.

The preceding inventory fix carries source-owned parent exports before leaf
conditionals; see MODULE-INVENTORY-CONTEXT.md. The cohort has 38 C entries on
amd64 and 40 each on ARM64 and RISC-V64. FDT selects micphy.c and mii_fdt.c.
The independent Make builds exposed miiproxy's missing ofw_bus_if.h prerequisite
on both FDT architectures. Its Makefile now declares that genuine conditional
prerequisite. Four failed plain/CTF builds and fourteen successful builds are
retained in `bazel-mii-family-make-r1-20261101`; all eighteen clean references
pass in `bazel-mii-family-make-r2-20261101`.

Reference builds use isolated object/staging paths, copied and hashed genuine
GENERIC option headers, and four concurrent builds with four compilation workers
each on sixteen CPUs. Each leaf query asserts the exact isolated .OBJDIR and
source selection before compiling; parent object-root exports cannot redirect
these builds into the standard object tree.

## Passed native gates

Six normal build-bsd format-5 profiles pass under
`/usr/obj/usr/src/bazel-mii-family-{amd64,arm64,riscv}-{plain,ctf}-r1-20261101`:

- 18 module configurations and 27 exact Make installation records.
- Nine plain installed modules byte-identical to independent Make output.
- Nine installed CTF modules with equal section metadata/payload except build-ID
  and debuglink; .SUNW_ctf matches exactly. Native and Make debuglink CRCs verify.
  Full separate-debug DWARF byte identity is not claimed.
- 236 actual compiler actions with original warning flags, target triples,
  forced opt_global.h policy and no SDK kernel headers.
- 460 option-input hash checks and 28,146 physical Make source/header checks
  across 211 unique files; generated C inputs bind to captured native outputs.
- All 18 original object orders; linker arguments are captured and hash-verified
  immediately before changing profiles.

Artifacts resolve through immutable receipt/manifest/content bindings.
Review reports, copied input profiles and audit scripts are under
`/usr/obj/usr/src/bazel-mii-family-review-r1-20261101`.

The original makeobjops.awk generator independently reproduces all four complete
interface source/header outputs using a stable basename input. Compared with
actual Make outputs, the only difference is the single source pathname in the
provenance comment; all generated code and whitespace otherwise match. Plain
module byte comparisons remain strict. The MDIO generator executed freshly;
the existing MII generator was cached from the preceding Ethernet cohort. A
first audit incorrectly expected two fresh actions; it failed after output
comparisons passed. The corrected record reports reuse explicitly and retains
all output parity checks. Evidence: `bazel-mii-family-generator-review-r2-20261101`.

## Inventory, resources and integration

Fresh parent-export-aware source inventories are under
`/usr/obj/usr/src/bazel-mii-family-module-inventory-20261101`. They select 729
amd64, 627 ARM64 and 553 RISC-V64 modules without query errors. The amd64
inventory now has 222 direct native module declarations and 507 without them.
Declaration presence is not completed conversion, and the amd64 macro-presence
diagnostic must not be presented as cross-target qualification.

Both native run batches and both independent reference matrices enforce an
18 GiB minimum initial free space and a 16 GiB reserve. No reserve was breached.
Guard records remain under `/usr/obj/usr/src/bazel-mii-family-*-disk-20261101.json`.
Timing and memory/I/O logs include qualification overhead and concurrent work;
they are not controlled comparative performance measurements.

The existing build-bsd C/CLI, native module/install/configuration helpers and
format-5 inputs express this cohort. No signing, staging or publication change
is needed. README, manual and observability notes are updated together. Make
remains the production/default backend. No host installation or module loading
was performed, and these profiles contain no runtime tests.

Hardware PHY/MDIO operation, alternate kernel options, complete world/kernel/
pkgbase/image builds, boot/service checks and comparative CPU/memory/disk/cache
qualification remain open. A direct scan of the 38 physical production C files
found no DTrace/SDT/audit markers. Review link/autonegotiation, PHY reset, MDIO
transactions and proxy attach/detach/error paths with their network callers;
no probes were added solely for a marker scan. BIP remains out of scope.
