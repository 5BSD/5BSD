# Native PCI Ethernet module qualification

2026-11-01. Native candidates now cover alc, ale, aq, bce, bge, et, jme,
msk, nfe, re, rge, sge and vte. Maintained Make selects all thirteen on
amd64, and ten on ARM64 and RISC-V64 (excluding aq, et and nfe there).
These are GENERIC-tied component builds; hardware operation is not qualified.

## Design and independent references

Static native BUILD declarations compile all original sources and retain
Make's source/object order, export policy, generated interfaces and genuine
configuration headers. Make is queried for development review, never at
native build time. Each driver consumes its actual architecture's physical
header-provider closure; unrelated driver dependencies were removed. No C
source, shared warning policy, empty option substitute or SDK header fallback
was introduced. Nine genuine missing OFW header prerequisites were fixed in
Make in the preceding checkpoint; see PCI-ETHERNET-CHECKPOINT.md.

The reusable device-ID action uses the maintained AWK source generators with
declared native AWK/runner and runtime libraries. MII invokes miidevs2h.awk
without an extra flag; the existing USB wrapper retains usbdevs2h.awk's -h,
output path, environment and mnemonic. Both complete generated headers equal
the original Make/generator references. MII generation was observed in the
execution log. The unchanged USB action was reused; its current configured
arguments/environment were checked with aquery, not claimed as fresh execution.

All sixty-six independent Make references passed under
`/usr/obj/usr/src/bazel-pci-ethernet-make-r2-20261101`. They use isolated
objects/staging, genuine copied and hashed target GENERIC option headers, and
four independent builds with four compilation workers each on sixteen CPUs.

## Passed native gates

All six maintained build-bsd format-5 profiles passed under
`/usr/obj/usr/src/bazel-pci-ethernet-{amd64,arm64,riscv}-{plain,ctf}-r1-20261101`:

- 66 module configurations and 99 exact installation records.
- 33 plain modules byte-identical to Make.
- 33 installed CTF modules with equal section metadata and payload except
  build-ID/debuglink; every .SUNW_ctf is exact. Native and Make debug CRCs
  verify; separate debug-file DWARF byte identity is not claimed.
- 104 actual compiler actions with original warning flags, source hashes,
  target triples and forced opt_global.h policy.
- All 540 consumed option-header hashes match genuine Make headers.
- 66 original object orders and 14,934 physical Make source/header hash
  checks over 239 unique files.

Artifacts resolve through receipt/manifest/content bindings. Review evidence
and copied input profiles reside in
`/usr/obj/usr/src/bazel-pci-ethernet-review-r1-20261101`; the generated-header
reference and review are in `bazel-pci-ethernet-device-ids-reference-20261101`.
Original execution logs are retained. Small audit subsets are extracted in one
streaming pass, with original/subset hashes and selected records recorded in
each profile's cohort-execution-provenance.json.

The audit caught late capture of twenty cross-target plain linker parameter
files: subsequent CTF builds had overwritten Bazel's working copies. Configured
action queries recovered their arguments, and serialized bytes must match the
original execution-record hashes exactly. No hash or object-order check was
relaxed. Future orchestration must capture parameters before switching profiles.
The other 46 parameter captures already matched the original hashes. Failed
query attempts that omitted the declared JDK or cross-toolchain registration
remain recorded; corrected queries preserve the actual profile inputs.

## Resources, frontend and remaining work

Each native profile required 18 GiB free initially and enforced a 16 GiB free
reserve throughout the run. No reserve interruption occurred. Per-profile
resource guard records remain in
`/usr/obj/usr/src/bazel-pci-ethernet-native-runs-r1-20261101`. An unguarded
six-profile run was rejected by automatic approval because the filesystem was
99% full; it did not execute. The guarded runs replace that unsafe orchestration.
Timing/memory/I/O logs include qualification overhead and are not a comparative
performance result. No old evidence was deleted.

The existing build-bsd API and maintained native module/install/configuration
helpers express this cohort. No frontend C/CLI, signing, staging or publication
change is needed; README and manual are updated. Make stays production/default.

These profiles contain no runtime tests. Additional kernel configurations,
hardware/firmware operation, full world/kernel/pkgbase, boot/service tests and
comparative CPU/memory/disk/cache qualification remain open. A direct bounded
scan of the 26 production C sources found no DTrace/SDT/audit markers; driver
reset, link/ring, firmware and error paths need caller-level observability review.
No probes were added to satisfy a scan. BIP remains out of scope.
