# PCI Ethernet checkpoint — 2026-11-01

Work stopped at the user's request for a host system upgrade.

## Qualified Make dependency correction

Nine module Makefiles now explicitly request `ofw_bus_if.h`: alc, ale, bce,
bge, jme, msk, re, sge, and vte. Their MII headers consume the generated OFW
interface when the GENERIC platform enables FDT. Isolated ARM64 and RISC-V
builds exposed this missing prerequisite; previously generated kernel files
can hide it. No driver C source or shared build policy was changed.

The fresh corrected Make matrix passed all 66 builds: amd64's 13 selected
modules and arm64/riscv's 10 each, with plain and CTF variants. The cohort is
alc, ale, aq, bce, bge, et, jme, msk, nfe, re, rge, sge, and vte; maintained
root Make selection excludes aq, et and nfe from these ARM/RISC configurations.
This is compile evidence, not hardware execution or native Bazel parity.

Evidence: `/usr/obj/usr/src/bazel-pci-ethernet-make-r2-20261101/results.json`
(66 passed, zero failures), SHA-256
`44e061297610c991a363a509d281d133041dc12045923d9716439fd3f27cf79d`.
The same root retains actual Make commands, header inputs, build logs and
staged installation manifests. The initial failed matrix remains at
`/usr/obj/usr/src/bazel-pci-ethernet-make-20261101`.

## Deferred native generator work

`deferred/pci-ethernet-device-ids.patch` preserves the exact unqualified WIP.
It factors the existing USB generator action into a shared device-ID rule,
adds the original MII AWK generator and MII interface header providers.
It was removed from the active graph for this checkpoint. `git apply --check`
passed against the checkpoint source. No Bazel build or generator equivalence
test has run on this patch. Driver module BUILD declarations remain to do.

After upgrade, revalidate/restage the SDK with the maintained helpers; receipts
bind host tool hashes and must not be edited to bypass changed tools. Then
apply the patch, qualify both USB and MII generated headers against maintained
generators, implement the selected driver declarations, and compare all 66
native module artifacts and installation metadata with independent Make.
Review actual compiler inputs/options and object order before claiming parity.
Development discovery scripts and metadata remain under `/tmp/pci-ethernet-*20261101*`;
regenerate them from maintained sources when resuming rather than making them
production build inputs.

## Frontend review

The Make fix declares an existing generated-header dependency and does not
change build inputs exposed by build-bsd, staging, signing, publication, or
security policy. No frontend/backend CLI or manual change is required.
The deferred generator patch will use the existing native qualification API;
its integration and regression checks are still pending. Make stays the
production default. No packages were installed and no upgrade was performed.
