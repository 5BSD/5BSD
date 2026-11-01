# Native USB network module qualification

2026-11-01. This component cohort covers the source-selected USB network
leaves: usie, umb, uether, aue, axe, axge, cdce, cdceem, cue, kue, mos, rue,
smsc, udav, uhso, ipheth, muge, ure and urndis. Selection comes from the
maintained module hierarchy and each leaf's real source search path, not a
replacement list of C files maintained by the qualification runner.

## Source and configuration graph

Source-owned BUILD declarations compile the twenty original C translation
units in their Make object order. Per-driver physical header dependencies
come from actual independent Make prerequisites. Existing config-generated
GENERIC option, device-ID and kobj interface providers are reused with narrow
consumer visibility. No C source, warning policy or shared toolchain rule is
changed for this cohort. Native builds do not execute Make for discovery.

Eight Make leaves now explicitly require ofw_bus_if.h when OPT_FDT is set:
aue, axe, axge, mos, rue, udav, uether and ure. Clean isolated ARM64/RISC-V64
references exposed their inherited miivar.h dependency. A previous full kernel
object directory could supply this header incidentally. This is a missing
prerequisite correction, not a claim that every ordinary full Make build was
broken. All 114 independent references (19 modules, three architectures, plain
and CTF/debug variants) pass after the correction.

Reference discovery preserves both module-root and USB-parent exports and
checks recursive override variables. The qualified default USB parent has no
extra MAKE arguments or SUBDIR_ENV/SUBDIR_OVERRIDE values. USB_DEBUG and other
alternate recursive contexts remain unqualified; export propagation alone is
not a general implementation of Make recursion.

## Passed component gates

Paths below are relative to /usr/obj/usr/src. Independent Make builds and
installation records pass for all 114 configurations in
bazel-usb-ethernet-make-r3-20261101. Native amd64 plain passes in
bazel-usb-ethernet-amd64-plain-r2-20261101; the other five profiles pass in
bazel-usb-ethernet-{arch}-{variant}-r3-20261101, using arm64/riscv for cross
architectures and plain/ctf for variants.

- All 114 native module configurations and 171 installation records pass.
- All 57 plain installed modules are byte-identical to Make.
- All 57 installed CTF modules have equal section metadata/payload except
  build-ID/debuglink, exact .SUNW_ctf and verified native/Make debug CRCs.
  Separate-debug DWARF byte identity is not claimed.
- Actual compiler audit covers 120 C actions, 17,644 physical source/header
  hash checks across 241 unique files, 588 genuine option-header hash checks,
  exact Make warning vectors and all 114 original link object orders.
- All 476 consumed generated-header bindings match independent Make headers.
  Kobj headers differ only in the one recorded source-provenance comment
  pathname; no generated code is normalized or rewritten.
- Complete USB/MII device-ID headers match fresh independent invocations of
  the original AWK generators. Fresh native generator execution is not claimed
  when the provider was already cached.

Artifact paths resolve through immutable manifests and content hashes. Actual
link parameter files are captured and hash-checked before changing profiles.
Reports, copied profiles and audit scripts are retained in
bazel-usb-ethernet-review-r3-20261101; complete device-ID output review is in
bazel-usb-ethernet-generator-review-r2-20261101. The earlier first-profile
review-r2 remains a separate snapshot.

All twenty physical C sources were scanned for direct DTrace/SDT, audit and
CTR markers; none were found. Unchanged source bytes and installed module
parity preserve their existing behavior. This is an observability review
candidate, not evidence that network-stack probes cannot observe them or that
every packet path should acquire a new probe. Hardware behavior and live
tracing remain open.

## Retained failures and resource scope

The r1 discovery script accidentally bound parent query stdout as a leaf's
SRCS result. The strict reference preflight rejected it before C compilation.
The corrected discovery preserves actual leaf stdout and validates its KMOD
and source bindings. The r2 Make matrix exposed the eight missing OFW
prerequisites. Original scripts, source hashes, failures and logs are retained.

Initial native analysis also rejected a duplicate opt_usb provider added
because a literal source search missed the existing computed rule. The added
duplicate was removed and the existing provider's consumer visibility extended.
No duplicate provider, fallback headers or weakened validation remains. The
first cross analysis also rejected missing INET provider visibility. Only the
actual USB network consumer was added to INET/INET6 on ARM64 and RISC-V64;
other options in the existing shared declaration were not exposed. Failed
analysis r2 and successful corrected r3 remain distinct evidence paths.

Reference builds use four parallel jobs with four compilation CPUs each;
native compilation uses all sixteen logical CPUs. Disk guards require 18 GiB
free initially and retain a 16 GiB reserve. No guard reserve was breached.
Concurrent work and qualification logging are included in resource evidence;
these are not controlled performance comparisons.

The existing build-bsd format-5 module/install actions express these targets;
no frontend C/CLI or security-policy option is needed. Make stays the production
default. This is component build/install/input evidence, without host module
loading, USB hardware operation, live tracing or a complete kernel boot claim.
The documented host /bin/sh execution-closure gap and full world/kernel/pkgbase,
VM service acceptance, alternate configurations and comparative performance
qualification remain open. BIP is out of scope.

Fresh parent-export-aware inventories in
bazel-usb-ethernet-module-inventory-20261101 select 729 amd64, 627 ARM64 and
553 RISC-V64 leaves without query errors. The amd64 source-presence diagnostic
counts 244 direct native module declarations and 485 without. Cross inventories
have 217/215 local BUILD files respectively; neither file counts nor the
inventory's amd64-macro detector establish cross qualification. The six explicit
native profiles above provide this cohort's artifact evidence.
