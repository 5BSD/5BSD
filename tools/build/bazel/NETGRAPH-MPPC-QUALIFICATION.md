# MPPC module: amd64, ARM64 and RISC-V64

2026-11-01. Native `ng_mppc` module and install candidates now cover all three
architectures in the GENERIC profile. The shared source-owned Netgraph inventory
selects the four original translation units: ng_mppc.c, mppcc.c, mppcd.c and
sha1.c, with narrow source/header exports. Existing registered freestanding
compilation, module linking, export, CTF, debug and installation rules are reused.
No C or Makefile behavior changes are made.

## Configuration contract

The actual target-generated GENERIC opt_netgraph.h defines neither MPPC option.
The amd64 header also enables other Netgraph/Bluetooth nodes; ARM64/RISC-V64
headers are empty. ng_mppc.c's existing
KLD_MODULE fallback consequently enables both compression and encryption. This
matches Make's default source selection. Neither a generated replacement header
nor a command-line define overrides that behavior.

Make's NETGRAPH_MPPC_COMPRESSION/ENCRYPTION variables and custom kernel option
combinations are **not yet modeled or qualified** by this candidate. Their source
selection must agree with the actual parent kernel configuration, including
netgraph.h's own option include. Supporting those variants remains explicit work;
the default GENERIC comparison does not establish it.

## Evidence

Six independent Make build/install references pass: three architectures, each
with CTF/debug disabled and enabled. Commands, queried ARCH_FLAGS, generated
files, resources and NO_ROOT METALOGs are retained under
`/usr/obj/usr/src/bazel-netgraph-mppc-make-20261101/`.

Six maintained `build-bsd bazel-test` kernel-profile runs pass under
`/usr/obj/usr/src/bazel-netgraph-mppc-{amd64,arm64,riscv}-{plain,ctf}-r4-20261101/`.
The r4 name reflects reuse of the preceding Netgraph qualification script; this
MPPC tranche had no earlier failed native attempts. Each run selects the module
and its install manifest; executable tests are empty in this artifact profile.

All three plain modules match Make byte for byte. All three installed CTF modules
match every ELF section except build-ID and debuglink contents, including code,
symbols, relocations and CTF. Both native and reference debuglinks validate against
their actual separate debug files. DWARF/build-ID/layout differences remain
recorded; source debugging is not qualified. All nine file/debug install records
match destination, type, owner, group, mode and package/debug tags. Directory
metadata and linker.hints are outside this comparison.

Execution-log review observes all twenty-four actual target compile actions,
with correct target triples, -nostdinc/-ffreestanding and no SDK include inputs.
Review, compiler audit, source/input hashes, bounded marker scan and reproduction
scripts are retained under
`/usr/obj/usr/src/bazel-netgraph-mppc-review-20261101/`.
The four-source scan finds no direct SDT/DTrace/audit/CTR markers; framework-level
observation, privileged graph/control authorization and live tracing need runtime
review. Compression/encryption traffic, interoperability, errors, cryptographic
suitability and matching-kernel module loading are not established by compilation.

The maintained frontend needs no new API, packaging/signing helper or policy
change for these existing module/manifest targets; its manual records coverage.
No host installation or module loading occurred. No controlled performance claim
is made from concurrent runs. Complete kernels, all modules, world/pkgbase,
bootstrap/cache qualification and CPU/RAM/disk measurements remain open. Make
remains the production backend; BIP remains excluded.

Netgraph now has 36 declared core/node candidates. Seven selected Bluetooth
modules still need native declarations. Architecture inventory counts and the
preceding eighteen-module evidence remain historical in
NETGRAPH-CORE-NODES-QUALIFICATION.md; they are not whole-system completion claims.
