# ARM64/RISC-V network built-ins (2026-11-03)

Status: selected default GENERIC sys/net and sys/netinet built-ins pass four
maintained native-root SDK profiles and independent original Make comparisons.
This does not establish complete cross kernels or network runtime behavior.

## Source rules and frontend

The source-owned lists select 89 ARM64 and 86 RISC-V products, representing
89 distinct physical C sources. They use ordinary native cc_library built-in
policy and typed CTF conversion, without loadable-module ABI flags. Twenty
header providers declare 176 physical header members. Selected config outputs
supply 21 ARM64 and 20 RISC-V option names. Existing declared offset, vnode
and KOBJ interface producers supply generated interfaces. Neither Make queries
nor prebuilt original objects implement these targets. Nested packages such as sys/netinet/cc and sys/netinet/libalias remain
separate work; the selected sys/net/route sources are included here.

The existing maintained format-5 build-bsd bazel-test workflow accepts these
source-owned targets. No new build input, policy, staging, signing, installation
or publication contract is introduced, so build-bsd.c and backend interfaces
need no change for this cohort. This manual and the maintained plan describe
the qualified scope. Make remains production/default; BIP remains excluded.

## Qualification

The final evidence and source binding is
`/usr/obj/usr/src/bazel-cross-kernel-network-work-r1-20261103/qualification-summary.json`.
The four profiles cover ARM64 and RISC-V, each with plain or CTF/debug settings.
All four declared DTS host artifact test invocations pass. Actual compiler
action captures finish before configuration switches. Independent fresh Make
plain controls use separate object roots; original CTF/debug controls remain
unchanged.

Across 350 object configurations, allocated section metadata and bytes, named
symbols and runtime relocations match the originals. All 175 plain objects
are whole-byte identical; all 175 raw CTF payloads match. Separate DWARF bytes
are not claimed identical. No object or output byte rewriting is used.

The compiler-input ledger covers 54,306 original/native logical pairs:
54,280 are raw byte identical. The other 26 are generated KOBJ headers whose
provenance comments use source basenames in native outputs and absolute source
paths in the original outputs. The initial strict raw audit rejected them and
is retained. They are reported separately, without comment stripping or byte
normalization.

Fourteen independent invocations of the original makeobjops.awk establish
seven architecture/header controls: bus_if, device_if, ifdi_if, pci_if and
pci_iov_if on ARM64; bus_if and device_if on RISC-V. Passing the original
absolute source argument reproduces each original header exactly. Passing
the basename of a symlink to the identical source reproduces the native
header exactly. Source, generator, tool and runtime hashes are bound and
unchanged. The final audit accepts only the recorded architecture/member
digest pairs; missing, extra or unexplained differences still fail.

These profiles consumed cached native KOBJ outputs. They do not provide a
fresh native generator execution witness. A first private control harness
incorrectly required such a witness and failed; that failure is retained.
The successful controls establish the output policy independently and bind
the headers actually consumed by the compiler, without inventing executions.

ARM64 additionally consumes 178 explicitly reported source-derived DTS
version header inputs, whose macro values match the original compiler
definition. These additions are not hidden in a claim of identical input sets.
All 89 primary source hashes and 124 lexical DTrace/SDT/audit marker lines
are unchanged. Runtime object comparison preserves compiled instrumentation;
it does not establish live probe behavior or instrumentation completeness.

## Remaining gates

Composite target-SDK host-tool execution closure is still unqualified for
this cohort. The KOBJ helper's host runtime library declarations require an
actual composite profile probe before deciding whether a correction is needed.
Other configurations, nested network owners, complete source/generator/link
closure, boot/runtime tests, packages, bootstrap, sandbox/cache behavior and
comparative CPU, memory, disk I/O and disk usage remain open.

Debug source lookup is also a separate gate. Inspection of VM objects found
inline header paths under Bazel virtual include directories. A private archive
and source-map prototype recovered actual inline-header text on ARM64;
RISC-V ET_REL debugger relocation support blocked the corresponding test.
There is no maintained native source archive producer or debug package closure
yet. The follow-up must use public Bazel artifact paths and compilation header
providers, qualify primary/generated/SDK/inline source lookup after relocation,
and integrate source archives with package identity and the normal frontend.
Full linked artifacts are required for all supported architectures.
