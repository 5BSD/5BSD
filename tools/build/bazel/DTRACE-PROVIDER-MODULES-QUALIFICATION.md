# Native tracing provider and transport module candidates

2026-11-01. Native GENERIC-tied module/install candidates cover dttransport,
hypertrace, dtaudit, dtmalloc, dtnfscl, profile, prototype and sdt on amd64,
ARM64 and RISC-V64. Make remains production/default. This qualifies selected
artifacts, not working trace sessions, complete DTrace modules or booted kernels.

## Native source and compatibility graph

The nine maintained C translation units remain with their original owners.
HyperTrace retains both hypertrace.c and hypertrace_map.c; audit and NFS tracing
sources stay in their audit/NFS packages. The standalone transport remains a
normal kernel module and retains exactly its five Make export symbols. Other
modules retain their original module-symbol policy. No C, ABI, probe definition,
transport policy or host runtime state was modified.

The CDDL wrapper uses the existing generic compiler-object/CTF module rules.
Source-only CcInfo providers declare actual physical compatibility headers and
used include roots in original Make precedence: OpenZFS include, FreeBSD and SPL
namespaces, OpenSolaris compatibility, then common OpenSolaris UTS headers.
The additional Make os/freebsd/zfs search root is unused by these sources and
is not an ambient native header search path. Source-owned LinuxKPI compiler
headers retain the genuine relative include closure, with no replacement files.
Profile/HyperTrace retain their local DTrace include namespace. SDT's relative
../dtrace header input is declared physically without adding that search root.

The forced ccompile.h must precede opt_global.h, and debug_compat.h must follow
it. An optional preinclude_headers input to both generic object macros preserves
this order with declared source labels, compiler inputs and source-path maps.
Default callers preserve their original flags. The wrapper retains the actual
_SYS_VMEM_H_, __KERNEL__ and SMP defines from OPENZFS_CFLAGS. Real config output
supplies option contents. Generated vnode/bus/device dependencies use the
maintained kernel generators. This is checked-in native Bazel metadata, not
production Make parsing or execution behind a Bazel action.

## Evidence

All evidence resides under /usr/obj/usr/src:

- bazel-dtrace-providers-make-20261101 holds 48 fresh independent Make module
  builds and staged installs. Header-only KERNBUILDDIRs contain copied/hashed
  actual GENERIC opt_*.h, with no old kernel objects. Four independent jobs
  use -j4 each on this sixteen-CPU host.
- bazel-dtrace-providers-{amd64,arm64,riscv}-{plain,ctf}-r1-20261101 holds six
  successful maintained build-bsd profiles. Format 5, target-kind=kernel, the
  actual SDK receipt/toolchain and sixteen jobs are preserved. Plain profiles
  select eighteen targets (eight new modules/manifests plus if_epair regression);
  CTF profiles select sixteen. Tests are empty: artifact successes do not count
  as runtime test passes.
- bazel-dtrace-providers-review-20261101 retains immutable artifact comparisons,
  actual compilation/forced-header/include/option audits, link-order captures,
  if_epair regression, source hashes, profiles and reproduction helpers.

Targets are //sys/modules/dttransport:generic_module and :install_manifest, and
//sys/modules/dtrace/{hypertrace,dtaudit,dtmalloc,dtnfscl,profile,prototype,sdt}
with the same target names. ARM64/RISC-V use arm64_ or riscv_ name prefixes.
Retained profiles and command records provide exact frontend invocations.

All 24 plain module files are byte-identical to independent Make outputs.
All 24 installed CTF modules match section metadata/payloads except expected
build ID/debuglink CRC differences; .SUNW_ctf matches exactly. Both native and
Make separate-debug CRC checks pass. Complete DWARF/layout parity remains open.
ELF type/machine match each maintained architecture's module contract. All
72 installed file records match destination, type, owner/group, mode and tags.
Directory aggregation and linker.hints remain outside this component gate.

The action audit checks all 54 actual new-module C compilations, expected target
triples, freestanding flags, original warning lists and absence of SDK user
include inputs. All 108 declared option-header hashes match actual Make GENERIC
headers. Every CDDL compile has the original forced-header order, genuine
forced-header content hashes, compatibility defines and used include precedence;
transport compiles have only the ordinary forced global option header. All
48 actual module linker parameter files are captured immediately and SHA-bound
to successful execution inputs; object order matches Make.

The unchanged generic-helper path additionally passes if_epair regressions on
all three architectures: byte-identical plain Make modules and exact installed
file records. The maintained capture resolver checks receipt/manifest/content
bindings for these comparisons. All six cohort capture manifests and every
payload hash are independently reverified against the completed receipts.
Comparisons use immutable captured files, not shared mutable bazel-bin aliases.

## Observability and remaining gates

The nine-source scan records 72 direct textual SDT/DTRACE/audit/CTR marker lines.
These include provider/control definitions and are not active probe counts.
Existing compiled provider sections are retained in matching artifacts. The
transport source has no direct matched marker; review queue/session lifecycle,
enqueue/backpressure, transport registration/teardown, authentication and denial
visibility in context with its callers and the live HyperTrace protocol.

Matching-kernel module loading/unloading, provider registration, trace enabling,
probe arguments, audit/NFS/allocation/profile/SDT firing, transport queues,
HyperTrace mapping/forwarding, VM interfaces, permission/MAC denials, teardown,
concurrency and failure recovery remain runtime qualification work. Core DTrace,
FBT/kinst/systrace/fasttrap and the remaining tracing modules are not completed
by this tranche. Non-GENERIC configurations and controlled CPU/RAM/disk I/O
performance remain open. No host module, tracing session, network, service or
installation state changed.

Existing build-bsd profiles suffice; no frontend C/CLI, signing, staging or
publication policy change is needed. The manual describes the new targets and
compatibility handling. Full kernels/world/pkgbase, bootstrap/sandbox closure,
mutation/cache coverage, publication and normal system boot/SSH remain open.
Make remains production/default; BIP is excluded.
