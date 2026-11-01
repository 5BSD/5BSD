# Native CAM core and peripheral module

2026-11-01. GENERIC-tied CAM module/install candidates cover amd64, ARM64 and
RISC-V64 in plain and CTF/debug modes. Make remains production/default.
This tranche qualifies module artifacts, not live SCSI/ATA/NVMe/MMC devices,
complete kernels or system startup.

## Native source graph and Make dependency correction

All thirty maintained C translation units retain their original source owners.
They cover CAM core/compatibility, I/O scheduling, peripheral/queue/SIM/transport
code, ATA, NVMe and SCSI peripherals. The NVMe utility source remains owned by
sys/dev/nvme; its existing userland exports are preserved and CAM is an explicit
additional consumer. Existing physical storage-header providers are reused with
narrow CAM visibility. The CAM-owned private header set is explicit.

The native compiler group supplies all original generated bus/device/vnode and
peripheral option inputs. Options are extracted from the real architecture's
config output, including empty headers; there are no invented header bodies.
Declared compiler-object selection preserves original Make SRCS order across
subdirectories without archive extraction or binary rewriting. EXPORT_SYMS=YES
is retained. No maintained C source or ABI was changed.

The first native build rejected cam.c's missing opt_kdtrace.h input. This source
now directly includes that header, but the module Makefile did not declare it.
The fresh Make references succeeded because their genuine GENERIC option set
already contained the header; .depend files independently prove the dependency
on all three architectures. Both the maintained Make SRCS and native provider
now declare it. The native header is extracted from config, not replaced with
an empty stub or a disabled tracing option. Six new independent Make references
were built after the declaration correction.

## Evidence and exact scope

All evidence resides under /usr/obj/usr/src:

- bazel-cam-make-20261101 preserves the original six successful references;
  bazel-cam-make-r2-20261101 contains the six corrected fresh Make builds and
  staged installs. Header-only KERNBUILDDIRs contain copied/hashed actual
  GENERIC opt_*.h, not old kernel objects. Four independent jobs use -j4 each
  on this sixteen-CPU host.
- bazel-cam-{amd64,arm64,riscv}-{plain,ctf}-r2-20261101 are six successful
  maintained build-bsd qualification profiles. Format 5, target-kind=kernel,
  actual SDK receipt/toolchain and sixteen jobs are unchanged. Each selects
  module and install-manifest targets with tests empty. These are artifact
  successes, not runtime test passes.
- bazel-cam-review-20261101 retains immutable comparisons, actual compile/option
  and link-order audits, source hashes, profile inputs and reproduction helpers.
  The failed native amd64 plain r1 attempt remains available.

Targets are //sys/modules/cam:generic_module and :install_manifest. ARM64/RISC-V
use arm64_ or riscv_ target-name prefixes. Captured profiles and command records
provide complete frontend invocations.

All three plain modules are byte-identical to independent Make output. All three
installed CTF modules match section metadata/payloads except expected build ID
and debuglink CRC differences; .SUNW_ctf matches exactly. Both native and Make
separate-debug CRC checks pass. Complete DWARF/layout parity remains open.
ELF type/machine match each maintained architecture's module contract. All nine
installed file records match path, type, owner/group, mode and tags. Directory
aggregation and linker.hints are outside this component gate.

The action audit checks all 180 actual module C compilations, expected target
triples, freestanding flags, original warning lists, source closure and absence
of SDK user include inputs. Required options are independently derived per
translation unit from Make .depend files. All 4,680 declared option-header hashes
match genuine Make GENERIC headers, including opt_kdtrace.h. All six actual
module linker parameter files are captured and SHA-bound to execution inputs;
object order matches Make. Artifact comparisons verify captured file hashes and
read immutable payloads, rather than shared mutable bazel-bin aliases.

## Observability and remaining gates

The thirty-source scan records eighteen direct textual SDT/DTRACE/audit/CTR
marker lines. Existing compiled probe sections are retained in matching module
artifacts; textual markers are not active probe counts or live argument tests.
Sources with no direct matched markers are listed in observability-audit.md for
contextual review of transport/SIM/peripheral discovery, I/O scheduling, command
submit/completion/error, timeout/reset/retry and audit policy coverage.

Matching-kernel module load/unload, CAM device discovery and dynamic rescans,
ATA/NVMe/SCSI/MMC transports, disks/CD/tape/changer/enclosure/pass-through/target
peripherals, queue pressure and scheduling, detach/hotplug, timeout/reset/retry,
fault recovery and concurrency remain runtime qualification work. Non-GENERIC
options and controlled CPU/RAM/disk I/O comparisons remain open. No host storage
modules, interfaces, services or installation state changed.

Existing build-bsd kernel profiles suffice; no frontend C/CLI, signing, staging
or publication policy change is required. The manual documents this candidate.
Full kernel/world/pkgbase aggregation, bootstrap/sandbox closure, mutation/cache
coverage, publication and normal system boot/SSH are still open. Make remains
production/default; BIP is excluded.
