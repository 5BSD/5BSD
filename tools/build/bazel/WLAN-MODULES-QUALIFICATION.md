# Native WLAN modules on amd64, ARM64 and RISC-V64

2026-11-01. Make remains the production backend. Native GENERIC-tied candidates
cover wlan, wlan_acl, wlan_amrr, wlan_ccmp, wlan_gcmp, wlan_rssadapt, wlan_tkip,
wlan_wep and wlan_xauth on all three supported architectures. This is artifact
qualification, not evidence of working radios, complete kernels or a booted OS.

## Source ownership and graph

The core keeps its 33 maintained C sources and EXPORT_SYMS=YES behavior. Its
five per-source -Wno-unused-function overrides apply only to adhoc, crypto,
hostap, mesh and sta. Two native compiler groups and declared object selections
preserve Make's original link order without archive extraction or reordering
finished binaries. Other modules retain their own original C translation units.
CCMP and GCMP share the two source-owned Rijndael compiler outputs; neither AES
translation unit consumes opt_wlan.h. Native compilation therefore has 44 unique
C inputs per configuration, while independent Make modules compile 46 entries.

Header providers declare the actual source closure in each owning package.
Physical source headers use the existing kernel -Isys context. No generated
header contents are invented: wlan/tdma and the other option headers are extracted
from the selected architecture's real config output. The core consumes the
maintained generated bus/device interfaces. Existing MAC/VM/CK header providers
remain dependencies. Adding the net80211 package moves ieee80211_ioctl.h out of
the root package; wlanstat's label follows its new owner, and wlanstat plus its
installation archive passed a maintained build-bsd regression. No C source,
Make source, ABI or runtime policy was changed.

These are checked-in native Bazel source declarations. The retained Make queries
and discovery scripts establish the independent review inventory; production
Bazel analysis does not parse Makefiles or those JSON files.

## Independent comparison

All evidence is under /usr/obj/usr/src. Fresh Make references reside in
bazel-wlan-make-20261101, with header-only KERNBUILDDIRs containing copied and
hashed actual GENERIC option headers. Four independent jobs use -j4 each on
this 16-CPU host. They cannot reuse old GENERIC object files through .PATH.

Six normal build-bsd bazel-test profiles (format 5, target-kind=kernel) build
nine module targets and nine installation manifests each. Targets are
//sys/modules/<module>:generic_module and :install_manifest on amd64; ARM64 and
RISC-V use arm64_ or riscv_ target prefixes. Profiles use the maintained SDK
receipt/toolchain, explicit declared inputs and 16 jobs. They select no runtime
tests; successful artifact receipts are not counted as runtime test passes.
Native directories are bazel-wlan-{amd64,arm64,riscv}-{plain,ctf}-r1-20261101.

The 54 comparisons establish:

- All 27 plain module files are byte-identical to independent Make outputs.
- All 27 installed CTF modules match section metadata and payloads except the
  expected build ID and debuglink CRC. .SUNW_ctf matches exactly. Both native
  and Make separate-debug CRC checks pass; complete DWARF/layout parity is open.
- All 81 installed file records match destination, type, owner, group, mode
  and tags. Directory aggregation and linker.hints are outside this gate.
- Actual ELF type/machine match each maintained architecture's module contract.
- All 264 actual native C compile actions use the correct target triple,
  freestanding flags and declared kernel inputs, without SDK user headers.
  Per-translation-unit required options are derived independently from Make's
  .depend files. 2,616 declared option-header hash checks match actual Make
  GENERIC headers. Warning lists match Make, including exactly five overrides.
- All 54 actual module linker parameter files are captured immediately and
  SHA-bound to execution-log inputs. Each module's object order matches Make.
  Both crypto consumers use the same AES compiler outputs per configuration.

Comparisons use immutable captured artifact files and validate their recorded
SHA256 before inspection, rather than shared mutable bazel-bin aliases.
Review, compile/link audits, source hashes, profiles and reproduction helpers
are retained in bazel-wlan-review-20261101. The header-owner regression is
bazel-wlanstat-regression-r1-20261101. No host modules, interfaces, services or
installed files were modified.

## Remaining runtime and system gates

The bounded 44-source observability scan retains the existing 14 textual
SDT/KDTRACE/audit/CTR marker lines; these are not active probe counts. Unmarked
sources are recorded in observability-audit.md. Review association/authentication,
key lifecycle, crypto failures, roaming, scan/node lifecycle and drop paths,
including live arguments and audit requirements during runtime qualification.

Matching-kernel module loading/unloading, physical drivers/firmware, hardware
and software crypto, CCMP/GCMP/TKIP/WEP compatibility, ACL/AMRR/rate adaptation,
monitor/mesh/TDMA modes, VNET/jails, MAC denials and failure/concurrency behavior
remain open. Non-GENERIC options are not qualified by this matrix.

Existing build-bsd profile support is sufficient; no frontend C, CLI, signing,
staging or publication policy change is needed. The manual documents these
candidates. This tranche does not prove full world/kernel/pkgbase aggregation,
bootstrap/sandbox closure, input-mutation behavior, controlled CPU/RAM/disk I/O
performance, publication, startup or SSH. Make remains production/default; BIP
is excluded.

## Current module inventory

The maintained module_inventory.py refreshed actual GENERIC Make selections
on all three architectures (bazel-wlan-inventory-20261101). It finds 1,003
module Makefile directories overall. Its declaration column detects a direct
amd64_generic_module invocation; it is a static inventory indicator, not proof
of cross-architecture compilation or runtime qualification. This WLAN batch
separately builds and compares the actual ARM64/RISC-V targets.

| Architecture | Make-selected leaves | Direct module declaration | Still without one |
| --- | ---: | ---: | ---: |
| amd64 | 729 | 169 | 560 |
| arm64 | 615 | 160 | 455 |
| riscv | 543 | 160 | 383 |

After removing unused option visibility grants, the ARM64 plain graph was
requalified and all 27 captured outputs matched its original run. Restoring
plain mode after the CTF/architecture matrix executed 89 actions (including
44 WLAN C sources and the generated offset helper); this is not a warm-cache
result. The following unchanged repeat is reported separately below.

The immediate unchanged ARM64 plain repeat
(bazel-wlan-arm64-plain-warm-repeat-20261101) produced 27 identical captured
outputs and zero execution-log action records. Both captures' payload hashes
were reverified. CCMP and GCMP's captured linker parameters also prove identical
full AES object paths in all six original profiles. This establishes a bounded
warm incremental check, not remote-cache portability or controlled performance.
