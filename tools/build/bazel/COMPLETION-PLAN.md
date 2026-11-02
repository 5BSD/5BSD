# Native Bazel completion plan

## Open module debug qualification gate

Read [MODULE-DEBUG-QUALIFICATION.md](MODULE-DEBUG-QUALIFICATION.md) before interpreting
historical “CTF/debug” claims. Installed stripped module/CTF parity and separate
CRC validity do not establish cross-build DWARF parity. Direct audits of 117
pairs find five differing sections; semantic DIE/line mapping and actual debugger
source lookup against a canonical source/debug package layout remain required.
Carry any input/toolchain/package/frontend change through maintained tooling.


Resumed by user instruction on 2026-11-01 after the committed upgrade
checkpoint (`7ffc0048161`). The target is complete base-system Make coverage
and a complete native Bazel system build, not BUILD-file presence. Make
remains supported for ports and third-party software. BIP remains out of scope.

## Latest system/I/O module checkpoint (2026-11-02)

Thirty-seven further amd64 module leaves pass compiler/input/link and artifact/
install checks: 125 actual compiler contexts and 13,134 original / 13,135 native consumed
dependencies per profile, with the sole extra TPM header alias verified as the
same physical file and bytes, plus 37 ordered links. Thirty-five plain modules equal
untouched Make; two equal explicitly documented filename controls. CTF/debug
payloads/CRCs and 74 install records pass, plus 37 plain records. Explicit iconv/
nvdimm exports and Thunderbolt's module option header are preserved. Actual
before/after dconschat archives, including debug payloads, remain byte-identical
using the unchanged public ABI view with physical package-owned file labels.
See [SYSTEM-IO-MODULES-QUALIFICATION.md](SYSTEM-IO-MODULES-QUALIFICATION.md).

BUILD presence is 628/729 selected amd64 leaves (101 missing), not qualification
percentage. Other architectures/options, full world/rescue/pkgbase/hardware,
bootstrap/publication, VM/runtime and CPU/memory/disk I/O/cache/sandbox gates remain
open. Existing build-bsd format-5 inputs/rules carry this cohort; no new CLI or
security/publication policy. Make stays production/default; BIP remains excluded.

## Latest storage-adapter checkpoint (2026-11-02)

Seventeen further amd64 storage module leaves pass native compiler/input/link,
artifact and installation checks: 260 compiler contexts, 36,990 original/native-
consumed dependencies and seventeen ordered links per profile. Four original
vendor ELF objects are explicit hash-bound link inputs. All seventeen plain
modules match untouched Make whole-file; CTF/debug payloads, CRCs and 34 install
records pass, plus seventeen plain records. Qualification found and corrected
hptmv's missing original CFLAGS-reset policy using native feature selection;
its first artifact remains rejected. Eighty unchanged-default output bindings
remain exact. See
[STORAGE-ADAPTERS-MODULES-QUALIFICATION.md](STORAGE-ADAPTERS-MODULES-QUALIFICATION.md).

BUILD presence is 591/729 selected amd64 leaves (138 missing), not qualification
percentage. Other architectures/options, full world/rescue/pkgbase/hardware,
bootstrap/publication, runtime and CPU/memory/disk I/O/cache/sandbox gates remain
open. Maintained build-bsd format-5 inputs carry this cohort; module helper and
docs are updated without new CLI/security/publication policy. Make stays default;
BIP remains excluded.

## Latest platform-module checkpoint (2026-11-02)

Twenty-four further amd64 platform/GPIO/watchdog modules pass two native
compiler/input/link and artifact/install profiles: 36 actual compilers and 3,843
original/native-consumed dependencies per profile, plus 24 ordered links.
Twenty-two plain modules equal untouched Make whole-file; p2sb/superio equal
independent canonical-filename Make controls. Original lexical-path discrepancies
remain recorded. CTF/debug payloads, CRCs and 48 install records pass, alongside
24 plain records. Six existing provider tests pass per profile; device runtime
is not qualified. See
[PLATFORM-FAMILIES-MODULES-QUALIFICATION.md](PLATFORM-FAMILIES-MODULES-QUALIFICATION.md).

BUILD presence is 574/729 selected amd64 leaves (155 missing), not qualification
percentage. Other architectures/options, full world/rescue/pkgbase/hardware,
bootstrap/publication, VM/runtime and CPU/memory/disk I/O/cache/sandbox gates remain
open. Existing build-bsd format-5 inputs/helpers carry this cohort; no new CLI or
security/publication policy. Make stays production/default; BIP remains excluded.

## Latest Intel Ethernet checkpoint (2026-11-02)

Seven more amd64 modules pass two native compiler/input/link and artifact/install
profiles. Each binds 118 actual uncached compiler actions and 21,775 original and
native-consumed dependencies; all seven plain modules are whole-file identical
to Make. CTF/debug sections, CTF payloads, split-debug CRCs and seventeen install
records pass; ten plain records pass. Three relative aliases follow configured
kernel directories. The common helper has positive archive and negative prefix
tests; existing archive and prior network outputs remain exact. Actual Make
staging also qualifies the empty-alias-package-tag correction and explicit
package/tag overrides. See
[INTEL-ETHERNET-MODULES-QUALIFICATION.md](INTEL-ETHERNET-MODULES-QUALIFICATION.md).

Local BUILD presence is 550/729 selected amd64 leaves (179 missing), not whole
system qualification. ARM64/RISC-V, complete world/rescue/pkgbase/hardware,
bootstrap/publication, runtime and CPU/memory/disk I/O/cache/sandbox gates remain
open. The maintained build-bsd frontend exercises these changes with existing
format-5 inputs; module rules, tests and manual are updated. Make stays default;
BIP remains excluded.

## Latest network-module checkpoint (2026-11-02)

Nine amd64 network/RDMA leaves now pass native compiler/input/link and artifact/
installation reviews against eighteen original Make controls. Both profiles bind
98 actual compilers and 27,502 original and native-consumed dependency occurrences,
plus nine complete ordered links. Five plain modules match whole-file bytes;
four differ only in independently reproduced 20-byte build-ID descriptors from
original local debug compilation, with every other final byte equal. CTF/debug
sections, CTF payloads, split-debug CRCs and eighteen installation records pass;
nine plain installation records pass. Six existing provider tests pass per profile.
See [NETWORK-FAMILIES-MODULES-QUALIFICATION.md](NETWORK-FAMILIES-MODULES-QUALIFICATION.md)
for the rejected initial strict criterion and exact linker-control evidence.

BUILD presence is 543/729 selected amd64 leaves (186 missing), not qualification
percentage. Fresh parent-export-aware inventories select 627 ARM64 and 553 RISC-V
leaves; only 216/214 have recognized cross-module declarations. Older cross
inventories omitted twelve/ten FDT-selected leaves. Evidence and exact gaps are
retained under `/usr/obj/usr/src/bazel-current-module-selection-20261102/`.
The separate real static rescue dispatcher is under qualification; its bounded
three-application result does not close the full rescue selection. Full world,
rescue/pkgbase/hardware/bootstrap/publication, alternate options/architectures,
VM/runtime and CPU/memory/disk I/O/cache/sandbox qualification remain open.
Existing build-bsd format-5 inputs and maintained rules carry these declarations;
no new CLI/backend/security/publication policy. Make stays production/default;
BIP remains excluded.

## Latest kernel checkpoint (2026-11-02)

Complete native amd64 GENERIC now passes controlled full Make parity: all 2,462
objects match code/allocated data/CTF, and the linked full/runtime kernels match
55 allocated payloads plus validated build-ID metadata, 96,147 loader symbols
and merged CTF. The comparison found and fixed the initial helper DSO build-path
DT_NEEDED defect; old artifacts fail the new test. See
[FULL-KERNEL-PARITY-QUALIFICATION.md](FULL-KERNEL-PARITY-QUALIFICATION.md).
Native kernel installation now also matches original Make staging in default,
alternate and colocated-debug layouts; see
[KERNEL-INSTALLATION-QUALIFICATION.md](KERNEL-INSTALLATION-QUALIFICATION.md).
Next kernel work is pkgbase integration and module/configuration/architecture
qualification, followed by VM/runtime and performance gates. Full world and
bootstrap/publication remain open; Make stays production/default.

The package driver now preserves first-class directory layout records, including
empty directories, alongside optional mtree ownership metadata. Its registered
real-pkg/BSD-tar Bazel regression passes three valid layouts and three rejection
cases. Kernel/GDB component packages also preserve the captured payloads; this
does not close complete kernel packaging. See
[PACKAGE-DIRECTORY-QUALIFICATION.md](PACKAGE-DIRECTORY-QUALIFICATION.md).


Two further hardware modules, amd_ecc_inject and amdsbwd, now pass native plain
and CTF/debug artifact/install comparisons against corrected original Make
controls. See [HARDWARE-MODULE-GAP-QUALIFICATION.md](HARDWARE-MODULE-GAP-QUALIFICATION.md)
for the export-policy correction, debug-definedness mismatch and fresh SDK
qualification after a changed host tar input. Other module coverage remains open.


Nine further hardware modules now pass native plain and CTF/debug artifact and
installation comparisons: AAC/AACRAID and their Linux adapters, Alder Lake/AMD
GPIO, Apple BCE, Areca and Apple SMC. The batch covers 19 source files and 2,799
Make dependency occurrences; see
[NINE-HARDWARE-MODULES-QUALIFICATION.md](NINE-HARDWARE-MODULES-QUALIFICATION.md).


Ten Atheros loadable modules now pass native default plain/CTF-debug comparison,
including the complete 138-object default inventory and both alternative rate
algorithms. All twelve plain binaries are byte-identical to Make; CTF/debug
runtime sections and 36 install records agree. Actual compiler/input and ordered
link audits pass. Source corrections and runtime limitations are recorded in
[ATH-MODULES-QUALIFICATION.md](ATH-MODULES-QUALIFICATION.md).

The next twelve-module Broadcom group has original Make source facts captured.
Its two native NVRAM header producers now match original Make output bodies with
declared AWK/map/runtime inputs; module compilation remains open. See
[BHND-NVRAM-GENERATOR-QUALIFICATION.md](BHND-NVRAM-GENERATOR-QUALIFICATION.md).

Twelve Broadcom bus/wireless modules now pass native 75-object compile/input and
ordered-link audits, corrected Make plain/CTF-debug comparisons and 36 install
records. Static import review found four local-only shared provider policies;
explicit exports and positive/negative artifact tests remove fallback reliance.
GPIO providers and runtime/module loading remain open. See
[BROADCOM-MODULES-QUALIFICATION.md](BROADCOM-MODULES-QUALIFICATION.md).

Six GPIO modules now pass ten actual compiler/input and six ordered-link audits,
plain/CTF-debug comparisons and eighteen install records. Both profiles pass three
provider tests, including explicit Broadcom-to-GPIO edges. Two ordinary Make
filename differences require separately audited compiler-policy controls; the
untouched baselines and a rejected first control remain recorded. SPI providers,
full loading and runtime/performance gates remain open. See
[GPIO-MODULES-QUALIFICATION.md](GPIO-MODULES-QUALIFICATION.md).

At the GPIO checkpoint, the 729-leaf amd64 selection had 284 local BUILD files
and 445 leaves without one; these were source-coverage counts only.

Six SPI controller/bus/flash/HID modules now pass eleven actual compiler/input
and six ordered-link audits, untouched Make plain/CTF-debug comparisons and
eighteen install records. Both profiles pass four provider tests. The qualified
kernel plus twenty-four Broadcom/GPIO/SPI modules now have providers for every
strong import with no hidden supplied providers; loading/runtime remain open.
See [SPI-MODULES-QUALIFICATION.md](SPI-MODULES-QUALIFICATION.md).

At the SPI checkpoint, the 729-leaf amd64 selection had 290 local BUILD files
and 439 leaves without one; these were source-coverage counts only.

Twenty-four HID/evdev modules now pass 28 actual compiler/input and 24 ordered-link
audits, Make plain/CTF-debug comparisons and 72 install records. An original hgame
policy localized three public callbacks used by three controller modules; explicit
exports and positive/negative provider tests remove reliance on local-symbol fallback. Static strong-import
coverage passes for the kernel plus 48 Broadcom/GPIO/SPI/HID modules. Runtime and
hardware behavior remain open. See
[HID-MODULES-QUALIFICATION.md](HID-MODULES-QUALIFICATION.md).

At the HID checkpoint, the 729-leaf amd64 selection had 314 local BUILD files
and 415 leaves without one; these were source-coverage counts only.

Module export tests enforce explicit ELF bindings; the source loader defaults permit
local-symbol lookup for compatibility. Earlier claims that local-only findings
necessarily caused default load failures are withdrawn. Explicit exports remain;
actual VM loading under both settings is still required. See
[MODULE-LOADER-EXPORT-CONTRACT.md](MODULE-LOADER-EXPORT-CONTRACT.md).

Four crypto modules now pass 80 actual compiler/input and four ordered-link audits,
untouched Make plain/CTF-debug comparisons and twelve install records. Assembly,
fifteen custom SIMD compilations and 820 explicit SDK header occurrences are covered;
48 prior HID artifacts remain byte-identical and all six provider regressions pass
in both profiles. Existing OpenCrypto SDT descriptor/relocation sections match Make.
Crypto runtime/known-answer/performance gates remain open. See
[CRYPTO-MODULES-QUALIFICATION.md](CRYPTO-MODULES-QUALIFICATION.md).

The current 729-leaf amd64 selection has 318 local BUILD files and 411 leaves
without one. These are source-coverage counts, not qualified builds.

Earlier component checkpoints below are retained historical evidence.

Refreshed Make module selection finds 729 selected amd64 leaves, with 245 local
BUILD files (244 direct audited macros and one separate ZFS description). This
is discovery, not build qualification; see
[MODULE-SELECTION-QUALIFICATION.md](MODULE-SELECTION-QUALIFICATION.md).

## Current resumption (2026-11-02)

The user resumed after the committed kernel-upgrade checkpoint a28f294501e.
Eight host execution input hashes changed; the maintained SDK preparation was
rerun into bazel-postupgrade-sdk-20261102 under /usr/obj/usr/src rather than
rebinding the historical receipt. All 16,812 new baseline checks pass. The next
twenty-four amd64 GENERIC virtual-memory objects pass actual compile/input,
code and CTF inspection; see VM-KERNEL-QUALIFICATION.md. This is component
progress, not a full native kernel/world/package/runtime or performance gate.
A further forty-three selected IPv4/TCP built-in objects pass the same native
compile/input, code/CTF and symbolic relocation checks; see
IPV4-KERNEL-QUALIFICATION.md. Full kernel link/network runtime gates remain open.
Twenty-nine selected IPv6 objects now pass corresponding native object/input
checks; see IPV6-KERNEL-QUALIFICATION.md. These cohorts do not close full kernel
aggregation, cross-build or runtime/performance gates.
Userland completed native WPA utility/crypto private libraries and passphrase
qualification across five declared configurations; see WPA-PRIVATE-QUALIFICATION.md
for 25 immutable ELF comparisons, 35 runtime methods and source/input/install
checks. The common library and hostapd control client now also pass four profiles,
twelve immutable ELF comparisons and sixteen safe CLI/loader methods; see
WPA-COMMON-CLIENT-QUALIFICATION.md. Remaining WPA private libraries/programs and
wireless/service behavior are open. Nine further support libraries now pass
38 Make configurations, five native profiles and 76 archive comparisons; see
WPA-SUPPORT-QUALIFICATION.md. All four remaining private libraries now pass
32 archive comparisons and 660 actual object/compiler/input checks across four
profiles; see WPA-FINAL-PRIVATE-QUALIFICATION.md. All sixteen private library
directories have bounded native output qualification. The wpa_cli client now
passes four immutable ELF contracts, actual compiler/link/input checks, sixteen
safe CLI/loader methods and original install metadata; see WPA-CLI-QUALIFICATION.md.
Remaining programs are wpa_supplicant and hostapd. Their source/link/install
graphs and all actual service/wireless runtime gates remain next. The next upgrade checkpoint records prepared
common/control-client Make references, which require post-upgrade revalidation. All remaining work
and final completion requirements below apply.

Thirty-two selected network built-ins now pass native code/CTF, input and
symbolic relocation checks; see NETWORK-KERNEL-QUALIFICATION.md. The corrected
graph reuses existing interface providers. Whole-kernel aggregation, cross-build
and runtime/performance gates remain open. This work resumed at user instruction
after the November 2 committed stopping point; host/SDK revalidation passes.

Thirty-six selected MII built-ins now pass native code/CTF, input and relocation
checks; see MII-KERNEL-QUALIFICATION.md. Refreshed known-builtin analysis finds
512 source matches among 2,466 Make final link products, plus six weaker name
matches and 1,948 unmatched products. These counts describe analysis, not full
compiled coverage. Kernel aggregation, cross-build, runtime and performance
requirements remain open.

Thirty-seven wireless built-ins now pass native code/CTF, input and relocation
checks after five actual per-source warning exceptions were corrected; see
WIRELESS-KERNEL-QUALIFICATION.md. Latest known-builtin configured analysis finds
549 source matches among 2,466 Make final link products, six weaker name matches
and 1,911 unmatched products. Earlier counts above are retained snapshots.
These remain analysis counts; full compile/link/runtime/performance gates apply.

Twenty-five OpenCrypto built-ins now pass native code/CTF/input/relocation
checks, with consumed libsodium headers owned by their source package; see
OPENCRYPTO-KERNEL-QUALIFICATION.md. Complete known-built-in analysis passes
across that boundary: 574 source matches among 2,466 Make final link products,
six weaker name matches and 1,886 unmatched in this known graph. Earlier counts
are retained snapshots; complete link/runtime/performance gates remain open.
The existing frontend API handles these targets unchanged; no new CLI/manual
option or signing/packaging policy is required.

Native amd64 VDSO production now uses separate declared compile/link/validation/
offset/embed actions; see VDSO-QUALIFICATION.md. Four original products match
Make byte for byte and 16 native validator regression methods pass. This closes
a producer prerequisite for elf_machdep, not the prepared 32-source low-level
amd64 conversion or full kernel link/runtime qualification. Existing staged
compiler/linker/Python and format-5 artifact/host-test APIs remain the workflow.

The 32-source low-level amd64 cohort now passes native object/input and
symbolic relocation checks, including seven CTF-bearing assembly files and
two actual Make no-CTF exceptions; see AMD64-LOWLEVEL-QUALIFICATION.md. Nested
architecture headers retain their logical namespaces. Latest successful known-
builtin analysis finds 606 source matches, six weaker name matches and 1,854
unmatched among 2,466 Make final products. These remain analysis counts, not a
linked kernel; earlier counts above are retained snapshots. The next 22 x86
C objects have unchanged independent Make object/recipe/dependency references
prepared; declarations and output qualification remain to be done.

The next 22 x86 C built-ins now pass native code/CTF/input/relocation review;
see X86-CORE-KERNEL-QUALIFICATION.md. New physical header ownership preserves
bhyve's recorded configured header context. Latest successful known-builtin
analysis finds 628 source matches, six weaker name matches and 1,832 unmatched
among 2,466 Make final products. These remain configured-analysis counts, not
a full compile/link. The next 22 debugger objects have unchanged independent
Make object/recipe/dependency references prepared; native output qualification
is still required. Existing whole-system and performance gates remain open.

The 22 debugger built-ins now pass native code/CTF/input/relocation review;
see DDB-CORE-KERNEL-QUALIFICATION.md. Latest successful known-builtin analysis
finds 650 source matches, six weaker name matches and 1,810 unmatched among
2,466 Make final products. These are configured-analysis counts, not a complete
kernel build. The next 29 ACPI drivers have unchanged independent Make object/
recipe/dependency references prepared; native declarations/output qualification
remain required. Full system, runtime and performance gates remain open.

Format 5 now supports opt-in compact execution evidence, matching formats 3/4;
see SOURCE-COMPACT-LOG-QUALIFICATION.md. Three native test targets pass 25 actual
unittest methods, configured inventory succeeds, and the hash-verified upstream
converter preserves source/XML bindings through the shared streaming reader.
JSON remains default. Compiler/link/generator coverage on subsequent component
runs and controlled resource/cache comparisons remain required; this bounded
integration does not close the full-system performance gate.

The 29 ACPI platform built-ins now pass native code/CTF/input/relocation checks;
see ACPICA-CORE-KERNEL-QUALIFICATION.md. The corrected graph declares the real
maintained quirk-table AWK producer and preserves its output hash exactly.
Upstream compact-log reconstruction binds actual compiler/CTF/generator records
without expanded disk logs. Latest successful known-builtin analysis finds
679 source matches, six weaker name matches and 1,781 unmatched among 2,466
Make final products. Earlier counts remain snapshots; full kernel/world/package,
cross-build, runtime and controlled resource/performance gates remain open.

## ACPICA engine checkpoint (2026-11-02)

156 additional amd64 GENERIC engine objects pass exact code/CTF, actual compiler
input and relocation checks. The upstream source-owner move also passes affected
acpidb/iasl configured action comparison, native binary/archive builds and bounded
host-runtime launch checks. See ACPICA-ENGINE-KERNEL-QUALIFICATION.md for evidence
and limitations. Known kernel reconciliation now has 835 source matches plus six
name-only matches among 2,466 products; 1,625 remain unmatched. Full kernel/world,
all architectures, package, runtime and performance gates remain open.

## ISCI checkpoint (2026-11-02)

109 additional amd64 GENERIC Intel SAS built-ins pass native compilation,
code/CTF, actual input and relocation checks. Source-owned header closures and
actual config/interface producers preserve maintained Make policy. Known graph
reconciliation now has 944 source matches plus six name-only matches among
2,466 final products; 1,516 remain unmatched. See ISCI-KERNEL-QUALIFICATION.md.
Full-system, module, other-architecture, runtime and performance gates stay open.

## LinuxKPI checkpoint (2026-11-02)

46 native amd64 GENERIC compatibility objects pass final code/CTF, actual input,
forced-include policy and relocation checks. The strict policy audit caught and
corrected an omission despite matching machine code. Known graph reconciliation
now has 990 source matches plus six name-only matches among 2,466 final inputs;
1,470 remain unmatched. See LINUXKPI-KERNEL-QUALIFICATION.md. Full-system, module,
other-architecture, runtime and performance gates remain open.

## OpenZFS checkpoint (2026-11-02)

237 native amd64 GENERIC built-ins pass exact code/CTF, actual compiler-policy/
input/overlay-order and nondebug relocation checks. Per-file RPC/config exceptions
are independently preserved. Additive macro ordering inputs leave all 999 prior
configured compile actions unchanged. The standalone CTF checker's untyped string
address limitation is documented alongside bounded hash-bound graph/relocation
proof, without weakening the tool. Known graph reconciliation now has 1,227 source
matches plus six name-only matches among 2,466 final products, leaving 1,233
unmatched. See OPENZFS-KERNEL-QUALIFICATION.md. Full-system/module, other-architecture,
filesystem/runtime and comparative performance gates remain open.

## Atheros checkpoint (2026-11-02)

130 native amd64 GENERIC driver/HAL objects pass exact code/CTF, actual compiler
policy/input/include-order and nondebug relocation checks. New source owners and
actual config-generated AH/ATH options replace no runtime policies or source code.
Known graph reconciliation now has 1,357 source matches plus six name-only matches
among 2,466 final products, leaving 1,103 unmatched. See ATH-KERNEL-QUALIFICATION.md.
Full-system, module, other-architecture, radio/runtime and performance gates remain.

## Intel NIC checkpoint (2026-11-02)

69 native amd64 GENERIC objects pass code/CTF, compiler policy/input/header-order
and nondebug relocation checks. bhyve's header/action contracts remain unchanged
apart from 333 recorded action keys; an actual post-move binary build passes. Known
graph reconciliation has 1,426 source matches plus six name-only matches among 2,466
final products, leaving 1,034 unmatched. See INTEL-NIC-KERNEL-QUALIFICATION.md.
Full-system/module, other-architecture, device/guest/runtime and performance gates
remain open.

## Mellanox checkpoint (2026-11-02)

52 native amd64 GENERIC objects pass code/CTF, compiler policy/input/compatibility
header order and nondebug relocation checks. Explicit OFED/UAPI child exports
preserve source ownership. Known graph reconciliation has 1,478 source matches
plus six name-only matches among 2,466 final products, leaving 982 unmatched.
See MLX-KERNEL-QUALIFICATION.md. Full-system/module, other-architecture,
device/runtime and performance gates remain open.

## Storage HBA checkpoint (2026-11-02)

39 native amd64 GENERIC OCS FC/SmartPQI objects pass code/CTF, actual compiler
policy/input and nondebug relocation checks. Known graph reconciliation now has
1,517 source matches plus six name-only matches among 2,466 final products,
leaving 943 unmatched. See STORAGE-HBA-KERNEL-QUALIFICATION.md. Full kernel link,
modules, other architectures, storage runtime and performance gates remain open.

## Storage core checkpoint (2026-11-02)

76 native amd64 GENERIC CAM/GEOM/NVMe/UFSHCI objects pass code/CTF, actual compiler
policy/input and nondebug relocation checks. Existing source package boundaries
are preserved. Known graph reconciliation has 1,593 source matches plus six
name-only matches among 2,466 final products, leaving 867 unmatched. See
STORAGE-CORE-KERNEL-QUALIFICATION.md. Complete kernel link, modules, other
architectures, runtime and performance gates remain open.

## Filesystem/RPC checkpoint (2026-11-02)

101 native amd64 GENERIC objects pass code, compiler policy/input, NFS tracing
header precedence and nondebug relocation checks. CTF is byte-exact for 100;
ufs_bmap passes the unchanged production graph/symbol verifier with one fewer
unreferenced empty slot. Native RPC TLS reuses its existing protocol generators.
Known graph: 1,694 source matches plus six name-only matches among 2,466 final
products, leaving 766 unmatched. See FILESYSTEMS-RPC-KERNEL-QUALIFICATION.md.
Complete kernel/world/modules, other architectures, runtime and performance gates
remain open.

## Device I/O checkpoint (2026-11-02)

98 native amd64 GENERIC USB/input/audio/console objects pass exact code/CTF,
actual compiler/input and nondebug relocation checks. Native audio/teken tables
use original scripts; sound preset overrides pass through normal format-5 inputs.
Existing AWK default actions remain exact. Unchanged outputs are reused with only
workspace-status execution (ten BEP local cache hits in the two-target closure);
restoring previous preset configurations re-executes because no persistent disk
action cache is configured. Retain that failed expectation and add/qualify managed
persistent action-cache support before full-system cache/performance claims.
Known graph: 1,792 source matches plus six name-only matches among 2,466 products,
leaving 668 unmatched. See DEVICE-IO-KERNEL-QUALIFICATION.md. Full kernel/world,
modules, other architectures, runtime and performance gates remain open.

## Work order

1. Revalidate host, SDK and independent Make references after upgrades.
   Resume the saved bsdtrace and PCI Ethernet candidates, qualify actual
   outputs, installation metadata, declared inputs and code generation.
2. Refresh maintained Make inventories for world, libraries, programs, tests,
   generated data, kernel and modules on amd64, ARM64 and RISC-V64. Reconcile
   selected products to actual native targets and installed destinations;
   retain every missing or unqualified item as an open gate. Presence counts
   are diagnostics, never completion evidence.
3. Complete native libraries/programs/generators and kernel/driver/module
   graphs with explicit configuration inputs and dependencies. Preserve
   DTrace/FIDL generation, audit hooks, embedded policy, debug/CTF and
   installation semantics. Review each converted cohort and commit it.
4. Supply maintained aggregate world, kernel and installation targets,
   including bootstrap and cross-build dependencies. Compile and link the
   system with Bazel actions; wrapping Make does not satisfy conversion.
5. Integrate native products with pkgbase-only package construction, separate
   hardware builds and verified combined publication under
   `/usr/obj/usr/src/repo`. Retain ports Make interoperability. Publication
   worlds require production malloc and existing identity/validation gates.
6. Build the full system and packages through the maintained frontend; run
   Bazel tests and disposable-VM boot, login/PAM/su, SSH and service checks.
   Qualify clean/incremental/cache behavior and CPU, memory, disk I/O and
   disk-use regressions. Record configuration coverage and runtime limits.
7. Audit inventory closure and reproducible build/package evidence before
   claiming completion or changing the production default to Bazel.

## Integration and checkpoints

Each implementation change checks `usr.sbin/bsd-build/build-bsd.c`, maintained
backend targets, helpers, tests and manual for corresponding updates. Existing
component qualification uses the format-5 frontend API; the pending component
resumption adds no CLI option. Aggregate world/kernel/package backend work
will require frontend integration in the same changes.

Use standard `/usr/obj`, configured ports inputs and all logical CPUs. Do not
install or reboot the host as part of build qualification. Commit reviewed
chunks and update qualification documents with checks actually performed.
The saved patches remain historical checkpoints; applying them is not proof
that the active graph is qualified.

## Explicit reconciliation gates found during component work

- Close host execution dependencies and sandbox isolation before claiming a
  hermetic toolchain. In particular, the existing makeobjops AWK generator
  invokes host /bin/sh through system(); output parity does not establish
  complete execution-platform input closure.
- Reconcile Make compile policy as well as runtime output. Mailwrapper review
  found a missing -DPIC and warning vector in its initial native declaration.
  Its correction is component-scoped; earlier userland declarations still
  require an explicit warning/macro-policy audit. Kernel cohorts retain their
  actual per-source warning-vector checks.
- Parent-export-aware module selection is a discovery audit. Before accepting
  aggregate configurations, reconcile source-owned recursive command-line and
  SUBDIR_ENV overrides too; export propagation alone does not model arbitrary
  recursive Make semantics. Native products must retain explicit Bazel inputs.

- Keep source-package ownership valid as BUILD files are introduced. A configured
  query of existing built-in kernel groups exposed stale root-package ACPICA
  and autofs header paths; loading a narrow cohort does not establish whole-
  graph validity. Correct ownership and qualify affected consumers rather than
  excluding the kernel version/COPYRIGHT dependency that exposes the error.
- Diagnose execution-tool cache behavior from paired configured actions and
  actual execution records. PPP observed uncached tool compilation in a later
  profile, but matching execution output roots disprove the tentative differing-
  root explanation. Neither build-progress counts nor execution-log size alone
  establish how many tools rebuilt or why. Qualify compact evidence logging
  before full-system scale and controlled performance comparisons.

- Root header ownership is now corrected with unchanged physical/logical
  source closure and actual configured version/COPYRIGHT analysis. Preserve
  package boundaries in later source-owner conversions. Next reconcile the
  exact bhyve dependency order (equal sets are insufficient) and investigate
  actual acpidump/iasl/autofs/bhyve physical section differences. Retain shared
  directory package-tag contexts when qualifying pkgbase splitting; final
  staged metadata alone is not full package ownership evidence. See
  ROOT-HEADER-OWNERSHIP-QUALIFICATION.md.

- Generate fresh independent configured-kernel references from the selected
  current source/configuration before closure audits. The old amd64 configured
  Makefile omitted 385 current final-link products. The maintained
  kernel_inventory.py audit retains the actual final link order, architecture
  link arguments/post-processing, missing generated sources and unresolved
  custom products. CFILES/SYSTEM_OBJS-only counts are insufficient. See
  KERNEL-INVENTORY.md for current evidence and analysis/build distinctions.

### Ordered dynamic lookup and current-source references

The common ELF checker now rejects ordered DT_NEEDED differences for programs
and shared libraries, including existing probe callers. Follow
[ELF-NEEDED-ORDER-QUALIFICATION.md](ELF-NEEDED-ORDER-QUALIFICATION.md): fix historical
hwstat/bsdinstruments/dtrace ordering gaps in native dependencies, retain original
failed evidence, and rerun immutable comparisons. bhyve default order/install
passes a fresh post-merge Make reference; code/DOF/section parity and other
configurations remain separate gates. Every reused Make receipt must still pass
its recorded source hashes after merges; an old successful receipt is not a
current-source baseline.

### WPA daemon continuation (2026-11-02)

The genuine AES-SIV dependency fix and native hostapd checks are recorded in
WPA-AES-CTR-QUALIFICATION.md and WPA-HOSTAPD-QUALIFICATION.md. Four of five WPA
programs had bounded native qualification at that checkpoint. Native
wpa_supplicant now adds 51 actual code/input/raw-relocation checks, eight safe
methods and sixteen install records (WPA-SUPPLICANT-QUALIFICATION.md). All five
programs have bounded qualification. Audit configured Make world coverage and
aggregate/install/pkg ownership next; retain shared wpa/hostapd directory package
contexts. Reconcile the independent internal-backend SAE/EHT/crypto API failures
without silently disabling features.
Qualify hostapd IPv6/examples-disabled and custom build selections explicitly.
Retain live control, root driver setup, wireless/EAP/authentication and audit
event delivery as separate runtime gates. Archive construction and safe CLI
reports do not establish those behaviors. Existing compact execution logging,
configured exec-action caching and full pkgbase/system gates remain open.

### WPA family milestone and next world gap (2026-11-02)

WPA-FAMILY-QUALIFICATION.md records default family composition, 37 products, 33 install records and 23 safe methods. The old default control-client capture was invalidated and independently requalified; unsafe one-off objcopy dump invocations must not be reused. All audit tools must preserve source/reference/candidate bytes, bind producer output hashes and recheck inputs after inspection. The fresh 2,127-directory metadata survey is a review queue, not action coverage. Next convert the actual csv.enc plugin/install gap under inherited parent context, then reconcile selected world actions/generated sources/install/pkg ownership. Retain internal WPA backend failures and live runtime/full-system gates.

### Selected CSV plugin gap closed (2026-11-02)

LIBXO-CSV-QUALIFICATION.md qualifies the actual csv.enc producer and six installation records after parent-export comparison: one original source, exact object code/constants/relocations, strict shared ELF and five runtime methods. Installed-path discovery, whole-libxo tests/composition and final packages remain open. Continue the actual configured world action/install queue; usr.sbin/apm is a selected program with no native producer in the fresh inventory and requires source/parent-context review before conversion. Presence counts are not build coverage.

### APM selected leaf and next static PAM product (2026-11-02)

APM-PROGRAM-QUALIFICATION.md records native source/ELF/install qualification of the selected x86 APM leaf; whole-world aggregation must retain its parent MK_APM switch. Next close lib/libpam/static_libpam, the actual missing /usr/lib/libpam.a product: compile the real core with OPENPAM_STATIC_MODULES, retain all option-selected module archives and registration partial-link order, preserve DTrace/DOF and original install metadata. Existing shared-core/module targets alone do not establish this static product. Keep device runtime, full PAM authentication, pkg/world and performance gates explicit.

## Virtualization built-in checkpoint (2026-11-02)

60 Hyper-V, Xen and VirtIO built-ins compile through the maintained frontend with exact code/CTF and checked inputs/policies/relocations. See VIRTUALIZATION-KERNEL-QUALIFICATION.md. Full kernel/world/pkgbase, architecture, runtime, bootstrap and performance gates remain open.

## Storage-controller checkpoint (2026-11-02)

62 additional native storage-controller built-ins pass exact code/CTF and compiler/input/relocation checks through the maintained frontend. See STORAGE-CONTROLLERS-KERNEL-QUALIFICATION.md. Full kernel/world/pkgbase, architecture, runtime, bootstrap and performance gates remain open.

## Ethernet built-in checkpoint (2026-11-02)

73 additional native Ethernet built-ins pass exact code/CTF and compiler/input/relocation checks through the maintained frontend. See ETHERNET-KERNEL-QUALIFICATION.md. Complete kernel/world/pkgbase, architecture, runtime, bootstrap and performance gates remain open.

### Combined static PAM selected product (2026-11-02)

STATIC-PAM-QUALIFICATION.md closes the missing native `/usr/lib/libpam.a` producer:
54 original core sources, original selected module registration/partial-link order,
DTrace metadata/sites, compiler/input/relocation checks, default/reduced install
records and two fully static registry-only native tests (24/20 modules). Keep
full PAM aggregation/pam.d, installed original authentication/login/SSH tests,
other LOCALBASE/options/architectures and whole-world/pkgbase/runtime gates open.
Next reconcile the actual configured userland action/install queue from the
2,127-directory Make survey; source BUILD presence alone is not coverage.

## Network stack and PF built-in checkpoint (2026-11-02)

73 additional native Network stack and PF built-ins pass exact code/CTF and compiler/input/relocation checks through the maintained frontend. See NETWORK-POLICY-KERNEL-QUALIFICATION.md. Complete kernel/world/pkgbase, architecture, runtime, bootstrap and performance gates remain open.

### PAM policy installation (2026-11-02)

PAM-POLICY-QUALIFICATION.md closes the selected pam.d file/archive producer:
27 exact original payloads and 29 unique Make-matching records across default
and AT/FTP-off profiles. Retain full PAM aggregation, explicit directory ownership
consumption by final package composition, installed authentication tests, other
configurations/architectures and whole-world/pkgbase gates.

## Kernel codec/crypto checkpoint (2026-11-02)

73 additional native Kernel codec/crypto built-ins pass exact code/CTF and compiler/input/relocation checks through the maintained frontend. See CODECS-CRYPTO-KERNEL-QUALIFICATION.md. Complete kernel/world/pkgbase, architecture, runtime, bootstrap and performance gates remain open.

## Peripheral-device checkpoint (2026-11-02)

90 additional amd64 GENERIC objects pass native compilation, exact machine code/CTF and compiler/input/relocation checks. Reconciliation r29 leaves 187 missing Make link products, plus six weaker matches. See PERIPHERAL-DEVICES-KERNEL-QUALIFICATION.md. Full linking, modules, architectures, world, packaging, runtime, bootstrap and performance remain open.

## Platform-support checkpoint (2026-11-02)

56 platform built-ins pass object/CTF/compiler/input/relocation checks; the native ACPI assembly-to-binary/header chain matches Make. Reconciliation r30 leaves 131 missing link products and six weaker matches. See PLATFORM-SUPPORT-KERNEL-QUALIFICATION.md. Full linking, modules, architectures, world, packaging, runtime, bootstrap and performance remain open.

## Monitoring/device checkpoint (2026-11-02)

52 additional amd64 GENERIC objects pass native object/CTF/compiler/input/relocation checks. Reconciliation r31 leaves 79 missing link products and six weaker matches. See MONITORING-DEVICES-KERNEL-QUALIFICATION.md. Full linking, generators/tracing remainder, modules, architectures, world, packaging, runtime, bootstrap and performance remain open.

### Original PAM test inventory (2026-11-02)

PAM-TESTS-QUALIFICATION.md closes the three missing original program producers
and seven-program installation inventory. Nineteen exact object-policy/payload
checks, seven ordered ELF contracts, twenty install records and fourteen safe
wrapper results pass. Retain nine installed-path policy cases plus one root
accounting case for disposable-guest execution, then PAM aggregate reconciliation
and full world/pkgbase gates. No source assertions or requirements were disabled.

## DTrace built-in checkpoint (2026-11-02)

15 additional amd64 GENERIC objects pass native object/CTF/compiler/input/relocation checks after fixing real parent-header namespace and late Solaris utility ordering. Reconciliation r33 leaves 64 missing link products and six weaker matches. See DTRACE-BUILTINS-KERNEL-QUALIFICATION.md. Full linking, generated products, modules, architectures, world, packaging, runtime, bootstrap and performance remain open.

## Generated-interface checkpoint (2026-11-02)

49 KOBJ interface objects and 98 generated C/header bodies pass independent Make comparisons through the maintained frontend. Reconciliation r34 leaves 15 missing link products, 53 generated-name-only and two object-name-only matches; independent provenance/artifact checks strengthen 49 of those generated matches. See KOBJ-BUILTINS-KERNEL-QUALIFICATION.md. Full linking, remaining generators/custom products, modules, architectures, world, packaging, runtime, bootstrap and performance remain open.

## Generated RPC checkpoint (2026-11-02)

Four RPC generated objects pass exact machine-code/CTF/runtime-section/compiler/input/relocation checks; six generator products match Make byte-for-byte. Reconciliation r35 leaves 11 missing products, 57 generated-name-only and two object-name-only matches; independent provenance/artifact checks strengthen 53 generated matches. See RPC-BUILTINS-KERNEL-QUALIFICATION.md. Complete linking, custom identities, modules, architectures, world, packaging, runtime, bootstrap and performance remain open.

## SIMD crypto checkpoint (2026-11-02)

Five optimized SIMD crypto objects pass native code/CTF/runtime-section/compiler/input/relocation comparisons; 276 external SDK header occurrences match Make. Existing 2,284 configured groups retain identical compiler commands/output paths; five debug targets select O0. Reconciliation r36 leaves six missing products and conservative generated/name-only classifications, with separate artifact/source proofs retained. See SIMD-CRYPTO-KERNEL-QUALIFICATION.md. Full linking, remaining identities, modules, architectures, world, packaging, runtime, bootstrap and performance remain open.

## PAM family checkpoint (2026-11-02)

PAM-FAMILY-QUALIFICATION.md records default28/reduced23 component archive sets,
108 actual shared compiler recipes with 3756 fresh Make input bindings, both
linked ELF/DOF contracts and 65 install records per configuration. Default15 safe
wrappers pass; KERBEROS-off13 pass with two explicit exclusions. Preserve original
nine installed-policy and one privileged accounting guest gates, final pkgbase
composition, inherited world selection and full-system/runtime/bootstrap gates.

## Custom-named kernel checkpoint (2026-11-02)

Four radix/OpenZFS SHA objects pass code/CTF/compiler/input/relocation checks, including one complete hash-bound filename spelling difference. Three declared symlink aliases preserve actual final-link names and bytes. Reconciliation r38 binds 2,405 physical-source identities, leaves 57 generated-name matches (53 independently qualified), two weak object identities and two missing producer chains (VDSO and force-dynamic). See CUSTOM-NAMES-KERNEL-QUALIFICATION.md. Full linking, modules, architectures, world, packaging, runtime, bootstrap and performance remain open.

## Refreshed final-producer checkpoint (2026-11-02)

After merge 7056e69713f, refreshed SDK/config inventories and a complete independent Make amd64 GENERIC reference pass. The native force-dynamic helper and existing VDSO yield six original products exactly matching fresh Make. Current query r45/reconciliation r39 accounts for all 2,462 selected amd64 products with no missing producer in this audit, retaining two weak object identities and four unqualified generated identities. The prior VDSO missing classification was a query-selection gap, now corrected. See FINAL-PRODUCERS-KERNEL-QUALIFICATION.md. Complete native kernel linking/post-processing/install, modules, other architectures, world, packaging, bootstrap, runtime and performance remain open.

## DWATCH and post-merge world checkpoint (2026-11-02)

DWATCH-QUALIFICATION.md records native default 133 / EXAMPLES-off 131 installation
records, 259 exact installed-path payloads and 198 actual hardlink checks. One
actual syntax case parses 30 original inputs; the second configuration explicitly
reuses the byte-identical cached result. Live tracing/world/package gates remain.
Fresh Make recursion selects 2,128 directories, adding sbin/mount_virtiofs; this is
not compiled coverage. External merge 7056e69713f changes existing userland
sources/tests (including capability/runtime libraries, kldload/mount,
BSDExtension/base-accounts/bhyve/switchboard/dtraced) and adds requalification
obligations. Earlier receipts remain historical; no SDK receipt was rebound.

## Generated core checkpoint (2026-11-02)

Five generated built-ins and clock calibration pass source/compiler/prerequisite/code/CTF/runtime-section and 5,091 strict relocation comparisons. The initial successful build with missing debug/CTF was explicitly rejected; typed shared policy now supplies them. Config/version references use identical declared inputs without normalizing payloads. Clock declares selected-SDK SSP availability and opt-only O3. Query r47/reconciliation r40 leaves no missing or weak object-name identities in the 2,462-product configured inventory; 53 generated-name matches retain separate KOBJ/RPC proofs. See GENERATED-CORE-KERNEL-QUALIFICATION.md. Next: complete native kernel aggregation/link/order/post-processing/install and per-object debug/CTF validation. Modules, other configurations/architectures, world, packages, bootstrap, runtime and performance remain open.

## LLDB generation milestone (2026-11-02)

The root-selected four-source TableGen producer and 19 library headers pass
native/Make output, eight actual compiler-policy, 5,882 prerequisite-hash and
789 relocation checks. The original bootstrap stddef wrapper is now declared.
Host-static Make versus declared-native dynamic execution is explicit; this is
not installed LLDB completion. The 756-source private shared library now passes
actual compiler/input/archive-order checks, exact allocated object and linked DSO
sections against a complete declared filename-policy Make control, five install
records and one safe API wrapper. See LLDB-LIBRARY-QUALIFICATION.md for the
untouched baseline differences and historical SDK binding. Next: two CLI option
headers, programs, debugger runtime/package context and ancestor MK_LLDB selection.
See LLDB-GENERATORS-QUALIFICATION.md; original ordinary-leaf and strict input
failures are retained. No host installation or debugger activation occurred.

## Parser-owned kernel input inventory (2026-11-02)

`config -J` now exports the resolved ordered input table; native config exposes
it as an explicit manifest without Make discovery. All 12 architecture/option
cases match independent Make OBJS exactly; custom prefix/no-obj/JSON escaping,
unchanged ordinary outputs, deterministic writes, failed writes and shortcut
rejection pass using both Make-built and captured native config. Three native
architecture manifests exactly match Make. See
KERNEL-CONFIG-INVENTORY-QUALIFICATION.md. Next remains native aggregate coverage
validation/link/post-processing/install; no full kernel/world completion claim.

## Native kernel aggregation guard (2026-11-02)

All 2,285 public native object groups expose exactly the 2,462 default selected
link products. An explicit migrated catalog and ordered File provider reject
missing/ambiguous/surplus products; parser metadata validation passes all four
ZSTDIO/NFS_ROOT selections. Bazel host rejection tests pass separately from
kernel artifact profiles. See KERNEL-AGGREGATE-GUARD-QUALIFICATION.md. The final
linker must consume the validation marker and ordered Files; full kernel link,
post-processing/install and wider system gates remain unfinished.

## Complete amd64 GENERIC native link milestone (2026-11-02)

The complete 2,462-product native kernel compiles/links through the maintained
frontend; CTF merge and runtime/debug split also pass. Actual link order/flags
match Make, recorded inputs are hash-bound, all allocated sections survive
postprocessing, and original Make postprocessing of identical native inputs is
byte-exact. The initial missing socket audit-header dependency was fixed locally.
See FULL-KERNEL-LINK-QUALIFICATION.md. This is not complete independently compiled
Make-kernel parity, installation or boot/runtime acceptance. Those gates plus
modules, other configurations/architectures, world, packages, bootstrap and
performance remain open; Make stays production/default.

## LLDB CLI milestone (2026-11-02)

The original one/five-source programs, two generated option headers, native
shared dependency closure, safe loader/pre-initialization tests and ten
installation records now pass. Direct compiler objects preserve original Make
link order. Every allocated object/program section matches independent explicit
filename-policy Make controls; original baselines/rejected archive links remain.
LLDB-CLI-QUALIFICATION.md records actual input, link, SDK and scoped cache proof.
Next: family aggregate and inherited MK_LLDB selection/package ownership;
debugger execution, upstream suite, cross/static variants and full world stay open.

## LLDB family milestone (2026-11-02)

The native debugger subset now composes three independently qualified components
with original order and separate installation contexts: fifteen records, three
safe wrappers and exact prior immutable payload hashes. Existing LLDB/tests
selection supports a zero-payload disabled family and rejects an explicitly
requested all-incompatible suite. Four original Make parent controls pass; fresh
recursive world inventory observes 2,128 directories, not compilation coverage.
See LLDB-FAMILY-QUALIFICATION.md. Next: reconcile actual selected product/action
and aggregate coverage. sbin/mount_virtiofs already has a native graph and
October 26 component evidence; later recursive selection is not a missing-native
proof. Full world/bootstrap/package ownership and debugger execution remain open.


### printenv selected original test/package gap (2026-11-02)

The selected printenv program/test graph now preserves actual Make PIC/warning
policy, all four original cases and separate utility/debug/test installation
contexts. Native default and TESTS-off products match eight/five Make records;
object/program allocated sections and all 73 consumed dependency occurrences
agree. Legal non-shell environment names exposed an original shell-variable
oracle defect, corrected by a complete-byte comparison to native env with no
filtering. A missing ATF tr dependency was caught after green XML and fixed
before qualification. See PRINTENV-QUALIFICATION.md. This bounded completion
adds no full-world, cross-architecture or final-package completion claim.

## I2C/SMBus module milestone (2026-11-02)

Qualified 39 selected amd64 GENERIC leaves spanning controllers, buses, devices
and muxes: 51 actual compiles/5,089 original consumed prerequisite occurrences,
39 ordered initial links and 117 plain/CTF-debug installation records. All plain
artifacts are exact respective Make references: 37 untouched originals plus two
independent canonical-filename controls whose four actual recipes differ only
by one explicit map and whose 382 prerequisites agree. Existing SDT sections
and relocations are exact. No runtime/Make/helper/CLI policy changed. See
I2C-MODULES-QUALIFICATION.md. Discovery coverage is 357/729 local BUILD leaves,
not a qualified percentage; 372 still lack local BUILD declarations in this
selection. Remaining configurations, architectures, actual bus/controller/input/
RTC/sensor behavior, aggregate world/pkgbase/bootstrap, VM and performance gates
remain open. The six existing family provider regressions passing each profile
are regression evidence, not I2C hardware execution or strict-loader proof.

## Sound module milestone (2026-11-02)

Closed the ten remaining local-BUILD gaps in the reviewed selected amd64 sound
subtree: forty actual compiler actions, 6,239 original consumed prerequisites,
ten ordered initial links and thirty plain/CTF-debug installation records pass.
All ten plain modules match untouched Make byte for byte; CTF/debug and compiled
PCM SDT sections/relocations match the stated contracts. Seven KOBJ and three
existing AWK header producers remain native and declared. An initial duplicate
computed-name header view was rejected before compilation, then corrected to
reuse the existing providers. See SOUND-MODULES-QUALIFICATION.md.

Discovery now observes 367/729 local BUILD leaves, with 362 still missing in this
selection. This count neither qualifies every existing declaration nor replaces
full-world/cross-architecture/module/pkgbase/bootstrap/publication gates. Audio
playback/capture/MIDI/mixer, hotplug/error paths, live probes, hardware and
CPU/memory/disk I/O/disk-use/cache/sandbox performance remain open. Make stays
production/default; BIP remains excluded.


### Internal rescue replacements (2026-11-02)

Native librescue now preserves seven regular/seven PIE own objects, both internal
archive products, Make's no-install contract and direct-object consumer interface.
Two independent configurations match object payloads/relocations/symbols and
1,694 consumed dependency occurrences. This closes the bounded internal library
product gap, not full rescue: crunchgen generation, all crunched application
variants, static linking, aliases/scripts/install and safe/guest runtime gates
remain. HESIOD-enabled SDK/header preparation is an explicit configuration gate.
See LIBRESCUE-QUALIFICATION.md.

## USB cohort milestone and genuine Make fix (2026-11-02)

Qualified 63 remaining selected amd64 USB leaves: 99 ordinary compile contexts
and four firmware compile contexts, 13,412 consumed prerequisite occurrences,
63 ordered initial links and 189 plain/CTF-debug file-install records pass. All
plain files match respective Make references: 62 untouched originals plus fresh
corrected i2ctinyusb. Its real duplicated SRCS/OBJS produced duplicate module
registration/sysinit; original compiler argv is unchanged and corrected Make/
native each have one entry. Old artifacts/failures are retained.

Firmware blobs and registration C are produced by declared native uudecode/AWK
actions; original firmw.S uses explicit cc_library additional_compiler_inputs
for .incbin payloads, then the existing object-alias rule preserves .fwo names.
Twenty previous sound artifacts remain byte-identical with the helper default.
Actual successful partial-run compilers reused by the accepted retry are bound
from original logs, not invented cache spawns. See
USB-REMAINING-MODULES-QUALIFICATION.md for exact evidence and retained failures.

Discovery now observes 430/729 local BUILD leaves, leaving 299 missing in this
selection. Existing BUILD presence is not a qualified percentage. USB device/
controller/WLAN/storage/input/video/serial/gadget and firmware runtime, live
probes/audit, cross/KERNCONF/FDT and aggregate world/pkgbase/bootstrap/publication
gates remain open, along with CPU/memory/disk I/O/disk-use/cache/sandbox checks.
Make stays production/default; BIP remains excluded.

## Remaining firmware reference checkpoint (2026-11-02)

Read-only source queries now cover all 299 remaining selected amd64 leaves.
Selection by actual nonempty FIRMWS identifies 38 modules, 59 images and 111
object contexts. This includes LiquidIO's fourteen real driver C objects as well
as its firmware registration/embedding; it must not be reduced to a data-only
module. All 76 original Make build/install controls pass, sequentially with
sixteen jobs per control. No host installation occurs.

`/usr/obj/usr/src/bazel-remaining-module-source-facts-r1-20261102` retains the
complete missing-leaf query. `bazel-firmware-module-make-references-r1-20261102`
under the same object root contains original controls;
`bazel-firmware-module-source-facts-r1-20261102` binds actual compiler/producer
recipes and payload hashes. Twenty-four inputs are uudecoded; thirty-five are
raw, including two Otus copies whose original source and copied bytes agree.
Original FIRMWS specifications preserve omitted, dotted and hexadecimal version
spellings and image order. No filename/family-based producer guesses are needed.

Next: implement and qualify native composition of decode/raw inputs, original
AWK registration, declared .incbin inputs, original ordered driver objects and
module/debug/install stages. A native macro draft is retained as design material,
not implemented or qualified production code. Required gates are real per-context
compiler/input and link audits, payload/generated-source equality, plain and
CTF/debug/install parity, prior firmware regressions and honest configuration/
runtime limits. These 38 modules still count as missing native declarations;
coverage remains 430/729 local BUILD leaves. Hardware/firmware-loading, complete
world/cross/pkgbase/bootstrap/publication and performance gates remain open.


### Rescue tool and dispatcher generation (2026-11-02)

The original native crunchgen, declared cwd/runtime and explicit object metadata
now produce the default 103-program/39-alias dispatcher with no Make invocation.
C bytes, three normal compiler objects, program ABI/allocated payloads, actual
input/link chains and five tool installation records match original controls;
ten native wrapper targets pass (nine analysis negatives and six runtime methods
inside one fixture wrapper). See RESCUE-DISPATCH-QUALIFICATION.md. The 592 original
application object names remain descriptors: actual RESCUE/static/NOSSP source
variants, generated stubs, crunchide transforms, complete static link/aliases/
script installation and runtime/package matrices remain required. No full rescue
or complete option/architecture/world coverage claim is added.


### Remaining FIRMWS module qualification (2026-11-02)

The preceding reference-only checkpoint is superseded by the implemented and
qualified native firmware composition. All 38 remaining selected FIRMWS modules
now declare their 59 image inputs and original ordered registration/driver links.
All 111 compiler contexts and 38 links pass actual input reviews. Plain modules
match 37 untouched Make references and one independently checked LiquidIO
filename-policy control; CTF/debug payload and all 114 installation records match.
Four prior USB firmware artifacts remain byte-identical. The six existing provider
tests pass in each profile; these are not firmware-loading or hardware tests.
See FIRMWARE-MODULES-QUALIFICATION.md for evidence and configuration limits.

Local BUILD presence is now 468/729 selected amd64 leaves (261 missing), not a
whole-system qualification percentage. Complete rescue application/static linking,
remaining module families, ARM64/RISC-V, aggregate pkgbase/hardware/bootstrap,
publication, VM/runtime and CPU/memory/disk I/O/cache/sandbox gates remain open.
Add maintained automatic parameter-file capture before later build profiles:
current proof preserves exact hash-verified recovered parameter bytes, not an
implemented frontend capture guarantee. Make remains production/default; BIP is
excluded. Existing format-5 build-bsd/backend inputs cover this composition; no
CLI, signing, staging or publication policy change is needed for this cohort.

### Rescue direct-stub checkpoint (November 2)

Original crunchgen direct output and declared native entry-stub groups are
qualified: 103 files equal actual original Make echo recipes, with unchanged
default dispatcher/cache/Makefile bytes and fresh tool/install checks. See
[direct-stub evidence](CRUNCHGEN-DIRECT-STUBS-QUALIFICATION.md). Next production
gates are genuine per-application RESCUE objects, original crunchide/relocatable
transforms, complete static link and rescue installation/package/runtime.
Generating 103 stubs does not count those applications as compiled.


### ISP and Myricom module qualification (2026-11-02)

Eleven additional selected amd64 leaves now use native C/module composition:
six ISP firmware selections, four Myricom firmware modules and its network driver.
All eleven plain modules are byte-identical to untouched Make outputs; CTF/debug,
33 installation records, eleven actual compiler contexts/1,008 prerequisites and
eleven initial links pass. Nine firmware array headers are declared inputs.
Original runtime C and Makefiles are unchanged. See
CARRAY-FIRMWARE-MODULES-QUALIFICATION.md for evidence and qualification limits.
Local BUILD presence is 479/729 selected leaves (250 missing), not a qualified
whole-system percentage. Six existing provider tests pass in each profile; no
firmware loading/hardware claim. Cross-architecture, complete world/rescue/pkgbase,
bootstrap/publication, VM and performance/cache/sandbox gates remain open.
Existing build-bsd format-5/backend helpers cover this composition without a new
CLI, helper extension, signing/staging or publication policy. Make remains the
production/default build. BIP stays excluded.


### libalias and NTB module qualification (2026-11-02)

Fifteen more selected amd64 leaves use native C/KOBJ and module helpers: eight
libalias core/extensions and seven NTB core/hardware/transport/network/tool modules.
All fifteen plain binaries are byte-identical to untouched Make references;
CTF/debug, 45 installation records, 21 actual compilers/2,793 prerequisites and
fifteen initial links pass. Original export policies are retained, including
libalias/ntb/ntb_transport EXPORT_SYMS=YES. No runtime C or original Makefile change.
See ALIAS-NTB-MODULES-QUALIFICATION.md for scoped evidence and remaining gates.
Local BUILD presence is 494/729 selected amd64 leaves (235 missing), not a
whole-system qualification percentage. Six existing provider tests pass per
profile; protocol behavior, module loading, hardware, KTR variants and live
tracing remain open. Whole world/rescue/cross/pkgbase/hardware/bootstrap,
publication, VM/runtime and CPU/memory/disk I/O/cache/sandbox qualification remain
required. Existing build-bsd C/format-5/backend helpers cover this composition
without new CLI, helper extension, signing/staging or publication requirements.
Make remains production/default. BIP stays excluded.

### Real rescue object checkpoint (November 2)

Three source-owned RESCUE application variants (cat/echo/head) plus crunchide's
three tool objects pass original Make allocated/relocation/symbol and actual
compiler policy/input checks. Ordinary tool installation metadata also passes.
[Evidence](RESCUE-CORE-OBJECTS-QUALIFICATION.md) explicitly keeps successful
stub-plus-application ld-r/crunchide transformation, static dispatcher/runtime
and complete rescue installation/package coverage open. Raw Clang input rejection
is preserved; it is not a successful transformation or reason to relax the tool.


### FireWire and Hyper-V module qualification (2026-11-02)

Twelve additional selected amd64 leaves now use native C/assembly/KOBJ module
stages. All twelve plain binaries match untouched Make byte-for-byte; exact CTF
bytes, debug CRCs and 36 installation records pass. Thirty-eight original executed
compiler contexts/4,853 prerequisites and twelve actual ordered links are bound;
final CTF-only results reuse prior compilations, with no invented cached spawns.
The original VMBus custom assembly recipe skips ctfconvert. A per-group boolean
convert_ctf defaults true and participates in the global kernel setting; false
preserves that recipe and cannot override global disable. All 22 prior ISP/Myricom
module artifacts remain byte-identical. The frontend manual records the exception.

Shared FireWire source/header ownership moved into its package with the old root
header target retained as a native alias. fwcontrol/dconschat are built separately
with the userland SDK: executable sections match except debug links, manifests/
manuals are unchanged and debug CRCs validate. Archives/DWARF differ; full byte
identity is not claimed. Rejected analysis/mixed-toolchain/CTF/archive-equality
attempts are retained with diagnosis. See FIREWIRE-HYPERV-MODULES-QUALIFICATION.md.

Local BUILD presence is 506/729 selected amd64 leaves (223 missing), not a whole
system qualification percentage. Original export policies are retained. Six
existing provider tests pass per module profile; hardware/loading/live probes,
other options/architectures and complete world/rescue/pkgbase/hardware/bootstrap,
publication, VM/runtime and CPU/memory/disk I/O/cache/sandbox gates remain open.
During ARM qualification, review/fix the existing Hyper-V Make branch that uses
SRC instead of SRCS for its architecture sources; current evidence is amd64 only.
Existing build-bsd C/format-5/backend inputs cover the composition; no new CLI,
signing/security, staging or publication contract. Make remains production/
default; BIP is excluded. Automatic parameter capture remains a frontend gate.


### NVMe-oF, TCP and kernel-test modules (2026-11-02)

Thirteen more selected amd64 leaves use native C/module stages: four NVMe-oF,
four TCP and five ktest modules. Twenty-nine compiler contexts/4,803 consumed
prerequisites and thirteen actual ordered links pass. All thirteen plain modules
match respective Make references byte-for-byte: eleven untouched originals and
two independently checked BBR/RACK filename-policy controls. Sixteen original/
control recipes and 3,218 prerequisites differ only by one source-path-derived
macro map. Original noncanonical-path differences are retained; no final artifact
normalization or production source/compiler-policy change. CTF bytes/debug CRCs
and 39 file installation records pass, including original package=tests for the
five test modules and package=kernel for the other eight. Export policy retained.

Static registration checks preserve 34 compiled ktest cases, including twenty
enabled HPTS functional cases, not merely its disabled warning stub. None is
claimed executed. The example Python wrapper skips two intentional failures;
matching-guest VM qualification must report skips and explicitly test failure
reporting. Six existing provider test targets pass per build profile; these do
not demonstrate protocol/storage/kernel-test runtime behavior. See
STORAGE-TCP-KTEST-MODULES-QUALIFICATION.md for bounded evidence and open gates.

Local BUILD presence is 519/729 selected amd64 leaves (210 missing), not a whole
system qualification percentage. ARM64/RISC-V, alternate KERNCONF/options, actual
loading/ktest/NVMe-oF/TCP/live-probe behavior, complete world/rescue/pkgbase/hardware/
bootstrap/publication, VM and CPU/memory/disk I/O/cache/sandbox gates remain open.
Existing build-bsd C/format-5/backend/helper inputs already carry this composition
and package tags; no new CLI/manual behavior, signing/security, staging or
publication requirements. Make remains production/default; BIP is excluded.


### IPMI, storage, one-wire, PWM and VMware modules (2026-11-02)

Fifteen more selected amd64 leaves now use native C/KOBJ module stages: IPMI and
its Linux compatibility module; MFI core/Linux/CAM; MRSAS core/Linux; one-wire
bus/temperature/GPIO controller; PWM bus/controller; VMware PVSCSI/VMCI/VMXNET3.
Forty-four compiler contexts/5,098 consumed prerequisites and fifteen original
ordered links pass. All fifteen plain modules match untouched Make byte-for-byte;
CTF bytes/debug CRCs and 45 file installation records pass. Original export and
package=kernel policies are retained. No runtime C, Makefile or common helper
change. Three Linux modules reuse the existing declared machine/../linux header
view; only dependency edges and narrow visibility extend. Rejected initial
missing-view compilation is retained; failed spawns are excluded from evidence.
See DEVICE-FAMILIES-MODULES-QUALIFICATION.md for exact scope and retained proofs.

Local BUILD presence is 534/729 selected amd64 leaves (195 missing), not a whole
system qualification percentage. Six existing provider test targets pass in each
profile; they do not establish device/Linux-ioctl/hardware behavior. FDT-enabled
PWM and other option/architecture variants, actual loading, live probes, complete
world/rescue/pkgbase/hardware/bootstrap/publication, VM and CPU/memory/disk I/O/
cache/sandbox qualification remain open. Existing build-bsd C/format-5/backend
inputs carry these relationships; no new CLI/manual behavior, signing/security,
staging or publication requirement. Make stays production/default; BIP excluded.

### Rescue combined-object milestone (November 2, 2026)

Three actual application objects now pass the original stub-first relocatable
link and basename-sensitive crunchide pipeline, with 6 actual compiler actions,
135 consumed inputs, 3 links/transforms and 12 accepted suite members (2 fresh
negative tests; 10 cached results). [Evidence](RESCUE-COMBINED-OBJECTS-QUALIFICATION.md)
retains exact runtime object proof and identical-input whole-file controls;
DWARF path bytes differ explicitly. Next: real bounded static rescue dispatcher
and safe application execution, then all selected applications/static libraries,
full rescue install/package and option/architecture coverage.

### Bounded static rescue execution (November 2, 2026)

[Real cat/echo/head subset](RESCUE-CORE-PROGRAM-QUALIFICATION.md): native main,
three hidden objects, libutil/libc/compiler_rt and startup link successfully;
whole main/binary bytes equal original generated Make using those same native
library/startup inputs. Ten actual runtime methods pass; two consumed-input
inventories total86 occurrences. This does not close full world/library or rescue
install/package parity. Next correct the existing libutil cc_library's missing
Make standard/pipe/fno-common/warning policy, qualify its archive/DSO and repeat
core tests, then expand the complete rescue application/static-library closure.

### Libutil compiler policy and SDK refresh (November 2, 2026)

[Qualified correction](LIBUTIL-COMPILE-POLICY-QUALIFICATION.md): 68 original Make
normal/PIC recipes, 3,778 original and actual native consumed-input occurrences,
all compiler-object allocated sections/nondebug relocations, 72 unchanged
representative default actions and keys, four PIC fixture methods and eleven
real bounded rescue methods. A fresh maintained SDK explicitly snapshots the
new default-disabled small-PIC feature; no historical receipt was rebound.
Before/after native DSO/archive runtime sections are unchanged and rescue ELF
bytes exact. Remaining library work: Make member order (including pw_scan),
section-archive versus separate provider/DOF and final DSO payload/installed-test
parity. Then expand real rescue applications, static libraries, selected options,
complete installation/pkgbase and full world/bootstrap; this bounded correction
does not close those gates.

### Real eight-program rescue integration (November 2, 2026)

[Evidence](RESCUE-EIGHT-PROGRAM-QUALIFICATION.md): five more original RESCUE
variants add 11 application objects and a genuine no-header expr Yacc producer;
current 17 compiler actions have 691 consumed occurrences per side. One generated C
pair differs only 38 exact #line filename fields. Eight original stub/link/hide
pipelines match runtime sections/relocations/symbols, with one explicit pwd
filename control; 21 actual runtime methods pass. An identical-input original
Make control reproduces main, eight stubs/hidden objects and the complete static ELF.
Next expand the remaining selected applications/static libraries and preserve
actual generator, object order, per-source policy, aliases and installation
contracts. All 103 programs, full independent world/library parity, rescue install/
pkgbase, options/architectures/bootstrap/hardware/publication remain open;
libutil's archive/provider/final DSO and installed-test gates remain separate.

### Real fourteen-program rescue integration (November 2, 2026)

[Qualification](RESCUE-FOURTEEN-PROGRAM-QUALIFICATION.md) adds six original RESCUE
variants, including five actual DTrace header/provider transformations. Six raw
and transformed object contracts, 314 consumed input pairs, complete DOF schemas/
relocated sites/encoding, actual ordered links and 31 runtime methods pass.
Original generated Make on identical accepted native objects/archives/startup
reproduces the entire static ELF. Continue remaining actual rescue applications
and library dependencies, selected options and original standalone tests, then
complete rescue install/pkgbase and world/bootstrap. The full 103-program graph
and independent full-library/installed-test parity are not closed by this subset.

### Module inventory early source context (November 2, 2026)

[Context and checks](MODULE-INVENTORY-CONTEXT.md): recursive audits now supply
normal kernel SYSDIR and MODULE_TIED inputs before leaf parsing. The maintained
Bazel test passes all 11 Python methods, including real Make under a custom
source root. Refreshed selections remain amd64 729 / ARM64 627 / RISC-V64 553;
amd64 local BUILD presence is 628, leaving 101 selected leaves without one.
The pending network cohort's first six source-lookup failures are retained;
repeat original controls with the actual kernel source context before native
conversion. No accepted native artifacts or full-system gates are inferred from
selection, and no build-bsd CLI/signing/publication change is required.

### Network/routing/entropy modules (November 2, 2026)

[Qualification](NETWORK-SERVICES-MODULES-QUALIFICATION.md): 37 more selected amd64
leaves, 188 actual compiler contexts and exactly 32,362 consumed original/native
dependency occurrences per plain/CTF profile; actual ordered parameters retained.
All 37 plain ELF files match untouched Make bytes; all CTF/debug payloads and
CTF data match, with valid debug CRCs and 111 original installation records.
ENA's physical include namespace is explicitly declared; netlink's nested CTF
sort paths are an optional validated native rule input. Four actual-rule analysis
negatives and the existing CTF executable regression pass; 108 default-path
outputs are unchanged. All 22 compiled SDT/DTrace module sections are preserved.
Local BUILD presence is now 665/729, leaving 64; it does not close architecture,
full kernel/world/rescue/library/pkgbase, bootstrap/runtime or performance gates.
No build-bsd CLI, signing or publication policy change; Make remains default.

### Real nineteen-program rescue integration (November 2, 2026)

[Qualification](RESCUE-NINETEEN-PROGRAM-QUALIFICATION.md): five actual traced
file-operation variants add six C objects/398 consumed pairs and unlink. Two
original one-map filename controls, six rewritten objects, five complete DOF/
relocated-site comparisons, actual link order and 43 runtime methods pass.
Original generated Make with identical accepted inputs reproduces the entire
static ELF. Initial wrong cp -n expected status is retained; test-only correction
matches source and leaves ELF bytes unchanged. Next close the genuine original
static-library/provider/order gate or first new library dependency, remaining
applications, original test suites and installed rescue/mv helper/pkgbase paths;
full world/bootstrap/publication/resource gates remain open.

### RDMA/InfiniBand/Mellanox modules (November 2, 2026)

[Qualification](RDMA-MODULES-QUALIFICATION.md): fourteen more selected amd64 leaves,
206 actual uncached compiler contexts and exactly 83,230 original/native consumed
dependency occurrences per plain/CTF profile. All actual ordered link parameters
are captured. Thirteen plain ELFs match untouched original Make files; iSER
matches an independent one-map original filename control (ten exact compiler
vector comparisons, ordinary originals retained). All CTF/debug data and CRCs
and 42 installation records match corresponding controls. Original iSER header
precedence is preserved by ordered provider composition; default helper vectors
and 39 other-module outputs remain unchanged. Four compiled SDT/DTrace modules
retain exact sections/relocations. Local BUILD presence is 679/729 (50 remain),
not full-system completion. No frontend CLI/signing/publication policy change;
Make remains default and cross-target/full world/kernel/packages/runtime and
performance gates remain open.

### Chelsio modules and complete option coverage (November 2, 2026)

[Qualification](CHELSIO-MODULES-QUALIFICATION.md): eleven selected amd64 leaves,
50 compiler contexts and exactly 11,730 original/native consumed occurrences per
plain/CTF profile. All eleven plain ELFs are whole-file exact untouched Make;
CTF/debug payloads/CRCs and 33 install records match, with actual ordered link
parameter captures. Four compiled SDT/DTrace modules retain exact sections.
A supplementary option observer's directory/KMOD and host-helper coverage bug
was found and corrected: mandatory object-driven coverage now agrees with full
compiler inputs (Chelsio127, network365, RDMA554 option occurrences). No native
artifact/input result was changed; correction diagnostics retain old behavior.
BUILD presence is 690/729 (39 remain), not full qualification. No helper/runtime/
Make/frontend/signing/publication policy change; full architecture/world/kernel/
packages/bootstrap/runtime/performance gates remain open and Make stays default.

### Independent libutil static archive gate (November 2, 2026)

[Qualification](LIBUTIL-STATIC-ARCHIVE-QUALIFICATION.md): fresh original Make
35-member archive/order/provider contract, 34 exact C allocated payloads and
35 exact nondebug relocation sections; all nine DOF sections and actual probe
site accounted for with independently verified path keys. Actual archive action
order and all member hashes bound; eight maintained contract methods pass.
Default DSO/rescue and explicit experimental archive/DSO regression bytes match.
Keep default CcInfo anchored-provider static-consumer semantics as the next
independent gate; full DSO/installed tests, untraced modes, full rescue/packages
and runtime/performance remain open. Existing format-5 workflow only; Make default.

### Default libutil static-consumer gate (November 2, 2026)

[Qualification](LIBUTIL-STATIC-CONSUMER-QUALIFICATION.md): original missing-provider
and native over-extraction defects corrected with the existing retained-anchor
mechanism and lazy provider import. Two complete ordered extraction graphs match
corrected original Make. All 68 actual normal/PIC compilers, 3,778 consumed
occurrences, 35 component members and actual anchor/archive producers are bound;
56 actual test methods pass without credential changes. Shared ELF metadata
passes; full DSO payload/install, arbitrary CcInfo ordering and DTrace host
provenance/cache hermeticity remain open. Make remains default.

### libutil DSO allocated-payload gate (November 2, 2026)

[Qualification](LIBUTIL-DSO-PAYLOAD-QUALIFICATION.md): actual link controls isolate
misordered pw_scan and missing original local-symbol discard. Two native
declarations repair these; corrected allocated sections match original Make
except fully accounted DOF path encoding and verified actual linked sites.
Each mode preserves 68 actual compiler controls; unaffected archive/consumers/
rescue remain byte-identical. Default 56 and experimental 43 methods are cached
accepted results. Whole/debug/install/original ATF, arbitrary CcInfo and full
world/package/runtime/provenance gates remain open; Make remains default.

### Compatibility/storage/tracing modules (November 2, 2026)

[Qualification](COMPAT-SERVICES-MODULES-QUALIFICATION.md): eighteen more amd64
leaves, 130 actual compiler contexts and 26,206 exact consumed occurrences per
profile; actual ordered links, whole-file untouched-Make plain parity and 54
installation records pass. Seven compiled SDT/DTrace modules retain exact
sections/relocations. Explicit existing architecture views fix eight original
Linux-header consumers; attempts and fresh SDK provenance are retained.
BUILD presence is 708/729, leaving 21, not full qualification. Complete debug,
architecture/world/kernel/packages/bootstrap/runtime/performance gates remain
open; existing build-bsd format-5 workflow applies and Make stays default.

### Wireless/crypto/EFI/SGX runtime-artifact qualification

[Work record](FINAL-DRIVERS-MODULES-WORK.md): all 42 original controls for the last
21 selected amd64 leaves pass. Eighteen native declarations pass both profiles:
455 compiler contexts and 159,574 consumed prerequisite occurrences per profile,
complete original object identities/order, installation metadata and runtime
ELF/CTF comparisons. All eighteen plain modules are byte-identical. Both RTWN
microcode settings additionally pass 101-context original/native reviews per
profile and actually change runtime code. Local declaration presence is 726/729;
Linux64/OpenSSL/VMM still lack native declarations. Separate DWARF/source lookup,
nondefault configurations and full world/kernel/cross-target/pkgbase/bootstrap/
runtime/cache/performance gates remain open. No C/shared-rule/frontend-C changes
are required: the maintained typed setting interface carries the new RTWN flag,
and its producer/manual are updated together. Make stays production/default.

### OpenSSL crypto module runtime-artifact qualification

[Qualification](OSSL-MODULE-QUALIFICATION.md): nineteen actual compiler contexts
(ten C, nine checked-in assembly), 821 consumed occurrences and nineteen option
headers pass per profile. Plain whole-file equality, CTF/runtime sections, debug
CRCs, complete ordered object identities and installation manifests pass against
original Make. Local declaration presence is 727/729; Linux64 and VMM remain.
Separate DWARF, runtime crypto/dispatch, alternative settings, cross targets and
full-system/cache/performance gates remain open. Existing native helpers and
normal format-5 frontend inputs suffice; no new frontend/manual policy is added.

### VMM native module and layout-producer qualification

[Qualification](VMM-MODULE-QUALIFICATION.md): both profiles pass 185 actual module
compiler contexts, 15,693 consumed occurrences, 204 option-header occurrences,
complete original object order, installation and runtime ELF/CTF comparisons.
The full plain module is byte-identical. Two actual layout compilers/extractors
per profile preserve original common-symbol policy, 227 consumed occurrences and
full generated-header equality; helper objects are excluded from module linkage.
The bhyve native consumer build and actual affected source/header/link inputs
pass after physical-package label relocation. Local declaration presence is
728/729; Linux64 remains. Separate DWARF, live VM execution, alternative settings,
cross targets and full-system/pkgbase/bootstrap/cache/performance gates remain
open. Existing rules/format-5 frontend suffice; no new C/helper/manual option.
