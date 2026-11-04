# Native Bazel completion plan

## Current CTF linker checkpoint (2026-11-03)

LLD section integration is implemented. Fresh verified SDKs now pass normal
maintained build-bsd/Bazel nullfs profiles on AMD64, ARM64 and RISC-V. The strict
CTF/export/debug-split tests actually execute (112/112/114 associations and
fourteen named-type checks per architecture). Actual selected SDK/tool actions
are reviewed on all three architectures.

Native Bazel now builds LLD and passes its 138 section/graph/script cases and
ten symbol/thunk/reference cases. Its first run exposed an SDK/compiler versus
source-built LLVM runtime collision in a test. Explicit per-child runtime
selection fixes that collision; every regression assertion remains intact.
BEP outputs and both executed tests are retained. The rebuilt exact-version
upstream converter now verifies the native action chain from eight relevant
source compilations through the PIC archive, LLVM shared library, LLD and both
executed tests. Failed and corrected symbol tests use identical linked inputs.

Shared test-runner runtime inheritance still needs an audit beyond these fixed
harnesses. Independent refreshed Make controls, debugger/runtime, compression/
footprint, complete LLVM/bootstrap, world/kernel, packaging/publication,
sandbox/cache and broad performance acceptance remain open.

Current CTF output is uncompressed v3: tested full modules grow about 37 KiB,
about 13-15%. Compression/footprint and broad CPU/memory/I/O/disk gates remain
open. Limited no-CTF controls show no regression. See CTF-NAMESPACE-UNION.md.
This supersedes chronological entries saying LLD is not connected. Full system
and publication gates remain open. Make stays default; BIP is excluded. No host
upgrade, installation into the running system or reboot occurred.

## Storage module checkpoint (2026-11-03)

Twenty-three shared storage module leaves per ARM64/RISC-V architecture and
two ARM64-only Linux compatibility children pass native builds and artifact
review. The shared components cover 92 plain/CTF variants, 380 compiler
contexts/55,888 canonical consumed pairs, 184 ordered links and 138 installation
records. Forty-two of 46 plain artifacts equal untouched Make bytes; four equal
explicit identical-source filename controls. CTF/runtime contracts retain that
42/4 distinction. All 46 shared separate DWARF files differ; source/debugger
qualification remains open.

Complete recursive MFI/MRSAS comparisons cover eight family variants and all
24 installation records, including the two ARM64 children. The children add
four compiler contexts/546 consumed pairs and eight ordered links. Family
records overlap component records; they are not extra installation coverage.
Original amd64 controls qualify MMC/consumer exports and MRSAS compiler policy.
Twelve actual positive/negative provider tests pass across six profiles.

The changes preserve real Make compiler options, forced headers, generated
schemas, exports and child selection. The normal format-5 build-bsd workflow
uses 16 CPUs and a disk reserve. Its C frontend needs no new command-line option.
No C implementation or probe changed. Full world/cross kernels, separate DWARF,
package publication, runtime, bootstrap/sandbox and performance gates remain
open. Make remains production/default; BIP remains excluded.

See [the storage qualification record](CROSS-STORAGE-BUSES-QUALIFICATION.md).

## Cross-target network protocol checkpoint (2026-11-03)

Twenty-eight selected network protocol/interface module leaves per architecture
pass ARM64/RISC-V builds and artifact checks. Fifty of 56 plain modules equal
untouched Make bytes; six equal explicit identical-source canonical-filename
controls. CTF/runtime checks retain the same 50/6 distinction. The review
covers 344 actual compiler contexts/55,296 canonical consumed pairs, 224 ordered
links and 168 installation records. It preserves WireGuard's forced header,
TCP-specific defines and Netlink's relative CTF object paths. A missing tuntap
generated-header prerequisite and localized TCP timer API exports are corrected
in maintained Make and native metadata. Twelve actual provider tests pass
across six profiles, including amd64 regressions. Separate DWARF, runtime,
full-system and performance gates remain open. See
[CROSS-NETWORK-PROTOCOLS-QUALIFICATION.md](CROSS-NETWORK-PROTOCOLS-QUALIFICATION.md).

## Cross-target I/O-bus checkpoint (2026-11-03)

Sixty-one selected GPIO/I2C/1-Wire/PWM/SPI module leaves per architecture pass
ARM64/RISC-V Bazel builds and artifact checks. Of 122 plain modules, 110 equal
untouched Make bytes; 12 equal explicit identical-source canonical-filename
controls. CTF/runtime checks retain the same 110/12 distinction. The review
covers 340 actual compilers/34,550 canonical consumed pairs, 488 ordered links
and 366 install records. A real 1-Wire export defect is fixed in both backends
and additionally qualified on amd64. All twelve positive/negative provider
tests pass. Separate DWARF, runtime and performance gates remain open. See
[CROSS-IO-BUSES-QUALIFICATION.md](CROSS-IO-BUSES-QUALIFICATION.md).

## ARM64/RISC-V USB core/peripheral checkpoint (2026-11-03)

Twenty-two USB core/controller/storage/peripheral modules on each of
ARM64/RISC-V pass four normal build-bsd profiles/provider tests and 88 original
Make controls. All 44 plain modules match whole-file bytes; 44
CTF/runtime/debuglink comparisons, 240 actual compilers/30,264 canonical
consumed input pairs, 176 ordered links and 132 original installation
records/payload bindings pass. Target FDT adds usb_fdt_support.c; a real cp2112
Make prerequisite omission is corrected in both build descriptions. Separate
DWARF/source lookup and device/runtime/performance gates remain open. See
[CROSS-USB-CORE-MODULES-QUALIFICATION.md](CROSS-USB-CORE-MODULES-QUALIFICATION.md).

## ARM64/RISC-V USB serial/input checkpoint (2026-11-03)

Twenty-nine USB serial/input module leaves on each of ARM64/RISC-V pass four
normal build-bsd profiles/provider tests and 116 original Make controls. All 58
plain module bytes match; 58 CTF/runtime/debuglink comparisons, 116 actual
compilers/15,232 canonical consumed input pairs, 232 ordered links and 174
original installation records/payload bindings pass. Actual parent-exported
Make options, GENERIC KERN_OPTS and 64 regular Makefiles are retained alongside
the explicit empty configuration sentinel. Separate DWARF/source lookup and
device/runtime/performance gates remain open. See
[CROSS-USB-INPUT-MODULES-QUALIFICATION.md](CROSS-USB-INPUT-MODULES-QUALIFICATION.md).

## ARM64/RISC-V input module checkpoint (2026-11-03)

Twenty-six input modules per architecture pass original Make comparison on
ARM64 and RISC-V: 52 exact plain modules, 52 CTF/runtime/debuglink checks, 120
actual compilers/13,522 canonical consumed input pairs, 208 ordered links and
156 original installation records/payload bindings. Four maintained
provider-test profiles pass, checking required callbacks and deliberate
localization defects. KOBJ schema provenance comments are the only permitted
generated-input content differences and remain explicit; standalone
DWARF/source lookup remains open. See
[CROSS-INPUT-MODULES-QUALIFICATION.md](CROSS-INPUT-MODULES-QUALIFICATION.md).

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

### Linux64 native generated-input and module qualification

[Qualification](LINUX64-MODULE-QUALIFICATION.md): both profiles pass 34 actual
module compilers, 5,004 consumed occurrences and forty selected kernel options.
Three native helpers per profile preserve original flags and 140 consumed
occurrences. The layout header, five syscall outputs and complete 5,392-byte
VDSO are exact original payloads; actual compiler/extractor/generator/link/image/
incbin dependencies are independently bound. Plain full-file module equality,
CTF/runtime/debug CRCs, complete ordered links and installation pass. The initial
missing architecture-header declaration and observer -Wa classification failures
are retained and corrected. Existing format-5/backend workflow and updated manual
carry the graph without frontend-C inputs; no C/Make source changes are added.

All 729 selected amd64 directories have BUILD files, but inspection of the
actual top-level declarations finds 690 generic and 38 firmware module producers:
728/729. ZFS has headers and separate built-in kernel rules, with no loadable
module producer. Implement and qualify that missing module; directory presence
must not stand in for module-target coverage.

The [Linux64 original/changed/restored check](LINUX64-INCREMENTAL-QUALIFICATION.md)
now passes actual generated-image/embedding invalidation and exact original-byte
restoration in a clean isolated object-root checkout. Next refresh the complete
current GENERIC kernel and aggregate module build, and continue original userland
install/test/package closure. Cross-target world/kernel/modules, other options,
complete pkgbase/hardware/publication, bootstrap, source/debug lookup, sandboxing,
VM/runtime and measured CPU/memory/disk/cache gates remain part of the full
objective. Make stays production/default; BIP is excluded. Individual profile
parity is not full completion.

## libutil original test/install closure (2026-11-03)

The [bounded original test/install gate](LIBUTIL-TEST-INSTALLATION-QUALIFICATION.md)
now supplies all twelve owning Make-selected programs and their 25 installed
test/debug/Kyuafile payloads plus five tagged directories. Sixteen compiler
contexts/740 consumed pairs and all twelve final allocated ELF payloads match
the separately audited original filename-policy control. All 31 native test
rules pass; the zero-status wrong-value TAP negative is rejected. TESTS-off
removes exactly that subtree and preserves 124 runtime/dev records and payloads.
The safe fork-failure correction preserves EAGAIN and prevents kill(-1); the
existing Kyua environment attribute now reaches constructors while preserving
unmentioned inherited environment. Make remains production/default. Continue
actual world install/package closure; full independent library/debug/source
lookup, other options/architectures and the broad completion gates above remain.

## ZFS loadable module closure (2026-11-03)

The [native ZFS module](ZFS-MODULE-QUALIFICATION.md) passes two normal build-bsd
profiles against fresh original Make: 261 actual compiler contexts, 68,785
consumed input occurrences and 261 selected options each, plus complete ordered
compiler/CTF/alias-to-link identities. Whole-file plain equality, CTF/runtime
sections, split-debug CRCs and all installation records pass. The unchanged
sources preserve all eight compiled SDT sections/relocations. Original module
policy is separate from built-in kernel objects; no C/Make/shared-rule/frontend-C
change is introduced. The source declaration inventory is now 729/729 amd64
leaves (691 generic, 38 firmware). This supersedes the prior ZFS missing-producer
checkpoint, not the outstanding full-build gates.

Next refresh the current full GENERIC kernel and aggregate selected module
build; continue the missing stand boot-program/library world closure in parallel
with userland installation/pkgbase work. ARM64/RISC-V/configuration, world/rescue,
bootstrap, hardware/combined publication, debugger source lookup, sandboxing,
VM/runtime and measured CPU/memory/disk/cache qualification remain required.
Make stays production/default; BIP stays excluded.

## First native legacy boot products (2026-11-03)

Fresh maintained world recursion retains 2,128 selected directories, including
52 in stand. The [first seven real products](LEGACY-BOOT-QUALIFICATION.md) now
have source-owned native compile/link/install composition. Seven complete ELF32
objects and flat images are exact original bytes; all actual flags, ten consumed
pairs and six original installation records match. Seven host unittest methods
pass without executing an image. The original expression is preserved through
response-file quoting; successful cached witnesses remain explicitly bound to
the rejected first profile's individual successful actions. No global helper/
toolchain/SDK policy changes. Continue the remaining BIOS/EFI/kboot/library and
full world/rescue/pkgbase graph, cross/options/bootstrap, boot/runtime and broad
completion gates above; directory presence or raw equality is not boot/security
qualification. Make stays production/default.

## Current full GENERIC compiled parity refresh (2026-11-03)

The [new current-source full build](CURRENT-KERNEL-REFRESH-QUALIFICATION.md) passes
normal build-bsd and fresh controlled original Make. All 2,462 object code,
allocated metadata/payloads and CTF bytes match. Both full/runtime kernels pass
56 allocated contracts (55 exact payloads plus validated build-ID note), 96,147
loader symbols and merged CTF; native debug positive/negative checks and original
CRC pass. Before/after source bindings and actual original dependency coverage
are retained, including explicit earlier helper-source hashes supplementing the
initial failed audit. External Make prerequisites, standalone DWARF/source
lookup and general cache/toolchain hermeticity are not declared complete.

Next aggregate all 729 amd64 module producers and installation/pkgbase closure;
continue actual stand/boot2, world/rescue and cross-architecture/configuration
coverage. Bootstrap, hardware/combined publication, sandboxing, VM/runtime and
controlled CPU/memory/disk/cache qualification remain required. Make stays
production/default; BIP stays excluded. This is current compiled parity, not a
booted installed system or full-goal completion.

## Complete selected amd64 aggregate (2026-11-03)

The [combined request](AMD64-AGGREGATE-MODULES-QUALIFICATION.md) passes the current
full kernel and all 729 selected amd64 modules with CTF/debug: 2,191 targets and
3,649 captured output records. All module ELF/debuglink CRCs and producer/install
payload bindings pass; all component destinations are collision-free. The real
mac_ntpd compile failure is fixed by reusing its existing precise capability
header provider; failed build and inspection records remain retained. Default
component paths and package-pair consistency are not full original installation
or pkgbase parity. Full aggregate installation/package closure remains next.

Continue actual userland library/program/stand/rescue closure and ARM64/RISC-V
native architecture coverage. The last maintained cross selections contain 627
ARM64 and 553 RISC-V leaves; current literal declaration inspection recognizes
216 and 214 respectively, not successful-build counts. Cross firmware/driver and
architecture-specific generated inputs remain real work. Bootstrap, hardware/
publication, debugger source lookup, sandboxing, VM/runtime and controlled CPU/
memory/disk I/O/cache qualification remain required. Make stays production/default;
BIP remains excluded. This checkpoint supersedes earlier aggregate-build TODOs.

### Boot2 producer closure and directory installation checkpoint (2026-11-03)

Added the actual selected boot/boot1/boot2 chain: seven i386 compile objects,
ordered internal BTX crt0, original nm/AWK header generation, selected linker/
objcopy and source-built btxld, size checking/padding/concatenation. Corrected the
existing btxld target's missing original policy through normal source-owned
objects/direct program linkage, preserving its public/install/archive labels.
Eleven actual compiler contexts bind 310 consumed pairs; five ordered links and
seven complete generated outputs match original policy/bytes. Nine original
install records preserve file/directory ownership and distinct package tags;
the missing original /boot record is represented through first-class
bsd_install_directory using the existing provider/manifest/archive protocol.
Six host artifact methods pass and previous legacy archive bytes are unchanged.
Retained source/recipe/cached-action proofs, first rejected tool-policy and
missing-directory comparisons, and explicit separate DWARF/source lookup/boot
limits are in [BOOT2-QUALIFICATION.md](BOOT2-QUALIFICATION.md). No final package,
publication or runtime/boot qualification follows. Continue portable library/
program closure and proper ARM64/RISC-V target/execution SDK support; this
architecture-specific BIOS cohort is not cross-world coverage.

## ARM64/RISC-V routing module checkpoint (2026-11-03)

The [four routing/diagnostic modules](CROSS-ROUTING-MODULES-QUALIFICATION.md)
dummymbuf, fib_dxr and dpdk_lpm4/6 now pass both architectures and plain/CTF-debug
settings: eight whole-file plain matches, eight CTF/runtime/debuglink comparisons,
24 original install records, 24 actual module compilers/3,056 consumed pairs and
32 ordered links. The first real missing ARM64 CK dependency is corrected with
an explicit original-consumed source-header view; no C/Make/shared-rule/frontend
policy changes. Original parallel-log interleaving and overridden RISC-V default
flags are handled with per-object Make metadata and actual compiler-driver proof,
not ignored. Separate DWARF/source lookup, complete architectures/world/pkgbase,
bootstrap/publication, VM/runtime and controlled performance/cache/sandbox gates
remain open. Existing format-5 --arch profiles carry this cohort. Make stays
production/default; BIP stays excluded.

## ARM64/RISC-V firmware module checkpoint (2026-11-03)

The [shared native firmware pipeline](CROSS-FIRMWARE-MODULES-QUALIFICATION.md)
now covers seventeen selected ARM64 and twelve RISC-V leaves. Four normal
build-bsd profiles and all 58 original Make controls pass: 29 whole-file plain
matches, 29 CTF/runtime/debuglink checks, 87 install records, 140 actual compiler
contexts/5,108 consumed pairs and 116 ordered links. All 82 embedding instances
bind exact payload bytes and explicit .incbin input digests; 29 registration and
20 decode actions bind original sources/specifications. All 38 current amd64
module/debug/install captures remain byte-identical after the shared refactor.
No C/assembly/AWK/Make/compiler-policy or security change. Existing format-5
architecture selection carries the cohort. Separate DWARF/source lookup,
complete cross/world/pkgbase/bootstrap/hardware/publication, runtime and controlled
performance/cache/sandbox gates remain open. Userland target/exec SDK separation
continues independently with fresh receipts after receipt-bound tool changes.
Make stays production/default; BIP stays excluded.

### 2026-11-03: actual userland target/execution SDK separation

Maintained SDK-only preparation explicitly selects amd64/ARM64/RISC-V real
world profiles and composes cross targets with an independently validated native
execution SDK. Fresh native-r3 validates 16,712 bindings; only intentional
conditional RISC-V ccconfig bytes differ from native-r1. Existing native and
kernel role policy is retained; cross tests require the host artifact provider.
Original cross header floors were repaired through maintained private-sysroot
header recipes, with fresh cross original references afterward. Two maintained
policy test targets pass (15 settings/18 inventory direct methods; 10 reference
option methods separately pass). See USERLAND-SDK-QUALIFICATION.md. Actual
three-architecture bz2/bzip2 component evidence is a separate bounded gate;
full world/rescue/pkgbase/foreign execution/bootstrap remain incomplete.

### 2026-11-03: genuine libbz2/bzip2 production closure on three ABIs

Normal format-5 amd64/ARM64/RISC-V profiles pass actual production builds,
source-owned original-order regular/PIC archives and default static CcInfo
extraction, actual shared/program links and component installation archives.
All 45 production CPP contexts/995 original-native consumed pairs, 42 archive
members, nine ordered link sequences, six linked allocated payloads and 54 original
component installation records pass independent Make comparison. All nine
declared tests pass without skips/foreign execution. Strict final review caught
real omitted executable-link -gz=zlib despite green initial tests; final r3
preserves original compressed DWARF, and the maintained host test rejects all
three real earlier outputs. Actual debuglink/CRC checks are distinct from open
separate DWARF/source lookup parity. See BZIP2-THREE-ARCH-QUALIFICATION.md.
Next real package-family gate is bzip2recover original policy/installation plus
the existing packages/bzip2 aggregate and real pkgbase outputs on selected ABIs;
full world/rescue/bootstrap/foreign runtime and publication remain incomplete.

### 2026-11-03: selected bzip2 recovery/package family on three ABIs

The next component gap is closed: actual recovery production/installation and
four selected pkgbase outputs pass three normal profiles and independent
original Make package recipes. All 48 production contexts/1,040 consumed pairs,
nine allocated linked payloads, twelve actual links, 66 original component
records→57 composed records and sixteen declared tests pass. Six prior component
archives are unchanged whole bytes. Default-off identical-directory composition
preserves every metadata field and rejects file collisions. Ordinary Make
package stage timestamps versus declared native epoch zero and separate DWARF
source lookup are retained distinctions; no package archive byte-equality claim.
See BZIP2-FAMILY-QUALIFICATION.md and its hash-bound summary. Complete selected
world/rescue/pkgbase, dependency solver/installation, bootstrap, foreign runtime
and publication remain incomplete; this is the selected four-package profile.

### 2026-11-03: actual libz and three-package family on three ABIs

The selected lib/libz gap now has original-order regular/PIC archives, genuine
default CcInfo extraction, DSO, generated metadata and original installation
records. Three normal profiles pass 96 production compiler contexts/3,648
consumed pairs, three allocated DSO comparisons, ten links, 33 install records,
nine independent original package comparisons and seven declared tests. The
initial SDK/project header identity rejection is preserved and corrected.
See ZLIB-THREE-ARCH-QUALIFICATION.md. Package timestamp policies and separate
DWARF/source lookup remain explicit; this is not full world, bootstrap, foreign
runtime, installation or publication qualification. Broader libz consumer
rebuilds remain a full-world gate because CTF tools consume this library.

### 2026-11-03: private zstd library, command and packages on three ABIs

The next selected compression dependency now has genuine original-order regular
and PIC archives/default CcInfo extraction, private DSO, eleven-source CLI and
four actual packages per ABI. All 233 compiler contexts/9,937 consumed pairs,
200 archive members, six linked allocated payloads, nine core links, 57 original
install records→54 unique records, twelve package comparisons and five declared
tests pass. RISC-V's original extra runtime C source is retained. Ordinary
references remain untouched: 206 objects match allocated bytes, while 27
filename-sensitive objects require separately audited original one-map controls.
The final ARM64 link correction preserves its original Cortex-A53 policy;
other architecture branches remain empty. See ZSTD-THREE-ARCH-QUALIFICATION.md.
Separate DWARF/source lookup, alternate options/upstream suites, package-manager
installation, full-world/rescue/bootstrap and foreign runtime remain open.
Cross libmd/liblzma/xz and the larger libarchive stack remain distinct gaps.

### 2026-11-03: complete original cross-kernel baselines and SDK selection

ARM64/RISC-V original GENERIC kernels and private staged installations pass;
2,035/1,194 selected products plus three auxiliary generators each have actual
compiler/dependency/producer review (408,447 canonical consumed pairs).
The four-header crypto provenance control and explicit assembly firmware input
are retained distinctions. Source-derived policy grouping identifies 37 ARM64
and 19 RISC-V compiler groups. The maintained format-5 backend now accepts a
matching composite target/native execution SDK, with 17 settings tests and
three real SDK snapshot checks. See CROSS-KERNEL-BASELINE.md. No full Bazel
cross-kernel claim: next implement precise owners, intrinsic-header policies,
source-derived DTS version, generated inputs and ordered links/installations,
then compare complete native outputs before module/pkgbase/runtime/performance.

### 2026-11-03: genuine three-ABI libmd prerequisite for XZ

The inherited amd64-only libmd graph now models actual default amd64/ARM64
optimized and RISC-V portable source selections. Explicit regular/PIC archives
serve installation, default CcInfo extraction and the DSO. Three normal profiles
pass 158 compiler contexts/4,762 consumed pairs, 158 archive member bindings,
three DSO allocated comparisons, six link contracts and 381 library records.
Twenty-eight genuine native static/shared digest tests and three host archive
tests pass. Initial SSP/header-origin policy failures are retained and fixed.
Ordinary references retain twelve filename-sensitive contexts; three separately
checked original one-map controls prove full allocated/relocation parity without
rewriting bytes. See LIBMD-THREE-ARCH-QUALIFICATION.md. Nondefault optimization,
bootstrap, foreign runtime, separate DWARF, recursive installed-test producer
parity and full runtime/tests packages remain open. The liblzma/XZ four-package
family is staged privately and still requires its own native qualification.

### 2026-11-03: native common cross-kernel compilation foundation

Source-owned built-in helpers preserve ARM64/RISC-V policies separately from
KLD modules. The first 46/48 common sources and ARM64 crypto wrapper pass 282
object configurations, 19,054 consumed pairs and explicit source-derived DTS
header checks. All 141 plain objects are byte-equal to matching original plain
controls; 141 raw CTF payloads and all allocated/symbol/relocation contracts
match. Eight normal profiles pass ten declared tests. The public C++ archive
API fixes a genuine composite host-tool declaration defect; libc++ dynamic/static
runtime and native member-order checks pass. See CROSS-KERNEL-COMMON-QUALIFICATION.md
and its hash-bound summary. Next expand precise built-in owners and generated
producers across the full config inventory, then complete ordered cross-kernel
links/installations and cross-module/pkgbase aggregates. Separate DWARF,
configuration breadth, bootstrap/sandbox/cache, actual boot/runtime/upgrades
and CPU/aggregate memory/disk I/O/usage remain gates. Make remains production;
BIP remains excluded.

### 2026-11-03: XZ/liblzma commands and package family on three ABIs

The libmd prerequisite is now consumed by genuine native liblzma, xz, xzdec and
lzmainfo producers on all three ABIs. Three normal profiles/captures pass
561 production contexts/46,575 consumed pairs and 63 real static-command test
contexts/5,079 pairs, with strict distinct SDK versus public source API origins.
All twelve production ELF metadata/allocated payloads match untouched originals;
468 archive members, fifteen actual links/generated outputs, 49-to-44 install
records per ABI, twelve actual package comparisons and nineteen independent
native/original runtime comparisons pass. Three declared artifact tests pass.
The ordinary installed archive is the default CcInfo input. Rejected test-PIE,
DSO pthread, production header-origin and shared-root dependency policies remain
retained. See XZ-THREE-ARCH-QUALIFICATION.md. Separate DWARF/source lookup, foreign
execution, i386/alternate options, full-world/rescue/bootstrap, package solver/
installation/publication and measured performance remain gates. The earlier
XZ-pending entries are historical checkpoints; the larger libarchive stack and
complete selected world still need independent closure.

### 2026-11-03: ARM64/RISC-V VM built-in cohort

Four maintained profiles and independent Make controls qualify 24 selected VM
sources per architecture: 96 object configurations/13,740 consumed input pairs,
48 byte-identical plain objects, 48 exact CTF payloads and exact runtime
sections/symbols/relocations throughout. Ten options per architecture come from
the selected config; vnode interfaces remain declared producers. Source hashes
and 122 existing lexical instrumentation markers are retained. See
CROSS-KERNEL-VM-QUALIFICATION.md. Full cross-kernel linking, remaining owners,
configuration breadth, separate DWARF/source lookup, boot/runtime, packages,
bootstrap/sandbox/cache and comparative performance remain open. The private
next network candidate is not counted as qualified coverage. Make remains
production; BIP remains excluded.

### 2026-11-03: BSD XML prerequisite on three ABIs

The selected libbsdxml default normal/PIC archives, DSO, generated headers,
public API/default static extraction and eight install records per ABI pass
three ordinary profiles. Strict review binds 30 production contexts and 1,020
consumed pairs; original archive order and nine actual links pass. Five tests
pass, including two native parser executions. Six filename-sensitive xmlparse
contexts retain untouched-original rejections and match three independent
original controls with exactly one macro-prefix map; the other 24 objects
match untouched originals. All three DSO metadata/allocated contracts match
controls. See BSDXML-THREE-ARCH-QUALIFICATION.md. This is a runtime component,
not an invented standalone package. Next substantive libarchive closure needs
source-owned ARM64/RISC-V libcrypto inventories, architecture assembly/flags,
ordered normal/PIC archives and default consumer/provider semantics, preserving
selected OpenSSL/FIPS/KTLS/DTrace/iconv. Recursive providers/engines, separate
DWARF/source lookup, foreign execution, full world/bootstrap and pkgbase remain
gates. Make remains production; BIP remains excluded.

### 2026-11-03: ARM64/RISC-V network built-in cohort

The selected sys/net and sys/netinet lists now qualify 175 products through
four maintained profiles: 350 runtime object matches, 175 whole-byte plain
objects and 175 exact CTF payloads. The 54,306-pair input ledger separately
records 54,280 raw exact pairs and 26 independently reproduced KOBJ header
path-policy pairs. Existing C/runtime instrumentation is unchanged (89 distinct
sources, 124 lexical marker lines). See CROSS-KERNEL-NETWORK-QUALIFICATION.md.

Next kernel gates include composite SDK host-tool closure for KOBJ, remaining
owners and configs, complete source/generator/link closure and boot/runtime.
The debug source follow-up must replace the private prototype with public
artifact/provider based archive and mapping outputs, package identity binding,
and maintained frontend integration. Validate actual primary/inline/generated/
SDK text after relocation and with execution trees unavailable. ARM64 private
inline-header lookup succeeded; RISC-V ET_REL debugger relocation is unresolved
and requires linked-artifact qualification. No debug package completion claimed.
Full world/pkgbase/hardware publication, bootstrap/sandbox/cache and comparative
CPU/memory/disk I/O/usage gates remain. Make stays production; BIP is excluded.

### 2026-11-03: reproduced composite KOBJ runtime defect

The unchanged ARM64 composite networking profile failed with the native loader
rejecting target libc in BSDKobjInterface. Inspection also finds foreign
libc/libsys declarations under the RISC-V SDK. Source defaults are corrected
to execution-runtime labels, retaining execution-configured source libm.
Corrected ARM64/RISC-V composite profiles pass: 175 whole-byte plain objects,
175 bound compiler contexts, 27,140 raw exact input pairs, 13 independently
controlled KOBJ provenance pairs and 89 explicit ARM64 DTS header additions.
Five ARM64 KOBJ actions execute; two RISC-V consumed header members are cached
and independently checked. Other execution declarations (CTF/modules, RPC,
device IDs, locales, crunch, boot images and callers) require role classification
and composite qualification; intentional target ABI inspection stays target data. See KOBJ-EXECUTION-RUNTIME-QUALIFICATION.md.
This does not close complete host sandbox, source/debug, cross-kernel/link,
world/package/bootstrap/cache/runtime or comparative resource/performance gates.

### 2026-11-03: selected core-owner qualification closed

All 212 ARM64 and 209 RISC-V core-owner products, including layout auxiliaries
and source-decoded firmware, pass four maintained composite-SDK profiles.
Independent Make controls establish 842 runtime object matches, 421 byte-exact
plain objects, 414 exact CTF payloads and seven matching CTF absences. The input
ledger preserves 103,782 raw exact pairs, 212 independently regenerated KOBJ
provenance pairs, 424 explicit DTS header additions and two separately checked
firmware binary inputs. Six declared tests pass; all 212 primary sources and
existing instrumentation remain unchanged. See CROSS-KERNEL-CORE-QUALIFICATION.md.
Initial missing MSI/PIC header views and an observer pre/post-CTF mismatch are
retained with their explicit corrections. The existing frontend contract handles
these native source targets; no CLI, package or signing interface change occurs.
Next kernel work includes remaining source/generator owners, ordered full links,
configuration breadth and execution-runtime helper classification. Source/debug
packages, bootstrap/sandbox/cache, full world/pkgbase/hardware, boot/runtime and
comparative CPU/memory/disk I/O/usage remain gates. Make stays production;
BIP remains excluded.

### 2026-11-03: execution versus target library role audit

The static follow-up classifies 538 literal SDK references in 185 files:
380 intentional target inputs, 148 host-runtime candidates, six shared-variable
references requiring separate host/target lists, and four unresolved data-flow
references. Actual ELF inspection confirms eight foreign SDK/library pairs
cannot be loaded as native runtime libraries. These are inspected declarations,
not 148 executed failures or complete label coverage. See
KOBJ-EXECUTION-RUNTIME-QUALIFICATION.md and its standard-object-root audit ledger.
The unchanged composite nullfs CTF path reproduced two native converter
failures loading ARM64 libc. The isolated two-helper correction is applied;
corrected ARM64/RISC-V host runtime selection passes (ten executed actions,
74 native ELF inputs). Complete target artifact qualification remains rejected. Preserve target test runtimes, target drti and package
ABI inputs; review FIDL and remaining generator families individually. Existing
frontend/SDK interfaces cover the proposed correction; no new CLI or package
contract is introduced. The runtime selection fix is qualified only for those selected host actions.

### Immediate kernel gate: refresh and qualify foreign bootstrap tools

The new strict composite nullfs review caught wrong ARM64 CTF associations,
including SDT probe/provider data, at export localization. Source/history review
finds the robust identity-preserving objcopy fix already committed in d7f9be55deb;
its 65-case maintained format suite exists. Do not reinvent pipeline ordering
or the previously rejected fuzzy-merge workaround. The unchanged native r4 SDK
passes all 65 cases; both foreign r4 tools fail the localization case.

Refresh ARM64/RISC-V bootstrap objcopy through its maintained cross-tools
source-owner recipes, with all available CPUs and guarded resource budgets.
Rebuilding the LLVM bootstrap library is separate from installing it: replaying
the full cross-tools library installation over a completed foreign sysroot can
replace target libraries with native bootstrap libraries. Derive the XMAKE
context from the recorded profile, build libllvm without installing it, then
build and stage only the objcopy/strip programs. Hash the complete target
header/library inventory before and after; require it to remain unchanged.
Coordinate world/tmp mutations
with original-reference controls. Generate fresh SDKs/receipts; retain r4 inputs
and failures unchanged. Run the existing semantic/format suite for each SDK's
actual selected tool, then rerun real module/CTF/export/debug/install profiles
and cache checks. Make source already contains the correct objcopy algorithm;
foreign staged tools require refresh and behavior qualification. Version strings
and hashes alone cannot prove the needed capability. Full native Bazel toolchain
bootstrap and declared regression coverage for every selected SDK remain gates.
Separate DWARF/source lookup, remaining runtime helper families, whole-system
production/runtime and comparative performance remain open.


### 2026-11-03: selected-default libcrypto core checkpoint

The native AMD64/ARM64/RISC-V core producers now have source-owned ordered
normal/PIC lists, architecture assembly/ISA policy, target-derived buildinf,
explicit installed archive providers and shared whole-PIC linkage. Actual input
and link receipts bind all 5,826 production contexts. Independent original
controls add only the recorded filename-map flag: all allocated bytes and
runtime relocations match; all DSO symbols match. RISC-V raw object symbols
remain unequal only in 300,356 exhaustively classified local offsets into
nonallocated debug sections (1,868 objects). This is not raw Make byte parity
or completed debug qualification. The untouched filename rejections remain.

Each ABI core install manifest matches 6,465 original metadata records through
physical hardlink equivalence; 6,460 fixed source payloads are exact. AMD64 runs
the real static/shared API tests; foreign profiles run host artifact inspection
without executing foreign ELF. See LIBCRYPTO-CORE-THREE-ARCH-QUALIFICATION.md.
Existing format-5 frontend/SDK/install interfaces cover this checkpoint; no new
CLI, signing, packaging or publication fields are required.

Next close default recursion: engines, providers, FIPS tests, libssl, openssl
CLI and complete component/package ownership. Do not disable Make recursion,
produce a partial OpenSSL package, or count core-only qualification as selected
world completion. Separate debug/source lookup, alternate options, foreign
runtime, native toolchain bootstrap and performance remain open.


### 2026-11-03: ARM64 bootstrap tool refresh closes format gate

The maintained bootstrap source-owner rebuild/install completed for ARM64's
native objcopy. All 65 format regressions pass on its actual newly staged bytes.
The initial inventory rejection is retained; exactly its separate native program
debug file changed under usr/lib, and follow-up checks prove that install output
against the new build while every other target header/library entry is unchanged.
RISC-V refresh is active, not yet qualified. Both frozen r4 SDKs remain unchanged.
See KOBJ-EXECUTION-RUNTIME-QUALIFICATION.md for hashes and actual evidence.

Next finish the RISC-V refresh, construct fresh composite SDKs and qualify their
selected tools, then rerun real module export/CTF/debug/install and cache paths.
Add a declared cross-module semantic test: the existing AMD64 whole-module audit
cannot establish foreign ET_DYN coverage. Preserve original failures and compare
against independently refreshed original controls. Full-system/bootstrap/debug/
performance gates and Make production/default policy remain unchanged.


### 2026-11-03: final shared-link CTF regression remains open

Both refreshed foreign-stage objcopy tools pass all 65 format checks. A fresh
ARM64 composite SDK is materialized and passes its own format checks; the new
RISC-V composite SDK is not yet materialized. Explicit host artifact tests now
inspect real target module full/runtime pairs. Native passes all 112 association
checks and 14 policy object checks; actual ARM64 fresh-SDK and RISC-V native-SDK
kernel frontend profiles reject CTF links to SYMTAB. Their failures are retained.
A controlled captured-action replay independently isolates final LLD shared
linking: both lose sh_link and RISC-V corrupts 106 object associations.

Next correct exact symbol/type association preservation in the linker and
qualify independent refreshed Make controls and actual native/foreign profiles.
Account explicitly for the initial multi-input relocatable link plus maintained
ctfmerge; no fuzzy matching, output patching, CTF disabling or relaxed acceptance.
See CROSS-MODULE-CTF-QUALIFICATION.md. No LLD fix or complete module acceptance
is claimed. The native Bazel parser/copy suites pass 37 methods.

The normal frontend now uses independent OS copy offload for duplicate SDK and
private repository-cache files, with mandatory identical snapshot verification.
The copy/cache helpers are bound in receipts; all seven copy methods pass and
16,179 actual ARM64 snapshot paths plus independent regular-file inodes verify.
The initial disk-guard interruption remains rejected, followed by fully verified
cache reuse. This is storage-copy correctness, not comparative performance.
No config schema, SDK staging helper, signing, packaging or publication change
is introduced. Keep Make production/default and BIP excluded.


### 2026-11-03: correct the CTF checker before linker extraction

Independent producer/ctfdump checks disproved the proposed per-function padding
change to objcopy. The semantic checker was wrong for consecutive packed v2
function associations; its single-record fixture masked the defect. Corrected
it, added subsection alignment checks, and replaced the misleading fixture with
16 format/alignment combinations. Normal build-bsd/Bazel executes all 30 CTF
methods successfully, and explicit-tool independent/semantic checks pass 129
cases. Previous-reader rejection and proposed-padded-fixture failure remain
retained. See CTF-SEMANTIC-CHECK.md for source bindings and qualification scope.

Still OPEN: local libctf init_symtab's inconsistent v2 width/record rounding;
exact linker symbol provenance and final CTF sh_link/association preservation;
initial multi-input CTF link/merge handling; full module and system acceptance.
No linker fix, producer change or completed world/kernel build is claimed.
No frontend schema or production-default change is required for this checker
correction. Keep Make production/default and BIP excluded.


### 2026-11-03: shared CTF symbol-association foundation

Extracted the ObjCopy container rewriter into LLVM Object CTFSymbolTable so
linker work can share one owning parser with exact original symbol identities.
Make and Bazel source ownership are updated. ELF policy and the unchanged opaque
fast path remain in ObjCopy. No type-graph merger or LLD fix is implemented yet.

Independent review also found and reproduced the old identical-payload/different
header-boundary bug in all eight format combinations. Fixed the unchanged
check; the rebuilt native bootstrap tool passes 137 format checks and the
explicit-library API diagnostic passes 160 checks. Source-owner Make builds,
source/library/tool bindings, first failed compilation, unchanged staged tool
and 16 GiB disk reserve are retained. See tests/ctf/LOCALIZATION.md and
/usr/obj/usr/src/bazel-ctf-shared-helper-review-r1-20261103.

Next: integrate exact input-file/index provenance with final LLD symtab order,
preserve CTF section links, solve the initial multiple-input-container contract,
and qualify refreshed original controls and actual modules across all three
architectures. Native Bazel LLVM API/bootstrap qualification is still required;
these explicit-tool diagnostics do not substitute for it. Full world/kernel,
packages, runtime and performance gates remain open; Make stays default.


### 2026-11-03: qualify disjoint CTF namespace relocation before LLD hooks

LLVM Object can now union self-contained v2/v3 dictionaries into a valid v3
namespace using exact container/index provenance. It relocates all supported
record layouts and internal/external string references; preserves cycles,
duplicate names and root flags; and rejects unrepresentable label/parent cases.
String interning avoids copying unused ELF strings. All source association refs,
including discarded symbols, are validated. This is not type deduplication.

Normal build-bsd/Bazel tests now qualify the source-built Object/Support API
(160 checks), semantic reader (30 methods), and union graph suite (1,024 graphs,
256 source-built ctfdump controls, 16 negatives and layout/resource controls).
Make-library and Bazel drivers serialize all 1,024 compared cases identically.
Source bindings, prior rejected attempts and resource recovery are retained.
See CTF-NAMESPACE-UNION.md for scope, evidence and normal test labels.

The union is NOT CONNECTED TO LLD yet. Next implement exact selected-definition
provenance, section/script placement, final symtab ordering and CTF links, then
qualify refreshed original controls plus real native/foreign module pipelines.
No module acceptance, complete bootstrap/world/kernel, package/publication or
performance qualification is claimed. Make stays production/default; BIP stays
excluded. Keep signed/staged SDKs immutable and refresh through normal helpers.

### 2026-11-03: LLD exact symbol provenance, not final module acceptance

Selected input indices now follow definitions through COMMON conversion,
version copies, replacement and wrapping, without increasing SymbolUnion.
No-CTF files use a decision bitset and allocate a transient index map only for
same-file collisions; CTF files retain exact index maps for later output work.
The initial all-global map cost time/memory in a 200,000-symbol diagnostic and
was replaced. Final samples show no regression on that limited workload;
whole-system performance gates remain open.

The maintained source-owner LLD build passes with frozen sources and no install.
An existing same-file weak/strong section-selection bug is reproduced by the
old tool and fixed by the candidate. Eight payload/binding/size regression cases
and 16 baseline link controls pass. A native Bazel source-built linker test is
declared but not yet executed. See CTF-NAMESPACE-UNION.md for exact scope.

Next: script-respecting CTF section synthesis, correct final output symbol order,
output section links and refreshed native/ARM64/RISC-V real module checks.
No final-link CTF, complete world/kernel or publication acceptance is claimed.
Make stays default. BIP remains excluded. No host upgrade or reboot authorized.

### 2026-11-03: exact CTF layout size without dictionary serialization

Added shared size planning with the same identity/overflow validation as symbol
rewriting. It counts real packed function records, unknown associations and
alignment without copying/compressing the dictionary. Final order still must be
used for serialization. Normal frontend/Bazel tests pass: 328 API checks and
1,024 union graphs actually run; semantic suite is cached. The first two suites
use native source-built LLVM components. See CTF-NAMESPACE-UNION.md.

Next remains LLD synthetic section placement, participation in layout before
final offsets, final symbol ordering and sh_link, then refreshed real module
qualification. Sizing alone does not satisfy any final module/world/kernel gate.
No frontend configuration or security-policy changes are needed at this step.

### 2026-11-04: selected EFI libsa matrix on AMD64, ARM64 and RISC-V

Private ARM64 (259 objects) and RISC-V (263 objects) now reuse the regular source
inventory and the same 69 verifier sources. Platform selections retain the real
wchar, machine include and soft-float/general-register ABI differences. Shared
flag definitions remove duplicated option lists. The selected regular/private
matrix has six archive contexts; it is not a count of new programs or libraries.

Both foreign archives pass complete member-order/symbol comparisons, generated
header and actual compiler/archive bindings. Only three assertion filename
members differ in raw allocated bytes; isolated original compiler controls
explain all three. Regular archive bytes remain unchanged. See
LIBSA-CROSS-EFI-QUALIFICATION.md for retained evidence and exact profile limits.

A repeat on the final flag factoring correctly refused a changed HyperTrace SDK
origin after dev advanced to a914137016e. Preserve that failure and the immutable
previous captures. Fresh native/cross SDKs were prepared with maintained
plan/staging helpers. All three current-input frontend repeats pass and preserve
both archive byte hashes. The changed SDK update reran all 451 native compilers;
that coarse invalidation is not a warm-cache pass. Old receipts and origin
checks remain intact. See SDK-VERIFICATION-QUALIFICATION.md.

The maintained frontend now performs bounded parallel full-content verification
using --jobs, with receipt-bound file/byte/worker/hash-phase timing records.
Native Bazel runs 43 methods covering corruption, concurrency, settings and test
inventory. No digest cache or input-check suppression was introduced. Narrowing
freestanding compiler inputs and measuring SDK materialization/CPU/memory/physical
I/O remain required; parallel hashing alone does not qualify performance.

Next: actual loader entry and final EFI links.
Complete world/rescue/cross kernel/module, installation/debug, runtime/boot,
bootstrap/sandbox/cache, pkgbase/hardware/combined publication and CPU/memory/disk
performance gates remain required. The broad SDK input/validation overhead is
still open. No VM, installation, upgrade or reboot occurred. Make stays default;
BIP remains excluded. No frontend C switch or policy default changed.

### 2026-11-04: first EFI loader construction reference

The maintained AMD64 loader reference passes at
`bazel-efi-loader-amd64-make-r1-20261104`, with 58 actual object recipes,
REPRODUCIBLE_BUILD explicitly enabled and BUILD_UTC explicitly selected. It
produces the full/debug/stripped symbol files, PE image and installation records.
Its link still consumes the existing world SDK's three private EFI archives;
this is an entry-object/generator reference, not a closed whole-loader oracle
or a native Bazel loader build.

Next carry the actual font, help and version generators into declared actions,
then entry objects and final links. The existing newvers.sh still collects host
metadata even when -r suppresses it; remove that unnecessary dependency while
preserving Make output. PE epoch must be a declared input; the current recipe's
maintained 2024 timestamp default is reference policy, not a value to embed in a
new generator. Close the original-library link inputs before asserting complete
loader parity or boot qualification. All broader completion gates remain open.

### 2026-11-04: native loader font and ordered help

The actual source-built execution converter and maintained AWK script now produce
font/common/FDT-help artifacts on all three target configurations. Generated font
and common help match the actual Make reference, and all three output sets have
identical hashes. Native ELF/runtime and full configured input/action reviews
pass. Seven methods execute natively and are reused by foreign profiles; cached
results are not counted as fresh executions. See LOADER-GENERATORS-QUALIFICATION.md.

The native runtime audit was corrected to inspect transitive dependencies. The
foreign audit was corrected to attest cached producers using exact configured
actions and input hashes. Production outputs or tests were not changed to hide
those diagnostic assumptions. Final helper search paths exclude Python data
directories. No new frontend C switch or input format was needed.

Next: maintained-script version generation with declared tools/output/build
metadata, then real entry objects and final links. Preserve the version script's
ordinary Make interface and output while removing metadata-only calls from -r.
Continue the full installation/debug, world/rescue/cross kernel/module,
bootstrap/sandbox/cache, publication, runtime and CPU/memory/disk gates.
Make stays default; BIP remains excluded. No installation or reboot authorized.

### Native loader version generation (2026-11-04)

The maintained version script now runs as a declared native Bazel action for
AMD64, ARM64 and RISC-V. Original-script byte comparisons, seven focused methods
and metadata change/restoration checks pass. Typed format-5 settings select
reproducible output or an explicit metadata source label; no host identity or
test metadata is selected by default. See
[LOADER-VERSION-QUALIFICATION.md](LOADER-VERSION-QUALIFICATION.md).

Next: actual loader entry objects and final native links, then installation/debug
and runtime qualification. All complete world/kernel/module, bootstrap/sandbox,
package/publication and performance gates remain open. Make stays default.
