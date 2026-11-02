# Native Bazel completion plan

Resumed by user instruction on 2026-11-01 after the committed upgrade
checkpoint (`7ffc0048161`). The target is complete base-system Make coverage
and a complete native Bazel system build, not BUILD-file presence. Make
remains supported for ports and third-party software. BIP remains out of scope.

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
