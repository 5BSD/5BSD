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
checks. Remaining WPA private libraries/programs and wireless/service behavior
are open. The next upgrade checkpoint records prepared common/control-client
Make references, which require post-upgrade revalidation. All remaining work
and final completion requirements below apply.

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
