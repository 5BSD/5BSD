# Native loader FDT libraries (2026-11-03)

## Native graph and scope

`//stand/fdt:static_archive` builds the complete selected ten-unit common
archive: nine vendor libfdt sources and fdt_loader_cmd.c. The separate
`//stand/efi/fdt:static_archive` builds efi_fdt.c. Both preserve Make member order,
freestanding architecture flags and their distinct regular/private EFI verifier
policy. Header contexts are explicit source-owned declarations derived during
migration from the three actual Make dependency inventories. No Make query,
prebuilt archive or generated Make file enters native compilation.

FDT introduces no new generated configuration in these components. Direct target
selection makes the libraries available; feature selection for the completed
loader/world aggregate remains separate work. Independent Make references
explicitly select FDT and foreign EFI references select the matching EFI policy.
No source runtime implementation was rewritten. The userland lib/libfdt remains
a separate context and is not substituted for the standalone archive.

## Builds and independent comparisons

All evidence paths below are under `/usr/obj/usr/src`.

| Target ABI | Final maintained frontend run | Independent common reference | Independent EFI reference |
| --- | --- | --- | --- |
| amd64 | `bazel-loader-fdt-amd64-r5-20261103` | `bazel-loader-fdt-common-amd64-make-r1-20261103` | `bazel-loader-fdt-efi-amd64-make-r1-20261103` |
| aarch64 | `bazel-loader-fdt-aarch64-r1-20261103` | `bazel-loader-fdt-common-aarch64-make-r1-20261103` | `bazel-loader-fdt-efi-aarch64-make-r1-20261103` |
| riscv64 | `bazel-loader-fdt-riscv64-r1-20261103` | `bazel-loader-fdt-common-riscv64-make-r1-20261103` | `bazel-loader-fdt-efi-riscv64-make-r1-20261103` |

Every 10+1 member archive matches unmodified Make in allocated section bytes,
flags/type/alignment/size, external defined/undefined symbol contracts and symbolic
relocations. Per architecture, 932, 1,214 and 1,171 allocated relocations are
compared. The six `bazel-loader-fdt-<common|efi>-<arch>-review-r1-20261103`
reports retain the raw comparisons. No filename controls were needed. Full object
bytes differ for all 33 objects; DWARF/source mapping and debugger qualification
remain open. Both libraries are INTERNALLIB with no component installation
payloads, so no fabricated package or installation entries were added.

Two native-host archive tests run per architecture, three Python methods each:
member order, every member's ELF/CPU ABI (including RISC-V soft-float), and the
platform/export/import contracts. All 18 inspection methods pass. Foreign target
code is inspected and never executed.

## Actual algorithm execution and cache reuse

The AMD64 runtime_program links the actual standalone common archive directly.
It creates and packs a device tree, verifies exact big-endian cell bytes, opens
it into a larger buffer, deletes a property, applies a target-path overlay and
checks the resulting node/property. Malformed magic and insufficient capacity
are rejected through the APIs supplied by this source version. The program uses
explicit failure checks and returns nonzero on failure; plain test reporting
preserves that status. It supplies no fake loader or EFI callbacks. The vendor
algorithms execute; fdt_loader_cmd and the EFI platform callbacks are not runtime
qualified by this program.

`bazel-loader-fdt-action-review-r2-20261103` binds the captured executable to its
actual successful link using the standalone archive digest and the actual test
spawn consuming that executable. The ELF defines the vendor FDT APIs and does
not depend on a libfdt shared object. Source-built libc/libsys and the explicitly
declared SDK runtime are selected through the maintained test runner. SDK startup
and bootstrap inputs remain outside complete native-world qualification.

The r4 AMD64 run executes both inspection targets and the program freshly.
The r5 repeat additionally captures the executable and reuses all three passing
results. Its cache-review.json verifies unchanged archive digests and no compiler,
archive or link execution. This establishes immediate local incremental/test
reuse, not remote caching or preservation of every prior configuration.

## Compiler and action review

The action review covers all 33 owned target object outputs, matching actual
noncached compiler actions and final owned-object archive inputs/output digests.
It records which earlier run actually executed each reused step. Successful
library actions from the initial runtime-test link failure are accepted only
where hashes match final captured objects and archives.

Clang dependency files belong to Bazel: each inspected action has one -MF operand
naming its own bazel-out .d file, and no Make .depend output. CPU/freestanding
flags, regular/private verifier selection, target ELF identities and Make ABI
flags are checked. The upstream compact-log converter and its runtime bindings
are verified before/after each log read. Source-definition and input hashes are
retained. The first runtime validator selected the separate XML-generation spawn,
which shares the TestRunner mnemonic/label; the final proof distinguishes that
postprocessor from the actual program execution. It does not infer execution
from XML generation.

## Retained failures and corrections

The initial native attempt stopped before compilation because its authoring
script failed; no successful run is claimed. The next attempt exposed Make-only
-MD/-MF.depend/-MT operands imported from a recorded recipe. They overrode Bazel's
owned dependency output and were removed. The maintained declarations retain
compiler semantics and let Bazel generate/consume its own dependency files.
A scoped search of native definitions found no other matching Make .depend
operands in stand, lib, usr.bin, usr.sbin and tools/build/bazel; this is not a
repository-wide semantic certificate.

The following runtime test initially called fdt_check_full, which this maintained
libfdt version does not supply. The test now uses the available header, mutation,
packing and overlay APIs; undeclared calls are compile-time errors. No missing
production API was added or stubbed to pass a test.
The first foreign Make orchestration used the wrong profile and was rejected
before reference output creation; its corrected commands preserve normal identity
checks. The frontend's build lock also rejected an overlapping invocation; final
foreign qualifications run sequentially with all 16 CPUs available inside each
build. No lock or validation check was bypassed.

## Frontend, instrumentation and remaining work

The existing maintained build-bsd bazel-test format-5 interface selects both
archive/test labels, matching SDKs and target architectures. The AMD64 profile
additionally selects runtime_program/runtime_test; foreign profiles select only
explicit host-artifact tests. No C frontend option or staging/signing/publication
contract changed. The manual and observability ledger document the new native
components. Make remains production/default; BIP remains out of scope.

FDT command execution, firmware tree acquisition/fixups/overlay behavior and boot
handoff require the complete loader and runtime/VM tests. This work is not a full
FDT firmware or verified-boot qualification. Complete libsa/Forth, entry objects,
final EFI links/IA32, full world/kernel/modules/pkgbase/hardware publication,
bootstrap/sandbox, broad runtime and CPU/memory/disk performance remain open.
No host installation, upgrade, reboot or VM run occurred.
