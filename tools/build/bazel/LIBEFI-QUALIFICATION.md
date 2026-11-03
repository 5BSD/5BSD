# Native EFI support archive candidate (2026-11-03)

## Implementation

`//stand/efi/libefi:static_archive` builds the complete selected libefi source
inventory: 17 common units, Teken and the architecture-selected clock, in Make's
archive order. AMD64 uses time.c, ARM64 time_arm64.c, and RISC-V time_event.c.
All compiler/header dependencies are native declarations. The three original
Make dependency inventories were used during migration to author explicit header
contexts; no Make query or prebuilt object/archive enters the native build.
The existing userland efichar.c export is retained.

Architecture views, EFI ABI/compiler policy, per-file format-warning exceptions,
ZFS declarations and standalone safe headers follow the maintained recipes.
The typed loader_net, loader_md and loader_zfs booleans default true, matching
this component's network, UEFI memory-disk and ZFS defaults. Existing disk/GELI
and private EFI verifier settings select their corresponding compile definitions.
Only selected-default network/memory-disk and ZFS-on/off profiles are qualified
here; other combinations are not implied. No runtime source implementation changed.

Teken uses the existing sys/teken native AWK rule and source sequence inventory.
Its generated header is a declared dependency only of the terminal compiler
group. Firmware ABI fixtures remain outside the production archive and static-only:
CHAR16/GUID/status/pointer widths, AMD64/ARM64 wchar width and RISC-V soft-float
are checked at compilation. All cross tests are declared native-host inspections;
no target ELF or firmware code executes.

## Builds and artifact tests

Evidence paths below are under `/usr/obj/usr/src`.

| Target/profile | Frontend qualification | Independent Make reference | Host test methods |
| --- | --- | --- | --- |
| amd64 defaults | `bazel-libefi-amd64-r1-20261103` | `bazel-libefi-amd64-make-r1-20261103` | 4 |
| aarch64 defaults | `bazel-libefi-aarch64-r1-20261103` | `bazel-libefi-aarch64-make-r1-20261103` | 4 |
| riscv64 defaults | `bazel-libefi-riscv64-r1-20261103` | `bazel-libefi-riscv64-make-r1-20261103` | 4 |
| amd64 ZFS disabled | `bazel-libefi-amd64-nozfs-r1-20261103` | `bazel-libefi-amd64-nozfs-make-r1-20261103` | 4 |

All builds and 16 methods pass. The methods check actual archive order/clock
selection, every member's ELF identity/ABI, firmware API and ZFS symbol selection,
and generated terminal-header bytes against the original AWK recipe. The fixtures
also compile successfully in ordinary/PIC variants; they are not archive members.
Independent Make references use supported target/profile checks and recipe
metadata. Foreign references explicitly enable LOADER_EFI_SECUREBOOT for this
component; their recorded target profiles/SDK identities remain unchanged.
The archives are INTERNALLIB and their component METALOGs contain no installed
payloads. No synthetic package/installation records were added.

## Raw differences and filename controls

The unmodified Make comparisons match all 19 members' external defined/undefined
symbol contracts and ELF ABI identities. Allocated section bytes and symbolic
relocations match directly for 18 of 19 members in each profile.
Teken is the one retained raw mismatch: Make compiles absolute source names,
while Bazel uses relative names. Assertions embed those file paths in string data;
string-pool offsets also change some relocations. Assertions remain enabled.
The raw reports are explicitly marked contracts-differ; no green full-byte or
unmodified 19/19 comparison is claimed.

The complete raw reports are `bazel-libefi-amd64-review-r2-20261103`,
`bazel-libefi-aarch64-review-r1-20261103`,
`bazel-libefi-riscv64-review-r1-20261103` and
`bazel-libefi-amd64-nozfs-review-r1-20261103`. The initial strict amd64 comparison
stopped at that mismatch and is retained separately.

`bazel-libefi-<profile>-filename-control-r1-20261103/review.json` records four
independent controls. Each reruns the original recorded Make Teken compiler recipe
with its recorded compiler, an isolated output, and the explicit compiler option
-fmacro-prefix-map=<source-root>/=. The source root is the selected source input.
The controls reproduce every native allocated section and symbolic relocation.
Their compiler fingerprints match the original Make receipts. Neither production
Bazel declarations, native outputs nor original Make references are modified or
normalized. This establishes the filename-only explanation; it does not turn the
raw comparison into equality. Diagnostic/source path policy, full DWARF/source
lookup, debugger behavior and complete object-byte parity remain open.

## Action and generated-header evidence

`bazel-libefi-action-review-r2-20261103` binds all 76 owned outputs across the
four profiles to actual successful, noncached compiler actions and exact owned
archive inputs/captured archive hashes. It checks the freestanding/CPU/option
flags, two ABI fixture variants, absence of assertion disabling, ELF identities
and Make ABI flags, and the terminal compiler's generated-header input digest.
Source-definition hashes and the original-compiler filename controls are retained.
The upstream compact execution-log converter/runtime bindings were checked before
and after every log read.

The generated header's captured bytes equal the independently produced Make
header in every profile and the direct original AWK recipe used by the artifact
test. The generator action itself was cached in these execution logs: no fresh
execution is claimed. `bazel-libefi-generator-graph-r1-20261103` and the action
review's generator-review.json retain the configured action, exact script/data,
AWK/redirect inputs and output path. Header payload digests are identical across
all four profiles. An initial review incorrectly required a fresh generator
record; that failed review is retained. The final review accepts honest cache
reuse and preserves the independent byte and compiler-input checks.

## Frontend, scope and remaining work

The normal maintained build-bsd bazel-test format-5 workflow selects the library,
host test and generated-header target with explicit SDKs and all 16 logical CPUs.
Typed settings already pass through that backend; no new C frontend option,
signing/staging/publication contract or replacement workflow was introduced.
The manual documents the new component options. Make stays production/default.
No host installation, upgrade, reboot or VM run occurred.

Firmware disk/network/console/clock/variable behavior and error cases require
execution with the completed loader. This archive qualification does not establish
UEFI runtime, signature verification or verified boot. Complete libsa/FDT/Forth,
entry objects, final loader links, IA32 variants, full world/kernel/modules and
pkgbase/hardware publication remain open. Bootstrap/sandbox, broad runtime and
comparative CPU/memory/disk performance remain separate gates. Disk reserves are
safety guards; client-only timing is not a process-tree resource benchmark.
BIP remains out of scope.

The common and EFI FDT archive prerequisites were subsequently qualified in
LOADER-FDT-QUALIFICATION.md. Their firmware runtime and full-loader gates remain
separate from archive/host algorithm checks.
