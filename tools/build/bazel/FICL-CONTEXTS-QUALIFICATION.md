# Standalone and EFI Ficl contexts (2026-11-03)

## Current qualified scope

Both standalone Ficl contexts now build natively for AMD64, ARM64 and RISC-V.
`//stand/ficl:static_archive` selects shared standalone objects;
`//stand/efi/ficlefi:static_archive` aliases the private EFI archive owned by
`stand/ficl`. One source-owned macro contains the maintained fifteen-unit source
inventory and exact archive order. Each context owns distinct compiler outputs;
EFI's verification settings do not modify the shared context. No Make action or
Make-generated C file is consumed by the native graph.

The private context follows the actual Ficl Make recipe: EFI warning/wchar
settings, private verifier/vectx/manifest selectors and verification declarations.
It does not borrow Lua's additional verity define. Common ABI, dictionary size,
assertions, disk/GELI selections and source headers remain explicit.
The shared softcore producer preserves the ordered original AWK recipe and typed
datestamp setting introduced in [the initial checkpoint](FICL-QUALIFICATION.md).

Original Make references and native receipts pass on all three architectures.
These are internal archives; the six independent Make component METALOGs are
empty. No installation/package parity is inferred from an empty internal-library
payload. Full loader links, interpreter/firmware runtime and boot remain open.

## Comparisons and actual action provenance

Each of the six archives has fifteen members. Raw comparisons retain original
Make outputs without normalization:

| Architecture | Contexts | Raw allocated-byte/relocation matches per archive | Isolated original compiler controls |
| --- | --- | --- | --- |
| AMD64 | standalone and EFI | 3/15 each | 15/15 each |
| ARM64 | standalone and EFI | 4/15 each | 15/15 each |
| RISC-V | standalone and EFI | 4/15 each | 15/15 each |

All raw archive orders and exported/imported symbol contracts match. The retained
raw differences are assertion filename strings and their symbolic relocations:
absolute Make source names versus relative native source names, plus distinct
generated-source paths. Separate original compiler controls use only explicit
macro filename maps (and remove dependency-output flags to preserve original
files). Every control matches native allocated bytes and relocations. Neither
production artifact was edited and no assertion was disabled. Full object/debug
bytes and a common diagnostic/debug source lookup policy remain open.

The actual action records bind all ninety selected object outputs to successful
compiler actions and ordered archive inputs/outputs, then to immutable captured
archives. AMD64 shared objects reuse successful actions from the initial Ficl
archive attempts, with matching digests; that provenance is explicit. ARM64 and
RISC-V records use their own actual actions. Softcore compiler inputs bind to
the captured generated C digest. Actions retain standalone/architecture options,
private verifier/wchar selection and exactly one Bazel-owned dependency output.
Shared AMD64 archive bytes remain identical to the pre-EFI checkpoint.

## Tests

Archive tests use declared execution-configured archive/symbol tools to inspect
target ELF class, machine, soft-float ABI on RISC-V, duplicate member names,
interpreter API exports and verifier imports. They also reject unexpected stack
protector imports, matching the maintained pre-kernel SSP-disabled recipe.
Completeness/order evidence comes from independent Make archives, rather than a
second source list inside the test. The first AMD64 run additionally exercised
an earlier membership-list test; current tests retain the ABI/API/context checks.
The independent ordered-input AWK recipe test passes for each architecture.
Foreign tests inspect artifacts on the host and do not execute target binaries.
No VM or firmware execution is claimed.

## Evidence locations

All records below are under `/usr/obj/usr/src/`:

- `bazel-ficl-contexts-{amd64,aarch64,riscv64}-r1-20261103`: normal frontend
  receipts, compact execution logs, reports and immutable captured archives.
- `bazel-ficl-{amd64,aarch64,riscv64}-make-r1-20261103` and
  `bazel-ficl-efi-{amd64,aarch64,riscv64}-make-r1-20261103`: independent Make
  references with original compiler metadata and component install records.
- `bazel-ficl-contexts-<arch>-{common,efi}-review-r1-20261103`: raw comparisons.
- `bazel-ficl-contexts-<arch>-{common,efi}-controls-r1-20261103`: isolated
  compiler controls; scripts are retained alongside the records.
- `bazel-ficl-contexts-<arch>-actions-r1-20261103`: actual native compiler/archive
  actions and digest chains, including separate input-log bindings.

## EFI toggle, default metadata, rejection and reuse

The additional AMD64 EFI-verification-disabled reference/profile passes its
archive and recipe checks. Its fifteen isolated original compiler controls also
match native allocated bytes/relocations; raw equality remains 3/15. This adds
one policy variant to the ninety-object matrix above, rather than fifteen new
source units. The shared archive's entire bytes remain identical with EFI
verification enabled, disabled and restored. The private archive changes with
the verifier setting and returns to its original complete bytes when restored.
The normal frontend's default-empty date profile also produces the expected
undated C source and passes the original recipe test. A comment-terminator date
value is rejected through normal frontend analysis before generator execution.

Restoring the verifier setting rebuilt fifteen private objects and one archive.
The initial review incorrectly expected zero rebuilds for configuration restore;
that checker failure and its source are retained. The corrected review separates
byte-identical restoration from unchanged archive-input reuse. The later repeat
executes zero compiler, archive or link actions and captures identical archives.
The intervening undated profile can require regenerating dated source; this is
not a claim that every action/test was cached. No disk/remote action-cache or
complete-system incremental/performance qualification is established here.

Additional evidence under `/usr/obj/usr/src/`:

- `bazel-ficl-contexts-amd64-{off,on-final,undated,repeat}-r1-20261103`: frontend
  receipts/reports and captured artifacts for the additional profiles.
- `bazel-ficl-efi-amd64-off-make-r1-20261103`: independent disabled-EFI reference.
- `bazel-ficl-contexts-amd64-off-efi-{review,controls}-r1-20261103` and
  `bazel-ficl-contexts-amd64-off-actions-r1-20261103`: disabled-context raw
  comparison, fifteen compiler controls and actual action provenance.
- `bazel-ficl-contexts-final-state-r1-20261103`: retained failed checker
  assumption; revision 2 holds successful toggle/default/repeat bindings and
  actual compiler-input counts plus SDK footprint observations.
- `bazel-ficl-contexts-metadata-rejection-r1-20261103`: expected frontend
  rejection command, status and diagnostic. The failed analysis output is kept
  separately in `bazel-ficl-contexts-invalid-datestamp-r1-20261103`.

## Build performance issue found during qualification

The current bootstrap SDK is broader than this freestanding compilation needs.
The actual AMD64 `dict.o` compile has 4,778 input entries, including 4,374 SDK
userland headers, despite `-nostdinc`; ARM64 has 4,293 entries and 3,915 such
headers. Whole-SDK verification also reads large unused debug/runtime files and
noticeably delays these small qualification runs. The snapshots contain about
2.38 GB logically for AMD64 and 5.1 GB per cross SDK, including about 1.06 GB
and 2.4 GB of debug content respectively. These are per-path logical sizes, not
physical ZFS allocation measurements. These observations are not a
controlled Make/Bazel benchmark and do not quantify operating-system runtime.

Before performance/default gates close, narrow the freestanding toolchain input
closure and bootstrap SDK contents through maintained source/toolchain/staging
interfaces. Preserve verification of the resulting declared distribution and
prepare fresh receipts; do not ignore mismatches, edit frozen SDKs or omit
verification to accelerate a passing test. Then measure cold/warm builds,
changes/invalidation, CPU, memory, disk I/O and storage against Make. The present
broad SDK and Make-built bootstrap floor remain explicit completion gaps.

## Frontend and next integration work

The existing maintained build-bsd format-5 interface selects both labels,
supported architectures, typed settings, tests and captured results. No new C
switch, staging/signing policy or publication route is needed for these library
labels. The manual describes the targets and policy selection. All jobs use
sixteen logical CPUs. Make remains production/default; BIP remains out of scope.

Independent AMD64 libsa references are also ready for the next required loader
tranche: 191 regular and 260 private EFI units. The regular reference installs
the bootloader-dev `libsa(3)` manual, which native installation must preserve.
These are Make baselines, not native libsa completion. Full libsa, IA32, entry
objects and final loader links remain required, along with full world/kernel/
modules, debug/source lookup, runtime, packages/hardware/combined publication,
reproducible bootstrap, sandbox and comparative performance gates. No host
installation, upgrade, reboot or VM run occurred.
