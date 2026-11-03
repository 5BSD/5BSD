# Storage adapter module qualification (2026-11-02)

## Implemented composition

Seventeen selected amd64 GENERIC leaves now have native module declarations:
ciss, hpt27xx, hptiop, hptmv, hptnr, hptrr, isci, isp, mpi3mr, mpr, mps, mpt,
ocs_fc, pms/pmspcv, smartpqi, tws and ufshci. The graph contains 260 physical C
files/compiler contexts, 178 native object groups and 191 physical header
contexts (171 exact existing contexts reused). Source packages own files and
narrow visibility; generated interface/option headers use declared native
producers. There are no generated C sources in this cohort.

HighPoint's four original BLOB_OBJS are explicit source-owned ELF object labels,
not C compiler outputs. Fresh original Make queries and pre/post-build hashes
bind each object. Existing module linking and CTF merging receive all 264 ordered
object inputs: original C objects followed by the actual vendor objects. No blob
is silently omitted, substituted or presented as newly compiled source. Original
ufshci EXPORT_SYMS=YES, other EXPORT_SYMS=NO and all package=kernel policies remain.

PMS's original -fno-builtin, -w and warning vector before WERROR remain explicit,
with WERROR at its original position and still controlled by the typed setting.
The migration-only generator initially rejected its incorrect first-WERROR
assumption before applying any source; that rejected driver is retained.

## Actual correction found by qualification

The first native CTF/debug build and existing provider tests passed, but compiler
and artifact comparisons correctly rejected hptmv. Its original Makefile resets
CFLAGS, removing ordinary optimization and -fno-strict-aliasing. The first native
candidate inherited both, changing code, CTF, data and relocations. The initial
capture, failed-policy observer and hash-bound artifact rejection are retained;
that artifact is not qualified.

The maintained amd64 object macro now accepts optional kernel_flags and native
cc_library features. Defaults retain the original shared policy. hptmv declares
the original flag vector without the absent aliasing flag and disables the
existing opt toolchain feature. This uses Bazel's standard target
[feature selection](https://bazel.build/reference/be/common-definitions#common.features)
and the existing toolchain's opt feature. The selection is explicit in the source target; the shared helper
contains no driver-name branch. No original Makefile, runtime source,
compiler or artifact is rewritten. Compiler flag checks stay exact.

The corrected CTF/debug profile passes strict comparisons against untouched Make.
All eighty captured module/debug/install output bindings across the other sixteen
modules remain whole-file identical before/after the optional helper API change.

## Compiler, link, artifact and install proof

Both maintained build-bsd format-5 profiles use all sixteen logical CPUs, opt
compilation, strip=never and the current validated SDK. Each reviews 260 actual
successful compiler contexts, 36,990 original dependency occurrences and 36,990
actually consumed native occurrences with declared matching hashes. Compiler/
source bytes, defines, warning order, semantic flags, forced-header order and
used physical include-root order pass. The final CTF witness set uses unchanged
successful r1 actions plus corrected hptmv r2 actions; rejected hptmv actions are
excluded. Cached computations are not invented as new executions.

Each profile retains seventeen actual ordered linker argument files and all
object hashes, including exact vendor-object identities and order. All seventeen
plain modules are whole-file byte-identical to untouched original Make. All
CTF/debug modules preserve recorded section inventory, metadata and payload except
GNU build-ID/debuglink values; CTF bytes agree, original/native split-debug CRCs
pass, and 34 CTF/debug plus 17 plain file installation records match actual Make
staging. Whole-file debug/DWARF identity is not claimed.

Six existing provider regression targets pass in each accepted profile. These do
not test storage commands, DMA, interrupts, recovery, module loading or hardware.
See [MODULE-LOADER-EXPORT-CONTRACT.md](MODULE-LOADER-EXPORT-CONTRACT.md).

## Observability, integration and remaining gates

A bounded scan of 260 C files records twelve explicit marker candidate lines in
MPR/MPS allocation/request/free paths, including macros/comments. Both modules
preserve compiled SDT/DTrace sections and relocation payloads against Make. No
new probes or live events are qualified. Other files' lack of explicit markers
is not proof of missing inherited subsystem instrumentation. Review CAM/storage
request/error/recovery and controller/reset paths using shared hooks without
per-I/O logs or payload disclosure.

Evidence is under /usr/obj/usr/src/bazel-storage-adapters-modules-review-r1-20261102.
Original controls are in bazel-storage-adapters-module-make-references-r1-20261102;
accepted native profiles are bazel-storage-adapters-modules-ctf-debug-native-r2-20261102
and bazel-storage-adapters-modules-plain-native-r1-20261102. The root retains source
snapshots and bindings, actual compiler/link witnesses, parameter/dependency files,
all comparisons, vendor object hashes, rejected candidate evidence and review
drivers. Thirty-four original Make build/install controls pass.

Existing build-bsd C inputs, format-5 backend and install metadata carry this
composition. The maintained module helper and documentation are updated; no new
CLI/manual behavior, signer/verifier, staging or publication policy is introduced.
Bundle signing does not prove verified boot or compromised-root protection. Make
remains production/default; BIP is excluded. No host installation, module loading,
upgrade or reboot was performed.

Local BUILD presence is 591/729 selected amd64 leaves (138 missing), not a system
qualification percentage. Other architectures/options, full world/rescue/pkgbase/
hardware/bootstrap/publication and VM/runtime remain open. Original resource
counters and native free-space guards are bounded observations; controlled CPU/
total-memory/disk-I/O/disk-use, cache and sandbox gates remain open.
