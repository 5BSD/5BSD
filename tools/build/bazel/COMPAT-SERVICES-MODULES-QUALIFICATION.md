# Compatibility, storage and tracing module qualification

## Scope (November 2, 2026)

Eighteen selected amd64 GENERIC leaves:

cfiscsi, ctl, hwpmc, hwt, iscsi, lindebugfs, linprocfs, linsysfs, linux_common, linux_ntsync, linuxkpi, linuxkpi_hdmi, linuxkpi_video, linuxkpi_wlan, ntsync, safexcel, sgx_linux, vsock

The graph contains 130 compiler contexts, 123 physical C sources and two KOBJ
schemas (six generated compiler contexts), 117 source-owned object groups and
181 physical header contexts, with 83 exact existing contexts reused. Explicit
source labels, generated interfaces and ordered dependencies use maintained
native rules. No runtime source or original Makefile was changed. Lindebugfs's
22 exported names and the other original YES/NO export policies are preserved.

## Evidence

All 36 original Make controls build and install in private /usr/obj directories
using the selected kernel SYSDIR, tied-kernel context and inherited exports.
Both maintained build-bsd plain and CTF/debug native profiles pass using all
16 logical CPUs and disk reserve guards. This is build/artifact qualification,
not execution of compatibility services, tracing, iSCSI, SGX or hardware drivers.

Each profile has 130 actual compiler witnesses. Compiler/source hashes,
code-generation flags, definitions, warning order, forced headers and physical
include-root order match the original Make controls. All 26,206 consumed
original/native dependency occurrences per profile reconcile per compiler
context without missing or extra occurrences. The only generated-byte changes
are independently checked single KOBJ provenance-comment schema-path spellings.
All actual native dependency files and eighteen ordered initial-link parameter
files per profile are retained and hash-bound to the actions. The separate
object-driven option audit covers 130 contexts/155 option-header occurrences;
its count independently agrees with the complete compiler-input audit.

All eighteen plain module ELF files are whole-file byte-identical to untouched
original Make outputs. The stripped CTF modules' complete section inventories
and payloads, including CTF, match except build-id/debuglink fields. Each original
and native binary/debug pair has a valid GNU debuglink CRC. All 36 CTF and 18
plain installation records match original destinations, types, owners, groups,
modes and package/debug tags. No filename control or artifact rewrite is used.

Separate DWARF files are NOT byte-identical. Direct comparisons find differences
in .debug_line, .debug_str, .rela.debug_info, .rela.debug_line and build-id;
all other separate-file section inventories/payloads match. LLVM 19 verifies
all 36 native/original files structurally. This does not establish equivalent
source/line lookup or complete semantic DWARF parity. See the explicit remaining
gates in [module debug qualification](MODULE-DEBUG-QUALIFICATION.md).

A bounded scan of 125 physical C/schema inputs records 149 SDT/DTrace/KTR/audit
candidate lines, including macros/comments. All seven modules with compiled
SDT/DTrace sections retain exact section payloads and relocations. No live probe
or audit-completeness claim follows from this scan.

## Corrections and retained attempts

The first CTF attempt failed at sgx_linux's machine/../linux/linux.h include.
The existing architecture-header-view rule now exposes the three original
amd64 Linux headers in a separate cohort view, used by eight consuming compiler
contexts. The previous architecture view is unchanged. No include rewrite,
header-byte copy, blanket include-root addition or new helper is introduced.
The second CTF attempt passes; the first failure remains retained.

The first plain invocation stopped before compilation because the frozen SDK's
host bsdtar binding no longer matched the host. Its failed receipt/log is kept;
its old receipt was not rebound. Maintained SDK preparation produced a fresh
snapshot, with all 16,755 input/snapshot bindings verified. The exact snapshot
deltas are tar plus seven host execution libraries/loader, not target compiler
or target sysroot bytes. The plan differs only by its output-root relocation.
The second plain invocation uses this new snapshot and passes. These runs do
not share an identical host execution envelope and establish no performance
comparison. SDK validation and delta reports retain that distinction.

## Evidence locations and frontend review

- Original controls: /usr/obj/usr/src/bazel-compat-services-module-make-references-r1-20261102
- Native CTF: /usr/obj/usr/src/bazel-compat-services-modules-ctf-debug-native-r2-20261102
- Native plain: /usr/obj/usr/src/bazel-compat-services-modules-plain-native-r2-20261102
- Comparisons, captured inputs/parameters, raw debug checks and observers: /usr/obj/usr/src/bazel-compat-services-modules-review-r1-20261102
- Fresh SDK: /usr/obj/usr/src/bazel-compat-services-sdk-20261102
- SDK validation and delta review: /usr/obj/usr/src/bazel-compat-services-sdk-validation-20261102.json and bazel-compat-services-sdk-delta-review-20261102.json

Existing build-bsd bazel-test, format-5 configuration, staging/validation helpers
and native module rules carry this work. No CLI, manual option, C frontend,
signing, installation or publication requirement changes. Documentation records
the SDK provenance and narrower debug evidence rather than silently weakening
verification. No host installation, upgrade, reboot or module loading occurred.

Local BUILD presence is 708/729 selected amd64 module directories (21 remain),
not full-system completion. Other options/architectures, current full kernel,
world/rescue/libraries, full debug/source packages, installation/pkgbase,
bootstrap/hardware/publication, VM/runtime and CPU/memory/disk I/O/cache/sandbox
qualification remain open. Make remains production/default; BIP is excluded.
