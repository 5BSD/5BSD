# Linux64 native module qualification (November 2, 2026)

## Native dependency graph

The selected amd64 GENERIC linux64 module has 34 original objects in 33 native
source groups. It uses existing module, layout extraction, source alias, syscall
table and VDSO link primitives. The maintained syscall producer now emits the
module switch table as well as its existing outputs; module sources and ABI
headers come from that producer. Two declared architecture views preserve
machine/../linux and amd64/linux includes without rewriting C sources.
The architecture view forwards generated headers as ordinary declared artifacts.

The Linux layout compiler preserves original common-symbol/debug flags; its
object feeds the maintained genassym script with the checked genoffset
prerequisite. The original .asm input is byte-preservingly aliased as .S for
rules_cc preprocessing. VDSO helpers use original hosted/PIC flags, not ordinary
freestanding module flags. Target identity and default freestanding flags are
separate toolchain features; only these two helper groups disable the latter.
Ordinary module/default policy remains selected.

The VDSO uses the original linker script, complete options and ordered helper
objects. Its generated image is an explicit additional input to the unchanged
incbin assembly; assembler lookup uses the configured output directory. Compiler
dependency files alone do not discover incbin. No original Make image, generated
header or source/object substitute is copied into the build. Linux support
assembly preserves its original custom no-CTF recipe; embedding assembly follows
ordinary CTF policy. All original module exports and installation policy remain.

## Actual qualification

Both native profiles pass through maintained build-bsd format-5 inputs with
sixteen CPUs and disk guards. Each profile's 34 actual module compiler witnesses
reconcile 5,004 consumed prerequisite occurrences per side and forty selected
kernel option occurrences. Original compiler/source bytes, defines, warnings,
code-generation options, forced-header order and consumed physical namespaces
are checked. The two generated table source files and syscall headers are
required to have exactly their original checked-in payload bytes. Complete
ordered compiler/CTF-to-link identities and link parameters are retained.

Three actual helper compiler witnesses per profile cover 140 consumed occurrences
and original defines/warnings/code flags. The only source basename adjustment in
dependency comparison is the explicit .asm-to-.S alias, whose filesystem/source
identity and bytes are checked. The generated layout header, all five syscall
outputs and the complete 5,392-byte native VDSO image are byte-for-byte identical
to their originals. Actual layout compiler/symlink/extractor, syscall master/
configuration, ordered VDSO objects/script/options/linker and embedding input
hashes are independently bound. The embedding object's entire .data section is
the actual generated image, and its assembler search argument is checked.

The complete plain module is byte-for-byte identical to original Make. Installed
CTF/runtime sections match with only build-ID/debug-link differences; native and
original debug CRCs verify. Installation manifests match in each profile. Six
existing provider regression tests pass per profile; these are rule regressions,
not Linuxulator runtime tests. A bounded 33-source/master scan records 28
SDT/DTrace/KTR/audit candidate lines including comments/macros; compiled original/
native SDT/DTrace payloads and relocations are preserved.

The first native build failed because the architecture view omitted
linux_emul_md.h. Its actual failed action is retained; the corrected four-header
inventory is derived from original consumed prerequisites, with no C/Make edit
or broad include-path workaround. An observer initially misclassified -Wa
assembler forwarding as a warning flag; that failure is retained and assembler
options are now independently checked. Module witnesses come from each successful
profile's own log. Unchanged auxiliary producers reused in the plain profile are
bound to retained actual prior actions and current input/output hashes; they are
not described as fresh executions.

## Scope and remaining gates

Evidence: /usr/obj/usr/src/bazel-linux64-module-review-r1-20261102, including actual
module/auxiliary actions, raw dependency files and parameters, full generated
payloads, original/native reconciliation, failed action and source correction.
Successful profiles are bazel-linux64-module-ctf-debug-native-r2-20261102 and
bazel-linux64-module-plain-native-r1-20261102. Original controls are
bazel-final-module-make-references-r1-20261102 and
bazel-linux64-helper-dependency-controls-r1-20261102.

Changed-image original/changed/restored invalidation now passes; see
[the actual incremental check](LINUX64-INCREMENTAL-QUALIFICATION.md). The native
BSD VDSO validator has a different ABI/layout contract and was not weakened to
accept Linux. Separate DWARF/source lookup, actual Linux execution/module loading,
other settings/targets, full current kernel/module aggregation, world/pkgbase,
bootstrap, sandboxing, runtime and resource/performance gates remain open.

All 729 selected amd64 directories have BUILD files, but only 728 declare
module producers (690 generic and 38 firmware). ZFS currently declares headers
only; its built-in kernel rules do not supply a loadable module. It remains an
implementation gap. These counts do not establish a complete system build. No frontend-C change or new CLI input is needed; the normal
backend carries these targets, and its maintained manual describes the source/
ABI behavior. No C or original Make source changes are introduced. Make stays
production/default; BIP remains excluded. No host installation, upgrade, module
loading or reboot is performed.
