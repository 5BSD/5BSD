# Platform, GPIO and watchdog module qualification (2026-11-02)

Twenty-four selected amd64 GENERIC leaves now have native module declarations:
bytgpio, chromebook_platform, chvgpio, coreboot, dpms, ftgpio, ftwd, hfsts, ichwd,
intel_pmc, itwd, nctgpio, ncthwm, nvram, p2sb, pchtherm, puc, pvpanic, superio,
tglhgpio, viawd, vmd, wbwd and wdatwd. These are build/install qualifications,
not tests of actual sensors, GPIO, serial ports, firmware or watchdog operation.

## Native composition and evidence

Thirty-six compiler contexts cover 35 ordinary physical C files and one generated
serdev_if implementation. Thirty-three native object groups use 37 physical
header contexts, with 25 exact existing contexts reused. Physical packages own
headers/sources; generated KOBJ/option dependencies, complete original OBJS link
order, warnings and typed WERROR remain explicit. Original superio EXPORT_SYMS=YES
and the other twenty-three EXPORT_SYMS=NO policies are retained. All use the
original package=kernel metadata. No runtime source, original Makefile, common
module rule or compiler policy changes are needed.

Both maintained build-bsd format-5 profiles pass with all sixteen logical CPUs,
opt compilation, strip=never, and the current validated SDK. Each profile retains
36 actual uncached successful compiler actions, 3,843 original dependency
occurrences and 3,843 actual native consumed occurrences. Compiler/source bytes,
defines, warnings, semantic flags, forced-header order, used physical include
ordering and declared input hashes pass. Each also retains 24 actual ordered
link argument files and object hashes. The sole generated provenance-comment
source-path difference is checked explicitly; final artifacts are not rewritten.

Six existing provider regression targets pass in each profile. They do not test
these devices or emulate kernel module-loader policy. See
[MODULE-LOADER-EXPORT-CONTRACT.md](MODULE-LOADER-EXPORT-CONTRACT.md).

## Original filename difference and independent controls

Twenty-two plain modules are whole-file byte-identical to untouched original
Make. Initial CTF/debug comparison rejected p2sb and superio: their Make .PATH
uses /sys/modules/<name>/../../dev/<name>, so diagnostic filename strings contain
that lexical path. Native compilation uses the existing canonical source-path
policy. String lengths also change relocations and symbol offsets. The original
failed comparison and all untouched references are retained.

Four independent Make controls (two modules, two profiles) include the original
Makefiles unchanged and append one derived -fmacro-prefix-map from each original
lexical source directory to its resolved physical directory. They use original
recipes, source and compiler policy, with normal target-dependent dependency
flags. These controls establish the filename-only explanation; they are not
reported as untouched Make parity. No native source, path policy, compiler or
artifact was changed to match them. Both controlled plain modules are whole-file
identical to native output.

All twenty-four CTF/debug modules preserve recorded section inventory, metadata
and payload except GNU build-ID/debuglink values against their respective
untouched/filename controls. CTF bytes agree; original/native split-debug CRCs
pass. Whole DWARF identity is not claimed. Twenty-four plain and 48 CTF/debug
installation records match actual untouched Make staging.

## Instrumentation, integration and limits

0 explicit source marker candidate lines were found in 35 C files and
one schema using the retained bounded DTrace/SDT/CTR/audit pattern; comments and
macros are included. The selected compiled modules contain no recorded SDT/DTrace sections. No probes were added; this is not live event
qualification or proof that shared-subsystem instrumentation is absent.

Evidence is under /usr/obj/usr/src/bazel-platform-families-modules-review-r1-20261102,
with original controls in bazel-platform-families-module-make-references-r2-20261102,
filename controls in bazel-platform-families-module-filename-controls-r1-20261102,
and native captures in bazel-platform-families-modules-{ctf-debug,plain}-native-r1-20261102.
The root retains actual action/parameter/input witnesses, immutable artifact
bindings, dependency files, raw original discrepancy review, source snapshots,
profiles and review drivers. The first original-reference launch rejected stale
kmod.mk inventory before compilation; r1 and its failure log remain. The r3
source inventory was freshly queried after the prior committed alias-tag fix.

Existing build-bsd C inputs, format-5 backend and maintained module/install rules
carry these declarations; no new frontend/manual behavior, signing, staging,
verification or publication requirement is introduced. Bundle signing does not
prove verified boot or protection from compromised root. Make remains production/
default; BIP is excluded. No host installation, module load, upgrade or reboot.

Local BUILD presence is 574/729 selected amd64 leaves (155 missing), not a system
qualification percentage. Other configurations/architectures, full world/rescue/
pkgbase/hardware/bootstrap/publication and VM/runtime remain open. Original Make
resource counters and native free-space guards are bounded observations;
controlled CPU/total-memory/disk-I/O/disk-use, cache and sandbox gates remain open.
