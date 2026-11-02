# System and I/O module qualification (2026-11-02)

## Composition and retained source policies

Thirty-seven selected amd64 GENERIC leaves now have native declarations:
cpufreq, dcons, dcons_crom, imgact_binmisc, io, ioat, kbdmux, ksyms, libiconv, md,
mem, mmc, mmcsd, nlsysevent, nvdimm, proto, pt, rtsx, scc, sdhci, sdhci_acpi,
sdhci_pci, sdio, snp, tests/framework, thunderbolt, tpm, uart, uinput, vesa,
video, videomode, vkbd, x86bios, xdr, xz and zlib. This is artifact/install
qualification, not device, storage, security, firmware or test-framework execution.

The graph contains 125 compiler contexts over 116 ordinary physical C files and
nine KOBJ schemas: scc, sdhci, sdio, tb, tpm, uart, video, serdev and iconv_converter.
There are 106 native object groups and 120 physical header contexts (84 exact
existing contexts reused). Physical packages own files with narrow visibility;
generated headers/sources and complete original object ordering remain explicit.
Original YES/NO export policies and the two explicit export lists are retained:
libiconv's ten names and nvdimm's two SPA lifecycle names. All use package=kernel.

Thunderbolt's module Makefile generates opt_thunderbolt.h with THUNDERBOLT_DEBUG=1
independently of the empty GENERIC kernel header. The source-owned native module
uses a declared write_file producer and header view for those exact bytes;
GENERIC's option output is unchanged. Both original profiles and actual native
consumed hashes verify this separation. Keyboard module defaults still use the
selected KERNBUILDDIR headers as the original tied-module Make paths do.
No runtime C, original Makefile, common module helper or compiler-policy changes.

## Compiler, link and installed artifact evidence

Both maintained build-bsd format-5 profiles pass using all sixteen logical CPUs,
opt compilation, strip=never and the validated current SDK. Each independently
retains 125 actual uncached successful compiler actions, 13,134 original Make
dependency occurrences and 13,135 actually consumed native occurrences. Compiler/
source bytes, defines, warning order, semantic flags, forced-header order, used
physical include-root order and declared input hashes pass. Only exact single
KOBJ provenance-comment paths differ in generated inputs. Each profile retains
37 actual ordered link parameter files and object hashes. TPM has one extra
native header occurrence: the direct generated tpm_if.h and its virtual include
view resolve to the same physical file and hash. Every context's consumed
basename/content multiset reconciles, with only that verified extra alias; counts
are retained separately.

Thirty-five plain modules are whole-file byte-identical to untouched Make.
Initial CTF/debug comparisons rejected nlsysevent and sdio: the former embeds
/sys/netlink// and the latter /sys/modules/sdio/../../dev/sdio/ in diagnostic
filenames, while native compilation follows its existing canonical path policy.
The untouched raw artifacts and their exact differing sections/strings remain.

Four independent original Make controls (two profiles for each module) include
unchanged Makefiles and append one derived directory-prefix macro map, retaining
trailing separators so unrelated header paths are unaffected. Lexical doubled
slashes are preserved when deriving that mapping. Generated C remains under its
original recipe. These controls produce both plain modules whole-file identical
to native output. They establish filename-only equivalence, not untouched Make
byte parity for these two modules. Native source/compiler/artifacts were unchanged.

All 37 CTF/debug modules agree on recorded section inventory, metadata and payload
except GNU build-ID/debuglink values against respective untouched/filename
controls. CTF bytes agree; original/native split-debug CRCs pass. All 74 CTF/debug
and 37 plain file install records match actual untouched Make staging. Whole
DWARF identity is not claimed. Six existing provider regression targets pass per
profile; they do not execute the listed devices or the kernel test framework.
See [MODULE-LOADER-EXPORT-CONTRACT.md](MODULE-LOADER-EXPORT-CONTRACT.md).

## DCONS header ownership and actual userspace regression

Creating sys/dev/dcons's physical package would invalidate the root provider's
old implicit file label. The first move retained the public target through an
alias, but changed the debug virtual-include paths: the archive regression
correctly rejected changed .debug_info/.debug_line and the resulting debuglink
CRC. The first after-capture and failed comparison are retained.

The accepted composition preserves the existing root cc_library ABI view, its
strip prefix and virtual include namespace. It refers to the physical package's
explicit file label, exported only to that view. There is no duplicate header,
compiler flag or debug-path rewrite. Actual current-SDK before/after dconschat
archives and both archive metadata outputs are whole-file identical, including
program, debug file, manual and ownership/package metadata. This qualifies the
ownership boundary; it does not establish interactive FireWire operation.

## Observability and open gates

The bounded scan of 116 C files and nine schemas records 57 DTrace/SDT/CTR/audit
candidate lines, including comments/macros, in IOAT, MD, MMC, SDIO, SNP, UART and
image-activation paths. Seven modules (imgact_binmisc, geom_md, mmc, sdio, snp,
uart, xdr) preserve compiled SDT/DTrace sections and relocation payloads against
Make. Source markers and preserved sections do not establish live probe firing.
Review shared request/completion/error/recovery, device attach/detach, terminal
and image-activation events without per-I/O logs or payload/credential disclosure.
The framework module itself is compiled, not run. No probes added.

Evidence root: /usr/obj/usr/src/bazel-system-io-modules-review-r1-20261102.
Original controls: bazel-system-io-module-make-references-r1-20261102.
Filename controls: bazel-system-io-module-filename-controls-r1-20261102.
Native captures: bazel-system-io-modules-{ctf-debug,plain}-native-r1-20261102.
The root retains source snapshots, actual action/input/parameter witnesses,
consumed dependencies, all artifact/install/ownership comparisons, first rejected
archives, original policies and migration/review drivers. Three migration-only
preflight assumptions (new source ownership, nonliteral header contexts and the
root-owned DCONS file label) were rejected before source application and corrected.

Existing build-bsd C inputs, format-5 backend and maintained module/install rules
carry this composition. Source declarations and docs are updated; no new CLI/
manual behavior, signing, staging, verification or publication policy is needed.
Bundle signing does not establish verified boot or compromised-root protection.
Make remains production/default; BIP is excluded. No host installation, module
load, upgrade or reboot was performed.

Local BUILD presence is 628/729 selected amd64 leaves (101 missing), not a system
qualification percentage. Other architectures/options, full world/rescue/pkgbase/
hardware/bootstrap/publication and VM/runtime remain open. Resource counters and
native free-space guards are bounded observations. Six unrelated read-only
preprocessor invocations briefly overlapped original controls after a window-
ownership message race; those runs are not controlled performance evidence.
Controlled CPU/total-memory/disk-I/O/disk-use, cache and sandbox gates remain open.

### Separate-debug evidence scope correction

The CTF/debug payload comparisons above concern stripped installed module ELF
sections, including CTF. Separate debug files were independently CRC-checked;
that did not prove DWARF parity between Make and Bazel. Direct separate-file
comparisons now record five differing sections and leave semantic/source lookup
qualification open. See [module debug qualification](MODULE-DEBUG-QUALIFICATION.md)
for exact observed scope and required follow-up. Runtime ELF/CTF, compiler-input,
installation and instrumentation results remain unchanged.
