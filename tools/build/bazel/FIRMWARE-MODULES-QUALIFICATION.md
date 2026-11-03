# Remaining firmware module qualification

## Scope (2026-11-02)

All 38 remaining Make-selected amd64 GENERIC modules declaring FIRMWS now have
native declarations. Their 59 images include 24 uudecoded inputs and 35 raw
inputs, including two Otus source copies whose bytes equal the declared raw source.
The 111 compiler contexts comprise 59 original firmware assembly instances,
38 generated registration C sources and fourteen real LiquidIO driver C sources.
LiquidIO's eleven native groups preserve its complete driver object inventory;
nineteen physical header contexts reuse five existing providers. All original
export and package policies remain unchanged. No original Makefile or runtime
C/assembly/AWK source changes.

## Native composition and ownership

amd64_firmware_module.bzl composes existing native uudecode, AWK, compiler, CTF,
object-alias, link, export, debug and installation rules. Images declare source
labels, raw/uu encoding, logical filenames and original registration specifications.
The filename/spec agreement and unique filenames are checked. Original omitted,
dotted and hexadecimal version spellings pass unchanged to the maintained AWK
script. License arguments are forwarded; all currently selected license values
are empty, so nonempty-license runtime behavior is not newly qualified.

The existing optional additional_compiler_inputs parameter supplies each .incbin
payload explicitly. Compiler actions contain its actual digest even though Make
compiler depfiles omit that binary data. No generated image/stub is imported from
Make or committed instead of its producer. Raw data aliases preserve input bytes;
registration and embedding use logical firmware names independently of physical
source filenames. Existing object aliases preserve original .fwo link names.

LiquidIO adds its fourteen real C objects in original order between firmware data
and registration. Include roots derive from actual source-owned compiler paths,
including its base directory; no installed host header fallback is used. Payload
exports retain existing owning packages, notably Chelsio's firmware subdirectory
inside its existing owner. New data packages are checked against existing root
label/relative-source references before introduction. Common firmware assembly
and registration script visibility is scoped to kernel module subpackages.

Image lists are source-owned Bazel metadata. New/changed payloads, versions or
optional Chelsio configuration files must update those declarations and their
source exports. They are not discovered by invoking Make or scanning installed
package databases during a native build. Alternate source/configuration selections
and full Make-option parity remain separate qualification requirements.

## Retained evidence

Paths below are under /usr/obj/usr/src.

- bazel-remaining-module-source-facts-r1-20261102 captures all 299 then-missing
  selected leaves. Actual FIRMWS values select this cohort, not a name list.
- bazel-firmware-module-make-references-r1-20261102 contains all 76 passing original
  Make build/install controls, sequentially with sixteen jobs each. No host install
  occurs. bazel-firmware-module-source-facts-r1-20261102 binds actual source/decoder/
  copy/compiler contracts and payload hashes; unsupported producer assumptions are
  rejected, and the two explicit Otus copy recipes are checked byte for byte.
- bazel-firmware-modules-{plain,ctf-debug}-native-r1-20261102 are passing normal
  build-bsd profiles: 278 targets including module/debug/install, individual image/
  embedding/registration outputs, two prior USB firmware artifacts and six existing
  family regressions. Those six tests do not execute firmware or LiquidIO hardware.
- bazel-firmware-modules-review-r1-20261102 retains 111 actual compiler contexts and
  6,209 original consumed source/header occurrences, warning/define/code-generation
  and compiler/source digests, plus explicit .incbin data checks. All 59 payloads
  and 38 registration sources equal Make. All 38 complete ordered initial links
  pass; each embedded link input equals its immutable captured object digest.
- All 38 plain modules match respective Make references byte for byte: 37 untouched
  originals and the explicitly audited LiquidIO filename-policy control below.
  CTF/debug runtime section inventories, metadata and payloads match except GNU
  build-ID/debug-link values; CTF bytes agree exactly. Both sets of debug CRCs
  validate. All 114 file-install records across the two variants match. Whole DWARF
  equality is not claimed. Four previous USB firmware artifacts are byte-identical.

## Explicit LiquidIO filename-policy control

Untouched Make passes paths below sys/modules/lio/../../dev/liquidio, whereas
native compilation uses canonical source paths. The ordinary comparison retains
these filename/string-pool/relocation differences in ordinary-ctf-debug-diagnosis.json.
bazel-firmware-module-filename-controls-r1-20261102 includes the original Makefile
unchanged plus one appended -fmacro-prefix-map from that original directory prefix
to its canonical prefix. All 32 actual compiler recipes differ only by that flag;
all 6,140 consumed prerequisite occurrences and bytes agree. Target MD/MF/MT
flags are preserved. The resulting plain module is exact native. No finished
artifact is normalized or production rule changed to reproduce noncanonical paths.

Later plain builds replace mutable execroot parameter files. The link audit retains
original checked arguments and recovers changed object-path lines only when the
complete reconstructed bytes match the original logged SHA-256, preserving all
other quoting/flags. Exact recovered parameter bytes are retained. All artifacts
are compared through immutable qualification captures. This is bounded evidence
recovery; automatic parameter-file capture before subsequent profiles remains a
maintained qualification improvement, not an implemented guarantee.

## Workflow and remaining qualification

The existing build-bsd C interface and maintained format-5 backend already carry
selected SDK/kernel settings, targets/tests, build settings and job count. This
change updates source declarations, the reusable composition macro and docs.
No new CLI/schema, stage/signing/verification/publication policy or replacement
frontend is needed. Existing module compilation and artifact helpers are reused.

The bounded scan of fourteen LiquidIO C files, firmw.S and fw_stub.awk finds no
explicit source probe/audit markers. That does not establish absence of shared
header/subsystem instrumentation. Firmware register/get/put/unregister, validation,
version/error behavior and driver attach/reset/DMA/interrupt/rx/tx need runtime
coverage and observability review. Shared firmware-subsystem hooks should cover
lifecycle without repeating per-image probes or logging firmware contents.

Actual firmware loading/unloading, nonempty license behavior, hardware operation,
alternate image/configuration/KERNCONF/FDT and ARM64/RISC-V selections, live probes/
audit and loader compatibility remain open; see MODULE-LOADER-EXPORT-CONTRACT.md.
Whole world/module/pkgbase/hardware/bootstrap/publication, VM and CPU/memory/disk
I/O/disk-use/cache/sandbox performance gates remain open. Make stays production/
default; BIP is excluded. No host module loading, installation, upgrade or reboot.
