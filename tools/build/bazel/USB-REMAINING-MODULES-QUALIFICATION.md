# Remaining selected USB module qualification

## Scope (2026-11-02)

All 63 remaining local-BUILD gaps in the reviewed amd64 GENERIC USB subtree now
have native module declarations. The cohort covers USB core and host controllers,
HID/input, serial, storage, WLAN, gadget/template, video, GPIO/I2C bridges and two
firmware modules. It contains 103 unique module/object compilation contexts:
99 ordinary C/KOBJ contexts and four firmware C/assembly contexts. usb_if.c is
legitimately compiled for two distinct modules. Ordinary declarations use 87
compiler groups and 110 exact physical header contexts, reusing 67 providers.
Existing export policies are preserved. Other existing USB declarations are not
newly qualified merely by closing these local-BUILD gaps.

## Actual original Make defect fixed

Original i2ctinyusb listed its C source twice. Its actual original linker command
included the object twice and produced duplicate driver metadata and sysinit
entries. The source Makefile now lists the C file once; the native source/object
inventory does likewise. Original controls/artifacts and the initial native
analysis rejection remain intact. Fresh corrected original Make controls pass
both variants. The actual compiler argv is unchanged; both corrected Make and
native modules now contain one registration instead of two. This is an explicit
Make correctness fix, not a weakened duplicate-input check or normalized artifact.

## Native firmware and generated inputs

The runfw and rsu-rtl8712fw modules use the maintained source payloads. Existing
native uudecode produces each declared binary; existing native AWK actions run
fw_stub.awk with explicit module/name/version inputs to generate registration C.
Their outputs match Make exactly. Existing normal cc_library assembly compiles
the original firmw.S, and the existing object-alias rule gives each compiled
object its original .fwo link name without rewriting its bytes.

The module compilation helper adds optional additional_compiler_inputs (default
empty), forwarding it to cc_library. The firmware blob is an explicit input to
.incbin compilation, including its actual input digest; it is not discovered via
ambient filesystem access. FIRMW_FILE is a properly escaped literal C string
containing that declared output path. Standard KOBJ, USB ID/config/offset/vnode
producers supply other generated inputs. The new USB data-ID header uses the
existing declared device-ID AWK rule and original script with -d; all consumed
native header bytes match their original Make counterparts.

## Evidence

Paths below are under /usr/obj/usr/src.

- bazel-usb-remaining-module-source-facts-r1-20261102 preserves initial selected
  parent context, inventories and Makefile hashes. It includes the original
  duplicate i2ctinyusb entry, explicitly corrected above.
- bazel-usb-remaining-module-make-references-r1-20261102 contains 126 passing
  untouched original build/install controls; bazel-usb-i2ctinyusb-corrected-make-
  references-r1-20261102 adds the two corrected leaf controls. Each runs with all
  sixteen CPUs, one control at a time; none installs on the host.
- bazel-usb-remaining-modules-ctf-debug-native-r3-20261102 and
  bazel-usb-remaining-modules-plain-native-r1-20261102 are accepted normal build-bsd
  runs. Each selects 189 module artifact/debug/install targets, six firmware
  outputs, ten prior sound artifacts and six existing family provider regressions.
  Those six tests do not establish USB device behavior or firmware loading.
- bazel-usb-remaining-modules-review-r1-20261102 binds 99 actual ordinary compiler
  actions and 13,248 original consumed prerequisite occurrences, plus four actual
  firmware compiler actions and 164 prerequisites. Explicit .incbin payload input
  hashes are additionally checked because Make compiler depfiles omit that data.
  Source/compiler/policy/input hashes and all 63 ordered initial links pass.
- All 63 plain modules match their respective original Make references byte for
  byte: 62 untouched controls and corrected i2ctinyusb. CTF/debug runtime section
  inventories, metadata and payloads match except GNU build-ID/debug-link values;
  CTF bytes agree exactly. Both Make/native debug CRCs validate. All 189 file-
  install records across both variants match. Whole DWARF equality is not claimed.
- Twenty prior sound module artifacts remain byte-identical after the helper's
  optional input parameter. Source scans and compiled-probe-preservation.json
  retain existing probe sections and relocations; live events remain unqualified.

## Retained rejected attempts and actual cache evidence

The first native attempt rejected duplicate i2ctinyusb inputs before compilation.
The second compiled ordinary inputs but rejected a firmware FIRMW_FILE definition
whose quotes were removed by copts tokenization. The corrected declarations escape
those literal characters; original assembly/payload bytes are unchanged. Both failed
runs and correction records are retained. No test or validation policy was weakened.

The accepted retry reused successful ordinary actions from the partial second run.
The input audit retains actual execution records from both complete compact logs,
checks duplicate contexts for identical argv/input hashes, and identifies their
source logs. It does not invent fresh/cached compiler spawns for skipped actions.
The physical-source-only observer was corrected to distinguish usb_if.c's two
legitimate module contexts. Full cache/sandbox/incremental performance qualification
remains separate and open.

## Maintained workflow and remaining qualification

The existing build-bsd C interface and maintained format-5 backend already carry
selected SDK/kernel inputs, targets/tests and job count. This change updates
source rules, the optional compiler-input helper, the original Make defect and
qualification docs together. No new CLI/schema, signing/staging/publication policy
or replacement frontend is needed. Make metadata is migration evidence only;
production native actions never invoke Make for graph discovery.

Controller discovery, device enumeration/hotplug/reset, transfer cancellation,
DMA/interrupt ownership, HID/serial/storage/video/WLAN/gadget functionality,
firmware registration/loading/unloading and errors need runtime/hardware coverage.
Live probes and audit, strict/default loader behavior, alternate KERNCONF/FDT and
ARM64/RISC-V selections remain open; MODULE-LOADER-EXPORT-CONTRACT.md explains
static export-test limits. Source marker/probe-byte preservation is not runtime
coverage. Complete world/modules/pkgbase/hardware/bootstrap/publication and
CPU/memory/disk I/O/disk-use/cache/sandbox performance gates remain open. Make
stays production/default; BIP is excluded. No host USB module loading, system
installation, upgrade or reboot occurred.
