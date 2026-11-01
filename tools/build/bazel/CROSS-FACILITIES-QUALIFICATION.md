# ARM64 / RISC-V facility and crypto modules

2026-11-01. Native BUILD declarations now cover backlight, firmware, CUSE and
cryptodev on ARM64 and RISC-V64, in addition to filemon. All four are selected
by both independently architecture-checked GENERIC Make inventories. This is
build/install/CTF evidence, not complete module/kernel, boot, device or runtime
qualification. Make remains the production backend; BIP is out of scope.

## Native source ownership

The existing cross object helper accepts a source-group name and compiler
options, preserving filemon's existing default labels/flags. This models the
two backlight source groups independently, including the generated interface
translation unit. Firmware, CUSE and both cryptodev sources remain original C;
no source, probe or error path was changed to make a build pass.

Backlight's platform option is extracted from the actual target config tree.
No empty replacement option header is synthesized. Its interface source/header
comes from the maintained makeobjops generator and declared .m input. Compiler
source mappings reproduce the generated source's Make provenance; outputs are
not rewritten for comparison. All ordinary headers, generated interfaces and
source selections remain declared native Bazel inputs. The established
relocatable / CTF / export / shared-link / debug / installation sequence is
unchanged. Firmware and backlight exercise the formerly unqualified shared
export-all branch; CUSE/cryptodev exercise export-NO. Both architectures use
native host generators and their own target headers/ABI/linker policy.

## Actual independent Make comparison

All sixteen fresh Make combinations (four modules, two architectures, CTF/debug
off or on) build and stage successfully. The reference captures parent-kernel
ARCH_FLAGS, all commands, object/dependency/generated files, CFLAGS/LDFLAGS/export
policy queries, isolated install METALOGs and resource counters under
`/usr/obj/usr/src/bazel-cross-facilities-make-20261101/`. Builds use all sixteen
logical CPUs; source/objects/repositories stay in the standard trees.
Install calls use normal unprivileged -U/-M/-D flags; NO_XREF avoids claiming a
linker.hints comparison. No host installation or module loading occurs.

The four maintained `build-bsd bazel-test --arch ...` runs each build eight
explicit module/install targets. Receipts are
`/usr/obj/usr/src/bazel-cross-facilities-{arm64,riscv}-{plain,ctf}-r1-20261101/`.
Input JSON files select the kernel target profile and existing typed CTF/debug
settings. No new frontend/backend, signing or publication API is introduced;
the normal maintained cross-target path is used and the manual is updated.

| Module | ARM64 plain bytes | RISC-V plain bytes | Entire no-debug files match Make |
| --- | ---: | ---: | --- |
| backlight | 10,344 | 11,312 | yes |
| firmware | 29,152 | 33,560 | yes |
| cuse | 36,544 | 45,592 | yes |
| cryptodev | 57,280 | 69,568 | yes |

All eight installed CTF/debug modules match every ELF section and section offset
except the contents of build-ID/debuglink. This includes code/data, dynamic and
ordinary symbols, relocations, CTF and SDT metadata. All native and Make debug
links validate against their actual separate debug files. Those separate files
differ in debug_info/debug_line/debug_str/build-ID/symtab and some file offsets;
full debug-file identity, debugger path resolution and source-level behavior
remain unqualified. No differing section is dropped from the retained reports.
All 24 file/debug install records match Make (destination, root/wheel, mode0444,
package=kernel and dbg tags). Directory metadata and linker.hints are not part
of that file comparison.

The exact reports and scripts are at
`/usr/obj/usr/src/bazel-cross-facilities-review-20261101/review.json`, with native
input JSON copies. Default and named source groups, generated-source compiler
options, actual options, multi-object linking and shared export-all are covered
by real consumers, not fixture-only claims.

## Build-resource observation and next gates

The ARM64 CTF run built a large native host-tool closure and wrote a
4,533,907,787-byte logical expanded JSON execution log. The following RISC-V CTF
run's log is 3,201,697bytes, showing that it did not repeat that entire closure.
These facts do not establish an execution-platform defect or acceptable build
performance. Expanded logging was already identified as a disk-overhead issue
in the maintained README; supported compact logging and compatible audit readers
remain required work. Large logs must be parsed with the maintained streaming
execution_log reader, never loaded wholesale. Stored logical size is not an
allocated-disk or disk-I/O measurement. Captured command counters are not a
matched Make/Bazel CPU, aggregate RAM or disk benchmark.

Next: extend real selected module/kernel bodies, preserve target options and
probe metadata, qualify matching-kernel load/unload plus device and failure
behavior, full pkgbase/kernel/world production, debugger behavior, mutation/cache
and controlled CPU/RAM/disk-I/O/disk-usage comparisons. For this cohort no device
was opened and no VM run is claimed.
