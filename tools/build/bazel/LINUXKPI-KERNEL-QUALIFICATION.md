# LinuxKPI built-in qualification

## Scope (2026-11-02)

46 selected LinuxKPI C sources have native amd64 GENERIC built-in object rules.
They retain native cc_library compilation and existing CTF conversion. Physical
headers are declared through 92 distinct source-owned closures across the common
Linux, architecture/network and dummy namespaces plus existing BSD dependencies.
The new common/include parent owner preserves the existing linux child package.
No production C, Linux compatibility behavior or runtime policy changed.

Compiler-local -I roots preserve common-before-dummy lookup for objects that
actually use those namespaces. Unused roots absent from a sandbox are omitted,
without creating placeholder directories or suppressing missing-include warnings.
CK's source-owned providers expose its real include directory. The extra CK search
root requested by linux_rcu remains explicit. All objects retain the maintained
forced -include kconfig.h, with the real source header declared as an input.

Six narrow option-header views reuse actual config(8) outputs. Bus/device, ACPI,
backlight, PCI/PCI-IOV/bridge and I2C interfaces use the existing schema generators;
vnode and offset products reuse the shared kernel providers. No Make-generated
headers, fake options or one-off compiler wrapper substitute for native actions.
Make metadata is a qualification reference, not a native build-time dependency.

The normal build-bsd bazel-test format-5 interface supplies the SDK, kernel
platform, CTF/debug settings, compact logs and 16 workers. No frontend C/backend
API, manual/CLI, signing/verification/staging or package-policy changes are needed
for this component graph. Make remains production/default; BIP remains excluded.

## Evidence and corrections

Paths are under /usr/obj/usr/src.

- bazel-kernel-linuxkpi-make-metadata-r1-20261102 captures maintained Make recipes
  without filemon. All 46 prior completed-kernel reference objects stay unchanged;
  selected C hashes match the independent inventory. This is metadata capture,
  not fresh Make compilation or a complete dynamic input trace.
- Native attempts r1/r2 retain sandbox failures for unused dummy include roots
  and missing CK lookup respectively. Source-owned dependencies/search roots were
  corrected; neither warnings nor feature configurations were weakened.
- r3 compiles and matches code/CTF, but the stricter compiler-policy review rejects
  its omitted forced kconfig include. r4 is the corrected final normal frontend
  build. Byte equality alone was not accepted as proof of correct compiler policy.
- bazel-kernel-linuxkpi-review-r2-20261102 is the accepted final review. The earlier
  partial review directory is explicitly marked unaccepted. A rejected attempt to
  reuse existing CTF report names remains visible; final CTF reports use a fresh
  output directory and bind to r4 immutable artifacts.

All 46 .text and .SUNW_ctf sections match Make byte for byte and pass the maintained
CTF semantic checker. Allocated payload/layout matches except 35 exact known-source
filename spellings. All other strings and 10,582 nondebug relocations compare
symbolically. No artifact is rewritten. Complete DWARF, string-table and symbol-index
byte equality is not claimed.

46 final successful actual compiler actions report cacheHit=false and bind 13,929
physical and 292 generated prerequisites to expected hashes. Ordered warnings,
defines, code-generation option sets, stack protection, final debug switch,
language and both forced includes match Make. The source-absolute Make kconfig
filename maps only to its hash-verified source-relative native input. Generated
interface comments map only the physical schema's absolute path to its actual
basename; original header hashes remain recorded. Debug-prefix/random-seed/output
paths remain explicit build-system differences.

Final raw compiler outputs bind through CTF input/output hashes to final immutable
captures. Where Bazel reuses identical converted output, matching earlier execution
records provide converter provenance; they do not substitute older compiler policy
for the final r4 actions. Upstream compact-log reconstruction verifies all 189
recorded converter bindings before/after and records log hashes and exit status.
Expanded JSON is streamed rather than materialized. Review/source/profile hashes
and correction records remain retained.

Final known built-in query r20 passes for 824 groups and 999 compiler actions.
Guarded reconciliation r15 finds 990 source matches, two object-name and four
generated-name matches, with 1,470 unmatched among 2,466 Make final link products.
Three auxiliary generator objects are separate. Query r19 predates the forced
include fix; r20 is the current analysis evidence. Counts describe the known amd64
graph, not a complete linked kernel or all architecture coverage.

## Observability and remaining gates

A bounded source-hash-bound call-shaped scan finds tracing/CTR markers in
linux_80211_fullmac.c, linux_firmware.c, linux_shrinker.c and linux_work.c. No
production hooks changed. Missing scan matches in 42 files do not prove missing
shared instrumentation or absence of other tracing mechanisms.

tests=[] does not exercise a running kernel. Wireless/firmware callbacks, workers,
RCU/scheduling, memory pressure, PCI/USB/I2C/ACPI and actual LinuxKPI consumers need
runtime qualification. Complete native kernel link/order/identity/post-processing/
install, loadable modules, other KERNCONF, ARM64/RISC-V64, world/pkgbase/hardware
publication, bootstrap and runtime/VM checks remain open. Disk reserves pass;
controlled CPU/memory/disk I/O/disk-use/cache comparisons remain open. No host
installation, upgrade or reboot occurred.
