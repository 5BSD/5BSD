# Native ACPI support module qualification

2026-11-01. Native GENERIC-tied candidates now cover all sixteen maintained
amd64 ACPI support modules and the two ARM64 selections, acpi_einj/acpi_ged.
Genuine root and directory Make queries select those sets. The maintained root
does not select this directory on RISC-V64; no unsupported target was invented.
Each selected module retains its original one-C-file source inventory and
export/install behavior. Runtime hardware operation remains unqualified.

## Build design

Actual maintained source files compile through the existing native module
rules; no runtime Make parsing or discovery JSON is consumed. Physical source
headers stay in their actual owning packages. Existing native .m generators
supply acpi, WMI, APEI, backlight, bus and device interface headers. Genuine
native GENERIC option headers cover the maintained SRCS options plus actually
consumed indirect opt_kbd headers. No empty-header or SDK substitute is used.
Original warnings, target triples and ordinary module forced-header policy
match captured Make CFLAGS exactly, preserving the existing typed WERROR choice.
No source, module ABI, Make rule or shared warning policy was changed.

The initial analysis caught incorrect option-target labels, corrected to the
existing generic_opt_* targets with narrow ARM64 consumer visibility. A later
strict compile-action audit rejected an incorrectly inferred warning policy:
Make does include -Wno-unknown-pragmas. The unnecessary new warning policy was
removed completely and all four profiles rebuilt with the existing shared
flags. Earlier successful artifact comparisons did not excuse a failed policy
audit. Thirty-six rejected actions and the corrected reference-scope record
remain retained; no comparison was relaxed to accept the omission.

## Evidence

All thirty-six fresh independent Make build/install references passed under
/usr/obj/usr/src/bazel-acpi-support-make-20261101. Reference builds use genuine
copied/hashed GENERIC options, isolated object and staging trees, and four jobs
with four compilation workers each on the sixteen-CPU host.

All four final build-bsd format-5 profiles passed under
/usr/obj/usr/src/bazel-acpi-support-{amd64,arm64}-{plain,ctf}-r3-20261101:

- Thirty-six module comparisons and fifty-four exact installation records.
- Eighteen plain modules byte-identical to Make.
- Eighteen installed CTF modules with equal section metadata and payloads except
  build-ID/debuglink; .SUNW_ctf is exact. Both actual native/Make debuglink CRCs
  verify. Separate debug-file DWARF byte identity is not claimed.
- Thirty-six actual compiler actions with exact maintained warning flags,
  source hashes, target triples and forced opt_global.h policy.
- All 192 option-header input hashes match genuine reference files, and all
  thirty-six captured link lists retain original source/object order.
- All physical Make source/header prerequisites appear in actual native inputs
  with their source hash: 3,870 checks across 172 unique source/header files.

Every captured artifact is checked through qualification_artifacts.resolve
receipt/manifest/content bindings. Commands, artifact/install/action/header
comparisons, observability scan and helpers are retained under
/usr/obj/usr/src/bazel-acpi-support-review-r3-20261101 and
bazel-acpi-support-native-runs-r3-20261101. Initial references reside in
bazel-acpi-support-reference-review-20261101. r1 analysis failure and r2 rejected
warning policy/captures remain available, including
bazel-acpi-support-review-r2-20261101/rejected-warning-policy.json.

## Integration and remaining qualification

Existing frontend target/input profiles handle this module family; no frontend
C/CLI, SDK, staging, signing or publication changes are required. Its manual and
native README document this bounded gate. Make remains production/default and
BIP remains excluded.

These profiles select build/install outputs and contain no runtime tests.
Whole-kernel/module/package integration, additional kernel configurations,
ACPI hardware attach/detach, notifications, WMI/backlight/input behavior, APEI
fault injection, permissions and concurrency remain open. No host device was
opened, module installed/loaded or fault injected. Source-change/cache and
controlled CPU/memory/disk performance gates remain open.
