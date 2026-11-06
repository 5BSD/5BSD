# Source-owned static module parent hierarchy (2026-11-06)

## Implemented traversal

Twenty-four unconditional source SUBDIR parents now declare typed AMD64 module
sets and base installation targets. The cohort covers 134 unique module products:
HID (23), GEOM including its partition children (15), Intel wireless firmware (13),
Realtek wireless firmware (10), NTB and Bluetooth (7 each), FireWire/Hyper-V/ISP
firmware/QAT firmware (6 each), and smaller source families. These are source
build declarations; the original leaf owners retain compilation and artifact policy.

bsd_kernel_module_set consumes explicit product and child-set dependencies. Its
provider carries the selected members and real payload Files; its inventory names
source labels, runtime/debug Files, aliases, owners and installation attributes.
Repeated products and runtime/alias basename collisions fail. Nested sets share
actual configured products, without changing compilation configuration or copying
payloads. Empty sets can represent disabled branches, but an empty module-only
installation fails rather than claiming an installed module payload. A full kernel
profile without modules must omit that optional installation component.

The current hierarchy includes GEOM -> geom_part as a real nested source parent.
GEOM's existing public filegroups remain available. The prior FireWire target is
preserved and consumes the new set. All new cohort targets explicitly require the
FreeBSD AMD64 platform; this does not introduce an alternate-architecture fallback.

## Source migration and independent checks

A retained one-time migration reads only literal unconditional SUBDIR declarations
with known source includes, rejects computed/conditional parents and writes normal
checked-in BUILD declarations. It is not called by production rules. No Make query,
source parser, frozen global selected-module list or installed-tree scan runs in
native build actions. Conditional/unresolved parents remain explicit future work.
Changing source membership requires maintained source declarations and audit review.

Under /usr/obj/usr/src:

- bazel-module-static-parent-migration-r1-20261106 retains the survey, migration
  implementation, original existing BUILD files, exact source hashes and changes.
  The survey deliberately leaves twelve unresolved literal and 33 other logic/
  conditional parents; it does not label them converted or silently select defaults.
- bazel-static-module-parents-native-r1-20261106 passes the normal maintained
  format-5 frontend with sixteen jobs, 61 selected targets and thirteen test targets.
  Three new tests execute: nested selection, repeated-member rejection and empty
  installation rejection. Earlier test executions are valid cached results. Real
  producer outputs can also reuse cached actions; fresh recompilation is not claimed
  for every module.
  Receipt SHA256 2469681ea0a1d38568aab08c79e1a0868823a33d0a103c0c801319602d57f617
- bazel-static-module-parents-review-r2-20261106/review.json compares all 24 exact
  parent SUBDIR lists with original Make. It verifies all set member labels, complete
  base/debug installation records, propagated source attributes and actual shared
  producer identities across overlapping parent views. The 24 views contain 138
  member occurrences / 276 installation records; GEOM's four partition modules
  are also captured separately. There are exactly 134 unique modules.
- That review separately queries every original leaf in the selected kernel install
  context, requiring equal KMOD names, owner/group, numeric mode, package/debug tags,
  debug prefix and link policy. All 134 actual ELF/debug-link/CRC pairs pass. Source
  hashes remain unchanged. The earlier selection inventory is used only as an
  independently checked membership reference, never as a production dependency list.
  Review SHA256 d46ccd7a0d1506d6353f777faf7bf4afbee48f75f66fc801da6abdae39072e88

This is source traversal, producer binding and installation-policy qualification.
It is not an independent fresh Make compilation of all module bytes, actual full
kernel installation, linker.hints, package archive, module loading or hardware/
service runtime proof. Current profile uses separate debug files; other kernel/
source-option profiles and architectures still require their own qualification.

## Frontend and next work

Existing format-5 targets and settings express the cohort. Backend rule, source
parents, tests and manual are updated together; no frontend C option, staging/signing/
publication contract or production/default change is needed. No host installation,
module loading, upgrade or reboot occurred. Standard /usr/obj staging and separate
hardware/combined publication requirements remain. BIP remains excluded.

Next migrate conditional/source-option parents and the root module traversal with
shared explicit kernel/source option authority. Compose complete kernel/GDB,
modules, directories/aliases/linker.hints and kernel-flavored pkgbase output, merging
explicit non-kernel module owners into world packages. Keep original complete Make
selection/staging/package comparisons, normal boot/services, real upgrades, other
platforms, bootstrap/cache/sandbox/reproducibility/debug/performance and verified
combined-publication gates open. Make remains production/default.
