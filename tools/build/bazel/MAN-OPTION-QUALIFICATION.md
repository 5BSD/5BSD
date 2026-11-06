# Native MAN option qualification

## Source-owned behavior (2026-11-06)

The current selected AMD64 world now honors MAN=false for manual file and alias
installation. The correction is at the owning installation entries, not a final
archive/inventory pathname filter. Existing format-5 inputs select
//tools/build/bazel/config:man; true remains the default.

bsd_install_file and bsd_install_link accept an explicit manual boolean. For a
manual entry with MAN disabled, the typed provider contributes neither source nor
metadata; manifest composition skips that absent entry before composing payload
dependencies and validating hardlinks. Ordinary entries retain their previous
behavior. Shared utility/script/manual/command/libarchive/OpenSSL helpers mark
manual entries and aliases explicitly. Mixed source tables carry an is_manual
field; binary/header/configuration/schema/license entries remain ordinary.
GEOM's custom manifest uses the same typed setting when declaring its manual
record and payload. No program C/C++/assembly or kernel source was changed.

The source review compares all 257 changed BUILD/Starlark files to their original
ASTs. 251 preserve source declarations except explicit manual keyword arguments
and role tuple fields. Six implementation/integration changes are separately
reviewed: the common typed-entry rule, GEOM custom manifest, OpenSSL wrapper,
inventory configuration snapshot, maintained test registration and gzip directory
ownership. Additional inventory Python code only records the declared MAN input.
There is no runtime source scanner or filename heuristic in these producers.
Temporary edit scripts are not part of the production build.

## Whole-world output evidence

Both final profiles pass the maintained build-bsd bazel-test frontend using all
16 logical CPUs, standard /usr/obj inputs and immutable artifact capture.
The enabled world retains all 32,518 file/link records. The disabled profile has
14,546 file/link records and zero paths in either manual namespace, including
aliases and indexes. The audit accounts for 17,971 removed manual paths (pages,
aliases and two indexes). This disabled profile also explicitly turns servicesdb
off; its one separate generated database difference is recorded independently.
MAN does not control servicesdb.

Every remaining ordinary file/link record is unchanged. All 13,397 captured
ordinary regular/hardlink file payloads are byte-identical between profiles;
symlink destinations are checked through their unchanged metadata. Relative to
the prior complete default native capture, 1,279 of 1,280 archives remain exactly
byte-identical. The bsd-build archive differs only in its maintained manual;
its decompressed manual matches the recorded source hash. This is native output
preservation, not independent whole-world Make binary or package parity.

Source-owned physical/empty directory policy remains distinct from MAN payload
inclusion. No builder filesystem permissions or placeholder files are substituted.

## Independent Make and maintained tests

Fresh original Make libmd and gzip build/install controls pass with MAN enabled
and disabled, TESTS disabled and all 16 CPUs. Native complete component namespace,
owner/group/mode/flags/package metadata, actual hardlink topology, directory claims
and all non-ELF/nonarchive contents match. libmd has 126/17 paths enabled/disabled;
gzip has 24/12. These checks exclude ELF/static archive equivalence explicitly.
They are two independent component controls, not a complete Make world control.

The gzip comparison exposed an existing missing utilities claim on /usr/bin.
Its source-owned archive policy now includes the original Make claim. All four
component comparisons pass after the repair; the earlier failure is retained.

The new maintained //tools/build/bazel:world_man_option_test consumes the COMPLETE
world inventory and its typed configuration snapshot. It requires manual payload
when enabled and rejects any manual payload/index when disabled. It does not
filter installation output. This catches newly added unmarked manual producers.
The enabled run passes four wrappers: the whole-world guard, seven inventory
unit methods and two six-case real-pkg fixture wrappers. The disabled run passes
the guard and the same seven inventory unit methods. Overlapping methods are not
additional original system test bodies. No installed login/PAM/SSH or VM body is
claimed from these tests.

## Evidence under /usr/obj/usr/src

- bazel-man-enabled-request-r2-20261106 and
  bazel-man-disabled-request-r2-20261106: explicit final format-5 inputs.
- bazel-man-enabled-native-r3-20261106 and
  bazel-man-disabled-native-r10-20261106: passed final profiles and guard tests;
  both include complete fresh-world archive capture and selected components.
- bazel-man-lib-libmd-yes/no-make-r1-20261106 and
  bazel-man-usr.bin-gzip-yes/no-make-r1-20261106: passed original Make controls.
- bazel-man-libmd-enabled-review-r2-20261106,
  bazel-man-gzip-enabled-review-r2-20261106,
  bazel-man-libmd-disabled-review-r1-20261106 and
  bazel-man-gzip-disabled-review-r1-20261106: passed component comparisons.
- bazel-man-world-review-r1-20261106: every source-selected world record and
  captured ordinary payload, original native archive hashes and manual-source proof.
- bazel-man-owner-source-review-r3-20261106: reviewed owner AST changes and hashes.
- bazel-man-option-final-review-r1-20261106: passed hash-bound combined evidence.

Intermediate runs retain the real discovery failures: missing alias roles,
incomplete mixed-table edits and their corrections. r5 had a mistyped optional
execution-log receipt environment path; it nevertheless produced a passed
receipt. Final runs explicitly use the correct converter receipt. No failed run
was relabeled or used in place of final evidence. Earlier inventory audits that
reported the MAN gap remain unchanged as historical counterexamples.

Frontend review: existing format-5 MAN input selects this work. Maintained entry
rules, source-owner declarations, inventory configuration, tests and manual are
updated together; no new frontend C/CLI, signing/publication or default change is
needed. Independent whole-world/kernel/module/debug/pkgbase parity, complete
source-owned package family metadata/dependencies and archive assembly,
package-driven construction/account preservation, normal installed services,
ARM64/RISC-V/bootstrap/cache/sandbox/reproducibility and CPU/memory/disk-I/O/
footprint gates remain open. Make stays production default. BIP remains excluded;
no host installation, upgrade, publication or reboot was performed.
