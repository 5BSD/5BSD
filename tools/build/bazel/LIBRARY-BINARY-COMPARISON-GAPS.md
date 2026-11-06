# Complete binary checks for the 23-parent directory-policy cohort

## Result (2026-11-06)

All 23 previously completed positive directory-policy parents were checked using
captured native installation archives and their original per-component Make
controls. All parents ran; none were filtered out. The check compares actual
installed payloads, not source lists or construction status. Eight parents pass
all binary contracts tested. Across the cohort, 77 contracts pass: 13 static
archive member/order/symbol comparisons, 20 shared-library metadata comparisons
and 44 program metadata comparisons. Twenty-six checks fail across 15 parents.
The earlier namespace/directory/non-ELF/debug-link results do not establish these
binary contracts and remain valid only for their recorded scope.

Evidence under /usr/obj/usr/src:

- bazel-library-directory-binary-review-r1-20261106: input plan, frozen checker,
  all 23 logs/reports, verified captured payloads and per-binary passing reports.
- bazel-directory-remaining-native-r5-20261106: original immutable native capture.
- bazel-directory-remaining-review-r2-20261106: earlier passed directory cohort.
- bazel-directory-<component>-make-r1-20261106: each independent Make control.

## Required reconciliation

| Check | Count | Components and next action |
| --- | ---: | --- |
| Installed test linkage | 10 | libcapbundle (7), libcapimage (2), libcapreclaim (1): native tests are static EXEC with no interpreter; original Make tests are dynamic PIE. Use native dynamic component/ATF links and keep host execution support separate from installed payloads. |
| Test runtime paths | 2 | libcapsulert claim_parse_test/storage_namespace_test: candidate search paths differ from original. Original source embeds an OBJTOP path, which is itself unsuitable for installed tests. Reconcile the original installation policy as well as the native build; do not copy that build-tree path into Bazel. |
| Static member ordering | 6 | libfidl, liblogcmp, libnetworkcmp, libnotify, libtimecmp, libtracecmp: inspect each actual source-owned order and declare it without dropping members. |
| Extra dynamic dependency | 2 | libpowercmp and libtimecmp DSOs: native adds libthr.so.3, absent from Make. Inspect declared direct/transitive ownership and original link policy. |
| Ordered dynamic dependencies | 2 | libnotify DSO and libsysdecode test: dependency sets match but load order differs. Preserve source-owned ordering and interposition behavior. |
| Path-derived DTrace symbols | 4 | libcapsulert, libchannel, libservice, libshmring archives: all observed changed symbol records are generated $dtrace<key> aliases. Raw comparisons remain failed. Validate actual DOF/function/relocation/site correspondence before accepting semantic equivalence; do not strip these symbols or weaken the comparator. |

Follow-up actual-member validation now passes for the four DTrace archives:
5 provider records, 46 matching schemas and 63 independently validated ordinary
sites on each side; all non-DTrace member symbols and archive orders match.
Raw symbol failures remain retained, and static-consumer/live-tracing behavior is
not proved. See DTRACE-RELOCATABLE-METADATA-QUALIFICATION.md and
bazel-library-static-dtrace-review-r1-20261106 for the companion-object bindings.

The four recorded ELF direct/ordered dependency gaps now match original Make:
powercmp/timecmp no longer add direct libthr, and notify/sysdecode retain original
load order. All four complete parents, installed ELF contracts, 24 debug checks
and the original installed sysdecode body/native runtime checks pass. Raw traced
archive differences remain visible with unchanged object bytes. See
LIBRARY-DYNAMIC-DEPENDENCY-QUALIFICATION.md. These close this cohort's identified
dependency gaps, not unreviewed whole-tree ABI/runtime or full installation gaps.

The remaining nine recorded static substitutions and original test RPATHs are
now reconciled. Three full installation parents and all 11 affected dynamic test
programs match original controls; 204 safe host body targets pass. Eight capimage
kernel/root cases and 17 capbundle shell-format bodies remain unexecuted here.
See CAPABILITY-INSTALLED-TEST-QUALIFICATION.md. All ten initial cohort static
substitutions are closed including capreclaim; direct/ordered DSO and broader
full-library/system gates remain open. Historical initial findings are retained.

The libcapreclaim installed-test linkage gap is now fixed: the dynamic native
installation matches Make, all 28 original bodies pass with declared native
runtime, and full original metadata/ELF/debug/package controls pass. The separate
static host candidate is retained as an additional variant. See
CAPRECLAIM-NATIVE-TEST-QUALIFICATION.md. Those nine later fixes are recorded in the follow-up above; historical counts
remain the initial cohort findings.

All six static member-order gaps are now corrected and independently compared
in both DTrace modes. All member symbols match without DTrace; traced ordinary
symbols and actual DOF bindings match while raw generated alias differences are
retained. Three feature-mode construction runs pass. See
LIBRARY-STATIC-ORDER-QUALIFICATION.md for the twelve comparisons and prototype
construction limits. Installed test linkage, runtime paths and dynamic dependency
gaps remain open; this does not establish static-consumer or body execution.

The separate libfidl actual-object check establishes matching 19 schemas and 26
patched sites on both sides while retaining its archive-order/raw-symbol
limitations. See LIBFIDL-BINARY-QUALIFICATION.md. The follow-up above qualifies the other four archives' DOF bindings only.
No original bodies execute in these comparisons.

## Ordering and integration

Complete the already active source-bound full-library native and Make controls
before changing any library BUILD/Make input. Preserve their current results even
if installation metadata matches: the binary gaps above remain independent.
Then correct and qualify the actual component definitions, including applicable
feature variants and declared dependency/cache behavior. Re-run these captured
comparisons after reconstruction; retain failures for review.

No frontend/backend/schema/signing/manual option change is needed for these
read-only artifact comparisons; they consume maintained format-5 workflow captures.
Any subsequent installation/linkage input change must be checked against the
normal frontend and documentation in the same implementation change.

Full ELF bytes, raw DWARF, debugger usability, live probes, full ABI/runtime,
whole world/kernel/modules/pkgbase, ARM64/RISC-V, bootstrap/cache/sandbox,
CPU/RAM/disk-I/O/footprint and combined publication gates remain open. These
bounded comparisons are not a system-wide completion percentage. Make stays the
production default and BIP is excluded.
