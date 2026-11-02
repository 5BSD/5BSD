# Complete native amd64 GENERIC link milestone (2026-11-02)

Historical initial link checkpoint: the later complete comparison found a
helper DSO DT_NEEDED build-path defect in these r2/r3 artifacts. They are retained
as rejected parity evidence. The corrected r4 build and independent full-object/
linked-kernel comparisons are in FULL-KERNEL-PARITY-QUALIFICATION.md.

The maintained frontend now builds all selected amd64 GENERIC objects, links the
complete kernel directly with declared lld/scripts, merges CTF and emits the
split runtime/debug artifacts. The new linker consumes the ordered File provider
and parser-validation marker. There is no Make invocation, prebuilt kernel or
manually shortened selection in the native production actions.

## Implementation and actual build

`bsd_kernel_link.bzl` passes the exact explicit object order to a declared linker
response file. Its dependencies include the validated catalog marker, all
objects, the architecture linker script and its debug script include, plus the
selected SDK linker runtime. amd64's emulation/page/alignment/ifunc and dynamic
link/export policy matches the maintained Make architecture backend.

Existing `bsd_ctf_merge` and `bsd_debug_split` provide the following public targets
in `//sys/amd64/conf`:

- `generic_linked_kernel`: raw linked `generic/kernel.linked`.
- `generic_full_kernel`: CTF-merged `generic/kernel.full`.
- `generic_kernel`: split runtime `generic/kernel`.
- `generic_kernel_debug`: separate `generic/kernel.debug`.

The first complete attempt r1 rejected a missing declared audit-header dependency
in `generic_socket`: current `uipc_socket.c` includes security/audit/audit.h.
Adding the existing narrow audit header target fixes it. No C source, compiler
warning policy or global include exposure changed. r2 completes compilation/link;
r3 completes and captures all four artifacts with CTF/debug enabled.

## Verification

Evidence lives under `/usr/obj/usr/src`:

- `bazel-kernel-full-link-native-r1-20261102`: retained missing-header failure.
- `bazel-kernel-full-link-native-r2-20261102`: successful complete raw link and
  official execution record for the actual linker action.
- `bazel-kernel-full-link-native-r3-20261102`: successful CTF/split pipeline and
  immutable captures of all four artifacts.
- `bazel-kernel-full-link-review-r1-20261102`: verification described below.

The actual response-file bytes match their execution-log input digest before
parsing. Its 2,462 ordered object basenames exactly match the independent Make
final-link inventory. All recorded digest-bearing link inputs/tools are checked
against current bytes before and after review. Link flags exactly match Make
apart from independently resolved equal script/directory paths. The validation
marker is an actual declared linker input. The linked output digest matches the
immutable captured artifact.

Every allocated section retains identical metadata/content across raw link,
CTF merge and runtime debug splitting. The full/runtime outputs contain CTF;
full retains debug sections, runtime does not. The repaired socket object's code
and CTF sections exactly match the independent fresh Make reference.

All three actual postprocessing actions and 2,486 input/tool occurrences are
hash-verified. Independently queried original Make CTF/objcopy tools and flags,
using the same bound native raw link and object files with original basenames,
produce **byte-identical kernel.full, kernel.debug and kernel**. This proves
postprocessing parity for identical inputs. It does not prove that a separately
compiled complete Make kernel is byte-identical to this native kernel.

The maintained debug checker now has an explicit `--kernel` mode requiring
executable ELF and retained loader symbols. Userland and module modes keep their
existing contracts. The reusable `elf-kernel-debug-test.py` passes the real
kernel/debug pairing and rejects userland mode, module mode, conflicting modes,
corrupt debug contents and a mismatched debug filename. GNU debug-link basename
and CRC are checked without rewriting artifacts.

## Resource observations

Official executed-action metrics report approximately 0.81 seconds / 894 MB peak
for the raw link, and 16.37 seconds / 1,053 MB peak for CTF merge in these cached
cohort runs. These are individual action observations, not whole-build memory,
cold-build timings or controlled Make-versus-Bazel performance conclusions.
The disk budget guards pass. CPU, total memory, disk I/O/usage and cache/sandbox
performance qualification remain required before any production default change.

## Frontend integration and limits

The normal format-5 `build-bsd bazel-test --bazel-inputs ... --jobs 16` workflow
builds these declared targets. Backend rules, script exports, checker/tests and
documentation changed together. There is no new frontend CLI option to document
or alternate build frontend; frontend C therefore needs no change in this cohort.
The explicit version input is held fixed across r1/r2/r3 to isolate build-policy
repairs; it is a supplied version label, not an attestation of all worktree bytes.

**Still required:** broader full-kernel compiler/prerequisite/debug/CTF parity,
other feature/configuration and architecture builds, installation/pkgbase
metadata including debugger helpers, module/driver closure, complete world,
bootstrap/package/hardware/publication qualification, VM boot and normal-service
runtime acceptance, and controlled performance/cache/sandbox qualification.
No kernel was installed, no host upgrade/reboot occurred, and no VM was booted
with this kernel. Make remains production/default. BIP remains excluded.
