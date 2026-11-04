# Standalone legacy BIOS ABI qualification (2026-11-04)

## Change and supported scope

boot0, serial boot0, MBR, protective MBR and cdboot now compile their original
assembly in the verified SDK's standalone i386 configuration. Their public image
and object labels cross explicit freestanding artifact boundaries; CcInfo does
not escape into hosted userland. The selected SDK linker runs directly with the
original entry, origin, script, flat-image, strip, build-ID and hardening policy.
The two internal BTX producers already use this architecture in ce0571fea12.

This replaces hosted AMD64 cc_binary construction with manual 32-bit flags. A
flat BIOS image is represented as data, not an executable for the host. Source
assembly, shared headers, Make recipes, compiler operands and installed names
remain intact. The serial target still compiles the shared boot0.S with SIO and
installs boot0sio; original Make's intermediate is named boot0. The original
whitespace-containing COMSPEED compiler operand remains one argument. Passing
compiler-only flags through a second compiler-driver link is no longer needed.

The qualified profile retains the existing selected Make defaults. Additional
Make OPTS, flag/tick/serial overrides and non-default boot-policy coverage remain
to be implemented/qualified before complete build-option parity is claimed.
There is no runtime Make query or imported Make object in the native graph.

## Evidence

All evidence roots below are under /usr/obj/usr/src.

- bazel-cdboot-make-r1-20261104 and
  bazel-legacy-standalone-{boot0,boot0sio,mbr,pmbr}-make-r1-20261104:
  five fresh maintained original Make constructions/installations, each with
  sixteen jobs, original recipes, dependency files and source/SDK bindings.
- bazel-cdboot-r1-20261104: initial standalone cdboot construction through
  the normal build-bsd bazel-test interface.
- bazel-cdboot-review-r1-20261104: cdboot object/image whole-byte equality,
  compiler/link chain and actual image/manual archive metadata/payload checks.
- bazel-legacy-standalone-r1-20261104: final five-component construction and
  real legacy installation archive through build-bsd with sixteen CPUs.
  All 24 selected tests pass: one executes and 23 reuse cached results for
  unchanged test inputs. This is not 24 freshly executed tests.
- bazel-legacy-standalone-review-r1-20261104: five whole-byte equal objects,
  five whole-byte equal images, ten compiler/link chains and six original
  installation records. Actual compiler vectors retain all source-owned
  original operands in order, with SDK/dependency/output/search-root plumbing
  accounted for separately. Every original consumed source/header is bound to
  its actual native action input digest; the selected compiler bytes match.
  Each link binds exactly its own object and original linker script, correct
  i386 emulation/entry/origin, SDK linker and flat output policy. The real archive
  contains exactly five images and cdboot's compressed manual, with matching
  payloads, root/wheel ownership, 0444 modes and original package metadata.

The final audit also verifies nineteen unchanged prior boot products: sixteen
EFI images, the BIOS Lua image/archive and boot2's combined boot image. The
legacy artifact test continues to check ELF32 inputs, BIOS signatures/partition
slots, serial differentiation and BTX structure. Existing negative corrupt-image
and wrong-ABI assertions are unchanged. Cached test results are not represented
as fresh firmware execution.

The initial audit scripts needed corrections to resolve an execroot-relative
compiler through its logged digest, select boot0sio's original intermediate
name, and select the archive tar separately from its JSON metadata outputs.
No production recipe or regression assertion was relaxed for those audit fixes.
The final successful scripts and their bindings are retained with the review.

## Frontend, observability and remaining gates

The maintained build-bsd.c dispatch and format-5 backend already accept these
source-owned public labels and installation providers. The existing stage,
archive, signing and publication policies need no new interface or exception;
the manual records the standalone ABI boundary. No alternate build entry point
or publication repository is introduced.

Original preboot assembly and diagnostic paths are unchanged. No OS DTrace or
BSM audit provider is present in these components; native artifact equality does
not establish runtime observability or firmware behavior.

Firmware/VM boot, alternate boot policy, other stand consumers, complete
world/kernel/pkgbase/hardware publication, bootstrap, source/debug mapping,
broad sandbox/cache and CPU/memory/disk I/O/disk-space acceptance remain open.
These small construction comparisons are not a system performance benchmark.
Make remains production/default. BIP is excluded. No running-system installation,
host upgrade, reboot or package publication occurred.
