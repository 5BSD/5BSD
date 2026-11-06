# USB and test-framework module parent qualification (2026-11-06)

## Source-owned selection

The new sys/modules/usb BUILD declaration composes the existing native AMD64
products, including the existing nested rsufw module set. It preserves the actual
AMD64 source selection: urtw and uacpi included, other architecture-only controllers
excluded. The existing sourceless_ucode setting gates all eight source-controlled
firmware/driver families. The new boolean usb_gadget_examples defaults true, as in
kern.opts.mk; its enabled selector also requires usb=true because the source disables
gadget examples when USB itself is disabled. Directly building this parent still
selects its other products when usb=false, matching Make. Root traversal will decide
whether the whole family is selected; it must not reinterpret that parent contract.

The source-owned tests parent selects the existing framework producer. The original
.WAIT is an ordering barrier, not another file/module. Root TESTS selection remains
separate; directly requesting this parent builds its declared framework just as Make
does. No runtime source, module link policy or package owner was changed. These
parents consume typed products rather than recomputing or copying their payloads.

## Actual builds and independent review

All evidence roots below are under /usr/obj/usr/src. Normal format-5 build-bsd
bazel-test profiles use the maintained explicit package SDK and all 16 CPUs:

- bazel-usb-module-parent-default-native-r1-20261106: USB plus test framework,
  83 unique runtime/debug pairs.
- bazel-usb-module-parent-off-native-r1-20261106: sourceless firmware and gadget
  examples disabled, 71 pairs; exactly 12 default members omitted.
- bazel-usb-module-parent-usb-off-native-r1-20261106: USB disabled while directly
  requesting the parent, 79 pairs; exactly four gadget examples omitted.

All profiles report 14 existing tests passed; cached test results are not new
executions or specific USB runtime tests. Each profile actually constructs/captures
the selected module-set and installation targets. The independent review compares
original Make parent SUBDIR and nested rsufw membership with every native member,
then checks every selected leaf's owner/group/octal mode/package/debug tags and
aliases. It compares complete runtime/debug installation records and destinations,
resolves hash-verified immutable payloads, and checks ELF loader identity/debug-link
CRC for all selected pairs in every profile. All common configured output paths and
runtime/debug hashes remain identical across the three profiles.

Evidence: bazel-usb-module-parent-review-r1-20261106/{audit.py,review.json}.
Review SHA256: adaa85c17d1d5862ed57ac0386cbae3856942a401f08c4bd7e4e8ef03adc0bed
The review retains original Make commands/stdout/stderr, actual source environment
and kernel-header context, payload receipt bindings and every per-leaf check.
bazel-usb-module-parent-migration-r1-20261106 retains the one-time source migration
and its option/architecture policy. This script is not a production build dependency;
no native action queries Make or reads a frozen global module inventory.

## Frontend and remaining qualification

Existing build-bsd format-5 build-settings/target/test inputs carry the new boolean
and requests without a C frontend change. The maintained source settings, new source
parents, manual and roadmap change together. Kernel selection and package helpers
need no new signing/staging/publication behavior for this cohort. Make remains the
production/default backend and BIP stays excluded.

This is AMD64 selected-product/membership/installation-metadata qualification, not
normal USB/device operation, a boot, or a full installed kernel/package result.
USB_DEBUG and USB_REQ_DEBUG inherited macro variants still need native typed input
and qualification; they are not covered by the default producer checks. ARM64 and
RISC-V parent selection, remaining kernel-option/root traversal and optional
producers, coherent kernel/GDB/modules/directories/aliases/linker.hints/pkgbase,
normal startup/login/PAM/SSH/capability services and real upgrades remain required.
All independent world/kernel parity, bootstrap/cache/sandbox/reproducibility/debug/
resource/hardware/combined-publication gates retain their separately recorded scope.
No host installation, module loading, upgrade or reboot was performed.
