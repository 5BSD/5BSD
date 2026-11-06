# Shared TCP hook configuration and module selection (2026-11-06)

## Implementation

`kernel_option_settings.bzl` declares the existing ZSTDIO/NFS_ROOT overrides and
new boolean `//tools/build/bazel/config:kernel_tcp_hhook` (default true) for all
three GENERIC configuration producers. The source-built config parser remains
the authority for actual headers and object inventory. The same typed TCP setting
selects four optional congestion-control modules and h_ertt in the new source-owned
cc/khelp parents. Four other congestion-control modules remain unconditional.
Configuration captures now include the exact override file in their metadata.

A source-disabled khelp component explicitly permits an empty install manifest.
The installation rule defaults to rejecting empty selection, and its existing
negative test still passes. This permits a legitimate optional component; it is
not permission to build an empty kernel image or omit required content.

## Original Make defect and correction

The independent disabled-profile check reproduced a real defect: both original
Make parents inspected OPT_GLOBAL, which was undefined in this path. Its fallback
selected all hook-dependent modules despite an actual generated header tree with
TCP_HHOOK disabled. Retained original failure:
`bazel-tcp-hook-original-make-failure-r1-20261106/{audit.py,review.json,kernel-options}`.

Both Make parents now include kmod.opts.mk and inspect the existing resolved
KERN_OPTS for tied builds. Untied standalone builds retain their previous full
family selection; ALL_MODULES remains an explicit full-family override. Independent
queries verify all three modes against actual generated header trees. No Make
query or migration inventory becomes a native production build action.

## Evidence

All paths below are under /usr/obj/usr/src. Three normal build-bsd bazel-test
profiles use all 16 CPUs and explicit format-5 settings:

- `bazel-tcp-hook-final-on-debug-native-r1-20261106`: 8 CC + h_ertt, separate debug.
- `bazel-tcp-hook-final-off-debug-native-r1-20261106`: 4 CC, empty helper component.
- `bazel-tcp-hook-final-on-nodebug-native-r1-20261106`: 8 CC + h_ertt, no separate debug.

Each passes 14 Bazel test targets. The permanent cross-layer test compares the
requested setting with the actual generated header, actual native member inventories
and helper install metadata; debug payload expectations derive from the actual
selected products. Existing empty-selection and collision regression checks remain.

`bazel-tcp-hook-final-review-r2-20261106/review.json` independently resolves
hash-verified captured outputs, checks Make tied/standalone/ALL_MODULES membership
for both parents in each profile, including deriving options directly from headers,
checks the generated override/header, and checks
all runtime ELFs plus all 13 selected runtime/debug CRC pairs in the debug profiles.
No-debug products explicitly contain no separate debug file.
Review SHA256: 65bd9db25e80bd8262ce7d0e3ca7a164bc13de1b69fff822ff97520520dcf10c

The maintained kernel-config-inventory-test.py passes 15 parser cases across AMD64,
ARM64 and RISC-V: default, ZSTDIO disabled, NFS_ROOT disabled, both disabled, and
TCP_HHOOK disabled. It compares each native parser object inventory/order with
original Make OBJS and exercises deterministic output and negative modes.
Evidence: `bazel-kernel-tcp-hook-parser-inventory-r1-20261106/receipt.json`;
`bazel-kernel-tcp-hook-parser-runtime-r1-20261106/preflight.json` binds the copied
native config executable and its native runtime libraries. These parser cases do
not cross-compile or boot kernels. Default object counts are 2455/2030/1189 for
this source snapshot; unrelated source updates can change earlier recorded counts.

## Frontend and remaining gates

The maintained build-bsd format-5 build-settings/target/test APIs already carry
these settings; no C frontend or signing/staging/publication protocol changes are
needed. Source declarations, backend rules, permanent tests, manual and plan change
together. These are native qualification profiles, not verified-boot, root-protection
or performance proof. Make remains production/default and BIP stays excluded.

The added explicit TCP override changes current configuration inputs. Earlier full
kernel parity receipts retain their earlier input scope; they are not a refreshed
full-kernel result for this profile. Remaining root selection, optional producers,
coherent kernel/GDB/modules/directories/aliases/linker.hints/pkgbase, fresh full
kernel build, normal startup/authentication/services, genuine upgrades, cross-platform,
bootstrap/cache/sandbox/reproducibility/debug/performance/hardware/publication gates
remain open. No host installation, module loading, upgrade or reboot was performed.

A subsequent fresh full current-profile native kernel link/CTF/debug build passes;
see CURRENT-PROFILE-KERNEL-QUALIFICATION.md. This closes construction for the
refreshed profile, not original Make parity, installation or runtime qualification.
