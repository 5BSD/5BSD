# Kernel package composition next steps (2026-11-06)

The earlier native aggregate built 729 AMD64 modules under its own selected option
profile. It did not compose a complete installed kernel package. Its component
manifests use the standalone module default /boot/modules, whereas original kernel
builds pass KMODDIR=${KODIR} from sys/conf/kern.pre.mk. Complete base composition
must bind module placement to the selected kernel context rather than globally
changing standalone module defaults or rewriting captured metadata.

## New independent audit

bazel-kernel-module-package-partition-r1-20261106/review.json (under
/usr/obj/usr/src) resolves all 729 immutable component manifests and passes all
1,461 records through the actual Make mtree-to-plist.awk kernel policy. Package
owners include kernel, mac-abac, oes and tests, with separate debug partitions.
The comparison includes an explicitly labeled destination-relocation model; it
is not rebuilt artifacts or actual base kernel installation.
SHA256 f67c39cf195efc1635e62194f5adfd0be11f102d39a4620334c03cad5a53995c

The current world profile disables TESTS. A fresh original module selection using
its recorded options plus explicit world overrides selects 722 modules, all with
source native declarations. Seven test-related leaves from the old cohort are
excluded. All 722 are represented in the earlier captured producer set, yielding
1,447 component records with kernel, mac-abac and oes owners. This is selection/
source coverage, not a fresh build. The declared GENERIC option headers govern
kernel-specific feature options: userland FDT=yes does not enable kernel FDT.
Effective Make query values, including undefined userland-only options, are retained.

Evidence: bazel-modules-world-profile-selection-r2-20261106/amd64.json and
bazel-modules-world-profile-review-r1-20261106/review.json.
Review SHA256 8a335ddb8baaf45c4ffa2cfe2adbea2e993a14913a7fcd37e744ba8c86582b0f
The failed r1 selection put environment-only options in src.conf; original Make
rejected it. The retry uses its supported SRC_ENV_CONF interface. The first overly
broad probe expected userland-only options in kernel scope; corrected review keeps
all observed values and checks the actual applicable source/kernel option authority.

## Implementation order

1. Add source-owned module traversal/selection providers for the actual kernel and
   source-option profile. Do not import one frozen 729/722 list into production or
   query Make in native actions. Keep independent original selection reconciliation.
2. Compose kernel/GDB files, selected modules, aliases, declared directory policy
   and source-built linker.hints under a coherent configured kernel installation
   context. Preserve standalone module installation inputs as their separate use case.
3. Follow original Make ownership policy: create-world-packages uses
   world-kmod-metadata.awk to merge explicit non-kernel/non-dtb module payloads with
   their world package. Kernel and debug flavors use the selected KERNCONF identity;
   DTB ownership remains separate. Reject every unexplained/unowned payload.
4. Construct actual native combined world/kernel package sets using existing typed
   archive/family/index rules. Retain package-local actions and declared inspection
   referents; do not copy the complete world into each package action or hardcode
   shlib requirements. Reconcile complete installation and all package partitions
   against original Make before calling the aggregate complete.
5. Boot the actual native kernel/world with normal startup and service/authentication
   tests. Qualify real version upgrades and site/database state separately, then
   hardware/combined publication, other architectures and remaining bootstrap,
   cache/sandbox/reproducibility/debug/performance gates.

Frontend review: existing source-settings/target APIs can carry the qualification;
maintained native backend, staging/package helpers, tests and manual must change
with composition semantics. Do not make Bazel production/default before the full
acceptance gates. BIP stays excluded. No host installation, upgrade or reboot.

Implementation checkpoint: typed layout-independent module products now support
base/standalone composition with one configured runtime/debug File pair and shared
source attribute policy. The original six-member FireWire parent is source-owned;
NewReno and FireWire real ELF/debug checks pass. Conditional all-module traversal,
full kernel/pkgbase aggregation and linker.hints remain open. See
KERNEL-MODULE-PRODUCTS-QUALIFICATION.md. The temporary transition implementation
was replaced before committing because it created an extra configured product.
