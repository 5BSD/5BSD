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

Hierarchy checkpoint: 24 unconditional source parents now use typed module sets,
covering 134 unique modules. Thirteen native test targets and independent original
Make membership/leaf-install-policy plus all ELF/debug CRC checks pass. Nested
GEOM selection shares the same actual products. Conditional/source-option parents,
root selection and full installed kernel/pkgbase remain the next work. See
STATIC-MODULE-PARENTS-QUALIFICATION.md for exact scope and retained migration inputs.

Architecture/source-option checkpoint: 19 additional parents handle parent-owned
KMOD plus children and AMD64 branches, with existing DTrace/OFED selectors. The
combined hierarchy now covers 43 parents / 258 unique modules. Default and disabled
selector profiles match original Make, all 127 new cohort ELF/debug pairs pass,
and all 33 common selector products remain identical. Kernel-option-controlled
parents still need shared source authority; legacy AIC7xxx producers are missing
and remain explicit optional coverage gaps. See CONDITIONAL-MODULE-PARENTS-QUALIFICATION.md.

## Shared kernel-option and TCP module checkpoint (2026-11-06)

TCP_HHOOK now has one typed setting shared by the actual GENERIC parser overrides
and source-owned cc/khelp membership. Enabled, disabled and no-debug native profiles
each pass 14 Bazel tests; independent Make tied/standalone/ALL_MODULES checks and
all 13 selected debug pairs pass. A reproduced original Make OPT_GLOBAL defect is
fixed using resolved KERN_OPTS while preserving standalone behavior. Fifteen native
parser inventory cases pass across AMD64/ARM64/RISC-V; these are not cross kernel
builds. See TCP-HHOOK-MODULES-QUALIFICATION.md.

NEXT: remaining kernel-option/root traversal and optional producers; coherent kernel/
module/pkgbase composition and a fresh full current-profile kernel build, then normal
startup/services and genuine upgrades. All cross/bootstrap/cache/sandbox/reproducibility/
debug/resource/hardware/publication gates remain open. Make stays production/default;
BIP is excluded. Earlier full-kernel evidence retains its original input scope.

## USB and test-framework parent selection passes (2026-11-06)

New source-owned AMD64 USB and test-framework parents compose 83 actual module/debug
pairs. Default, firmware/gadgets-disabled (71), and USB-disabled (79) profiles each
pass 14 existing tests; independent original Make membership/leaf attributes and
all actual ELF/debug CRC checks pass. Common configured products stay byte-identical.
The gadget selector preserves kern.opts.mk's USB dependency. See
USB-MODULE-PARENT-QUALIFICATION.md for exact scope, including unqualified USB debug
macro variants. No new runtime/module source or signing/publication policy changed.

NEXT: remaining kernel-option/root selection and optional producers; coherent
kernel/GDB/modules/directories/aliases/linker.hints/pkgbase, then normal startup,
authentication/services and genuine upgrades. All cross/bootstrap/cache/sandbox/
reproducibility/debug/resource/hardware/publication gates remain open. Make stays
production/default; BIP excluded.

## FDT option authority and I2C/GPIO parents pass (2026-11-06)

Three new AMD64 parents compose 45 unique module/debug products under auto/no and
55 under FDT=yes, including ten added AMD64 producers and three corrected source
alternatives. Sixteen test targets pass in each final profile. Independent original
Make parent-export propagation, complete membership/installation attributes and
ordered object lists plus all 145 selected ELF/debug pairs pass. Final captures
preserve every reviewed artifact byte for byte. See FDT-MODULE-PARENTS-QUALIFICATION.md.

Auto defaults live in one source-owned declaration shared by selectors/configuration;
normal parser actions validate the complete actual option-header set before publishing
identity/inventory. A real wrapper negative check rejects a stale expectation even
without running a Bazel test. Eighteen parser inventory cases pass across the three
architectures; they are not full cross builds. Retained failed producers and observers
are documented; no source C, installation payload or signing/publication policy changed.

NEXT: remaining root/kernel-option selection and optional producers; coherent full
kernel/GDB/modules/directories/aliases/linker.hints/pkgbase, then normal startup/
authentication/services and genuine upgrades. FDT-enabled whole-kernel/custom-config
and all cross/bootstrap/cache/sandbox/reproducibility/debug/resource/hardware/publication
gates remain open. Make stays production/default; BIP excluded.

## Netgraph/TCP module parent selection passes (2026-11-06)

Four AMD64 profiles compose 47/38/46/43 unique products and each pass 19 test targets.
Independent original Make export-aware membership, leaf/install policy and exact
ordered link inputs match; all 174 selected ELF/debug pairs pass. IPsec/signature
selectors share checked native GENERIC option authority. Optional MPPC follows
source crypt and precise RC4 source availability, with present/absent/generated
predicate analysis tests. See NETWORK-MODULE-PARENTS-QUALIFICATION.md for evidence
and limits; this is not normal boot or fresh Make machine-code parity.

NEXT: source-owned root selection and coherent kernel/GDB/modules/directories/
aliases/linker.hints/pkgbase, then normal startup/services and genuine upgrades.
Custom/ALL_MODULES/cross, bootstrap/cache/sandbox/reproducibility/debug/resources/
hardware/publication gates remain open. Make stays production/default; BIP excluded.

## Normal AMD64 root module graph passes (2026-11-06)

Source-owned root selection now builds the complete current 722-module profile.
Default, nineteen-features-disabled (468) and ACPI-off/Veriexec-on (726) profiles each
pass 20 test targets. Complete original source Make traversal, leaf/base-install
policy and exact ordered OBJS+BLOB_OBJS match; all 1,916 selected ELF/debug pairs
pass. Actual VMM and amdsmu header dependencies are fixed. Shared checked kernel
options and native device directives preserve tied source selection. A focused
Bazel follow-up passes the final 13-case Make-audit regression and option tests.
Iwlwifi ACPI objects, CTF paths and flags now follow the actual device option;
configured compile-action checks cover every linked object.
See ROOT-MODULE-GRAPH-QUALIFICATION.md for hash-bound evidence and retained failures.

NEXT: coherent current-profile kernel/GDB/modules/directories/aliases/linker.hints/
pkgbase. FDT/MMCCAM/TESTS root branches still require missing parent/producers;
MODULES_OVERRIDE/EXTRA/WITHOUT_MODULES/ALL_MODULES are not implemented. These and
custom/cross, normal boot/services/upgrades, bootstrap/cache/sandbox/reproducibility/
debug/resources/hardware/publication remain open. Make stays default; BIP excluded.

Next composition should reuse the existing native kldxref -o explicit-input mode.
Its implementation requires regular files together in the output directory and
rejects symlink inputs. The original default FTS_PHYSICAL traversal likewise skips
installation aliases; compare identical real kernel/module payloads in basename
order (the original compare() uses strcmp), then separately preserve aliases in
the installation manifest. Declare the native execution tool and runtime libraries;
materialize only those selected ELF files, not the complete installed world. Prove
explicit and ordinary directory-mode hints agree before merging that generated
record with the existing kernel/GDB directory policy and typed module manifest.
This is the next design step, not a completed hints/composition result.

## Complete installation implementation qualified (2026-11-06)

The new native hints rule consumes typed installation records, selects the regular
ELF names ordinary kldxref would scan, and streams only those payloads into an
action-private directory for the existing -o API. It declares the native execution
tool and DSOs, and publishes a normal installation entry for linker.hints. A native
Bazel test compares directory/explicit/build outputs, alias and ignored-file
behavior, undeclared-file exclusion, corrupt-input atomicity and input preservation.
The AMD64 complete installation joins the existing kernel/GDB/directory manifest
and source-owned module root, then adds generated hints and an installation archive.

The default, no-separate-debug and relocated profiles pass all 21 selected tests
and independent complete archive/ELF/debug/CTF review. Across all profiles, the
723 runtime ELFs preserve identical allocated sections and CTF; relocation leaves
all regular payloads unchanged. Explicit supplemental directory policy supplies
custom ancestors; absent policy is rejected. See
KERNEL-INSTALLATION-COMPOSITION-QUALIFICATION.md. The initial request lacked the mandatory
explicit kernel source revision and was rejected during analysis. The next request
identifies the dirty source revision and explicitly enables kernel/module CTF, as
GENERIC requests WITH_CTF for DTrace. Existing format-5 target/settings/test APIs
carry these changes; frontend C and signing/publication interfaces need no update.
No normal boot, final pkgbase archives or publication is established by this work.

Final package composition must preserve world-kmod-metadata.awk's non-kernel module
merge into the oes/mac-abac families and project kernel ownership into the declared
KERNCONF/flavor package. The original mtree-to-plist.awk still identifies kernel
debug payloads through a /usr/lib/debug/boot prefix; relocated/debug-prefix tests
must address that source policy before claiming general package-layout support.

NEXT: final flavored kernel pkgbase families, non-kernel module/world package merge
and complete package inventory before normal startup/services/upgrades.
