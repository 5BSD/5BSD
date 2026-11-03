# World audit architecture and metadata refresh (2026-11-03)

## Maintained audit corrections

`world-inventory.py` now accepts an explicit `--target-arch` of amd64, aarch64
or riscv64. The default remains amd64. The selected architecture is checked
against the actual recorded world profile and staged compiler through the
existing BuildEnvironment checks. The buildenv prefix is checked against that
profile, rather than an amd64 literal. Each inventory records its architecture.

`world-components.py` derives its architecture from that bound profile, checks
any inventory architecture declaration agrees, and verifies each component's
MACHINE/MACHINE_ARCH metadata against the selected context. It no longer assumes
all queried directories belong to amd64.

The metadata survey now retains GoogleTest, pytest, TAP and porch test selectors
alongside existing ATF/plain selectors. It captures actual selected include-group
contents, rather than treating empty INCS as proof that a component has no
headers. Group values are queried from Make and checked again with the other
metadata. Groups already present in the standard metadata fields are reused.

`world-native-survey.py` classifies these test forms and nonempty header groups,
retains grouped-header declarations in its review records, binds its own source
hash, and rejects failed metadata rows even if a summary claims success.
Package-file presence remains a review queue, never a build/completion gate.

## Evidence and current execution state

`/usr/obj/usr/src/bazel-world-audit-matrix-r1-20261103` records the exact commands,
logs and phase statuses for the sequential three-profile audit. Each phase uses
all 16 logical CPUs/workers where supported. The pipeline uses the maintained
source tools, standard object roots, recorded .src_opts files and an explicit
public trust-anchor input. It does not generate a replacement certificate.

At this checkpoint:

| Target ABI | Recorded machine | SDK/profile preflight | Full world audit |
| --- | --- | --- | --- |
| amd64 | amd64 | passed | complete metadata and package-presence survey: 2,128 directories, no query failures |
| aarch64 | arm64 | passed | complete metadata and package-presence survey: 2,087 directories, no query failures |
| riscv64 | riscv | passed | complete metadata and package-presence survey: 2,050 directories, no query failures |

`sdk-preflight.json` records actual BuildEnvironment construction, compiler and
profile checks, and Make MACHINE/MACHINE_ARCH queries for all three contexts.
These checks do not establish complete foreign inventories or compiled ABI
correctness. No foreign program was executed.

`context-rejections/review.json` records two real CLI checks: incompatible
explicit architecture/profile selection and incompatible inventory/profile
selection both fail before an output directory is created.

The completed amd64 metadata survey captures all 23 selected private gtest
headers, all 15 gmock headers, and the eight gtest self-test selectors. This
checks the newly added metadata fields against real maintained Makefiles.
Partial streams are not complete inventories. Final component summaries and
native surveys must pass before publishing refreshed directory/package counts.

The refreshed amd64 survey is complete. Its 2,128 directories divide into
1,479 with local BUILD files and 649 with only ancestor packages. Among those
ancestor-only directories, 125 have program metadata and 55 have library
metadata. These are review leads, not unconverted binary/library counts:
parents can own implementations, while a local BUILD file can contain only
source/header bindings. The ARM64 metadata/package-presence survey is also complete. The RISC-V
metadata/package-presence survey is complete with 2,050 directories and no query
failures. These audits do not compile the surveyed products.

`bazel-world-components-amd64-r1-20261103/review.json` records the complete
amd64 metadata checks and a concrete next dependency review. The generic
standalone and EFI standalone libraries select different source/verification
contexts. Existing `stand/libsa/BUILD.bazel` covers boot2 header/textual inputs;
`stand/efi/libefi/BUILD.bazel` exports efichar.c for userland. Neither defines
its corresponding complete freestanding archive. The selected EFI loader
directories lack native program declarations. Their archive/source-generator
contexts and final EFI links are a required next implementation tranche.
Do not omit these boot products to construct a passing partial world.

The 2026-10-27/30 survey predates many native conversions. Its numbers remain
historical and must not be presented as current coverage. The old root-package
"source file only" description was also inaccurate: the current root has
source/header bindings, while a complete native world aggregate remains absent.

## Integration and remaining work

This change corrects maintained migration audits. It does not replace native
Bazel declarations with Make interpretation at build time, add a world aggregate,
or change program/library/module implementations. The normal build-bsd frontend
already accepts the three supported architectures for its existing actions;
there is no new C frontend, staging/signing/publication or manual interface.
The audit CLI's architecture selector and evidence scope are documented here.
No host installation, upgrade or reboot is authorized or performed.

Every matrix phase completed successfully. Reconcile selected Make outputs with
native actions/installations, including ownership by parent packages. A local
BUILD file can contain only exports; absence of a local file can still mean a
parent owns the implementation. Neither observation is a completion percentage.
The component survey still does not expand every multi-program compiler context
or resolve all generated-source/install payloads.

Complete native world/kernel/modules, pkgbase/hardware publication, cross-platform
runtime, bootstrap/sandbox/cache and CPU/memory/disk performance qualification
remain required. Make remains production/default; BIP remains out of scope.
