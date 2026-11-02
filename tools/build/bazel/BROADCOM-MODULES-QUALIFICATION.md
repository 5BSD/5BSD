# Broadcom loadable module qualification

## Scope (2026-11-02)

Twelve amd64 GENERIC module leaves now use native declared producers and
compile/CTF/link/export/debug/install actions: bhnd, bcma, bcma_bhndb, bhndb,
bhndb_pci, bhnd_pci, bhnd_pci_hostb, bhnd_pcib, siba, siba_bhndb, if_bwi and
if_bwn. Their complete default inventory contains 75 objects: 66 physical C sources
and 9 generated interface sources. Fourteen existing interface schemas/producers
supply the required C/header outputs. The two NVRAM producers were qualified
separately in [BHND-NVRAM-GENERATOR-QUALIFICATION.md](BHND-NVRAM-GENERATOR-QUALIFICATION.md).
Make references are migration oracles, never production graph discovery or a
fallback build backend.

Ninety exact physical header contexts reuse 14 existing providers and add 76 contexts in their source packages; consumer visibility is extended only where required. Generated
KOBJ sources/headers come from their owning versioned .m schemas; option headers
come from the actual selected config(8) output. No empty stand-ins, imported Make
outputs, copied installed headers, new generator implementation or shell build
wrapper is used. Generated source filename policy matches Make's module-local
source basenames, as in the existing native interface rules. Original warning
vectors, defines and code-generation policies are preserved. All 75 objects retain
original Make link order across their 70 native compiler contexts/groups.

## Real source policy defects and regression tests

The initial native files matched original Make, but static import/provider
inspection found 28 distinct shared symbols hidden by four original empty export
policies. Five consumers had 37 required references to these local definitions.
The source Makefiles and native wrappers now explicitly export the shared bcma,
bhnd_pci, siba and bhndb_pci implementations, consistent with bhnd/bhndb. See
[BROADCOM-EXPORT-POLICY-QUALIFICATION.md](BROADCOM-EXPORT-POLICY-QUALIFICATION.md)
for the separately committed source fixes and old rejected artifacts.

The registered broadcom_known_providers_test reads real module ELF bindings and
rejects imports with only a localized supplied provider. Its negative companion
localizes the actual BCMA artifact with the maintained export transform and proves
the failure remains detectable using the actual bridge consumer. These are host
artifact inspections, not module execution. Unknown external imports are reported,
not described as complete closure. The selected kernel plus this batch still need
GPIO interface/gpiobus providers. The final observer reads actual ELF binding bits,
so GNU IFUNC exports are counted correctly; an nm-case-only observer's false memory
primitive gaps are retained but not accepted as final evidence.

## Evidence

Paths below are under /usr/obj/usr/src.

- bazel-broadcom-module-source-facts-r1-20261102 captures original selected sources,
  original OBJS order, nested parent Make export contexts, configuration inputs,
  owning schemas and generator inventory.
- bazel-broadcom-module-make-references-r1-20261102 records 24 passing original Make
  build/install controls in independent object/stage trees. The four export
  provider corrections have 8 fresh replacement controls in
  bazel-broadcom-provider-make-references-r2-20261102; the other 16 controls are
  unchanged. No host files were installed.
- bazel-broadcom-modules-ctf-debug-native-r6-20261102 and
  bazel-broadcom-modules-plain-native-r3-20261102 are the final accepted normal
  frontend profiles. Both pass the two registered host artifact tests. All twelve
  plain module files equal Make byte for byte. All twelve CTF/debug runtime section
  inventories/metadata/payloads agree except GNU build-ID/debug-link values; CTF
  bytes agree exactly. All native/Make debug-link CRC checks and 36 file-install
  records (paths, owners/groups, modes, package/debug tags) pass.
- bazel-broadcom-modules-review-r1-20261102 retains 75 actual compiler actions, source/
  compiler digests, exact warnings/defines/code-generation policies and 8,961 Make
  dependency-occurrence checks. Both generated .c and .h inputs differ only by the
  exact checked single KOBJ/NVRAM provenance-comment path. The same capture binds
  twelve actual ordered initial-link inventories and object hashes. The later
  repairs only change four export flags after link/CTF; all compiler declarations,
  source files and original dependency hashes were rechecked unchanged. These
  are retained actual-action checks, not invented executions for cache hits or
  complete dynamic input discovery.
- bazel-broadcom-modules-review-r2-20261102 contains final corrected artifact/
  debug/install comparisons, direct-ELF symbol review, source-policy bindings,
  retained migration/control/observer scripts and profiles, raw source scans and
  final source-commit manifest. Whole debug-file byte equality is not claimed.

Earlier successful-build artifacts with bad export policies, the initial test
harness/toolchain failures, and the rejected frontend local-variable collision
remain recorded separately. Passing Make comparisons alone were insufficient to
accept those provider policies. The final profiles above use the qualified
[host artifact frontend contract](HOST-ARTIFACT-TEST-QUALIFICATION.md), including
pre-execution rejection of ordinary and unlisted target tests.

## Maintained frontend, observability and remaining gates

The normal build-bsd format-5 frontend supplies the selected SDK/kernel platform,
CTF/debug settings, native test inventory and all 16 workers. The generic backend,
Python test rule, frontend unit tests and maintained manual were updated together
for the host artifact contract; no new C CLI/config option, signing/stage or
publication policy is needed for these module source declarations.

A bounded call-shaped scan of66 physical C sources and 9 interface schemas found no
local SDT/DTRACE_PROBE/AUDIT_ARG/audit/CTR-family calls. This does not establish
missing generic FBT/bus/WLAN/framework coverage. Review privileged GPIO/NVRAM/SPROM
access, bus resource/power/clock transitions, bridge attach/detach, device failures
and wireless authentication/data-path tracing and audit delivery at runtime.

GPIO aggregation and full dependency loading, hardware/wireless operation,
optional BWN_GPL_PHY source selection, other KERNCONF/architectures, complete
module/world/pkgbase/hardware publication, bootstrap, VM and controlled CPU,
memory, disk I/O, disk-use, cache and sandbox performance gates remain open.
Make stays production/default and BIP stays excluded. No host module loading,
installation, upgrade or reboot occurred.
