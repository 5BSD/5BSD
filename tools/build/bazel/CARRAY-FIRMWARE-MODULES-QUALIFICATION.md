# ISP and Myricom module qualification

## Implemented scope

Eleven selected amd64 GENERIC module leaves use native C compilation and the
existing module link/CTF/debug/install helpers: six ISP firmware selections,
four Myricom firmware modules and the Myricom network driver. Eleven actual
compiler contexts cover six physical C files. Nine firmware array headers are
explicit consumed inputs: five ISP and four Myricom images. No firmware format,
registration code, driver code, original Makefile or runtime policy is changed.

The all-images ISP variant and five individual variants retain their original
preprocessor selections and quoted MODULE_NAME values. All original export
policies remain EXPORT_SYMS=NO. Header contexts and generated option/interface
providers are reused where exact (seven of nineteen physical header contexts).
The complete original object order is explicit. No Make discovery runs inside
Bazel actions. These declarations describe the current source-owned inputs;
new firmware selections/headers require matching source metadata updates.

## Evidence

All paths below are under /usr/obj/usr/src:

- bazel-remaining-module-source-facts-r2-20261102/facts.json records original
  Make metadata for all 261 then-missing selected leaves; none declares FIRMWS.
- bazel-carray-firmware-module-make-references-r1-20261102 retains all 22 original
  build/install controls, one Make workload at a time, each with all 16 CPUs.
- bazel-carray-firmware-modules-{plain,ctf-debug}-native-r1-20261102 are normal
  build-bsd format-5 qualifications of 39 targets, including six existing provider
  tests per profile. Those tests are regressions, not firmware/hardware tests.
- bazel-carray-firmware-modules-review-r1-20261102 retains actual compiler and link
  actions, exact parameter bytes, dependency digests, artifact/debug/install proofs,
  source hashes, profiles and review drivers.

All eleven plain modules are byte-identical to untouched original Make outputs.
All CTF/debug section inventories, metadata and payloads agree except GNU build-ID
and debug-link values; CTF bytes agree exactly and both debug CRC sets validate.
All 33 file installation records match. Whole DWARF byte identity is not claimed.
Eleven actual compiler actions agree in SDK compiler, defines, warning order,
code-generation flags and 1,008 original consumed prerequisite occurrences.
Eleven actual initial links preserve original object order and input digests.
Parameter bytes were copied and verified before the later profile changed the
execroot; no parameter reconstruction or finished-artifact normalization is used.
This observer ordering is not automatic maintained frontend parameter capture.

The bounded scan of six C files finds no explicit DTrace/SDT/CTR/audit markers.
That does not establish absence of shared header/subsystem instrumentation.
Compiled section comparisons preserve any existing probe payloads. Shared firmware
lifecycle and driver attach/reset/interrupt/rx/tx observability need runtime review;
avoid repeated per-image probes and logging firmware contents.

## Workflow and open gates

The existing build-bsd C interface, format-5 backend and SDK/kernel inputs already
express this composition. Source declarations and qualification docs change;
no CLI, security/signing/stage/publication policy or helper extension is required.

Firmware loading/unloading, real hardware, alternate KERNCONF/options and
ARM64/RISC-V selection remain unqualified. Default loader local-symbol fallback
and strict export checks remain distinct (MODULE-LOADER-EXPORT-CONTRACT.md).
Complete world/rescue/module/pkgbase/hardware/bootstrap/publication, VM/runtime,
cache/sandbox and CPU/memory/disk I/O/disk-use performance gates remain open.
Resource records are bounded build observations, not system performance proof.
Make remains production/default. BIP is excluded. No host module loading,
installation, upgrade or reboot was performed.
