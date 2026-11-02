# I2C and SMBus module qualification

## Scope (2026-11-02)

All 39 I2C subtree leaves selected by the reviewed amd64 GENERIC Make traversal
now have native Bazel module declarations. This covers bus/controller drivers,
I2C HID and Cyapa input, EEPROM/RTC/sensor/GPIO devices, DIMM monitoring, and muxes.
The 51-object inventory contains 47 physical C sources and four KOBJ-generated
sources (iicbb_if, iicbus_if, iicmux_if and smbus_if), compiled in 48 native groups.
Thirty-eight exact header contexts reuse 25 existing providers. Existing native
KOBJ, config-option, offset and vnode producers supply generated dependencies.
The original export policies are preserved, including the four public bus/mux
providers. No runtime C code, Makefile or common compilation helper is changed.

## Evidence

All paths below are under /usr/obj/usr/src.

- bazel-i2c-module-source-facts-r1-20261102 preserves selected parent context,
  original source/option inventories and Makefile hashes.
- bazel-i2c-module-make-references-r1-20261102 contains all 78 passing untouched
  original Make build/install controls (plain and CTF/debug). Controls run one at
  a time; each uses all sixteen logical CPUs. No host installation occurs.
- bazel-i2c-modules-{plain,ctf-debug}-native-r1-20261102 are passing normal
  build-bsd profiles, each selecting 117 module artifact/debug/install targets
  and six existing family provider regressions. Those six tests do not execute
  I2C hardware or establish its runtime behavior.
- bazel-i2c-modules-review-r1-20261102 binds all 51 actual compiler actions,
  compiler/source hashes, warning/define/code-generation flags and all 5,089
  original Make consumed prerequisite occurrences to native action input hashes.
  Generated KOBJ bytes differ only by the exact checked provenance comment path.
  All 39 actual initial module links preserve ordered object inventories/hashes.
- Thirty-seven plain modules match untouched Make byte for byte. The remaining
  two match the independently audited filename-policy Make controls described
  below, also byte for byte. CTF/debug runtime section inventories, metadata and
  payloads match their respective references except GNU build-ID/debug-link values;
  CTF payloads agree exactly. Both sets of debug CRCs pass. All 117 file-install
  records across the two configurations match Make. Whole DWARF equality is not
  claimed.
- compiled-probe-preservation.json binds original/native iicbus SDT provider,
  probe/argument/tracepoint sections and relocations, all exact. Runtime probe
  registration and event delivery remain open.

## Explicit filename-policy controls

The original jedec_dimm recipe passes a source path with ../../../ components;
original pcf8574 passes a doubled slash below dev/iicbus/gpio. Those spellings
change embedded assertion filenames and resulting string/symbol/relocation layouts.
Native compilation uses the canonical source-owned path. Original artifacts and
all ordinary comparison differences are retained in ordinary-ctf-debug-diagnosis.json.

bazel-i2c-module-filename-controls-r1-20261102 contains four additional Make
controls. Each includes its original Makefile unchanged and appends one explicit
-fmacro-prefix-map from that original source directory spelling to its canonical
spelling. The actual four compiler recipes differ only by that mapping; all 382
consumed prerequisite occurrences and bytes agree with untouched Make. Target
MD/MF/MT dependency flags remain intact. The resulting plain modules are identical
to native. No artifact normalization or production path-spelling workaround is
introduced. These two comparisons establish parity under the stated filename
policy, not byte identity to the untouched original recipes.

## Workflow and remaining qualification

The existing build-bsd frontend and maintained format-5 backend already carry
selected kernel/SDK settings, targets, typed CTF/debug policy and job count. This
batch needs source declarations, their qualification evidence and docs; no new C
CLI field, signing/stage/publication policy or replacement frontend is required.
Native actions use normal compiler/header/generator providers with declared inputs;
Make metadata is used only for migration review, never to discover runtime graphs.

These results cover selected optimized amd64 GENERIC, not FDT, alternate KERNCONF,
ARM64/RISC-V or unselected drivers. Actual controller discovery, bus lock/contention,
retry/error paths, RTC/sensor reads and writes, input reports, mux behavior and
hotplug require suitable runtime/hardware tests. A generic VM cannot prove physical
I2C controller behavior. Provider export checks have the documented
[loader compatibility limits](MODULE-LOADER-EXPORT-CONTRACT.md); default loading,
strict lookup and kernels without built-in providers are separate open checks.

The bounded source scan found existing IIC bus acquire/transfer probes. Missing
per-controller/device observability and audit review remain work items; static
marker preservation does not prove comprehensive instrumentation. Complete world,
cross-architecture kernels/modules, pkgbase/hardware publication, bootstrap, VM
runtime and CPU/memory/disk I/O/disk-use/cache/sandbox performance gates remain open.
Make remains production/default; BIP is excluded. No host module loading, upgrade
or reboot occurred.
