# Peripheral-device kernel qualification

## Scope (2026-11-02)

90 additional amd64 GENERIC objects have native built-in declarations across
39 device families: CPU controls/sensors, firmware, framebuffers, I2C/SMBus,
IOMMU, wireless, keyboard, memory devices, Mellanox firmware, MMC/SDHCI,
PCI, serial ports, TPM, veriexec, VMware, watchdog and supporting devices.
This is object qualification, not proof that these devices work at runtime.

126 physical prerequisite contexts reuse identical source/header sets. Native
cc_library compilation and the maintained CTF pipeline preserve common flags,
per-source defines, forced headers and ordered warnings. The three MLX firmware
objects retain their extra warning suppressions before Werror, LinuxKPI root
before generic kernel roots, CONFIG_INFINIBAND_USER_MEM and kconfig.h forced
include. Unused Make search paths do not acquire fabricated header dependencies.
Original KOBJ schema producers and native GENERIC options supply generated
headers; no generated Make reference file is an input to the native graph.

New source package boundaries preserve the existing root bhyve header provider
through its canonical sys/dev/io owner label. Production C sources are unchanged.
Existing build-bsd format-5 inputs/backend targets, CTF, staging and verification
APIs cover this batch; no frontend C, security, publication or manual option
change is required. Make remains production/default; BIP remains excluded.

## Evidence

Paths below are under /usr/obj/usr/src.

- bazel-kernel-peripheral-devices-make-metadata-r1-20261102 retains supported
  Make recipes, filemon disabled, with all 90 reference object hashes unchanged.
  This does not establish complete dynamic input discovery.
- bazel-kernel-peripheral-devices-amd64-ctf-r1-20261102 passes through the
  maintained frontend with 16 jobs and disk-reserve monitoring. All 90 compiler
  executions are bound through CTF input/output hashes to immutable captures.
- bazel-kernel-peripheral-devices-review-r1-20261102 retains declaration copies,
  source identities, compiler/input reports and artifact comparisons. Actual
  executed argv agrees with final configured actions. Ordered warnings, defines,
  undefines, code-generation options, debug/stack policies and forced headers
  agree with Make. The audit verifies 10,834 physical and
  503 generated prerequisite occurrences and all three MLX include precedence cases.
- All 90 .text and CTF payloads are byte-identical; CTF graphs agree. Complete
  allocated payloads and 27,432 non-debug relocations agree after
  independently bound source-filename comparison (46 string spelling changes).
  Byte-identical string pools use strict raw symbol values/addends. Artifacts
  are never rewritten; full DWARF/string/symbol table byte parity is not claimed.
  Generated KOBJ comparison adjusts only exact schema provenance comments;
  original and comparison hashes remain recorded.
- A bounded source-bound scan finds call-shaped tracing/CTR/audit markers in
  9 of 90 files. This is neither live probe coverage nor proof that other
  files lack shared instrumentation. Existing probes and hooks remain.

Closure query r36 passes for 2,107 known groups and
2,282 compilation actions. Reconciliation r29 finds
2,273 source-identity matches, two object-name-only and four generated-name-only
matches among 2,466 Make final-link products, leaving 187 missing. These are
configured graph counts, not a complete compiled or linked kernel.

## Remaining gates

Device behavior, TPM/veriexec operations, error paths and live tracing require
runtime qualification. This profile has tests=[]; it performs no device-policy
or host-authentication changes. Full kernel link/order/version/post-processing,
modules, alternate KERNCONF, ARM64/RISC-V64, world, pkgbase/hardware publication
and bootstrap remain open. Disk reserves pass; controlled CPU, memory and disk
I/O/use comparisons remain open. No managed disk cache was enabled. No host
installation, upgrade or reboot occurred.
