# ARM64 and RISC-V bhyve snapshot support (5BSD)

Status: experimental implementation, offline evidence only. Runtime behavior on
ARM64 or RISC-V hardware or emulation has NOT been exercised and is
unqualified. The maintained build keeps `BHYVE_SNAPSHOT` in `BROKEN_OPTIONS`
for both targets and their GENERIC kernels do not enable `options
BHYVE_SNAPSHOT`; the code below is built only by an explicit opt-in.

The product contract is unchanged: tracing is not continued across restore or
migration. A restored or migrated guest starts a fresh HyperTrace session after
old guest probes are quiesced, the old host session is retired, transport work
is discarded, restored tracing state is reset, and new programs are authorized
before execution. Nothing in this file adds tracing continuity.

## 1. What the AMD64 path covers

User space (`usr.sbin/bhyve/snapshot.c`, `checkpoint_*`, `migration_*`):

* Session/transaction: `VM_SNAPSHOT_SESSION` BEGIN/COMMIT/ABORT/ABORT_CURRENT
  wraps every record; vCPUs are parked behind the userspace startup fence and
  devices are paused before records are taken.
* Kernel records, in order, through `VM_SNAPSHOT_REQ`: `vhpet`, `vioapic`,
  `vlapic`, `vm` (VMS2 envelope: VM common, vCPU common, x86 vCPU, guest
  FPU/XSAVE), `vmcx` (VMCS/VMCB register state), `vatpit`, `vatpic`, `vpmtmr`,
  `vrtc`.
* Device records: every PCI device (generic compat envelope), `atkbdc`
  (non-PCI platform device), `qemu_fwcfg`, TPM refused.
* Contracts: checkpoint manifest (architecture string), CPU contract (x86
  CPUID records), topology, NUMA, memory geometry, machine-topology digest.
* `VM_RESTORE_TIME` rebases guest time once per committed restore, consuming
  the kernel's one-shot restore-time credential.
* Migration: HELLO carries `arch_id`/`intr_controller` (x86 values), then the
  same snapshot records travel inside the authenticated FSS1 stream.
* HyperTrace fresh-session restore/migration coordination lives in
  arch-neutral code (`snapshot.c`, `hypertrace.c`, `pci_virtio_dtrace.c`).

Kernel (`sys/amd64/vmm`, `sys/dev/vmm`): `vm_snapshot_req()` selector
dispatch, VMS2 envelope/common-state codecs, x86 transaction capture/plan/
commit, per-device snapshot functions, `vm_restore_time()`, session ABI and
restore-time credential in `sys/dev/vmm/vmm_dev.c` (already MI).

## 2. Gap list before this work (ARM64 and RISC-V)

| # | Gap | ARM64 | RISC-V |
|---|-----|-------|--------|
| G1 | `machine/vmm_snapshot.h` is a placeholder (`$FreeBSD$` only); no `vm_snapshot_meta`, selectors or session ABI | yes | yes |
| G2 | No `VM_SNAPSHOT_REQ` / `VM_SNAPSHOT_SESSION` / `VM_RESTORE_TIME` ioctl numbers or handlers | yes | yes |
| G3 | No kernel `BHYVE_SNAPSHOT` option (`options.amd64` only); vmm module has no snapshot sources | yes | yes |
| G4 | No kernel vm/vCPU save/restore: GPRs, PC/PSTATE, EL1 system registers, PMU/debug registers, guest FP/SIMD | yes | GPRs, sepc/sstatus/hstatus, VS CSRs, FP |
| G5 | No interrupt-controller save/restore | vGICv3 distributor, SPIs, SGI/PPI, ICH_VMCR/APR, act/pend lists | APLIC domaincfg/sources/targets |
| G6 | No timer save/restore and no time rebase | CNTVOFF, virt/phys timer ctl/cval, CNTKCTL, callout re-arm | SBI timer deadline is not stored at all; no htimedelta virtualization; SSTC vstimecmp not saved by the world switch |
| G7 | libvmmapi snapshot calls compiled only with `WITH_VMMAPI_SNAPSHOT` (amd64 Makefile.inc) | yes | yes |
| G8 | `snapshot.c` kern-struct table hard-codes amd64 selectors; does not compile for other targets | yes | yes |
| G9 | Non-PCI platform devices not checkpointed | PL011 UART, PL031 RTC | NS16550 MMIO UART |
| G10 | vCPU power state (PSCI CPU_ON/OFF, SBI HSM) lives only in userspace masks; checkpoint/migration resume paths call `vm_resume_all_cpus()`, which would start powered-off vCPUs; restore resumes every vCPU | yes | yes |
| G11 | Migration HELLO reports `arch_id=0, intr_controller=0` for both, so an ARM64 and a RISC-V endpoint would not be distinguished by HELLO (the manifest/CPU contract would still refuse later) | yes | yes |
| G12 | Kernel atomicity: interrupt injection ioctls and timer callouts are not fenced by the MI event coordinator on these targets | yes | yes |
| G13 | Pre-existing memory-safety bug found during audit: APLIC source arrays are allocated with `nirqs` entries but indexed 1..`nirqs` (guest MMIO write to SOURCECFG/TARGET 63 writes past the allocation) | n/a | yes |
| G14 | No offline codec round-trip / malformed-image tests for non-x86 state | yes | yes |
| G15 | No cross-build evidence for snapshot-enabled kernel/libvmmapi/bhyve on these targets | yes | yes |

## 3. Design

### Kernel ABI

* `sys/dev/vmm/vmm_snapshot_common.h`: the architecture-independent part of the
  snapshot ABI (buffer, op, meta, session, helpers). ARM64/RISC-V
  `machine/vmm_snapshot.h` define their own `enum snapshot_req` and include it.
  The structure layouts are identical to the AMD64 header (which is left
  untouched in this change).
* Selectors: ARM64 `STRUCT_VM=1` (`"vm"`), `STRUCT_VGIC=2` (`"vgic"`);
  RISC-V `STRUCT_VM=1` (`"vm"`), `STRUCT_APLIC=2` (`"aplic"`).
* Ioctl numbers reuse the AMD64 values 113/114/115 (no collision in the
  ARM64/RISC-V enums). Every snapshot ioctl is `LOCK_ALL_VCPUS`, requires
  `FWRITE`, and `VM_SNAPSHOT_REQ` requires the descriptor's active session.
  A successful `STRUCT_VM` restore stages the one-shot restore-time credential,
  exactly as on AMD64.
* Every record is one canonical VMS2 envelope (`vmm_snapshot_envelope.c`) with
  critical sections, so an unknown section refuses the restore.

### Wire sections

All sections are critical (`VMM_SNAPSHOT_SECTION_F_CRITICAL`); the common
types 0x0001/0x0002 are shared with AMD64, ARM64 uses 0x20xx and RISC-V 0x30xx
(AMD64 uses 0x10xx), so no type number is reused across architectures.

ARM64 `vm`: `VM_COMMON(0x0001)`, `VCPU_COMMON(0x0002)/i`, `ARM64_VM(0x2001)`
(CNTFRQ, guest virtual counter), `ARM64_VCPU(0x2002)/i` (196 64-bit values:
X0-X30, SP_EL0, PC, PSTATE, SP_EL1, 24 EL1 system registers, VMPIDR/VPIDR
identity, 9 PMU control registers, 31+31 PMU event counters/types, 4x16 debug
breakpoint/watchpoint registers; flags: pending injected exception, OS lock),
`ARM64_FP(0x2003)/i` (V0-V31, FPCR, FPSR), `ARM64_TIMER(0x2004)/i` (CNTKCTL,
virtual/physical timer CTL and CVAL).

ARM64 `vgic`: `VM_COMMON`, `ARM64_VGIC_DIST(0x2010)` (distributor and
redistributor geometry, GICD_CTLR, VPMR width, LR/APR counts, 991 SPI entries
of 16 bytes: route MPIDR, target vCPU, active/pending/enabled/level/listed
flags, priority, trigger) and `ARM64_VGIC_CPU(0x2011)/i` (ICH_HCR enable bit,
ICH_VMCR, AP0R/AP1R, 32 SGI/PPI entries, the active/pending list in its exact
order, zero padding to 8 bytes).

RISC-V `vm`: `VM_COMMON`, `VCPU_COMMON/i`, `RISCV_VM(0x3001)` (timebase, capture
time, SSTC flag), `RISCV_VCPU(0x3002)/i` (47 values: 31 GPRs, sepc, HS
sstatus, hstatus, 11 VS CSRs, guest scounteren, SBI timer deadline; flags:
exception, IPI pending, timer interrupt pending, timer armed),
`RISCV_FP(0x3003)/i` (32 x 128-bit slots, fcsr).

RISC-V `aplic`: `VM_COMMON`, `RISCV_APLIC(0x3010)` (geometry, nirqs=63,
domaincfg, 64 source slots: sourcecfg, state, target; slot 0 must be zero).

### Validation (fail closed)

Portable decoders reject: missing, duplicated or reordered sections; wrong
payload lengths/versions; non-critical known sections; unknown critical
sections (unknown non-critical sections are skipped); nonzero reserved fields
and padding; unknown flags; PSTATE outside AArch64 EL0t/EL1t/EL1h; VMPIDR
without RES1; timer CTL bits other than ENABLE/IMASK/ISTATUS; FPSR/FCSR reserved
bits; SGIs not edge, PPIs not level, SPI trigger values other than level/edge;
route bits outside the kernel affinity mask; out-of-range targets; private
interrupts whose target is not their CPU; list entries out of range,
duplicated, on two CPUs, or not flagged as listed, and flagged interrupts
missing from every list; ICH_HCR bits other than En; ICH_VMCR reserved bits;
APRs beyond the implemented count; hstatus bits other than SPV/SPVP/GVA/VTW/
VSXL (SPV and VTW required; HU, VTSR, VTVM, VGEIN, VSBE never restored); HS
sstatus bits outside the S-mode set; hvip bits other than VSSIP/VSTIP/VSEIP;
a timer deadline without the armed flag; reserved APLIC source modes 2/3;
delegated sources with non-child bits; APLIC domaincfg bits other than IE.

Kernel destination checks reject, before any state changes: a vCPU set that
differs from the destination's allocated vCPUs; VMPIDR, VPIDR or PMCR.N
mismatch; CNTFRQ or RISC-V timebase mismatch; vGIC geometry, LR/APR count or
VPMR width mismatch; private interrupt routes that disagree with the
destination VMPIDR; SPI targets naming an absent vCPU; APLIC geometry mismatch.
Capture refuses (EBUSY/EOPNOTSUPP): non-frozen vCPUs, active debug
capabilities (ARM64 debug SPSR/MDSCR shadows), FEAT_ECV physical-timer
passthrough, per-vCPU CNTVOFF that differs from the VM value, list registers
not folded back, an internally inconsistent vGIC capture, SSTC hosts (RISC-V),
and RISC-V restore when host `time` is behind the captured time.

### Time

ARM64: the guest virtual counter at capture is recorded; restore sets
`CNTVOFF = now - guest_count` for the VM and every vCPU, drains the timer
callouts, and `VM_RESTORE_TIME` (one-shot credential, as on AMD64) re-arms the
software timer callouts. The asserted level of timer PPIs travels in the vGIC
record.

RISC-V: the VMM does not virtualize `time` (no htimedelta), so the guest sees
host time. Restore is refused if host time is behind the captured time; when it
is ahead the guest observes a forward jump, as after a long stall. The SBI timer
deadline is now recorded by `vtimer_set_timer()` and re-armed by
`VM_RESTORE_TIME` (a past deadline asserts the timer interrupt immediately).

### Kernel concurrency

All snapshot ioctls freeze every vCPU and require the descriptor's active MI
checkpoint session. ARM64/RISC-V publish no deferred events through the MI
coordinator; their `vm_event_checkpoint_deferred_apply()` panics if one ever
appears. The vGIC capture holds each vCPU's timer callout mutexes while copying
its private interrupts and list (timer callouts are the only asynchronous PPI
source left once vCPUs are frozen). Device interrupt injection
(`VM_ASSERT_IRQ`, `VM_RAISE_MSI`) is not fenced by the kernel on these targets;
consistency relies on bhyve pausing devices first (gap G12, unchanged). A torn
capture is caught by the encoder's validation and refused, not published.

### User space

* `snapshot.c` uses a per-architecture kern-struct table (`vm`,`vgic` /
  `vm`,`aplic`).
* `snapshot_md.h` declares the machine-dependent platform-record table
  (`bhyve_snapshot_md_devices()`), used on non-AMD64 targets in the same places
  as the AMD64 `atkbdc` record: save after PCI, restore presence/topology/
  machine-digest checks, side-effect-free VALIDATE, restore, pause/resume
  (platform devices pause last and resume first; hooks are idempotent).
  ARM64: `cpu_power` (PSCI mask), `pl011` (only when a console is configured),
  `pl031` (guest RTC stored as an offset from host wall-clock time). RISC-V:
  `cpu_power` (HSM mask) and `uart` (existing NS16550 snapshot code).
* Explicit `#ifdef __amd64__` blocks keep `vm_resume_all_cpus()` on AMD64
  (unchanged code, so text-extracting fixtures still see it) and call
  `bhyve_resume_powered_cpus()` elsewhere, replacing resume-all in
  the checkpoint resume, fresh-session restore release, migration destination
  release and migration source rollback paths, and the restore start loop in
  `bhyverun.c` resumes only powered vCPUs.
* Migration HELLO: ARM64 `arch_id=0xaa64, intr_controller=3`; RISC-V
  `arch_id=0x5264, intr_controller=4`. AMD64 unchanged.

## 4. Implemented in this change

ARM64: G1, G2, G3 (option, files, module sources), G4, G5, G6 (with ECV
refused), G7, G8, G9 (PL011, PL031), G10, G11, G14, G15.
RISC-V: G1, G2, G3, G4, G5, G6 (deadline recording and re-arm; no time
virtualization; SSTC refused), G7, G8, G9 (MMIO UART), G10, G11, G13 (APLIC
array now nirqs+1 slots; `aplic_inject_irq()` rejects source 0 and sources
above nirqs), G14, G15.

HyperTrace: no architecture-specific HyperTrace code was needed. The
fresh-session coordinator, guest-probe quiesce, collector retirement, transport
discard and post-restore authorization in `snapshot.c`/`hypertrace.c`/
`pci_virtio_dtrace.c` contain no architecture guards; with the records above
the same path compiles and links for ARM64/RISC-V. The kernel HyperTrace state
of a restored or migrated VM is that of a new VM (new VM identity and epoch);
no tracing state is serialized.

## 5. Still unsupported or unqualified

* Runtime: nothing here has been executed on ARM64 or RISC-V hardware or
  under emulation. No VM was started, no module loaded. Runtime behavior is
  unqualified; the live acceptance matrix entries for these targets remain
  not-run.
* Maintained configuration: `BHYVE_SNAPSHOT` stays in `BROKEN_OPTIONS` for
  non-AMD64 userland and default-off in `kern.opts.mk`; GENERIC kernels do not
  enable it. Enabling requires an explicit opt-in (see section 6 commands).
* RISC-V SSTC hosts (vstimecmp not context-switched by the VMM; also a
  pre-existing multi-vCPU correctness gap in the run loop, not fixed here).
* RISC-V time virtualization (htimedelta) and backward host time.
* ARM64 FEAT_ECV physical-timer passthrough (`hw.vmm.vtimer.allow_ecv_phys`),
  debug-exit capabilities during checkpoint, SVE/SME (not exposed to guests).
* ARM64 GICv3 LPIs/ITS (not implemented by the VMM).
* Kernel fencing of device interrupt injection during capture (G12).
* `gdb.c` still uses `vm_resume_all_cpus()` (another agent owns gdb.c);
  configured GDB already blocks source migration.
* The pre-existing GICD_AFF definition omits AFF2; routing therefore ignores
  Aff2 on both ends and the wire contract matches it.
* Cross builds use the existing `/usr/src` cross-world sysroots for system
  headers/libraries; they are not matched whole-system builds.

## 6. Evidence (offline only; all under /usr/obj/5BSD-hypertrace-validation)

Source hashes of every file in this change: `featB-final2-source-hashes.txt`.

Kernels (`make buildkernel MODULES_OVERRIDE=vmm`, host clang via XCC/XLD,
`-j16`, separate MAKEOBJDIRPREFIX each, configs in `featB-kernconf/`):

| Directory | Config | Result |
| --- | --- | --- |
| `featB-final-kernel-arm64-featb-snapshot` | GENERIC + `options BHYVE_SNAPSHOT` | kernel + vmm.ko built |
| `featB-final-kernel-arm64-featb-base` | GENERIC (maintained) | built |
| `featB-final-kernel-riscv-featb-snapshot` | GENERIC + `options BHYVE_SNAPSHOT` | built |
| `featB-final-kernel-riscv-featb-base` | GENERIC (maintained) | built |
| `featB-amd64-vmm-module` | native standalone vmm.ko, snapshot yes | built |

User space (`tests/arch-snapshot-build.py`: libvmmapi, lib9p, libuvmem, libfdt
and fully linked bhyve; ELF machine checked; binaries never executed):
`featB-final2-{arm64,riscv,amd64}-snapshot-{yes,no}` all PASS (ELF 183/243/62).

Tests (`tests/arch-snapshot-codec.py`, native amd64, ASan+UBSan):
`featB-final-codec-tests/results.json` - ARM64 codec 8/8 cases, RISC-V codec
5/5, platform PL011/PL031 4/4; 8/8 deliberately weakened codec mutants killed.
Mutation sweeps: 40,000 (ARM64 vm), 20,000 (vGIC), 40,000 (RISC-V vm),
30,000 (APLIC) single-record mutations, each either rejected or re-encoded
byte-identically. The two ATF programs also build through the maintained
`tests/sys/vmm/Makefile` (`featB-tests-makefile`).

Shared-file regression: migration/fresh-session fixtures that extract code
from `snapshot.c`/`bhyverun.c` were rerun after the final change:
`featB-fixture-*` (18 scripts, all exit 0).

Not done: no runtime execution on ARM64/RISC-V hardware or emulation, no VM,
no module load, no install; no matched whole-system world build.

## 7. Gate-text proposal for INTEGRATION-GATES.5BSD.md

> ARM64/RISC-V checkpoint support is implemented as an experimental opt-in:
> kernel `options BHYVE_SNAPSHOT` (new for both targets, not in GENERIC) and
> userland `MK_BHYVE_SNAPSHOT=yes` (still in BROKEN_OPTIONS). Kernel records
> `vm`/`vgic` (ARM64) and `vm`/`aplic` (RISC-V) use canonical VMS2 envelopes;
> platform records `cpu_power`, `pl011`, `pl031` (ARM64) and `cpu_power`,
> `uart` (RISC-V) replace the AMD64 `atkbdc` record. Snapshot-enabled and
> maintained kernels, vmm modules and fully linked bhyve binaries build for
> both targets (featB-final-*), and native ASan/UBSan codec tests pass with all
> mutants killed (featB-final-codec-tests). Runtime behavior is unqualified:
> no ARM64/RISC-V VM has been checkpointed, restored or migrated. SSTC RISC-V
> hosts, backward RISC-V host time, ARM64 FEAT_ECV passthrough and ARM64 debug
> capabilities are refused. Snapshot/migration live-matrix cases for these
> targets remain not-run, and BHYVE_SNAPSHOT must stay in BROKEN_OPTIONS until
> they pass on matched hardware.
