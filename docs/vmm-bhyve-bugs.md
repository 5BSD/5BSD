# VMM / bhyve — Correctness Bug List

Correctness-focused review (not a security review) of the hypervisor code:
`sys/amd64/vmm` (Intel VMX incl. nested, AMD SVM, IOMMU, emulated io devices, snapshot),
`usr.sbin/bhyve` (device models — virtio 1.4 stack, PCI emulation, AHCI/NVMe/xHCI, checkpoint),
`lib/libvmmapi`, and the `vmm_dev` ioctl interface.

References: `/usr/src/bluetooth-specs/…` (n/a here); virtio spec + reference sources in
`/tmp/bhyve-virtio-*`, `/tmp/linux-virtio-*`, `/tmp/freebsd-main-virtio.*`,
`/tmp/virtio-admin-spec.txt`; Intel SDM Vol 3 at `/tmp/325384-092-sdm-vol-3abcd.txt`;
design docs in `docs/bhyve-virtio-*.md` and `docs/bhyve-virtio-1.4-validation-review.md`.

Review method: repeated passes with changing focus (broad correctness by component, then
concurrency, arithmetic/bounds, spec conformance, error/rollback, ring/DMA handling) until a
pass finds nothing new. Same severity scale as the Bluetooth doc (P1/P2/P3).

Status: **COMPLETE** — 3 correctness rounds (28 findings, all P2/P3) + a completeness round
(findings 29-44, adding **4 P1 completeness gaps**: NVMe can't checkpoint, FPU/XSAVE not saved,
5-level EPT lie, save-preemption-timer lie). See summaries at end. The correctness of the code that
*exists* is strong; the P1s are missing coverage, not wrong logic.

**2026-08-12 revalidation (Phase A item 5):** all 44 findings re-checked against the current `dev` tree.
**No finding is fixed** — all 4 P1s (29, 36, 43, 44) and every P2 remain present; dated
status lines added under each finding below with current file:line evidence. Several
subsystems were refactored since the review (virtio-snd completion, virtio-gpu blob flush,
xHCI ERST validation, admin device-parts publish, svm #DB/startup-guard paths) without
resolving the cited defects. Findings 29-32, 36, 37, 40, 41 (NVMe/HDA/pci-uart/xHCI
snapshot, guest-FPU snapshot, PIT/IOAPIC/LAPIC snapshot) and 8-9 (svm.c) sit in files that
carry uncommitted in-flight edits from concurrent fix work; they were validated against the
tree as readable today.

**2026-08-12 fix wave (working tree, uncommitted):** findings 11, 12, 13, 16, 18, 24,
29, 30, 31, 32, 36, 37, 40, 41, 43, and 44 were fixed the same day; findings 38 and 39
(IA32_XSS, IA32_SPEC_CTRL) were resolved by explicit fail-closed decisions.  A dated
fix/resolution line sits under each affected finding.  The snapshot fixes (29-32, 36,
37, 40, 41) have rootless model/codec evidence only — live checkpoint/restore runs
remain required before any of them is called release-qualified.  Still open from the
high/medium set: 15 (xHCI ERST TOCTOU), 33 (pre-copy engine dormant — Phase E work),
and the remaining P2/P3 findings without a fix line.

**2026-08-13 whole-tree review-loop pass (working tree, uncommitted) — cross-reference only:**
a multi-round rotated-lens adversarial review over all virtualization code (bhyve device
models, the VMM kernel, Intel nested VMX, snapshot/checkpoint, and the code added this
cycle: the migration control plane and pvclock) fixed a further **52**
correctness/concurrency/portability/divergence issues beyond the 2026-08-12 fix wave above.
Several land in subsystems already listed here (e.g. additional gdb bounds hardening, a
vlapic x2apic path, AHCI, e1000, and HDA); others are in code introduced this cycle
(migration session codec, pvclock seqlock).  This is a cross-reference note only: the
historical findings below and their 2026-08-12 status lines are **unchanged**, and the
loop's fixes carry model/build evidence only (no live checkpoint/migration/nested
qualification).  The consolidated review-loop entry is in
`docs/waspnest-remaining-work-handoff.md` §1B.

---

## Findings

- **Round 1** (virtio core/transport; admin+SR-IOV+device-parts; virtio net/block/scsi/console;
  virtio-fs/gpu/iommu; kernel io-devices + instruction emulation; snapshot/checkpoint): in progress.

---

### Round 1 — snapshot / checkpoint / migration

**Verified fully clean — no findings.** All of `vmm_snapshot.c`, `vmm_snapshot_x86_state.c`,
`vmm_snapshot_x86_transaction.c`, `vmm_snapshot.h`, bhyve `snapshot.c`, `checkpoint_manifest.c`,
`checkpoint_cpu.c`, `checkpoint_machine.c`, `checkpoint_compat.c`, `checkpoint_topology.c`,
`checkpoint_numa.c`, `migration_dirty.c` are a hardened rewrite: save/restore are byte-exact
mirrors at fixed offsets; per-vCPU/device section counts are matched exactly on restore;
untrusted length/offset fields from the manifest/JSON are bounds-checked against the mmap before
use; `format_version == 3` exact gate rejects older formats; SHA-256 + payload CRC verified before
use; reserved bytes written-zero and verified-zero; dirty-bitmap byte count and page-index bounds
are correct. No save/restore asymmetry, struct-layout drift, permissive version gate, trusted-
length overread, or count mismatch found.

### Round 1 — virtio core transport / ring layer

**Verified fully clean — no findings.** `virtio.c`, `virtio.h`, `virtio_pci_modern.c`,
`virtio_packed.c/.h`, `virtio_dma.h` cross-checked against upstream `/tmp/freebsd-main-virtio.c`
and the Linux packed-ring driver: split-ring chain walking (head/next masked & bounds-checked,
direct/indirect chain length bounded by qsize, `n_indir` from mapped length), packed-ring walking
(boundary-crossing wrap-counter toggle matches Linux, indirect bounded, WRITE-only masking per
§2.8.7), EVENT_IDX suppression (canonical `vring_need_event`; packed variant proven equivalent),
packed wrap counters, modern PCI transport (feature-select `< 2`, GF masking, device-cfg
bounds/alignment, half-open BAR window checks, FEATURES_OK→DRIVER_OK gating, late RING_PACKED
renegotiation rejected), MSI-X vector range checks (legacy + modern), 8-bit config_generation
latching, and `paddr_guest2host(len)` translation with NULL checks. No off-by-one, overflow, or
feature-mask bug found. (Stricter-than-legacy INDIRECT+NEXT rejection is intentional/fail-closed.)

### Round 1 — kernel emulated io-devices + instruction emulation

**Verified fully clean of P1/P2 — no correctness bugs.** `vlapic.c`, `vioapic.c`, `vatpic.c`,
`vatpit.c`, `vhpet.c`, `vrtc.c`, `vpmtmr.c`, `vmm_instruction_emul.c`, `vmm_lapic.c`,
`vmm_ioport.c`, `vmm_mtrr.c`, `x86.c`, `x86_cpuid.c` are faithful to upstream FreeBSD vmm; fork
changes are almost entirely `#ifdef BHYVE_SNAPSHOT` save/restore rewrites (staging + validation)
plus a hardened MTRR MSR path and a CPUID topology refactor, all verified correct and
wire-compatible. Checked: LVT masking, ICR delivery-mode/dest-shorthand validation, EOI/ISR
priority resolution, DCR divisor decode (no guest div-by-zero), timer math; IOAPIC RTE/remote-IRR,
8259 sequencing/cascade; PIT divisor guarded against guest zero, HPET comparator div-by-zero
guarded; RTC rate/BCD/alarm; instruction emul sign/zero-extension, MMIO RMW, gla2gpa page walks
(PAE/4-level/LA57); CPUID leaf/subleaf registers, masks, topology, VMX gated behind VM_CAP.
Minor P3/by-design notes (not scored): leaf 0xB/0x1F EDX=0 for subleaves ≥2 (matches upstream);
leaf 0x1F ignores the `cpuid_leaf_b=0` tunable; guest MAXPHYADDR clamped to 52 (MTRR mask-width
tradeoff). Notably the vpmtmr snapshot rewrite *fixes* a latent upstream bug (elapsed count lost
across restore).

### Round 1 — virtio admin queue / SR-IOV / device-parts

1. **[P3] virtio_device_parts.c:263-268 — duplicate `(type, selector)` device parts only rejected
   when consecutive**
   The iterator enforces non-decreasing `type` order but never enforces `selector` ordering within
   a type; duplicate detection compares only against the immediately preceding part. A stream like
   `[COMMON_CFG off=0][COMMON_CFG off=4][COMMON_CFG off=0]` is type-ordered, so the repeated
   `off=0` passes and both copies reach the provider's `prepare_restore` (last-writer-wins double
   apply). Not memory-unsafe; a validation gap. Fix: also reject `type == prior_type &&
   selector < prior_selector`, or track seen selectors.
   *2026-08-12 revalidation: STILL PRESENT — virtio_device_parts.c:263-268 still rejects duplicates only against the immediately prior part (`le64dec(selector) == iterator->prior_selector`).*

2. **[P3, latent] virtio_admin_device_parts.c:1150-1170 — post-commit capability publish failure
   would leave resource/ownership state half-updated**
   After `virtio_admin_resource_restore_commit()` swaps the new object set live, the driver
   capability limits are published; if that returned nonzero the `if (error == 0)` guard skips
   copying `present`/`members` into the ownership arrays while `driver_limit` was already reverted,
   leaving committed objects and ownership indices disagreeing. The in-code argument that the
   publish "cannot fail" (prepare validated every staged object deterministically) holds, so this
   is a robustness note, not an active bug.
   *2026-08-12 revalidation: STILL PRESENT (latent) — refactored (`driver_set` branch) but virtio_admin_device_parts.c:1151-1170 still guards the `present`/`members` copy with `if (error == 0)` after commit.*

*Round 1 clean (admin/device-parts): virtio_admin.c header decode & command gating,
virtio_state_range.h wrap-aware overlap, device_parts_handler GET/SET bounds,
virtio_admin_device_parts dispatch offsets & `resource_present/member[UINT8_MAX]` sizing,
virtio_admin_resource create/modify/destroy ownership & stage commit (no double-free),
virtio_admin_capability bitmap sizing, virtio_admin_group precedence/lease pattern,
virtio_admin_sriov VF-index bounds & rdlock/wrlock fence, virtio_admin_queue iov gather/scatter &
namespace resolve, virtio_admin_pci quiesce gating. All serialize/deserialize pairs symmetric; no
over-read, dispatch gap, index escape, leak/double-free, or offset+length overflow.*

### Round 1 — virtio net / block / scsi / console

**Verified clean of P1/P2 — no memory-safety, data-corruption, or info-leak bug.** A heavily
hardened fork: `block_if.c` (offset/resid/iovcnt/total-length validation), `pci_virtio_block.c`
(descriptor-shape gate, status located by walking back over zero-length writable descs, LBA/sector
overflow-safe capacity checks, completion `len` = bytes actually read, IDENT buffer zeroed),
`pci_virtio_net.c` (RX staging bounds & header reframing, num_buffers/mergeable accounting matches
bytes written, csum_start/offset bounds, control-queue RSS/HASH offset validation),
`pci_virtio_scsi.c` + `virtio_scsi_event.c` (header IN/OUT length checks, LUN validation, residual/
sense `MIN` copies, loss-aware event ring), `pci_virtio_console.c` (RX/TX direction checks, control
message length pinned, stale-connection fd guard). All used-ring lengths equal bytes written to
writable descriptors; no header/status descriptor folded into a data iovec.

3. **[P3] pci_virtio_scsi.c:1066 — `pci_vtscsi_an_handle` is a silent no-op**
   AN_QUERY/AN_SUBSCRIBE always return `event_actual=0`/`response=OK` without recording any
   subscription (matches upstream; a stub, not a safety issue).
   *2026-08-12 revalidation: STILL PRESENT — `pci_vtscsi_an_handle` stub now at pci_virtio_scsi.c:1067 (softc `__unused`).*

4. **[P3] pci_virtio_scsi.c:~1859 (request_response) — returns `S_OVERRUN` even on `CTL_SCSI_ERROR`
   when `ext_data_filled > data_len`**
   Slightly at odds with the file's own comment that a SCSI error should surface as `S_OK` with
   sense; only reachable if CTL reports fill > provided length.
   *2026-08-12 revalidation: STILL PRESENT — pci_virtio_scsi.c:1897-1901: `CTL_SUCCESS`/`CTL_SCSI_ERROR` both return `S_OVERRUN` when `ext_data_filled > data_len`.*

### Round 1 — virtio-fs / virtio-gpu (2D) / virtio-iommu

**Verified clean of P1/P2 — no memory-safety, overflow, OOB, UAF, or wrong-reply-length bug.**
Uniformly length-gated, overflow-checked, id-keyed lookups (not raw array indexing). virtio-iommu:
ATTACH/DETACH linear scans + domain-id bounds, MAP end<=start/wrap/phys overflow/alignment/overlap
checks, UNMAP affected-set exact complement of MAP (no off-by-one), DMA-active→S_BUSY, VIOT table
bounds. virtio-fs: FUSE in/out headers length-gated before every field read, chain gather/scatter
clamped, pending table hash+free-list, used-length = validated FUSE out.len. virtio-gpu-2d:
CREATE_2D stride*height overflow-guarded, ATTACH_BACKING count [1,4096] with exact length & per-
entry overflow, SET_SCANOUT rect⊆resource, UAF prevented by ref-clear-on-unref + re-lookup under
mutex, TRANSFER_TO_HOST_2D row/offset math in-bounds, blob/EDID feature-gated.

5. **[P3] virtio_fs_host.c:245-246 — `FUSE_INTERRUPT` marked `expects_reply=true`**
   Diverges from real FUSE fire-and-forget; a true-FUSE backend that never replied would leave the
   hiprio descriptor outstanding until reset. By-design for the local VFSB backend contract.
   *2026-08-12 revalidation: STILL PRESENT (by design) — virtio_fs_host.c:245-246: `expects_reply = opcode != FORGET && opcode != BATCH_FORGET`, so INTERRUPT still expects a reply.*
6. **[P3] pci_virtio_fs.c:562-606 — notification delivery keys on device-offered `vsc_notifications`
   rather than guest-ACKed `VIRTIO_FS_F_NOTIFICATION`**
   Degrades safely (guest that didn't negotiate posts no queue-1 buffers → EAGAIN); spec nit.
   *2026-08-12 revalidation: STILL PRESENT — pci_virtio_fs.c:131,387 still key on device-offered `vsc_notifications`, not the guest-ACKed feature.*
7. **[P3] virtio_gpu_2d_state.c:733-765 — blob `RESOURCE_FLUSH` re-DMAs guest backing every flush**
   CREATE_BLOB→ATTACH→SET_SCANOUT_BLOB→DETACH→RESOURCE_FLUSH hits `gpu_backing_read()` with
   `backing_bytes==0` → EFAULT → RESP_ERR_UNSPEC, violating the "detach leaves retained host copy"
   design (2D resources honor it; blob branch doesn't). Bounds safe; Linux never detach-then-flushes
   blobs. Also (out of scope) virtio-iommu PROBE always returns an empty property list (no RESV_MEM).
   *2026-08-12 revalidation: STILL PRESENT (refactored) — blob branch of RESOURCE_FLUSH (virtio_gpu_2d_state.c:733-760) still reads guest backing per row via `gpu_backing_read`; detach-then-flush still fails to RESP_ERR_UNSPEC.*

*Round 1 VMM summary: across snapshot/checkpoint, virtio core transport, kernel io-devices +
instruction emulation, virtio admin/device-parts, virtio net/block/scsi/console, and
virtio-fs/gpu/iommu — NO P1/P2 correctness bugs. The hypervisor code is markedly more hardened than
the Bluetooth stack. Findings 1-7 are all P3/latent. Round 2 covers the deferred areas: nested VMX,
AMD SVM, remaining virtio devices, non-virtio PCI, libvmmapi/vmm_dev.*

### Round 2 — nested VMX: VMCS12→VMCS02 shadowing/composition

**Verified clean — no findings.** All 16 files traced: exit controls taken verbatim from L0,
entry LOAD_DEBUG/PAT/EFER forced with GUEST_LMA from effective EFER, APICv/posted-int/TPR stripped
when absent from virtual caps (CR8-exiting substituted), secondary control validated against hw
caps after compose. `VMCS_LINK_POINTER = UINT64_MAX` disables hardware VMCS shadowing so all L1
VMREAD/VMWRITE trap (no shadow-bitmap escape surface); the software `nvmcs_header` enforces
sorted-unique well-typed fields with read-only + width-truncation checks. Control-word compose is
`(l0 & (l0_owned|emulated)) | (l1 & l1_owned) | ((l0|l1) & merged)` with correct L1-owned masks;
exception bitmap = L0|L1, CR0/CR4 mask = L0|L1, read-shadow overlap → L1, CR3-target =
intersection, PF mask/match falls back to software filter on conflict (matches SDM/KVM). Lease/
registry paths use generation/epoch/digest gating and atomic replace.

**OPEN LEAD (P1 if confirmed) — nested VMX ENABLE_VPID composed as merged `(l0|l1)`, not
L1-owned.** On a host where L0 runs its own guests with VPID, VMCS02's composed secondary has
VPID bit 5 set even when L1 did not enable VPID for L2; `vmx_nested_vmcs02_bind.c:107` +
`nvmxp_validate` then require `hardware_vpid != 0`, so nested entry hard-fails unless
`vmx_nested_vpid_transition_plan()` (in vmx_nested_vpid_owner.c) *always* allocates a hardware
VPID for VMCS02. Needs confirmation from the vpid_owner/EPT reviewer: if VPID is allocated only
when L1 requested it, this is a P1 (nested entry always fails on VPID-using L0 hosts).

### Round 2 — AMD SVM + AMD IOMMU

**No P1/P2 correctness defects in the guest-execution hot path or VMCB setup.** svm.c VMCB
control/intercept setup, CR-shadow mask, EVENTINJ encoding, EXITINTINFO save/re-inject, NMI/IRET
blocking, V_IRQ/V_TPR window logic, ASID generation/FlushByAsid, NPT n_cr3, clean-bit dirtying,
exitcode dispatch, EFER consistency all correct and upstream-faithful; the Aug-11 refactors
(exception-class classification, deferred lastcpu publication, CPUID staging, snapshot restore) are
faithful (deferred-lastcpu is more correct than the upstream premature version). svm_msr.c, vmcb.c,
npt.c, and the AMD IOMMU (amdvi_hw/ivrs_drv/amdviiommu — command/event ring math, DTE setup, IVRS
overrun guard, device-entry bounds) all clean.

8. **[P3, upstream-parity] svm.c:1363,1454-1518,1562 — `errcode_valid` read uninitialized when
   reflecting a non-single-step #DB**
   `errcode_valid` is uninitialized; the `case IDT_DB:` arm only assigns state when
   `stepped && RFLAGS_TF`, so a plain guest #DB (hardware breakpoint via DR7, or trace-exceptions
   on) breaks with `reflect==1` and `errcode_valid` garbage. `vm_inject_exception_class(...,
   errcode_valid, ...)` then may push a bogus error code for #DB (which has none), corrupting the
   guest handler's stack. Reachable but identical to upstream `main` (not a fork regression).
   *2026-08-12 revalidation: STILL PRESENT — svm.c:1363 (`errcode_valid` uninit); the IDT_DB arm (1454-1517) assigns nothing on the non-stepped reflect path; injected at 1562. File is mid-edit by concurrent work.*
9. **[P3, likely self-healing] svm.c:2276-2292 — event left in EVENTINJ when the startup-entry-
   owner guard aborts entry before VMRUN**
   When the capsule startup owner guard returns a non-ENTER action, the loop breaks after
   `svm_inj_interrupts()` already programmed `ctrl->eventinj` but before VMRUN. Traced re-entry
   appears to self-heal (stale VALID bit defers new injection, next VMRUN delivers the accepted
   event) without hitting the KASSERT or double-injecting; flagged only as an invariant deviation
   exercised by the fork's startup owner.
   *2026-08-12 revalidation: STILL PRESENT — svm.c:2277-2291: the guard-abort path now does `svm_set_dirty(vcpu, 0xffffffff)` before `break` but still leaves the programmed `ctrl->eventinj` valid (self-healing as analyzed).*

### Round 2 — VMM core / ioctl ABI / libvmmapi

**Verified fully clean — no findings.** vmm_dev_machdep.c ioctl dispatch (VM_RUN cpuset copyout
bounded + tail zero-fill, VM_RUN_GENERATION ranges validated under sv_maxuser, KERNEMU access-width
can't overflow the 24-byte value field, compat shims correct), vmm.c (register/seg/x2apic/
capability setters all range-checked, vm_copy_setup bounds nused, snapshot capture/restore validate
counts vs capacity/maxcpus with overflow guards + generation re-checks), vmm_mem_machdep
(gpa+len<gpa overflow + page-align), vmm_dirty_log_machdep, vmm_intinfo (vector/type bounds),
vmm_ioport (MAX_IOPORTS guard), vmm_x86_startup_* (enum→register mappings reject out-of-range,
guarded array indexing, transactional apply/rollback). libvmmapi shares vmm_dev.h with the kernel so
ioctl numbers/structs agree by construction; vm_get_stats/gpa_pmap/register helpers all bounded by
kernel-validated counts. No OOB, ABI mismatch, or wrong-state path found.

### Round 2 — nested VMX: nested EPT (L2→L1→host)

**Verified clean of P1/P2.** The nested-EPT translation core is well-defended: EPTP validation
(memtype UC/WB, walk-length 3/4, AD-cap, reserved bits, MAXPHYADDR), 4-level GPA cap to <2^48,
per-entry high-reserved/misconfig checks before pointer chase, `vm_gpa_hold` bounding every load,
index shift maxing at 48, misconfig checks matching SDM 28.2.3, exit-qualification bit layout
matching SDM Table 28-7, PAE PDPTE reserved mask `0x1e6`, two-level composition (alias L2 GPA→L1
GPA re-translated through L0 EPT), INVEPT/INVVPID type-capability + descriptor + canonical-address
checks, cache keyed on {eptp, capability_signature, mbec} with conservative over-invalidation. No
stale-mapping, OOB, or wrong-translation path.

10. **[P3, benign] vmx_nested_ept.c / vmx_nested_ept_root.c:218 — top-of-range L2 GPA can translate
    but cannot be shadowed**
    `vmx_nested_ept_walk` accepts `gpa < 2^47` (advertised width), but the shadow vmspace's
    `max_address` (`VM_MAXUSER_ADDRESS_LA48 = 0x7ffffffff000`) is one page below 2^47. An L1 EPT12
    mapping an L2 GPA in `[0x7ffffffff000, 2^47)` walks to TRANSLATED, POPULATE emits
    `l2_page = 0x7ffffffff000`, and `vm_map` insert exceeds `vm_map_max` and fails — an L1-triggered
    failure of its own L2 (no OOB, no wrong translation). The physical-width clamp otherwise
    correctly prevents the 4-level-shadow/5-level-EPT12 mismatch.
    *2026-08-12 revalidation: NOT RE-VERIFIED (area refactored) — the shadow backend now carries explicit `min_address`/`max_address` bounds (vmx_nested_ept_root.c:65-75); the one-page top-of-range mismatch could not be re-confirmed or refuted without a deeper trace. Benign P3 either way.*

### Round 2 — remaining virtio devices (balloon/mem/pmem/rtc/snd/rnd/input/vsock/9p)

11. **[P2] virtio_snd_queue.c:369-372 (with virtio_snd_async.c:287-293, pci_virtio_snd.c:581-589,842)
    — virtio-snd capture backend error forces a full device reset instead of returning IO_ERR
    status**
    On a capture (RX) PCM request, when the OSS record backend errors or returns a zero-length
    read, the async layer delivers `capture_size == 0`. `virtio_snd_queue_capture_complete()`
    rejects `payload_size == 0` at line 369 (EINVAL) *before* reaching its own error branch (388)
    that would zero the buffer and encode `S_IO_ERR`. The caller treats the EINVAL as fatal, sets
    NEEDS_RESET, and relchains with `used = 0`. Trigger: any `VIRTIO_SND_R_PCM_RX` while
    `backend=oss` and the record device errors/short-reads (not reachable with the default `null`
    backend → P2). Fix: pass the real `completed.payload_size` instead of `capture_size` on the
    error path.
    *2026-08-12 revalidation: STILL PRESENT — virtio_snd_queue.c:369-372 still EINVALs `payload_size == 0` first; virtio_snd_async.c:285-293 still passes length 0 on IO_ERR; pci_virtio_snd.c:582-589 then sets NEEDS_RESET.*
    *2026-08-12 fix (working tree): `pci_vtsnd_async_complete()` now passes NULL payload with the claim's nonzero `payload_size` on backend error, so the queue layer's error branch completes the request with `S_IO_ERR` and full used length instead of tripping the protocol-violation EINVAL into NEEDS_RESET. Regression test `capture_backend_error_completes_request_without_reset` fails with the fix reverted, passes with it.*

*Round 2 clean (remaining virtio devices): virtio-balloon (PFN→gpa bounds-checked before
discard, no shift overflow), virtio-mem (range decode validates base/alignment/overflow +
independent re-bound before madvise, UNPLUG no underflow), virtio-pmem (length validated, async
lifetime safe via VS_LOCK + epoch/generation fence), virtio-rtc (control parse per-type sizes into
fixed buffer, alarm overflow guarded), virtio-rnd (device-write-only, bounded, no leak),
virtio-input (direction checks, exact-8-byte events, config select bounds), virtio-9p (chain split
by respidx, iov bounded to 128, freed exactly once), virtio-vsock (hdr.len bounded + re-validated,
iov overflow checked, event re-lookup by immutable id+fd under lock, overflow-checked credit math,
fds closed on failure).*

### Round 2 — nested VMX: entry/exit/run/reflect flow

12. **[P2] vmx_nested_vmentry.c:332 (software), :407 (snapshot) — PAE-L2 VM-entry MSR-load failure
    is un-reflectable to L1; L0 returns EPROTO instead of exit reason 34**
    In `vmx_nested_vmentry_validate` the stages run in architectural order. For a PAE + paging +
    non-IA-32e L2, the PDPTE stage on success sets `candidate.pdpte.active = true`. If the *next*
    stage (VM-entry MSR-load list) then fails, `nvmx_entry_failure(&candidate, STAGE_MSR, ...)`
    builds the rejection but does not clear `candidate.pdpte`, so the record carries
    `pdpte.active == true`. `vmx_nested_vmentry_rejection_validate` (line 120) rejects exactly that
    (`result->pdpte.active` → EPROTO), reached during reflection via
    `vmx_nested_context.c:520`. Net: instead of L1 receiving the architected "VM-entry failure due
    to MSR loading" (basic exit reason 34), the emulation returns a hard EPROTO. STAGE_MSR is the
    only stage after PDPTE, so the condition is precise and L1-triggerable (32-bit PAE L2 + a
    malformed VM-entry MSR-load entry). Same defect on the snapshot path (line 407). Fix: zero
    `candidate.pdpte` when converting to a STAGE_MSR entry-failure in both functions. (Hardware-
    attempt rejection paths are clean — they build from a fresh memset candidate.)
    *2026-08-12 revalidation: STILL PRESENT — vmx_nested_vmentry.c:328-336 (software) and 393-411 (snapshot) still convert to a STAGE_MSR entry-failure without clearing `candidate.pdpte`; `nvmx_entry_failure` (86-96) does not touch pdpte and `vmx_nested_vmentry_rejection_validate` (~120) rejects `pdpte.active` with EPROTO.*
    *2026-08-12 fix (working tree): `nvmx_entry_failure()` now zeroes `result->pdpte`, fully unwinding the candidate at every rejection funnel point; the PAE-then-MSR-failure case now reflects entry-failure reason 0x80000022 with the failed index and passes rejection validation. Covered in `vmentry_pipeline` with a positive PDPTE control.*

*Round 2 clean (nested entry/exit/reflect — cross-checked vs SDM §25.2/§26/§27/§28/§30): reflect
router predicates (INVPCID/RDTSCP/UMWAIT/WBINVD/RDRAND/DESC gating, CR0/CR4/LMSW/CLTS masks, #PF
PFEC mask/match inversion, NMI/ext-intr L0 carve-outs, MTF, preempt-timer), basic exit-reason
enum vs Appendix C, IDT-vectoring/exit-interruption copied intact + entry-interruption valid bit
cleared, event/window synthesis, deliver-error-code vector set {8,10,11,12,13,14,17} (#CP excluded),
L2→L1 guest-state save/host-state load, EFER.LMA→"IA-32e mode guest" gating, preempt-timer
wraparound, nested TSC compose/offset (INT64_MIN-safe), entry interruption-info validity + reserved
mask 0x7ffff000, wrong-VMCS-current hazard guarded by critnest+assertion, entry MSR-load-failure 34
/ MCE-during-entry 41 correctly L0-owned.*

### Round 2 — nested VMX: MSR/capabilities/instruction emulation + base Intel VMX

13. **[P2] vmx_nested_instruction_handoff.c:725-735 — VMLAUNCH/VMRESUME with no current VMCS
    becomes an L0 host error instead of VMfailInvalid**
    For VM-entry instructions the handoff calls `ops->vmcs_launch_state(arg,
    candidate.current_vmcs_gpa, …)` *before* `vmx_nested_machine_vmentry()` runs its
    `current_vmcs_gpa == UINT64_MAX → FAIL_INVALID` check. When L1 does VMXON then
    VMLAUNCH/VMRESUME without a VMPTRLD, `current_vmcs_gpa == UINT64_MAX`; the launch-state
    callback returns ESTALE/EPROTO → mapped to ACCESS_FATAL → `disposition = HOST_ERROR`
    (EINPROGRESS), so `if (error != 0) goto out` fires and the FAIL_INVALID branch is never
    reached. SDM requires VMfailInvalid (guest-recoverable; a standard kvm-unit-tests case).
    VMREAD/VMWRITE run their machine check before the callback — only the VM-entry path is
    inverted. Not hit in normal operation (real hypervisors VMPTRLD first) → P2. Fix: check
    `current_vmcs_gpa == UINT64_MAX` before invoking `vmcs_launch_state`.
    *2026-08-12 revalidation: STILL PRESENT — vmx_nested_instruction_handoff.c:717-735 still calls `ops->vmcs_launch_state(arg, candidate.current_vmcs_gpa, ...)` before `vmx_nested_machine_vmentry`; `nvmx_runtime_vmcs_launch_state` → `vmx_nested_vmcs_registry_launched` errors for the UINT64_MAX sentinel (no registry entry), so the FAIL_INVALID branch is still unreachable.*
    *2026-08-12 fix (working tree): the UINT64_MAX no-current-VMCS sentinel is checked before the `vmcs_launch_state` callback; VMLAUNCH/VMRESUME without a current VMCS now complete in L1 as VMfailInvalid (CF set, RIP advanced). Covered in `vmx_instruction_frozen_handoff`.*

14. **[P3] vmx_nested_instruction_capture.c:144 + vmx_nested_instruction_handoff.c:218-221 —
    MOV-SS-blocked non-entry VMX instruction fails emulation as an L0 host error**
    Capture copies `movss_blocked` for every operation; `nvmx_ih_request_valid` then returns
    EINVAL for any request with `movss_blocked` set whose op is not VMLAUNCH/VMRESUME, propagating
    to a host error. A legal `MOV SS,x; VMREAD` turns a normally-succeeding VMREAD into an L0 host
    error. MOV-SS blocking is architecturally relevant only to VM entry. Extremely narrow trigger
    → P3. Fix: only propagate `movss_blocked` for VMLAUNCH/VMRESUME.
    *2026-08-12 revalidation: STILL PRESENT — vmx_nested_instruction_handoff.c:218-221: `movss_blocked` on any non-entry op still returns EINVAL.*

*Round 2 clean (nested caps/MSR/instruction + base VMX, vs SDM App A/B): IA32_VMX_BASIC assembly,
default1 constants (PIN 0x16 / PRIMARY 0x0401e172 / EXIT 0x00036dff / ENTRY 0x000011ff),
legacy-vs-TRUE derivation, CR0/CR4 FIXED0/FIXED1 (unrestricted-guest PE/PG clear), PROCBASED_CTLS2
allowed-0==0, all cap MSRs read-only, FEATURE_CONTROL lock; instruction CPL/UD/#GP ordering,
VMfailValid-vs-Invalid, revision/alignment gating, VMWRITE read-only rejection, INVEPT/INVVPID
checks; UINT64_MAX "no current VMCS" sentinel handling, VMCLEAR-of-current, VMXERR 6, shadow
bit-31 clear; base vmx.c event-injection format, CR0/CR4/EFER shadowing/masks, MSR-bitmap;
vmx_msr allowed-0/1 negotiation + TRUE selection + TSC_AUX 63:32 reject + PAT validation; vmcs.c
field encodings + TSC_MULTIPLIER 0x2032 + exit reasons 65-85; ept.c cap/EPTP assembly; cpufunc asm
CTASSERTs. The two unverified residuals it flagged (EPT A/D capability lie; preemption-timer) are
CLEARED by other reviewers — nested EPT does compare-exchange A/D updates on permitted access, and
vmx_nested_timer.c countdown/wraparound was verified correct.*

### Round 2 — non-virtio PCI device models + PCI core

*(All three are inherited from upstream FreeBSD bhyve, not fork regressions — but real and worth
fixing. The fork is otherwise a hardening rewrite that fixed several upstream bugs.)*

15. **[P2] pci_xhci.c:885-886,890,959 — event-ring (ERST) size TOCTOU → guest-triggerable OOB host
    write**
    `pci_xhci_insert_event()` re-reads `dwEvrsTableSize` live from guest RAM, but `erst_p` was
    mapped once at ERSTBA-program time for the size present then. A guest programs the ERST, then
    inflates `dwEvrsTableSize` in the in-memory entry; the insert-time guard
    (`er_enq_idx >= event_count`) now permits `er_enq_idx` past the mapped region, so
    `memcpy(&erst_p[er_enq_idx], evtrb, ...)` writes beyond the validated map (into guest RAM or an
    unmapped hole → bhyve crash / host DoS). The `XHCI_EVENT_RING_SEGMENT_MAX` cap bounds the
    overrun to ~1 MB but doesn't close it. Fix: cache the size `erst_p` was mapped with; reject/
    remap/clamp when the live value differs.
    *2026-08-12 revalidation: STILL PRESENT — insert path (pci_xhci.c:885-886) re-reads `rts->erstba_p->dwEvrsTableSize` live from guest RAM and indexes `erst_p[er_enq_idx]` with it (917, 942, 959), while `erst_p` was mapped for the size at ERSTBA-program time (2532-2544); the softc still caches no count (240-241).*

16. **[P2] pci_e82545.c:906 — RX DMA map return not NULL-checked → guest-triggerable crash**
    The RX-descriptor path does `vec[i].iov_base = pci_emul_map_dma(..., rxd->buffer_addr, bufsz,
    WRITE)` with no NULL check; `pci_emul_map_dma` returns NULL for an address outside guest RAM.
    Guest sets a valid RX ring with a bogus `buffer_addr`; on packet arrival `netbe_recv` scatters
    into `iov_base==NULL` → SIGSEGV. The fork added exactly this check on the TX side (line 1222)
    but missed RX.
    *2026-08-12 revalidation: STILL PRESENT — pci_e82545.c:904-907: RX `pci_emul_map_dma` return still unchecked; the TX-side check is at 1220-1226.*
    *2026-08-12 fix (working tree): each RX-loop `pci_emul_map_dma()` result is now NULL-checked; a bogus guest RX buffer address drops the pending packet(s) via the existing `netbe_rx_discard()` idiom instead of crashing bhyve.*

17. **[P3] pci_nvme.c:3278,3300 — DSM range length computed in 32-bit (truncation)**
    `bytes = range[r].length << sectsz_bits` with `range[r].length` a `uint32_t` → shift in 32-bit
    before widening to `size_t`. A guest DSM Deallocate with `length >= 2^(32-sectsz_bits)` on a
    large namespace truncates `bytes`, deallocating the wrong length. Advisory-only, no memory
    unsafety. Byte-identical to upstream.
    *2026-08-12 revalidation: STILL PRESENT — pci_nvme.c:3277,3300: `bytes = range[..].length << sectsz_bits` still shifts in 32-bit.*

*Round 2 clean (non-virtio PCI): pci_emul.c core (MSI-X table/PBA, config dispatch, BAR sizing,
capability walk bounded; `pci_emul_map_dma` funnels through `paddr_guest2host`), pci_ahci.c (slot
masked, PRDT/ctba NULL-checked, dbc clamped, TRIM validated; fork fixed an upstream atapi_read
bug), pci_nvme.c (doorbell validated + command copied locally closing an upstream TOCTOU, PRP
traversal bounded, fork fixed a reversed WRITE DMA direction), pci_xhci.c (slot/epid/DCBAA/
doorbell range-checked, TRB traversal budgeted), pci_passthru (MSI-X table bounded, cap-chain
walk bounded), pci_hda (BDL-count bound + overflow guards, CORB/RIRB masked), pci_fbuf (offset
validation), pci_uart (baridx/size/offset gate). Non-counted: an AHCI prdtl TOCTOU that reads
adjacent guest RAM only (no host unsafety).*

### Round 2 — nested VMX VPID lead: RESOLVED (no bug)

The open lead from the VMCS-shadowing pass is **cleared by targeted trace.** ENABLE_VPID (bit 5)
is indeed composed as merged `(l0|l1)` (not L1-owned), so VMCS02 can carry it from L0's own usage,
and bind/validate require `hardware_vpid != 0` when it's set. But both the composed bit and the
nonzero `hardware_vpid` derive from the *single* global `procbased_ctls2 & PROCBASED2_ENABLE_VPID`:
L0's VMCS01 secondary VPID bit (vmx.c:1008,1605), `vpid_alloc`→`vcpu->state.vpid` (vmx.c:733,1658),
and the `state.vpid==0 ⟺ owner-inactive` invariant (vmx_nested_entry_environment_intel.c:53-71)
together guarantee composed-bit-5 ⟺ `hardware_vpid != 0`. On a VPID host with an L1 that didn't
enable VPID, L2 correctly runs on the shared `vmcs01_vpid` with `flush_effective_context` set
(deliberate). On a non-VPID host, neither L0 nor L1 can set the composed bit. Bind/validate cannot
fail. NOT A BUG.

### Round 3 — bhyve core run-loop / MMIO-PIO dispatch / guest memory

**Verified clean — no findings.** The guest MMIO/PIO vmexit dispatch path is upstream FreeBSD
code *unchanged* on `dev` (empty `git diff main...dev` for mem.c, mem_md.c, mem_x86.c, inout.c,
vmexit.c, bhyverun.c, config.c). `vm_loop` validates exitcode/handler before dispatch; mem
interval-tree lookup + per-vCPU hint cache correct with an explicit base+size overflow guard;
inout write-back masks with `vie_size2mask` and merges into RAX; pci_emul BAR-decode bounds-checks
`addr+bytes` against `bar.addr+bar.size` and splits 8-byte MEM access into two 4-byte device calls.
The only substantive fork changes in scope are `iov.c` (a **bug fix** — upstream `split_iov`
computed `*niov2` after overwriting `*niov1`, always yielding 1 and dropping trailing iovecs; the
fork captures `total` first) and the pci_emul BHYVE_SNAPSHOT restore path (BAR/MSI geometry
validated against the live device, unregister-old/re-register-new intercept ordering traced
correct).

### Round 3 — bhyve platform / firmware / debug stub (ACPI, basl, bootrom, gdb)

18. **[P2] gdb.c:1925-1928 (H), :1946 (T), :1798 (qThreadExtraInfo), parser :764 — unbounded
    thread-id used as a `cpuset_t` index → OOB read / crash reachable from the gdb port**
    `parse_threadid()` returns `parse_integer()` truncated to `int` with no upper bound; each site
    guards only `tid <= 0` then does `CPU_ISSET(tid - 1, &vcpus_active)`. A client sending
    `Hg7fffffff` yields `CPU_ISSET(0x7ffffffe, ...)`, indexing `__bits[...]` far past the
    fixed-size cpuset on the stack — an OOB read that typically faults. `gdb.address` can be bound
    non-localhost (init_gdb:2218), so it's remotely reachable when the debug port is exposed.
    (Register indexes are correctly bounded by contrast.) Fix: bound `tid-1` against the vCPU count.
    *2026-08-12 revalidation: STILL PRESENT — parse_threadid (gdb.c:771-781) still returns unbounded `parse_integer`; sites at 1820-1821 (H), 1938/1950 (T), 1968-1969 (qThreadExtraInfo) still guard only `tid <= 0` before `CPU_ISSET(tid - 1, ...)`.*
    *2026-08-12 fix (working tree): `parse_threadid()` parses via `uintmax_t` and rejects ids outside `1..guest_ncpus` with the existing `-2` invalid sentinel (0/-1 any/all semantics preserved), so every use site returns the proper GDB error instead of indexing past the cpuset.*

19. **[P3] gdb.c:1827-1834 — `qXfer:features:read` decrements `len` by zero (reversed data/len
    update) → OOB read of the command buffer**
    The code advances `data` before computing the `len` decrement, so `pathend - data` is now -1
    and `len -= 0`; the subsequent `if (len > sizeof(buf)-1)` check is wrong and `memcpy(buf, data,
    len)` over-reads the annex by `strlen(path)+1` bytes. `buf[len]` stays in bounds and the later
    sscanf parses correctly, so functionally benign, but a real OOB read of the packet buffer.
    *2026-08-12 revalidation: STILL PRESENT — gdb.c:1849-1851: `data` is advanced before the `len` decrement, so `len -= 0` (identical bug, shifted lines).*

20. **[P3] gdb.c:1881-1882 — duplicated digit check in sequence-id detection**
    `data[0] >= '0' && data[0] <= '9'` is tested twice; the second was meant to validate `data[1]`.
    Sequence-ids are obsolete; negligible impact.
    *2026-08-12 revalidation: STILL PRESENT — gdb.c:1903-1904 still tests `data[0]` twice.*

21. **[P3] acpi.c:449-450 — `BHYVE_TMPDIR`/`TMPDIR` override logic broken**
    The `||` short-circuit means BHYVE_TMPDIR never takes effect and the intended "BHYVE_TMPDIR
    else TMPDIR else /tmp" precedence isn't implemented (if BHYVE_TMPDIR is set the third clause
    overwrites it with TMPDIR; if unset it falls straight to _PATH_TMP). Only affects where iasl
    temp files land; the /tmp fallback works.
    *2026-08-12 revalidation: STILL PRESENT — acpi.c:449-451: same `||` short-circuit; BHYVE_TMPDIR still never takes effect.*

22. **[P3, latent] basl.c:220-246 — checksum write offset wrong when `start != 0`**
    The byte is written at `table->off + start + off` — an extra `+start` versus the true field
    location `table->off + off`. Every current caller uses `start == 0` so it's correct today; a
    future `start != 0` checksum would write to the wrong address. (The summed region is correct.)

    *2026-08-12 revalidation: STILL PRESENT (latent) — basl.c:220,235: patch address is gpa `table->off + checksum->start` plus gva `+ checksum->off` — still the extra `+start`; all callers still pass `start == 0`.*
23. **[P3, latent] smbiostbl.c:934,712 — SMBIOS table size only asserted, not enforced**
    Per-type initializers write sequentially through `curaddr` with no bounds check; only a final
    `assert(curaddr - startaddr < SMBIOS_MAX_LENGTH)` (5120 bytes) guards it. With ~60+ cpu_sockets
    (one ~80-byte Type-4 record each) the structure table overruns into BHYVE_ACPI_BASE, and in a
    release build the assert is compiled out. Requires an extreme socket count.
    *2026-08-12 revalidation: STILL PRESENT — smbiostbl.c:934: still only the final `assert(curaddr - startaddr < SMBIOS_MAX_LENGTH)`.*

*Round 3 clean (platform): acpi_device.c, pci_irq (PIRQ routing / PERMITTED_IRQS mask), pci_lpc
(LPC/ISA DSDT, UART IRQ), all ACPI table builders (FADT/MADT/MCFG/HPET/SRAT/RSDP/SPCR/FACS/VIOT
lengths, GAS widths, RSDT/XSDT registration, checksums patched last in basl_finish), bootrom.c
mapping math (ROM in [highmem-16MB, highmem), no 4GB off-by-one, page-align + size validation).
mptable.c does not exist in this tree (feature removed).*

### Round 3 — bhyve device-model concurrency / threading

24. **[P2, effectively P1 on snapshot-heavy hosts] pci_ahci.c:817 (also :854, :1017, :1580) —
    split-transfer/TRIM continuation re-submitted during snapshot quiesce hits `assert(err==0)`
    and aborts bhyve**
    Snapshot/suspend pauses vCPUs, then `pci_ahci_pause → blockif_suspend → blockif_quiesce` sets
    `bc_paused` and waits for worker queues to drain. The pause is not taken under `sc->mtx`, so
    during the drain a block_if worker still runs the AHCI completion callback. For any split
    transfer (`aior->more`, set when a request needs >128 segments) or multi-range TRIM,
    `ata_ioreq_cb`/`atapi_ioreq_cb`/`ahci_handle_next_trim` re-submits the next chunk; because
    `bc_paused != 0` and the continuation isn't a stability flush, `blockif_request` returns EBUSY,
    but the AHCI submit sites `assert(err == 0)` → process abort. The block_if fence lets a write's
    own stability flush through but treats AHCI's `more` continuation as new work. Trigger: a
    snapshot landing while a >128-segment read/write or multi-range TRIM is mid-flight.
    *2026-08-12 revalidation: STILL PRESENT — asserts at pci_ahci.c:817,854,1017,1580; continuations resubmitted at 2087-2093/2157; block_if.c:1033-1035 still EBUSYs everything but a stability flush while `bc_paused` (the comment at 1026-1032 documents exactly that fence).*
    *2026-08-12 fix (working tree): continuations that collide with the quiesce fence are parked on a per-port deferred list (`paused` flag set under `sc->mtx` before the fence, making the race impossible) and resubmitted losslessly on resume; the four assert sites are now handled error paths failing the command to the guest via `ahci_abort_command()`. A snapshot with a parked continuation is rejected at restore (`port->pending != 0`) rather than restored mid-command.*

25. **[P3] pci_ahci.c:2059,2136 — completion callbacks compute `hdr = cmd_lst + slot*CL_SIZE`
    before taking `sc->mtx`**
    `cmd_lst` is mutated (and NULL-able on HBF error) under `sc->mtx`; `hdr` is only dereferenced
    after the lock, so benign on amd64, but a concurrent guest CMD write NULLing `cmd_lst` could
    fault the post-lock `hdr->prdbc` write. Pre-existing upstream pattern.
    *2026-08-12 revalidation: STILL PRESENT — pci_ahci.c:2059/2136: `hdr` still computed before `pthread_mutex_lock(&sc->mtx)` (taken at ~2069).*
26. **[P3] pci_nvme.c:1491,3643-3665 — `regs.csts` mixed synchronization drops a fatal-error CFS
    bit**
    Completion/admin/AEN threads set CFS via `atomic_set_32` without `sc->mtx`, while the
    CC-register handler does a plain non-atomic RMW of the same field under `sc->mtx`. A CFS set
    interleaving the RMW window is silently dropped, so the guest may miss the fatal-error
    indication on CQ overflow / malloc failure. Error-reporting correctness only.
    *2026-08-12 revalidation: STILL PRESENT — pci_nvme.c:1491 `atomic_set_32(&sc->regs.csts, CFS)` on the completion path vs plain `sc->regs.csts |= ...` RMWs at 1194/1253/1259/1268/1294.*
27. **[P3] pci_virtio_net.c:1761 — `proctx` reads vhdrlen/be_vhdrlen/vsc_features with tx_mtx
    released** — safe only because feature renegotiation is gated to pre-DRIVER_OK/reset; an
    unenforced invariant, not a live race.
    *2026-08-12 revalidation: STILL PRESENT — unchanged pattern around pci_virtio_net.c:1758-1765.*
28. **[P3] pci_virtio_net.c:1831 — `ping_txq` reads `vq_has_descs` under tx_mtx while the worker
    runs `vq_getchain` on the same txq without it** — formal race on `vq_last_avail`, but
    single-writer/aligned-16-bit; stale read only yields a redundant/self-correcting signal.
    *2026-08-12 revalidation: STILL PRESENT — pci_vtnet_ping_txq (pci_virtio_net.c:1817,1831) still reads `vq_has_descs` under tx_mtx against the unlocked worker.*

*Round 3 clean (concurrency): mevent.c (async delete marks+enqueues, free on dispatch thread
between batches, delete_sync waits across batch boundary — no in-batch UAF), block_if.c (freeq/
pendq/busyq + bc_paused nesting + resize_inflight all under bc_mtx, close sync-deletes resize
mevent), virtio_pmem async (lock order vs_mtx→worker→async, epoch+generation fence, no inversion/
UAF), virtio_snd async (synchronous engine, quiesce fails closed), pci_virtio_block (vsc_mtx
serialized, generation fence, snapshot drains), pci_virtio_scsi (per-structure locks vss_mtx→
vsq_rmtx→{vsq_fmtx,vsq_qmtx} no inversion, recycle after all reads), pci_nvme (per-queue mutexes,
ioreq lifecycle, quiesce defers teardown). virtqueue-notify handlers all run on the vCPU thread
holding vs_mtx; worker/mevent publishers correctly re-take it.*

---

## VMM / bhyve review — COMPLETE (converged)

3 rounds / 20 reviewer passes (+1 targeted VPID confirmation) across the whole tree: kernel VMX
(base + the ~90-file nested set), AMD SVM + IOMMU, emulated io-devices, instruction emulation,
snapshot/checkpoint, the vmm_dev ioctl ABI, libvmmapi, and all of bhyve (virtio 1.4 core + admin/
SR-IOV/device-parts + every virtio device, non-virtio PCI, the run-loop/MMIO dispatch, platform/
ACPI/bootrom/gdb, and device-model concurrency).

**28 findings — all P2/P3; NO P1.** The hypervisor code is markedly more hardened than the
Bluetooth stack: many subsystems (snapshot, virtio core transport, kernel io-devices +
instruction emulation, vmm_dev/libvmmapi, nested-VMX VMCS shadowing/EPT, AMD SVM hot path, bhyve
core dispatch) came back with zero findings, and the fork has *fixed* several upstream bugs
(iov split_iov, vpmtmr snapshot, NVMe WRITE DMA direction, atapi_read). The one nested-VMX VPID
lead was chased down and confirmed NOT a bug.

**Highest-priority fixes (P2):**
- **15** xHCI ERST size TOCTOU → guest-triggerable OOB host write (host DoS) *(inherited)*
- **16** e1000 RX DMA map not NULL-checked → guest-triggerable bhyve crash *(inherited)*
- **18** gdb stub unbounded thread-id → OOB `CPU_ISSET` read, remotely reachable if gdb port exposed
- **24** AHCI split-transfer/TRIM continuation vs snapshot quiesce → `assert` aborts bhyve
- **12** nested PAE-L2 VM-entry MSR-load failure returns EPROTO instead of reflecting exit reason 34
- **13** nested VMLAUNCH/VMRESUME with no current VMCS → host error instead of VMfailInvalid
- **11** virtio-snd capture backend error forces full device reset instead of IO_ERR status

Note: findings 12/13 are behavioral (nested guest sees wrong result); 15/16/18/24 are the
guest-triggerable memory-safety / crash issues and are the most urgent operationally. 15/16/17 are
inherited from upstream FreeBSD bhyve, not fork regressions.

---

## Completeness Round — device support, save/restore, nested (added later)

Gap analysis (what is declared/supported but missing/half-wired), distinct from the correctness
findings above. Three independent lifecycle mechanisms exist and are separate: **checkpoint
save/restore** (`pe_snapshot` + `pe_snapshot_validate`), **checkpoint pause/resume**
(`pe_pause`/`pe_resume`), and **precopy live-migration eligibility** (`pe_migration_flags`); the
virtio-1.4 admin-queue "device parts" in-band migration protocol is a fourth, separate thing.

### Device-support completeness

**Structural facts:** A missing `pe_snapshot` makes checkpoint SAVE hard-fail with ENOTSUP
(pci_emul.c:2971-2989) which aborts the *entire* checkpoint (snapshot.c:3063), and restore
preflight rejects it too ("no complete restore validator", snapshot.c:1918-1925). So a VM
containing any no-snapshot device is refused at both save and restore (guest not corrupted, just
un-checkpointable). All 27 device models are otherwise fully wired (real init + bar r/w + config
parse; no stubs).

29. **[P1] pci_nvme.c:4140-4143 — an NVMe-backed VM cannot be checkpointed at all**
    `pci_de_nvme` registers only init/legacy_config/barread/barwrite — no `pe_snapshot` /
    `pe_snapshot_validate`. Any VM using an emulated NVMe device fails checkpoint SAVE with ENOTSUP
    and fails restore preflight. NVMe is a common, high-value boot device, so in a tree this
    invested in checkpoint/migration this is a real P1 (inherited from upstream, which also lacks
    NVMe snapshot).
    *2026-08-12 revalidation: STILL PRESENT — pci_de_nvme (pci_nvme.c:4138-4145) still registers no `pe_snapshot`/`pe_snapshot_validate`; pci_emul.c:3045-3046 still hard-fails ENOTSUP. Overlaps in-flight NVMe-snapshot work.*
    *2026-08-12 fix (working tree): pci_nvme.c now registers `pe_pause`/`pe_resume`/`pe_snapshot`/`pe_snapshot_validate` and migration flags; versioned LE record ("NVM1" v1) with fail-closed validation, bounded blockif drain, EBUSY rollback on timeout, and EOPNOTSUPP for RAM-backed namespaces. Live checkpoint evidence still pending.*

30. **[P2] pci_hda.c:277-279 — an HD-audio VM cannot be checkpointed** (no `pe_snapshot`; same
    hard-fail as NVMe).
    *2026-08-12 revalidation: STILL PRESENT — pci_de_hda (pci_hda.c:275) still has no `pe_snapshot`. Overlaps in-flight HDA-snapshot work.*
    *2026-08-12 fix (working tree): full HDA snapshot implemented ("HDA1"/"HDC1" v1 records: register file, CORB/RIRB, stream cursors/tags, codec converter state) with side-effect-free validate and fail-closed BDL reconstruction on restore. Live checkpoint evidence still pending.*

31. **[P2] pci_uart.c:128-131 — a PCI `com` (pci_uart) VM cannot be checkpointed** (no
    `pe_snapshot`). Lower impact: the common serial port is the separate LPC/`uart_emul` path, not
    this PCI_EMUL device.
    *2026-08-12 revalidation: STILL PRESENT — pci_de_com (pci_uart.c:126) still has no `pe_snapshot`. Overlaps in-flight UART-snapshot work.*
    *2026-08-12 fix (working tree): pci_uart.c now wires the existing ns16550/backend codec (as pci_lpc.c already did) for snapshot/pause/resume; backend fd never serialized, destination reopens from its own config. Live checkpoint evidence still pending.*

32. **[P2] pci_xhci.c:4262-4268 — xHCI is checkpointable but NOT quiesced during snapshot, and not
    migratable** — it has `pe_snapshot`/`pe_snapshot_validate` but no `pe_pause`/`pe_resume`, so
    `pci_checkpoint_pause` no-ops it and in-flight USB transfers aren't fenced during snapshot
    (consistency risk); also no `pe_migration_flags`.
    *2026-08-12 revalidation: STILL PRESENT — pci_de_xhci (pci_xhci.c:4260-4268) is still snapshot-only: no `pe_pause`/`pe_resume`/`pe_migration_flags`. Overlaps in-flight xHCI-snapshot work.*
    *2026-08-12 fix (working tree): xHCI gains `pe_pause`/`pe_resume` (bounded 2 s monotonic drain; fence drops async completions before guest memory; ETIMEDOUT leaves device usable and checkpoint failed) plus `pe_migration_flags`. Snapshot codec itself unchanged. Live pause-under-contention evidence still pending.*

33. **[P2] migration_precopy.c:402-411 — the precopy live-migration engine is dormant (no caller)**
    `migration_precopy_enable()` (which validates devices then starts dirty logging) has zero
    callers tree-wide; no IPC/command wires it. The per-device `pe_migration_flags` on the 8
    "eligible" devices (ahci, e82545, fbuf, hostbridge, vtblk, vtnet, vrnd, vtvsock) are declared
    and unit-validated but unreachable — no VM can actually be live-migrated regardless of device
    set. (Consistent with the roadmap's "live migration incomplete", but recorded as a
    product-completeness gap.)

    *2026-08-12 revalidation: STILL PRESENT — `migration_precopy_enable` still has no caller outside migration_precopy.{c,h}.*
34. **[P3] virtio_device_parts_handler_*/virtio_admin_pci — the virtio-1.4 admin-queue "device
    parts" in-band migration provider is not wired to ANY device (tests only)**
    No `pci_virtio_*.c` calls `virtio_device_parts_handler_create`; no device advertises
    `VIRTIO_F_ADMIN_VQ` in `vc_hv_caps`; `vi_pci_stage_admin_queues()` (virtio.c:956) has no
    caller, so the admin snapshot paths (virtio.c:4339-4431) are dead in practice. Roadmap
    classifies this "foundation only, unadvertised" — no contradiction, recorded for completeness.

    *2026-08-12 revalidation: STILL PRESENT — still no `virtio_device_parts_handler_create`/`vi_pci_stage_admin_queues` caller from any device model.*
35. **[P3] Only 8 of ~24 devices declare `pe_migration_flags`** — even once the precopy engine is
    wired, a VM containing v9p/vcon/vinput/vscsi/vtballoon/vtfs/vtgpu/vtiommu/vtmem/vtpmem/vtrtc/
    vtsnd can't be live-migrated. passthru has no snapshot by nature (physical device state can't
    be captured).
    *2026-08-12 revalidation: STILL PRESENT — still exactly 8 device files declare `pe_migration_flags` (vtrnd, fbuf, hostbridge, e82545, vtnet, vtblk, ahci, vtvsock).*

*Roadmap cross-check (VIRTIO_1_4_ROADMAP.md): honest — no device claimed "production" is actually
a stub; the "provisional" virtio devices (GPU/iommu/fs/mem/pmem) are code-complete + checkpointable
but correctly not live-migration-eligible. The roadmap is virtio-scoped, so the non-virtio
checkpoint holes (NVMe/HDA/com, findings 29-31) are NOT tracked there — this review adds them.*

### Save/restore (checkpoint) state completeness

**Definitive answers:** (a) an NVMe VM's checkpoint is *refused* (ENOTSUP, fails safe) not silently
broken — see finding 29; (b) nested VMX state **is** checkpointed completely (vmcs12 registry + all
guest VMCS pages + current-VMCS pointer serialized VM-wide at vmx.c:7024-7035; nested-EPT/VPID
rebuilt-not-serialized; refuses with ESTALE/EBUSY when it can't capture rather than corrupting L1);
(c) no register/MSR class is saved-but-not-restored — but one whole class is *never captured*
(below).

36. **[P1] vmm.c:966,994 + vmm_snapshot_x86_state.c:149-160 + vmm_snapshot.h:45-56 — the guest
    FPU/SSE/AVX/AVX-512 register file (XSAVE area) is never serialized**
    `vcpu->guestfpu` (savefpu) is touched only at runtime entry/exit (`fpurestore`/`fpusave`); it is
    absent from the STRUCT_VM envelope (which encodes only flags/x2apic/exception/exitintinfo/xcr0/
    absolute_tsc), absent from STRUCT_VMCX (VMX reg/desc/MSR lists + guest_msrs; SVM set), and there
    is no STRUCT_FPU in the `snapshot_req` enum — a whole-tree grep finds no snapshot copy of
    `guestfpu`. Meanwhile XCR0 (the *enable mask*) IS captured and restored. Consequence: a restored
    guest resumes with reset/zeroed x87/SSE/AVX registers and MXCSR while XCR0 advertises those
    components active — any guest thread mid-FP/vector computation gets silently corrupted results
    or faults; restored guests running SSE/AVX userland crash or misbehave. Normal-scenario
    data-loss gap. (Verified by direct grep: `guestfpu` occurs only in vmm.c runtime paths.)
    *2026-08-12 revalidation: STILL PRESENT — `guestfpu` still appears only in vmm.c runtime paths (334, 390, 411, 966, 994); still no STRUCT_FPU in the vmm_snapshot.h enum (46-55). Overlaps in-flight guest-FPU-snapshot work.*
    *2026-08-12 fix (working tree): per-vCPU versioned LE FPU/XSAVE record (section 0x1002) is now mandatory in the snapshot transaction; validation covers truncation, compacted images, MXCSR, component dependencies, and destination-capability rejection before mutation; restore lands into `guestfpu` in the cannot-fail publish section. Pre-record development checkpoints are rejected fail-closed. Live checkpoint evidence still pending.*

37. **[P2] io/vatpit.c:545,557,113-114 — PIT per-channel `now_bt` restored as raw source-host
    uptime, never re-anchored**
    `now_bt` is saved/restored verbatim; on restore only `callout_bt` is re-anchored to destination
    uptime, not `now_bt`. The counter read-back computes `binuptime() - now_bt`, so on a destination
    host with different uptime the delta is wrong or wraps — guest PIT counter reads return garbage
    until the channel is reprogrammed (borderline P1 for a guest using the PIT as a clocksource
    across the restore point).
    *2026-08-12 revalidation: STILL PRESENT — `vatpit_snapshot_restore_locked` (vatpit.c:528-557) still copies `now_bt` verbatim (545); its own comment says only `callout_bt` is re-anchored (via `pit_timer_start_cntr0`); the counter read-back at 114 still subtracts `now_bt` from destination uptime. Overlaps in-flight PIT-snapshot work.*
    *2026-08-12 fix (working tree): gen-2 record ("APT2") serializes per-channel elapsed and channel-0 remaining/armed state; restore reanchors both `now_bt` and `callout_bt` against destination uptime and rearms directly for the serialized remaining time. Destination-uptime differential test passes at dest uptimes of 3 s and 2,000,000 s; expired one-shots no longer spuriously rearm.*

38. **[P3] IA32_XSS (supervisor XSAVE states) not captured** — if the guest uses CET or Processor
    Trace (XSAVES supervisor components) that state is lost on restore.
    *2026-08-12 revalidation: STILL PRESENT — no IA32_XSS capture found in the vmm sources.*
    *2026-08-12 resolution (working tree): IA32_XSS is not virtualized anywhere in the tree (no MSR handler, CPUID 0xD.1 masks XSAVES away), so no guest value exists to lose; the new FPU record is pinned to user XCR0 components and capture/restore both reject supervisor bits — a fail-closed tripwire until XSS virtualization ships with its own record.*
39. **[P3] IA32_SPEC_CTRL not context-switched or snapshotted** — not among the 7 VMX guest_msrs
    (vmx.h:143-151) nor the SVM VMCB set; guest speculation-control posture not preserved.
    *2026-08-12 revalidation: STILL PRESENT — no SPEC_CTRL references in vmx.h guest_msrs / vmx_msr.c.*
    *2026-08-12 resolution (working tree): IA32_SPEC_CTRL is likewise unvirtualized (no handler, IBRS/STIBP/SSBD masked from guest CPUID), so nothing can be silently lost; the record-definition comment requires SPEC_CTRL virtualization to ship with its own versioned snapshot record.*
40. **[P3] io/vioapic.c:62 — IOAPIC `id` register not saved** (guest-writable, reverts to init on
    restore; most OSes program once at boot).
    *2026-08-12 revalidation: STILL PRESENT — vioapic snapshot (vioapic.c:598-611) still saves only `ioregsel` + rtbl `reg`/`acnt`; guest-writable `id` (334) not captured. Overlaps in-flight IOAPIC-snapshot work.*
    *2026-08-12 fix (working tree): the `id` register is now in the snapshot record with `APIC_ID_MASK` validation; pre-`id` development records fail closed (short-record E2BIG) per the current-only format policy.*
41. **[P3] vlapic `svr_last` shadow not captured** (vlapic_priv.h:177) — first post-restore SVR
    write can spuriously re-run the enable/disable transition.
    *2026-08-12 revalidation: STILL PRESENT — `svr_last` still only at vlapic.c:1350-1351 (runtime) and 1638 (reset); no snapshot capture. Overlaps in-flight LAPIC-snapshot work.*
    *2026-08-12 fix (working tree): `vlapic_snapshot_restore_locked()` recomputes `svr_last` from the restored APIC page SVR — deterministic and side-effect-free since every SVR writer updates the shadow immediately, so `svr_last == svr` holds in any quiesced source state; no wire field needed.*
42. **[P3] nested active-L2 capture refuses (fail-safe) when L2 itself uses VMCS-shadowing or is
    mid-SMM** (vmx_nested_checkpoint.c:867-873, ESTALE) — ordinary L2 unaffected; a
    nested-hypervisor-with-shadowing checkpoint is refused rather than corrupted.
    *2026-08-12 revalidation: STILL PRESENT (fail-safe by design) — the ESTALE refusals are now at vmx_nested_checkpoint.c:844-859.*

*Fully covered (verified): all GPRs, RIP/RFLAGS, segment selectors + hidden descriptors,
GDTR/IDTR/LDTR/TR, CR0-4 (CR8 via LAPIC TPR), DR0-3/6/7, intr_shadow, nextrip; MSRs EFER/STAR
family/KERNEL_GS_BASE/FS-GS base/PAT/TSC_AUX/SYSENTER/full MTRR set; TSC captured as absolute and
re-anchored via vm_restore_time; XCR0 (mask only — see finding 36); pending NMI/ExtINT/exception +
exitintinfo + x2apic mode; VMX/SVM control state (ENTRY/EXIT_CTLS, interruptibility, activity,
intercepts, PIR, ASID/TLB_CTRL/VIRQ); device handlers for vlapic/vioapic/vhpet/vrtc/vatpic/vatpit/
vpmtmr + all virtio/e1000/ahci/xhci/fbuf/hostbridge/atkbdc; nested VMX; guest low+high+devmem/fb/
pmem memory. Timer re-anchoring is notably rigorous except the vatpit `now_bt` gap (finding 37).*

### Nested virtualization completeness

The Intel nested-VMX code follows an "implementation allowlist" discipline — capability MSR bits
are withheld unless the full path (validate → compose VMCS02 → route every exit → save → restore)
exists — so most dangerous controls are correctly *not* advertised. Nested is off by default
(`hw.vmm.vmx.nested=0`) + per-guest `x86.nested_vmx=true`; guest CPUID VMX bit masked unless backend
capable. Two genuine advertised-but-not-honored mismatches were found:

43. **[P1] vmx_nested_caps.c:134,275,452 vs ept.c:62,215-218 + vmx_nested_ept_root.c:81 — 5-level
    nested EPT (EPT_VPID_CAP walk-5, bit 7) advertised but EPT02 is hardcoded 4-level**
    On a 5-level-EPT-capable host, walk-5 is passed through to L1 and the software EPT12 walk
    supports 5 levels, but the hardware EPT02 root is always built via
    `eptp_without_ad(...)` which hardcodes walk-length from `EPT_PWLEVELS = 4`. An L1 that builds a
    5-level EPT12 with >48-bit L2 GPAs cannot be represented by the 4-level EPT02 → L2
    mistranslates/faults. Hardware-gated (only 5-level-EPT hosts with an L1 using >48-bit GPAs), so
    narrow blast radius, but a real capability lie. Fix: mask walk-5 out of `VMX_EPT_CAP_ALLOWED`,
    or build a 5-level EPT02 when EPT12 is 5-level.
    *2026-08-12 revalidation: STILL PRESENT — `VMX_EPT_CAP_ALLOWED` still includes bit 7 (walk-5) at vmx_nested_caps.c:140 while ept.c:62 `EPT_PWLEVELS = 4` and `eptp_without_ad()` (ept.c:215-218) still hardcode the 4-level walk.*
    *2026-08-12 fix (working tree): walk-5 (EPT_VPID_CAP bit 7) is masked from `VMX_EPT_CAP_ALLOWED`; capability validation now rejects any policy carrying it and a 5-level EPTP12 can no longer validate — fail-closed per the §8.6 rule. Model tests cover the masked derivation and rejection.*

44. **[P1] vmx_nested_caps.c:89 + vmx_nested_timer.c:95-120 (zero callers) +
    vmx_nested_vmcs_store.c:651-760 — "save VMX-preemption timer value" (exit control bit 22)
    advertised but never written back to VMCS12**
    Bit 22 is in `VMX_EXIT_IMPLEMENTED`; the load side works (timer armed into VMCS02, expiry
    reflects to L1), but the save side is dead code: `vmx_nested_timer_exit()` computes the residual
    yet has zero callers tree-wide, and the exit-state writeback path writes no
    `VMCS_PREEMPTION_TIMER_VALUE`. An L1 (e.g. KVM) that enables save-preemption-timer and reads the
    residual after an L2 exit gets a stale value → misbehaving TSC-deadline/preemption-timer
    emulation in L1. Fix: wire `vmx_nested_timer_exit()` into exit-state writeback, gated on VMCS12
    exit-control bit 22.
    *2026-08-12 revalidation: STILL PRESENT — `vmx_nested_timer_exit()` (vmx_nested_timer.c:96) still has zero callers tree-wide (only its own .c/.h reference it).*
    *2026-08-12 fix (working tree): WIRED, not masked — the transactional VM-exit planner now captures the live VMCS02 preemption-timer residual and writes VMCS_PREEMPTION_TIMER_VALUE into VMCS12 when exit-control bit 22 is set (0 on a timer-expired exit; never-entered runtimes skip the architectural no-op). Covered in `vmcs_region_vmexit_commit` and the portable-state consistency tests.*

**Honest feature gaps (correctly withheld from the capability MSRs — not lies, but limits nested
guests):** VMFUNC/EPTP-switching (P2 — L1s exposing VMFUNC to L2 can't); posted interrupts + APICv
+ TPR shadow (P2 — all L2 APIC/TPR accesses trap-and-reflect, functional but unaccelerated); PML,
EPT-violation #VE, sub-page write permission, XSAVES, ENCLS/ENCLV exiting, MBEC (P2 — MBEC partly
coded but gated off on a pmap-representation gap); no hardware VMCS shadowing (P3, all VMREAD/
VMWRITE trap-and-emulate — documented optimization deferral); Monitor Trap Flag withheld (P3, L1
can't single-step L2).

*Nested — verified COMPLETE: exit-reflection router handles all L2-reachable exit reasons 0-77
with a safe default-to-L0 (no panic) for unknown reasons; all nested instructions
(VMXON..INVVPID) implemented with SDM consistency/permission/VMfail checks (none stubbed);
checkpoint/migration saves+restores VMXON state, current-VMCS pointer, cached VMCS12, nested MSRs,
EPT/VPID ownership, and in-flight active-L2 (freeze/rebuild/thaw), capability-signature-bound so a
destination lacking VPID rejects VPID-bearing state. AMD nested SVM is ABSENT and correctly
advertised as absent (guest SVM CPUID bit not exposed; no capability lie) — feature-absent-by-
design (P2).*

---

## Completeness Round — summary

The completeness pass (device support, save/restore, nested) found **4 P1 GAPS** that the
correctness rounds could not surface, because they are *missing coverage*, not wrong logic in
existing code:

- **29 — NVMe-backed VMs cannot be checkpointed** (no `pe_snapshot`; save+restore both hard-fail
  ENOTSUP → whole checkpoint aborts). Also HDA/pci-com (P2). The single most impactful gap: NVMe is
  a common boot disk.
- **36 — the guest FPU/SSE/AVX/AVX-512 register file (XSAVE area) is never serialized** on
  snapshot (XCR0 mask is saved, register contents are not) → restored guests mid-FP/vector work get
  corrupted results/faults.
- **43 — 5-level nested EPT advertised to L1 but the hardware EPT02 root is hardcoded 4-level**
  (capability lie; bites 5-level-EPT hosts with L1 using >48-bit GPAs).
- **44 — nested "save VMX-preemption timer" advertised but its writeback function has zero
  callers** (dead code) → L1 reads a stale residual.

**What is strong / complete:** nested VMX exit-reflection, instructions, and checkpoint/migration
are complete; the nested capability MSRs otherwise follow an honest allowlist (unimplemented
features are withheld, not lied about); AMD nested is absent-by-design and correctly not
advertised; all 27 device models are fully wired; the vCPU register/MSR/timer save-restore is
rigorous apart from the FPU gap and the vatpit `now_bt` re-anchor (37). The virtio-1.4 admin-queue
"device parts" migration and the precopy live-migration engine are foundation-only/dormant (33-34)
— consistent with the roadmap, which is honest about its provisional areas.

**Recommended priority order for the whole VMM doc:** (1) NVMe snapshot [29] and FPU/XSAVE snapshot
[36] — both block/again-corrupt normal checkpoint use; (2) the two guest-triggerable memory-safety
issues xHCI ERST TOCTOU [15] and e1000 RX null-deref [16]; (3) nested capability lies [43,44] and
gdb OOB [18]; (4) AHCI snapshot-quiesce assert [24]; then the P2 device/nested feature gaps.
