/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The 5BSD Project
 */

/*
 * RISC-V kernel side of bhyve checkpoint/restore (BHYVE_SNAPSHOT only).
 *
 * VM_SNAPSHOT_REQ records:
 *   STRUCT_VM    GPRs, sepc/sstatus/hstatus, VS-level CSRs, FP state,
 *                pending IPI/timer/exception flags and the SBI timer deadline.
 *   STRUCT_APLIC APLIC domain configuration, sources and targets.
 *
 * Limits (fail closed): SSTC guests are refused because these records do
 * not carry vstimecmp; the VMM does not virtualize `time` (no
 * htimedelta), so a restore onto a host whose time is behind the captured
 * time is refused rather than letting guest time run backwards.  Tracing
 * state is never part of these records.
 */

#include "opt_bhyve_snapshot.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/sx.h>

#include <machine/cpufunc.h>
#include <machine/reg.h>
#include <machine/riscvreg.h>
#include <machine/vmm.h>
#include <machine/vmm_snapshot.h>

#include <dev/vmm/vmm_mem.h>
#include <dev/vmm/vmm_snapshot_envelope.h>
#include <dev/vmm/vmm_vm.h>

#include "riscv.h"
#include "vmm_aplic.h"
#include "vmm_snapshot_riscv.h"
#include "vmm_vtimer.h"

#ifndef BHYVE_SNAPSHOT
#error "vmm_snapshot_machdep.c requires options BHYVE_SNAPSHOT"
#endif

static MALLOC_DEFINE(M_VMM_SNAPSHOT, "vmm_snapshot", "vmm checkpoint staging");

_Static_assert(HSTATUS_GVA == VMM_SNAPSHOT_RISCV_HSTATUS_GVA &&
    HSTATUS_SPV == VMM_SNAPSHOT_RISCV_HSTATUS_SPV &&
    HSTATUS_SPVP == VMM_SNAPSHOT_RISCV_HSTATUS_SPVP &&
    HSTATUS_VTW == VMM_SNAPSHOT_RISCV_HSTATUS_VTW,
    "portable hstatus bits");
_Static_assert(SSTATUS_SIE == VMM_SNAPSHOT_RISCV_SSTATUS_SIE &&
    SSTATUS_SPIE == VMM_SNAPSHOT_RISCV_SSTATUS_SPIE &&
    SSTATUS_SPP == VMM_SNAPSHOT_RISCV_SSTATUS_SPP &&
    SSTATUS_FS_MASK == VMM_SNAPSHOT_RISCV_SSTATUS_FS_MASK &&
    SSTATUS_SUM == VMM_SNAPSHOT_RISCV_SSTATUS_SUM &&
    SSTATUS_MXR == VMM_SNAPSHOT_RISCV_SSTATUS_MXR,
    "portable sstatus bits");
_Static_assert(HVIP_VSSIP == VMM_SNAPSHOT_RISCV_HVIP_VSSIP &&
    HVIP_VSTIP == VMM_SNAPSHOT_RISCV_HVIP_VSTIP &&
    HVIP_VSEIP == VMM_SNAPSHOT_RISCV_HVIP_VSEIP, "portable hvip bits");
_Static_assert(sizeof(((struct fpreg *)0)->fp_x) ==
    sizeof(((struct vmm_snapshot_riscv_fp *)0)->f), "FP register file");

/*
 * RISC-V publishes no deferred event bits through the MI checkpoint
 * coordinator; any call indicates a broken coordinator invariant.
 */
void
vm_event_checkpoint_deferred_apply(void *arg, uint16_t vcpuid,
    uint64_t deferred_mask)
{

	panic("%s: unexpected deferred event %#jx for vCPU %u", __func__,
	    (uintmax_t)deferred_mask, vcpuid);
}

static uint64_t *
riscv_snapshot_reg(struct hypctx *hypctx, u_int wire)
{
	struct hypregs *g;
	struct hypcsr *c;

	g = &hypctx->guest_regs;
	c = &hypctx->guest_csrs;
	if (wire >= VMM_SNAPSHOT_RISCV_T0 && wire <= VMM_SNAPSHOT_RISCV_T6)
		return (&g->hyp_t[wire - VMM_SNAPSHOT_RISCV_T0]);
	if (wire >= VMM_SNAPSHOT_RISCV_S0 && wire <= VMM_SNAPSHOT_RISCV_S11)
		return (&g->hyp_s[wire - VMM_SNAPSHOT_RISCV_S0]);
	if (wire >= VMM_SNAPSHOT_RISCV_A0 && wire <= VMM_SNAPSHOT_RISCV_A7)
		return (&g->hyp_a[wire - VMM_SNAPSHOT_RISCV_A0]);
	switch (wire) {
	case VMM_SNAPSHOT_RISCV_RA:		return (&g->hyp_ra);
	case VMM_SNAPSHOT_RISCV_SP:		return (&g->hyp_sp);
	case VMM_SNAPSHOT_RISCV_GP:		return (&g->hyp_gp);
	case VMM_SNAPSHOT_RISCV_TP:		return (&g->hyp_tp);
	case VMM_SNAPSHOT_RISCV_SSTATUS:	return (&g->hyp_sstatus);
	case VMM_SNAPSHOT_RISCV_HSTATUS:	return (&g->hyp_hstatus);
	case VMM_SNAPSHOT_RISCV_HVIP:		return (&c->hvip);
	case VMM_SNAPSHOT_RISCV_VSSTATUS:	return (&c->vsstatus);
	case VMM_SNAPSHOT_RISCV_VSIE:		return (&c->vsie);
	case VMM_SNAPSHOT_RISCV_VSTVEC:		return (&c->vstvec);
	case VMM_SNAPSHOT_RISCV_VSSCRATCH:	return (&c->vsscratch);
	case VMM_SNAPSHOT_RISCV_VSEPC:		return (&c->vsepc);
	case VMM_SNAPSHOT_RISCV_VSCAUSE:	return (&c->vscause);
	case VMM_SNAPSHOT_RISCV_VSTVAL:		return (&c->vstval);
	case VMM_SNAPSHOT_RISCV_VSATP:		return (&c->vsatp);
	case VMM_SNAPSHOT_RISCV_SCOUNTEREN:	return (&c->scounteren);
	case VMM_SNAPSHOT_RISCV_SENVCFG:	return (&c->senvcfg);
	case VMM_SNAPSHOT_RISCV_GUEST_SCOUNTEREN:
		return (&hypctx->guest_scounteren);
	default:
		/* SEPC (vcpu->nextpc) and TIMER_DEADLINE are handled apart. */
		return (NULL);
	}
}

static int
riscv_snapshot_vcpus(struct vm *vm, uint32_t *instances, uint32_t *countp)
{
	struct vcpu *vcpu;
	uint32_t count;
	uint16_t maxcpus;

	maxcpus = vm_get_maxcpus(vm);
	count = 0;
	for (uint16_t i = 0; i < maxcpus; i++) {
		vcpu = vm_vcpu(vm, i);
		if (vcpu == NULL)
			continue;
		if (vcpu_get_state(vcpu, NULL) != VCPU_FROZEN)
			return (EBUSY);
		instances[count++] = i;
	}
	if (count == 0)
		return (EINVAL);
	*countp = count;
	return (0);
}

static int
riscv_snapshot_sstc(struct vcpu *vcpu, bool *sstc)
{
	int error, value;

	error = vm_get_capability(vcpu, VM_CAP_SSTC, &value);
	if (error != 0)
		return (error);
	*sstc = value != 0;
	return (0);
}

static int
riscv_snapshot_vm_save(struct vm *vm, struct vm_snapshot_meta *meta,
    struct vmm_snapshot_riscv_vcpu_stage *stage, uint32_t *instances)
{
	struct vmm_snapshot_riscv_transaction transaction;
	struct hypctx *hypctx;
	struct vcpu *vcpu;
	struct fpreg *fpu;
	uint8_t *wire;
	size_t length, written;
	uint64_t *regp;
	uint32_t count;
	bool sstc;
	int error;

	error = riscv_snapshot_vcpus(vm, instances, &count);
	if (error != 0)
		return (error);
	memset(&transaction, 0, sizeof(transaction));
	transaction.vm.max_vcpus = vm_get_maxcpus(vm);
	transaction.vm.vcpu_count = count;
	transaction.vcpu_count = count;
	for (uint32_t i = 0; i < count; i++) {
		vcpu = vm_vcpu(vm, instances[i]);
		hypctx = vcpu->cookie;
		error = riscv_snapshot_sstc(vcpu, &sstc);
		if (error != 0)
			return (error);
		/* These records do not carry vstimecmp. */
		if (sstc)
			return (EOPNOTSUPP);
		if (i == 0)
			transaction.riscv.timebase = hypctx->vtimer.freq;
		else if (hypctx->vtimer.freq != transaction.riscv.timebase)
			return (EOPNOTSUPP);
		stage[i].instance = instances[i];
		for (u_int r = 0; r < VMM_SNAPSHOT_RISCV_REG_COUNT; r++) {
			regp = riscv_snapshot_reg(hypctx, r);
			if (regp != NULL)
				stage[i].vcpu.regs[r] = *regp;
		}
		stage[i].vcpu.regs[VMM_SNAPSHOT_RISCV_SEPC] = vcpu->nextpc;
		if (hypctx->vtimer.armed) {
			stage[i].vcpu.flags |=
			    VMM_SNAPSHOT_RISCV_VCPU_F_TIMER_ARMED;
			stage[i].vcpu.regs[VMM_SNAPSHOT_RISCV_TIMER_DEADLINE] =
			    hypctx->vtimer.deadline;
		}
		if (hypctx->has_exception)
			stage[i].vcpu.flags |= VMM_SNAPSHOT_RISCV_VCPU_F_EXCEPTION;
		if (atomic_load_int(&hypctx->ipi_pending) != 0)
			stage[i].vcpu.flags |= VMM_SNAPSHOT_RISCV_VCPU_F_IPI;
		if ((atomic_load_int(&hypctx->interrupts_pending) &
		    HVIP_VSTIP) != 0)
			stage[i].vcpu.flags |=
			    VMM_SNAPSHOT_RISCV_VCPU_F_TIMER_PENDING;
		stage[i].common.flags = 0;
		stage[i].common.next_pc = vcpu->nextpc;
		fpu = vcpu->guestfpu;
		memcpy(stage[i].fp.f, fpu->fp_x, sizeof(stage[i].fp.f));
		stage[i].fp.fcsr = fpu->fp_fcsr;
	}
	transaction.riscv.capture_time = rdtime();
	error = vmm_snapshot_riscv_vm_size(count, &length);
	if (error != 0)
		return (error);
	if (length > meta->buffer.buf_rem)
		return (E2BIG);
	wire = malloc(length, M_VMM_SNAPSHOT, M_WAITOK | M_ZERO);
	error = vmm_snapshot_riscv_vm_encode(&transaction, stage, count, wire,
	    length, &written);
	if (error == 0)
		error = vm_snapshot_buf(wire, written, meta);
	explicit_bzero(wire, length);
	free(wire, M_VMM_SNAPSHOT);
	return (error);
}

static int
riscv_snapshot_vm_restore(struct vm *vm, struct vm_snapshot_meta *meta,
    struct vmm_snapshot_riscv_vcpu_stage *stage, uint32_t *instances)
{
	struct vmm_snapshot_riscv_transaction transaction;
	struct hypctx *hypctx;
	struct vcpu *vcpu;
	struct fpreg *fpu;
	uint8_t *wire;
	size_t bound, length;
	uint64_t *regp;
	uint32_t count, flags;
	uint16_t maxcpus;
	bool sstc;
	int error;

	maxcpus = vm_get_maxcpus(vm);
	error = riscv_snapshot_vcpus(vm, instances, &count);
	if (error != 0)
		return (error);
	error = vmm_snapshot_riscv_vm_size(maxcpus, &bound);
	if (error != 0)
		return (error);
	length = meta->buffer.buf_rem;
	if (length > bound || length < VMM_SNAPSHOT_ENVELOPE_HEADER_SIZE)
		return (EINVAL);
	wire = malloc(length, M_VMM_SNAPSHOT, M_WAITOK | M_ZERO);
	error = vm_snapshot_buf(wire, length, meta);
	if (error == 0)
		error = vmm_snapshot_riscv_vm_decode(wire, length, stage,
		    maxcpus, &transaction);
	explicit_bzero(wire, length);
	free(wire, M_VMM_SNAPSHOT);
	if (error != 0)
		return (error);

	/* Destination checks.  Nothing has been modified yet. */
	if (transaction.vm.max_vcpus != maxcpus ||
	    transaction.vcpu_count != count ||
	    (transaction.riscv.flags & VMM_SNAPSHOT_RISCV_VM_F_SSTC) != 0)
		return (EINVAL);
	/* No htimedelta: guest `time` is host time and must not go back. */
	if (rdtime() < transaction.riscv.capture_time)
		return (EOPNOTSUPP);
	for (uint32_t i = 0; i < count; i++) {
		if (stage[i].instance != instances[i])
			return (EINVAL);
		vcpu = vm_vcpu(vm, instances[i]);
		hypctx = vcpu->cookie;
		error = riscv_snapshot_sstc(vcpu, &sstc);
		if (error != 0)
			return (error);
		if (sstc)
			return (EOPNOTSUPP);
		if (hypctx->vtimer.freq != transaction.riscv.timebase)
			return (EINVAL);
	}

	/* Commit. */
	for (uint32_t i = 0; i < count; i++) {
		vcpu = vm_vcpu(vm, instances[i]);
		hypctx = vcpu->cookie;
		vtimer_snapshot_quiesce(hypctx);
		for (u_int r = 0; r < VMM_SNAPSHOT_RISCV_REG_COUNT; r++) {
			regp = riscv_snapshot_reg(hypctx, r);
			if (regp != NULL)
				*regp = stage[i].vcpu.regs[r];
		}
		vcpu->nextpc = stage[i].vcpu.regs[VMM_SNAPSHOT_RISCV_SEPC];
		hypctx->guest_regs.hyp_sepc = vcpu->nextpc;
		flags = stage[i].vcpu.flags;
		hypctx->vtimer.armed =
		    (flags & VMM_SNAPSHOT_RISCV_VCPU_F_TIMER_ARMED) != 0;
		hypctx->vtimer.deadline =
		    stage[i].vcpu.regs[VMM_SNAPSHOT_RISCV_TIMER_DEADLINE];
		hypctx->has_exception =
		    (flags & VMM_SNAPSHOT_RISCV_VCPU_F_EXCEPTION) != 0;
		atomic_store_int(&hypctx->ipi_pending,
		    (flags & VMM_SNAPSHOT_RISCV_VCPU_F_IPI) != 0 ? 1 : 0);
		atomic_store_int(&hypctx->interrupts_pending,
		    (flags & VMM_SNAPSHOT_RISCV_VCPU_F_TIMER_PENDING) != 0 ?
		    HVIP_VSTIP : 0);
		/*
		 * Pending remote fences were aimed at the source host's TLBs.
		 * Discard the queue and require a full fence before entry.
		 */
		mtx_lock_spin(&hypctx->fence_queue_mtx);
		hypctx->fence_queue_head = 0;
		hypctx->fence_queue_tail = 0;
		mtx_unlock_spin(&hypctx->fence_queue_mtx);
		atomic_set_32(&hypctx->fence_req, FENCE_REQ_I | FENCE_REQ_VMA);
		fpu = vcpu->guestfpu;
		memcpy(fpu->fp_x, stage[i].fp.f, sizeof(fpu->fp_x));
		fpu->fp_fcsr = stage[i].fp.fcsr;
	}
	return (0);
}

static int
riscv_snapshot_vm(struct vm *vm, struct vm_snapshot_meta *meta)
{
	struct vmm_snapshot_riscv_vcpu_stage *stage;
	uint32_t *instances;
	uint16_t maxcpus;
	int error;

	maxcpus = vm_get_maxcpus(vm);
	if (maxcpus == 0 || maxcpus > VMM_SNAPSHOT_RISCV_MAX_VCPUS)
		return (EINVAL);
	stage = mallocarray(maxcpus, sizeof(*stage), M_VMM_SNAPSHOT,
	    M_WAITOK | M_ZERO);
	instances = mallocarray(maxcpus, sizeof(*instances), M_VMM_SNAPSHOT,
	    M_WAITOK | M_ZERO);
	if (meta->op == VM_SNAPSHOT_SAVE)
		error = riscv_snapshot_vm_save(vm, meta, stage, instances);
	else
		error = riscv_snapshot_vm_restore(vm, meta, stage, instances);
	explicit_bzero(stage, (size_t)maxcpus * sizeof(*stage));
	free(stage, M_VMM_SNAPSHOT);
	free(instances, M_VMM_SNAPSHOT);
	return (error);
}

static int
riscv_snapshot_aplic(struct vm *vm, struct vm_snapshot_meta *meta)
{
	struct vmm_snapshot_riscv_aplic *state;
	struct hyp *hyp;
	uint8_t *wire;
	size_t bound, length, written;
	uint32_t *instances, count;
	uint16_t maxcpus;
	int error;

	hyp = vm_get_cookie(vm);
	maxcpus = vm_get_maxcpus(vm);
	if (maxcpus == 0 || maxcpus > VMM_SNAPSHOT_RISCV_MAX_VCPUS)
		return (EINVAL);
	instances = mallocarray(maxcpus, sizeof(*instances), M_VMM_SNAPSHOT,
	    M_WAITOK | M_ZERO);
	error = riscv_snapshot_vcpus(vm, instances, &count);
	free(instances, M_VMM_SNAPSHOT);
	if (error != 0)
		return (error);
	state = malloc(sizeof(*state), M_VMM_SNAPSHOT, M_WAITOK | M_ZERO);
	(void)vmm_snapshot_riscv_aplic_size(&bound);
	wire = malloc(bound, M_VMM_SNAPSHOT, M_WAITOK | M_ZERO);
	if (meta->op == VM_SNAPSHOT_SAVE) {
		state->vm.max_vcpus = maxcpus;
		state->vm.vcpu_count = count;
		error = aplic_snapshot_capture(hyp, state);
		if (error == 0)
			error = vmm_snapshot_riscv_aplic_encode(state, wire,
			    bound, &written);
		if (error == 0 && written > meta->buffer.buf_rem)
			error = E2BIG;
		if (error == 0)
			error = vm_snapshot_buf(wire, written, meta);
	} else {
		length = meta->buffer.buf_rem;
		if (length != bound)
			error = EINVAL;
		if (error == 0)
			error = vm_snapshot_buf(wire, length, meta);
		if (error == 0)
			error = vmm_snapshot_riscv_aplic_decode(wire, length,
			    state);
		if (error == 0 && (state->vm.max_vcpus != maxcpus ||
		    state->vm.vcpu_count != count))
			error = EINVAL;
		if (error == 0)
			error = aplic_snapshot_restore(hyp, state);
	}
	explicit_bzero(wire, bound);
	free(wire, M_VMM_SNAPSHOT);
	explicit_bzero(state, sizeof(*state));
	free(state, M_VMM_SNAPSHOT);
	return (error);
}

int
vm_snapshot_req(struct vm *vm, struct vm_snapshot_meta *meta)
{
	int error __diagused;

	if (vm == NULL || meta == NULL || !vm_snapshot_op_is_kernel(meta->op))
		return (EINVAL);
	switch (meta->dev_req) {
	case STRUCT_VM:
	case STRUCT_APLIC:
		break;
	default:
		return (EINVAL);
	}
	vm_xlock_memsegs(vm);
	error = vm_mem_dirty_log_invalidate(vm);
	vm_unlock_memsegs(vm);
	KASSERT(error == 0 || error == EOVERFLOW,
	    ("%s: invalid dirty-log owner state %d", __func__, error));

	switch (meta->dev_req) {
	case STRUCT_VM:
		return (riscv_snapshot_vm(vm, meta));
	default:
		return (riscv_snapshot_aplic(vm, meta));
	}
}

/*
 * Consumes the one-shot restore-time credential (checked by the caller) and
 * re-arms each restored SBI timer.  A deadline already in the past asserts
 * the guest timer interrupt immediately, exactly like a late set_timer.
 */
int
vm_restore_time(struct vm *vm)
{
	struct hypctx *hypctx;
	struct vcpu *vcpu;
	uint16_t maxcpus;

	maxcpus = vm_get_maxcpus(vm);
	for (uint16_t i = 0; i < maxcpus; i++) {
		vcpu = vm_vcpu(vm, i);
		if (vcpu == NULL)
			continue;
		hypctx = vcpu->cookie;
		if (hypctx->vtimer.armed)
			(void)vtimer_set_timer(hypctx, hypctx->vtimer.deadline);
	}
	return (0);
}
