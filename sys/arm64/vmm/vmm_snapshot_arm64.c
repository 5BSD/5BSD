/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The 5BSD Project
 */

/*
 * Portable ARM64 checkpoint codec.  See vmm_snapshot_arm64.h.  Every record
 * is one canonical VMS2 envelope whose sections are all marked critical.
 * Decoders never trust a section count or length beyond the envelope reader,
 * reject unknown critical sections, and validate every field before
 * reporting success.  On failure the caller's stage array may hold partial
 * output and must be discarded.
 */

#include <sys/types.h>
#include <sys/endian.h>
#include <sys/errno.h>
#ifdef _KERNEL
#include <sys/systm.h>
#else
#include <string.h>
#endif

#include <dev/vmm/vmm_snapshot_envelope.h>
#include <dev/vmm/vmm_snapshot_state.h>
#include "vmm_snapshot_arm64.h"

#define	ARM64_SECTION_FLAGS	VMM_SNAPSHOT_SECTION_F_CRITICAL
#define	ARM64_VMPIDR_RES1	UINT64_C(0x0000000080000000)

_Static_assert(VMM_SNAPSHOT_ARM64_VGIC_DIST_SIZE >=
    VMM_SNAPSHOT_ARM64_VGIC_CPU_MAX_SIZE, "staging bound");
_Static_assert(VMM_SNAPSHOT_ARM64_VGIC_DIST_SIZE >=
    VMM_SNAPSHOT_ARM64_VCPU_SIZE, "staging bound");

static bool
arm64_size_add(size_t *total, size_t value)
{

	if (value > SIZE_MAX - *total)
		return (false);
	*total += value;
	return (true);
}

int
vmm_snapshot_arm64_vcpu_validate(const struct vmm_snapshot_arm64_vcpu *vcpu)
{
	uint64_t mode, pstate;

	if (vcpu == NULL)
		return (EINVAL);
	if ((vcpu->flags & ~VMM_SNAPSHOT_ARM64_VCPU_F_VALID) != 0)
		return (EINVAL);
	pstate = vcpu->regs[VMM_SNAPSHOT_ARM64_PSTATE];
	mode = pstate & VMM_SNAPSHOT_ARM64_PSR_M_MASK;
	/* The VMM runs AArch64 EL1/EL0 guests only; never restore EL2/AArch32. */
	if ((pstate >> 32) != 0 || (pstate & VMM_SNAPSHOT_ARM64_PSR_M_32) != 0 ||
	    (mode != VMM_SNAPSHOT_ARM64_PSR_M_EL0t &&
	    mode != VMM_SNAPSHOT_ARM64_PSR_M_EL1t &&
	    mode != VMM_SNAPSHOT_ARM64_PSR_M_EL1h))
		return (EINVAL);
	if ((vcpu->regs[VMM_SNAPSHOT_ARM64_VMPIDR_EL2] & ARM64_VMPIDR_RES1) == 0)
		return (EINVAL);
	return (0);
}

static int
arm64_timer_validate(const struct vmm_snapshot_arm64_timer *timer)
{

	if ((timer->virt_ctl & ~VMM_SNAPSHOT_ARM64_CNT_CTL_VALID) != 0 ||
	    (timer->phys_ctl & ~VMM_SNAPSHOT_ARM64_CNT_CTL_VALID) != 0)
		return (EINVAL);
	return (0);
}

static int
arm64_fp_validate(const struct vmm_snapshot_arm64_fp *fp)
{

	if ((fp->fpsr & ~VMM_SNAPSHOT_ARM64_FPSR_VALID) != 0)
		return (EINVAL);
	return (0);
}

static int
arm64_stage_validate(const struct vmm_snapshot_arm64_vcpu_stage *stage)
{
	int error;

	/* ARM64 vCPU power state is a userspace PSCI record, not STARTUP_WAIT. */
	if (stage->common.flags != 0 ||
	    stage->common.next_pc != stage->vcpu.regs[VMM_SNAPSHOT_ARM64_PC])
		return (EINVAL);
	error = vmm_snapshot_arm64_vcpu_validate(&stage->vcpu);
	if (error == 0)
		error = arm64_fp_validate(&stage->fp);
	if (error == 0)
		error = arm64_timer_validate(&stage->timer);
	return (error);
}

static int
arm64_instances_validate(const struct vmm_snapshot_vm_common *vm,
    uint32_t count, const uint32_t *instance, size_t stride)
{
	const uint8_t *cursor;
	uint32_t previous, value;

	if (vm->max_vcpus == 0 ||
	    vm->max_vcpus > VMM_SNAPSHOT_ARM64_MAX_VCPUS ||
	    vm->vcpu_count != count || count == 0 || count > vm->max_vcpus)
		return (EINVAL);
	cursor = (const uint8_t *)instance;
	previous = 0;
	for (uint32_t i = 0; i < count; i++) {
		memcpy(&value, cursor + (size_t)i * stride, sizeof(value));
		if (value >= vm->max_vcpus || (i != 0 && value <= previous))
			return (EINVAL);
		previous = value;
	}
	return (0);
}

int
vmm_snapshot_arm64_vm_size(uint32_t vcpus, size_t *length)
{
	size_t per_vcpu, total;

	if (length == NULL || vcpus == 0 ||
	    vcpus > VMM_SNAPSHOT_ARM64_MAX_VCPUS)
		return (EINVAL);
	per_vcpu = 4 * VMM_SNAPSHOT_SECTION_HEADER_SIZE +
	    VMM_SNAPSHOT_VCPU_COMMON_SIZE + VMM_SNAPSHOT_ARM64_VCPU_SIZE +
	    VMM_SNAPSHOT_ARM64_FP_SIZE + VMM_SNAPSHOT_ARM64_TIMER_SIZE;
	total = VMM_SNAPSHOT_ENVELOPE_HEADER_SIZE +
	    2 * VMM_SNAPSHOT_SECTION_HEADER_SIZE +
	    VMM_SNAPSHOT_VM_COMMON_SIZE + VMM_SNAPSHOT_ARM64_VM_SIZE;
	if (!arm64_size_add(&total, per_vcpu * vcpus) || total > UINT32_MAX)
		return (EOVERFLOW);
	*length = total;
	return (0);
}

static void
arm64_encode_vm(const struct vmm_snapshot_arm64_vm *vm, uint8_t *wire)
{

	memset(wire, 0, VMM_SNAPSHOT_ARM64_VM_SIZE);
	le16enc(wire, VMM_SNAPSHOT_ARM64_STATE_VERSION);
	le16enc(wire + 2, VMM_SNAPSHOT_ARM64_VM_SIZE);
	le64enc(wire + 8, vm->cntfrq);
	le64enc(wire + 16, vm->guest_count);
}

static int
arm64_decode_vm(const struct vmm_snapshot_section *section,
    struct vmm_snapshot_arm64_vm *vm)
{
	const uint8_t *wire;

	wire = section->payload;
	if (section->payload_length != VMM_SNAPSHOT_ARM64_VM_SIZE ||
	    le16dec(wire) != VMM_SNAPSHOT_ARM64_STATE_VERSION ||
	    le16dec(wire + 2) != VMM_SNAPSHOT_ARM64_VM_SIZE ||
	    le32dec(wire + 4) != 0)
		return (EINVAL);
	vm->cntfrq = le64dec(wire + 8);
	vm->guest_count = le64dec(wire + 16);
	if (vm->cntfrq == 0)
		return (EINVAL);
	return (0);
}

static void
arm64_encode_vcpu(const struct vmm_snapshot_arm64_vcpu *vcpu, uint8_t *wire)
{

	memset(wire, 0, VMM_SNAPSHOT_ARM64_VCPU_HEADER_SIZE);
	le16enc(wire, VMM_SNAPSHOT_ARM64_STATE_VERSION);
	le16enc(wire + 2, VMM_SNAPSHOT_ARM64_VCPU_HEADER_SIZE);
	le32enc(wire + 4, vcpu->flags);
	le32enc(wire + 8, VMM_SNAPSHOT_ARM64_REG_COUNT);
	for (size_t i = 0; i < VMM_SNAPSHOT_ARM64_REG_COUNT; i++)
		le64enc(wire + VMM_SNAPSHOT_ARM64_VCPU_HEADER_SIZE + 8 * i,
		    vcpu->regs[i]);
}

static int
arm64_decode_vcpu(const struct vmm_snapshot_section *section,
    struct vmm_snapshot_arm64_vcpu *vcpu)
{
	const uint8_t *wire;

	wire = section->payload;
	if (section->payload_length != VMM_SNAPSHOT_ARM64_VCPU_SIZE ||
	    le16dec(wire) != VMM_SNAPSHOT_ARM64_STATE_VERSION ||
	    le16dec(wire + 2) != VMM_SNAPSHOT_ARM64_VCPU_HEADER_SIZE ||
	    le32dec(wire + 8) != VMM_SNAPSHOT_ARM64_REG_COUNT ||
	    le32dec(wire + 12) != 0)
		return (EINVAL);
	vcpu->flags = le32dec(wire + 4);
	for (size_t i = 0; i < VMM_SNAPSHOT_ARM64_REG_COUNT; i++)
		vcpu->regs[i] = le64dec(wire +
		    VMM_SNAPSHOT_ARM64_VCPU_HEADER_SIZE + 8 * i);
	return (vmm_snapshot_arm64_vcpu_validate(vcpu));
}

static void
arm64_encode_fp(const struct vmm_snapshot_arm64_fp *fp, uint8_t *wire)
{

	memset(wire, 0, 16);
	le16enc(wire, VMM_SNAPSHOT_ARM64_STATE_VERSION);
	le16enc(wire + 2, 16);
	le32enc(wire + 4, fp->fpcr);
	le32enc(wire + 8, fp->fpsr);
	memcpy(wire + 16, fp->vregs, sizeof(fp->vregs));
}

static int
arm64_decode_fp(const struct vmm_snapshot_section *section,
    struct vmm_snapshot_arm64_fp *fp)
{
	const uint8_t *wire;

	wire = section->payload;
	if (section->payload_length != VMM_SNAPSHOT_ARM64_FP_SIZE ||
	    le16dec(wire) != VMM_SNAPSHOT_ARM64_STATE_VERSION ||
	    le16dec(wire + 2) != 16 || le32dec(wire + 12) != 0)
		return (EINVAL);
	fp->fpcr = le32dec(wire + 4);
	fp->fpsr = le32dec(wire + 8);
	memcpy(fp->vregs, wire + 16, sizeof(fp->vregs));
	return (arm64_fp_validate(fp));
}

static void
arm64_encode_timer(const struct vmm_snapshot_arm64_timer *timer,
    uint8_t *wire)
{

	memset(wire, 0, VMM_SNAPSHOT_ARM64_TIMER_SIZE);
	le16enc(wire, VMM_SNAPSHOT_ARM64_STATE_VERSION);
	le16enc(wire + 2, VMM_SNAPSHOT_ARM64_TIMER_SIZE);
	le32enc(wire + 4, timer->cntkctl);
	le64enc(wire + 8, timer->virt_ctl);
	le64enc(wire + 16, timer->virt_cval);
	le64enc(wire + 24, timer->phys_ctl);
	le64enc(wire + 32, timer->phys_cval);
}

static int
arm64_decode_timer(const struct vmm_snapshot_section *section,
    struct vmm_snapshot_arm64_timer *timer)
{
	const uint8_t *wire;

	wire = section->payload;
	if (section->payload_length != VMM_SNAPSHOT_ARM64_TIMER_SIZE ||
	    le16dec(wire) != VMM_SNAPSHOT_ARM64_STATE_VERSION ||
	    le16dec(wire + 2) != VMM_SNAPSHOT_ARM64_TIMER_SIZE)
		return (EINVAL);
	timer->cntkctl = le32dec(wire + 4);
	timer->virt_ctl = le64dec(wire + 8);
	timer->virt_cval = le64dec(wire + 16);
	timer->phys_ctl = le64dec(wire + 24);
	timer->phys_cval = le64dec(wire + 32);
	return (arm64_timer_validate(timer));
}

int
vmm_snapshot_arm64_vm_encode(
    const struct vmm_snapshot_arm64_transaction *transaction,
    const struct vmm_snapshot_arm64_vcpu_stage *stage, size_t count,
    void *buffer, size_t capacity, size_t *written)
{
	static const uint16_t vcpu_types[] = {
		VMM_SNAPSHOT_SECTION_ARM64_VCPU,
		VMM_SNAPSHOT_SECTION_ARM64_FP,
		VMM_SNAPSHOT_SECTION_ARM64_TIMER,
	};
	struct vmm_snapshot_envelope_builder builder;
	uint8_t staging[VMM_SNAPSHOT_ARM64_VCPU_SIZE];
	size_t length, required, used;
	int error;

	if (transaction == NULL || stage == NULL || buffer == NULL ||
	    written == NULL || count != transaction->vcpu_count)
		return (EINVAL);
	error = arm64_instances_validate(&transaction->vm, (uint32_t)count,
	    &stage[0].instance, sizeof(*stage));
	if (error != 0)
		return (error);
	if (transaction->arm64.cntfrq == 0)
		return (EINVAL);
	for (size_t i = 0; i < count; i++) {
		error = arm64_stage_validate(&stage[i]);
		if (error != 0)
			return (error);
	}
	error = vmm_snapshot_arm64_vm_size((uint32_t)count, &required);
	if (error != 0)
		return (error);
	if (capacity < required)
		return (E2BIG);
	error = vmm_snapshot_envelope_builder_init(&builder, buffer, capacity);
	if (error != 0)
		return (error);
	error = vmm_snapshot_vm_common_encode(&transaction->vm, staging,
	    sizeof(staging), &used);
	if (error == 0)
		error = vmm_snapshot_envelope_add(&builder,
		    VMM_SNAPSHOT_SECTION_VM_COMMON, ARM64_SECTION_FLAGS, 0,
		    staging, used);
	for (size_t i = 0; error == 0 && i < count; i++) {
		error = vmm_snapshot_vcpu_common_encode(&stage[i].common,
		    staging, sizeof(staging), &used);
		if (error == 0)
			error = vmm_snapshot_envelope_add(&builder,
			    VMM_SNAPSHOT_SECTION_VCPU_COMMON,
			    ARM64_SECTION_FLAGS, stage[i].instance, staging,
			    used);
	}
	if (error == 0) {
		arm64_encode_vm(&transaction->arm64, staging);
		error = vmm_snapshot_envelope_add(&builder,
		    VMM_SNAPSHOT_SECTION_ARM64_VM, ARM64_SECTION_FLAGS, 0,
		    staging, VMM_SNAPSHOT_ARM64_VM_SIZE);
	}
	for (size_t t = 0; error == 0 && t < sizeof(vcpu_types) / sizeof(vcpu_types[0]); t++) {
		for (size_t i = 0; error == 0 && i < count; i++) {
			switch (vcpu_types[t]) {
			case VMM_SNAPSHOT_SECTION_ARM64_VCPU:
				arm64_encode_vcpu(&stage[i].vcpu, staging);
				length = VMM_SNAPSHOT_ARM64_VCPU_SIZE;
				break;
			case VMM_SNAPSHOT_SECTION_ARM64_FP:
				arm64_encode_fp(&stage[i].fp, staging);
				length = VMM_SNAPSHOT_ARM64_FP_SIZE;
				break;
			default:
				arm64_encode_timer(&stage[i].timer, staging);
				length = VMM_SNAPSHOT_ARM64_TIMER_SIZE;
				break;
			}
			error = vmm_snapshot_envelope_add(&builder,
			    vcpu_types[t], ARM64_SECTION_FLAGS,
			    stage[i].instance, staging, length);
		}
	}
	if (error == 0)
		error = vmm_snapshot_envelope_finalize(&builder, &length);
	if (error == 0 && length != required)
		error = EPROTO;
	if (error == 0)
		*written = length;
	explicit_bzero(staging, sizeof(staging));
	return (error);
}

int
vmm_snapshot_arm64_vm_decode(const void *buffer, size_t length,
    struct vmm_snapshot_arm64_vcpu_stage *stage, size_t capacity,
    struct vmm_snapshot_arm64_transaction *transaction)
{
	struct vmm_snapshot_arm64_transaction candidate;
	struct vmm_snapshot_envelope_reader reader;
	struct vmm_snapshot_section section;
	size_t common_seen, vcpu_seen, fp_seen, timer_seen, index;
	bool have_vm, have_arm64;
	int error;

	if (buffer == NULL || stage == NULL || transaction == NULL ||
	    capacity == 0)
		return (EINVAL);
	error = vmm_snapshot_envelope_reader_init(&reader, buffer, length);
	if (error != 0)
		return (error);
	memset(&candidate, 0, sizeof(candidate));
	common_seen = vcpu_seen = fp_seen = timer_seen = 0;
	have_vm = have_arm64 = false;
	for (;;) {
		error = vmm_snapshot_envelope_next(&reader, &section);
		if (error == ENOENT)
			break;
		if (error != 0)
			return (error);
		switch (section.type) {
		case VMM_SNAPSHOT_SECTION_VM_COMMON:
		case VMM_SNAPSHOT_SECTION_VCPU_COMMON:
		case VMM_SNAPSHOT_SECTION_ARM64_VM:
		case VMM_SNAPSHOT_SECTION_ARM64_VCPU:
		case VMM_SNAPSHOT_SECTION_ARM64_FP:
		case VMM_SNAPSHOT_SECTION_ARM64_TIMER:
			if (section.flags != ARM64_SECTION_FLAGS)
				return (EINVAL);
			break;
		default:
			error = vmm_snapshot_section_skip_unknown(&section);
			if (error != 0)
				return (error);
			continue;
		}
		if (section.type == VMM_SNAPSHOT_SECTION_VM_COMMON) {
			if (have_vm || section.instance != 0)
				return (EINVAL);
			error = vmm_snapshot_vm_common_decode(section.payload,
			    section.payload_length, &candidate.vm);
			if (error != 0)
				return (error);
			if (candidate.vm.vcpu_count == 0 ||
			    candidate.vm.vcpu_count > capacity ||
			    candidate.vm.max_vcpus >
			    VMM_SNAPSHOT_ARM64_MAX_VCPUS)
				return (EINVAL);
			have_vm = true;
			continue;
		}
		/* The canonical type order places VM_COMMON first. */
		if (!have_vm)
			return (EINVAL);
		switch (section.type) {
		case VMM_SNAPSHOT_SECTION_VCPU_COMMON:
			index = common_seen++;
			if (index >= candidate.vm.vcpu_count ||
			    section.instance >= candidate.vm.max_vcpus)
				return (EINVAL);
			memset(&stage[index], 0, sizeof(stage[index]));
			stage[index].instance = section.instance;
			error = vmm_snapshot_vcpu_common_decode(section.payload,
			    section.payload_length, &stage[index].common);
			break;
		case VMM_SNAPSHOT_SECTION_ARM64_VM:
			if (have_arm64 || section.instance != 0)
				return (EINVAL);
			have_arm64 = true;
			error = arm64_decode_vm(&section, &candidate.arm64);
			break;
		case VMM_SNAPSHOT_SECTION_ARM64_VCPU:
			index = vcpu_seen++;
			if (index >= common_seen ||
			    stage[index].instance != section.instance)
				return (EINVAL);
			error = arm64_decode_vcpu(&section, &stage[index].vcpu);
			break;
		case VMM_SNAPSHOT_SECTION_ARM64_FP:
			index = fp_seen++;
			if (index >= common_seen ||
			    stage[index].instance != section.instance)
				return (EINVAL);
			error = arm64_decode_fp(&section, &stage[index].fp);
			break;
		default:
			index = timer_seen++;
			if (index >= common_seen ||
			    stage[index].instance != section.instance)
				return (EINVAL);
			error = arm64_decode_timer(&section,
			    &stage[index].timer);
			break;
		}
		if (error != 0)
			return (error);
	}
	if (!have_vm || !have_arm64 ||
	    common_seen != candidate.vm.vcpu_count ||
	    vcpu_seen != common_seen || fp_seen != common_seen ||
	    timer_seen != common_seen)
		return (EINVAL);
	candidate.vcpu_count = candidate.vm.vcpu_count;
	error = arm64_instances_validate(&candidate.vm, candidate.vcpu_count,
	    &stage[0].instance, sizeof(*stage));
	for (size_t i = 0; error == 0 && i < candidate.vcpu_count; i++)
		error = arm64_stage_validate(&stage[i]);
	if (error != 0)
		return (error);
	*transaction = candidate;
	return (0);
}

/* vGIC */

static int
arm64_vgic_irq_validate(const struct vmm_snapshot_arm64_vgic_irq *irq,
    uint32_t irqid, uint32_t max_vcpus, int32_t owner)
{

	if ((irq->flags & ~VMM_SNAPSHOT_ARM64_IRQ_F_VALID) != 0 ||
	    (irq->mpidr & ~VMM_SNAPSHOT_ARM64_GICD_AFF) != 0)
		return (EINVAL);
	if (irqid < VMM_SNAPSHOT_ARM64_VGIC_SGI_COUNT) {
		/* SGIs are edge-triggered and immutable. */
		if (irq->config != VMM_SNAPSHOT_ARM64_IRQ_CONFIG_EDGE)
			return (EINVAL);
	} else if (irqid < VMM_SNAPSHOT_ARM64_VGIC_PRIVATE_COUNT) {
		/* The VMM models PPIs as level-triggered, read-only config. */
		if (irq->config != VMM_SNAPSHOT_ARM64_IRQ_CONFIG_LEVEL)
			return (EINVAL);
	} else if (irq->config != VMM_SNAPSHOT_ARM64_IRQ_CONFIG_LEVEL &&
	    irq->config != VMM_SNAPSHOT_ARM64_IRQ_CONFIG_EDGE)
		return (EINVAL);
	if (owner >= 0) {
		if (irq->target_vcpu != owner)
			return (EINVAL);
	} else if (irq->target_vcpu < -1 ||
	    (irq->target_vcpu >= 0 && (uint32_t)irq->target_vcpu >= max_vcpus))
		return (EINVAL);
	return (0);
}

int
vmm_snapshot_arm64_vgic_validate(
    const struct vmm_snapshot_arm64_vgic_transaction *transaction,
    const struct vmm_snapshot_arm64_vgic_stage *stage, size_t count)
{
	const struct vmm_snapshot_arm64_vgic_dist *dist;
	const struct vmm_snapshot_arm64_vgic_cpu *cpu;
	uint8_t spi_listed[(VMM_SNAPSHOT_ARM64_VGIC_SPI_COUNT + 7) / 8];
	uint32_t private_listed, id;
	int error;

	if (transaction == NULL || stage == NULL ||
	    count != transaction->vcpu_count)
		return (EINVAL);
	error = arm64_instances_validate(&transaction->vm, (uint32_t)count,
	    &stage[0].instance, sizeof(*stage));
	if (error != 0)
		return (error);
	dist = &transaction->dist;
	if (dist->lr_num == 0 || dist->lr_num > VMM_SNAPSHOT_ARM64_VGIC_LR_MAX ||
	    dist->apr_num == 0 ||
	    dist->apr_num > VMM_SNAPSHOT_ARM64_VGIC_APR_MAX ||
	    dist->min_prio > 0xff ||
	    (dist->gicd_ctlr & ~(VMM_SNAPSHOT_ARM64_GICD_CTLR_G1A |
	    VMM_SNAPSHOT_ARM64_GICD_CTLR_ARE_NS)) != 0 ||
	    dist->dist_size == 0 ||
	    dist->dist_start > UINT64_MAX - dist->dist_size ||
	    dist->redist_start > UINT64_MAX - dist->redist_size)
		return (EINVAL);
	for (uint32_t i = 0; i < VMM_SNAPSHOT_ARM64_VGIC_SPI_COUNT; i++) {
		error = arm64_vgic_irq_validate(&dist->spis[i],
		    i + VMM_SNAPSHOT_ARM64_VGIC_PRIVATE_COUNT,
		    transaction->vm.max_vcpus, -1);
		if (error != 0)
			return (error);
	}
	memset(spi_listed, 0, sizeof(spi_listed));
	for (size_t c = 0; c < count; c++) {
		cpu = &stage[c].cpu;
		if ((cpu->ich_hcr & ~VMM_SNAPSHOT_ARM64_ICH_HCR_EN) != 0 ||
		    (cpu->ich_vmcr & ~VMM_SNAPSHOT_ARM64_ICH_VMCR_VALID) != 0 ||
		    cpu->aplist_count > VMM_SNAPSHOT_ARM64_VGIC_NIRQS)
			return (EINVAL);
		for (uint32_t j = dist->apr_num;
		    j < VMM_SNAPSHOT_ARM64_VGIC_APR_MAX; j++) {
			if (cpu->ap0r[j] != 0 || cpu->ap1r[j] != 0)
				return (EINVAL);
		}
		for (uint32_t j = 0; j < VMM_SNAPSHOT_ARM64_VGIC_PRIVATE_COUNT;
		    j++) {
			error = arm64_vgic_irq_validate(&cpu->private_irqs[j],
			    j, transaction->vm.max_vcpus,
			    (int32_t)stage[c].instance);
			if (error != 0)
				return (error);
		}
		private_listed = 0;
		for (uint32_t k = 0; k < cpu->aplist_count; k++) {
			id = cpu->aplist[k];
			if (id >= VMM_SNAPSHOT_ARM64_VGIC_NIRQS)
				return (EINVAL);
			if (id < VMM_SNAPSHOT_ARM64_VGIC_PRIVATE_COUNT) {
				if ((private_listed & (UINT32_C(1) << id)) != 0 ||
				    (cpu->private_irqs[id].flags &
				    VMM_SNAPSHOT_ARM64_IRQ_F_APLIST) == 0)
					return (EINVAL);
				private_listed |= UINT32_C(1) << id;
				continue;
			}
			id -= VMM_SNAPSHOT_ARM64_VGIC_PRIVATE_COUNT;
			if ((spi_listed[id / 8] & (1U << (id % 8))) != 0 ||
			    (dist->spis[id].flags &
			    VMM_SNAPSHOT_ARM64_IRQ_F_APLIST) == 0)
				return (EINVAL);
			spi_listed[id / 8] |= (uint8_t)(1U << (id % 8));
		}
		for (uint32_t j = 0; j < VMM_SNAPSHOT_ARM64_VGIC_PRIVATE_COUNT;
		    j++) {
			if ((cpu->private_irqs[j].flags &
			    VMM_SNAPSHOT_ARM64_IRQ_F_APLIST) != 0 &&
			    (private_listed & (UINT32_C(1) << j)) == 0)
				return (EINVAL);
		}
	}
	for (uint32_t i = 0; i < VMM_SNAPSHOT_ARM64_VGIC_SPI_COUNT; i++) {
		if ((dist->spis[i].flags & VMM_SNAPSHOT_ARM64_IRQ_F_APLIST) != 0 &&
		    (spi_listed[i / 8] & (1U << (i % 8))) == 0)
			return (EINVAL);
	}
	return (0);
}

static void
arm64_encode_irq(const struct vmm_snapshot_arm64_vgic_irq *irq, uint8_t *wire)
{

	le64enc(wire, irq->mpidr);
	le32enc(wire + 8, (uint32_t)irq->target_vcpu);
	wire[12] = irq->flags;
	wire[13] = irq->priority;
	wire[14] = irq->config;
	wire[15] = 0;
}

static int
arm64_decode_irq(const uint8_t *wire, struct vmm_snapshot_arm64_vgic_irq *irq)
{

	if (wire[15] != 0)
		return (EINVAL);
	irq->mpidr = le64dec(wire);
	irq->target_vcpu = (int32_t)le32dec(wire + 8);
	irq->flags = wire[12];
	irq->priority = wire[13];
	irq->config = wire[14];
	return (0);
}

static size_t
arm64_vgic_cpu_size(uint32_t aplist_count)
{

	return (VMM_SNAPSHOT_ARM64_VGIC_CPU_FIXED_SIZE +
	    (((size_t)aplist_count * 2 + 7) & ~(size_t)7));
}

int
vmm_snapshot_arm64_vgic_size(uint32_t vcpus, size_t *length)
{
	size_t total;

	if (length == NULL || vcpus == 0 ||
	    vcpus > VMM_SNAPSHOT_ARM64_MAX_VCPUS)
		return (EINVAL);
	/*
	 * An upper bound: each CPU may carry a full active/pending list, plus
	 * one distributor-sized scratch region used by the encoder.
	 */
	total = VMM_SNAPSHOT_ENVELOPE_HEADER_SIZE +
	    2 * VMM_SNAPSHOT_SECTION_HEADER_SIZE + VMM_SNAPSHOT_VM_COMMON_SIZE +
	    2 * VMM_SNAPSHOT_ARM64_VGIC_DIST_SIZE;
	if (!arm64_size_add(&total, (VMM_SNAPSHOT_SECTION_HEADER_SIZE +
	    VMM_SNAPSHOT_ARM64_VGIC_CPU_MAX_SIZE) * (size_t)vcpus) ||
	    total > UINT32_MAX)
		return (EOVERFLOW);
	*length = total;
	return (0);
}

int
vmm_snapshot_arm64_vgic_encode(
    const struct vmm_snapshot_arm64_vgic_transaction *transaction,
    const struct vmm_snapshot_arm64_vgic_stage *stage, size_t count,
    void *buffer, size_t capacity, size_t *written)
{
	struct vmm_snapshot_envelope_builder builder;
	const struct vmm_snapshot_arm64_vgic_dist *dist;
	const struct vmm_snapshot_arm64_vgic_cpu *cpu;
	uint8_t *staging;
	size_t length, size;
	int error;

	if (transaction == NULL || stage == NULL || buffer == NULL ||
	    written == NULL)
		return (EINVAL);
	error = vmm_snapshot_arm64_vgic_validate(transaction, stage, count);
	if (error != 0)
		return (error);
	error = vmm_snapshot_envelope_builder_init(&builder, buffer, capacity);
	if (error != 0)
		return (error);
	/*
	 * The distributor payload does not fit on a kernel stack.  Each large
	 * payload is therefore built in the unused tail of the output buffer
	 * and copied forward by vmm_snapshot_envelope_add(), which accepts
	 * only non-overlapping sources.  vmm_snapshot_arm64_vgic_size()
	 * includes that scratch slack; the encoder reports the exact length.
	 */
	{
		uint8_t common[VMM_SNAPSHOT_VM_COMMON_SIZE];

		error = vmm_snapshot_vm_common_encode(&transaction->vm, common,
		    sizeof(common), &size);
		if (error == 0)
			error = vmm_snapshot_envelope_add(&builder,
			    VMM_SNAPSHOT_SECTION_VM_COMMON,
			    ARM64_SECTION_FLAGS, 0, common, size);
		if (error != 0)
			return (error);
	}
	dist = &transaction->dist;
	size = VMM_SNAPSHOT_ARM64_VGIC_DIST_SIZE;
	if (builder.length > capacity ||
	    capacity - builder.length < 2 * size +
	    VMM_SNAPSHOT_SECTION_HEADER_SIZE)
		return (E2BIG);
	staging = (uint8_t *)buffer + capacity - size;
	memset(staging, 0, VMM_SNAPSHOT_ARM64_VGIC_DIST_HEADER_SIZE);
	le16enc(staging, VMM_SNAPSHOT_ARM64_STATE_VERSION);
	le16enc(staging + 2, VMM_SNAPSHOT_ARM64_VGIC_DIST_HEADER_SIZE);
	le32enc(staging + 4, dist->gicd_ctlr);
	le32enc(staging + 8, VMM_SNAPSHOT_ARM64_VGIC_SPI_COUNT);
	le32enc(staging + 12, dist->min_prio);
	le16enc(staging + 16, dist->lr_num);
	le16enc(staging + 18, dist->apr_num);
	le64enc(staging + 24, dist->dist_start);
	le64enc(staging + 32, dist->dist_size);
	le64enc(staging + 40, dist->redist_start);
	le64enc(staging + 48, dist->redist_size);
	for (uint32_t i = 0; i < VMM_SNAPSHOT_ARM64_VGIC_SPI_COUNT; i++)
		arm64_encode_irq(&dist->spis[i], staging +
		    VMM_SNAPSHOT_ARM64_VGIC_DIST_HEADER_SIZE +
		    VMM_SNAPSHOT_ARM64_VGIC_IRQ_SIZE * i);
	error = vmm_snapshot_envelope_add(&builder,
	    VMM_SNAPSHOT_SECTION_ARM64_VGIC_DIST, ARM64_SECTION_FLAGS, 0,
	    staging, size);
	for (size_t c = 0; error == 0 && c < count; c++) {
		cpu = &stage[c].cpu;
		size = arm64_vgic_cpu_size(cpu->aplist_count);
		if (builder.length > capacity ||
		    capacity - builder.length < 2 * size +
		    VMM_SNAPSHOT_SECTION_HEADER_SIZE) {
			error = E2BIG;
			break;
		}
		staging = (uint8_t *)buffer + capacity - size;
		memset(staging, 0, size);
		le16enc(staging, VMM_SNAPSHOT_ARM64_STATE_VERSION);
		le16enc(staging + 2, VMM_SNAPSHOT_ARM64_VGIC_CPU_HEADER_SIZE);
		le32enc(staging + 4, cpu->aplist_count);
		le64enc(staging + 8, cpu->ich_hcr);
		le64enc(staging + 16, cpu->ich_vmcr);
		for (uint32_t j = 0; j < VMM_SNAPSHOT_ARM64_VGIC_APR_MAX; j++) {
			le32enc(staging + 24 + 4 * j, cpu->ap0r[j]);
			le32enc(staging + 40 + 4 * j, cpu->ap1r[j]);
		}
		for (uint32_t j = 0; j < VMM_SNAPSHOT_ARM64_VGIC_PRIVATE_COUNT;
		    j++)
			arm64_encode_irq(&cpu->private_irqs[j], staging +
			    VMM_SNAPSHOT_ARM64_VGIC_CPU_HEADER_SIZE +
			    VMM_SNAPSHOT_ARM64_VGIC_IRQ_SIZE * j);
		for (uint32_t k = 0; k < cpu->aplist_count; k++)
			le16enc(staging + VMM_SNAPSHOT_ARM64_VGIC_CPU_FIXED_SIZE +
			    2 * k, cpu->aplist[k]);
		error = vmm_snapshot_envelope_add(&builder,
		    VMM_SNAPSHOT_SECTION_ARM64_VGIC_CPU, ARM64_SECTION_FLAGS,
		    stage[c].instance, staging, size);
	}
	if (error == 0)
		error = vmm_snapshot_envelope_finalize(&builder, &length);
	if (error == 0) {
		/* Scrub the scratch tail beyond the published record. */
		if (capacity > length)
			memset((uint8_t *)buffer + length, 0, capacity - length);
		*written = length;
	}
	return (error);
}

int
vmm_snapshot_arm64_vgic_decode(const void *buffer, size_t length,
    struct vmm_snapshot_arm64_vgic_stage *stage, size_t capacity,
    struct vmm_snapshot_arm64_vgic_transaction *transaction)
{
	struct vmm_snapshot_arm64_vgic_transaction *candidate;
	struct vmm_snapshot_arm64_vgic_cpu *cpu;
	struct vmm_snapshot_envelope_reader reader;
	struct vmm_snapshot_section section;
	const uint8_t *wire;
	size_t cpus_seen, index;
	uint32_t count;
	bool have_vm, have_dist;
	int error;

	if (buffer == NULL || stage == NULL || transaction == NULL ||
	    capacity == 0)
		return (EINVAL);
	error = vmm_snapshot_envelope_reader_init(&reader, buffer, length);
	if (error != 0)
		return (error);
	/*
	 * The distributor image is large; decode it directly into the caller's
	 * transaction object and report failure without a success guarantee
	 * for its contents, like the stage array.
	 */
	candidate = transaction;
	memset(candidate, 0, sizeof(*candidate));
	cpus_seen = 0;
	have_vm = have_dist = false;
	for (;;) {
		error = vmm_snapshot_envelope_next(&reader, &section);
		if (error == ENOENT)
			break;
		if (error != 0)
			goto fail;
		switch (section.type) {
		case VMM_SNAPSHOT_SECTION_VM_COMMON:
		case VMM_SNAPSHOT_SECTION_ARM64_VGIC_DIST:
		case VMM_SNAPSHOT_SECTION_ARM64_VGIC_CPU:
			if (section.flags != ARM64_SECTION_FLAGS) {
				error = EINVAL;
				goto fail;
			}
			break;
		default:
			error = vmm_snapshot_section_skip_unknown(&section);
			if (error != 0)
				goto fail;
			continue;
		}
		wire = section.payload;
		error = EINVAL;
		switch (section.type) {
		case VMM_SNAPSHOT_SECTION_VM_COMMON:
			if (have_vm || section.instance != 0)
				goto fail;
			error = vmm_snapshot_vm_common_decode(wire,
			    section.payload_length, &candidate->vm);
			if (error != 0)
				goto fail;
			if (candidate->vm.vcpu_count == 0 ||
			    candidate->vm.vcpu_count > capacity) {
				error = EINVAL;
				goto fail;
			}
			have_vm = true;
			break;
		case VMM_SNAPSHOT_SECTION_ARM64_VGIC_DIST:
			if (!have_vm || have_dist || section.instance != 0 ||
			    section.payload_length !=
			    VMM_SNAPSHOT_ARM64_VGIC_DIST_SIZE ||
			    le16dec(wire) != VMM_SNAPSHOT_ARM64_STATE_VERSION ||
			    le16dec(wire + 2) !=
			    VMM_SNAPSHOT_ARM64_VGIC_DIST_HEADER_SIZE ||
			    le32dec(wire + 8) !=
			    VMM_SNAPSHOT_ARM64_VGIC_SPI_COUNT ||
			    le32dec(wire + 20) != 0)
				goto fail;
			candidate->dist.gicd_ctlr = le32dec(wire + 4);
			candidate->dist.min_prio = le32dec(wire + 12);
			candidate->dist.lr_num = le16dec(wire + 16);
			candidate->dist.apr_num = le16dec(wire + 18);
			candidate->dist.dist_start = le64dec(wire + 24);
			candidate->dist.dist_size = le64dec(wire + 32);
			candidate->dist.redist_start = le64dec(wire + 40);
			candidate->dist.redist_size = le64dec(wire + 48);
			for (uint32_t i = 0;
			    i < VMM_SNAPSHOT_ARM64_VGIC_SPI_COUNT; i++) {
				if (arm64_decode_irq(wire +
				    VMM_SNAPSHOT_ARM64_VGIC_DIST_HEADER_SIZE +
				    VMM_SNAPSHOT_ARM64_VGIC_IRQ_SIZE * i,
				    &candidate->dist.spis[i]) != 0)
					goto fail;
			}
			have_dist = true;
			break;
		default:
			if (!have_vm || !have_dist)
				goto fail;
			index = cpus_seen++;
			if (index >= candidate->vm.vcpu_count ||
			    section.instance >= candidate->vm.max_vcpus ||
			    section.payload_length <
			    VMM_SNAPSHOT_ARM64_VGIC_CPU_FIXED_SIZE ||
			    le16dec(wire) != VMM_SNAPSHOT_ARM64_STATE_VERSION ||
			    le16dec(wire + 2) !=
			    VMM_SNAPSHOT_ARM64_VGIC_CPU_HEADER_SIZE)
				goto fail;
			count = le32dec(wire + 4);
			if (count > VMM_SNAPSHOT_ARM64_VGIC_NIRQS ||
			    section.payload_length != arm64_vgic_cpu_size(count))
				goto fail;
			memset(&stage[index], 0, sizeof(stage[index]));
			stage[index].instance = section.instance;
			cpu = &stage[index].cpu;
			cpu->aplist_count = count;
			cpu->ich_hcr = le64dec(wire + 8);
			cpu->ich_vmcr = le64dec(wire + 16);
			for (uint32_t j = 0; j < VMM_SNAPSHOT_ARM64_VGIC_APR_MAX;
			    j++) {
				cpu->ap0r[j] = le32dec(wire + 24 + 4 * j);
				cpu->ap1r[j] = le32dec(wire + 40 + 4 * j);
			}
			for (uint32_t j = 0;
			    j < VMM_SNAPSHOT_ARM64_VGIC_PRIVATE_COUNT; j++) {
				if (arm64_decode_irq(wire +
				    VMM_SNAPSHOT_ARM64_VGIC_CPU_HEADER_SIZE +
				    VMM_SNAPSHOT_ARM64_VGIC_IRQ_SIZE * j,
				    &cpu->private_irqs[j]) != 0)
					goto fail;
			}
			for (uint32_t k = 0; k < count; k++)
				cpu->aplist[k] = le16dec(wire +
				    VMM_SNAPSHOT_ARM64_VGIC_CPU_FIXED_SIZE +
				    2 * k);
			/* Alignment padding must be zero. */
			for (size_t p = VMM_SNAPSHOT_ARM64_VGIC_CPU_FIXED_SIZE +
			    2 * (size_t)count; p < section.payload_length; p++) {
				if (wire[p] != 0)
					goto fail;
			}
			break;
		}
		error = 0;
	}
	if (!have_vm || !have_dist || cpus_seen != candidate->vm.vcpu_count) {
		error = EINVAL;
		goto fail;
	}
	candidate->vcpu_count = candidate->vm.vcpu_count;
	error = vmm_snapshot_arm64_vgic_validate(candidate, stage,
	    candidate->vcpu_count);
	if (error == 0)
		return (0);
fail:
	memset(candidate, 0, sizeof(*candidate));
	return (error);
}
