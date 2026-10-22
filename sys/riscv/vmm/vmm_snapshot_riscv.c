/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The 5BSD Project
 */

/*
 * Portable RISC-V checkpoint codec.  See vmm_snapshot_riscv.h.  Records are
 * canonical VMS2 envelopes with critical sections; decoders validate every
 * field and reject unknown critical sections.
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
#include "vmm_snapshot_riscv.h"

#define	RISCV_SECTION_FLAGS	VMM_SNAPSHOT_SECTION_F_CRITICAL

#define	RISCV_HSTATUS_ALLOWED	(VMM_SNAPSHOT_RISCV_HSTATUS_GVA | \
	VMM_SNAPSHOT_RISCV_HSTATUS_SPV | VMM_SNAPSHOT_RISCV_HSTATUS_SPVP | \
	VMM_SNAPSHOT_RISCV_HSTATUS_VTW | VMM_SNAPSHOT_RISCV_HSTATUS_VSXL_MASK)
#define	RISCV_HSTATUS_REQUIRED	(VMM_SNAPSHOT_RISCV_HSTATUS_SPV | \
	VMM_SNAPSHOT_RISCV_HSTATUS_VTW)
#define	RISCV_SSTATUS_ALLOWED	(VMM_SNAPSHOT_RISCV_SSTATUS_SIE | \
	VMM_SNAPSHOT_RISCV_SSTATUS_SPIE | VMM_SNAPSHOT_RISCV_SSTATUS_SPP | \
	VMM_SNAPSHOT_RISCV_SSTATUS_VS_MASK | VMM_SNAPSHOT_RISCV_SSTATUS_FS_MASK | \
	VMM_SNAPSHOT_RISCV_SSTATUS_XS_MASK | VMM_SNAPSHOT_RISCV_SSTATUS_SUM | \
	VMM_SNAPSHOT_RISCV_SSTATUS_MXR | VMM_SNAPSHOT_RISCV_SSTATUS_UXL_MASK | \
	VMM_SNAPSHOT_RISCV_SSTATUS_SD)
#define	RISCV_HVIP_ALLOWED	(VMM_SNAPSHOT_RISCV_HVIP_VSSIP | \
	VMM_SNAPSHOT_RISCV_HVIP_VSTIP | VMM_SNAPSHOT_RISCV_HVIP_VSEIP)

static bool
riscv_size_add(size_t *total, size_t value)
{

	if (value > SIZE_MAX - *total)
		return (false);
	*total += value;
	return (true);
}

int
vmm_snapshot_riscv_vcpu_validate(const struct vmm_snapshot_riscv_vcpu *vcpu)
{
	uint64_t hstatus, sstatus, xl;

	if (vcpu == NULL ||
	    (vcpu->flags & ~VMM_SNAPSHOT_RISCV_VCPU_F_VALID) != 0)
		return (EINVAL);
	/*
	 * hstatus and the HS sstatus are hypervisor-owned controls.  Accept only
	 * bits the world switch itself produces; in particular never restore
	 * HU, VTSR, VTVM, VGEIN or VSBE from an image.
	 */
	hstatus = vcpu->regs[VMM_SNAPSHOT_RISCV_HSTATUS];
	xl = (hstatus & VMM_SNAPSHOT_RISCV_HSTATUS_VSXL_MASK) >>
	    VMM_SNAPSHOT_RISCV_HSTATUS_VSXL_SHIFT;
	if ((hstatus & ~RISCV_HSTATUS_ALLOWED) != 0 ||
	    (hstatus & RISCV_HSTATUS_REQUIRED) != RISCV_HSTATUS_REQUIRED ||
	    (xl != 0 && xl != 2))
		return (EINVAL);
	sstatus = vcpu->regs[VMM_SNAPSHOT_RISCV_SSTATUS];
	xl = (sstatus & VMM_SNAPSHOT_RISCV_SSTATUS_UXL_MASK) >>
	    VMM_SNAPSHOT_RISCV_SSTATUS_UXL_SHIFT;
	if ((sstatus & ~RISCV_SSTATUS_ALLOWED) != 0 || (xl != 0 && xl != 2))
		return (EINVAL);
	if ((vcpu->regs[VMM_SNAPSHOT_RISCV_HVIP] & ~RISCV_HVIP_ALLOWED) != 0 ||
	    (vcpu->regs[VMM_SNAPSHOT_RISCV_SCOUNTEREN] >> 32) != 0 ||
	    (vcpu->regs[VMM_SNAPSHOT_RISCV_GUEST_SCOUNTEREN] >> 32) != 0)
		return (EINVAL);
	if ((vcpu->flags & VMM_SNAPSHOT_RISCV_VCPU_F_TIMER_ARMED) == 0 &&
	    vcpu->regs[VMM_SNAPSHOT_RISCV_TIMER_DEADLINE] != 0)
		return (EINVAL);
	return (0);
}

static int
riscv_fp_validate(const struct vmm_snapshot_riscv_fp *fp)
{

	return ((fp->fcsr & ~VMM_SNAPSHOT_RISCV_FCSR_VALID) != 0 ? EINVAL : 0);
}

static int
riscv_stage_validate(const struct vmm_snapshot_riscv_vcpu_stage *stage)
{
	int error;

	/* RISC-V hart power state is a userspace HSM record. */
	if (stage->common.flags != 0 ||
	    stage->common.next_pc != stage->vcpu.regs[VMM_SNAPSHOT_RISCV_SEPC])
		return (EINVAL);
	error = vmm_snapshot_riscv_vcpu_validate(&stage->vcpu);
	if (error == 0)
		error = riscv_fp_validate(&stage->fp);
	return (error);
}

static int
riscv_instances_validate(const struct vmm_snapshot_vm_common *vm,
    const struct vmm_snapshot_riscv_vcpu_stage *stage, uint32_t count)
{

	if (vm->max_vcpus == 0 || vm->max_vcpus > VMM_SNAPSHOT_RISCV_MAX_VCPUS ||
	    vm->vcpu_count != count || count == 0 || count > vm->max_vcpus)
		return (EINVAL);
	for (uint32_t i = 0; i < count; i++) {
		if (stage[i].instance >= vm->max_vcpus ||
		    (i != 0 && stage[i].instance <= stage[i - 1].instance))
			return (EINVAL);
	}
	return (0);
}

int
vmm_snapshot_riscv_vm_size(uint32_t vcpus, size_t *length)
{
	size_t total;

	if (length == NULL || vcpus == 0 || vcpus > VMM_SNAPSHOT_RISCV_MAX_VCPUS)
		return (EINVAL);
	total = VMM_SNAPSHOT_ENVELOPE_HEADER_SIZE +
	    2 * VMM_SNAPSHOT_SECTION_HEADER_SIZE + VMM_SNAPSHOT_VM_COMMON_SIZE +
	    VMM_SNAPSHOT_RISCV_VM_SIZE;
	if (!riscv_size_add(&total, (size_t)vcpus *
	    (3 * VMM_SNAPSHOT_SECTION_HEADER_SIZE +
	    VMM_SNAPSHOT_VCPU_COMMON_SIZE + VMM_SNAPSHOT_RISCV_VCPU_SIZE +
	    VMM_SNAPSHOT_RISCV_FP_SIZE)) || total > UINT32_MAX)
		return (EOVERFLOW);
	*length = total;
	return (0);
}

int
vmm_snapshot_riscv_vm_encode(
    const struct vmm_snapshot_riscv_transaction *transaction,
    const struct vmm_snapshot_riscv_vcpu_stage *stage, size_t count,
    void *buffer, size_t capacity, size_t *written)
{
	struct vmm_snapshot_envelope_builder builder;
	uint8_t staging[VMM_SNAPSHOT_RISCV_FP_SIZE];
	size_t length, required, used;
	int error;

	_Static_assert(VMM_SNAPSHOT_RISCV_FP_SIZE >= VMM_SNAPSHOT_RISCV_VCPU_SIZE,
	    "staging bound");
	if (transaction == NULL || stage == NULL || buffer == NULL ||
	    written == NULL || count != transaction->vcpu_count ||
	    count > UINT32_MAX)
		return (EINVAL);
	error = riscv_instances_validate(&transaction->vm, stage,
	    (uint32_t)count);
	if (error != 0)
		return (error);
	if (transaction->riscv.timebase == 0 ||
	    (transaction->riscv.flags & ~VMM_SNAPSHOT_RISCV_VM_F_VALID) != 0)
		return (EINVAL);
	for (size_t i = 0; i < count; i++) {
		error = riscv_stage_validate(&stage[i]);
		if (error != 0)
			return (error);
	}
	error = vmm_snapshot_riscv_vm_size((uint32_t)count, &required);
	if (error != 0)
		return (error);
	if (capacity < required)
		return (E2BIG);
	error = vmm_snapshot_envelope_builder_init(&builder, buffer, capacity);
	if (error == 0)
		error = vmm_snapshot_vm_common_encode(&transaction->vm, staging,
		    sizeof(staging), &used);
	if (error == 0)
		error = vmm_snapshot_envelope_add(&builder,
		    VMM_SNAPSHOT_SECTION_VM_COMMON, RISCV_SECTION_FLAGS, 0,
		    staging, used);
	for (size_t i = 0; error == 0 && i < count; i++) {
		error = vmm_snapshot_vcpu_common_encode(&stage[i].common,
		    staging, sizeof(staging), &used);
		if (error == 0)
			error = vmm_snapshot_envelope_add(&builder,
			    VMM_SNAPSHOT_SECTION_VCPU_COMMON,
			    RISCV_SECTION_FLAGS, stage[i].instance, staging,
			    used);
	}
	if (error == 0) {
		memset(staging, 0, VMM_SNAPSHOT_RISCV_VM_SIZE);
		le16enc(staging, VMM_SNAPSHOT_RISCV_STATE_VERSION);
		le16enc(staging + 2, VMM_SNAPSHOT_RISCV_VM_SIZE);
		le32enc(staging + 4, transaction->riscv.flags);
		le32enc(staging + 8, transaction->riscv.timebase);
		le64enc(staging + 16, transaction->riscv.capture_time);
		error = vmm_snapshot_envelope_add(&builder,
		    VMM_SNAPSHOT_SECTION_RISCV_VM, RISCV_SECTION_FLAGS, 0,
		    staging, VMM_SNAPSHOT_RISCV_VM_SIZE);
	}
	for (size_t i = 0; error == 0 && i < count; i++) {
		memset(staging, 0, VMM_SNAPSHOT_RISCV_VCPU_HEADER_SIZE);
		le16enc(staging, VMM_SNAPSHOT_RISCV_STATE_VERSION);
		le16enc(staging + 2, VMM_SNAPSHOT_RISCV_VCPU_HEADER_SIZE);
		le32enc(staging + 4, stage[i].vcpu.flags);
		le32enc(staging + 8, VMM_SNAPSHOT_RISCV_REG_COUNT);
		for (size_t r = 0; r < VMM_SNAPSHOT_RISCV_REG_COUNT; r++)
			le64enc(staging + VMM_SNAPSHOT_RISCV_VCPU_HEADER_SIZE +
			    8 * r, stage[i].vcpu.regs[r]);
		error = vmm_snapshot_envelope_add(&builder,
		    VMM_SNAPSHOT_SECTION_RISCV_VCPU, RISCV_SECTION_FLAGS,
		    stage[i].instance, staging, VMM_SNAPSHOT_RISCV_VCPU_SIZE);
	}
	for (size_t i = 0; error == 0 && i < count; i++) {
		memset(staging, 0, 16);
		le16enc(staging, VMM_SNAPSHOT_RISCV_STATE_VERSION);
		le16enc(staging + 2, 16);
		le64enc(staging + 8, stage[i].fp.fcsr);
		for (size_t r = 0; r < 32; r++) {
			le64enc(staging + 16 + 16 * r, stage[i].fp.f[r][0]);
			le64enc(staging + 24 + 16 * r, stage[i].fp.f[r][1]);
		}
		error = vmm_snapshot_envelope_add(&builder,
		    VMM_SNAPSHOT_SECTION_RISCV_FP, RISCV_SECTION_FLAGS,
		    stage[i].instance, staging, VMM_SNAPSHOT_RISCV_FP_SIZE);
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
vmm_snapshot_riscv_vm_decode(const void *buffer, size_t length,
    struct vmm_snapshot_riscv_vcpu_stage *stage, size_t capacity,
    struct vmm_snapshot_riscv_transaction *transaction)
{
	struct vmm_snapshot_riscv_transaction candidate;
	struct vmm_snapshot_envelope_reader reader;
	struct vmm_snapshot_section section;
	const uint8_t *wire;
	size_t common_seen, vcpu_seen, fp_seen, index;
	bool have_vm, have_riscv;
	int error;

	if (buffer == NULL || stage == NULL || transaction == NULL ||
	    capacity == 0)
		return (EINVAL);
	error = vmm_snapshot_envelope_reader_init(&reader, buffer, length);
	if (error != 0)
		return (error);
	memset(&candidate, 0, sizeof(candidate));
	common_seen = vcpu_seen = fp_seen = 0;
	have_vm = have_riscv = false;
	for (;;) {
		error = vmm_snapshot_envelope_next(&reader, &section);
		if (error == ENOENT)
			break;
		if (error != 0)
			return (error);
		switch (section.type) {
		case VMM_SNAPSHOT_SECTION_VM_COMMON:
		case VMM_SNAPSHOT_SECTION_VCPU_COMMON:
		case VMM_SNAPSHOT_SECTION_RISCV_VM:
		case VMM_SNAPSHOT_SECTION_RISCV_VCPU:
		case VMM_SNAPSHOT_SECTION_RISCV_FP:
			if (section.flags != RISCV_SECTION_FLAGS)
				return (EINVAL);
			break;
		default:
			error = vmm_snapshot_section_skip_unknown(&section);
			if (error != 0)
				return (error);
			continue;
		}
		wire = section.payload;
		if (section.type == VMM_SNAPSHOT_SECTION_VM_COMMON) {
			if (have_vm || section.instance != 0)
				return (EINVAL);
			error = vmm_snapshot_vm_common_decode(wire,
			    section.payload_length, &candidate.vm);
			if (error != 0)
				return (error);
			if (candidate.vm.vcpu_count == 0 ||
			    candidate.vm.vcpu_count > capacity ||
			    candidate.vm.max_vcpus > VMM_SNAPSHOT_RISCV_MAX_VCPUS)
				return (EINVAL);
			have_vm = true;
			continue;
		}
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
			error = vmm_snapshot_vcpu_common_decode(wire,
			    section.payload_length, &stage[index].common);
			break;
		case VMM_SNAPSHOT_SECTION_RISCV_VM:
			if (have_riscv || section.instance != 0 ||
			    section.payload_length != VMM_SNAPSHOT_RISCV_VM_SIZE ||
			    le16dec(wire) != VMM_SNAPSHOT_RISCV_STATE_VERSION ||
			    le16dec(wire + 2) != VMM_SNAPSHOT_RISCV_VM_SIZE ||
			    le32dec(wire + 12) != 0)
				return (EINVAL);
			have_riscv = true;
			candidate.riscv.flags = le32dec(wire + 4);
			candidate.riscv.timebase = le32dec(wire + 8);
			candidate.riscv.capture_time = le64dec(wire + 16);
			if (candidate.riscv.timebase == 0 ||
			    (candidate.riscv.flags &
			    ~VMM_SNAPSHOT_RISCV_VM_F_VALID) != 0)
				return (EINVAL);
			break;
		case VMM_SNAPSHOT_SECTION_RISCV_VCPU:
			index = vcpu_seen++;
			if (index >= common_seen ||
			    stage[index].instance != section.instance ||
			    section.payload_length !=
			    VMM_SNAPSHOT_RISCV_VCPU_SIZE ||
			    le16dec(wire) != VMM_SNAPSHOT_RISCV_STATE_VERSION ||
			    le16dec(wire + 2) !=
			    VMM_SNAPSHOT_RISCV_VCPU_HEADER_SIZE ||
			    le32dec(wire + 8) != VMM_SNAPSHOT_RISCV_REG_COUNT ||
			    le32dec(wire + 12) != 0)
				return (EINVAL);
			stage[index].vcpu.flags = le32dec(wire + 4);
			for (size_t r = 0; r < VMM_SNAPSHOT_RISCV_REG_COUNT; r++)
				stage[index].vcpu.regs[r] = le64dec(wire +
				    VMM_SNAPSHOT_RISCV_VCPU_HEADER_SIZE + 8 * r);
			error = vmm_snapshot_riscv_vcpu_validate(
			    &stage[index].vcpu);
			break;
		default:
			index = fp_seen++;
			if (index >= common_seen ||
			    stage[index].instance != section.instance ||
			    section.payload_length != VMM_SNAPSHOT_RISCV_FP_SIZE ||
			    le16dec(wire) != VMM_SNAPSHOT_RISCV_STATE_VERSION ||
			    le16dec(wire + 2) != 16 || le32dec(wire + 4) != 0)
				return (EINVAL);
			stage[index].fp.fcsr = le64dec(wire + 8);
			for (size_t r = 0; r < 32; r++) {
				stage[index].fp.f[r][0] = le64dec(wire + 16 +
				    16 * r);
				stage[index].fp.f[r][1] = le64dec(wire + 24 +
				    16 * r);
			}
			error = riscv_fp_validate(&stage[index].fp);
			break;
		}
		if (error != 0)
			return (error);
	}
	if (!have_vm || !have_riscv || common_seen != candidate.vm.vcpu_count ||
	    vcpu_seen != common_seen || fp_seen != common_seen)
		return (EINVAL);
	candidate.vcpu_count = candidate.vm.vcpu_count;
	error = riscv_instances_validate(&candidate.vm, stage,
	    candidate.vcpu_count);
	for (size_t i = 0; error == 0 && i < candidate.vcpu_count; i++)
		error = riscv_stage_validate(&stage[i]);
	if (error != 0)
		return (error);
	*transaction = candidate;
	return (0);
}

/* APLIC */

int
vmm_snapshot_riscv_aplic_validate(const struct vmm_snapshot_riscv_aplic *aplic)
{
	const struct vmm_snapshot_riscv_aplic_source *source;
	uint32_t mode;

	if (aplic == NULL || aplic->vm.max_vcpus == 0 ||
	    aplic->vm.max_vcpus > VMM_SNAPSHOT_RISCV_MAX_VCPUS ||
	    aplic->vm.vcpu_count > aplic->vm.max_vcpus ||
	    aplic->nirqs != VMM_SNAPSHOT_RISCV_APLIC_NIRQS ||
	    aplic->mem_size == 0 ||
	    aplic->mem_start > UINT64_MAX - aplic->mem_size ||
	    (aplic->domaincfg & ~VMM_SNAPSHOT_RISCV_APLIC_DOMAINCFG_IE) != 0)
		return (EINVAL);
	source = &aplic->sources[0];
	if (source->sourcecfg != 0 || source->state != 0 || source->target != 0)
		return (EINVAL);
	for (uint32_t i = 1; i < VMM_SNAPSHOT_RISCV_APLIC_SLOTS; i++) {
		source = &aplic->sources[i];
		if ((source->state & ~VMM_SNAPSHOT_RISCV_APLIC_STATE_VALID) != 0)
			return (EINVAL);
		if ((source->sourcecfg & VMM_SNAPSHOT_RISCV_APLIC_SOURCECFG_D) !=
		    0) {
			if ((source->sourcecfg &
			    ~(VMM_SNAPSHOT_RISCV_APLIC_SOURCECFG_D |
			    VMM_SNAPSHOT_RISCV_APLIC_SOURCECFG_CHILD)) != 0)
				return (EINVAL);
			continue;
		}
		mode = source->sourcecfg;
		/* 2 and 3 are reserved source modes. */
		if ((mode & ~VMM_SNAPSHOT_RISCV_APLIC_SOURCECFG_SM) != 0 ||
		    mode == 2 || mode == 3)
			return (EINVAL);
	}
	return (0);
}

int
vmm_snapshot_riscv_aplic_size(size_t *length)
{

	if (length == NULL)
		return (EINVAL);
	*length = VMM_SNAPSHOT_ENVELOPE_HEADER_SIZE +
	    2 * VMM_SNAPSHOT_SECTION_HEADER_SIZE + VMM_SNAPSHOT_VM_COMMON_SIZE +
	    VMM_SNAPSHOT_RISCV_APLIC_PAYLOAD_SIZE;
	return (0);
}

int
vmm_snapshot_riscv_aplic_encode(const struct vmm_snapshot_riscv_aplic *aplic,
    void *buffer, size_t capacity, size_t *written)
{
	struct vmm_snapshot_envelope_builder builder;
	uint8_t staging[VMM_SNAPSHOT_RISCV_APLIC_PAYLOAD_SIZE];
	size_t length, required, used;
	int error;

	if (aplic == NULL || buffer == NULL || written == NULL)
		return (EINVAL);
	error = vmm_snapshot_riscv_aplic_validate(aplic);
	if (error != 0)
		return (error);
	(void)vmm_snapshot_riscv_aplic_size(&required);
	if (capacity < required)
		return (E2BIG);
	error = vmm_snapshot_envelope_builder_init(&builder, buffer, capacity);
	if (error == 0)
		error = vmm_snapshot_vm_common_encode(&aplic->vm, staging,
		    sizeof(staging), &used);
	if (error == 0)
		error = vmm_snapshot_envelope_add(&builder,
		    VMM_SNAPSHOT_SECTION_VM_COMMON, RISCV_SECTION_FLAGS, 0,
		    staging, used);
	if (error == 0) {
		memset(staging, 0, sizeof(staging));
		le16enc(staging, VMM_SNAPSHOT_RISCV_STATE_VERSION);
		le16enc(staging + 2, VMM_SNAPSHOT_RISCV_APLIC_HEADER_SIZE);
		le32enc(staging + 4, aplic->nirqs);
		le32enc(staging + 8, aplic->domaincfg);
		le64enc(staging + 16, aplic->mem_start);
		le64enc(staging + 24, aplic->mem_size);
		for (uint32_t i = 0; i < VMM_SNAPSHOT_RISCV_APLIC_SLOTS; i++) {
			uint8_t *entry;

			entry = staging + VMM_SNAPSHOT_RISCV_APLIC_HEADER_SIZE +
			    VMM_SNAPSHOT_RISCV_APLIC_SOURCE_SIZE * i;
			le32enc(entry, aplic->sources[i].sourcecfg);
			le32enc(entry + 4, aplic->sources[i].state);
			le32enc(entry + 8, aplic->sources[i].target);
		}
		error = vmm_snapshot_envelope_add(&builder,
		    VMM_SNAPSHOT_SECTION_RISCV_APLIC, RISCV_SECTION_FLAGS, 0,
		    staging, sizeof(staging));
	}
	if (error == 0)
		error = vmm_snapshot_envelope_finalize(&builder, &length);
	if (error == 0 && length != required)
		error = EPROTO;
	if (error == 0)
		*written = length;
	return (error);
}

int
vmm_snapshot_riscv_aplic_decode(const void *buffer, size_t length,
    struct vmm_snapshot_riscv_aplic *aplic)
{
	struct vmm_snapshot_riscv_aplic candidate;
	struct vmm_snapshot_envelope_reader reader;
	struct vmm_snapshot_section section;
	const uint8_t *wire, *entry;
	bool have_vm, have_aplic;
	int error;

	if (buffer == NULL || aplic == NULL)
		return (EINVAL);
	error = vmm_snapshot_envelope_reader_init(&reader, buffer, length);
	if (error != 0)
		return (error);
	memset(&candidate, 0, sizeof(candidate));
	have_vm = have_aplic = false;
	for (;;) {
		error = vmm_snapshot_envelope_next(&reader, &section);
		if (error == ENOENT)
			break;
		if (error != 0)
			return (error);
		wire = section.payload;
		switch (section.type) {
		case VMM_SNAPSHOT_SECTION_VM_COMMON:
			if (have_vm || section.instance != 0 ||
			    section.flags != RISCV_SECTION_FLAGS)
				return (EINVAL);
			error = vmm_snapshot_vm_common_decode(wire,
			    section.payload_length, &candidate.vm);
			if (error != 0)
				return (error);
			have_vm = true;
			break;
		case VMM_SNAPSHOT_SECTION_RISCV_APLIC:
			if (!have_vm || have_aplic || section.instance != 0 ||
			    section.flags != RISCV_SECTION_FLAGS ||
			    section.payload_length !=
			    VMM_SNAPSHOT_RISCV_APLIC_PAYLOAD_SIZE ||
			    le16dec(wire) != VMM_SNAPSHOT_RISCV_STATE_VERSION ||
			    le16dec(wire + 2) !=
			    VMM_SNAPSHOT_RISCV_APLIC_HEADER_SIZE ||
			    le32dec(wire + 12) != 0)
				return (EINVAL);
			candidate.nirqs = le32dec(wire + 4);
			candidate.domaincfg = le32dec(wire + 8);
			candidate.mem_start = le64dec(wire + 16);
			candidate.mem_size = le64dec(wire + 24);
			for (uint32_t i = 0; i < VMM_SNAPSHOT_RISCV_APLIC_SLOTS;
			    i++) {
				entry = wire + VMM_SNAPSHOT_RISCV_APLIC_HEADER_SIZE +
				    VMM_SNAPSHOT_RISCV_APLIC_SOURCE_SIZE * i;
				if (le32dec(entry + 12) != 0)
					return (EINVAL);
				candidate.sources[i].sourcecfg = le32dec(entry);
				candidate.sources[i].state = le32dec(entry + 4);
				candidate.sources[i].target = le32dec(entry + 8);
			}
			have_aplic = true;
			break;
		default:
			error = vmm_snapshot_section_skip_unknown(&section);
			if (error != 0)
				return (error);
			break;
		}
	}
	if (!have_vm || !have_aplic)
		return (EINVAL);
	error = vmm_snapshot_riscv_aplic_validate(&candidate);
	if (error != 0)
		return (error);
	*aplic = candidate;
	return (0);
}
