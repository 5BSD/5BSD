/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <sys/types.h>
#include <sys/errno.h>
#ifdef _KERNEL
#include <sys/systm.h>
#else
#include <stddef.h>
#include <string.h>
#endif
#include <dev/vmm/vmm_snapshot_envelope.h>
#include "vmm_snapshot_x86_transaction.h"

#ifdef _KERNEL
#include <sys/param.h>
#include <sys/malloc.h>
#else
#include <stdlib.h>
#endif

/*
 * The guest FPU payload staging buffer is too large for a kernel stack
 * frame, so the encoder borrows a transient heap allocation.  Userspace
 * (test) builds use the C library allocator.
 */
static void *
vmm_snapshot_x86_payload_alloc(size_t size)
{

#ifdef _KERNEL
	return (malloc(size, M_TEMP, M_NOWAIT | M_ZERO));
#else
	return (calloc(1, size));
#endif
}

static void
vmm_snapshot_x86_payload_free(void *payload)
{

#ifdef _KERNEL
	free(payload, M_TEMP);
#else
	free(payload);
#endif
}

/*
 * Maximum encoded transaction extent for the given vCPU count.  The guest
 * FPU section payload is variable length (48-byte header plus the source's
 * save-area image), so this is a capacity bound: the encoder reports the
 * exact emitted length through its written argument.
 */
int
vmm_snapshot_x86_transaction_size(uint32_t vcpu_count, size_t *sizep)
{
	size_t count, fixed, per_vcpu;

	if (sizep == NULL ||
	    !vmm_snapshot_range_valid(sizep, sizeof(*sizep)))
		return (EINVAL);
	count = vcpu_count;
	fixed = VMM_SNAPSHOT_ENVELOPE_HEADER_SIZE +
	    VMM_SNAPSHOT_SECTION_HEADER_SIZE + VMM_SNAPSHOT_VM_COMMON_SIZE;
	per_vcpu = 3 * VMM_SNAPSHOT_SECTION_HEADER_SIZE +
	    VMM_SNAPSHOT_VCPU_COMMON_SIZE + VMM_SNAPSHOT_VCPU_X86_SIZE +
	    VMM_SNAPSHOT_VCPU_X86_FPU_MAX_SIZE;
	if (count > (SIZE_MAX - fixed) / per_vcpu)
		return (EOVERFLOW);
	*sizep = fixed + count * per_vcpu;
	return (0);
}

static int
validate_source(const struct vmm_snapshot_x86_transaction *transaction,
    const struct vmm_snapshot_x86_vcpu_stage *stage, size_t capacity)
{
	size_t stage_length;
	size_t count;
	uint32_t previous;

	if (transaction == NULL ||
	    !vmm_snapshot_range_valid(transaction, sizeof(*transaction)))
		return (EINVAL);
	count = transaction->vcpu_count;
	if (transaction->vm.max_vcpus == 0 ||
	    transaction->vm.vcpu_count != transaction->vcpu_count ||
	    transaction->vcpu_count > transaction->vm.max_vcpus ||
	    count > capacity || count > SIZE_MAX / sizeof(*stage))
		return (EINVAL);
	stage_length = count * sizeof(*stage);
	if (!vmm_snapshot_range_valid(stage, stage_length) ||
	    vmm_snapshot_ranges_overlap(transaction, sizeof(*transaction),
	    stage, stage_length) ||
	    (count != 0 && stage == NULL))
		return (EINVAL);
	previous = 0;
	for (size_t i = 0; i < transaction->vcpu_count; i++) {
		if (stage[i].instance >= transaction->vm.max_vcpus ||
		    (i != 0 && stage[i].instance <= previous) ||
		    (stage[i].common.flags & ~VMM_SNAPSHOT_VCPU_F_VALID) != 0 ||
		    vmm_snapshot_vcpu_x86_validate(&stage[i].x86) != 0 ||
		    vmm_snapshot_vcpu_x86_fpu_validate(&stage[i].fpu) != 0)
			return (EINVAL);
		previous = stage[i].instance;
	}
	return (0);
}

int
vmm_snapshot_x86_transaction_encode(
    const struct vmm_snapshot_x86_transaction *transaction,
    const struct vmm_snapshot_x86_vcpu_stage *stage, size_t capacity,
    void *buffer, size_t buffer_capacity, size_t *written)
{
	struct vmm_snapshot_envelope_builder builder;
	uint8_t payload[VMM_SNAPSHOT_VCPU_X86_SIZE];
	uint8_t *fpu_payload;
	size_t count, payload_length, required, stage_length;
	int error;

	error = validate_source(transaction, stage, capacity);
	if (error != 0 || buffer == NULL || written == NULL ||
	    !vmm_snapshot_range_valid(buffer, buffer_capacity) ||
	    !vmm_snapshot_range_valid(written, sizeof(*written)))
		return (error != 0 ? error : EINVAL);
	count = transaction->vcpu_count;
	stage_length = count * sizeof(*stage);
	if (vmm_snapshot_ranges_overlap(buffer, buffer_capacity, transaction,
	    sizeof(*transaction)) || vmm_snapshot_ranges_overlap(buffer,
	    buffer_capacity, stage, stage_length) ||
	    vmm_snapshot_ranges_overlap(written, sizeof(*written), transaction,
	    sizeof(*transaction)) || vmm_snapshot_ranges_overlap(written,
	    sizeof(*written), stage, stage_length) ||
	    vmm_snapshot_ranges_overlap(written, sizeof(*written), buffer,
	    buffer_capacity))
		return (EINVAL);
	/*
	 * Guard the arithmetic with the (maximum) size query, then charge the
	 * exact extent: the guest FPU payload is variable length, and the
	 * capacity check must reject before any output byte is written.
	 */
	error = vmm_snapshot_x86_transaction_size(transaction->vcpu_count,
	    &required);
	if (error != 0)
		return (error);
	required = VMM_SNAPSHOT_ENVELOPE_HEADER_SIZE +
	    VMM_SNAPSHOT_SECTION_HEADER_SIZE + VMM_SNAPSHOT_VM_COMMON_SIZE;
	for (size_t i = 0; i < count; i++) {
		required += 3 * VMM_SNAPSHOT_SECTION_HEADER_SIZE +
		    VMM_SNAPSHOT_VCPU_COMMON_SIZE + VMM_SNAPSHOT_VCPU_X86_SIZE +
		    VMM_SNAPSHOT_VCPU_X86_FPU_HEADER_SIZE +
		    stage[i].fpu.area_length;
	}
	if (buffer_capacity < required)
		return (E2BIG);
	/*
	 * Acquire the FPU payload staging before the builder writes the
	 * envelope header, so allocation failure also leaves the output
	 * untouched.
	 */
	fpu_payload = NULL;
	if (count != 0) {
		fpu_payload = vmm_snapshot_x86_payload_alloc(
		    VMM_SNAPSHOT_VCPU_X86_FPU_MAX_SIZE);
		if (fpu_payload == NULL)
			return (ENOMEM);
	}

	error = vmm_snapshot_envelope_builder_init(&builder, buffer,
	    buffer_capacity);
	if (error == 0)
		error = vmm_snapshot_vm_common_encode(&transaction->vm, payload,
		    sizeof(payload), &payload_length);
	if (error == 0)
		error = vmm_snapshot_envelope_add(&builder,
		    VMM_SNAPSHOT_SECTION_VM_COMMON,
		    VMM_SNAPSHOT_SECTION_F_CRITICAL, 0, payload,
		    payload_length);
	for (size_t i = 0; error == 0 && i < count; i++) {
		error = vmm_snapshot_vcpu_common_encode(&stage[i].common,
		    payload, sizeof(payload), &payload_length);
		if (error == 0)
			error = vmm_snapshot_envelope_add(&builder,
			    VMM_SNAPSHOT_SECTION_VCPU_COMMON,
			    VMM_SNAPSHOT_SECTION_F_CRITICAL, stage[i].instance,
			    payload, payload_length);
	}
	for (size_t i = 0; error == 0 && i < count; i++) {
		error = vmm_snapshot_vcpu_x86_encode(&stage[i].x86, payload,
		    sizeof(payload), &payload_length);
		if (error == 0)
			error = vmm_snapshot_envelope_add(&builder,
			    VMM_SNAPSHOT_SECTION_VCPU_X86,
			    VMM_SNAPSHOT_SECTION_F_CRITICAL, stage[i].instance,
			    payload, payload_length);
	}
	for (size_t i = 0; error == 0 && i < count; i++) {
		error = vmm_snapshot_vcpu_x86_fpu_encode(&stage[i].fpu,
		    fpu_payload, VMM_SNAPSHOT_VCPU_X86_FPU_MAX_SIZE,
		    &payload_length);
		if (error == 0)
			error = vmm_snapshot_envelope_add(&builder,
			    VMM_SNAPSHOT_SECTION_VCPU_X86_FPU,
			    VMM_SNAPSHOT_SECTION_F_CRITICAL,
			    stage[i].instance, fpu_payload,
			    payload_length);
	}
	if (fpu_payload != NULL)
		vmm_snapshot_x86_payload_free(fpu_payload);
	if (error == 0)
		error = vmm_snapshot_envelope_finalize(&builder, &required);
	if (error == 0)
		*written = required;
	return (error);
}

static int
next_section_of_type(struct vmm_snapshot_envelope_reader *reader,
    uint16_t type, struct vmm_snapshot_section *section)
{
	int error;

	while ((error = vmm_snapshot_envelope_next(reader, section)) == 0) {
		if (section->type == type)
			return (0);
	}
	return (error);
}

static int
decode_pass(const void *buffer, size_t length,
    struct vmm_snapshot_x86_vcpu_stage *stage, size_t capacity,
    struct vmm_snapshot_x86_transaction *transaction, bool publish)
{
	struct vmm_snapshot_envelope_reader common_reader, fpu_pair_reader,
	    reader;
	struct vmm_snapshot_section common_section, section;
	struct vmm_snapshot_vm_common vm = { 0 };
	struct vmm_snapshot_vcpu_common common;
	struct vmm_snapshot_vcpu_x86 x86;
	uint32_t common_count, fpu_count, previous_instance, x86_count;
	bool have_vm;
	int error;

	common_count = fpu_count = previous_instance = x86_count = 0;
	have_vm = false;
	error = vmm_snapshot_envelope_reader_init(&reader, buffer, length);
	if (error != 0)
		return (error);
	error = vmm_snapshot_envelope_reader_init(&common_reader, buffer, length);
	if (error != 0)
		return (error);
	error = vmm_snapshot_envelope_reader_init(&fpu_pair_reader, buffer,
	    length);
	if (error != 0)
		return (error);
	while ((error = vmm_snapshot_envelope_next(&reader, &section)) == 0) {
		if (section.type != VMM_SNAPSHOT_SECTION_VM_COMMON &&
		    section.type != VMM_SNAPSHOT_SECTION_VCPU_COMMON &&
		    section.type != VMM_SNAPSHOT_SECTION_VCPU_X86 &&
		    section.type != VMM_SNAPSHOT_SECTION_VCPU_X86_FPU) {
			error = vmm_snapshot_section_skip_unknown(&section);
			if (error != 0)
				return (error);
			continue;
		}
		if ((section.flags & VMM_SNAPSHOT_SECTION_F_CRITICAL) == 0)
			return (EINVAL);
		switch (section.type) {
		case VMM_SNAPSHOT_SECTION_VM_COMMON:
			if (section.instance != 0 || have_vm)
				return (EINVAL);
			error = vmm_snapshot_vm_common_decode(section.payload,
			    section.payload_length, &vm);
			if (error != 0 || vm.vcpu_count > capacity)
				return (error != 0 ? error : E2BIG);
			have_vm = true;
			break;
		case VMM_SNAPSHOT_SECTION_VCPU_COMMON:
			if (!have_vm || section.instance >= vm.max_vcpus ||
			    common_count >= vm.vcpu_count ||
			    (common_count != 0 && section.instance <= previous_instance))
				return (EINVAL);
			error = vmm_snapshot_vcpu_common_decode(section.payload,
			    section.payload_length, &common);
			if (error != 0)
				return (error);
			if (publish) {
				/* Canonicalize private stage padding before publication. */
				memset(&stage[common_count], 0,
				    sizeof(stage[common_count]));
				stage[common_count].instance = section.instance;
				stage[common_count].common = common;
			}
			previous_instance = section.instance;
			common_count++;
			break;
		case VMM_SNAPSHOT_SECTION_VCPU_X86:
			if (!have_vm || x86_count >= common_count)
				return (EINVAL);
			if (publish) {
				if (stage[x86_count].instance != section.instance)
					return (EINVAL);
			} else {
				error = next_section_of_type(&common_reader,
				    VMM_SNAPSHOT_SECTION_VCPU_COMMON,
				    &common_section);
				if (error != 0 ||
				    common_section.instance != section.instance)
					return (EINVAL);
			}
			error = vmm_snapshot_vcpu_x86_decode(section.payload,
			    section.payload_length, &x86);
			if (error != 0)
				return (error);
			if (publish)
				stage[x86_count].x86 = x86;
			x86_count++;
			break;
		case VMM_SNAPSHOT_SECTION_VCPU_X86_FPU:
			if (!have_vm || fpu_count >= common_count)
				return (EINVAL);
			if (publish) {
				if (stage[fpu_count].instance !=
				    section.instance)
					return (EINVAL);
			} else {
				error = next_section_of_type(&fpu_pair_reader,
				    VMM_SNAPSHOT_SECTION_VCPU_COMMON,
				    &common_section);
				if (error != 0 ||
				    common_section.instance !=
				    section.instance)
					return (EINVAL);
			}
			/*
			 * The record is validated in place: the first pass
			 * proves every byte before the second (publishing)
			 * pass writes any caller memory, and the payload is
			 * too large for an on-stack candidate in the kernel.
			 */
			error = vmm_snapshot_vcpu_x86_fpu_wire_validate(
			    section.payload, section.payload_length);
			if (error != 0)
				return (error);
			if (publish) {
				error = vmm_snapshot_vcpu_x86_fpu_decode(
				    section.payload, section.payload_length,
				    &stage[fpu_count].fpu);
				if (error != 0)
					return (error);
			}
			fpu_count++;
			break;
		}
	}
	if (error != ENOENT || !have_vm ||
	    common_count != vm.vcpu_count || x86_count != common_count ||
	    fpu_count != common_count)
		return (error == ENOENT ? EINVAL : error);
	if (publish) {
		/* The private transaction also has native alignment padding. */
		memset(transaction, 0, sizeof(*transaction));
		transaction->vm = vm;
		transaction->vcpu_count = common_count;
	}
	return (0);
}

int
vmm_snapshot_x86_transaction_decode(const void *buffer, size_t length,
    struct vmm_snapshot_x86_vcpu_stage *stage, size_t capacity,
    struct vmm_snapshot_x86_transaction *transaction)
{
	int error;
	size_t stage_length;

	if (buffer == NULL || transaction == NULL ||
	    (capacity != 0 && stage == NULL) ||
	    capacity > SIZE_MAX / sizeof(*stage))
		return (EINVAL);
	stage_length = capacity * sizeof(*stage);
	if (!vmm_snapshot_range_valid(buffer, length) ||
	    !vmm_snapshot_range_valid(stage, stage_length) ||
	    !vmm_snapshot_range_valid(transaction, sizeof(*transaction)))
		return (EINVAL);
	if (vmm_snapshot_ranges_overlap(buffer, length, stage, stage_length) ||
	    vmm_snapshot_ranges_overlap(buffer, length, transaction,
	    sizeof(*transaction)) || vmm_snapshot_ranges_overlap(stage,
	    stage_length, transaction, sizeof(*transaction)))
		return (EINVAL);
	error = decode_pass(buffer, length, NULL, capacity, NULL, false);
	if (error != 0)
		return (error);
	return (decode_pass(buffer, length, stage, capacity, transaction, true));
}

int
vmm_snapshot_x86_transaction_validate_destination(
    const struct vmm_snapshot_x86_transaction *transaction,
    const struct vmm_snapshot_x86_vcpu_stage *stage, size_t capacity,
    uint32_t destination_max_vcpus, const uint32_t *destination_instances,
    size_t destination_count)
{
	uint32_t previous;
	size_t instances_length, stage_length;

	if (transaction == NULL || destination_max_vcpus == 0 ||
	    destination_count > UINT32_MAX ||
	    destination_count > SIZE_MAX / sizeof(*stage) ||
	    destination_count > SIZE_MAX / sizeof(*destination_instances))
		return (EINVAL);
	stage_length = destination_count * sizeof(*stage);
	instances_length = destination_count * sizeof(*destination_instances);
	if (!vmm_snapshot_range_valid(transaction, sizeof(*transaction)) ||
	    !vmm_snapshot_range_valid(stage, stage_length) ||
	    !vmm_snapshot_range_valid(destination_instances, instances_length) ||
	    vmm_snapshot_ranges_overlap(transaction, sizeof(*transaction),
	    stage, stage_length) || vmm_snapshot_ranges_overlap(transaction,
	    sizeof(*transaction), destination_instances, instances_length) ||
	    vmm_snapshot_ranges_overlap(stage, stage_length,
	    destination_instances, instances_length) ||
	    transaction->vm.max_vcpus != destination_max_vcpus ||
	    transaction->vm.vcpu_count != transaction->vcpu_count ||
	    transaction->vcpu_count != destination_count ||
	    transaction->vcpu_count > capacity ||
	    (destination_count != 0 &&
	    (stage == NULL || destination_instances == NULL)))
		return (EINVAL);
	previous = 0;
	for (size_t i = 0; i < destination_count; i++) {
		if (destination_instances[i] >= destination_max_vcpus ||
		    stage[i].instance != destination_instances[i] ||
		    (i != 0 && destination_instances[i] <= previous) ||
		    (stage[i].common.flags & ~VMM_SNAPSHOT_VCPU_F_VALID) != 0 ||
		    vmm_snapshot_vcpu_x86_validate(&stage[i].x86) != 0 ||
		    vmm_snapshot_vcpu_x86_fpu_validate(&stage[i].fpu) != 0)
			return (EINVAL);
		previous = stage[i].instance;
	}
	return (0);
}

int
vmm_snapshot_x86_transaction_restore_preflight(
    const struct vmm_snapshot_x86_transaction *transaction,
    const struct vmm_snapshot_x86_vcpu_stage *stage, size_t capacity,
    uint32_t destination_max_vcpus, const uint32_t *destination_instances,
    const uint8_t *destination_lapic_x2apic, size_t destination_count)
{
	size_t instances_length, modes_length, stage_length;
	int error;

	if (destination_count > SIZE_MAX / sizeof(*stage) ||
	    destination_count > SIZE_MAX / sizeof(*destination_instances) ||
	    destination_count > SIZE_MAX / sizeof(*destination_lapic_x2apic))
		return (EINVAL);
	stage_length = destination_count * sizeof(*stage);
	instances_length = destination_count * sizeof(*destination_instances);
	modes_length = destination_count * sizeof(*destination_lapic_x2apic);
	if (!vmm_snapshot_range_valid(destination_lapic_x2apic, modes_length) ||
	    vmm_snapshot_ranges_overlap(transaction, sizeof(*transaction),
	    destination_lapic_x2apic, modes_length) ||
	    vmm_snapshot_ranges_overlap(stage, stage_length,
	    destination_lapic_x2apic, modes_length) ||
	    vmm_snapshot_ranges_overlap(destination_instances, instances_length,
	    destination_lapic_x2apic, modes_length))
		return (EINVAL);
	error = vmm_snapshot_x86_transaction_validate_destination(transaction,
	    stage, capacity, destination_max_vcpus, destination_instances,
	    destination_count);
	if (error != 0)
		return (error);
	for (size_t i = 0; i < destination_count; i++) {
		if (destination_lapic_x2apic[i] > 1 ||
		    destination_lapic_x2apic[i] !=
		    (stage[i].x86.x2apic_state == 1))
			return (EINVAL);
	}
	return (0);
}
