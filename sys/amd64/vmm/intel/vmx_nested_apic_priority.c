/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/endian.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/types.h>

#ifndef _KERNEL
#include <stdint.h>
#else
#include <sys/systm.h>
#endif

#include "vmx_nested_apic_priority.h"
#include "vmx_nested_state_range.h"

/* Intel SDM: primary processor-based execution control bit 21. */
#define	NVMX_APIC_TPR_SHADOW		(UINT32_C(1) << 21)
#define	NVMX_APIC_TPR_OFFSET		UINT64_C(0x80)
#define	NVMX_APIC_TPR_CLASS_MASK	UINT32_C(0x000000f0)

static int
nvmx_apic_priority_page_address(uint64_t virtual_apic, uint64_t *address)
{

	if (address == NULL || virtual_apic == UINT64_MAX ||
	    (virtual_apic & UINT64_C(0xfff)) != 0 ||
	    virtual_apic > UINT64_MAX - NVMX_APIC_TPR_OFFSET -
	    sizeof(uint32_t) + 1)
		return (EINVAL);
	*address = virtual_apic + NVMX_APIC_TPR_OFFSET;
	return (0);
}

int
vmx_nested_apic_priority_get(uint32_t primary, uint64_t virtual_apic,
    const struct vmx_nested_memory *memory,
    const struct vmx_nested_apic_priority_ops *ops, void *arg,
    uint64_t *value)
{
	uint8_t bytes[sizeof(uint32_t)];
	uint64_t address, candidate;
	uint32_t tpr;
	int error;

	if (value == NULL || ops == NULL ||
	    vmx_nested_state_ranges_overlap(value, sizeof(*value), memory,
	    sizeof(*memory)) ||
	    vmx_nested_state_ranges_overlap(value, sizeof(*value), ops,
	    sizeof(*ops)))
		return (EINVAL);
	if ((primary & NVMX_APIC_TPR_SHADOW) == 0) {
		if (ops->shared_get == NULL)
			return (EINVAL);
		candidate = UINT64_MAX;
		error = ops->shared_get(arg, &candidate);
		if (error != 0)
			return (error);
		if (candidate > 15)
			return (EPROTO);
		*value = candidate;
		return (0);
	}
	if (memory == NULL || memory->read == NULL)
		return (EINVAL);
	error = nvmx_apic_priority_page_address(virtual_apic, &address);
	if (error != 0)
		return (error);
	error = memory->read(memory->arg, address, bytes, sizeof(bytes));
	if (error != 0)
		return (error);
	tpr = le32dec(bytes);
	*value = (tpr & NVMX_APIC_TPR_CLASS_MASK) >> 4;
	return (0);
}

int
vmx_nested_apic_priority_set(uint32_t primary, uint64_t virtual_apic,
    const struct vmx_nested_memory *memory,
    const struct vmx_nested_apic_priority_ops *ops, void *arg,
    uint64_t value)
{
	struct vmx_nested_memory memory_snapshot;
	uint8_t bytes[sizeof(uint32_t)];
	uint64_t address;
	uint32_t tpr;
	int error;

	if (ops == NULL || value > 15)
		return (EINVAL);
	if ((primary & NVMX_APIC_TPR_SHADOW) == 0) {
		if (ops->shared_set == NULL)
			return (EINVAL);
		return (ops->shared_set(arg, value));
	}
	if (memory == NULL || memory->read == NULL || memory->write == NULL)
		return (EINVAL);
	memory_snapshot = *memory;
	memory = &memory_snapshot;
	error = nvmx_apic_priority_page_address(virtual_apic, &address);
	if (error != 0)
		return (error);
	error = memory->read(memory->arg, address, bytes, sizeof(bytes));
	if (error != 0)
		return (error);
	tpr = le32dec(bytes);
	tpr &= ~UINT32_C(0xff);
	tpr |= (uint32_t)value << 4;
	le32enc(bytes, tpr);
	return (memory->write(memory->arg, address, bytes, sizeof(bytes)));
}
