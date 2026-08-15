/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>

#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#include "vmmapi_memory.h"

int
vmmapi_devmem_segid_valid(int segid)
{

	return (segid >= VM_BOOTROM && segid < VM_MEMSEG_END);
}

static int
vmmapi_u64_add(uint64_t left, uint64_t right, uint64_t *result)
{

	if (result == NULL)
		return (EINVAL);
	if (left > UINT64_MAX - right)
		return (EOVERFLOW);
	*result = left + right;
	return (0);
}

int
vm_distribute_memory_domains(size_t total_size, size_t domain_count,
    size_t allocation_granule, size_t *domain_sizes, size_t capacity)
{
	size_t base_units, extra_units, total_units;

	if (total_size == 0 || domain_count == 0 || allocation_granule == 0 ||
	    domain_sizes == NULL || capacity < domain_count)
		return (EINVAL);
	if (total_size % allocation_granule != 0)
		return (EINVAL);

	total_units = total_size / allocation_granule;
	if (total_units < domain_count)
		return (EINVAL);
	base_units = total_units / domain_count;
	extra_units = total_units % domain_count;

	for (size_t i = 0; i < domain_count; i++)
		domain_sizes[i] = (base_units + (i < extra_units)) *
		    allocation_granule;
	return (0);
}

int
vmmapi_memory_layout_calculate(const size_t *domain_sizes,
    size_t domain_count, uint64_t lowmem_limit, uint64_t highmem_base,
    uint64_t guard_size, uint64_t host_span_limit,
    struct vmmapi_memory_layout *layout)
{
	uint64_t guest_size, address_span, reservation_size;
	int error;

	if (domain_sizes == NULL || domain_count == 0 || layout == NULL ||
	    highmem_base < lowmem_limit)
		return (EINVAL);

	guest_size = 0;
	for (size_t i = 0; i < domain_count; i++) {
		if (domain_sizes[i] == 0)
			return (EINVAL);
		/*
		 * The layout and its public snapshot/migration consumers use
		 * fixed-width 64-bit GPAs.  Do not silently narrow a wider future
		 * size_t before the checked addition below.
		 */
		if (domain_sizes[i] > UINT64_MAX)
			return (EOVERFLOW);
		error = vmmapi_u64_add(guest_size,
		    (uint64_t)domain_sizes[i], &guest_size);
		if (error != 0)
			return (error);
	}

	if (guest_size <= lowmem_limit) {
		address_span = guest_size;
	} else {
		error = vmmapi_u64_add(highmem_base,
		    guest_size - lowmem_limit, &address_span);
		if (error != 0)
			return (error);
	}
	error = vmmapi_u64_add(guard_size, address_span, &reservation_size);
	if (error == 0)
		error = vmmapi_u64_add(reservation_size, guard_size,
		    &reservation_size);
	if (error != 0)
		return (error);
	if (reservation_size > host_span_limit)
		return (EOVERFLOW);

	*layout = (struct vmmapi_memory_layout) {
		.guest_size = guest_size,
		.address_span = address_span,
		.reservation_size = reservation_size,
	};
	return (0);
}
