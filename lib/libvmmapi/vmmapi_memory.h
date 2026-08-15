/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef _VMMAPI_MEMORY_H_
#define	_VMMAPI_MEMORY_H_

#include <sys/cdefs.h>

#include <stddef.h>
#include <stdint.h>

#include <dev/vmm/vmm_mem.h>

struct vmmapi_memory_layout {
	uint64_t guest_size;
	uint64_t address_span;
	uint64_t reservation_size;
};

int	vm_distribute_memory_domains(size_t, size_t, size_t, size_t *,
	    size_t);

/* True only for a device-memory identifier managed by libvmmapi. */
int	vmmapi_devmem_segid_valid(int) __hidden;

/*
 * Calculate the host reservation needed for a guest memory layout without
 * performing any mappings.  host_span_limit is explicit so callers and tests
 * can model a narrower host word size without compiling the codec there.
 */
int	vmmapi_memory_layout_calculate(const size_t *, size_t, uint64_t,
	    uint64_t, uint64_t, uint64_t, struct vmmapi_memory_layout *)
	    __hidden;

#endif
