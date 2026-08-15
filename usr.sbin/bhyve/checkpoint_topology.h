/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef _BHYVE_CHECKPOINT_TOPOLOGY_H_
#define	_BHYVE_CHECKPOINT_TOPOLOGY_H_

#include <sys/types.h>
#include <stdint.h>

#define	CHECKPOINT_NUMA_MAX_DOMAINS	8

struct checkpoint_record_range {
	uint64_t offset;
	uint64_t length;
};

struct checkpoint_numa_domain {
	uint64_t memory_size;
	const uint16_t *vcpus;
	size_t vcpu_count;
};

struct checkpoint_memory_geometry {
	uint64_t page_size;
	uint64_t lowmem_size;
	uint64_t highmem_base;
	uint64_t highmem_size;
};

/*
 * Compare the source checkpoint's named device-state sections with the
 * destination machine.  Ordering is deliberately irrelevant, but names must
 * be nonempty and unique on both sides and the sets must match exactly.
 */
int	checkpoint_topology_validate(const char * const *, size_t,
	    const char * const *, size_t);
int	checkpoint_cpu_topology_validate(uint64_t, uint64_t, uint64_t,
	    uint64_t);
int	checkpoint_numa_topology_validate(
	    const struct checkpoint_numa_domain *, size_t, size_t, uint64_t);
int	checkpoint_numa_mapping_validate(const uint64_t *, size_t,
	    const uint16_t *, size_t, uint64_t);
int	checkpoint_memory_geometry_validate(
	    const struct checkpoint_memory_geometry *, uint64_t);
int	checkpoint_memory_geometry_match(
	    const struct checkpoint_memory_geometry *,
	    const struct checkpoint_memory_geometry *, uint64_t);
int	checkpoint_record_layout_validate(
	    const struct checkpoint_record_range *, size_t, uint64_t);
int	checkpoint_record_consumption_validate(size_t, size_t);

#endif /* _BHYVE_CHECKPOINT_TOPOLOGY_H_ */
