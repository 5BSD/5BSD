/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "checkpoint_topology.h"

static bool
checkpoint_topology_contains(const char * const *names, size_t count,
    const char *wanted)
{

	for (size_t i = 0; i < count; i++) {
		if (strcmp(names[i], wanted) == 0)
			return (true);
	}
	return (false);
}

static int
checkpoint_topology_names_valid(const char * const *names, size_t count)
{

	if (count != 0 && names == NULL)
		return (EINVAL);
	for (size_t i = 0; i < count; i++) {
		if (names[i] == NULL || names[i][0] == '\0')
			return (EINVAL);
		for (size_t j = 0; j < i; j++) {
			if (strcmp(names[i], names[j]) == 0)
				return (EEXIST);
		}
	}
	return (0);
}

int
checkpoint_topology_validate(const char * const *source, size_t source_count,
    const char * const *destination, size_t destination_count)
{
	int error;

	error = checkpoint_topology_names_valid(source, source_count);
	if (error != 0)
		return (error);
	error = checkpoint_topology_names_valid(destination, destination_count);
	if (error != 0)
		return (error);
	if (source_count != destination_count)
		return (ENODEV);
	for (size_t i = 0; i < source_count; i++) {
		if (!checkpoint_topology_contains(destination, destination_count,
		    source[i]))
			return (ENODEV);
	}
	return (0);
}

int
checkpoint_record_consumption_validate(size_t record_size, size_t remaining)
{

	/*
	 * Restore and validation must consume the same exact representation.
	 * Also reject an impossible remaining count explicitly instead of
	 * allowing unsigned arithmetic in a caller to hide the mismatch.
	 */
	if (remaining > record_size || remaining != 0)
		return (EINVAL);
	return (0);
}

int
checkpoint_cpu_topology_validate(uint64_t ncpus, uint64_t sockets,
    uint64_t cores, uint64_t threads)
{
	uint64_t product;

	if (ncpus == 0 || ncpus > UINT16_MAX ||
	    sockets == 0 || sockets > UINT16_MAX ||
	    cores == 0 || cores > UINT16_MAX ||
	    threads == 0 || threads > UINT16_MAX)
		return (EINVAL);
	product = sockets * cores * threads;
	if (product != ncpus)
		return (EINVAL);
	return (0);
}

int
checkpoint_numa_topology_validate(
    const struct checkpoint_numa_domain *domains, size_t domain_count,
    size_t vcpu_count, uint64_t memory_size)
{
	bool *assigned;
	uint64_t accumulated;
	size_t assigned_count;
	int error;

	if (domains == NULL || domain_count == 0 ||
	    domain_count > CHECKPOINT_NUMA_MAX_DOMAINS ||
	    vcpu_count == 0 || vcpu_count > UINT16_MAX || memory_size == 0)
		return (EINVAL);
	assigned = calloc(vcpu_count, sizeof(*assigned));
	if (assigned == NULL)
		return (ENOMEM);

	accumulated = 0;
	assigned_count = 0;
	error = 0;
	for (size_t domain = 0; domain < domain_count; domain++) {
		if (domains[domain].memory_size == 0 ||
		    domains[domain].vcpu_count == 0 ||
		    domains[domain].vcpus == NULL ||
		    domains[domain].vcpu_count >
		    vcpu_count - assigned_count ||
		    domains[domain].memory_size > memory_size - accumulated) {
			error = EINVAL;
			break;
		}
		accumulated += domains[domain].memory_size;
		for (size_t i = 0; i < domains[domain].vcpu_count; i++) {
			uint16_t vcpu;

			vcpu = domains[domain].vcpus[i];
			if (vcpu >= vcpu_count || assigned[vcpu]) {
				error = EINVAL;
				break;
			}
			assigned[vcpu] = true;
			assigned_count++;
		}
		if (error != 0)
			break;
	}
	if (error == 0 &&
	    (accumulated != memory_size || assigned_count != vcpu_count))
		error = EINVAL;
	free(assigned);
	return (error);
}

int
checkpoint_numa_mapping_validate(const uint64_t *domain_sizes,
    size_t domain_count, const uint16_t *vcpu_domains, size_t vcpu_count,
    uint64_t memory_size)
{
	bool populated[CHECKPOINT_NUMA_MAX_DOMAINS];
	uint64_t accumulated;

	if (domain_sizes == NULL || domain_count == 0 ||
	    domain_count > CHECKPOINT_NUMA_MAX_DOMAINS ||
	    vcpu_domains == NULL || vcpu_count == 0 ||
	    vcpu_count > UINT16_MAX || memory_size == 0)
		return (EINVAL);
	memset(populated, 0, sizeof(populated));
	accumulated = 0;
	for (size_t domain = 0; domain < domain_count; domain++) {
		if (domain_sizes[domain] == 0 ||
		    domain_sizes[domain] > UINT64_MAX - accumulated)
			return (EINVAL);
		accumulated += domain_sizes[domain];
	}
	for (size_t vcpu = 0; vcpu < vcpu_count; vcpu++) {
		if (vcpu_domains[vcpu] >= domain_count)
			return (EINVAL);
		populated[vcpu_domains[vcpu]] = true;
	}
	for (size_t domain = 0; domain < domain_count; domain++) {
		if (!populated[domain])
			return (EINVAL);
	}
	return (accumulated == memory_size ? 0 : ERANGE);
}

int
checkpoint_memory_geometry_validate(
    const struct checkpoint_memory_geometry *geometry, uint64_t memory_size)
{
	uint64_t mapped;

	if (geometry == NULL || memory_size == 0 ||
	    geometry->page_size == 0 ||
	    (geometry->page_size & (geometry->page_size - 1)) != 0 ||
	    geometry->lowmem_size % geometry->page_size != 0 ||
	    geometry->highmem_base % geometry->page_size != 0 ||
	    geometry->highmem_size % geometry->page_size != 0 ||
	    geometry->lowmem_size > memory_size ||
	    geometry->highmem_size > memory_size - geometry->lowmem_size)
		return (EINVAL);
	mapped = geometry->lowmem_size + geometry->highmem_size;
	if (mapped != memory_size)
		return (ERANGE);
	if (geometry->highmem_size != 0 &&
	    (geometry->highmem_base < geometry->lowmem_size ||
	    geometry->highmem_size >
	    UINT64_MAX - geometry->highmem_base))
		return (EINVAL);
	return (0);
}

int
checkpoint_memory_geometry_match(
    const struct checkpoint_memory_geometry *source,
    const struct checkpoint_memory_geometry *destination,
    uint64_t memory_size)
{
	int error;

	error = checkpoint_memory_geometry_validate(source, memory_size);
	if (error != 0)
		return (error);
	error = checkpoint_memory_geometry_validate(destination, memory_size);
	if (error != 0)
		return (error);
	if (source->page_size != destination->page_size ||
	    source->lowmem_size != destination->lowmem_size ||
	    source->highmem_base != destination->highmem_base ||
	    source->highmem_size != destination->highmem_size)
		return (EXDEV);
	return (0);
}

int
checkpoint_record_layout_validate(const struct checkpoint_record_range *ranges,
    size_t count, uint64_t total_length)
{
	uint64_t cursor;
	size_t selected;

	if (count == 0)
		return (total_length == 0 ? 0 : EINVAL);
	if (ranges == NULL || total_length == 0)
		return (EINVAL);
	cursor = 0;
	for (size_t emitted = 0; emitted < count; emitted++) {
		selected = SIZE_MAX;
		for (size_t i = 0; i < count; i++) {
			if (ranges[i].length == 0 ||
			    ranges[i].offset > total_length ||
			    ranges[i].length > total_length - ranges[i].offset)
				return (EINVAL);
			if (ranges[i].offset < cursor)
				continue;
			if (selected == SIZE_MAX ||
			    ranges[i].offset < ranges[selected].offset)
				selected = i;
		}
		if (selected == SIZE_MAX || ranges[selected].offset != cursor)
			return (EINVAL);
		cursor += ranges[selected].length;
	}
	return (cursor == total_length ? 0 : EINVAL);
}
