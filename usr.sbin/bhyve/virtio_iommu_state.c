/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/endian.h>

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "virtio_iommu_state.h"
#include "virtio_state_range.h"

struct viommu_endpoint {
	uint32_t id;
	uint32_t domain;
	uint32_t active_dma;
	bool present;
	bool attached;
	bool dma_bypass;
};

struct viommu_domain {
	uint32_t id;
	uint32_t endpoint_count;
	bool present;
	bool bypass;
};

struct viommu_mapping {
	uint64_t virtual_start;
	uint64_t virtual_end;
	uint64_t physical_start;
	uint32_t domain;
	uint32_t flags;
	bool present;
};

struct virtio_iommu_state {
	pthread_mutex_t mutex;
	struct virtio_iommu_limits limits;
	struct virtio_iommu_ops ops;
	struct viommu_endpoint *endpoints;
	struct viommu_domain *domains;
	struct viommu_mapping *mappings;
	struct virtio_iommu_fault *faults;
	uint64_t generation;
	uint64_t fault_dropped;
	size_t domain_count;
	size_t endpoint_count;
	size_t mapping_count;
	size_t mapping_scan_limit;
	size_t fault_count;
	size_t fault_head;
	size_t fault_tail;
	bool reset_pending;
	bool boot_default_bypass;
};

/*
 * The configured table limits are retained for the state lifetime and are
 * reused by reset and snapshot alias checks.  Validate their byte extents at
 * construction time instead of depending on calloc(3) overflow handling on
 * a 32-bit destination host.
 */
static int
viommu_array_size(uint32_t count, size_t element_size, size_t *size)
{

	if (size == NULL || element_size == 0)
		return (EINVAL);
#if SIZE_MAX <= UINT32_MAX
	if (count > SIZE_MAX / element_size)
		return (EOVERFLOW);
#endif
	*size = (size_t)count * element_size;
	return (0);
}

#define	VIOMMU_STATE_MAGIC		0x534d4956U	/* "VIMS" */
#define	VIOMMU_STATE_VERSION		1U
#define	VIOMMU_STATE_HEADER_SIZE		96U
#define	VIOMMU_STATE_ENDPOINT_SIZE	12U
#define	VIOMMU_STATE_DOMAIN_SIZE		16U
#define	VIOMMU_STATE_MAPPING_SIZE	40U
#define	VIOMMU_STATE_FAULT_SIZE		24U
#define	VIOMMU_STATE_F_DEFAULT_BYPASS	(1U << 0)
#define	VIOMMU_STATE_F_BYPASS_DOMAINS	(1U << 1)
#define	VIOMMU_STATE_F_ALLOW_MMIO	(1U << 2)
#define	VIOMMU_STATE_F_MASK		(VIOMMU_STATE_F_DEFAULT_BYPASS | \
	VIOMMU_STATE_F_BYPASS_DOMAINS | VIOMMU_STATE_F_ALLOW_MMIO)
#define	VIOMMU_ENDPOINT_F_ATTACHED	(1U << 0)
#define	VIOMMU_DOMAIN_F_BYPASS		(1U << 0)
#define	VIOMMU_STATE_DIGEST_OFFSET	88U

static uint64_t
viommu_state_digest(const uint8_t *bytes, size_t length)
{
	uint64_t digest;

	/* FNV-1a is used only as an accidental-corruption detector. */
	digest = UINT64_C(14695981039346656037);
	for (size_t i = 0; i < length; i++) {
		uint8_t byte;

		byte = i >= VIOMMU_STATE_DIGEST_OFFSET &&
		    i < VIOMMU_STATE_DIGEST_OFFSET + sizeof(uint64_t) ?
		    0 : bytes[i];
		digest ^= byte;
		digest *= UINT64_C(1099511628211);
	}
	return (digest);
}

static bool
viommu_state_bytes_zero(const uint8_t *bytes, size_t length)
{

	for (size_t i = 0; i < length; i++) {
		if (bytes[i] != 0)
			return (false);
	}
	return (true);
}

static uint32_t
viommu_state_flags(const struct virtio_iommu_state *state)
{
	uint32_t flags;

	flags = 0;
	if (state->limits.default_bypass)
		flags |= VIOMMU_STATE_F_DEFAULT_BYPASS;
	if (state->limits.bypass_domains)
		flags |= VIOMMU_STATE_F_BYPASS_DOMAINS;
	if (state->limits.allow_mmio)
		flags |= VIOMMU_STATE_F_ALLOW_MMIO;
	return (flags);
}

/*
 * The default-bypass bit is live configuration, restored with the image and
 * protected by state->mutex.  The remaining limits are construction-time
 * compatibility properties.  Restore preflight deliberately runs without
 * holding the mutex while it decodes and validates a potentially large
 * image, so it must compare only this immutable subset there rather than
 * reading default_bypass concurrently with a config write.
 */
static uint32_t
viommu_state_compat_flags(const struct virtio_iommu_state *state)
{
	uint32_t flags;

	flags = 0;
	if (state->limits.bypass_domains)
		flags |= VIOMMU_STATE_F_BYPASS_DOMAINS;
	if (state->limits.allow_mmio)
		flags |= VIOMMU_STATE_F_ALLOW_MMIO;
	return (flags);
}

/*
 * Snapshotting sorts copies of the live endpoint and domain arrays.  The
 * public control-plane operations keep the cached counts and compact mapping
 * prefix in step with those arrays, but do not let a violated internal
 * invariant turn that bookkeeping into an allocation size or array bound.
 *
 * This is deliberately an internal-state check, not a validation rule for a
 * guest-provided VirtIO request.  A broken live state cannot describe a
 * portable checkpoint, so reject it before touching the caller's buffer.
 */
static int
viommu_snapshot_invariants_locked(const struct virtio_iommu_state *state)
{
	size_t domains, endpoints, mappings;
	uint64_t granularity;

	if (state->endpoint_count > state->limits.max_endpoints ||
	    state->domain_count > state->limits.max_domains ||
	    state->mapping_count > state->limits.max_mappings ||
	    state->mapping_scan_limit != state->mapping_count ||
	    state->fault_count > state->limits.max_faults)
		return (EPROTO);
	if ((state->limits.max_endpoints != 0 && state->endpoints == NULL) ||
	    (state->limits.max_domains != 0 && state->domains == NULL) ||
	    (state->limits.max_mappings != 0 && state->mappings == NULL) ||
	    (state->limits.max_faults != 0 && state->faults == NULL))
		return (EPROTO);
	if (state->limits.page_size_mask == 0)
		return (EPROTO);
	granularity = (uint64_t)1 << __builtin_ctzll(
	    state->limits.page_size_mask);
	if (state->limits.max_faults == 0) {
		if (state->fault_count != 0 || state->fault_head != 0 ||
		    state->fault_tail != 0)
			return (EPROTO);
	} else if (state->fault_head >= state->limits.max_faults ||
	    state->fault_tail >= state->limits.max_faults ||
	    state->fault_tail != (state->fault_head + state->fault_count) %
	    state->limits.max_faults) {
		return (EPROTO);
	}
	endpoints = 0;
	for (uint32_t i = 0; i < state->limits.max_endpoints; i++) {
		const struct viommu_endpoint *endpoint;
		bool found;

		endpoint = &state->endpoints[i];
		if (!endpoint->present)
			continue;
		endpoints++;
		for (uint32_t j = 0; j < i; j++) {
			if (state->endpoints[j].present &&
			    state->endpoints[j].id == endpoint->id)
				return (EPROTO);
		}
		if (!endpoint->attached) {
			if (endpoint->domain != 0)
				return (EPROTO);
			continue;
		}
		found = false;
		for (uint32_t j = 0; j < state->limits.max_domains; j++) {
			if (state->domains[j].present &&
			    state->domains[j].id == endpoint->domain) {
				found = true;
				break;
			}
		}
		if (!found)
			return (EPROTO);
	}
	domains = 0;
	for (uint32_t i = 0; i < state->limits.max_domains; i++) {
		const struct viommu_domain *domain;
		size_t attached;

		domain = &state->domains[i];
		if (!domain->present)
			continue;
		domains++;
		if (domain->id < state->limits.domain_start ||
		    domain->id > state->limits.domain_end ||
		    (domain->bypass && !state->limits.bypass_domains))
			return (EPROTO);
		for (uint32_t j = 0; j < i; j++) {
			if (state->domains[j].present &&
			    state->domains[j].id == domain->id)
				return (EPROTO);
		}
		attached = 0;
		for (uint32_t j = 0; j < state->limits.max_endpoints; j++) {
			if (state->endpoints[j].present &&
			    state->endpoints[j].attached &&
			    state->endpoints[j].domain == domain->id)
				attached++;
		}
		if (domain->endpoint_count != attached)
			return (EPROTO);
	}
	mappings = 0;
	for (uint32_t i = 0; i < state->limits.max_mappings; i++) {
		const struct viommu_domain *domain;
		const struct viommu_mapping *mapping;
		uint64_t length;
		bool found;

		mapping = &state->mappings[i];
		if (i >= state->mapping_count) {
			if (mapping->present)
				return (EPROTO);
			continue;
		}
		if (!mapping->present ||
		    (mapping->flags & ~BHYVE_VIOMMU_MAP_F_MASK) != 0 ||
		    ((mapping->flags & BHYVE_VIOMMU_MAP_F_MMIO) != 0 &&
		    !state->limits.allow_mmio) ||
		    mapping->virtual_end <= mapping->virtual_start ||
		    mapping->virtual_start < state->limits.input_start ||
		    mapping->virtual_end > state->limits.input_end ||
		    mapping->virtual_start % granularity != 0 ||
		    mapping->physical_start % granularity != 0 ||
		    (mapping->virtual_end + 1) % granularity != 0)
			return (EPROTO);
		length = mapping->virtual_end - mapping->virtual_start + 1;
		if (length == 0 || mapping->physical_start >
		    UINT64_MAX - (length - 1))
			return (EPROTO);
		found = false;
		for (uint32_t j = 0; j < state->limits.max_domains; j++) {
			domain = &state->domains[j];
			if (domain->present && domain->id == mapping->domain) {
				if (domain->bypass)
					return (EPROTO);
				found = true;
				break;
			}
		}
		if (!found)
			return (EPROTO);
		if (i != 0 && (mapping->domain < state->mappings[i - 1].domain ||
		    (mapping->domain == state->mappings[i - 1].domain &&
		    (mapping->virtual_start < state->mappings[i - 1].virtual_start ||
		    mapping->virtual_start <= state->mappings[i - 1].virtual_end))))
			return (EPROTO);
		mappings++;
	}
	if (endpoints != state->endpoint_count || domains != state->domain_count ||
	    mappings != state->mapping_count)
		return (EPROTO);
	return (0);
}

static int
viommu_snapshot_size_locked(struct virtio_iommu_state *state, size_t *result)
{
	size_t size;
	int error;

	error = viommu_snapshot_invariants_locked(state);
	if (error != 0)
		return (error);

	if (state->endpoint_count >
	    (SIZE_MAX - VIOMMU_STATE_HEADER_SIZE) /
	    VIOMMU_STATE_ENDPOINT_SIZE)
		return (EOVERFLOW);
	size = VIOMMU_STATE_HEADER_SIZE +
	    state->endpoint_count * VIOMMU_STATE_ENDPOINT_SIZE;
	if (state->domain_count >
	    (SIZE_MAX - size) / VIOMMU_STATE_DOMAIN_SIZE)
		return (EOVERFLOW);
	size += state->domain_count * VIOMMU_STATE_DOMAIN_SIZE;
	if (state->mapping_count >
	    (SIZE_MAX - size) / VIOMMU_STATE_MAPPING_SIZE)
		return (EOVERFLOW);
	size += state->mapping_count * VIOMMU_STATE_MAPPING_SIZE;
	if (state->fault_count >
	    (SIZE_MAX - size) / VIOMMU_STATE_FAULT_SIZE)
		return (EOVERFLOW);
	size += state->fault_count * VIOMMU_STATE_FAULT_SIZE;
	*result = size;
	return (0);
}

static uint32_t
viommu_fault_flags(enum virtio_dma_direction direction)
{

	switch (direction) {
	case VIRTIO_DMA_DEVICE_READ:
		return (BHYVE_VIOMMU_FAULT_F_READ |
		    BHYVE_VIOMMU_FAULT_F_ADDRESS);
	case VIRTIO_DMA_DEVICE_WRITE:
		return (BHYVE_VIOMMU_FAULT_F_WRITE |
		    BHYVE_VIOMMU_FAULT_F_ADDRESS);
	case VIRTIO_DMA_BIDIRECTIONAL:
		return (BHYVE_VIOMMU_FAULT_F_READ |
		    BHYVE_VIOMMU_FAULT_F_WRITE |
		    BHYVE_VIOMMU_FAULT_F_ADDRESS);
	default:
		return (BHYVE_VIOMMU_FAULT_F_ADDRESS);
	}
}

static void
viommu_fault_drop_locked(struct virtio_iommu_state *state)
{

	/*
	 * This counter is persisted in migration state.  Saturate rather than
	 * wrapping so a restored maximum value cannot make later loss appear
	 * to have never happened.
	 */
	if (state->fault_dropped != UINT64_MAX)
		state->fault_dropped++;
}

static void
viommu_fault_enqueue_locked(struct virtio_iommu_state *state,
    uint32_t endpoint, enum virtio_iommu_fault_reason reason,
    uint64_t address, enum virtio_dma_direction direction)
{

	if (state->limits.max_faults == 0) {
		viommu_fault_drop_locked(state);
		return;
	}
	if (state->fault_count == state->limits.max_faults) {
		/*
		 * Preserve the oldest report, which identifies the first
		 * failure in a burst, and account for every later loss.
		 */
		viommu_fault_drop_locked(state);
		return;
	}
	state->faults[state->fault_tail] = (struct virtio_iommu_fault) {
		.reason = reason,
		.flags = viommu_fault_flags(direction),
		.endpoint = endpoint,
		.address = address,
	};
	state->fault_tail =
	    (state->fault_tail + 1) % state->limits.max_faults;
	state->fault_count++;
}

static bool
viommu_direction_allowed(uint32_t flags, enum virtio_dma_direction direction)
{

	switch (direction) {
	case VIRTIO_DMA_DEVICE_READ:
		return ((flags & BHYVE_VIOMMU_MAP_F_READ) != 0);
	case VIRTIO_DMA_DEVICE_WRITE:
		return ((flags & BHYVE_VIOMMU_MAP_F_WRITE) != 0);
	case VIRTIO_DMA_BIDIRECTIONAL:
		return ((flags & (BHYVE_VIOMMU_MAP_F_READ |
		    BHYVE_VIOMMU_MAP_F_WRITE)) ==
		    (BHYVE_VIOMMU_MAP_F_READ | BHYVE_VIOMMU_MAP_F_WRITE));
	default:
		return (false);
	}
}

static struct viommu_endpoint *
viommu_endpoint_find(struct virtio_iommu_state *state, uint32_t endpoint)
{

	for (uint32_t i = 0; i < state->limits.max_endpoints; i++) {
		if (state->endpoints[i].present &&
		    state->endpoints[i].id == endpoint)
			return (&state->endpoints[i]);
	}
	return (NULL);
}

static struct viommu_domain *
viommu_domain_find(struct virtio_iommu_state *state, uint32_t domain)
{

	for (uint32_t i = 0; i < state->limits.max_domains; i++) {
		if (state->domains[i].present && state->domains[i].id == domain)
			return (&state->domains[i]);
	}
	return (NULL);
}

static struct viommu_domain *
viommu_domain_free(struct virtio_iommu_state *state)
{

	for (uint32_t i = 0; i < state->limits.max_domains; i++) {
		if (!state->domains[i].present)
			return (&state->domains[i]);
	}
	return (NULL);
}

static int
viommu_mapping_compare(const void *left, const void *right)
{
	const struct viommu_mapping *a, *b;

	a = left;
	b = right;
	if (a->domain != b->domain)
		return (a->domain < b->domain ? -1 : 1);
	if (a->virtual_start != b->virtual_start)
		return (a->virtual_start < b->virtual_start ? -1 : 1);
	if (a->virtual_end != b->virtual_end)
		return (a->virtual_end < b->virtual_end ? -1 : 1);
	return (0);
}

static int
viommu_endpoint_compare(const void *left, const void *right)
{
	const struct viommu_endpoint *a, *b;

	a = left;
	b = right;
	if (a->id != b->id)
		return (a->id < b->id ? -1 : 1);
	return (0);
}

static int
viommu_domain_compare(const void *left, const void *right)
{
	const struct viommu_domain *a, *b;

	a = left;
	b = right;
	if (a->id != b->id)
		return (a->id < b->id ? -1 : 1);
	return (0);
}

static void
viommu_mappings_sort_locked(struct virtio_iommu_state *state)
{

	qsort(state->mappings, state->mapping_count,
	    sizeof(*state->mappings), viommu_mapping_compare);
	state->mapping_scan_limit = state->mapping_count;
}

static void
viommu_domain_remove_mappings(struct virtio_iommu_state *state,
    uint32_t domain)
{
	size_t destination;

	destination = 0;
	for (size_t i = 0; i < state->mapping_count; i++) {
		if (state->mappings[i].domain == domain)
			continue;
		if (destination != i)
			state->mappings[destination] = state->mappings[i];
		destination++;
	}
	memset(&state->mappings[destination], 0,
	    (state->mapping_count - destination) * sizeof(*state->mappings));
	state->mapping_count = destination;
	state->mapping_scan_limit = destination;
}

static void
viommu_domain_drop_endpoint(struct virtio_iommu_state *state,
    struct viommu_endpoint *endpoint)
{
	struct viommu_domain *domain;

	if (!endpoint->attached)
		return;
	domain = viommu_domain_find(state, endpoint->domain);
	if (domain != NULL) {
		if (domain->endpoint_count > 0)
			domain->endpoint_count--;
		if (domain->endpoint_count == 0) {
			viommu_domain_remove_mappings(state, domain->id);
			memset(domain, 0, sizeof(*domain));
			state->domain_count--;
		}
	}
	endpoint->domain = 0;
	endpoint->attached = false;
}

static bool
viommu_domain_dma_active(struct virtio_iommu_state *state, uint32_t domain)
{

	for (uint32_t i = 0; i < state->limits.max_endpoints; i++) {
		if (state->endpoints[i].present &&
		    state->endpoints[i].attached &&
		    state->endpoints[i].domain == domain &&
		    state->endpoints[i].active_dma != 0)
			return (true);
	}
	return (false);
}

static bool
viommu_any_dma_active(struct virtio_iommu_state *state)
{

	for (uint32_t i = 0; i < state->limits.max_endpoints; i++) {
		if (state->endpoints[i].present &&
		    state->endpoints[i].active_dma != 0)
			return (true);
	}
	return (false);
}

/*
 * Resolve one device DMA transaction without assuming that the guest issued
 * one MAP command for the complete descriptor.  Adjacent mappings are a
 * legal way to describe one contiguous IOVA range.  The existing mapper API
 * returns one host pointer, so such mappings can be coalesced only when their
 * translated physical ranges are contiguous and grant the same requested
 * access.  A gap, permission transition, or physically discontiguous range
 * fails closed and is reported as one mapping fault.
 */
static bool
viommu_translate_range_locked(struct virtio_iommu_state *state,
    uint32_t domain, uint64_t address, uint64_t last,
    enum virtio_dma_direction direction, uint64_t *physical)
{
	struct viommu_mapping *mapping;
	uint64_t cursor, expected_physical, segment_last;
	size_t index;
	bool first;

	cursor = address;
	expected_physical = 0;
	first = true;
	index = 0;
	for (;;) {
		mapping = NULL;
		for (; index < state->mapping_count; index++) {
			if (state->mappings[index].domain > domain)
				break;
			if (state->mappings[index].domain == domain &&
			    cursor >= state->mappings[index].virtual_start &&
			    cursor <= state->mappings[index].virtual_end) {
				mapping = &state->mappings[index++];
				break;
			}
		}
		if (mapping == NULL ||
		    !viommu_direction_allowed(mapping->flags, direction))
			return (false);
		if (mapping->physical_start >
		    UINT64_MAX - (cursor - mapping->virtual_start))
			return (false);
		if (first) {
			*physical = mapping->physical_start +
			    (cursor - mapping->virtual_start);
			expected_physical = *physical;
			first = false;
		}
		if (mapping->physical_start +
		    (cursor - mapping->virtual_start) != expected_physical)
			return (false);
		segment_last = MIN(last, mapping->virtual_end);
		if (segment_last == last)
			return (true);
		if (segment_last == UINT64_MAX)
			return (false);
		if (expected_physical >
		    UINT64_MAX - (segment_last - cursor + 1))
			return (false);
		expected_physical += segment_last - cursor + 1;
		cursor = segment_last + 1;
	}
}

static void
viommu_reset_locked(struct virtio_iommu_state *state)
{

	memset(state->domains, 0,
	    state->limits.max_domains * sizeof(*state->domains));
	memset(state->mappings, 0,
	    state->limits.max_mappings * sizeof(*state->mappings));
	if (state->limits.max_faults != 0)
		memset(state->faults, 0,
		    state->limits.max_faults * sizeof(*state->faults));
	for (uint32_t i = 0; i < state->limits.max_endpoints; i++) {
		state->endpoints[i].domain = 0;
		state->endpoints[i].attached = false;
		state->endpoints[i].dma_bypass = false;
	}
	state->domain_count = 0;
	state->mapping_count = 0;
	state->mapping_scan_limit = 0;
	state->fault_count = 0;
	state->fault_head = 0;
	state->fault_tail = 0;
	state->fault_dropped = 0;
	state->reset_pending = false;
	/*
	 * Restore the boot-time default-bypass policy.  Otherwise a guest that
	 * set config.bypass=1 before resetting the device would leave every
	 * now-detached endpoint translating as identity bypass (full guest
	 * memory DMA) instead of the isolation a freshly reset IOMMU requires.
	 */
	state->limits.default_bypass = state->boot_default_bypass;
	state->generation++;
}

int
virtio_iommu_state_create(const struct virtio_iommu_limits *limits,
    const struct virtio_iommu_ops *ops, struct virtio_iommu_state **result)
{
	struct virtio_iommu_state *state;
	size_t domains_size, endpoints_size, faults_size, mappings_size;
	int error;

	if (limits == NULL || ops == NULL || result == NULL ||
	    ops->map_gpa == NULL || limits->page_size_mask == 0 ||
	    limits->input_start > limits->input_end ||
	    limits->domain_start > limits->domain_end ||
	    limits->max_domains == 0 || limits->max_endpoints == 0 ||
	    limits->max_mappings == 0)
		return (EINVAL);
	if ((error = viommu_array_size(limits->max_endpoints,
	    sizeof(*state->endpoints), &endpoints_size)) != 0 ||
	    (error = viommu_array_size(limits->max_domains,
	    sizeof(*state->domains), &domains_size)) != 0 ||
	    (error = viommu_array_size(limits->max_mappings,
	    sizeof(*state->mappings), &mappings_size)) != 0 ||
	    (limits->max_faults != 0 &&
	    (error = viommu_array_size(limits->max_faults,
	    sizeof(*state->faults), &faults_size)) != 0))
		return (error);
	state = calloc(1, sizeof(*state));
	if (state == NULL)
		return (ENOMEM);
	state->endpoints = calloc(1, endpoints_size);
	state->domains = calloc(1, domains_size);
	state->mappings = calloc(1, mappings_size);
	if (limits->max_faults != 0)
		state->faults = calloc(1, faults_size);
	if (state->endpoints == NULL || state->domains == NULL ||
	    state->mappings == NULL ||
	    (limits->max_faults != 0 && state->faults == NULL)) {
		free(state->faults);
		free(state->mappings);
		free(state->domains);
		free(state->endpoints);
		free(state);
		return (ENOMEM);
	}
	error = pthread_mutex_init(&state->mutex, NULL);
	if (error != 0) {
		free(state->faults);
		free(state->mappings);
		free(state->domains);
		free(state->endpoints);
		free(state);
		return (error);
	}
	state->limits = *limits;
	/*
	 * Remember the power-on default-bypass policy.  A guest may flip the
	 * live config.bypass bit through BYPASS_CONFIG, but a device reset must
	 * return the IOMMU to its construction-time isolation policy so that
	 * newly-detached endpoints do not silently fall back to identity DMA.
	 */
	state->boot_default_bypass = limits->default_bypass;
	state->ops = *ops;
	*result = state;
	return (0);
}

void
virtio_iommu_state_destroy(struct virtio_iommu_state *state)
{

	if (state == NULL)
		return;
	pthread_mutex_destroy(&state->mutex);
	free(state->faults);
	free(state->mappings);
	free(state->domains);
	free(state->endpoints);
	free(state);
}

void
virtio_iommu_state_reset(struct virtio_iommu_state *state)
{

	pthread_mutex_lock(&state->mutex);
	if (viommu_any_dma_active(state))
		state->reset_pending = true;
	else
		viommu_reset_locked(state);
	pthread_mutex_unlock(&state->mutex);
}

bool
virtio_iommu_default_bypass(struct virtio_iommu_state *state)
{
	bool bypass;

	pthread_mutex_lock(&state->mutex);
	bypass = state->limits.default_bypass;
	pthread_mutex_unlock(&state->mutex);
	return (bypass);
}

void
virtio_iommu_set_default_bypass(struct virtio_iommu_state *state, bool bypass)
{

	pthread_mutex_lock(&state->mutex);
	if (state->limits.default_bypass != bypass) {
		/*
		 * This changes authorization for the next non-overlapping DMA
		 * lease epoch on each unattached endpoint.  An endpoint with
		 * accepted work pins its prior address-space selection until
		 * that active set drains, preventing one descriptor request
		 * from being assembled from two address spaces.  Unlike ATTACH,
		 * DETACH, and UNMAP, changing this byte destroys no mapping
		 * object needed by an in-flight request.  Advancing the
		 * generation forces persistent ring mappings to be revalidated
		 * before a later acquisition.
		 */
		state->limits.default_bypass = bypass;
		state->generation++;
	}
	pthread_mutex_unlock(&state->mutex);
}

int
virtio_iommu_state_snapshot_size(struct virtio_iommu_state *state,
    size_t *result)
{
	int error;

	if (state == NULL || result == NULL)
		return (EINVAL);
	pthread_mutex_lock(&state->mutex);
	error = viommu_snapshot_size_locked(state, result);
	pthread_mutex_unlock(&state->mutex);
	return (error);
}

bool
virtio_iommu_state_storage_overlaps(struct virtio_iommu_state *state,
    const void *storage, size_t length)
{
	bool overlaps;

	if (state == NULL || length == 0)
		return (false);
	/*
	 * These allocations and maximum counts are immutable for the lifetime
	 * of state.  Callers already own a live-state reference, so overlap
	 * checks need not serialize ordinary request and event processing on
	 * the IOMMU control mutex.
	 */
	overlaps =
	    virtio_state_ranges_overlap(storage, length, state,
	    sizeof(*state)) ||
	    virtio_state_ranges_overlap(storage, length, state->endpoints,
	    (size_t)state->limits.max_endpoints *
	    sizeof(*state->endpoints)) ||
	    virtio_state_ranges_overlap(storage, length, state->domains,
	    (size_t)state->limits.max_domains * sizeof(*state->domains)) ||
	    virtio_state_ranges_overlap(storage, length, state->mappings,
	    (size_t)state->limits.max_mappings * sizeof(*state->mappings)) ||
	    virtio_state_ranges_overlap(storage, length, state->faults,
	    (size_t)state->limits.max_faults * sizeof(*state->faults));
	return (overlaps);
}

int
virtio_iommu_state_snapshot(struct virtio_iommu_state *state, void *buffer,
    size_t length)
{
	struct viommu_endpoint *endpoint;
	struct viommu_endpoint *endpoints;
	struct viommu_domain *domain;
	struct viommu_domain *domains;
	struct viommu_mapping *mapping;
	uint8_t *bytes, *cursor;
	size_t endpoint_index, domain_index;
	size_t expected;
	int error;

	if (state == NULL || buffer == NULL)
		return (EINVAL);
	endpoints = NULL;
	domains = NULL;
	pthread_mutex_lock(&state->mutex);
	if (viommu_any_dma_active(state)) {
		error = EBUSY;
		goto done;
	}
	error = viommu_snapshot_size_locked(state, &expected);
	if (error != 0)
		goto done;
	if (length != expected) {
		error = EMSGSIZE;
		goto done;
	}
	if (virtio_state_ranges_overlap(buffer, length, state, sizeof(*state)) ||
	    virtio_state_ranges_overlap(buffer, length, state->endpoints,
	    (size_t)state->limits.max_endpoints *
	    sizeof(*state->endpoints)) ||
	    virtio_state_ranges_overlap(buffer, length, state->domains,
	    (size_t)state->limits.max_domains * sizeof(*state->domains)) ||
	    virtio_state_ranges_overlap(buffer, length, state->mappings,
	    state->mapping_scan_limit * sizeof(*state->mappings)) ||
	    virtio_state_ranges_overlap(buffer, length, state->faults,
	    (size_t)state->limits.max_faults * sizeof(*state->faults))) {
		error = EINVAL;
		goto done;
	}
	if (state->endpoint_count != 0) {
		endpoints = calloc(state->endpoint_count, sizeof(*endpoints));
		if (endpoints == NULL) {
			error = ENOMEM;
			goto done;
		}
	}
	if (state->domain_count != 0) {
		domains = calloc(state->domain_count, sizeof(*domains));
		if (domains == NULL) {
			error = ENOMEM;
			goto done;
		}
	}
	endpoint_index = 0;
	for (uint32_t i = 0; i < state->limits.max_endpoints; i++) {
		if (state->endpoints[i].present)
			endpoints[endpoint_index++] = state->endpoints[i];
	}
	domain_index = 0;
	for (uint32_t i = 0; i < state->limits.max_domains; i++) {
		if (state->domains[i].present)
			domains[domain_index++] = state->domains[i];
	}
	if (state->endpoint_count > 1)
		qsort(endpoints, state->endpoint_count, sizeof(*endpoints),
		    viommu_endpoint_compare);
	if (state->domain_count > 1)
		qsort(domains, state->domain_count, sizeof(*domains),
		    viommu_domain_compare);
	bytes = buffer;
	memset(bytes, 0, length);
	le32enc(bytes + 0, VIOMMU_STATE_MAGIC);
	le16enc(bytes + 4, VIOMMU_STATE_VERSION);
	le16enc(bytes + 6, VIOMMU_STATE_HEADER_SIZE);
	le64enc(bytes + 8, length);
	/*
	 * The generation fences destination-local translation caches and is
	 * deliberately advanced after restore.  It is not architectural state,
	 * so its reserved wire slot is always zero.  Restore requires the same
	 * canonical value.
	 */
	le64enc(bytes + 16, 0);
	le64enc(bytes + 24, state->limits.page_size_mask);
	le64enc(bytes + 32, state->limits.input_start);
	le64enc(bytes + 40, state->limits.input_end);
	le32enc(bytes + 48, state->limits.domain_start);
	le32enc(bytes + 52, state->limits.domain_end);
	le32enc(bytes + 56, state->endpoint_count);
	le32enc(bytes + 60, state->domain_count);
	le32enc(bytes + 64, state->mapping_count);
	le32enc(bytes + 68, state->fault_count);
	le32enc(bytes + 72, viommu_state_flags(state));
	le64enc(bytes + 80, state->fault_dropped);
	cursor = bytes + VIOMMU_STATE_HEADER_SIZE;
	for (size_t i = 0; i < state->endpoint_count; i++) {
		endpoint = &endpoints[i];
		le32enc(cursor + 0, endpoint->id);
		le32enc(cursor + 4, endpoint->domain);
		le32enc(cursor + 8, endpoint->attached ?
		    VIOMMU_ENDPOINT_F_ATTACHED : 0);
		cursor += VIOMMU_STATE_ENDPOINT_SIZE;
	}
	for (size_t i = 0; i < state->domain_count; i++) {
		domain = &domains[i];
		le32enc(cursor + 0, domain->id);
		le32enc(cursor + 4, domain->endpoint_count);
		le32enc(cursor + 8, domain->bypass ?
		    VIOMMU_DOMAIN_F_BYPASS : 0);
		cursor += VIOMMU_STATE_DOMAIN_SIZE;
	}
	for (size_t i = 0; i < state->mapping_scan_limit; i++) {
		mapping = &state->mappings[i];
		if (!mapping->present)
			continue;
		le64enc(cursor + 0, mapping->virtual_start);
		le64enc(cursor + 8, mapping->virtual_end);
		le64enc(cursor + 16, mapping->physical_start);
		le32enc(cursor + 24, mapping->domain);
		le32enc(cursor + 28, mapping->flags);
		cursor += VIOMMU_STATE_MAPPING_SIZE;
	}
	for (size_t i = 0; i < state->fault_count; i++) {
		struct virtio_iommu_fault *fault;

		fault = &state->faults[(state->fault_head + i) %
		    state->limits.max_faults];
		cursor[0] = fault->reason;
		le32enc(cursor + 4, fault->flags);
		le32enc(cursor + 8, fault->endpoint);
		le64enc(cursor + 16, fault->address);
		cursor += VIOMMU_STATE_FAULT_SIZE;
	}
	le64enc(bytes + VIOMMU_STATE_DIGEST_OFFSET,
	    viommu_state_digest(bytes, length));
	error = 0;
done:
	pthread_mutex_unlock(&state->mutex);
	free(domains);
	free(endpoints);
	return (error);
}

static int
viommu_state_restore(struct virtio_iommu_state *state, const void *buffer,
    size_t length, bool publish)
{
	struct viommu_endpoint *endpoints;
	struct viommu_domain *domains;
	struct viommu_mapping *mappings;
	struct virtio_iommu_fault *faults;
	const uint8_t *bytes, *cursor;
	uint64_t fault_dropped, map_length;
	uint32_t endpoint_count, domain_count, mapping_count, fault_count, flags;
	size_t expected;
	int error;

	if (state == NULL || buffer == NULL)
		return (EINVAL);
	if (virtio_state_ranges_overlap(buffer, length, state, sizeof(*state)) ||
	    virtio_state_ranges_overlap(buffer, length, state->endpoints,
	    (size_t)state->limits.max_endpoints *
	    sizeof(*state->endpoints)) ||
	    virtio_state_ranges_overlap(buffer, length, state->domains,
	    (size_t)state->limits.max_domains * sizeof(*state->domains)) ||
	    virtio_state_ranges_overlap(buffer, length, state->mappings,
	    (size_t)state->limits.max_mappings * sizeof(*state->mappings)) ||
	    virtio_state_ranges_overlap(buffer, length, state->faults,
	    (size_t)state->limits.max_faults * sizeof(*state->faults)))
		return (EINVAL);
	bytes = buffer;
	if (length < VIOMMU_STATE_HEADER_SIZE ||
	    le32dec(bytes + 0) != VIOMMU_STATE_MAGIC ||
	    le16dec(bytes + 4) != VIOMMU_STATE_VERSION ||
	    le16dec(bytes + 6) != VIOMMU_STATE_HEADER_SIZE ||
	    le64dec(bytes + 8) != length ||
	    le64dec(bytes + 16) != 0 ||
	    le64dec(bytes + VIOMMU_STATE_DIGEST_OFFSET) !=
	    viommu_state_digest(bytes, length))
		return (EPROTO);
	flags = le32dec(bytes + 72);
	if ((flags & ~VIOMMU_STATE_F_MASK) != 0 ||
	    !viommu_state_bytes_zero(bytes + 76, 4) ||
	    le64dec(bytes + 24) != state->limits.page_size_mask ||
	    le64dec(bytes + 32) != state->limits.input_start ||
	    le64dec(bytes + 40) != state->limits.input_end ||
	    le32dec(bytes + 48) != state->limits.domain_start ||
	    le32dec(bytes + 52) != state->limits.domain_end ||
	    (flags & ~VIOMMU_STATE_F_DEFAULT_BYPASS) !=
	    viommu_state_compat_flags(state))
		return (EINVAL);
	endpoint_count = le32dec(bytes + 56);
	domain_count = le32dec(bytes + 60);
	mapping_count = le32dec(bytes + 64);
	fault_count = le32dec(bytes + 68);
	if (endpoint_count > state->limits.max_endpoints ||
	    domain_count > state->limits.max_domains ||
	    mapping_count > state->limits.max_mappings ||
	    fault_count > state->limits.max_faults)
		return (E2BIG);
	expected = VIOMMU_STATE_HEADER_SIZE;
	if (endpoint_count > (SIZE_MAX - expected) /
	    VIOMMU_STATE_ENDPOINT_SIZE)
		return (EPROTO);
	expected += endpoint_count * VIOMMU_STATE_ENDPOINT_SIZE;
	if (domain_count > (SIZE_MAX - expected) / VIOMMU_STATE_DOMAIN_SIZE)
		return (EPROTO);
	expected += domain_count * VIOMMU_STATE_DOMAIN_SIZE;
	if (mapping_count >
	    (SIZE_MAX - expected) / VIOMMU_STATE_MAPPING_SIZE)
		return (EPROTO);
	expected += mapping_count * VIOMMU_STATE_MAPPING_SIZE;
	if (fault_count > (SIZE_MAX - expected) / VIOMMU_STATE_FAULT_SIZE)
		return (EPROTO);
	expected += fault_count * VIOMMU_STATE_FAULT_SIZE;
	if (expected != length)
		return (EPROTO);

	endpoints = calloc(state->limits.max_endpoints, sizeof(*endpoints));
	domains = calloc(state->limits.max_domains, sizeof(*domains));
	mappings = calloc(state->limits.max_mappings, sizeof(*mappings));
	faults = state->limits.max_faults == 0 ? NULL :
	    calloc(state->limits.max_faults, sizeof(*faults));
	if (endpoints == NULL || domains == NULL || mappings == NULL ||
	    (state->limits.max_faults != 0 && faults == NULL)) {
		error = ENOMEM;
		goto out;
	}
	cursor = bytes + VIOMMU_STATE_HEADER_SIZE;
	for (uint32_t i = 0; i < endpoint_count; i++) {
		uint32_t endpoint_flags;

		endpoints[i].id = le32dec(cursor + 0);
		endpoints[i].domain = le32dec(cursor + 4);
		endpoint_flags = le32dec(cursor + 8);
		if ((endpoint_flags & ~VIOMMU_ENDPOINT_F_ATTACHED) != 0) {
			error = EPROTO;
			goto out;
		}
		endpoints[i].present = true;
		endpoints[i].attached =
		    (endpoint_flags & VIOMMU_ENDPOINT_F_ATTACHED) != 0;
		if (!endpoints[i].attached && endpoints[i].domain != 0) {
			error = EPROTO;
			goto out;
		}
		if (i != 0 && viommu_endpoint_compare(&endpoints[i - 1],
		    &endpoints[i]) >= 0) {
			error = EPROTO;
			goto out;
		}
		cursor += VIOMMU_STATE_ENDPOINT_SIZE;
	}
	for (uint32_t i = 0; i < domain_count; i++) {
		uint32_t domain_flags;

		domains[i].id = le32dec(cursor + 0);
		domains[i].endpoint_count = le32dec(cursor + 4);
		domain_flags = le32dec(cursor + 8);
		if ((domain_flags & ~VIOMMU_DOMAIN_F_BYPASS) != 0 ||
		    !viommu_state_bytes_zero(cursor + 12, 4) ||
		    domains[i].endpoint_count == 0 ||
		    domains[i].id < state->limits.domain_start ||
		    domains[i].id > state->limits.domain_end) {
			error = EPROTO;
			goto out;
		}
		domains[i].present = true;
		domains[i].bypass =
		    (domain_flags & VIOMMU_DOMAIN_F_BYPASS) != 0;
		if (domains[i].bypass && !state->limits.bypass_domains) {
			error = EPROTO;
			goto out;
		}
		if (i != 0 && viommu_domain_compare(&domains[i - 1],
		    &domains[i]) >= 0) {
			error = EPROTO;
			goto out;
		}
		cursor += VIOMMU_STATE_DOMAIN_SIZE;
	}
	for (uint32_t i = 0; i < endpoint_count; i++) {
		struct viommu_domain *domain;

		if (!endpoints[i].attached)
			continue;
		domain = NULL;
		for (uint32_t j = 0; j < domain_count; j++) {
			if (domains[j].id == endpoints[i].domain) {
				domain = &domains[j];
				break;
			}
		}
		if (domain == NULL) {
			error = EPROTO;
			goto out;
		}
		domain->endpoint_count--;
	}
	for (uint32_t i = 0; i < domain_count; i++) {
		if (domains[i].endpoint_count != 0) {
			error = EPROTO;
			goto out;
		}
		/* Restore the verified count below while rewalking endpoints. */
	}
	for (uint32_t i = 0; i < endpoint_count; i++) {
		if (!endpoints[i].attached)
			continue;
		for (uint32_t j = 0; j < domain_count; j++) {
			if (domains[j].id == endpoints[i].domain) {
				domains[j].endpoint_count++;
				break;
			}
		}
	}
	for (uint32_t i = 0; i < mapping_count; i++) {
		struct viommu_domain *domain;
		uint64_t granularity;

		mappings[i].virtual_start = le64dec(cursor + 0);
		mappings[i].virtual_end = le64dec(cursor + 8);
		mappings[i].physical_start = le64dec(cursor + 16);
		mappings[i].domain = le32dec(cursor + 24);
		mappings[i].flags = le32dec(cursor + 28);
		if (!viommu_state_bytes_zero(cursor + 32, 8) ||
		    (mappings[i].flags & ~BHYVE_VIOMMU_MAP_F_MASK) != 0 ||
		    ((mappings[i].flags & BHYVE_VIOMMU_MAP_F_MMIO) != 0 &&
		    !state->limits.allow_mmio) ||
		    mappings[i].virtual_end <= mappings[i].virtual_start ||
		    mappings[i].virtual_start < state->limits.input_start ||
		    mappings[i].virtual_end > state->limits.input_end) {
			error = EPROTO;
			goto out;
		}
		granularity = (uint64_t)1 << __builtin_ctzll(
		    state->limits.page_size_mask);
		map_length = mappings[i].virtual_end -
		    mappings[i].virtual_start + 1;
		if (map_length == 0 ||
		    mappings[i].virtual_start % granularity != 0 ||
		    mappings[i].physical_start % granularity != 0 ||
		    (mappings[i].virtual_end + 1) % granularity != 0 ||
		    mappings[i].physical_start >
		    UINT64_MAX - (map_length - 1) ||
		    (state->ops.validate_gpa != NULL &&
		    !state->ops.validate_gpa(state->ops.arg,
		    mappings[i].physical_start, map_length,
		    mappings[i].flags))) {
			error = EPROTO;
			goto out;
		}
		domain = NULL;
		for (uint32_t j = 0; j < domain_count; j++) {
			if (domains[j].id == mappings[i].domain) {
				domain = &domains[j];
				break;
			}
		}
		if (domain == NULL || domain->bypass) {
			error = EPROTO;
			goto out;
		}
		mappings[i].present = true;
		if (i != 0 && viommu_mapping_compare(&mappings[i - 1],
		    &mappings[i]) >= 0) {
			error = EPROTO;
			goto out;
		}
		cursor += VIOMMU_STATE_MAPPING_SIZE;
	}
	for (uint32_t i = 1; i < mapping_count; i++) {
		if (mappings[i - 1].domain == mappings[i].domain &&
		    mappings[i].virtual_start <= mappings[i - 1].virtual_end) {
			error = EPROTO;
			goto out;
		}
	}
	for (uint32_t i = 0; i < fault_count; i++) {
		faults[i].reason = cursor[0];
		faults[i].flags = le32dec(cursor + 4);
		faults[i].endpoint = le32dec(cursor + 8);
		faults[i].address = le64dec(cursor + 16);
		if (!viommu_state_bytes_zero(cursor + 1, 3) ||
		    !viommu_state_bytes_zero(cursor + 12, 4) ||
		    faults[i].reason > BHYVE_VIOMMU_FAULT_MAPPING ||
		    (faults[i].flags & ~(BHYVE_VIOMMU_FAULT_F_READ |
		    BHYVE_VIOMMU_FAULT_F_WRITE |
		    BHYVE_VIOMMU_FAULT_F_ADDRESS)) != 0 ||
		    (faults[i].flags & BHYVE_VIOMMU_FAULT_F_ADDRESS) == 0) {
			error = EPROTO;
			goto out;
		}
		cursor += VIOMMU_STATE_FAULT_SIZE;
	}
	fault_dropped = le64dec(bytes + 80);
	pthread_mutex_lock(&state->mutex);
	if (viommu_any_dma_active(state)) {
		error = EBUSY;
		goto unlock;
	}
	/*
	 * The generation is a destination-local invalidation epoch, not
	 * portable device state.  Reusing the saved value could make a queue
	 * mapping cached before a repeated restore appear current even though
	 * the restored mappings differ.  Advance the live epoch only after the
	 * complete image has been validated.
	 */
	if (state->generation == UINT64_MAX) {
		error = EOVERFLOW;
		goto unlock;
	}
	if (state->endpoint_count != endpoint_count) {
		error = EINVAL;
		goto unlock;
	}
	for (uint32_t i = 0; i < state->limits.max_endpoints; i++) {
		bool found;

		if (!state->endpoints[i].present)
			continue;
		found = false;
		for (uint32_t j = 0; j < endpoint_count; j++) {
			if (endpoints[j].id == state->endpoints[i].id) {
				found = true;
				break;
			}
		}
		if (!found) {
			error = EINVAL;
			goto unlock;
		}
	}
	if (!publish) {
		error = 0;
		goto unlock;
	}
	memcpy(state->endpoints, endpoints,
	    state->limits.max_endpoints * sizeof(*endpoints));
	memcpy(state->domains, domains,
	    state->limits.max_domains * sizeof(*domains));
	memcpy(state->mappings, mappings,
	    state->limits.max_mappings * sizeof(*mappings));
	if (state->limits.max_faults != 0)
		memcpy(state->faults, faults,
		    state->limits.max_faults * sizeof(*faults));
	state->domain_count = domain_count;
	state->mapping_count = mapping_count;
	state->mapping_scan_limit = mapping_count;
	state->fault_count = fault_count;
	state->fault_head = 0;
	state->fault_tail = state->limits.max_faults == 0 ? 0 :
	    fault_count % state->limits.max_faults;
	state->fault_dropped = fault_dropped;
	state->limits.default_bypass =
	    (flags & VIOMMU_STATE_F_DEFAULT_BYPASS) != 0;
	state->generation++;
	error = 0;
unlock:
	pthread_mutex_unlock(&state->mutex);
out:
	free(faults);
	free(mappings);
	free(domains);
	free(endpoints);
	return (error);
}

int
virtio_iommu_state_restore_validate(struct virtio_iommu_state *state,
    const void *buffer, size_t length)
{

	return (viommu_state_restore(state, buffer, length, false));
}

int
virtio_iommu_state_restore_prepare(struct virtio_iommu_state *state,
    const void *buffer, size_t length, struct virtio_iommu_state **preparedp)
{
	struct virtio_iommu_state *prepared;
	struct virtio_iommu_limits limits;
	struct virtio_iommu_ops ops;
	uint32_t *endpoint_ids;
	size_t endpoint_count;
	int error;

	if (state == NULL || buffer == NULL || preparedp == NULL)
		return (EINVAL);
	*preparedp = NULL;
	error = viommu_state_restore(state, buffer, length, false);
	if (error != 0)
		return (error);

	endpoint_ids = calloc(state->limits.max_endpoints,
	    sizeof(*endpoint_ids));
	if (endpoint_ids == NULL)
		return (ENOMEM);
	pthread_mutex_lock(&state->mutex);
	limits = state->limits;
	ops = state->ops;
	endpoint_count = 0;
	for (uint32_t i = 0; i < state->limits.max_endpoints; i++) {
		if (state->endpoints[i].present)
			endpoint_ids[endpoint_count++] = state->endpoints[i].id;
	}
	pthread_mutex_unlock(&state->mutex);

	/*
	 * A prepared view is used only to validate endpoint DMA addresses.
	 * It must map destination GPAs, but it must not publish faults or idle
	 * notifications to the live device while preflight is still reversible.
	 */
	ops.fault = NULL;
	ops.dma_idle = NULL;
	prepared = NULL;
	error = virtio_iommu_state_create(&limits, &ops, &prepared);
	if (error != 0)
		goto done;
	for (size_t i = 0; i < endpoint_count; i++) {
		if (virtio_iommu_endpoint_register(prepared, endpoint_ids[i]) !=
		    BHYVE_VIOMMU_S_OK) {
			error = EINVAL;
			goto done;
		}
	}
	error = viommu_state_restore(prepared, buffer, length, true);
	if (error != 0)
		goto done;
	*preparedp = prepared;
	prepared = NULL;
done:
	virtio_iommu_state_destroy(prepared);
	free(endpoint_ids);
	return (error);
}

int
virtio_iommu_state_restore(struct virtio_iommu_state *state,
    const void *buffer, size_t length)
{

	return (viommu_state_restore(state, buffer, length, true));
}

enum virtio_iommu_status
virtio_iommu_endpoint_register(struct virtio_iommu_state *state,
    uint32_t endpoint)
{
	struct viommu_endpoint *entry;
	enum virtio_iommu_status status;

	pthread_mutex_lock(&state->mutex);
	if (state->reset_pending) {
		status = BHYVE_VIOMMU_S_BUSY;
		goto done;
	}
	if (viommu_endpoint_find(state, endpoint) != NULL) {
		status = BHYVE_VIOMMU_S_INVAL;
		goto done;
	}
	if (state->endpoint_count == state->limits.max_endpoints) {
		status = BHYVE_VIOMMU_S_NOMEM;
		goto done;
	}
	entry = NULL;
	for (uint32_t i = 0; i < state->limits.max_endpoints; i++) {
		if (!state->endpoints[i].present) {
			entry = &state->endpoints[i];
			break;
		}
	}
	if (entry == NULL) {
		status = BHYVE_VIOMMU_S_NOMEM;
		goto done;
	}
	entry->id = endpoint;
	entry->present = true;
	state->endpoint_count++;
	state->generation++;
	status = BHYVE_VIOMMU_S_OK;
done:
	pthread_mutex_unlock(&state->mutex);
	return (status);
}

enum virtio_iommu_status
virtio_iommu_endpoint_unregister(struct virtio_iommu_state *state,
    uint32_t endpoint)
{
	struct viommu_endpoint *entry;
	enum virtio_iommu_status status;

	pthread_mutex_lock(&state->mutex);
	if (state->reset_pending) {
		status = BHYVE_VIOMMU_S_BUSY;
		goto done;
	}
	entry = viommu_endpoint_find(state, endpoint);
	if (entry == NULL) {
		status = BHYVE_VIOMMU_S_NOENT;
		goto done;
	}
	if (entry->active_dma != 0) {
		status = BHYVE_VIOMMU_S_BUSY;
		goto done;
	}
	viommu_domain_drop_endpoint(state, entry);
	memset(entry, 0, sizeof(*entry));
	state->endpoint_count--;
	state->generation++;
	status = BHYVE_VIOMMU_S_OK;
done:
	pthread_mutex_unlock(&state->mutex);
	return (status);
}

bool
virtio_iommu_endpoint_registered(struct virtio_iommu_state *state,
    uint32_t endpoint)
{
	bool registered;

	pthread_mutex_lock(&state->mutex);
	registered = viommu_endpoint_find(state, endpoint) != NULL;
	pthread_mutex_unlock(&state->mutex);
	return (registered);
}

enum virtio_iommu_status
virtio_iommu_attach(struct virtio_iommu_state *state, uint32_t domain_id,
    uint32_t endpoint_id, uint32_t flags)
{
	struct viommu_domain *domain;
	struct viommu_domain *old_domain;
	struct viommu_endpoint *endpoint;
	bool bypass;
	enum virtio_iommu_status status;

	if ((flags & ~BHYVE_VIOMMU_ATTACH_F_BYPASS) != 0 ||
	    ((flags & BHYVE_VIOMMU_ATTACH_F_BYPASS) != 0 &&
	    !state->limits.bypass_domains))
		return (BHYVE_VIOMMU_S_INVAL);
	if (domain_id < state->limits.domain_start ||
	    domain_id > state->limits.domain_end)
		return (BHYVE_VIOMMU_S_RANGE);
	bypass = (flags & BHYVE_VIOMMU_ATTACH_F_BYPASS) != 0;
	pthread_mutex_lock(&state->mutex);
	if (state->reset_pending) {
		status = BHYVE_VIOMMU_S_BUSY;
		goto done;
	}
	endpoint = viommu_endpoint_find(state, endpoint_id);
	if (endpoint == NULL) {
		status = BHYVE_VIOMMU_S_NOENT;
		goto done;
	}
	domain = viommu_domain_find(state, domain_id);
	if (domain != NULL && domain->bypass != bypass) {
		status = BHYVE_VIOMMU_S_INVAL;
		goto done;
	}
	if (endpoint->attached && endpoint->domain == domain_id) {
		status = BHYVE_VIOMMU_S_OK;
		goto done;
	}
	if (endpoint->active_dma != 0) {
		status = BHYVE_VIOMMU_S_BUSY;
		goto done;
	}
	if (domain == NULL) {
		domain = viommu_domain_free(state);
		/*
		 * Moving the sole endpoint out of a domain may reuse that
		 * domain's slot.  Decide this before changing either domain so
		 * an allocation failure leaves the old attachment intact.
		 */
		if (domain == NULL && endpoint->attached) {
			old_domain = viommu_domain_find(state, endpoint->domain);
			if (old_domain != NULL &&
			    old_domain->endpoint_count == 1)
				domain = old_domain;
		}
		if (domain == NULL) {
			status = BHYVE_VIOMMU_S_NOMEM;
			goto done;
		}
	}
	viommu_domain_drop_endpoint(state, endpoint);
	if (!domain->present) {
		domain->id = domain_id;
		domain->present = true;
		domain->bypass = bypass;
		state->domain_count++;
	}
	domain->endpoint_count++;
	endpoint->domain = domain_id;
	endpoint->attached = true;
	state->generation++;
	status = BHYVE_VIOMMU_S_OK;
done:
	pthread_mutex_unlock(&state->mutex);
	return (status);
}

enum virtio_iommu_status
virtio_iommu_detach(struct virtio_iommu_state *state, uint32_t domain_id,
    uint32_t endpoint_id)
{
	struct viommu_endpoint *endpoint;
	enum virtio_iommu_status status;

	pthread_mutex_lock(&state->mutex);
	if (state->reset_pending) {
		status = BHYVE_VIOMMU_S_BUSY;
		goto done;
	}
	endpoint = viommu_endpoint_find(state, endpoint_id);
	if (endpoint == NULL) {
		status = BHYVE_VIOMMU_S_NOENT;
		goto done;
	}
	if (!endpoint->attached || endpoint->domain != domain_id) {
		status = BHYVE_VIOMMU_S_INVAL;
		goto done;
	}
	if (endpoint->active_dma != 0) {
		status = BHYVE_VIOMMU_S_BUSY;
		goto done;
	}
	viommu_domain_drop_endpoint(state, endpoint);
	state->generation++;
	status = BHYVE_VIOMMU_S_OK;
done:
	pthread_mutex_unlock(&state->mutex);
	return (status);
}

enum virtio_iommu_status
virtio_iommu_map(struct virtio_iommu_state *state, uint32_t domain_id,
    uint64_t virtual_start, uint64_t virtual_end, uint64_t physical_start,
    uint32_t flags)
{
	struct viommu_domain *domain;
	struct viommu_mapping *mapping;
	uint64_t granularity, length;
	enum virtio_iommu_status status;

	if ((flags & ~BHYVE_VIOMMU_MAP_F_MASK) != 0 ||
	    ((flags & BHYVE_VIOMMU_MAP_F_MMIO) != 0 &&
	    !state->limits.allow_mmio))
		return (BHYVE_VIOMMU_S_INVAL);
	if (virtual_end <= virtual_start ||
	    virtual_start < state->limits.input_start ||
	    virtual_end > state->limits.input_end)
		return (BHYVE_VIOMMU_S_RANGE);
	granularity = (uint64_t)1 << __builtin_ctzll(
	    state->limits.page_size_mask);
	if (virtual_start % granularity != 0 ||
	    physical_start % granularity != 0 ||
	    (virtual_end + 1) % granularity != 0)
		return (BHYVE_VIOMMU_S_RANGE);
	length = virtual_end - virtual_start + 1;
	if (length == 0 || physical_start > UINT64_MAX - (length - 1))
		return (BHYVE_VIOMMU_S_RANGE);
	if (state->ops.validate_gpa != NULL &&
	    !state->ops.validate_gpa(state->ops.arg, physical_start, length,
	    flags))
		return (BHYVE_VIOMMU_S_RANGE);
	pthread_mutex_lock(&state->mutex);
	if (state->reset_pending) {
		status = BHYVE_VIOMMU_S_BUSY;
		goto done;
	}
	domain = viommu_domain_find(state, domain_id);
	if (domain == NULL) {
		status = BHYVE_VIOMMU_S_NOENT;
		goto done;
	}
	if (domain->bypass) {
		status = BHYVE_VIOMMU_S_INVAL;
		goto done;
	}
	for (size_t i = 0; i < state->mapping_count; i++) {
		mapping = &state->mappings[i];
		if (mapping->domain == domain_id &&
		    virtual_start <= mapping->virtual_end &&
		    mapping->virtual_start <= virtual_end) {
			status = BHYVE_VIOMMU_S_INVAL;
			goto done;
		}
	}
	if (state->mapping_count == state->limits.max_mappings) {
		status = BHYVE_VIOMMU_S_NOMEM;
		goto done;
	}
	mapping = &state->mappings[state->mapping_count];
	*mapping = (struct viommu_mapping) {
		.virtual_start = virtual_start,
		.virtual_end = virtual_end,
		.physical_start = physical_start,
		.domain = domain_id,
		.flags = flags,
		.present = true,
	};
	state->mapping_count++;
	viommu_mappings_sort_locked(state);
	state->generation++;
	status = BHYVE_VIOMMU_S_OK;
done:
	pthread_mutex_unlock(&state->mutex);
	return (status);
}

enum virtio_iommu_status
virtio_iommu_unmap(struct virtio_iommu_state *state, uint32_t domain_id,
    uint64_t virtual_start, uint64_t virtual_end)
{
	struct viommu_domain *domain;
	struct viommu_mapping *mapping;
	bool changed;
	enum virtio_iommu_status status;

	if (virtual_start > virtual_end)
		return (BHYVE_VIOMMU_S_RANGE);
	pthread_mutex_lock(&state->mutex);
	if (state->reset_pending) {
		status = BHYVE_VIOMMU_S_BUSY;
		goto done;
	}
	domain = viommu_domain_find(state, domain_id);
	if (domain == NULL) {
		status = BHYVE_VIOMMU_S_NOENT;
		goto done;
	}
	if (domain->bypass) {
		status = BHYVE_VIOMMU_S_INVAL;
		goto done;
	}
	changed = false;
	for (size_t i = 0; i < state->mapping_count; i++) {
		mapping = &state->mappings[i];
		if (mapping->domain != domain_id ||
		    virtual_start > mapping->virtual_end ||
		    mapping->virtual_start > virtual_end)
			continue;
		if (virtual_start > mapping->virtual_start ||
		    virtual_end < mapping->virtual_end) {
			status = BHYVE_VIOMMU_S_RANGE;
			goto done;
		}
		changed = true;
	}
	if (changed && viommu_domain_dma_active(state, domain_id)) {
		status = BHYVE_VIOMMU_S_BUSY;
		goto done;
	}
	size_t destination;

	destination = 0;
	for (size_t i = 0; i < state->mapping_count; i++) {
		mapping = &state->mappings[i];
		if (mapping->domain != domain_id ||
		    virtual_start > mapping->virtual_end ||
		    mapping->virtual_start > virtual_end) {
			if (destination != i)
				state->mappings[destination] = *mapping;
			destination++;
		}
	}
	if (changed) {
		memset(&state->mappings[destination], 0,
		    (state->mapping_count - destination) *
		    sizeof(*state->mappings));
		state->mapping_count = destination;
		state->mapping_scan_limit = destination;
		state->generation++;
	}
	status = BHYVE_VIOMMU_S_OK;
done:
	pthread_mutex_unlock(&state->mutex);
	return (status);
}

bool
virtio_iommu_dma_acquire(struct virtio_iommu_state *state,
    uint32_t endpoint_id)
{
	struct viommu_endpoint *endpoint;
	bool acquired;

	pthread_mutex_lock(&state->mutex);
	endpoint = viommu_endpoint_find(state, endpoint_id);
	acquired = endpoint != NULL && !state->reset_pending &&
	    endpoint->active_dma != UINT32_MAX;
	if (acquired) {
		if (endpoint->active_dma == 0) {
			struct viommu_domain *domain;

			endpoint->dma_bypass = state->limits.default_bypass;
			if (endpoint->attached) {
				domain = viommu_domain_find(state,
				    endpoint->domain);
				/*
				 * An attached endpoint always names a live
				 * domain; retain the defensive fallback so a
				 * corrupt internal topology cannot gain bypass.
				 */
				endpoint->dma_bypass =
				    domain != NULL && domain->bypass;
			}
		}
		endpoint->active_dma++;
	}
	pthread_mutex_unlock(&state->mutex);
	return (acquired);
}

void
virtio_iommu_dma_release(struct virtio_iommu_state *state,
    uint32_t endpoint_id)
{
	struct viommu_endpoint *endpoint;
	void (*idle)(void *, uint32_t);
	void *arg;
	bool notify;

	notify = false;
	idle = NULL;
	arg = NULL;
	pthread_mutex_lock(&state->mutex);
	endpoint = viommu_endpoint_find(state, endpoint_id);
	if (endpoint != NULL && endpoint->active_dma != 0) {
		endpoint->active_dma--;
		notify = endpoint->active_dma == 0;
		if (notify && !endpoint->attached &&
		    endpoint->dma_bypass != state->limits.default_bypass) {
			/*
			 * A queue mapping may have been refreshed after the
			 * config write while this endpoint still used its
			 * pinned old address space.  Publish one more epoch
			 * edge as that old lease set drains so the next
			 * request cannot reuse such a mapping.
			 */
			state->generation++;
		}
	}
	if (state->reset_pending && !viommu_any_dma_active(state))
		viommu_reset_locked(state);
	if (notify) {
		idle = state->ops.dma_idle;
		arg = state->ops.arg;
	}
	pthread_mutex_unlock(&state->mutex);
	if (idle != NULL)
		idle(arg, endpoint_id);
}

void *
virtio_iommu_translate(struct virtio_iommu_state *state, uint32_t endpoint_id,
    uint64_t address, size_t length, enum virtio_dma_direction direction)
{
	struct viommu_endpoint *endpoint;
	struct viommu_domain *domain;
	enum virtio_iommu_fault_reason reason;
	uint64_t physical, last;
	bool bypass;
	void *result;

	reason = BHYVE_VIOMMU_FAULT_MAPPING;
	result = NULL;
	physical = 0;
	if (length == 0 || address > UINT64_MAX - (length - 1))
		goto record_fault;
	last = address + length - 1;
	pthread_mutex_lock(&state->mutex);
	endpoint = viommu_endpoint_find(state, endpoint_id);
	if (endpoint == NULL) {
		reason = BHYVE_VIOMMU_FAULT_UNKNOWN;
		goto unlock_fault;
	}
	/*
	 * Pin the endpoint's address-space selection for the complete set of
	 * overlapping request leases.  A BYPASS_CONFIG write may race another
	 * vCPU processing a descriptor chain; without this pin, one chain
	 * could map its ring through the old address space and its payload
	 * through the new one.  The next lease after the active set drains
	 * observes the new configuration.
	 */
	bypass = endpoint->active_dma != 0 ? endpoint->dma_bypass :
	    state->limits.default_bypass;
	if (endpoint->attached) {
		domain = viommu_domain_find(state, endpoint->domain);
		if (domain == NULL) {
			reason = BHYVE_VIOMMU_FAULT_DOMAIN;
			goto unlock_fault;
		}
		if (endpoint->active_dma == 0)
			bypass = domain->bypass;
	}
	if (bypass) {
		physical = address;
		goto unlock_map;
	}
	if (!endpoint->attached) {
		reason = BHYVE_VIOMMU_FAULT_DOMAIN;
		goto unlock_fault;
	}
	if (viommu_translate_range_locked(state, endpoint->domain, address, last,
	    direction, &physical))
		goto unlock_map;
unlock_fault:
	viommu_fault_enqueue_locked(state, endpoint_id, reason, address,
	    direction);
	pthread_mutex_unlock(&state->mutex);
	goto notify_fault;
unlock_map:
	pthread_mutex_unlock(&state->mutex);
	/*
	 * Authorization is linearized while holding the state mutex, but the
	 * platform mapper is an external callback and must not run under it.
	 * Guest RAM remains pinned by the VM while a device request is active.
	 * The request-level DMA lease orders revoking ATTACH, DETACH, and UNMAP
	 * operations after every pointer authorized before their completion.
	 */
	result = state->ops.map_gpa(state->ops.arg, physical, length,
	    direction);
	if (result != NULL)
		return (result);
record_fault:
	pthread_mutex_lock(&state->mutex);
	viommu_fault_enqueue_locked(state, endpoint_id, reason, address,
	    direction);
	pthread_mutex_unlock(&state->mutex);
notify_fault:
	if (state->ops.fault != NULL)
		state->ops.fault(state->ops.arg, endpoint_id, reason, address,
		    direction);
	return (NULL);
}

bool
virtio_iommu_fault_pop(struct virtio_iommu_state *state,
    struct virtio_iommu_fault *fault)
{
	bool present;

	if (state == NULL || fault == NULL)
		return (false);
	pthread_mutex_lock(&state->mutex);
	present = state->fault_count != 0;
	if (present) {
		*fault = state->faults[state->fault_head];
		memset(&state->faults[state->fault_head], 0,
		    sizeof(state->faults[state->fault_head]));
		state->fault_head =
		    (state->fault_head + 1) % state->limits.max_faults;
		state->fault_count--;
	}
	pthread_mutex_unlock(&state->mutex);
	return (present);
}

uint64_t
virtio_iommu_fault_dropped(struct virtio_iommu_state *state)
{
	uint64_t dropped;

	pthread_mutex_lock(&state->mutex);
	dropped = state->fault_dropped;
	pthread_mutex_unlock(&state->mutex);
	return (dropped);
}

uint64_t
virtio_iommu_generation(struct virtio_iommu_state *state)
{
	uint64_t generation;

	pthread_mutex_lock(&state->mutex);
	generation = state->generation;
	pthread_mutex_unlock(&state->mutex);
	return (generation);
}

size_t
virtio_iommu_domain_count(struct virtio_iommu_state *state)
{
	size_t count;

	pthread_mutex_lock(&state->mutex);
	count = state->domain_count;
	pthread_mutex_unlock(&state->mutex);
	return (count);
}

size_t
virtio_iommu_mapping_count(struct virtio_iommu_state *state)
{
	size_t count;

	pthread_mutex_lock(&state->mutex);
	count = state->mapping_count;
	pthread_mutex_unlock(&state->mutex);
	return (count);
}
