/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/errno.h>
#include <sys/types.h>

#ifndef _KERNEL
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#else
#include <sys/systm.h>
#endif

#include "vmx_nested_ept_cache.h"
#include "vmx_nested_invalidate.h"
#include "vmx_nested_state_range.h"

static bool
vmx_nested_ept_cache_key_valid(const struct vmx_nested_ept_cache_key *key)
{

	return (key != NULL &&
	    key->capability_signature != 0);
}

static bool
vmx_nested_ept_cache_key_equal(const struct vmx_nested_ept_cache_key *first,
    const struct vmx_nested_ept_cache_key *second)
{

	return (first->eptp == second->eptp &&
	    first->capability_signature == second->capability_signature &&
	    first->mode_based_execute == second->mode_based_execute);
}

/*
 * Hot paths need not rescan the complete cache, but they must validate the
 * individual retained entry before dereferencing its root or handing it to a
 * provider callback.  Full cache validation remains the quiesce/destroy
 * boundary because it also proves cross-entry uniqueness.
 */
static int
vmx_nested_ept_cache_entry_validate(
    const struct vmx_nested_ept_cache *cache,
    const struct vmx_nested_ept_cache_entry *entry)
{

	if (cache == NULL || entry == NULL || !entry->valid ||
	    !vmx_nested_ept_cache_key_valid(&entry->key) ||
	    entry->runtime_root == NULL || entry->generation == 0 ||
	    entry->generation > cache->next_generation ||
	    entry->last_used > cache->clock)
		return (EPROTO);
	return (0);
}

/*
 * A selected free slot is part of the hot-path ownership proof too.  It may
 * be reused without a full-cache scan, but only when its inactive image is
 * canonical; otherwise overwriting it could discard an unowned stale root.
 */
static int
vmx_nested_ept_cache_slot_validate(const struct vmx_nested_ept_cache *cache,
    const struct vmx_nested_ept_cache_entry *entry)
{

	if (cache == NULL || entry == NULL)
		return (EINVAL);
	if (!entry->valid)
		return (entry->key.eptp == 0 &&
		    entry->key.capability_signature == 0 &&
		    !entry->key.mode_based_execute && entry->runtime_root == NULL &&
		    entry->generation == 0 && entry->last_used == 0 &&
		    entry->references == 0 ? 0 : EPROTO);
	return (vmx_nested_ept_cache_entry_validate(cache, entry));
}

int
vmx_nested_ept_cache_header_validate(
    const struct vmx_nested_ept_cache *cache)
{
	size_t bytes;

	if (cache == NULL)
		return (EINVAL);
	if (cache->entries == NULL || cache->capacity == 0 ||
	    cache->ops.create == NULL || cache->ops.destroy == NULL ||
	    cache->ops.invalidate == NULL)
		return (EPROTO);
	bytes = (size_t)cache->capacity * sizeof(*cache->entries);
	if (bytes / sizeof(*cache->entries) != cache->capacity)
		return (EOVERFLOW);
	if (vmx_nested_state_ranges_overlap(cache, sizeof(*cache),
	    cache->entries, bytes))
		return (EPROTO);
	return (0);
}

static int
nvmx_ept_cache_validate(const struct vmx_nested_ept_cache *cache)
{
	const struct vmx_nested_ept_cache_entry *entry, *other;
	int error;

	error = vmx_nested_ept_cache_header_validate(cache);
	if (error != 0)
		return (error);
	for (uint32_t i = 0; i < cache->capacity; i++) {
		entry = &cache->entries[i];
		if (!entry->valid) {
			if (entry->key.eptp != 0 ||
			    entry->key.capability_signature != 0 ||
			    entry->key.mode_based_execute ||
			    entry->runtime_root != NULL || entry->generation != 0 ||
			    entry->last_used != 0 || entry->references != 0)
				return (EPROTO);
			continue;
		}
		if (vmx_nested_ept_cache_entry_validate(cache, entry) != 0)
			return (EPROTO);
		for (uint32_t j = i + 1; j < cache->capacity; j++) {
			other = &cache->entries[j];
			if (!other->valid)
				continue;
			if (entry->runtime_root == other->runtime_root ||
			    entry->generation == other->generation ||
			    vmx_nested_ept_cache_key_equal(&entry->key,
			    &other->key))
				return (EPROTO);
		}
	}
	return (0);
}

static uint64_t
vmx_nested_ept_cache_touch(struct vmx_nested_ept_cache *cache)
{

	if (cache->clock == UINT64_MAX) {
		for (uint32_t i = 0; i < cache->capacity; i++)
			cache->entries[i].last_used = 0;
		cache->clock = 0;
	}
	return (++cache->clock);
}

int
vmx_nested_ept_cache_init(struct vmx_nested_ept_cache *cache,
    struct vmx_nested_ept_cache_entry *entries, uint32_t capacity,
    const struct vmx_nested_ept_cache_ops *ops, void *arg)
{
	size_t bytes;

	if (cache == NULL || entries == NULL || capacity == 0 || ops == NULL ||
	    ops->create == NULL || ops->destroy == NULL ||
	    ops->invalidate == NULL)
		return (EINVAL);
	bytes = (size_t)capacity * sizeof(*entries);
	if (bytes / sizeof(*entries) != capacity)
		return (EOVERFLOW);
	if (vmx_nested_state_ranges_overlap(cache, sizeof(*cache), entries,
	    bytes) ||
	    vmx_nested_state_ranges_overlap(cache, sizeof(*cache), ops,
	    sizeof(*ops)) ||
	    vmx_nested_state_ranges_overlap(entries, bytes, ops, sizeof(*ops)))
		return (EINVAL);
	memset(entries, 0, bytes);
	memset(cache, 0, sizeof(*cache));
	cache->entries = entries;
	cache->capacity = capacity;
	cache->ops = *ops;
	cache->arg = arg;
	return (0);
}

int
vmx_nested_ept_cache_acquire(struct vmx_nested_ept_cache *cache,
    const struct vmx_nested_ept_cache_key *key,
    struct vmx_nested_ept_cache_ref *reference)
{
	struct vmx_nested_ept_cache_entry *entry, *victim;
	struct vmx_nested_ept_cache_ref candidate;
	void *root;
	size_t bytes;
	uint32_t victim_slot;
	int error;

	error = vmx_nested_ept_cache_header_validate(cache);
	if (error != 0)
		return (error);
	if (!vmx_nested_ept_cache_key_valid(key) || reference == NULL)
		return (EINVAL);
	if (cache->callback_active)
		return (EBUSY);
	bytes = (size_t)cache->capacity * sizeof(*cache->entries);
	if (bytes / sizeof(*cache->entries) != cache->capacity)
		return (EOVERFLOW);
	if (vmx_nested_state_ranges_overlap(key, sizeof(*key), cache,
	    sizeof(*cache)) ||
	    vmx_nested_state_ranges_overlap(key, sizeof(*key), cache->entries,
	    bytes) ||
	    vmx_nested_state_ranges_overlap(reference, sizeof(*reference), cache,
	    sizeof(*cache)) ||
	    vmx_nested_state_ranges_overlap(reference, sizeof(*reference),
	    cache->entries, bytes) ||
	    vmx_nested_state_ranges_overlap(reference, sizeof(*reference), key,
	    sizeof(*key)))
		return (EINVAL);
	memset(&candidate, 0, sizeof(candidate));
	for (uint32_t i = 0; i < cache->capacity; i++) {
		entry = &cache->entries[i];
		if (!entry->valid)
			continue;
		if (!vmx_nested_ept_cache_key_equal(&entry->key, key))
			continue;
		error = vmx_nested_ept_cache_entry_validate(cache, entry);
		if (error != 0)
			return (error);
		if (entry->references == UINT32_MAX)
			return (EOVERFLOW);
		entry->references++;
		entry->last_used = vmx_nested_ept_cache_touch(cache);
		candidate.owner = cache;
		candidate.runtime_root = entry->runtime_root;
		candidate.generation = entry->generation;
		candidate.slot = i;
		*reference = candidate;
		return (0);
	}

	victim = NULL;
	victim_slot = 0;
	for (uint32_t i = 0; i < cache->capacity; i++) {
		entry = &cache->entries[i];
		if (!entry->valid) {
			error = vmx_nested_ept_cache_slot_validate(cache, entry);
			if (error != 0)
				return (error);
			victim = entry;
			victim_slot = i;
			break;
		}
		error = vmx_nested_ept_cache_entry_validate(cache, entry);
		if (error != 0)
			return (error);
		if (entry->references == 0 &&
		    (victim == NULL || entry->last_used < victim->last_used)) {
			victim = entry;
			victim_slot = i;
		}
	}
	if (victim == NULL)
		return (EBUSY);
	if (cache->next_generation == UINT64_MAX)
		return (EOVERFLOW);

	root = NULL;
	cache->callback_active = true;
	error = cache->ops.create(cache->arg, key, &root);
	cache->callback_active = false;
	if (error != 0)
		return (error < 0 ? EPROTO : error);
	if (root == NULL)
		return (EPROTO);
	/*
	 * A create callback must return a unique, independently owned root.  An
	 * identity that is already retained violates that private contract.  Do
	 * not call destroy on it: the callback may have returned an unreferenced
	 * alias of the live root, in which case destruction would free a root that
	 * the cache still owns.  The ambiguous malformed value is quarantined by
	 * failing the operation; a correct provider never reaches this path.
	 */
	for (uint32_t i = 0; i < cache->capacity; i++) {
		if (cache->entries[i].valid &&
		    cache->entries[i].runtime_root == root) {
			return (EPROTO);
		}
	}
	if (victim->valid) {
		cache->callback_active = true;
		cache->ops.destroy(cache->arg, victim->runtime_root);
		cache->callback_active = false;
	}
	memset(victim, 0, sizeof(*victim));
	victim->key = *key;
	victim->runtime_root = root;
	victim->generation = ++cache->next_generation;
	victim->last_used = vmx_nested_ept_cache_touch(cache);
	victim->references = 1;
	victim->valid = true;

	candidate.owner = cache;
	candidate.runtime_root = victim->runtime_root;
	candidate.generation = victim->generation;
	candidate.slot = victim_slot;
	*reference = candidate;
	return (0);
}

int
vmx_nested_ept_cache_release(struct vmx_nested_ept_cache *cache,
    const struct vmx_nested_ept_cache_ref *reference)
{
	struct vmx_nested_ept_cache_entry *entry;
	size_t bytes;
	int error;

	error = vmx_nested_ept_cache_header_validate(cache);
	if (error != 0)
		return (error);
	if (reference == NULL || reference->slot >= cache->capacity)
		return (EINVAL);
	if (cache->callback_active)
		return (EBUSY);
	bytes = (size_t)cache->capacity * sizeof(*cache->entries);
	if (bytes / sizeof(*cache->entries) != cache->capacity)
		return (EOVERFLOW);
	if (vmx_nested_state_ranges_overlap(reference, sizeof(*reference), cache,
	    sizeof(*cache)) ||
	    vmx_nested_state_ranges_overlap(reference, sizeof(*reference),
	    cache->entries, bytes))
		return (EINVAL);
	if (reference->owner != cache)
		return (ESTALE);
	entry = &cache->entries[reference->slot];
	error = vmx_nested_ept_cache_entry_validate(cache, entry);
	if (error != 0)
		return (error);
	if (entry->generation != reference->generation ||
	    entry->runtime_root != reference->runtime_root ||
	    entry->references == 0)
		return (ESTALE);
	entry->references--;
	entry->last_used = vmx_nested_ept_cache_touch(cache);
	return (0);
}

int
vmx_nested_ept_cache_resolve(const struct vmx_nested_ept_cache *cache,
    const struct vmx_nested_ept_cache_ref *reference,
    const struct vmx_nested_ept_cache_key *key, void **runtime_root)
{
	const struct vmx_nested_ept_cache_entry *entry;
	size_t bytes;
	int error;

	error = vmx_nested_ept_cache_header_validate(cache);
	if (error != 0)
		return (error);
	if (reference == NULL || !vmx_nested_ept_cache_key_valid(key) ||
	    runtime_root == NULL ||
	    reference->slot >= cache->capacity)
		return (EINVAL);
	if (cache->callback_active)
		return (EBUSY);
	bytes = (size_t)cache->capacity * sizeof(*cache->entries);
	if (bytes / sizeof(*cache->entries) != cache->capacity)
		return (EOVERFLOW);
	if (vmx_nested_state_ranges_overlap(runtime_root,
	    sizeof(*runtime_root), cache, sizeof(*cache)) ||
	    vmx_nested_state_ranges_overlap(runtime_root,
	    sizeof(*runtime_root), cache->entries, bytes) ||
	    vmx_nested_state_ranges_overlap(runtime_root,
	    sizeof(*runtime_root), reference, sizeof(*reference)) ||
	    vmx_nested_state_ranges_overlap(runtime_root,
	    sizeof(*runtime_root), key, sizeof(*key)))
		return (EINVAL);
	if (reference->owner != cache)
		return (ESTALE);
	entry = &cache->entries[reference->slot];
	error = vmx_nested_ept_cache_entry_validate(cache, entry);
	if (error != 0)
		return (error);
	if (entry->generation != reference->generation ||
	    entry->runtime_root != reference->runtime_root ||
	    entry->references == 0 ||
	    !vmx_nested_ept_cache_key_equal(&entry->key, key))
		return (ESTALE);
	*runtime_root = entry->runtime_root;
	return (0);
}

int
vmx_nested_ept_cache_invalidate(struct vmx_nested_ept_cache *cache,
    const struct vmx_nested_invalidation *invalidation)
{
	uint64_t root;
	size_t bytes;
	bool all;
	int error, first_error;

	error = vmx_nested_ept_cache_header_validate(cache);
	if (error != 0)
		return (error);
	if (invalidation == NULL || invalidation->address != 0)
		return (EINVAL);
	if (cache->callback_active)
		return (EBUSY);
	bytes = (size_t)cache->capacity * sizeof(*cache->entries);
	if (bytes / sizeof(*cache->entries) != cache->capacity)
		return (EOVERFLOW);
	if (vmx_nested_state_ranges_overlap(invalidation,
	    sizeof(*invalidation), cache, sizeof(*cache)) ||
	    vmx_nested_state_ranges_overlap(invalidation,
	    sizeof(*invalidation), cache->entries, bytes))
		return (EINVAL);
	switch (invalidation->scope) {
	case VMX_NESTED_INVALIDATE_EPT_SINGLE:
		root = invalidation->context &
		    VMX_NESTED_EPT_ROOT_ADDRESS_MASK;
		all = false;
		break;
	case VMX_NESTED_INVALIDATE_EPT_ALL:
		if (invalidation->context != 0)
			return (EINVAL);
		root = 0;
		all = true;
		break;
	default:
		return (EINVAL);
	}
	first_error = 0;
	for (uint32_t i = 0; i < cache->capacity; i++) {
		struct vmx_nested_ept_cache_entry *entry;

		entry = &cache->entries[i];
		if (!entry->valid ||
		    (!all && (entry->key.eptp &
		    VMX_NESTED_EPT_ROOT_ADDRESS_MASK) != root))
			continue;
		error = vmx_nested_ept_cache_entry_validate(cache, entry);
		if (error != 0)
			return (error);
		cache->callback_active = true;
		error = cache->ops.invalidate(cache->arg,
		    entry->runtime_root);
		cache->callback_active = false;
		if (error != 0 && first_error == 0)
			first_error = error < 0 ? EPROTO : error;
	}
	return (first_error);
}

int
vmx_nested_ept_cache_quiesce(const struct vmx_nested_ept_cache *cache)
{
	int error;

	error = nvmx_ept_cache_validate(cache);
	if (error != 0)
		return (error);
	if (cache->callback_active)
		return (EBUSY);
	for (uint32_t i = 0; i < cache->capacity; i++) {
		if (cache->entries[i].valid &&
		    cache->entries[i].references != 0)
			return (EBUSY);
	}
	return (0);
}

int
vmx_nested_ept_cache_empty(const struct vmx_nested_ept_cache *cache)
{
	int error;

	error = vmx_nested_ept_cache_quiesce(cache);
	if (error != 0)
		return (error);
	for (uint32_t i = 0; i < cache->capacity; i++) {
		if (cache->entries[i].valid)
			return (ENOTEMPTY);
	}
	return (0);
}

int
vmx_nested_ept_cache_destroy(struct vmx_nested_ept_cache *cache)
{
	int error;

	error = vmx_nested_ept_cache_quiesce(cache);
	if (error != 0)
		return (error);
	for (uint32_t i = 0; i < cache->capacity; i++) {
		if (cache->entries[i].valid) {
			cache->callback_active = true;
			cache->ops.destroy(cache->arg,
			    cache->entries[i].runtime_root);
			cache->callback_active = false;
		}
	}
	memset(cache->entries, 0,
	    (size_t)cache->capacity * sizeof(*cache->entries));
	cache->clock = 0;
	return (0);
}
