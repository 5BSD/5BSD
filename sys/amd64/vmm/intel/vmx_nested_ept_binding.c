/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/errno.h>
#include <sys/types.h>

#ifndef _KERNEL
#include <stdbool.h>
#include <string.h>
#else
#include <sys/systm.h>
#endif

#include "vmx_nested_ept_binding.h"
#include "vmx_nested_ept_cache.h"
#include "vmx_nested_state_range.h"

static int
nvmxeb_storage_validate(const struct vmx_nested_ept_cache *cache,
    const struct vmx_nested_ept_binding *binding)
{
	size_t bytes;

	if (cache == NULL || cache->entries == NULL || cache->capacity == 0 ||
	    binding == NULL)
		return (EINVAL);
	bytes = (size_t)cache->capacity * sizeof(*cache->entries);
	if (bytes / sizeof(*cache->entries) != cache->capacity)
		return (EOVERFLOW);
	if (vmx_nested_state_ranges_overlap(binding, sizeof(*binding), cache,
	    sizeof(*cache)) ||
	    vmx_nested_state_ranges_overlap(binding, sizeof(*binding),
	    cache->entries, bytes))
		return (EINVAL);
	return (0);
}

void
vmx_nested_ept_binding_init(struct vmx_nested_ept_binding *binding)
{

	if (binding != NULL)
		memset(binding, 0, sizeof(*binding));
}

int
vmx_nested_ept_binding_validate(
    const struct vmx_nested_ept_binding *binding)
{

	if (binding == NULL)
		return (EINVAL);
	if (!binding->active) {
		return (binding->key.eptp == 0 &&
		    binding->key.capability_signature == 0 &&
		    !binding->key.mode_based_execute &&
		    binding->reference.owner == NULL &&
		    binding->reference.runtime_root == NULL &&
		    binding->reference.generation == 0 &&
		    binding->reference.slot == 0 ? 0 : EPROTO);
	}
	if (binding->key.capability_signature == 0 ||
	    binding->reference.owner == NULL ||
	    binding->reference.runtime_root == NULL ||
	    binding->reference.generation == 0)
		return (EPROTO);
	return (0);
}

int
vmx_nested_ept_binding_bind(struct vmx_nested_ept_cache *cache,
    struct vmx_nested_ept_binding *binding,
    const struct vmx_nested_ept_cache_key *key)
{
	struct vmx_nested_ept_cache_ref candidate;
	int error, rollback_error;

	error = nvmxeb_storage_validate(cache, binding);
	if (error != 0)
		return (error);
	if (vmx_nested_ept_binding_validate(binding) != 0)
		return (EPROTO);
	if (key == NULL ||
	    vmx_nested_state_ranges_overlap(key, sizeof(*key), binding,
	    sizeof(*binding)))
		return (EINVAL);
	error = vmx_nested_ept_cache_acquire(cache, key, &candidate);
	if (error != 0)
		return (error);
	if (binding->active) {
		error = vmx_nested_ept_cache_release(cache,
		    &binding->reference);
		if (error != 0) {
			rollback_error = vmx_nested_ept_cache_release(cache,
			    &candidate);
			if (rollback_error != 0)
				return (EPROTO);
			return (error);
		}
	}
	binding->key = *key;
	binding->reference = candidate;
	binding->active = true;
	return (0);
}

int
vmx_nested_ept_binding_resolve(
    const struct vmx_nested_ept_cache *cache,
    const struct vmx_nested_ept_binding *binding,
    const struct vmx_nested_ept_cache_key *key, void **runtime_root)
{
	int error;

	error = nvmxeb_storage_validate(cache, binding);
	if (error != 0)
		return (error);
	if (vmx_nested_ept_binding_validate(binding) != 0)
		return (EPROTO);
	if (key == NULL ||
	    runtime_root == NULL)
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(runtime_root,
	    sizeof(*runtime_root), binding, sizeof(*binding)))
		return (EINVAL);
	if (!binding->active)
		return (ENOENT);
	return (vmx_nested_ept_cache_resolve(cache,
	    &binding->reference, key, runtime_root));
}

int
vmx_nested_ept_binding_unbind(struct vmx_nested_ept_cache *cache,
    struct vmx_nested_ept_binding *binding)
{
	int error;

	error = nvmxeb_storage_validate(cache, binding);
	if (error != 0)
		return (error);
	if (vmx_nested_ept_binding_validate(binding) != 0)
		return (EPROTO);
	if (!binding->active)
		return (ENOENT);
	error = vmx_nested_ept_cache_release(cache, &binding->reference);
	if (error != 0)
		return (error);
	vmx_nested_ept_binding_init(binding);
	return (0);
}
