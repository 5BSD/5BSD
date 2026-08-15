/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_EPT_CACHE_H_
#define	_VMM_INTEL_VMX_NESTED_EPT_CACHE_H_

#include "vmx_nested_types.h"

#include "vmx_nested_invalidate.h"

struct vmx_nested_ept_cache_key {
	uint64_t eptp;
	uint64_t capability_signature;
	bool mode_based_execute;
};

/*
 * A runtime root is an L0-owned opaque object.  It is never part of portable
 * state and must be reconstructed after restore.
 */
struct vmx_nested_ept_cache_entry {
	struct vmx_nested_ept_cache_key key;
	void *runtime_root;
	uint64_t generation;
	uint64_t last_used;
	uint32_t references;
	bool valid;
};

struct vmx_nested_ept_cache;

struct vmx_nested_ept_cache_ref {
	const struct vmx_nested_ept_cache *owner;
	void *runtime_root;
	uint64_t generation;
	uint32_t slot;
};

struct vmx_nested_ept_cache_ops {
	/*
	 * Success returns one unique independently owned root.  Returning the
	 * identity of a retained root violates the provider contract; the cache
	 * rejects it without destroy because that identity cannot safely prove a
	 * separate ownership transfer.
	 */
	int (*create)(void *, const struct vmx_nested_ept_cache_key *,
	    void **);
	void (*destroy)(void *, void *);
	int (*invalidate)(void *, void *);
};

struct vmx_nested_ept_cache {
	struct vmx_nested_ept_cache_entry *entries;
	uint32_t capacity;
	uint64_t next_generation;
	uint64_t clock;
	/* Provider identity is captured by value for the cache lifetime. */
	struct vmx_nested_ept_cache_ops ops;
	void *arg;
	bool callback_active;
};

/*
 * The owner serializes these operations with vCPU execution and snapshot
 * callbacks.  Backend callbacks are therefore never invoked under a cache
 * lock, and recursive cache entry from a callback is rejected.  A capacity
 * of zero is invalid; policy chooses the bound explicitly.
 */
int	vmx_nested_ept_cache_init(struct vmx_nested_ept_cache *,
	    struct vmx_nested_ept_cache_entry *, uint32_t,
	    const struct vmx_nested_ept_cache_ops *, void *);
/*
 * Constant-time retained-owner validation for constructors and hot paths.
 * This proves the entry array and complete provider table are present and
 * disjoint; it deliberately does not scan entries or require quiescence.
 */
int	vmx_nested_ept_cache_header_validate(
	    const struct vmx_nested_ept_cache *);
int	vmx_nested_ept_cache_acquire(struct vmx_nested_ept_cache *,
	    const struct vmx_nested_ept_cache_key *,
	    struct vmx_nested_ept_cache_ref *);
int	vmx_nested_ept_cache_release(struct vmx_nested_ept_cache *,
	    const struct vmx_nested_ept_cache_ref *);
int	vmx_nested_ept_cache_resolve(const struct vmx_nested_ept_cache *,
	    const struct vmx_nested_ept_cache_ref *,
	    const struct vmx_nested_ept_cache_key *, void **);
int	vmx_nested_ept_cache_invalidate(struct vmx_nested_ept_cache *,
	    const struct vmx_nested_invalidation *);
int	vmx_nested_ept_cache_quiesce(const struct vmx_nested_ept_cache *);
int	vmx_nested_ept_cache_empty(const struct vmx_nested_ept_cache *);
int	vmx_nested_ept_cache_destroy(struct vmx_nested_ept_cache *);

#endif /* _VMM_INTEL_VMX_NESTED_EPT_CACHE_H_ */
