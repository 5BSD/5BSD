/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _DEV_VMM_VMM_EVENT_INGRESS_H_
#define	_DEV_VMM_VMM_EVENT_INGRESS_H_

#include <sys/types.h>

#ifdef _KERNEL
#include <sys/stdint.h>
#else
#include <stdint.h>
#endif

/*
 * Architecture-neutral, transient checkpoint admission state.
 *
 * The caller supplies synchronization.  All functions are non-blocking and
 * perform no allocation.  A deferred bit may represent only idempotent work;
 * architecture adapters own the mapping from bits to live event state.
 * owner_id is a lifetime incarnation, not a reusable object number: an
 * adapter must not reuse it while any credential from an earlier incarnation
 * could remain.  Initialization and destruction require exclusive lifecycle
 * ownership.  Storage cookies are transient guards and are never serialized.
 */
enum vmm_event_ingress_mode {
	VMM_EVENT_INGRESS_OPEN = 0,
	VMM_EVENT_INGRESS_DRAINING,
	VMM_EVENT_INGRESS_QUIESCED,
	VMM_EVENT_INGRESS_MODE_LAST,
};

struct vmm_event_ingress {
	uint64_t owner_id;
	uint64_t publisher_generation;
	uint64_t last_lease_id;
	uint64_t current_lease_id;
	uint64_t deferred_mask;
	uintptr_t storage_cookie;
	uint32_t active_publishers;
	uint32_t mode;
};

struct vmm_event_ingress_ticket {
	uint64_t owner_id;
	uint64_t publisher_generation;
	uintptr_t state_cookie;
	uintptr_t storage_cookie;
	uint32_t active;
	uint32_t reserved;
};

struct vmm_event_ingress_lease {
	uint64_t owner_id;
	uint64_t lease_id;
	uintptr_t state_cookie;
	uintptr_t storage_cookie;
	uint32_t active;
	uint32_t reserved;
};

int	vmm_event_ingress_init(struct vmm_event_ingress *, uint64_t);
int	vmm_event_ingress_validate(const struct vmm_event_ingress *);
int	vmm_event_ingress_publisher_enter(struct vmm_event_ingress *,
	    struct vmm_event_ingress_ticket *);
int	vmm_event_ingress_publisher_exit(struct vmm_event_ingress *,
	    struct vmm_event_ingress_ticket *);
int	vmm_event_ingress_quiesce_begin(struct vmm_event_ingress *,
	    struct vmm_event_ingress_lease *);
int	vmm_event_ingress_defer_idempotent(struct vmm_event_ingress *,
	    uint64_t, uint64_t);
int	vmm_event_ingress_quiesce_finish(struct vmm_event_ingress *,
	    struct vmm_event_ingress_lease *, uint64_t *);
int	vmm_event_ingress_quiesce_abort(struct vmm_event_ingress *,
	    struct vmm_event_ingress_lease *, uint64_t *);

#endif /* _DEV_VMM_VMM_EVENT_INGRESS_H_ */
