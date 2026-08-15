/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _DEV_VMM_VMM_EVENT_CHECKPOINT_H_
#define	_DEV_VMM_VMM_EVENT_CHECKPOINT_H_

#include <sys/types.h>

#ifdef _KERNEL
#include <sys/stdint.h>
#else
#include <stdbool.h>
#include <stdint.h>
#endif

#include <dev/vmm/vmm_event_ingress.h>

/*
 * Allocation-free, caller-synchronized group transaction.
 *
 * The caller initializes only entry.state and zeroes every other field.  It
 * must hold every state's ingress lock, in stable order, across each call.
 * A sleep/wakeup adapter may drop those locks only after begin returns and
 * must reacquire all of them before ready, finish, or abort.  This value layer
 * never waits and is therefore usable by every host architecture.  owner_id
 * is a non-reused lifetime incarnation for the capture transaction, not a
 * vCPU index or externally supplied checkpoint number.  count is an internal,
 * lifecycle-owned set (normally the VM's bounded vCPU set), not an untrusted
 * request length; duplicate-state validation is intentionally quadratic on
 * this cold path so it needs neither allocation nor address sorting.
 */
struct vmm_event_checkpoint_entry {
	struct vmm_event_ingress *state;
	struct vmm_event_ingress_lease lease;
	uint64_t deferred_mask;
};

struct vmm_event_checkpoint {
	uint64_t owner_id;
	struct vmm_event_checkpoint_entry *entries;
	uintptr_t storage_cookie;
	uintptr_t entries_cookie;
	size_t count;
	uint32_t active;
	uint32_t reserved;
};

int	vmm_event_checkpoint_begin(struct vmm_event_checkpoint *,
	    struct vmm_event_checkpoint_entry *, size_t, uint64_t);
int	vmm_event_checkpoint_ready(const struct vmm_event_checkpoint *, bool *);
int	vmm_event_checkpoint_finish(struct vmm_event_checkpoint *);
int	vmm_event_checkpoint_abort(struct vmm_event_checkpoint *);

#endif /* _DEV_VMM_VMM_EVENT_CHECKPOINT_H_ */
