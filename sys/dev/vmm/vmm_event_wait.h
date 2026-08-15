/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _DEV_VMM_VMM_EVENT_WAIT_H_
#define	_DEV_VMM_VMM_EVENT_WAIT_H_

#include <sys/types.h>

#ifdef _KERNEL
#include <sys/stdint.h>
#else
#include <stdbool.h>
#include <stdint.h>
#endif

/*
 * Architecture-neutral checkpoint wake generation.
 *
 * The *_locked value functions require an external interlock.  The kernel
 * wrappers use the state's sleepqueue-chain spin lock as that interlock, so a
 * publisher may signal from interrupt-adjacent context and an interruptible
 * waiter cannot miss a transition between its predicate check and enqueue.
 * owner_id is a non-reused lifetime incarnation.  Storage cookies are
 * transient guards and are never serialized.
 */
struct vmm_event_wait_state {
	uint64_t owner_id;
	uint64_t generation;
	uintptr_t storage_cookie;
	uint32_t waiters;
	uint32_t cancelled;
	uint32_t reserved;
};

struct vmm_event_wait_ticket {
	uint64_t owner_id;
	uint64_t generation;
	uintptr_t state_cookie;
	uintptr_t storage_cookie;
	uint32_t active;
	uint32_t reserved;
};

int	vmm_event_wait_init(struct vmm_event_wait_state *, uint64_t);
int	vmm_event_wait_validate_locked(const struct vmm_event_wait_state *);
int	vmm_event_wait_prepare_locked(const struct vmm_event_wait_state *,
	    struct vmm_event_wait_ticket *);
int	vmm_event_wait_changed_locked(const struct vmm_event_wait_state *,
	    const struct vmm_event_wait_ticket *, bool *);
int	vmm_event_wait_wake_result_locked(
	    const struct vmm_event_wait_state *,
	    const struct vmm_event_wait_ticket *, int);
int	vmm_event_wait_ticket_release(struct vmm_event_wait_ticket *);
int	vmm_event_wait_signal_locked(struct vmm_event_wait_state *);
int	vmm_event_wait_cancel_locked(struct vmm_event_wait_state *);

#ifdef _KERNEL
int	vmm_event_wait_prepare(struct vmm_event_wait_state *,
	    struct vmm_event_wait_ticket *);
int	vmm_event_wait_signal(struct vmm_event_wait_state *);
int	vmm_event_wait_cancel(struct vmm_event_wait_state *);
int	vmm_event_wait_sleep(struct vmm_event_wait_state *,
	    const struct vmm_event_wait_ticket *, const char *, int);
int	vmm_event_wait_drain(struct vmm_event_wait_state *, const char *, int);
#endif

#endif /* _DEV_VMM_VMM_EVENT_WAIT_H_ */
