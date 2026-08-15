/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _DEV_VMM_VMM_EVENT_COORDINATOR_H_
#define	_DEV_VMM_VMM_EVENT_COORDINATOR_H_

#ifdef _KERNEL

#include <sys/_cpuset.h>
#include <sys/types.h>

#include <dev/vmm/vmm_event_checkpoint.h>
#include <dev/vmm/vmm_event_ingress.h>
#include <dev/vmm/vmm_event_wait.h>
#include <dev/vmm/vmm_startup_event.h>
#include <dev/vmm/vmm_startup_controller.h>
#include <dev/vmm/vmm_startup_handshake.h>

struct vmm_event_coordinator;

/*
 * Called with every selected ingress spin lock held after the value layer has
 * reopened admission but before those locks are released.  The callback must
 * not sleep, allocate, fail, or reenter the coordinator.  It may merge only
 * the caller-defined idempotent bits in deferred_mask into live event state.
 */
typedef void vmm_event_deferred_apply_t(void *, uint16_t, uint64_t);

/*
 * The enclosing VM lifetime is the pointer-stability authority.  Before
 * cancel/drain/destroy, it must prevent new API entries while retaining the
 * VM object itself.  Cancellation closes publisher and deferred-event
 * admission and wakes waiters; it does not implicitly abort an active group
 * transaction.  The caller must abort that exact transaction, drain waiters,
 * and release every publisher ticket before destroy can succeed.
 *
 * Coordinator, transaction, entry, instance, ticket, and ingress storage is
 * transient kernel state.  None is a save-state, userspace ABI, or stable
 * kernel programming interface; consumers must remain inside vmm(4).
 */

int	vmm_event_coordinator_create(uint16_t,
	    struct vmm_event_coordinator **);
int	vmm_event_coordinator_cancel(struct vmm_event_coordinator *);
int	vmm_event_coordinator_drain(struct vmm_event_coordinator *,
	    const char *, int);
int	vmm_event_coordinator_drain_publishers(
	    struct vmm_event_coordinator *, const char *, int);
int	vmm_event_coordinator_destroy(struct vmm_event_coordinator *);
int	vmm_event_coordinator_reset(struct vmm_event_coordinator *);

int	vmm_event_coordinator_startup_lock_default(
	    struct vmm_event_coordinator *, uint64_t *);
int	vmm_event_coordinator_startup_controller_claim(
	    struct vmm_event_coordinator *,
	    struct vmm_startup_controller_ticket *, uint64_t);
int	vmm_event_coordinator_startup_controller_release(
	    struct vmm_event_coordinator *,
	    struct vmm_startup_controller_ticket *);
int	vmm_event_coordinator_startup_configure_kernel(
	    struct vmm_event_coordinator *,
	    const struct vmm_startup_controller_ticket *, uint16_t, uint64_t *);
int	vmm_event_coordinator_startup_enter(
	    struct vmm_event_coordinator *,
	    const struct vmm_startup_controller_ticket *, uint16_t, uint64_t,
	    bool);
int	vmm_event_coordinator_startup_wait_ready(
	    struct vmm_event_coordinator *,
	    const struct vmm_startup_controller_ticket *, uint64_t,
	    struct vmm_event_wait_ticket *, const char *, int);
int	vmm_event_coordinator_startup_wait_committed(
	    struct vmm_event_coordinator *,
	    const struct vmm_startup_controller_ticket *, uint64_t,
	    struct vmm_event_wait_ticket *, const char *, int);
int	vmm_event_coordinator_startup_commit(
	    struct vmm_event_coordinator *,
	    const struct vmm_startup_controller_ticket *, uint64_t);
int	vmm_event_coordinator_startup_status(
	    struct vmm_event_coordinator *,
	    const struct vmm_startup_controller_ticket *,
	    struct vmm_startup_handshake_status *);
int	vmm_event_coordinator_startup_execution_status(
	    struct vmm_event_coordinator *,
	    struct vmm_startup_handshake_status *);

int	vmm_event_coordinator_publisher_enter(
	    struct vmm_event_coordinator *, uint16_t,
	    struct vmm_event_ingress_ticket *);
int	vmm_event_coordinator_publisher_exit(
	    struct vmm_event_coordinator *, uint16_t,
	    struct vmm_event_ingress_ticket *);
int	vmm_event_coordinator_publisher_enter_or_defer(
	    struct vmm_event_coordinator *, uint16_t,
	    struct vmm_event_ingress_ticket *, uint64_t, uint64_t, bool *);

int	vmm_event_coordinator_startup_publish_init(
	    struct vmm_event_coordinator *, uint16_t);
int	vmm_event_coordinator_startup_publish_sipi(
	    struct vmm_event_coordinator *, uint16_t, uint8_t);
int	vmm_event_coordinator_startup_claim_begin(
	    struct vmm_event_coordinator *, uint16_t,
	    struct vmm_startup_event_claim *);
int	vmm_event_coordinator_startup_claim_check(
	    struct vmm_event_coordinator *, uint16_t,
	    const struct vmm_startup_event_claim *);
int	vmm_event_coordinator_startup_claim_finish(
	    struct vmm_event_coordinator *, uint16_t,
	    struct vmm_startup_event_claim *);
int	vmm_event_coordinator_startup_claim_abort(
	    struct vmm_event_coordinator *, uint16_t,
	    struct vmm_startup_event_claim *);
int	vmm_event_coordinator_startup_run_token_capture(
	    struct vmm_event_coordinator *, uint16_t,
	    struct vmm_startup_event_run_token *);
int	vmm_event_coordinator_startup_run_token_check(
	    struct vmm_event_coordinator *, uint16_t,
	    const struct vmm_startup_event_run_token *);
int	vmm_event_coordinator_startup_publish_set(
	    struct vmm_event_coordinator *, const cpuset_t *,
	    enum vmm_startup_event_kind, uint8_t);
int	vmm_event_coordinator_startup_route_set(
	    struct vmm_event_coordinator *, const cpuset_t *,
	    enum vmm_startup_event_kind, uint8_t,
	    struct vmm_startup_delivery *);
int	vmm_event_coordinator_startup_publish_claim_batch(
	    struct vmm_event_coordinator *, const uint32_t *, size_t,
	    enum vmm_startup_event_kind, uint8_t,
	    struct vmm_startup_event_claim *);

int	vmm_event_coordinator_checkpoint_begin(
	    struct vmm_event_coordinator *, struct vmm_event_checkpoint *,
	    struct vmm_event_checkpoint_entry *, const uint32_t *, size_t);
int	vmm_event_coordinator_checkpoint_wait_ready(
	    struct vmm_event_coordinator *, struct vmm_event_checkpoint *,
	    struct vmm_event_wait_ticket *, const char *, int);
int	vmm_event_coordinator_checkpoint_finish(
	    struct vmm_event_coordinator *, struct vmm_event_checkpoint *,
	    vmm_event_deferred_apply_t *, void *);
int	vmm_event_coordinator_checkpoint_abort(
	    struct vmm_event_coordinator *, struct vmm_event_checkpoint *,
	    vmm_event_deferred_apply_t *, void *);

#endif /* _KERNEL */
#endif /* _DEV_VMM_VMM_EVENT_COORDINATOR_H_ */
