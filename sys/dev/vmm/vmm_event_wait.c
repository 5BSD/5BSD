/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>
#include <sys/errno.h>
#ifdef _KERNEL
#include <sys/param.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/sleepqueue.h>
#include <sys/systm.h>
#else
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#endif

#include <dev/vmm/vmm_event_wait.h>
#include <dev/vmm/vmm_address_range.h>

static bool
vmm_event_wait_overlap(const void *left, size_t left_length,
    const void *right, size_t right_length)
{
	return (vmm_address_ranges_overlap(left, left_length, right,
	    right_length));
}

static bool
vmm_event_wait_ticket_empty(const struct vmm_event_wait_ticket *ticket)
{

	return (ticket->owner_id == 0 && ticket->generation == 0 &&
	    ticket->state_cookie == 0 && ticket->storage_cookie == 0 &&
	    ticket->active == 0 && ticket->reserved == 0);
}

int
vmm_event_wait_init(struct vmm_event_wait_state *state, uint64_t owner_id)
{

	if (state == NULL || owner_id == 0)
		return (EINVAL);
	memset(state, 0, sizeof(*state));
	state->owner_id = owner_id;
	state->generation = 1;
	state->storage_cookie = (uintptr_t)state;
	return (0);
}

int
vmm_event_wait_validate_locked(const struct vmm_event_wait_state *state)
{

	if (state == NULL || state->owner_id == 0 || state->generation == 0 ||
	    state->storage_cookie != (uintptr_t)state || state->cancelled > 1 ||
	    state->reserved != 0)
		return (EINVAL);
	return (0);
}

int
vmm_event_wait_prepare_locked(const struct vmm_event_wait_state *state,
    struct vmm_event_wait_ticket *ticket)
{
	struct vmm_event_wait_ticket candidate;
	int error;

	if (state == NULL || ticket == NULL ||
	    vmm_event_wait_overlap(state, sizeof(*state), ticket,
	    sizeof(*ticket)))
		return (EINVAL);
	error = vmm_event_wait_validate_locked(state);
	if (error != 0 || !vmm_event_wait_ticket_empty(ticket))
		return (error != 0 ? error : EBUSY);
	if (state->cancelled != 0)
		return (ECANCELED);
	if (state->generation == UINT64_MAX)
		return (EOVERFLOW);
	candidate = (struct vmm_event_wait_ticket) {
		.owner_id = state->owner_id,
		.generation = state->generation,
		.state_cookie = (uintptr_t)state,
		.storage_cookie = (uintptr_t)ticket,
		.active = 1,
	};
	*ticket = candidate;
	return (0);
}

int
vmm_event_wait_changed_locked(const struct vmm_event_wait_state *state,
    const struct vmm_event_wait_ticket *ticket, bool *changedp)
{
	bool changed;
	int error;

	if (state == NULL || ticket == NULL || changedp == NULL ||
	    vmm_event_wait_overlap(state, sizeof(*state), ticket,
	    sizeof(*ticket)) || vmm_event_wait_overlap(state, sizeof(*state),
	    changedp, sizeof(*changedp)) || vmm_event_wait_overlap(ticket,
	    sizeof(*ticket), changedp, sizeof(*changedp)))
		return (EINVAL);
	error = vmm_event_wait_validate_locked(state);
	if (error != 0)
		return (error);
	if (ticket->active != 1 || ticket->reserved != 0 ||
	    ticket->owner_id != state->owner_id ||
	    ticket->generation == 0 ||
	    ticket->generation > state->generation ||
	    ticket->state_cookie != (uintptr_t)state ||
	    ticket->storage_cookie != (uintptr_t)ticket)
		return (ESTALE);
	if (state->cancelled != 0)
		return (ECANCELED);
	changed = ticket->generation != state->generation;
	*changedp = changed;
	return (0);
}

int
vmm_event_wait_ticket_release(struct vmm_event_wait_ticket *ticket)
{

	if (ticket == NULL || ticket->owner_id == 0 ||
	    ticket->generation == 0 || ticket->state_cookie == 0 ||
	    ticket->active != 1 || ticket->reserved != 0 ||
	    ticket->storage_cookie != (uintptr_t)ticket)
		return (ESTALE);
	memset(ticket, 0, sizeof(*ticket));
	return (0);
}

int
vmm_event_wait_wake_result_locked(
    const struct vmm_event_wait_state *state,
    const struct vmm_event_wait_ticket *ticket, int sleep_error)
{
	bool changed;
	int error;

	/* Preserve an interruptible sleep's signal result exactly. */
	if (sleep_error != 0)
		return (sleep_error);
	changed = false;
	error = vmm_event_wait_changed_locked(state, ticket, &changed);
	if (error != 0)
		return (error);
	(void)changed;
	/* Both a signalled and a spurious wake require a predicate replay. */
	return (EAGAIN);
}

int
vmm_event_wait_signal_locked(struct vmm_event_wait_state *state)
{
	int error;

	error = vmm_event_wait_validate_locked(state);
	if (error != 0)
		return (error);
	if (state->cancelled != 0)
		return (ECANCELED);
	/* UINT64_MAX is not a usable ticket generation. */
	if (state->generation >= UINT64_MAX - 1) {
		state->cancelled = 1;
		return (EOVERFLOW);
	}
	state->generation++;
	return (0);
}

int
vmm_event_wait_cancel_locked(struct vmm_event_wait_state *state)
{
	int error;

	error = vmm_event_wait_validate_locked(state);
	if (error != 0)
		return (error);
	if (state->cancelled != 0)
		return (0);
	if (state->generation != UINT64_MAX)
		state->generation++;
	state->cancelled = 1;
	return (0);
}

#ifdef _KERNEL
int
vmm_event_wait_prepare(struct vmm_event_wait_state *state,
    struct vmm_event_wait_ticket *ticket)
{
	int error;

	if (state == NULL)
		return (EINVAL);
	sleepq_lock(state);
	error = vmm_event_wait_prepare_locked(state, ticket);
	sleepq_release(state);
	return (error);
}

int
vmm_event_wait_signal(struct vmm_event_wait_state *state)
{
	int error;

	if (state == NULL)
		return (EINVAL);
	sleepq_lock(state);
	error = vmm_event_wait_signal_locked(state);
	sleepq_broadcast(state, SLEEPQ_SLEEP, 0, 0);
	sleepq_release(state);
	return (error);
}

int
vmm_event_wait_cancel(struct vmm_event_wait_state *state)
{
	int error;

	if (state == NULL)
		return (EINVAL);
	sleepq_lock(state);
	error = vmm_event_wait_cancel_locked(state);
	sleepq_broadcast(state, SLEEPQ_SLEEP, 0, 0);
	sleepq_release(state);
	return (error);
}

int
vmm_event_wait_sleep(struct vmm_event_wait_state *state,
    const struct vmm_event_wait_ticket *ticket, const char *wmesg, int pri)
{
	bool changed;
	int error, sleep_error;

	if (state == NULL || ticket == NULL || wmesg == NULL ||
	    (pri & ~PRIMASK) != 0)
		return (EINVAL);
	sleepq_lock(state);
	error = vmm_event_wait_changed_locked(state, ticket, &changed);
	if (error != 0 || changed) {
		sleepq_release(state);
		return (error != 0 ? error : EAGAIN);
	}
	if (state->waiters == UINT32_MAX) {
		sleepq_release(state);
		return (EOVERFLOW);
	}
	state->waiters++;
	sleepq_add(state, NULL, wmesg, SLEEPQ_SLEEP | SLEEPQ_INTERRUPTIBLE, 0);
	/* Match native interruptible sleep paths even for a future Giant caller. */
	DROP_GIANT();
	sleep_error = sleepq_wait_sig(state, pri);
	PICKUP_GIANT();
	sleepq_lock(state);
	if (state->waiters == 0)
		panic("%s: missing registered waiter", __func__);
	state->waiters--;
	/*
	 * A broadcast is only a request to re-evaluate the caller's predicate.
	 * Never translate an ordinary sleepqueue wake into predicate success.
	 * Revalidate while retaining the sleepqueue interlock so cancellation or
	 * corruption is reported precisely; EAGAIN makes the coordinator release
	 * this ticket, reacquire its transaction owner, and test the predicate.
	 */
	error = sleep_error;
	if (error == 0)
		error = vmm_event_wait_wake_result_locked(state, ticket, error);
	if (state->cancelled != 0 && state->waiters == 0)
		sleepq_broadcast(state, SLEEPQ_SLEEP, 0, 0);
	sleepq_release(state);
	return (error);
}

int
vmm_event_wait_drain(struct vmm_event_wait_state *state, const char *wmesg,
    int pri)
{
	int error;

	if (state == NULL || wmesg == NULL || (pri & ~PRIMASK) != 0)
		return (EINVAL);
	sleepq_lock(state);
	error = vmm_event_wait_validate_locked(state);
	if (error != 0 || state->cancelled == 0) {
		sleepq_release(state);
		return (error != 0 ? error : EINVAL);
	}
	while (state->waiters != 0) {
		sleepq_add(state, NULL, wmesg, SLEEPQ_SLEEP, 0);
		DROP_GIANT();
		sleepq_wait(state, pri);
		PICKUP_GIANT();
		sleepq_lock(state);
		error = vmm_event_wait_validate_locked(state);
		if (error != 0 || state->cancelled == 0) {
			sleepq_release(state);
			return (error != 0 ? error : EINVAL);
		}
	}
	sleepq_release(state);
	return (0);
}
#endif
