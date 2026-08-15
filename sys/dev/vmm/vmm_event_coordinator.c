/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/cpuset.h>
#include <sys/errno.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/sleepqueue.h>
#include <sys/systm.h>

#include <dev/vmm/vmm_event_coordinator.h>
#include <dev/vmm/vmm_address_range.h>
#include <dev/vmm/vmm_startup_controller.h>
#include <dev/vmm/vmm_startup_event.h>
#include <dev/vmm/vmm_startup_handshake.h>

struct vmm_event_coordinator_entry {
	struct mtx lock;
	struct vmm_event_ingress ingress;
	struct vmm_startup_event_state startup;
};

struct vmm_event_coordinator {
	uint64_t owner_id;
	size_t allocation_size;
	size_t checkpoint_count;
	uintptr_t storage_cookie;
	uintptr_t checkpoint_cookie;
	uintptr_t checkpoint_entries_cookie;
	struct mtx transaction_lock;
	struct vmm_event_wait_state wait;
	struct vmm_event_wait_state startup_wait;
	struct vmm_startup_controller_state startup_controller;
	struct vmm_startup_handshake startup_handshake;
	uint16_t maxcpus;
	uint16_t reserved16;
	volatile u_int cancelled;
	u_int transaction_active;
	u_int reserved32;
	struct vmm_event_coordinator_entry entry[];
};

static MALLOC_DEFINE(M_VMM_EVENT_COORDINATOR, "vmm_event_coordinator",
    "VMM checkpoint event coordinator");
static struct mtx vmm_event_owner_lock;
MTX_SYSINIT(vmm_event_owner_lock, &vmm_event_owner_lock,
    "vmm event owner", MTX_SPIN);
static uint64_t vmm_event_next_owner_id = 1;

static int
vmm_event_owner_allocate(uint64_t *owner_id)
{

	mtx_lock_spin(&vmm_event_owner_lock);
	if (vmm_event_next_owner_id == UINT64_MAX) {
		mtx_unlock_spin(&vmm_event_owner_lock);
		return (EOVERFLOW);
	}
	*owner_id = vmm_event_next_owner_id++;
	mtx_unlock_spin(&vmm_event_owner_lock);
	return (0);
}

/*
 * Close every entry admission point as one ordered operation.  Callers may
 * hold transaction_lock, but must not hold an entry lock.  An operation that
 * acquired an entry before this call finishes before cancellation becomes
 * visible; every later operation observes cancelled while holding that same
 * entry lock and cannot publish after this function returns.
 */
static void
vmm_event_coordinator_close_admission(
    struct vmm_event_coordinator *coordinator)
{
	size_t i;

	for (i = 0; i < coordinator->maxcpus; i++)
		mtx_lock_spin(&coordinator->entry[i].lock);
	atomic_store_rel_int(&coordinator->cancelled, 1);
	for (i = coordinator->maxcpus; i > 0; i--)
		mtx_unlock_spin(&coordinator->entry[i - 1].lock);
}

static bool
vmm_event_coordinator_size_multiply(size_t count, size_t item_size,
    size_t *lengthp)
{
	if (count > SIZE_MAX / item_size)
		return (false);
	*lengthp = count * item_size;
	return (true);
}

static bool
vmm_event_coordinator_range_valid(const void *base, size_t length)
{
	return (vmm_address_range_valid(base, length));
}

static bool
vmm_event_coordinator_range(const void *base, size_t count, size_t item_size,
    size_t *lengthp)
{
	size_t length;

	if (!vmm_event_coordinator_size_multiply(count, item_size, &length))
		return (false);
	*lengthp = length;
	return (vmm_event_coordinator_range_valid(base, length));
}

static bool
vmm_event_coordinator_allocation_layout(uint16_t maxcpus, size_t *sizep,
    size_t *startup_offsetp)
{
	size_t alignment, base_size, entries_size, instances_size, startup_size;
	size_t startup_offset, size;

	if (!vmm_event_coordinator_size_multiply(maxcpus,
	    sizeof(struct vmm_event_coordinator_entry), &entries_size) ||
	    !vmm_event_coordinator_size_multiply(maxcpus, sizeof(uint32_t),
	    &instances_size) || !vmm_event_coordinator_size_multiply(maxcpus,
	    sizeof(struct vmm_startup_handshake_vcpu), &startup_size) ||
	    entries_size > SIZE_MAX - sizeof(struct vmm_event_coordinator) ||
	    instances_size > SIZE_MAX - sizeof(struct vmm_event_coordinator) -
	    entries_size)
		return (false);
	base_size = sizeof(struct vmm_event_coordinator) + entries_size +
	    instances_size;
	alignment = _Alignof(struct vmm_startup_handshake_vcpu);
	if (base_size > SIZE_MAX - (alignment - 1))
		return (false);
	startup_offset = roundup2(base_size, alignment);
	if (startup_size > SIZE_MAX - startup_offset)
		return (false);
	size = startup_offset + startup_size;
	*sizep = size;
	if (startup_offsetp != NULL)
		*startup_offsetp = startup_offset;
	return (true);
}

static uint32_t *
vmm_event_coordinator_checkpoint_instances(
    struct vmm_event_coordinator *coordinator)
{

	return ((uint32_t *)&coordinator->entry[coordinator->maxcpus]);
}

static const uint32_t *
vmm_event_coordinator_checkpoint_instances_const(
    const struct vmm_event_coordinator *coordinator)
{

	return ((const uint32_t *)&coordinator->entry[coordinator->maxcpus]);
}

static struct vmm_startup_handshake_vcpu *
vmm_event_coordinator_startup_records(
    struct vmm_event_coordinator *coordinator)
{
	size_t allocation_size, startup_offset;

	if (!vmm_event_coordinator_allocation_layout(coordinator->maxcpus,
	    &allocation_size, &startup_offset) ||
	    allocation_size != coordinator->allocation_size)
		return (NULL);
	return ((struct vmm_startup_handshake_vcpu *)
	    ((char *)coordinator + startup_offset));
}

static const struct vmm_startup_handshake_vcpu *
vmm_event_coordinator_startup_records_const(
    const struct vmm_event_coordinator *coordinator)
{
	size_t allocation_size, startup_offset;

	if (!vmm_event_coordinator_allocation_layout(coordinator->maxcpus,
	    &allocation_size, &startup_offset) ||
	    allocation_size != coordinator->allocation_size)
		return (NULL);
	return ((const struct vmm_startup_handshake_vcpu *)
	    ((const char *)coordinator + startup_offset));
}

static bool
vmm_event_coordinator_startup_record_empty(
    const struct vmm_startup_handshake_vcpu *record)
{

	return (record->owner_id == 0 && record->generation == 0 &&
	    record->handshake_cookie == 0 && record->storage_cookie == 0 &&
	    record->vcpuid == 0 && record->bootstrap_processor == 0 &&
	    record->entered == 0 && record->reserved16 == 0);
}

static bool
vmm_event_coordinator_overlap(const void *left, size_t left_length,
    const void *right, size_t right_length)
{
	return (vmm_address_ranges_overlap(left, left_length, right,
	    right_length));
}

static bool
vmm_event_coordinator_wait_ticket_empty(
    const struct vmm_event_wait_ticket *ticket)
{

	return (ticket->owner_id == 0 && ticket->generation == 0 &&
	    ticket->state_cookie == 0 && ticket->storage_cookie == 0 &&
	    ticket->active == 0 && ticket->reserved == 0);
}

static int
vmm_event_coordinator_validate(const struct vmm_event_coordinator *coordinator)
{
	const struct vmm_startup_handshake_vcpu *startup_records;
	size_t allocation_size, i;

	if (coordinator == NULL || coordinator->owner_id == 0 ||
	    coordinator->storage_cookie != (uintptr_t)coordinator ||
	    !vmm_event_coordinator_allocation_layout(coordinator->maxcpus,
	    &allocation_size, NULL) ||
	    coordinator->allocation_size != allocation_size ||
	    coordinator->maxcpus == 0 || coordinator->reserved16 != 0 ||
	    atomic_load_acq_int(&coordinator->cancelled) > 1 ||
	    coordinator->transaction_active > 1 ||
	    coordinator->reserved32 != 0)
		return (EINVAL);
	/* These wait-state identity fields are immutable for this lifetime. */
	if (coordinator->wait.owner_id != coordinator->owner_id ||
	    coordinator->wait.storage_cookie != (uintptr_t)&coordinator->wait ||
	    coordinator->startup_wait.owner_id != coordinator->owner_id ||
	    coordinator->startup_wait.storage_cookie !=
	    (uintptr_t)&coordinator->startup_wait ||
	    coordinator->startup_controller.owner_id != coordinator->owner_id ||
	    vmm_startup_controller_validate(
	    &coordinator->startup_controller) != 0 ||
	    coordinator->startup_handshake.owner_id != coordinator->owner_id ||
	    vmm_startup_handshake_validate(
	    &coordinator->startup_handshake) != 0)
		return (EINVAL);
	if ((coordinator->startup_handshake.phase ==
	    VMM_STARTUP_HANDSHAKE_OPEN &&
	    coordinator->startup_controller.phase ==
	    VMM_STARTUP_CONTROLLER_REVOKED) ||
	    ((coordinator->startup_handshake.phase ==
	    VMM_STARTUP_HANDSHAKE_COLLECTING ||
	    (coordinator->startup_handshake.phase ==
	    VMM_STARTUP_HANDSHAKE_COMMITTED &&
	    coordinator->startup_handshake.mode.owner ==
	    VMM_STARTUP_OWNER_KERNEL)) &&
	    coordinator->startup_controller.phase !=
	    VMM_STARTUP_CONTROLLER_CLAIMED))
		return (EINVAL);
	if ((coordinator->startup_handshake.phase ==
	    VMM_STARTUP_HANDSHAKE_CANCELLED ||
	    (coordinator->startup_handshake.phase ==
	    VMM_STARTUP_HANDSHAKE_COMMITTED &&
	    coordinator->startup_handshake.mode.owner ==
	    VMM_STARTUP_OWNER_USERSPACE)) &&
	    coordinator->startup_controller.phase !=
	    VMM_STARTUP_CONTROLLER_REVOKED)
		return (EINVAL);
	startup_records = vmm_event_coordinator_startup_records_const(coordinator);
	if (startup_records == NULL)
		return (EINVAL);
	if (coordinator->startup_handshake.phase ==
	    VMM_STARTUP_HANDSHAKE_COLLECTING ||
	    (coordinator->startup_handshake.phase ==
	    VMM_STARTUP_HANDSHAKE_COMMITTED &&
	    coordinator->startup_handshake.mode.owner ==
	    VMM_STARTUP_OWNER_KERNEL)) {
		if (coordinator->startup_handshake.vcpus != startup_records ||
		    coordinator->startup_handshake.expected_vcpus >
		    coordinator->maxcpus)
			return (EINVAL);
		for (i = coordinator->startup_handshake.expected_vcpus;
		    i < coordinator->maxcpus; i++) {
			if (!vmm_event_coordinator_startup_record_empty(
			    &startup_records[i]))
				return (EINVAL);
		}
	} else {
		for (i = 0; i < coordinator->maxcpus; i++) {
			if (!vmm_event_coordinator_startup_record_empty(
			    &startup_records[i]))
				return (EINVAL);
		}
	}
	if (coordinator->transaction_active == 0) {
		if (coordinator->checkpoint_cookie != 0 ||
		    coordinator->checkpoint_entries_cookie != 0 ||
		    coordinator->checkpoint_count != 0)
			return (EINVAL);
	} else if (coordinator->checkpoint_cookie == 0 ||
	    coordinator->checkpoint_entries_cookie == 0 ||
	    coordinator->checkpoint_count == 0 ||
	    coordinator->checkpoint_count > coordinator->maxcpus) {
		return (EINVAL);
	}
	return (0);
}

static void
vmm_event_coordinator_fail_closed_locked(
    struct vmm_event_coordinator *coordinator)
{
	int error;

	mtx_assert(&coordinator->transaction_lock, MA_OWNED);
	vmm_event_coordinator_close_admission(coordinator);
	error = vmm_startup_handshake_retire(
	    &coordinator->startup_handshake);
	if (error != 0)
		panic("%s: startup retirement failed: %d", __func__, error);
	error = vmm_startup_controller_retire(
	    &coordinator->startup_controller);
	if (error != 0)
		panic("%s: startup controller retirement failed: %d", __func__,
		    error);
	error = vmm_event_wait_cancel(&coordinator->startup_wait);
	if (error != 0)
		panic("%s: startup wait cancellation failed: %d", __func__, error);
	error = vmm_event_wait_cancel(&coordinator->wait);
	if (error != 0)
		panic("%s: event wait cancellation failed: %d", __func__, error);
}

/*
 * Keep admission and both wait channels in one fail-closed lifetime domain.
 * EOVERFLOW permanently exhausts that domain; ECANCELED is expected during
 * teardown.  Any other signal failure is an internal state-corruption
 * invariant, not a recoverable publication error: the publisher credential
 * may already have been consumed when this is called.
 */
static int
vmm_event_coordinator_signal(struct vmm_event_coordinator *coordinator)
{
	int error;

	mtx_assert(&coordinator->transaction_lock, MA_NOTOWNED);
	error = vmm_event_wait_signal(&coordinator->wait);
	if (error == EOVERFLOW || error == ECANCELED) {
		mtx_lock(&coordinator->transaction_lock);
		vmm_event_coordinator_fail_closed_locked(coordinator);
		mtx_unlock(&coordinator->transaction_lock);
	} else if (error != 0) {
		panic("%s: invalid event wait owner: %d", __func__, error);
	}
	return (error);
}

static int
vmm_event_coordinator_startup_signal(
    struct vmm_event_coordinator *coordinator)
{
	int error;

	mtx_assert(&coordinator->transaction_lock, MA_OWNED);
	error = vmm_event_wait_signal(&coordinator->startup_wait);
	if (error == EOVERFLOW || error == ECANCELED)
		vmm_event_coordinator_fail_closed_locked(coordinator);
	else if (error != 0)
		panic("%s: invalid startup wait owner: %d", __func__, error);
	return (error);
}

static void
vmm_event_coordinator_wait_ticket_release_required(
    struct vmm_event_wait_ticket *ticket)
{
	int error;

	error = vmm_event_wait_ticket_release(ticket);
	if (error != 0)
		panic("%s: prepared ticket release failed: %d", __func__, error);
}

static void
vmm_event_coordinator_lock_entries(struct vmm_event_coordinator *coordinator,
    const uint32_t *instances, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++)
		mtx_lock_spin(&coordinator->entry[instances[i]].lock);
}

static void
vmm_event_coordinator_unlock_entries(
    struct vmm_event_coordinator *coordinator, const uint32_t *instances,
    size_t count)
{
	size_t i;

	for (i = count; i > 0; i--)
		mtx_unlock_spin(&coordinator->entry[instances[i - 1]].lock);
}

static int
vmm_event_coordinator_instances_validate(
    const struct vmm_event_coordinator *coordinator,
    const uint32_t *instances, size_t count)
{
	size_t instances_length, i;

	if (count == 0 || count > coordinator->maxcpus ||
	    !vmm_event_coordinator_range(instances, count,
	    sizeof(*instances), &instances_length))
		return (EINVAL);
	for (i = 0; i < count; i++) {
		if (instances[i] >= coordinator->maxcpus ||
		    (i != 0 && instances[i - 1] >= instances[i]))
			return (EINVAL);
	}
	return (0);
}

int
vmm_event_coordinator_create(uint16_t maxcpus,
    struct vmm_event_coordinator **coordinatorp)
{
	struct vmm_event_coordinator *coordinator;
	uint64_t owner_id;
	size_t allocation_size, i;
	int error;

	if (coordinatorp == NULL || *coordinatorp != NULL || maxcpus == 0 ||
	    !vmm_event_coordinator_allocation_layout(maxcpus, &allocation_size,
	    NULL))
		return (EINVAL);
	error = vmm_event_owner_allocate(&owner_id);
	if (error != 0)
		return (error);
	coordinator = malloc(allocation_size, M_VMM_EVENT_COORDINATOR,
	    M_WAITOK | M_ZERO);
	coordinator->owner_id = owner_id;
	coordinator->allocation_size = allocation_size;
	coordinator->storage_cookie = (uintptr_t)coordinator;
	coordinator->maxcpus = maxcpus;
	mtx_init(&coordinator->transaction_lock, "vmm event transaction", NULL,
	    MTX_DEF);
	error = vmm_event_wait_init(&coordinator->wait, owner_id);
	if (error != 0)
		panic("%s: wait initialization failed: %d", __func__, error);
	error = vmm_event_wait_init(&coordinator->startup_wait, owner_id);
	if (error != 0)
		panic("%s: startup wait initialization failed: %d", __func__,
		    error);
	error = vmm_startup_controller_init(&coordinator->startup_controller,
	    owner_id);
	if (error != 0)
		panic("%s: startup controller initialization failed: %d", __func__,
		    error);
	error = vmm_startup_handshake_init(&coordinator->startup_handshake,
	    owner_id);
	if (error != 0)
		panic("%s: startup handshake initialization failed: %d", __func__,
		    error);
	for (i = 0; i < maxcpus; i++) {
		mtx_init(&coordinator->entry[i].lock, "vmm event ingress", NULL,
		    MTX_SPIN);
		error = vmm_event_ingress_init(&coordinator->entry[i].ingress,
		    owner_id);
		if (error != 0)
			panic("%s: ingress initialization failed: %d", __func__,
			    error);
		error = vmm_startup_event_init(&coordinator->entry[i].startup,
		    owner_id, i);
		if (error != 0)
			panic("%s: startup initialization failed: %d", __func__,
			    error);
	}
	*coordinatorp = coordinator;
	return (0);
}

int
vmm_event_coordinator_startup_lock_default(
    struct vmm_event_coordinator *coordinator, uint64_t *generationp)
{
	bool already_locked;
	int error;

	if (coordinator == NULL || generationp == NULL)
		return (EINVAL);
	mtx_lock(&coordinator->transaction_lock);
	error = vmm_event_coordinator_validate(coordinator);
	if (error == 0 && vmm_event_coordinator_overlap(coordinator,
	    coordinator->allocation_size, generationp, sizeof(*generationp)))
		error = EINVAL;
	if (error == 0 && atomic_load_acq_int(&coordinator->cancelled) != 0)
		error = ECANCELED;
	if (error == 0 && coordinator->transaction_active != 0)
		error = EBUSY;
	already_locked = error == 0 &&
	    coordinator->startup_handshake.phase ==
	    VMM_STARTUP_HANDSHAKE_COMMITTED &&
	    coordinator->startup_handshake.mode.owner ==
	    VMM_STARTUP_OWNER_USERSPACE &&
	    coordinator->startup_controller.phase ==
	    VMM_STARTUP_CONTROLLER_REVOKED;
	if (error == 0 && !already_locked &&
	    (coordinator->startup_handshake.phase !=
	    VMM_STARTUP_HANDSHAKE_OPEN ||
	    coordinator->startup_controller.phase !=
	    VMM_STARTUP_CONTROLLER_UNCLAIMED))
		error = EBUSY;
	if (error == 0 && !already_locked)
		error = vmm_startup_handshake_lock_default(
		    &coordinator->startup_handshake);
	if (error == 0 && !already_locked) {
		error = vmm_startup_controller_retire(
		    &coordinator->startup_controller);
		if (error != 0)
			panic("%s: default controller retirement failed: %d",
			    __func__, error);
	}
	if (error == 0 && !already_locked)
		error = vmm_event_coordinator_startup_signal(coordinator);
	if (error == 0)
		*generationp = coordinator->startup_handshake.generation;
	mtx_unlock(&coordinator->transaction_lock);
	return (error);
}

static int
vmm_event_coordinator_startup_controller_check_locked(
    struct vmm_event_coordinator *coordinator,
    const struct vmm_startup_controller_ticket *ticket)
{

	mtx_assert(&coordinator->transaction_lock, MA_OWNED);
	if (ticket == NULL || vmm_event_coordinator_overlap(coordinator,
	    coordinator->allocation_size, ticket, sizeof(*ticket)))
		return (EINVAL);
	return (vmm_startup_controller_check(
	    &coordinator->startup_controller, ticket));
}

int
vmm_event_coordinator_startup_controller_claim(
    struct vmm_event_coordinator *coordinator,
    struct vmm_startup_controller_ticket *ticket, uint64_t controller_id)
{
	int error;

	if (coordinator == NULL || ticket == NULL || controller_id == 0)
		return (EINVAL);
	mtx_lock(&coordinator->transaction_lock);
	error = vmm_event_coordinator_validate(coordinator);
	if (error == 0 && vmm_event_coordinator_overlap(coordinator,
	    coordinator->allocation_size, ticket, sizeof(*ticket)))
		error = EINVAL;
	if (error == 0 && atomic_load_acq_int(&coordinator->cancelled) != 0)
		error = ECANCELED;
	if (error == 0 && coordinator->transaction_active != 0)
		error = EBUSY;
	if (error == 0 && coordinator->startup_handshake.phase !=
	    VMM_STARTUP_HANDSHAKE_OPEN)
		error = EBUSY;
	if (error == 0)
		error = vmm_startup_controller_claim(
		    &coordinator->startup_controller, ticket, controller_id);
	mtx_unlock(&coordinator->transaction_lock);
	return (error);
}

int
vmm_event_coordinator_startup_controller_release(
    struct vmm_event_coordinator *coordinator,
    struct vmm_startup_controller_ticket *ticket)
{
	int error;

	if (coordinator == NULL || ticket == NULL)
		return (EINVAL);
	mtx_lock(&coordinator->transaction_lock);
	error = vmm_event_coordinator_validate(coordinator);
	if (error == 0)
		error = vmm_event_coordinator_startup_controller_check_locked(
		    coordinator, ticket);
	if (error == 0 && coordinator->transaction_active == 0 &&
	    coordinator->startup_handshake.phase ==
	    VMM_STARTUP_HANDSHAKE_OPEN)
		error = vmm_startup_controller_abort(
		    &coordinator->startup_controller, ticket);
	else if (error == 0) {
		vmm_event_coordinator_fail_closed_locked(coordinator);
		/*
		 * check_locked() authenticated both the ticket identity and its
		 * exact storage while transaction_lock remained held.  Retirement
		 * deliberately invalidated its generation, so a second fallible
		 * credential check would add only a panic-shaped close path.
		 */
		explicit_bzero(ticket, sizeof(*ticket));
	}
	mtx_unlock(&coordinator->transaction_lock);
	return (error);
}

int
vmm_event_coordinator_startup_configure_kernel(
    struct vmm_event_coordinator *coordinator,
    const struct vmm_startup_controller_ticket *controller_ticket,
    uint16_t expected_vcpus, uint64_t *generationp)
{
	struct vmm_startup_handshake_vcpu *records;
	int error;

	if (coordinator == NULL || controller_ticket == NULL ||
	    expected_vcpus == 0 || generationp == NULL)
		return (EINVAL);
	mtx_lock(&coordinator->transaction_lock);
	error = vmm_event_coordinator_validate(coordinator);
	if (error == 0 && vmm_event_coordinator_overlap(coordinator,
	    coordinator->allocation_size, generationp, sizeof(*generationp)))
		error = EINVAL;
	if (error == 0 && vmm_event_coordinator_overlap(controller_ticket,
	    sizeof(*controller_ticket), generationp, sizeof(*generationp)))
		error = EINVAL;
	if (error == 0)
		error = vmm_event_coordinator_startup_controller_check_locked(
		    coordinator, controller_ticket);
	if (error == 0 && atomic_load_acq_int(&coordinator->cancelled) != 0)
		error = ECANCELED;
	if (error == 0 && coordinator->transaction_active != 0)
		error = EBUSY;
	if (error == 0 && expected_vcpus > coordinator->maxcpus)
		error = EINVAL;
	records = error == 0 ?
	    vmm_event_coordinator_startup_records(coordinator) : NULL;
	if (error == 0 && records == NULL)
		error = EINVAL;
	if (error == 0)
		error = vmm_startup_handshake_configure_kernel(
		    &coordinator->startup_handshake, records, expected_vcpus);
	if (error == 0)
		error = vmm_event_coordinator_startup_signal(coordinator);
	if (error == 0)
		*generationp = coordinator->startup_handshake.generation;
	mtx_unlock(&coordinator->transaction_lock);
	return (error);
}

int
vmm_event_coordinator_startup_enter(
    struct vmm_event_coordinator *coordinator,
    const struct vmm_startup_controller_ticket *controller_ticket,
    uint16_t vcpuid, uint64_t generation, bool bootstrap_processor)
{
	bool changed;
	int error;

	if (coordinator == NULL || controller_ticket == NULL)
		return (EINVAL);
	mtx_lock(&coordinator->transaction_lock);
	error = vmm_event_coordinator_validate(coordinator);
	if (error == 0)
		error = vmm_event_coordinator_startup_controller_check_locked(
		    coordinator, controller_ticket);
	if (error == 0 && atomic_load_acq_int(&coordinator->cancelled) != 0)
		error = ECANCELED;
	if (error == 0 && coordinator->transaction_active != 0)
		error = EBUSY;
	if (error == 0 && generation !=
	    coordinator->startup_handshake.generation)
		error = ESTALE;
	changed = false;
	if (error == 0) {
		error = vmm_startup_handshake_enter(
		    &coordinator->startup_handshake, vcpuid,
		    bootstrap_processor);
		if (error == EALREADY)
			error = 0;
		else if (error == 0)
			changed = true;
	}
	if (error == 0 && changed)
		error = vmm_event_coordinator_startup_signal(coordinator);
	mtx_unlock(&coordinator->transaction_lock);
	return (error);
}

int
vmm_event_coordinator_startup_wait_ready(
    struct vmm_event_coordinator *coordinator,
    const struct vmm_startup_controller_ticket *controller_ticket,
    uint64_t generation, struct vmm_event_wait_ticket *ticket,
    const char *wmesg, int pri)
{
	bool prepared, ready;
	int error;

	if (coordinator == NULL || controller_ticket == NULL || ticket == NULL ||
	    wmesg == NULL)
		return (EINVAL);
	for (;;) {
		prepared = false;
		mtx_lock(&coordinator->transaction_lock);
		error = vmm_event_coordinator_validate(coordinator);
		if (error == 0 && vmm_event_coordinator_overlap(controller_ticket,
		    sizeof(*controller_ticket), ticket, sizeof(*ticket)))
			error = EINVAL;
		if (error == 0)
			error =
			    vmm_event_coordinator_startup_controller_check_locked(
			    coordinator, controller_ticket);
		if (error == 0 && atomic_load_acq_int(
		    &coordinator->cancelled) != 0)
			error = ECANCELED;
		if (error == 0 && vmm_event_coordinator_overlap(coordinator,
		    coordinator->allocation_size, ticket, sizeof(*ticket)))
			error = EINVAL;
		if (error == 0 &&
		    !vmm_event_coordinator_wait_ticket_empty(ticket))
			error = EBUSY;
		if (error == 0 && generation !=
		    coordinator->startup_handshake.generation)
			error = ESTALE;
		if (error == 0 &&
		    coordinator->startup_handshake.mode.owner !=
		    VMM_STARTUP_OWNER_KERNEL)
			error = EBUSY;
		ready = error == 0 &&
		    coordinator->startup_handshake.entered_vcpus ==
		    coordinator->startup_handshake.expected_vcpus &&
		    coordinator->startup_handshake.bootstrap_entered == 1;
		if (error == 0 && coordinator->startup_handshake.phase ==
		    VMM_STARTUP_HANDSHAKE_COMMITTED && !ready)
			error = EINVAL;
		if (error == 0 && coordinator->startup_handshake.phase !=
		    VMM_STARTUP_HANDSHAKE_COLLECTING &&
		    coordinator->startup_handshake.phase !=
		    VMM_STARTUP_HANDSHAKE_COMMITTED)
			error = EBUSY;
		if (error == 0) {
			if (!ready) {
				error = vmm_event_wait_prepare(
				    &coordinator->startup_wait, ticket);
				prepared = error == 0;
			}
		}
		mtx_unlock(&coordinator->transaction_lock);
		if (error != 0 || ready) {
			if (prepared)
				vmm_event_coordinator_wait_ticket_release_required(
				    ticket);
			return (error);
		}
		error = vmm_event_wait_sleep(&coordinator->startup_wait, ticket,
		    wmesg, pri);
		vmm_event_coordinator_wait_ticket_release_required(ticket);
		if (error == EAGAIN)
			continue;
		return (error);
	}
}

int
vmm_event_coordinator_startup_wait_committed(
    struct vmm_event_coordinator *coordinator,
    const struct vmm_startup_controller_ticket *controller_ticket,
    uint64_t generation, struct vmm_event_wait_ticket *ticket,
    const char *wmesg, int pri)
{
	bool committed, prepared;
	int error;

	if (coordinator == NULL || controller_ticket == NULL || ticket == NULL ||
	    wmesg == NULL)
		return (EINVAL);
	for (;;) {
		prepared = false;
		mtx_lock(&coordinator->transaction_lock);
		error = vmm_event_coordinator_validate(coordinator);
		if (error == 0 && vmm_event_coordinator_overlap(controller_ticket,
		    sizeof(*controller_ticket), ticket, sizeof(*ticket)))
			error = EINVAL;
		if (error == 0)
			error =
			    vmm_event_coordinator_startup_controller_check_locked(
			    coordinator, controller_ticket);
		if (error == 0 && atomic_load_acq_int(
		    &coordinator->cancelled) != 0)
			error = ECANCELED;
		if (error == 0 && vmm_event_coordinator_overlap(coordinator,
		    coordinator->allocation_size, ticket, sizeof(*ticket)))
			error = EINVAL;
		if (error == 0 &&
		    !vmm_event_coordinator_wait_ticket_empty(ticket))
			error = EBUSY;
		if (error == 0 && generation !=
		    coordinator->startup_handshake.generation)
			error = ESTALE;
		if (error == 0 &&
		    coordinator->startup_handshake.mode.owner !=
		    VMM_STARTUP_OWNER_KERNEL)
			error = EBUSY;
		committed = error == 0 &&
		    coordinator->startup_handshake.phase ==
		    VMM_STARTUP_HANDSHAKE_COMMITTED;
		if (error == 0 && !committed &&
		    coordinator->startup_handshake.phase !=
		    VMM_STARTUP_HANDSHAKE_COLLECTING)
			error = EBUSY;
		if (error == 0 && !committed) {
			error = vmm_event_wait_prepare(
			    &coordinator->startup_wait, ticket);
			prepared = error == 0;
		}
		mtx_unlock(&coordinator->transaction_lock);
		if (error != 0 || committed) {
			if (prepared)
				vmm_event_coordinator_wait_ticket_release_required(
				    ticket);
			return (error);
		}
		error = vmm_event_wait_sleep(&coordinator->startup_wait, ticket,
		    wmesg, pri);
		vmm_event_coordinator_wait_ticket_release_required(ticket);
		if (error == EAGAIN)
			continue;
		return (error);
	}
}

int
vmm_event_coordinator_startup_commit(
    struct vmm_event_coordinator *coordinator,
    const struct vmm_startup_controller_ticket *controller_ticket,
    uint64_t generation)
{
	bool already_committed;
	int error;

	if (coordinator == NULL || controller_ticket == NULL)
		return (EINVAL);
	mtx_lock(&coordinator->transaction_lock);
	error = vmm_event_coordinator_validate(coordinator);
	if (error == 0)
		error = vmm_event_coordinator_startup_controller_check_locked(
		    coordinator, controller_ticket);
	if (error == 0 && atomic_load_acq_int(&coordinator->cancelled) != 0)
		error = ECANCELED;
	if (error == 0 && coordinator->transaction_active != 0)
		error = EBUSY;
	if (error == 0 && generation !=
	    coordinator->startup_handshake.generation)
		error = ESTALE;
	already_committed = error == 0 &&
	    coordinator->startup_handshake.phase ==
	    VMM_STARTUP_HANDSHAKE_COMMITTED &&
	    coordinator->startup_handshake.mode.owner ==
	    VMM_STARTUP_OWNER_KERNEL;
	if (error == 0 && !already_committed)
		error = vmm_startup_handshake_commit(
		    &coordinator->startup_handshake);
	if (error == 0 && !already_committed)
		error = vmm_event_coordinator_startup_signal(coordinator);
	mtx_unlock(&coordinator->transaction_lock);
	return (error);
}

int
vmm_event_coordinator_startup_status(
    struct vmm_event_coordinator *coordinator,
    const struct vmm_startup_controller_ticket *controller_ticket,
    struct vmm_startup_handshake_status *status)
{
	int error;

	if (coordinator == NULL || controller_ticket == NULL || status == NULL)
		return (EINVAL);
	mtx_lock(&coordinator->transaction_lock);
	error = vmm_event_coordinator_validate(coordinator);
	if (error == 0 && vmm_event_coordinator_overlap(coordinator,
	    coordinator->allocation_size, status, sizeof(*status)))
		error = EINVAL;
	if (error == 0 && vmm_event_coordinator_overlap(controller_ticket,
	    sizeof(*controller_ticket), status, sizeof(*status)))
		error = EINVAL;
	if (error == 0)
		error = vmm_event_coordinator_startup_controller_check_locked(
		    coordinator, controller_ticket);
	if (error == 0 && atomic_load_acq_int(&coordinator->cancelled) != 0)
		error = ECANCELED;
	if (error == 0)
		error = vmm_startup_handshake_status(
		    &coordinator->startup_handshake, status);
	mtx_unlock(&coordinator->transaction_lock);
	return (error);
}

int
vmm_event_coordinator_startup_execution_status(
    struct vmm_event_coordinator *coordinator,
    struct vmm_startup_handshake_status *status)
{
	int error;

	if (coordinator == NULL || status == NULL)
		return (EINVAL);
	mtx_lock(&coordinator->transaction_lock);
	error = vmm_event_coordinator_validate(coordinator);
	if (error == 0 && vmm_event_coordinator_overlap(coordinator,
	    coordinator->allocation_size, status, sizeof(*status)))
		error = EINVAL;
	if (error == 0 && atomic_load_acq_int(&coordinator->cancelled) != 0)
		error = ECANCELED;
	if (error == 0 && coordinator->startup_handshake.phase !=
	    VMM_STARTUP_HANDSHAKE_COMMITTED)
		error = EAGAIN;
	if (error == 0)
		error = vmm_startup_handshake_status(
		    &coordinator->startup_handshake, status);
	mtx_unlock(&coordinator->transaction_lock);
	return (error);
}

int
vmm_event_coordinator_cancel(struct vmm_event_coordinator *coordinator)
{
	int error;

	if (coordinator == NULL)
		return (EINVAL);
	mtx_lock(&coordinator->transaction_lock);
	error = vmm_event_coordinator_validate(coordinator);
	if (error == 0)
		vmm_event_coordinator_fail_closed_locked(coordinator);
	mtx_unlock(&coordinator->transaction_lock);
	return (error);
}

int
vmm_event_coordinator_drain(struct vmm_event_coordinator *coordinator,
    const char *wmesg, int pri)
{
	int error;

	if (coordinator == NULL || wmesg == NULL ||
	    atomic_load_acq_int(&coordinator->cancelled) == 0)
		return (EINVAL);
	error = vmm_event_wait_drain(&coordinator->startup_wait, wmesg, pri);
	if (error == 0)
		error = vmm_event_wait_drain(&coordinator->wait, wmesg, pri);
	return (error);
}

/*
 * Cancellation closes admission before this drain begins.  The coordinator's
 * sleepqueue-chain lock interlocks the all-ingress predicate check with
 * enqueue, while publisher_exit() takes the same interlock before broadcast.
 * Thus an exit immediately before, during, or after the check cannot be lost.
 */
int
vmm_event_coordinator_drain_publishers(
    struct vmm_event_coordinator *coordinator, const char *wmesg, int pri)
{
	size_t i;
	bool drained;
	int error;

	if (coordinator == NULL || wmesg == NULL ||
	    atomic_load_acq_int(&coordinator->cancelled) == 0)
		return (EINVAL);
	mtx_lock(&coordinator->transaction_lock);
	error = vmm_event_coordinator_validate(coordinator);
	if (error == 0 && coordinator->transaction_active != 0)
		error = EBUSY;
	mtx_unlock(&coordinator->transaction_lock);
	if (error != 0)
		return (error);

	sleepq_lock(coordinator);
	for (;;) {
		error = 0;
		drained = true;
		for (i = 0; i < coordinator->maxcpus; i++)
			mtx_lock_spin(&coordinator->entry[i].lock);
		for (i = 0; i < coordinator->maxcpus; i++) {
			if (vmm_event_ingress_validate(
			    &coordinator->entry[i].ingress) != 0 ||
			    vmm_startup_event_validate(
			    &coordinator->entry[i].startup) != 0) {
				error = EINVAL;
				break;
			}
			if (coordinator->entry[i].ingress.active_publishers != 0)
				drained = false;
			if (coordinator->entry[i].startup.active_claim_id != 0)
				drained = false;
		}
		for (i = coordinator->maxcpus; i > 0; i--)
			mtx_unlock_spin(&coordinator->entry[i - 1].lock);
		if (error != 0 || drained) {
			sleepq_release(coordinator);
			return (error);
		}
		sleepq_add(coordinator, NULL, wmesg, SLEEPQ_SLEEP, 0);
		DROP_GIANT();
		sleepq_wait(coordinator, pri);
		PICKUP_GIANT();
		sleepq_lock(coordinator);
	}
}

int
vmm_event_coordinator_destroy(struct vmm_event_coordinator *coordinator)
{
	size_t allocation_size, i;
	int error;

	if (coordinator == NULL ||
	    atomic_load_acq_int(&coordinator->cancelled) == 0)
		return (EINVAL);
	error = vmm_event_coordinator_drain(coordinator, "vmecdrn", 0);
	if (error != 0)
		return (error);
	mtx_lock(&coordinator->transaction_lock);
	error = vmm_event_coordinator_validate(coordinator);
	if (error == 0 && coordinator->transaction_active != 0)
		error = EBUSY;
	if (error == 0) {
		for (i = 0; i < coordinator->maxcpus; i++)
			mtx_lock_spin(&coordinator->entry[i].lock);
		for (i = 0; i < coordinator->maxcpus; i++) {
			if (vmm_event_ingress_validate(
			    &coordinator->entry[i].ingress) != 0 ||
			    vmm_startup_event_validate(
			    &coordinator->entry[i].startup) != 0 ||
			    coordinator->entry[i].ingress.mode !=
			    VMM_EVENT_INGRESS_OPEN ||
			    coordinator->entry[i].ingress.active_publishers != 0 ||
			    coordinator->entry[i].startup.active_claim_id != 0)
				error = EBUSY;
			if (error != 0)
				break;
		}
		for (i = coordinator->maxcpus; i > 0; i--)
			mtx_unlock_spin(&coordinator->entry[i - 1].lock);
	}
	mtx_unlock(&coordinator->transaction_lock);
	if (error != 0)
		return (error);
	for (i = 0; i < coordinator->maxcpus; i++)
		mtx_destroy(&coordinator->entry[i].lock);
	mtx_destroy(&coordinator->transaction_lock);
	allocation_size = coordinator->allocation_size;
	explicit_bzero(coordinator, allocation_size);
	free(coordinator, M_VMM_EVENT_COORDINATOR);
	return (0);
}

int
vmm_event_coordinator_reset(struct vmm_event_coordinator *coordinator)
{
	size_t i;
	int error;

	if (coordinator == NULL)
		return (EINVAL);
	mtx_lock(&coordinator->transaction_lock);
	error = vmm_event_coordinator_validate(coordinator);
	if (error == 0 && (atomic_load_acq_int(&coordinator->cancelled) != 0 ||
	    coordinator->transaction_active != 0))
		error = atomic_load_acq_int(&coordinator->cancelled) != 0 ?
		    ECANCELED : EBUSY;
	if (error != 0) {
		mtx_unlock(&coordinator->transaction_lock);
		return (error);
	}
	error = vmm_startup_handshake_reset_check(
	    &coordinator->startup_handshake);
	if (error != 0) {
		mtx_unlock(&coordinator->transaction_lock);
		return (error);
	}
	for (i = 0; i < coordinator->maxcpus; i++)
		mtx_lock_spin(&coordinator->entry[i].lock);
	for (i = 0; i < coordinator->maxcpus; i++) {
		if (vmm_event_ingress_validate(&coordinator->entry[i].ingress) !=
		    0 || coordinator->entry[i].ingress.mode !=
		    VMM_EVENT_INGRESS_OPEN ||
		    coordinator->entry[i].ingress.active_publishers != 0) {
			error = EBUSY;
			break;
		}
		if (coordinator->entry[i].ingress.publisher_generation ==
		    UINT64_MAX) {
			error = EOVERFLOW;
			break;
		}
		if (vmm_startup_event_validate(
		    &coordinator->entry[i].startup) != 0) {
			error = EINVAL;
			break;
		}
		if (coordinator->entry[i].startup.active_claim_id != 0) {
			error = EBUSY;
			break;
		}
		if (coordinator->entry[i].startup.generation == UINT64_MAX) {
			error = EOVERFLOW;
			break;
		}
	}
	if (error == 0) {
		for (i = 0; i < coordinator->maxcpus; i++) {
			coordinator->entry[i].ingress.publisher_generation++;
			error = vmm_startup_event_reset(
			    &coordinator->entry[i].startup);
			if (error != 0)
				panic("%s: startup reset failed after preflight: %d",
				    __func__, error);
		}
		error = vmm_startup_handshake_reset(
		    &coordinator->startup_handshake);
		if (error != 0)
			panic("%s: handshake reset failed after preflight: %d",
			    __func__, error);
	}
	for (i = coordinator->maxcpus; i > 0; i--)
		mtx_unlock_spin(&coordinator->entry[i - 1].lock);
	if (error == 0)
		error = vmm_event_coordinator_startup_signal(coordinator);
	mtx_unlock(&coordinator->transaction_lock);
	if (error == 0)
		error = vmm_event_coordinator_signal(coordinator);
	return (error);
}

static int
vmm_event_coordinator_startup_ready(
    struct vmm_event_coordinator *coordinator,
    struct vmm_event_coordinator_entry *entry)
{

	if (atomic_load_acq_int(&coordinator->cancelled) != 0)
		return (ECANCELED);
	if (vmm_event_ingress_validate(&entry->ingress) != 0 ||
	    vmm_startup_event_validate(&entry->startup) != 0)
		return (EINVAL);
	if (entry->ingress.mode != VMM_EVENT_INGRESS_OPEN)
		return (EBUSY);
	return (0);
}

int
vmm_event_coordinator_startup_publish_init(
    struct vmm_event_coordinator *coordinator, uint16_t vcpuid)
{
	struct vmm_event_coordinator_entry *entry;
	int error;

	if (coordinator == NULL || vcpuid >= coordinator->maxcpus)
		return (EINVAL);
	entry = &coordinator->entry[vcpuid];
	mtx_lock_spin(&entry->lock);
	error = vmm_event_coordinator_startup_ready(coordinator, entry);
	if (error == 0)
		error = vmm_startup_event_publish_init(&entry->startup);
	mtx_unlock_spin(&entry->lock);
	return (error);
}

int
vmm_event_coordinator_startup_publish_sipi(
    struct vmm_event_coordinator *coordinator, uint16_t vcpuid,
    uint8_t vector)
{
	struct vmm_event_coordinator_entry *entry;
	int error;

	if (coordinator == NULL || vcpuid >= coordinator->maxcpus)
		return (EINVAL);
	entry = &coordinator->entry[vcpuid];
	mtx_lock_spin(&entry->lock);
	error = vmm_event_coordinator_startup_ready(coordinator, entry);
	if (error == 0)
		error = vmm_startup_event_publish_sipi(&entry->startup, vector);
	mtx_unlock_spin(&entry->lock);
	return (error);
}

int
vmm_event_coordinator_startup_claim_begin(
    struct vmm_event_coordinator *coordinator, uint16_t vcpuid,
    struct vmm_startup_event_claim *claim)
{
	struct vmm_event_coordinator_entry *entry;
	int error;

	if (coordinator == NULL || claim == NULL ||
	    vcpuid >= coordinator->maxcpus ||
	    vmm_event_coordinator_overlap(coordinator,
	    coordinator->allocation_size, claim, sizeof(*claim)))
		return (EINVAL);
	entry = &coordinator->entry[vcpuid];
	mtx_lock_spin(&entry->lock);
	error = vmm_event_coordinator_startup_ready(coordinator, entry);
	if (error == 0)
		error = vmm_startup_event_claim_begin(&entry->startup, claim);
	mtx_unlock_spin(&entry->lock);
	return (error);
}

int
vmm_event_coordinator_startup_claim_check(
    struct vmm_event_coordinator *coordinator, uint16_t vcpuid,
    const struct vmm_startup_event_claim *claim)
{
	struct vmm_event_coordinator_entry *entry;
	int error;

	if (coordinator == NULL || claim == NULL ||
	    vcpuid >= coordinator->maxcpus ||
	    vmm_event_coordinator_overlap(coordinator,
	    coordinator->allocation_size, claim, sizeof(*claim)))
		return (EINVAL);
	entry = &coordinator->entry[vcpuid];
	mtx_lock_spin(&entry->lock);
	if (vmm_event_ingress_validate(&entry->ingress) != 0)
		error = EINVAL;
	else
		error = vmm_startup_event_claim_check(&entry->startup, claim);
	mtx_unlock_spin(&entry->lock);
	return (error);
}

static int
vmm_event_coordinator_startup_claim_end(
    struct vmm_event_coordinator *coordinator, uint16_t vcpuid,
    struct vmm_startup_event_claim *claim, bool aborting)
{
	struct vmm_event_coordinator_entry *entry;
	int error;

	if (coordinator == NULL || claim == NULL ||
	    vcpuid >= coordinator->maxcpus ||
	    vmm_event_coordinator_overlap(coordinator,
	    coordinator->allocation_size, claim, sizeof(*claim)))
		return (EINVAL);
	entry = &coordinator->entry[vcpuid];
	mtx_lock_spin(&entry->lock);
	if (vmm_event_ingress_validate(&entry->ingress) != 0 ||
	    vmm_startup_event_validate(&entry->startup) != 0)
		error = EINVAL;
	else if (aborting)
		error = vmm_startup_event_claim_abort(&entry->startup, claim);
	else
		error = vmm_startup_event_claim_finish(&entry->startup, claim);
	mtx_unlock_spin(&entry->lock);
	if (error == 0) {
		(void)vmm_event_coordinator_signal(coordinator);
		if (atomic_load_acq_int(&coordinator->cancelled) != 0) {
			sleepq_lock(coordinator);
			sleepq_broadcast(coordinator, SLEEPQ_SLEEP, 0, 0);
			sleepq_release(coordinator);
		}
	}
	return (error);
}

int
vmm_event_coordinator_startup_claim_finish(
    struct vmm_event_coordinator *coordinator, uint16_t vcpuid,
    struct vmm_startup_event_claim *claim)
{

	return (vmm_event_coordinator_startup_claim_end(coordinator, vcpuid,
	    claim, false));
}

int
vmm_event_coordinator_startup_claim_abort(
    struct vmm_event_coordinator *coordinator, uint16_t vcpuid,
    struct vmm_startup_event_claim *claim)
{

	return (vmm_event_coordinator_startup_claim_end(coordinator, vcpuid,
	    claim, true));
}

int
vmm_event_coordinator_startup_run_token_capture(
    struct vmm_event_coordinator *coordinator, uint16_t vcpuid,
    struct vmm_startup_event_run_token *token)
{
	struct vmm_event_coordinator_entry *entry;
	int error;

	if (coordinator == NULL || token == NULL ||
	    vcpuid >= coordinator->maxcpus ||
	    vmm_event_coordinator_overlap(coordinator,
	    coordinator->allocation_size, token, sizeof(*token)))
		return (EINVAL);
	entry = &coordinator->entry[vcpuid];
	mtx_lock_spin(&entry->lock);
	error = vmm_event_coordinator_startup_ready(coordinator, entry);
	if (error == 0)
		error = vmm_startup_event_run_token_capture(&entry->startup,
		    token);
	mtx_unlock_spin(&entry->lock);
	return (error);
}

int
vmm_event_coordinator_startup_run_token_check(
    struct vmm_event_coordinator *coordinator, uint16_t vcpuid,
    const struct vmm_startup_event_run_token *token)
{
	struct vmm_event_coordinator_entry *entry;
	int error;

	if (coordinator == NULL || token == NULL ||
	    vcpuid >= coordinator->maxcpus ||
	    vmm_event_coordinator_overlap(coordinator,
	    coordinator->allocation_size, token, sizeof(*token)))
		return (EINVAL);
	entry = &coordinator->entry[vcpuid];
	mtx_lock_spin(&entry->lock);
	error = vmm_event_coordinator_startup_ready(coordinator, entry);
	if (error == 0)
		error = vmm_startup_event_run_token_check(&entry->startup,
		    token);
	mtx_unlock_spin(&entry->lock);
	return (error);
}

static int
vmm_event_coordinator_startup_publish_value(
    struct vmm_startup_event_state *state,
    enum vmm_startup_event_kind kind, uint8_t vector)
{

	switch (kind) {
	case VMM_STARTUP_EVENT_INIT:
		return (vector == 0 ? vmm_startup_event_publish_init(state) :
		    EINVAL);
	case VMM_STARTUP_EVENT_SIPI:
		return (vmm_startup_event_publish_sipi(state, vector));
	default:
		return (EINVAL);
	}
}

int
vmm_event_coordinator_startup_publish_set(
    struct vmm_event_coordinator *coordinator, const cpuset_t *instances,
    enum vmm_startup_event_kind kind, uint8_t vector)
{
	struct vmm_event_coordinator_entry *entry;
	struct vmm_startup_event_state trial_state;
	int i, last;
	int commit_error, error;

	if (coordinator == NULL || instances == NULL ||
	    vmm_event_coordinator_overlap(coordinator,
	    coordinator->allocation_size, instances, sizeof(*instances)) ||
	    kind <= VMM_STARTUP_EVENT_NONE ||
	    kind >= VMM_STARTUP_EVENT_KIND_LAST ||
	    (kind == VMM_STARTUP_EVENT_INIT && vector != 0))
		return (EINVAL);
	error = EINVAL;
	last = 0;
	CPU_FOREACH_ISSET(i, instances) {
		if (i >= coordinator->maxcpus)
			return (EINVAL);
		error = 0;
		last = i + 1;
	}
	if (error != 0)
		return (error);

	/*
	 * Keep every selected entry immutable while privately preflighting the
	 * finite generation and coalescing rules.  No claim escapes this call;
	 * each target may acquire one later from durable coordinator storage.
	 */
	CPU_FOREACH_ISSET(i, instances)
		mtx_lock_spin(&coordinator->entry[i].lock);
	CPU_FOREACH_ISSET(i, instances) {
		entry = &coordinator->entry[i];
		error = vmm_event_coordinator_startup_ready(coordinator, entry);
		if (error != 0)
			break;
		trial_state = entry->startup;
		trial_state.storage_cookie = (uintptr_t)&trial_state;
		error = vmm_event_coordinator_startup_publish_value(&trial_state,
		    kind, vector);
		if (error != 0)
			break;
	}
	if (error == 0) {
		CPU_FOREACH_ISSET(i, instances) {
			entry = &coordinator->entry[i];
			commit_error =
			    vmm_event_coordinator_startup_publish_value(
			    &entry->startup, kind, vector);
			if (commit_error != 0)
				panic("%s: startup commit failed after preflight: %d",
				    __func__, commit_error);
		}
	}
	for (i = last; i > 0; i--) {
		if (CPU_ISSET(i - 1, instances))
			mtx_unlock_spin(&coordinator->entry[i - 1].lock);
	}
	return (error);
}

/*
 * Select the committed startup owner for one INIT/SIPI target set and, for a
 * kernel owner, publish the whole set atomically before the decision becomes
 * visible.  transaction_lock is held across owner observation and
 * publication so a concurrent checkpoint, reset, or ownership change cannot
 * split the two.  On any failure nothing is published and the output is
 * untouched: the caller must fail closed rather than deliver through the
 * other route, which could duplicate the event.  A userspace decision
 * publishes nothing; the caller retains the historical exit contract.
 */
int
vmm_event_coordinator_startup_route_set(
    struct vmm_event_coordinator *coordinator, const cpuset_t *instances,
    enum vmm_startup_event_kind kind, uint8_t vector,
    struct vmm_startup_delivery *delivery)
{
	struct vmm_startup_delivery candidate;
	size_t target_count;
	int i;
	int error;

	if (coordinator == NULL || instances == NULL || delivery == NULL ||
	    vmm_event_coordinator_overlap(coordinator,
	    coordinator->allocation_size, instances, sizeof(*instances)) ||
	    vmm_event_coordinator_overlap(coordinator,
	    coordinator->allocation_size, delivery, sizeof(*delivery)) ||
	    vmm_event_coordinator_overlap(instances, sizeof(*instances),
	    delivery, sizeof(*delivery)) ||
	    kind <= VMM_STARTUP_EVENT_NONE ||
	    kind >= VMM_STARTUP_EVENT_KIND_LAST ||
	    (kind == VMM_STARTUP_EVENT_INIT && vector != 0))
		return (EINVAL);
	target_count = 0;
	CPU_FOREACH_ISSET(i, instances) {
		if (i >= coordinator->maxcpus)
			return (EINVAL);
		target_count++;
	}
	if (target_count == 0)
		return (EINVAL);

	mtx_lock(&coordinator->transaction_lock);
	error = vmm_event_coordinator_validate(coordinator);
	if (error == 0 && atomic_load_acq_int(&coordinator->cancelled) != 0)
		error = ECANCELED;
	/*
	 * Routing requires the committed execution contract; before commit no
	 * vCPU can be executing guest code that generates a startup event.
	 */
	if (error == 0 && coordinator->startup_handshake.phase !=
	    VMM_STARTUP_HANDSHAKE_COMMITTED)
		error = EAGAIN;
	if (error == 0)
		error = vmm_startup_delivery_decide(
		    &coordinator->startup_handshake.mode, kind, vector,
		    target_count,
		    atomic_load_acq_int(&coordinator->cancelled) != 0,
		    coordinator->transaction_active != 0, &candidate);
	if (error == 0 && candidate.kernel_publication != 0)
		error = vmm_event_coordinator_startup_publish_set(coordinator,
		    instances, kind, vector);
	if (error == 0)
		*delivery = candidate;
	mtx_unlock(&coordinator->transaction_lock);
	return (error);
}

int
vmm_event_coordinator_startup_publish_claim_batch(
    struct vmm_event_coordinator *coordinator, const uint32_t *instances,
    size_t count, enum vmm_startup_event_kind kind, uint8_t vector,
    struct vmm_startup_event_claim *claims)
{
	struct vmm_event_coordinator_entry *entry;
	struct vmm_startup_event_claim trial_claim;
	struct vmm_startup_event_state trial_state;
	size_t claims_length, instances_length, i;
	int commit_error, error;

	if (coordinator == NULL || instances == NULL || claims == NULL ||
	    !vmm_event_coordinator_range(instances, count,
	    sizeof(*instances), &instances_length) ||
	    !vmm_event_coordinator_range(claims, count, sizeof(*claims),
	    &claims_length) ||
	    vmm_event_coordinator_overlap(instances, instances_length, claims,
	    claims_length) ||
	    vmm_event_coordinator_overlap(coordinator,
	    coordinator->allocation_size, instances, instances_length) ||
	    vmm_event_coordinator_overlap(coordinator,
	    coordinator->allocation_size, claims, claims_length) ||
	    kind <= VMM_STARTUP_EVENT_NONE ||
	    kind >= VMM_STARTUP_EVENT_KIND_LAST ||
	    (kind == VMM_STARTUP_EVENT_INIT && vector != 0))
		return (EINVAL);
	error = vmm_event_coordinator_instances_validate(coordinator, instances,
	    count);
	if (error != 0)
		return (error);

	/*
	 * Retain every entry lock from the first trial through the last commit.
	 * The trial uses private storage, so a finite-identity failure on any
	 * target cannot expose a partial broadcast.  With the complete input set
	 * held immutable, the identical commit operations are infallible.
	 */
	vmm_event_coordinator_lock_entries(coordinator, instances, count);
	for (i = 0; i < count; i++) {
		entry = &coordinator->entry[instances[i]];
		error = vmm_event_coordinator_startup_ready(coordinator, entry);
		if (error != 0)
			break;
		trial_state = entry->startup;
		trial_state.storage_cookie = (uintptr_t)&trial_state;
		trial_claim = claims[i];
		error = vmm_startup_event_publish_claim(&trial_state, kind,
		    vector, &trial_claim);
		if (error != 0)
			break;
	}
	if (error == 0) {
		for (i = 0; i < count; i++) {
			entry = &coordinator->entry[instances[i]];
			commit_error = vmm_startup_event_publish_claim(
			    &entry->startup, kind, vector, &claims[i]);
			if (commit_error != 0)
				panic("%s: startup commit failed after preflight: %d",
				    __func__, commit_error);
		}
	}
	vmm_event_coordinator_unlock_entries(coordinator, instances, count);
	return (error);
}

int
vmm_event_coordinator_publisher_enter(
    struct vmm_event_coordinator *coordinator, uint16_t vcpuid,
    struct vmm_event_ingress_ticket *ticket)
{
	struct vmm_event_coordinator_entry *entry;
	int error;

	if (coordinator == NULL || ticket == NULL ||
	    vcpuid >= coordinator->maxcpus ||
	    vmm_event_coordinator_overlap(coordinator,
	    coordinator->allocation_size, ticket, sizeof(*ticket)))
		return (EINVAL);
	if (atomic_load_acq_int(&coordinator->cancelled) != 0)
		return (ECANCELED);
	entry = &coordinator->entry[vcpuid];
	mtx_lock_spin(&entry->lock);
	if (atomic_load_acq_int(&coordinator->cancelled) != 0)
		error = ECANCELED;
	else
		error = vmm_event_ingress_publisher_enter(&entry->ingress,
		    ticket);
	mtx_unlock_spin(&entry->lock);
	return (error);
}

int
vmm_event_coordinator_publisher_exit(
    struct vmm_event_coordinator *coordinator, uint16_t vcpuid,
    struct vmm_event_ingress_ticket *ticket)
{
	struct vmm_event_coordinator_entry *entry;
	int error;

	if (coordinator == NULL || ticket == NULL ||
	    vcpuid >= coordinator->maxcpus ||
	    vmm_event_coordinator_overlap(coordinator,
	    coordinator->allocation_size, ticket, sizeof(*ticket)))
		return (EINVAL);
	entry = &coordinator->entry[vcpuid];
	mtx_lock_spin(&entry->lock);
	error = vmm_event_ingress_publisher_exit(&entry->ingress, ticket);
	mtx_unlock_spin(&entry->lock);
	if (error == 0) {
		(void)vmm_event_coordinator_signal(coordinator);
		if (atomic_load_acq_int(&coordinator->cancelled) != 0) {
			sleepq_lock(coordinator);
			sleepq_broadcast(coordinator, SLEEPQ_SLEEP, 0, 0);
			sleepq_release(coordinator);
		}
	}
	return (error);
}

int
vmm_event_coordinator_publisher_enter_or_defer(
    struct vmm_event_coordinator *coordinator, uint16_t vcpuid,
    struct vmm_event_ingress_ticket *ticket, uint64_t event_bit,
    uint64_t valid_mask, bool *deferredp)
{
	struct vmm_event_coordinator_entry *entry;
	bool deferred;
	int error;

	if (coordinator == NULL || ticket == NULL || deferredp == NULL ||
	    vcpuid >= coordinator->maxcpus || vmm_event_coordinator_overlap(ticket,
	    sizeof(*ticket), deferredp, sizeof(*deferredp)) ||
	    vmm_event_coordinator_overlap(coordinator,
	    coordinator->allocation_size, ticket, sizeof(*ticket)) ||
	    vmm_event_coordinator_overlap(coordinator,
	    coordinator->allocation_size, deferredp, sizeof(*deferredp)))
		return (EINVAL);
	if (atomic_load_acq_int(&coordinator->cancelled) != 0)
		return (ECANCELED);
	entry = &coordinator->entry[vcpuid];
	mtx_lock_spin(&entry->lock);
	if (atomic_load_acq_int(&coordinator->cancelled) != 0)
		error = ECANCELED;
	else if (ticket->owner_id != 0 || ticket->publisher_generation != 0 ||
	    ticket->state_cookie != 0 || ticket->storage_cookie != 0 ||
	    ticket->active != 0 || ticket->reserved != 0)
		error = EBUSY;
	else if (entry->ingress.mode == VMM_EVENT_INGRESS_OPEN) {
		error = vmm_event_ingress_publisher_enter(&entry->ingress, ticket);
		deferred = false;
	} else {
		error = vmm_event_ingress_defer_idempotent(&entry->ingress,
		    event_bit, valid_mask);
		deferred = true;
	}
	mtx_unlock_spin(&entry->lock);
	if (error == 0)
		*deferredp = deferred;
	return (error);
}

static int
vmm_event_coordinator_checkpoint_binding_validate(
    const struct vmm_event_coordinator *coordinator,
    const struct vmm_event_checkpoint *checkpoint)
{

	if (vmm_event_coordinator_validate(coordinator) != 0 ||
	    coordinator->transaction_active != 1 || checkpoint == NULL ||
	    coordinator->checkpoint_cookie != (uintptr_t)checkpoint ||
	    coordinator->checkpoint_entries_cookie !=
	    (uintptr_t)checkpoint->entries ||
	    coordinator->checkpoint_count != checkpoint->count)
		return (ESTALE);
	return (0);
}

static int
vmm_event_coordinator_checkpoint_indices_validate(
    const struct vmm_event_coordinator *coordinator,
    const struct vmm_event_checkpoint *checkpoint)
{
	const uint32_t *instances;
	size_t i;

	instances = vmm_event_coordinator_checkpoint_instances_const(
	    coordinator);
	for (i = 0; i < coordinator->checkpoint_count; i++) {
		if (instances[i] >= coordinator->maxcpus ||
		    (i != 0 && instances[i - 1] >= instances[i]) ||
		    checkpoint->entries[i].state !=
		    &coordinator->entry[instances[i]].ingress)
			return (ESTALE);
	}
	return (0);
}

static void
vmm_event_coordinator_lock_checkpoint(
    struct vmm_event_coordinator *coordinator,
    const struct vmm_event_checkpoint *checkpoint __unused)
{
	const uint32_t *instances;
	size_t i;

	instances = vmm_event_coordinator_checkpoint_instances_const(
	    coordinator);
	for (i = 0; i < coordinator->checkpoint_count; i++)
		mtx_lock_spin(&coordinator->entry[instances[i]].lock);
}

static void
vmm_event_coordinator_unlock_checkpoint(
    struct vmm_event_coordinator *coordinator,
    const struct vmm_event_checkpoint *checkpoint __unused)
{
	const uint32_t *instances;
	size_t i;

	instances = vmm_event_coordinator_checkpoint_instances_const(
	    coordinator);
	for (i = coordinator->checkpoint_count; i > 0; i--)
		mtx_unlock_spin(&coordinator->entry[instances[i - 1]].lock);
}

int
vmm_event_coordinator_checkpoint_begin(
    struct vmm_event_coordinator *coordinator,
    struct vmm_event_checkpoint *checkpoint,
    struct vmm_event_checkpoint_entry *entries, const uint32_t *instances,
    size_t count)
{
	uint32_t *checkpoint_instances;
	uint64_t checkpoint_owner_id;
	size_t entries_length, instances_length, i;
	bool instances_staged;
	int error;

	if (coordinator == NULL || checkpoint == NULL || entries == NULL ||
	    instances == NULL || !vmm_event_coordinator_range(entries, count,
	    sizeof(*entries), &entries_length) ||
	    !vmm_event_coordinator_range(instances, count, sizeof(*instances),
	    &instances_length) ||
	    vmm_event_coordinator_overlap(entries, entries_length, instances,
	    instances_length) || vmm_event_coordinator_overlap(checkpoint,
	    sizeof(*checkpoint), instances, instances_length) ||
	    vmm_event_coordinator_overlap(checkpoint, sizeof(*checkpoint), entries,
	    entries_length))
		return (EINVAL);
	instances_staged = false;
	mtx_lock(&coordinator->transaction_lock);
	error = vmm_event_coordinator_validate(coordinator);
	if (error == 0 && (count == 0 || count > coordinator->maxcpus))
		error = E2BIG;
	if (error == 0 && (vmm_event_coordinator_overlap(coordinator,
	    coordinator->allocation_size, checkpoint, sizeof(*checkpoint)) ||
	    vmm_event_coordinator_overlap(coordinator,
	    coordinator->allocation_size, entries, entries_length) ||
	    vmm_event_coordinator_overlap(coordinator,
	    coordinator->allocation_size, instances, instances_length)))
		error = EINVAL;
	if (error == 0 && atomic_load_acq_int(&coordinator->cancelled) != 0)
		error = ECANCELED;
	if (error == 0 && coordinator->transaction_active != 0)
		error = EBUSY;
	if (error != 0)
		goto out;
	checkpoint_instances =
	    vmm_event_coordinator_checkpoint_instances(coordinator);
	memcpy(checkpoint_instances, instances, instances_length);
	instances_staged = true;
	error = vmm_event_coordinator_instances_validate(coordinator,
	    checkpoint_instances, count);
	if (error != 0)
		goto out;
	for (i = 0; i < count; i++) {
		if (entries[i].state != NULL || entries[i].lease.owner_id != 0 ||
		    entries[i].lease.lease_id != 0 ||
		    entries[i].lease.state_cookie != 0 ||
		    entries[i].lease.storage_cookie != 0 ||
		    entries[i].lease.active != 0 ||
		    entries[i].lease.reserved != 0 ||
		    entries[i].deferred_mask != 0) {
			error = EBUSY;
			goto out;
		}
	}
	vmm_event_coordinator_lock_entries(coordinator, checkpoint_instances,
	    count);
	for (i = 0; i < count; i++) {
		if (vmm_startup_event_validate(
		    &coordinator->entry[checkpoint_instances[i]].startup) != 0) {
			error = EINVAL;
			break;
		}
		if (coordinator->entry[checkpoint_instances[i]].startup.pending !=
		    0 || coordinator->entry[checkpoint_instances[i]].startup.
		    active_claim_id != 0) {
			error = EBUSY;
			break;
		}
	}
	if (error == 0)
		error = vmm_event_owner_allocate(&checkpoint_owner_id);
	if (error == 0) {
		for (i = 0; i < count; i++)
			entries[i].state =
			    &coordinator->entry[checkpoint_instances[i]].ingress;
	}
	if (error == 0)
		error = vmm_event_checkpoint_begin(checkpoint, entries, count,
		    checkpoint_owner_id);
	vmm_event_coordinator_unlock_entries(coordinator, checkpoint_instances,
	    count);
	if (error == 0) {
		coordinator->checkpoint_cookie = (uintptr_t)checkpoint;
		coordinator->checkpoint_entries_cookie = (uintptr_t)entries;
		coordinator->checkpoint_count = count;
		coordinator->transaction_active = 1;
	} else {
		for (i = 0; i < count; i++)
			entries[i].state = NULL;
	}
out:
	if (error != 0 && instances_staged)
		explicit_bzero(checkpoint_instances, instances_length);
	mtx_unlock(&coordinator->transaction_lock);
	return (error);
}

int
vmm_event_coordinator_checkpoint_wait_ready(
    struct vmm_event_coordinator *coordinator,
    struct vmm_event_checkpoint *checkpoint,
    struct vmm_event_wait_ticket *ticket, const char *wmesg, int pri)
{
	bool prepared, ready;
	int error;

	if (coordinator == NULL || checkpoint == NULL || ticket == NULL ||
	    wmesg == NULL)
		return (EINVAL);
	for (;;) {
		prepared = false;
		mtx_lock(&coordinator->transaction_lock);
		error = vmm_event_coordinator_checkpoint_binding_validate(
		    coordinator, checkpoint);
		if (error == 0 && (vmm_event_coordinator_overlap(coordinator,
		    coordinator->allocation_size, ticket, sizeof(*ticket)) ||
		    vmm_event_coordinator_overlap(checkpoint, sizeof(*checkpoint),
		    ticket, sizeof(*ticket)) || vmm_event_coordinator_overlap(
		    checkpoint->entries, checkpoint->count * sizeof(
		    *checkpoint->entries), ticket, sizeof(*ticket))))
			error = EINVAL;
		if (error == 0 &&
		    atomic_load_acq_int(&coordinator->cancelled) != 0)
			error = ECANCELED;
		if (error == 0) {
			error = vmm_event_wait_prepare(&coordinator->wait, ticket);
			prepared = error == 0;
		}
		if (error == 0)
			error = vmm_event_coordinator_checkpoint_indices_validate(
			    coordinator, checkpoint);
		if (error != 0) {
			if (prepared)
				vmm_event_coordinator_wait_ticket_release_required(
				    ticket);
			mtx_unlock(&coordinator->transaction_lock);
			return (error);
		}
		vmm_event_coordinator_lock_checkpoint(coordinator, checkpoint);
		error = vmm_event_checkpoint_ready(checkpoint, &ready);
		vmm_event_coordinator_unlock_checkpoint(coordinator, checkpoint);
		mtx_unlock(&coordinator->transaction_lock);
		if (error != 0 || ready) {
			vmm_event_coordinator_wait_ticket_release_required(ticket);
			return (error);
		}
		error = vmm_event_wait_sleep(&coordinator->wait, ticket, wmesg,
		    pri);
		vmm_event_coordinator_wait_ticket_release_required(ticket);
		if (error == EAGAIN)
			continue;
		return (error);
	}
}

static int
vmm_event_coordinator_checkpoint_reopen(
    struct vmm_event_coordinator *coordinator,
    struct vmm_event_checkpoint *checkpoint, bool aborting,
    vmm_event_deferred_apply_t *apply, void *apply_arg)
{
	struct vmm_event_checkpoint_entry *entries;
	const uint32_t *instances;
	size_t count, i;
	int error;

	if (coordinator == NULL || checkpoint == NULL)
		return (EINVAL);
	mtx_lock(&coordinator->transaction_lock);
	error = vmm_event_coordinator_checkpoint_binding_validate(coordinator,
	    checkpoint);
	if (error != 0)
		goto out;
	if (!aborting && atomic_load_acq_int(&coordinator->cancelled) != 0) {
		error = ECANCELED;
		goto out;
	}
	error = vmm_event_coordinator_checkpoint_indices_validate(coordinator,
	    checkpoint);
	if (error != 0)
		goto out;
	entries = checkpoint->entries;
	count = coordinator->checkpoint_count;
	instances = vmm_event_coordinator_checkpoint_instances_const(
	    coordinator);
	vmm_event_coordinator_lock_checkpoint(coordinator, checkpoint);
	if (apply == NULL) {
		for (i = 0; i < count; i++) {
			if (entries[i].state->deferred_mask != 0) {
				error = EBUSY;
				break;
			}
		}
	}
	if (error != 0)
		goto unlock;
	if (aborting)
		error = vmm_event_checkpoint_abort(checkpoint);
	else
		error = vmm_event_checkpoint_finish(checkpoint);
	if (error == 0) {
		if (apply != NULL) {
			for (i = 0; i < count; i++) {
				if (entries[i].deferred_mask != 0)
					apply(apply_arg, (uint16_t)instances[i],
					    entries[i].deferred_mask);
			}
		}
		/* Consume the complete caller-owned group credential. */
		explicit_bzero(entries, count * sizeof(*entries));
	}
unlock:
	vmm_event_coordinator_unlock_checkpoint(coordinator, checkpoint);
	if (error == 0) {
		explicit_bzero(vmm_event_coordinator_checkpoint_instances(
		    coordinator), coordinator->checkpoint_count * sizeof(uint32_t));
		coordinator->checkpoint_cookie = 0;
		coordinator->checkpoint_entries_cookie = 0;
		coordinator->checkpoint_count = 0;
		coordinator->transaction_active = 0;
	}
out:
	mtx_unlock(&coordinator->transaction_lock);
	if (error == 0)
		(void)vmm_event_coordinator_signal(coordinator);
	return (error);
}

int
vmm_event_coordinator_checkpoint_finish(
    struct vmm_event_coordinator *coordinator,
    struct vmm_event_checkpoint *checkpoint,
    vmm_event_deferred_apply_t *apply, void *apply_arg)
{

	return (vmm_event_coordinator_checkpoint_reopen(coordinator, checkpoint,
	    false, apply, apply_arg));
}

int
vmm_event_coordinator_checkpoint_abort(
    struct vmm_event_coordinator *coordinator,
    struct vmm_event_checkpoint *checkpoint,
    vmm_event_deferred_apply_t *apply, void *apply_arg)
{

	return (vmm_event_coordinator_checkpoint_reopen(coordinator, checkpoint,
	    true, apply, apply_arg));
}
