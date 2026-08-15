/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2011 NetApp, Inc.
 * All rights reserved.
 */

#include <sys/param.h>
#include <sys/cpuset.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/sx.h>
#include <sys/sysctl.h>

#include <machine/smp.h>

#include <dev/vmm/vmm_event_coordinator.h>
#include <dev/vmm/vmm_address_range.h>
#include <dev/vmm/vmm_startup_entry_owner.h>
#include <dev/vmm/vmm_startup_mode.h>
#include <dev/vmm/vmm_vm.h>

SYSCTL_NODE(_hw, OID_AUTO, vmm, CTLFLAG_RW | CTLFLAG_MPSAFE, NULL, NULL);

int vmm_ipinum;
SYSCTL_INT(_hw_vmm, OID_AUTO, ipinum, CTLFLAG_RD, &vmm_ipinum, 0,
    "IPI vector used for vcpu notifications");

/*
 * Keep output-storage alias checks subtraction based.  Pointer-end addition
 * can wrap for an invalid caller address and accidentally turn an overlap
 * into an accepted request.  This helper intentionally has no ownership or
 * lifecycle meaning; it only protects the value-only observation API.
 */
static bool
vcpu_startup_entry_overlap(const void *left, size_t left_length,
    const void *right, size_t right_length)
{
	if (left == NULL || right == NULL || left_length == 0 ||
	    right_length == 0)
		return (false);
	return (vmm_address_ranges_overlap(left, left_length, right,
	    right_length));
}

int
vm_event_coordinator_init(struct vm *vm, u_int maxcpus)
{
	int error;

	if (vm == NULL || maxcpus == 0 || maxcpus > UINT16_MAX ||
	    vm->maxcpus != 0 ||
	    vm->event_coordinator != NULL)
		return (EINVAL);
	/*
	 * Do not publish any VM topology state until the independently owned
	 * coordinator exists.  In particular, a recoverable owner-allocation
	 * failure must leave this VM indistinguishable from one that was never
	 * initialized, rather than relying on a subsequent caller to repair a
	 * partially published maximum or startup mask.
	 */
	error = vmm_event_coordinator_create((uint16_t)maxcpus,
	    &vm->event_coordinator);
	if (error != 0)
		return (error);
	CPU_ZERO(&vm->startup_cpus);
	vm->maxcpus = (uint16_t)maxcpus;
	return (error);
}

int
vm_event_coordinator_reset(struct vm *vm)
{
	int error;

	if (vm == NULL || vm->event_coordinator == NULL)
		return (EINVAL);

	/*
	 * Use the same outer lock as vm_startup_enter().  Otherwise a new
	 * generation could admit an AP after the coordinator reset returns but
	 * before startup_cpus is cleared, and this reset would erase that AP's
	 * newly published wait-for-SIPI predicate.
	 */
	mtx_lock(&vm->rendezvous_mtx);
	error = vmm_event_coordinator_reset(vm->event_coordinator);
	if (error == 0)
		CPU_ZERO(&vm->startup_cpus);
	mtx_unlock(&vm->rendezvous_mtx);
	return (error);
}

void
vm_event_coordinator_cleanup(struct vm *vm)
{
	int error;

	if (vm == NULL || vm->event_coordinator == NULL)
		panic("%s: missing coordinator", __func__);
	error = vmm_event_coordinator_cancel(vm->event_coordinator);
	if (error == 0)
		error = vmm_event_coordinator_drain_publishers(
		    vm->event_coordinator, "vmecpub", 0);
	if (error == 0)
		error = vmm_event_coordinator_drain(vm->event_coordinator,
		    "vmecdrn", 0);
	if (error == 0)
		error = vmm_event_coordinator_destroy(vm->event_coordinator);
	if (error != 0)
		panic("%s: undrained coordinator owner: %d", __func__, error);
	vm->event_coordinator = NULL;
}

struct vmm_event_coordinator *
vm_event_coordinator(struct vm *vm)
{

	return (vm->event_coordinator);
}

static void
vcpu_notify_startup_event(struct vcpu *vcpu)
{
	uint64_t next;
	int error;

	vcpu_lock(vcpu);
	error = vmm_startup_notification_advance(
	    vcpu->startup_notify_generation, &next);
	if (error != 0)
		panic("%s: startup notification generation exhausted", __func__);
	vcpu->startup_notify_generation = next;
	vcpu_notify_event_locked(vcpu);
	vcpu_unlock(vcpu);
}

/*
 * Zero is reserved for an empty handoff.  A newly allocated vCPU has no
 * startup wake history yet, but its first frozen-entry observation is still
 * a valid handoff baseline.  Keep that lazy initialization under the vCPU
 * owner so every observer sees the same nonzero epoch.
 */
static uint64_t
vcpu_startup_notify_generation_capture_locked(struct vcpu *vcpu)
{

	vcpu_assert_locked(vcpu);
	vcpu->startup_notify_generation =
	    vmm_startup_notification_generation_capture(
	    vcpu->startup_notify_generation);
	return (vcpu->startup_notify_generation);
}

uint64_t
vcpu_startup_notify_generation_capture(struct vcpu *vcpu)
{
	uint64_t generation;

	if (vcpu == NULL)
		return (0);
	vcpu_lock(vcpu);
	generation = vcpu_startup_notify_generation_capture_locked(vcpu);
	vcpu_unlock(vcpu);
	return (generation);
}

/*
 * Take the common frozen-entry lifecycle observation under the same lock
 * order used by the startup sleep predicate.  It never dispatches or applies
 * machine state; the sole mutation is lazy normalization of the reserved-zero
 * notification baseline while the vCPU owner is held.  Dispatch and every
 * machine action remain the caller's responsibility.
 */
int
vcpu_startup_entry_observation(struct vcpu *vcpu,
    struct vmm_startup_entry_snapshot *snapshot, uint64_t *generationp)
{
	struct vm *vm;
	struct vmm_startup_entry_snapshot candidate;
	uint64_t generation;

	if (vcpu == NULL || snapshot == NULL)
		return (EINVAL);
	if (generationp != NULL && vcpu_startup_entry_overlap(snapshot,
	    sizeof(*snapshot), generationp, sizeof(*generationp)))
		return (EINVAL);
	vm = vcpu->vm;
	if (vm == NULL)
		return (EINVAL);
	memset(&candidate, 0, sizeof(candidate));
	mtx_lock(&vm->rendezvous_mtx);
	vcpu_lock(vcpu);
	candidate.rendezvous = vm->rendezvous_func != NULL;
	candidate.suspended = vm->suspend != VM_SUSPEND_NONE;
	candidate.reqidle = vcpu->reqidle != 0;
	candidate.debugged = vcpu_debugged(vcpu);
	candidate.waiting = CPU_ISSET(vcpu->vcpuid, &vm->startup_cpus);
	generation = vcpu_startup_notify_generation_capture_locked(vcpu);
	vcpu_unlock(vcpu);
	mtx_unlock(&vm->rendezvous_mtx);
	if (vmm_startup_entry_snapshot_validate(&candidate) != 0)
		return (EPROTO);
	*snapshot = candidate;
	if (generationp != NULL)
		*generationp = generation;
	return (0);
}

int
vcpu_startup_entry_snapshot(struct vcpu *vcpu,
    struct vmm_startup_entry_snapshot *snapshot)
{

	return (vcpu_startup_entry_observation(vcpu, snapshot, NULL));
}

/*
 * Capture the two independently timed admission observations as one value
 * operation.  This helper deliberately has no transition side effect: the
 * caller selects either the ordinary or deferred common-owner operation.
 * Keeping it private prevents a machine adapter from treating a cleanup
 * resolver as authority to take another live observation.
 */
static int
vcpu_startup_entry_owner_observe(struct vcpu *vcpu,
    const struct vmm_startup_entry_owner *owner, int *coordinator_error,
    int *notification_error)
{
	uint64_t notification_generation;

	if (vcpu == NULL || owner == NULL || coordinator_error == NULL ||
	    notification_error == NULL ||
	    vmm_startup_entry_owner_validate(owner) != 0)
		return (EINVAL);
	*coordinator_error = vcpu_startup_event_run_token_check(vcpu,
	    &owner->coordinator);
	notification_generation =
	    vcpu_startup_notify_generation_capture(vcpu);
	*notification_error = vmm_startup_entry_handoff_check(
	    notification_generation, &owner->notification);
	return (0);
}

/*
 * Revalidate both differently timed startup observations at the live vCPU
 * boundary.  The caller chooses the interrupt-disabled hardware-entry point;
 * this wrapper only obtains the current owners and applies the private value
 * transaction.  Both checks are evaluated so terminal disagreement remains
 * fail-stop rather than depending on check order.
 */
int
vcpu_startup_entry_owner_guard_before(struct vcpu *vcpu,
    struct vmm_startup_entry_owner *owner,
    struct vmm_startup_entry_runtime_result *result)
{
	int coordinator_error, notification_error;

	if (result == NULL)
		return (EINVAL);
	if (vcpu_startup_entry_owner_observe(vcpu, owner, &coordinator_error,
	    &notification_error) != 0)
		return (EINVAL);
	return (vmm_startup_entry_owner_guard_before(owner,
	    coordinator_error, notification_error, result));
}

/*
 * This deferred-admission wrapper observes a vCPU exactly once.  The matching
 * attempted-entry wrapper below has the same admission-only authority.  Once
 * a private adapter starts undoing pre-entry preparation, the stored decision
 * is historical: sampling again would turn cleanup timing into a new
 * admission decision.  Deferred post-entry settlement likewise has no vCPU
 * observation, because guest execution has already occurred.
 */
int
vcpu_startup_entry_owner_guard_before_defer(struct vcpu *vcpu,
    struct vmm_startup_entry_owner *owner,
    struct vmm_startup_entry_runtime_result *result)
{
	int coordinator_error, notification_error;

	if (result == NULL)
		return (EINVAL);
	if (vcpu_startup_entry_owner_observe(vcpu, owner, &coordinator_error,
	    &notification_error) != 0)
		return (EINVAL);
	return (vmm_startup_entry_owner_guard_before_defer(owner,
	    coordinator_error, notification_error, result));
}

int
vcpu_startup_entry_owner_guard_before_attempt(struct vcpu *vcpu,
    struct vmm_startup_entry_owner *owner,
    struct vmm_startup_entry_runtime_result *result)
{
	int coordinator_error, notification_error;

	if (result == NULL)
		return (EINVAL);
	if (vcpu_startup_entry_owner_observe(vcpu, owner, &coordinator_error,
	    &notification_error) != 0)
		return (EINVAL);
	return (vmm_startup_entry_owner_guard_before_attempt(owner,
	    coordinator_error, notification_error, result));
}

/*
 * Close the final post-refreeze publication window before erasing the stack
 * owner.  As above, preserve both observations for deterministic error
 * composition instead of short-circuiting after the first mismatch.
 */
int
vcpu_startup_entry_owner_retire(struct vcpu *vcpu,
    struct vmm_startup_entry_owner *owner,
    struct vmm_startup_entry_loop_result *result)
{
	int coordinator_error, notification_error;

	if (result == NULL)
		return (EINVAL);
	if (vcpu_startup_entry_owner_observe(vcpu, owner, &coordinator_error,
	    &notification_error) != 0)
		return (EINVAL);
	return (vmm_startup_entry_owner_retire(owner, coordinator_error,
	    notification_error, result));
}

int
vm_startup_lock_default(struct vm *vm, uint64_t *generationp)
{

	if (vm == NULL || vm->event_coordinator == NULL || generationp == NULL)
		return (EINVAL);
	return (vmm_event_coordinator_startup_lock_default(
	    vm->event_coordinator, generationp));
}

int
vm_startup_controller_claim(struct vm *vm,
    struct vmm_startup_controller_ticket *ticket, uint64_t controller_id)
{

	if (vm == NULL || vm->event_coordinator == NULL || ticket == NULL ||
	    controller_id == 0)
		return (EINVAL);
	return (vmm_event_coordinator_startup_controller_claim(
	    vm->event_coordinator, ticket, controller_id));
}

int
vm_startup_controller_release(struct vm *vm,
    struct vmm_startup_controller_ticket *ticket)
{

	if (vm == NULL || vm->event_coordinator == NULL || ticket == NULL)
		return (EINVAL);
	return (vmm_event_coordinator_startup_controller_release(
	    vm->event_coordinator, ticket));
}

/*
 * The coordinator and its startup records are intentionally portable, but
 * applying INIT/SIPI inside the kernel is presently an amd64 VMX/SVM-only
 * transaction.  Keep the common wrapper source buildable for future VMM
 * ports without implying that the generic record format authorizes a
 * machine-specific action there.
 */
static bool
vm_startup_kernel_actions_ready(void)
{

#ifdef __amd64__
	return (vmmops_startup_kernel_actions_ready());
#else
	return (false);
#endif
}

int
vm_startup_configure_kernel(struct vm *vm,
    const struct vmm_startup_controller_ticket *ticket,
    uint16_t expected_vcpus, uint64_t *generationp)
{

	if (vm == NULL || vm->event_coordinator == NULL || ticket == NULL ||
	    expected_vcpus == 0 || generationp == NULL)
		return (EINVAL);
	/*
	 * The cdev staging layer is not the only possible caller of this
	 * private VM helper.  Keep the same architecture-owned readiness gate
	 * here so an in-kernel user cannot accidentally activate the incomplete
	 * kernel-startup path by bypassing the management request decoder.
	 */
	if (!vm_startup_kernel_actions_ready())
		return (EOPNOTSUPP);
	return (vmm_event_coordinator_startup_configure_kernel(
	    vm->event_coordinator, ticket, expected_vcpus, generationp));
}

int
vm_startup_execution_status(struct vm *vm,
    struct vmm_startup_handshake_status *status)
{

	if (vm == NULL || vm->event_coordinator == NULL || status == NULL)
		return (EINVAL);
	return (vmm_event_coordinator_startup_execution_status(
	    vm->event_coordinator, status));
}

int
vm_startup_enter(struct vm *vm,
    const struct vmm_startup_controller_ticket *controller_ticket,
    uint16_t vcpuid, uint64_t generation, bool bootstrap_processor)
{
	bool already_waiting;
	int error;

	if (vm == NULL || controller_ticket == NULL ||
	    vm->event_coordinator == NULL || vcpuid >= vm->maxcpus ||
	    vm_vcpu(vm, vcpuid) == NULL)
		return (EINVAL);

	/*
	 * Publish an AP's architectural wait-for-SIPI predicate before its
	 * admission can make the coordinator ready and wake a committing thread.
	 * Holding rendezvous_mtx across the coordinator transaction also means a
	 * newly committed VM_RUN cannot test startup_cpus until this wrapper has
	 * either completed admission or rolled the speculative bit back.
	 */
	mtx_lock(&vm->rendezvous_mtx);
	already_waiting = CPU_ISSET(vcpuid, &vm->startup_cpus);
	if (bootstrap_processor)
		CPU_CLR(vcpuid, &vm->startup_cpus);
	else
		CPU_SET(vcpuid, &vm->startup_cpus);
	error = vmm_event_coordinator_startup_enter(vm->event_coordinator,
	    controller_ticket, vcpuid, generation, bootstrap_processor);
	if (error != 0) {
		if (already_waiting)
			CPU_SET(vcpuid, &vm->startup_cpus);
		else
			CPU_CLR(vcpuid, &vm->startup_cpus);
	}
	mtx_unlock(&vm->rendezvous_mtx);
	return (error);
}

int
vm_startup_wait_ready(struct vm *vm,
    const struct vmm_startup_controller_ticket *ticket, uint64_t generation,
    struct vmm_event_wait_ticket *wait_ticket, const char *wmesg, int pri)
{

	if (vm == NULL || vm->event_coordinator == NULL || ticket == NULL ||
	    wait_ticket == NULL || wmesg == NULL)
		return (EINVAL);
	return (vmm_event_coordinator_startup_wait_ready(
	    vm->event_coordinator, ticket, generation, wait_ticket, wmesg,
	    pri));
}

int
vm_startup_wait_committed(struct vm *vm,
    const struct vmm_startup_controller_ticket *ticket, uint64_t generation,
    struct vmm_event_wait_ticket *wait_ticket, const char *wmesg, int pri)
{

	if (vm == NULL || vm->event_coordinator == NULL || ticket == NULL ||
	    wait_ticket == NULL || wmesg == NULL)
		return (EINVAL);
	return (vmm_event_coordinator_startup_wait_committed(
	    vm->event_coordinator, ticket, generation, wait_ticket, wmesg,
	    pri));
}

int
vm_startup_commit(struct vm *vm,
    const struct vmm_startup_controller_ticket *ticket, uint64_t generation)
{

	if (vm == NULL || vm->event_coordinator == NULL || ticket == NULL)
		return (EINVAL);
	return (vmm_event_coordinator_startup_commit(vm->event_coordinator,
	    ticket, generation));
}

int
vm_startup_status(struct vm *vm,
    const struct vmm_startup_controller_ticket *ticket,
    struct vmm_startup_handshake_status *status)
{

	if (vm == NULL || vm->event_coordinator == NULL || ticket == NULL ||
	    status == NULL)
		return (EINVAL);
	return (vmm_event_coordinator_startup_status(vm->event_coordinator,
	    ticket, status));
}

int
vcpu_startup_event_publish_init(struct vcpu *vcpu)
{
	int error;

	if (vcpu == NULL || vcpu->vm == NULL ||
	    vcpu->vm->event_coordinator == NULL)
		return (EINVAL);
	error = vmm_event_coordinator_startup_publish_init(
	    vcpu->vm->event_coordinator, vcpu->vcpuid);
	if (error == 0)
		vcpu_notify_startup_event(vcpu);
	return (error);
}

int
vcpu_startup_event_publish_sipi(struct vcpu *vcpu, uint8_t vector)
{
	int error;

	if (vcpu == NULL || vcpu->vm == NULL ||
	    vcpu->vm->event_coordinator == NULL)
		return (EINVAL);
	error = vmm_event_coordinator_startup_publish_sipi(
	    vcpu->vm->event_coordinator, vcpu->vcpuid, vector);
	if (error == 0)
		vcpu_notify_startup_event(vcpu);
	return (error);
}

static int
vm_startup_event_publish_set(struct vm *vm, const cpuset_t *targets,
    enum vmm_startup_event_kind kind, uint8_t vector)
{
	cpuset_t stable_targets;
	struct vcpu *target;
	int error, i;

	if (vm == NULL || targets == NULL || vm->event_coordinator == NULL)
		return (EINVAL);
	CPU_COPY(targets, &stable_targets);
	if (CPU_EMPTY(&stable_targets))
		return (EINVAL);
	CPU_FOREACH_ISSET(i, &stable_targets) {
		if (i >= vm->maxcpus)
			return (EINVAL);
		target = vm_vcpu(vm, i);
		if (target == NULL || target->vm != vm || target->vcpuid != i)
			return (ENOENT);
	}
	error = vmm_event_coordinator_startup_publish_set(
	    vm->event_coordinator, &stable_targets, kind, vector);
	if (error != 0)
		return (error);
	CPU_FOREACH_ISSET(i, &stable_targets)
		vcpu_notify_startup_event(vm_vcpu(vm, i));
	return (0);
}

int
vm_startup_event_publish_init_set(struct vm *vm, const cpuset_t *targets)
{

	return (vm_startup_event_publish_set(vm, targets,
	    VMM_STARTUP_EVENT_INIT, 0));
}

int
vm_startup_event_publish_sipi_set(struct vm *vm, const cpuset_t *targets,
    uint8_t vector)
{

	return (vm_startup_event_publish_set(vm, targets,
	    VMM_STARTUP_EVENT_SIPI, vector));
}

/*
 * Route one INIT/SIPI target set to its committed startup owner.  Targets are
 * validated against live vCPU storage before the coordinator transaction, and
 * they are notified only after the kernel publication has committed, so a
 * routing failure can never wake a target for an event that was not durably
 * published.  A userspace decision performs no publication and no
 * notification: the caller must deliver through the historical
 * VM_EXITCODE_IPI/SPINUP_AP exit contract, which this wrapper leaves
 * untouched.
 */
static int
vm_startup_route_set(struct vm *vm, const cpuset_t *targets,
    enum vmm_startup_event_kind kind, uint8_t vector,
    struct vmm_startup_delivery *delivery)
{
	cpuset_t stable_targets;
	struct vmm_startup_delivery candidate;
	struct vcpu *target;
	int error, i;

	if (vm == NULL || targets == NULL || delivery == NULL ||
	    vm->event_coordinator == NULL ||
	    vcpu_startup_entry_overlap(targets, sizeof(*targets), delivery,
	    sizeof(*delivery)))
		return (EINVAL);
	CPU_COPY(targets, &stable_targets);
	if (CPU_EMPTY(&stable_targets))
		return (EINVAL);
	CPU_FOREACH_ISSET(i, &stable_targets) {
		if (i >= vm->maxcpus)
			return (EINVAL);
		target = vm_vcpu(vm, i);
		if (target == NULL || target->vm != vm || target->vcpuid != i)
			return (ENOENT);
	}
	memset(&candidate, 0, sizeof(candidate));
	error = vmm_event_coordinator_startup_route_set(vm->event_coordinator,
	    &stable_targets, kind, vector, &candidate);
	if (error != 0)
		return (error);
	/* Notify only after the whole set was durably published. */
	if (candidate.kernel_publication != 0) {
		CPU_FOREACH_ISSET(i, &stable_targets)
			vcpu_notify_startup_event(vm_vcpu(vm, i));
	}
	*delivery = candidate;
	return (0);
}

int
vm_startup_route_init_set(struct vm *vm, const cpuset_t *targets,
    struct vmm_startup_delivery *delivery)
{

	return (vm_startup_route_set(vm, targets, VMM_STARTUP_EVENT_INIT, 0,
	    delivery));
}

int
vm_startup_route_sipi_set(struct vm *vm, const cpuset_t *targets,
    uint8_t vector, struct vmm_startup_delivery *delivery)
{

	return (vm_startup_route_set(vm, targets, VMM_STARTUP_EVENT_SIPI,
	    vector, delivery));
}

int
vcpu_startup_event_claim_begin(struct vcpu *vcpu,
    struct vmm_startup_event_claim *claim)
{

	if (vcpu == NULL || vcpu->vm == NULL ||
	    vcpu->vm->event_coordinator == NULL)
		return (EINVAL);
	return (vmm_event_coordinator_startup_claim_begin(
	    vcpu->vm->event_coordinator, vcpu->vcpuid, claim));
}

int
vcpu_startup_event_claim_check(struct vcpu *vcpu,
    const struct vmm_startup_event_claim *claim)
{

	if (vcpu == NULL || vcpu->vm == NULL ||
	    vcpu->vm->event_coordinator == NULL)
		return (EINVAL);
	return (vmm_event_coordinator_startup_claim_check(
	    vcpu->vm->event_coordinator, vcpu->vcpuid, claim));
}

static int
vcpu_startup_event_claim_end(struct vcpu *vcpu,
    struct vmm_startup_event_claim *claim, bool aborting)
{
	int error;

	if (vcpu == NULL || vcpu->vm == NULL ||
	    vcpu->vm->event_coordinator == NULL)
		return (EINVAL);
	if (aborting)
		error = vmm_event_coordinator_startup_claim_abort(
		    vcpu->vm->event_coordinator, vcpu->vcpuid, claim);
	else
		error = vmm_event_coordinator_startup_claim_finish(
		    vcpu->vm->event_coordinator, vcpu->vcpuid, claim);
	/* A newer publication may have remained behind the released claim. */
	if (error == 0)
		vcpu_notify_startup_event(vcpu);
	return (error);
}

int
vcpu_startup_event_claim_finish(struct vcpu *vcpu,
    struct vmm_startup_event_claim *claim)
{

	return (vcpu_startup_event_claim_end(vcpu, claim, false));
}

int
vcpu_startup_event_claim_abort(struct vcpu *vcpu,
    struct vmm_startup_event_claim *claim)
{

	return (vcpu_startup_event_claim_end(vcpu, claim, true));
}

int
vcpu_startup_event_run_token_capture(struct vcpu *vcpu,
    struct vmm_startup_event_run_token *token)
{

	if (vcpu == NULL || vcpu->vm == NULL ||
	    vcpu->vm->event_coordinator == NULL)
		return (EINVAL);
	return (vmm_event_coordinator_startup_run_token_capture(
	    vcpu->vm->event_coordinator, vcpu->vcpuid, token));
}

int
vcpu_startup_event_run_token_check(struct vcpu *vcpu,
    const struct vmm_startup_event_run_token *token)
{

	if (vcpu == NULL || vcpu->vm == NULL ||
	    vcpu->vm->event_coordinator == NULL)
		return (EINVAL);
	return (vmm_event_coordinator_startup_run_token_check(
	    vcpu->vm->event_coordinator, vcpu->vcpuid, token));
}

/*
 * Invoke the rendezvous function on the specified vcpu if applicable.  Return
 * true if the rendezvous is finished, false otherwise.
 */
static bool
vm_rendezvous(struct vcpu *vcpu)
{
	struct vm *vm = vcpu->vm;
	int vcpuid;

	mtx_assert(&vcpu->vm->rendezvous_mtx, MA_OWNED);
	KASSERT(vcpu->vm->rendezvous_func != NULL,
	    ("vm_rendezvous: no rendezvous pending"));

	/* 'rendezvous_req_cpus' must be a subset of 'active_cpus' */
	CPU_AND(&vm->rendezvous_req_cpus, &vm->rendezvous_req_cpus,
	    &vm->active_cpus);

	vcpuid = vcpu->vcpuid;
	if (CPU_ISSET(vcpuid, &vm->rendezvous_req_cpus) &&
	    !CPU_ISSET(vcpuid, &vm->rendezvous_done_cpus)) {
		(*vm->rendezvous_func)(vcpu, vm->rendezvous_arg);
		CPU_SET(vcpuid, &vm->rendezvous_done_cpus);
	}
	if (CPU_CMP(&vm->rendezvous_req_cpus, &vm->rendezvous_done_cpus) == 0) {
		CPU_ZERO(&vm->rendezvous_req_cpus);
		vm->rendezvous_func = NULL;
		wakeup(&vm->rendezvous_func);
		return (true);
	}
	return (false);
}

int
vm_handle_rendezvous(struct vcpu *vcpu)
{
	struct vm *vm;
	struct thread *td;

	td = curthread;
	vm = vcpu->vm;

	mtx_lock(&vm->rendezvous_mtx);
	while (vm->rendezvous_func != NULL) {
		if (vm_rendezvous(vcpu))
			break;

		mtx_sleep(&vm->rendezvous_func, &vm->rendezvous_mtx, 0,
		    "vmrndv", hz);
		if (td_ast_pending(td, TDA_SUSPEND)) {
			int error;

			mtx_unlock(&vm->rendezvous_mtx);
			error = thread_check_susp(td, true);
			if (error != 0)
				return (error);
			mtx_lock(&vm->rendezvous_mtx);
		}
	}
	mtx_unlock(&vm->rendezvous_mtx);
	return (0);
}

static void
vcpu_wait_idle(struct vcpu *vcpu)
{
	KASSERT(vcpu->state != VCPU_IDLE, ("vcpu already idle"));

	vcpu->reqidle = 1;
	vcpu_notify_event_locked(vcpu);
	msleep_spin(&vcpu->state, &vcpu->mtx, "vmstat", hz);
}

int
vcpu_set_state_locked(struct vcpu *vcpu, enum vcpu_state newstate,
    bool from_idle)
{
	int error;

	vcpu_assert_locked(vcpu);

	/*
	 * State transitions from the vmmdev_ioctl() must always begin from
	 * the VCPU_IDLE state. This guarantees that there is only a single
	 * ioctl() operating on a vcpu at any point.
	 */
	if (from_idle) {
		while (vcpu->state != VCPU_IDLE)
			vcpu_wait_idle(vcpu);
	} else {
		KASSERT(vcpu->state != VCPU_IDLE, ("invalid transition from "
		    "vcpu idle state"));
	}

	if (vcpu->state == VCPU_RUNNING) {
		KASSERT(vcpu->hostcpu == curcpu, ("curcpu %d and hostcpu %d "
		    "mismatch for running vcpu", curcpu, vcpu->hostcpu));
	} else {
		KASSERT(vcpu->hostcpu == NOCPU, ("Invalid hostcpu %d for a "
		    "vcpu that is not running", vcpu->hostcpu));
	}

	/*
	 * The following state transitions are allowed:
	 * IDLE -> FROZEN -> IDLE
	 * FROZEN -> RUNNING -> FROZEN
	 * FROZEN -> SLEEPING -> FROZEN
	 */
	switch (vcpu->state) {
	case VCPU_IDLE:
	case VCPU_RUNNING:
	case VCPU_SLEEPING:
		error = (newstate != VCPU_FROZEN);
		break;
	case VCPU_FROZEN:
		error = (newstate == VCPU_FROZEN);
		break;
	default:
		error = 1;
		break;
	}

	if (error)
		return (EBUSY);

	vcpu->state = newstate;
	if (newstate == VCPU_RUNNING)
		vcpu->hostcpu = curcpu;
	else
		vcpu->hostcpu = NOCPU;

	if (newstate == VCPU_IDLE)
		wakeup(&vcpu->state);

	return (0);
}

/*
 * Try to lock all of the vCPUs in the VM while taking care to avoid deadlocks
 * with vm_smp_rendezvous().
 *
 * The complexity here suggests that the rendezvous mechanism needs a rethink.
 */
int
vcpu_set_state_all(struct vm *vm, enum vcpu_state newstate)
{
	cpuset_t locked;
	struct vcpu *rollback_vcpu, *vcpu;
	int error, i, rollback_error, rollback_id;
	uint16_t maxcpus;

	KASSERT(newstate != VCPU_IDLE,
	    ("vcpu_set_state_all: invalid target state %d", newstate));

	error = 0;
	CPU_ZERO(&locked);
	maxcpus = vm->maxcpus;

	mtx_lock(&vm->rendezvous_mtx);
restart:
	if (vm->rendezvous_func != NULL) {
		/*
		 * If we have a pending rendezvous, then the initiator may be
		 * blocked waiting for other vCPUs to execute the callback.  The
		 * current thread may be a vCPU thread so we must not block
		 * waiting for the initiator, otherwise we get a deadlock.
		 * Thus, execute the callback on behalf of any idle vCPUs.
		 */
		for (i = 0; i < maxcpus; i++) {
			vcpu = vm_vcpu(vm, i);
			if (vcpu == NULL)
				continue;
			vcpu_lock(vcpu);
			if (vcpu->state == VCPU_IDLE) {
				(void)vcpu_set_state_locked(vcpu, VCPU_FROZEN,
				    true);
				CPU_SET(i, &locked);
			}
			if (CPU_ISSET(i, &locked)) {
				/*
				 * We can safely execute the callback on this
				 * vCPU's behalf.
				 */
				vcpu_unlock(vcpu);
				(void)vm_rendezvous(vcpu);
				vcpu_lock(vcpu);
			}
			vcpu_unlock(vcpu);
		}
	}

	/*
	 * Now wait for remaining vCPUs to become idle.  This may include the
	 * initiator of a rendezvous that is currently blocked on the rendezvous
	 * mutex.
	 */
	CPU_FOREACH_ISCLR(i, &locked) {
		if (i >= maxcpus)
			break;
		vcpu = vm_vcpu(vm, i);
		if (vcpu == NULL)
			continue;
		vcpu_lock(vcpu);
		while (vcpu->state != VCPU_IDLE) {
			mtx_unlock(&vm->rendezvous_mtx);
			vcpu_wait_idle(vcpu);
			vcpu_unlock(vcpu);
			mtx_lock(&vm->rendezvous_mtx);
			if (vm->rendezvous_func != NULL)
				goto restart;
			vcpu_lock(vcpu);
		}
		error = vcpu_set_state_locked(vcpu, newstate, true);
		vcpu_unlock(vcpu);
		if (error != 0) {
			/*
			 * Roll back the exact vCPUs recorded in 'locked'.  Do not
			 * reuse 'vcpu': it names the vCPU whose transition failed,
			 * not the members changed by earlier iterations.
			 */
			CPU_FOREACH_ISSET(rollback_id, &locked) {
				rollback_vcpu = vm_vcpu(vm, rollback_id);
				if (rollback_vcpu == NULL)
					panic("%s: missing locked vCPU %d", __func__,
					    rollback_id);
				rollback_error = vcpu_set_state(rollback_vcpu,
				    VCPU_IDLE, false);
				if (rollback_error != 0)
					panic("%s: failed to roll back vCPU %d: %d",
					    __func__, rollback_id, rollback_error);
			}
			break;
		}
		CPU_SET(i, &locked);
	}
	mtx_unlock(&vm->rendezvous_mtx);
	return (error);
}


int
vcpu_set_state(struct vcpu *vcpu, enum vcpu_state newstate, bool from_idle)
{
	int error;

	vcpu_lock(vcpu);
	error = vcpu_set_state_locked(vcpu, newstate, from_idle);
	vcpu_unlock(vcpu);

	return (error);
}

enum vcpu_state
vcpu_get_state(struct vcpu *vcpu, int *hostcpu)
{
	enum vcpu_state state;

	vcpu_lock(vcpu);
	state = vcpu->state;
	if (hostcpu != NULL)
		*hostcpu = vcpu->hostcpu;
	vcpu_unlock(vcpu);

	return (state);
}

/*
 * This function is called to ensure that a vcpu "sees" a pending event
 * as soon as possible:
 * - If the vcpu thread is sleeping then it is woken up.
 * - If the vcpu is running on a different host_cpu then an IPI will be directed
 *   to the host_cpu to cause the vcpu to trap into the hypervisor.
 */
void
vcpu_notify_event_locked(struct vcpu *vcpu)
{
	int hostcpu;

	hostcpu = vcpu->hostcpu;
	if (vcpu->state == VCPU_RUNNING) {
		KASSERT(hostcpu != NOCPU, ("vcpu running on invalid hostcpu"));
		if (hostcpu != curcpu) {
			ipi_cpu(hostcpu, vmm_ipinum);
		} else {
			/*
			 * If the 'vcpu' is running on 'curcpu' then it must
			 * be sending a notification to itself (e.g. SELF_IPI).
			 * The pending event will be picked up when the vcpu
			 * transitions back to guest context.
			 */
		}
	} else {
		KASSERT(hostcpu == NOCPU, ("vcpu state %d not consistent "
		    "with hostcpu %d", vcpu->state, hostcpu));
		if (vcpu->state == VCPU_SLEEPING)
			wakeup_one(vcpu);
	}
}

void
vcpu_notify_event(struct vcpu *vcpu)
{
	vcpu_lock(vcpu);
	vcpu_notify_event_locked(vcpu);
	vcpu_unlock(vcpu);
}

int
vcpu_debugged(struct vcpu *vcpu)
{
	return (CPU_ISSET(vcpu->vcpuid, &vcpu->vm->debug_cpus));
}

void
vm_lock_vcpus(struct vm *vm)
{
	sx_xlock(&vm->vcpus_init_lock);
}

void
vm_unlock_vcpus(struct vm *vm)
{
	sx_unlock(&vm->vcpus_init_lock);
}

void
vm_disable_vcpu_creation(struct vm *vm)
{
	sx_xlock(&vm->vcpus_init_lock);
	vm->dying = true;
	sx_xunlock(&vm->vcpus_init_lock);
}

uint16_t
vm_get_maxcpus(struct vm *vm)
{
	return (vm->maxcpus);
}

void
vm_get_topology(struct vm *vm, uint16_t *sockets, uint16_t *cores,
    uint16_t *threads, uint16_t *maxcpus)
{
	*sockets = vm->sockets;
	*cores = vm->cores;
	*threads = vm->threads;
	*maxcpus = vm->maxcpus;
}

int
vm_set_topology(struct vm *vm, uint16_t sockets, uint16_t cores,
    uint16_t threads, uint16_t maxcpus __unused)
{
	/* Ignore maxcpus. */
	if (sockets * cores * threads > vm->maxcpus)
		return (EINVAL);
	vm->sockets = sockets;
	vm->cores = cores;
	vm->threads = threads;
	return (0);
}

int
vm_suspend(struct vm *vm, enum vm_suspend_how how)
{
	int i;

	if (how <= VM_SUSPEND_NONE || how >= VM_SUSPEND_LAST)
		return (EINVAL);

	if (atomic_cmpset_int(&vm->suspend, 0, how) == 0)
		return (EALREADY);

	/*
	 * Notify all active vcpus that they are now suspended.
	 */
	for (i = 0; i < vm->maxcpus; i++) {
		if (CPU_ISSET(i, &vm->active_cpus))
			vcpu_notify_event(vm_vcpu(vm, i));
	}

	return (0);
}

int
vm_reinit(struct vm *vm)
{
	int error;

	/*
	 * A virtual machine can be reset only if all vcpus are suspended.
	 */
	if (CPU_CMP(&vm->suspended_cpus, &vm->active_cpus) == 0) {
		error = vm_reset(vm);
	} else {
		error = EBUSY;
	}

	return (error);
}

int
vm_activate_cpu(struct vcpu *vcpu)
{
	struct vm *vm = vcpu->vm;

	if (CPU_ISSET(vcpu->vcpuid, &vm->active_cpus))
		return (EBUSY);

	CPU_SET_ATOMIC(vcpu->vcpuid, &vm->active_cpus);
	return (0);
}

int
vm_suspend_cpu(struct vm *vm, struct vcpu *vcpu)
{
	if (vcpu == NULL) {
		vm->debug_cpus = vm->active_cpus;
		for (int i = 0; i < vm->maxcpus; i++) {
			if (CPU_ISSET(i, &vm->active_cpus))
				vcpu_notify_event(vm_vcpu(vm, i));
		}
	} else {
		if (!CPU_ISSET(vcpu->vcpuid, &vm->active_cpus))
			return (EINVAL);

		CPU_SET_ATOMIC(vcpu->vcpuid, &vm->debug_cpus);
		vcpu_notify_event(vcpu);
	}
	return (0);
}

int
vm_resume_cpu(struct vm *vm, struct vcpu *vcpu)
{
	if (vcpu == NULL) {
		CPU_ZERO(&vm->debug_cpus);
	} else {
		if (!CPU_ISSET(vcpu->vcpuid, &vm->debug_cpus))
			return (EINVAL);

		CPU_CLR_ATOMIC(vcpu->vcpuid, &vm->debug_cpus);
	}
	return (0);
}

cpuset_t
vm_active_cpus(struct vm *vm)
{
	return (vm->active_cpus);
}

cpuset_t
vm_debug_cpus(struct vm *vm)
{
	return (vm->debug_cpus);
}

cpuset_t
vm_suspended_cpus(struct vm *vm)
{
	return (vm->suspended_cpus);
}
