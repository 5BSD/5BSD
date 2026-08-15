/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _DEV_VMM_VMM_STARTUP_CONTROLLER_H_
#define	_DEV_VMM_VMM_STARTUP_CONTROLLER_H_

#include <sys/types.h>

#ifdef _KERNEL
#include <sys/stdint.h>
#else
#include <stdint.h>
#endif

enum vmm_startup_controller_phase {
	VMM_STARTUP_CONTROLLER_UNCLAIMED = 0,
	VMM_STARTUP_CONTROLLER_CLAIMED,
	VMM_STARTUP_CONTROLLER_REVOKED,
	VMM_STARTUP_CONTROLLER_PHASE_LAST,
};

/*
 * Transient externally synchronized kernel values; never serialize these.
 * A ticket authenticates its original storage as well as the controller, so
 * copying it never creates a second credential.  ticket_forget() only erases
 * that local credential storage; it does not release or mutate the owner.
 */
struct vmm_startup_controller_state {
	uint64_t owner_id;
	uint64_t generation;
	uint64_t controller_id;
	uintptr_t storage_cookie;
	uint8_t phase;
	uint8_t reserved8[7];
};

struct vmm_startup_controller_ticket {
	uint64_t owner_id;
	uint64_t generation;
	uint64_t controller_id;
	uintptr_t state_cookie;
	uintptr_t storage_cookie;
	uint8_t active;
	uint8_t reserved8[7];
};

int	vmm_startup_controller_init(
	    struct vmm_startup_controller_state *, uint64_t);
int	vmm_startup_controller_validate(
	    const struct vmm_startup_controller_state *);
int	vmm_startup_controller_claim(
	    struct vmm_startup_controller_state *,
	    struct vmm_startup_controller_ticket *, uint64_t);
int	vmm_startup_controller_check(
	    const struct vmm_startup_controller_state *,
	    const struct vmm_startup_controller_ticket *);
int	vmm_startup_controller_abort(
	    struct vmm_startup_controller_state *,
	    struct vmm_startup_controller_ticket *);
int	vmm_startup_controller_retire(
	    struct vmm_startup_controller_state *);
int	vmm_startup_controller_ticket_forget(
	    struct vmm_startup_controller_ticket *);

#endif /* _DEV_VMM_VMM_STARTUP_CONTROLLER_H_ */
