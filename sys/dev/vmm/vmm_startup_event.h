/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _DEV_VMM_VMM_STARTUP_EVENT_H_
#define	_DEV_VMM_VMM_STARTUP_EVENT_H_

#include <sys/types.h>

#ifdef _KERNEL
#include <sys/stdint.h>
#else
#include <stdint.h>
#endif

/*
 * Allocation-free, caller-synchronized INIT/SIPI value protocol.
 *
 * This is machine-independent ownership plumbing, not an architecture ABI,
 * saved-state layout, or public kernel interface.  An architecture adapter
 * supplies the policy for reflecting or applying a selected event.  INIT
 * replaces an older SIPI; a SIPI published after INIT remains pending with
 * only its latest vector.  Receipts are bound to one owner, vCPU, state
 * object, storage location, and generation so a delayed or copied decision
 * cannot consume a different event incarnation.
 */
enum vmm_startup_event_kind {
	VMM_STARTUP_EVENT_NONE = 0,
	VMM_STARTUP_EVENT_INIT,
	VMM_STARTUP_EVENT_SIPI,
	VMM_STARTUP_EVENT_KIND_LAST,
};

#define	VMM_STARTUP_EVENT_PENDING_INIT	UINT8_C(0x01)
#define	VMM_STARTUP_EVENT_PENDING_SIPI	UINT8_C(0x02)
#define	VMM_STARTUP_EVENT_PENDING_VALID				\
	(VMM_STARTUP_EVENT_PENDING_INIT | VMM_STARTUP_EVENT_PENDING_SIPI)

struct vmm_startup_event_state {
	uint64_t owner_id;
	uint64_t generation;
	uint64_t next_claim_id;
	uint64_t active_claim_id;
	uintptr_t storage_cookie;
	uint32_t vcpuid;
	uint8_t pending;
	uint8_t sipi_vector;
	uint8_t active_kind;
	uint8_t active_vector;
	uint32_t reserved;
};

struct vmm_startup_event_receipt {
	uint64_t owner_id;
	uint64_t generation;
	uintptr_t state_cookie;
	uintptr_t storage_cookie;
	uint32_t vcpuid;
	uint8_t kind;
	uint8_t vector;
	uint8_t active;
	uint8_t reserved8;
	uint32_t reserved32;
};

/*
 * A claim permits the coordinator to release its spin owner while an
 * architecture adapter performs a potentially blocking rendezvous.  New
 * publications remain pending behind the active claim.  The adapter must
 * finish after an irrevocable side effect or abort before retry/rollback.
 * Claims are transient ownership credentials and are never serialized.
 */
struct vmm_startup_event_claim {
	uint64_t owner_id;
	uint64_t claim_id;
	uintptr_t state_cookie;
	uintptr_t storage_cookie;
	uint32_t vcpuid;
	uint8_t kind;
	uint8_t vector;
	uint8_t active;
	uint8_t reserved8;
	uint32_t reserved32;
};

/*
 * Value-only observation used to close the frozen-to-running notification
 * window.  A caller captures this while frozen, publishes VCPU_RUNNING, then
 * checks it before machine entry.  A publisher that commits before the check
 * changes one of these named fields; a publisher that commits after the check
 * observes VCPU_RUNNING and sends the ordinary notification.  The token is
 * runtime ownership evidence, not checkpoint state or a public ABI.
 */
struct vmm_startup_event_run_token {
	uint64_t owner_id;
	uint64_t generation;
	uint64_t next_claim_id;
	uint64_t active_claim_id;
	uint32_t vcpuid;
	uint8_t pending;
	uint8_t sipi_vector;
	uint8_t active_kind;
	uint8_t active_vector;
	uint32_t reserved;
};

int	vmm_startup_event_init(struct vmm_startup_event_state *, uint64_t,
	    uint32_t);
int	vmm_startup_event_validate(const struct vmm_startup_event_state *);
int	vmm_startup_event_publish_init(struct vmm_startup_event_state *);
int	vmm_startup_event_publish_sipi(struct vmm_startup_event_state *,
	    uint8_t);
int	vmm_startup_event_peek(struct vmm_startup_event_state *,
	    struct vmm_startup_event_receipt *);
int	vmm_startup_event_consume(struct vmm_startup_event_state *,
	    struct vmm_startup_event_receipt *);
int	vmm_startup_event_claim_begin(struct vmm_startup_event_state *,
	    struct vmm_startup_event_claim *);
int	vmm_startup_event_claim_check(const struct vmm_startup_event_state *,
	    const struct vmm_startup_event_claim *);
int	vmm_startup_event_publish_claim(struct vmm_startup_event_state *,
	    enum vmm_startup_event_kind, uint8_t,
	    struct vmm_startup_event_claim *);
int	vmm_startup_event_claim_finish(struct vmm_startup_event_state *,
	    struct vmm_startup_event_claim *);
int	vmm_startup_event_claim_abort(struct vmm_startup_event_state *,
	    struct vmm_startup_event_claim *);
int	vmm_startup_event_run_token_validate(
	    const struct vmm_startup_event_run_token *);
int	vmm_startup_event_run_token_capture(
	    const struct vmm_startup_event_state *,
	    struct vmm_startup_event_run_token *);
int	vmm_startup_event_run_token_check(
	    const struct vmm_startup_event_state *,
	    const struct vmm_startup_event_run_token *);
int	vmm_startup_event_reset(struct vmm_startup_event_state *);

#endif /* _DEV_VMM_VMM_STARTUP_EVENT_H_ */
