/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _DEV_VMM_VMM_STARTUP_HANDSHAKE_H_
#define	_DEV_VMM_VMM_STARTUP_HANDSHAKE_H_

#include <sys/types.h>

#ifdef _KERNEL
#include <sys/stdint.h>
#else
#include <stdbool.h>
#include <stdint.h>
#endif

#include <dev/vmm/vmm_startup_mode.h>

enum vmm_startup_handshake_phase {
	VMM_STARTUP_HANDSHAKE_OPEN = 0,
	VMM_STARTUP_HANDSHAKE_COLLECTING,
	VMM_STARTUP_HANDSHAKE_COMMITTED,
	VMM_STARTUP_HANDSHAKE_CANCELLED,
	VMM_STARTUP_HANDSHAKE_PHASE_LAST,
};

/* Transient caller-synchronized kernel values; never serialize these. */
struct vmm_startup_handshake_vcpu {
	uint64_t owner_id;
	uint64_t generation;
	uintptr_t handshake_cookie;
	uintptr_t storage_cookie;
	uint32_t vcpuid;
	uint8_t bootstrap_processor;
	uint8_t entered;
	uint16_t reserved16;
};

struct vmm_startup_handshake {
	struct vmm_startup_mode mode;
	uint64_t owner_id;
	uint64_t generation;
	struct vmm_startup_handshake_vcpu *vcpus;
	uintptr_t storage_cookie;
	uintptr_t vcpus_cookie;
	uint32_t expected_vcpus;
	uint32_t entered_vcpus;
	uint8_t bootstrap_entered;
	uint8_t phase;
	uint16_t reserved16;
	uint32_t reserved32;
};

/* Pointer-free transient observation; this is not a save-state or ABI. */
struct vmm_startup_handshake_status {
	struct vmm_startup_mode mode;
	uint64_t generation;
	uint32_t expected_vcpus;
	uint32_t entered_vcpus;
	uint8_t bootstrap_entered;
	uint8_t phase;
	uint16_t reserved16;
	uint32_t reserved32;
};

int	vmm_startup_handshake_init(struct vmm_startup_handshake *, uint64_t);
int	vmm_startup_handshake_validate(const struct vmm_startup_handshake *);
int	vmm_startup_handshake_lock_default(struct vmm_startup_handshake *);
int	vmm_startup_handshake_configure_kernel(
	    struct vmm_startup_handshake *,
	    struct vmm_startup_handshake_vcpu *, uint32_t);
int	vmm_startup_handshake_enter(struct vmm_startup_handshake *,
	    uint32_t, bool);
int	vmm_startup_handshake_commit(struct vmm_startup_handshake *);
int	vmm_startup_handshake_reset_check(
	    const struct vmm_startup_handshake *);
int	vmm_startup_handshake_reset(struct vmm_startup_handshake *);
int	vmm_startup_handshake_status(
	    const struct vmm_startup_handshake *,
	    struct vmm_startup_handshake_status *);
int	vmm_startup_handshake_cancel(struct vmm_startup_handshake *);
int	vmm_startup_handshake_retire(struct vmm_startup_handshake *);

#endif /* _DEV_VMM_VMM_STARTUP_HANDSHAKE_H_ */
