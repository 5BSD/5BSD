/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _DEV_VMM_VMM_STARTUP_REQUEST_H_
#define	_DEV_VMM_VMM_STARTUP_REQUEST_H_

#include <sys/types.h>

#ifdef _KERNEL
#include <sys/stdint.h>
#else
#include <stdint.h>
#endif

struct vmm_startup_handshake_status;

/*
 * Fixed-width versioned management request used by VM_STARTUP_REQUEST.
 * Unknown versions, operations, flags, and reserved fields are closed.
 */
#define	VMM_STARTUP_REQUEST_VERSION	UINT16_C(1)
#define	VMM_STARTUP_REQUEST_SIZE	UINT16_C(48)
#define	VMM_STARTUP_REQUEST_IOCNUM	116

enum vmm_startup_request_operation {
	VMM_STARTUP_REQUEST_CONFIGURE = 1,
	VMM_STARTUP_REQUEST_WAIT_READY,
	VMM_STARTUP_REQUEST_COMMIT,
	VMM_STARTUP_REQUEST_STATUS,
	VMM_STARTUP_REQUEST_OPERATION_LAST,
};

enum vmm_startup_request_phase {
	VMM_STARTUP_REQUEST_PHASE_OPEN = 0,
	VMM_STARTUP_REQUEST_PHASE_COLLECTING,
	VMM_STARTUP_REQUEST_PHASE_COMMITTED,
	VMM_STARTUP_REQUEST_PHASE_LAST,
};

enum vmm_startup_request_owner {
	VMM_STARTUP_REQUEST_OWNER_USERSPACE = 0,
	VMM_STARTUP_REQUEST_OWNER_KERNEL,
	VMM_STARTUP_REQUEST_OWNER_LAST,
};

enum vmm_startup_request_execution {
	VMM_STARTUP_REQUEST_EXECUTION_USERSPACE = 0,
	VMM_STARTUP_REQUEST_EXECUTION_PRESTARTED,
	VMM_STARTUP_REQUEST_EXECUTION_LAST,
};

struct vmm_startup_request {
	uint16_t version;
	uint16_t size;
	uint16_t operation;
	uint16_t flags;
	uint64_t generation;
	uint32_t expected_vcpus;
	uint32_t entered_vcpus;
	uint8_t bootstrap_entered;
	uint8_t phase;
	uint8_t owner;
	uint8_t execution;
	uint8_t reserved8[20];
};
_Static_assert(sizeof(struct vmm_startup_request) ==
    VMM_STARTUP_REQUEST_SIZE, "startup request ABI");

int	vmm_startup_request_validate(const struct vmm_startup_request *,
	    uint32_t);
int	vmm_startup_request_encode_status(const struct vmm_startup_request *,
	    uint32_t, const struct vmm_startup_handshake_status *,
	    struct vmm_startup_request *);

#endif /* _DEV_VMM_VMM_STARTUP_REQUEST_H_ */
