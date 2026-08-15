/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _DEV_VMM_VMM_STARTUP_RUN_REQUEST_H_
#define	_DEV_VMM_VMM_STARTUP_RUN_REQUEST_H_

#include <sys/types.h>

#ifdef _KERNEL
#include <sys/stdint.h>
#else
#include <stdint.h>
#endif

/*
 * Fixed-width generation-bearing VM_RUN_GENERATION request.  vcpuid must
 * remain first because the common vmm ioctl dispatcher reads that field
 * before it freezes the target vCPU.
 */
#define	VMM_STARTUP_RUN_REQUEST_VERSION	UINT16_C(1)
#define	VMM_STARTUP_RUN_REQUEST_SIZE		UINT16_C(64)
#define	VMM_STARTUP_RUN_REQUEST_IOCNUM		117

struct vmm_startup_run_request {
	int32_t vcpuid;
	uint16_t version;
	uint16_t size;
	uint32_t flags;
	uint32_t reserved32;
	uint64_t generation;
	uint64_t cpuset_address;
	uint64_t cpuset_size;
	uint64_t exit_address;
	uint64_t exit_size;
	uint8_t reserved8[8];
};

int	vmm_startup_run_request_validate(
	    const struct vmm_startup_run_request *, uint32_t, uint64_t,
	    uint64_t, uint64_t);

#endif /* _DEV_VMM_VMM_STARTUP_RUN_REQUEST_H_ */
