/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _DEV_VMM_VMM_DIRTY_LOG_REQUEST_H_
#define _DEV_VMM_VMM_DIRTY_LOG_REQUEST_H_

#include <sys/types.h>

#ifdef _KERNEL
#include <sys/stdint.h>
#else
#include <stdint.h>
#endif

/*
 * Fixed-width management ABI for one VM-wide CPU dirty-log owner.  Bitmap
 * bits always describe 4 KiB guest-physical units; host pointers, page sizes,
 * and native kernel structures never cross this boundary.
 */
#define VMM_DIRTY_LOG_REQUEST_VERSION UINT16_C(1)
#define VMM_DIRTY_LOG_REQUEST_SIZE UINT16_C(80)
#define VMM_DIRTY_LOG_RESULT_VERSION UINT16_C(1)
#define VMM_DIRTY_LOG_RESULT_SIZE UINT16_C(80)
#define VMM_DIRTY_LOG_REQUEST_IOCNUM 118

/*
 * Bound one synchronous kernel allocation and one vCPU-freeze interval.
 * Larger guests are collected in adjacent requests.  One MiB describes
 * 32 GiB of guest memory at the fixed 4 KiB dirty-log granularity.
 */
#define VMM_DIRTY_LOG_MAX_BITMAP_BYTES (UINT64_C(1024) * UINT64_C(1024))

enum vmm_dirty_log_request_operation {
	VMM_DIRTY_LOG_REQUEST_ENABLE = 1,
	VMM_DIRTY_LOG_REQUEST_OBSERVE,
	VMM_DIRTY_LOG_REQUEST_CLEAR,
	VMM_DIRTY_LOG_REQUEST_DISABLE,
	VMM_DIRTY_LOG_REQUEST_OPERATION_LAST,
};

struct vmm_dirty_log_request {
	uint16_t version;
	uint16_t size;
	uint16_t operation;
	uint16_t flags;
	uint64_t gpa;
	uint64_t length;
	uint64_t output_address;
	uint64_t output_bytes;
	uint64_t reserved64[3];
	uint8_t reserved8[16];
};
_Static_assert(sizeof(struct vmm_dirty_log_request) ==
    VMM_DIRTY_LOG_REQUEST_SIZE, "dirty log request ABI");

/*
 * OBSERVE and CLEAR publish this header and the bitmap in one contiguous
 * copyout.  The dirty generation is not cleared unless that complete copyout
 * succeeds, so an ioctl result-copy failure cannot lose dirty pages.
 */
struct vmm_dirty_log_result {
	uint16_t version;
	uint16_t size;
	uint16_t operation;
	uint16_t flags;
	uint64_t gpa;
	uint64_t length;
	uint64_t identity;
	uint64_t map_generation;
	uint64_t dirty_generation;
	uint64_t bitmap_offset;
	uint64_t bitmap_bytes;
	uint8_t reserved8[16];
};
_Static_assert(sizeof(struct vmm_dirty_log_result) ==
    VMM_DIRTY_LOG_RESULT_SIZE, "dirty log result ABI");

int vmm_dirty_log_request_validate(const struct vmm_dirty_log_request *);
int vmm_dirty_log_request_output_bytes(const struct vmm_dirty_log_request *,
    size_t *, size_t *);
int vmm_dirty_log_result_encode(const struct vmm_dirty_log_request *, uint64_t,
    uint64_t, uint64_t, struct vmm_dirty_log_result *);
int vmm_dirty_log_result_validate(const struct vmm_dirty_log_result *, size_t);

#endif /* _DEV_VMM_VMM_DIRTY_LOG_REQUEST_H_ */
