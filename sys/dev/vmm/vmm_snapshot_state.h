/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _DEV_VMM_VMM_SNAPSHOT_STATE_H_
#define	_DEV_VMM_VMM_SNAPSHOT_STATE_H_

#include <sys/types.h>

#ifdef _KERNEL
#include <sys/stdint.h>
#else
#include <stdint.h>
#endif

#define	VMM_SNAPSHOT_SECTION_VM_COMMON	UINT16_C(0x0001)
#define	VMM_SNAPSHOT_SECTION_VCPU_COMMON	UINT16_C(0x0002)

#define	VMM_SNAPSHOT_COMMON_STATE_VERSION	1U
#define	VMM_SNAPSHOT_VM_COMMON_SIZE	24U
#define	VMM_SNAPSHOT_VCPU_COMMON_SIZE	24U

#define	VMM_SNAPSHOT_VCPU_F_STARTUP_WAIT	UINT32_C(0x00000001)
#define	VMM_SNAPSHOT_VCPU_F_VALID	VMM_SNAPSHOT_VCPU_F_STARTUP_WAIT

struct vmm_snapshot_vm_common {
	uint32_t	max_vcpus;
	uint32_t	vcpu_count;
};

struct vmm_snapshot_vcpu_common {
	uint32_t	flags;
	uint64_t	next_pc;
};

int	vmm_snapshot_vm_common_encode(const struct vmm_snapshot_vm_common *,
	    void *, size_t, size_t *);
int	vmm_snapshot_vm_common_decode(const void *, size_t,
	    struct vmm_snapshot_vm_common *);
int	vmm_snapshot_vcpu_common_encode(
	    const struct vmm_snapshot_vcpu_common *, void *, size_t, size_t *);
int	vmm_snapshot_vcpu_common_decode(const void *, size_t,
	    struct vmm_snapshot_vcpu_common *);

#endif /* _DEV_VMM_VMM_SNAPSHOT_STATE_H_ */
