/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_L2_ACCESS_INTEL_H_
#define	_VMM_INTEL_VMX_NESTED_L2_ACCESS_INTEL_H_

#include <sys/types.h>

struct seg_desc;
struct vmx_nested_l2_portable_state;

/*
 * Adapt bhyve's amd64 VM_REG ABI to the portable nested-L2 value model.
 * ENOENT means the ABI register is intentionally outside this image (for
 * example a GPR in vmxctx); callers must not redirect ENOENT to VMCS01 while
 * L2 owns the architectural context.
 */
int	vmx_nested_l2_intel_getreg(
	    struct vmx_nested_l2_portable_state *, int, uint64_t *);
int	vmx_nested_l2_intel_setreg(
	    struct vmx_nested_l2_portable_state *, int, uint64_t);
int	vmx_nested_l2_intel_getdesc(
	    struct vmx_nested_l2_portable_state *, int, struct seg_desc *);
int	vmx_nested_l2_intel_setdesc(
	    struct vmx_nested_l2_portable_state *, int,
	    const struct seg_desc *);

#endif /* _VMM_INTEL_VMX_NESTED_L2_ACCESS_INTEL_H_ */
