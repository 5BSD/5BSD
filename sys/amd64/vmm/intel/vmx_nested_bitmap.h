/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_BITMAP_H_
#define	_VMM_INTEL_VMX_NESTED_BITMAP_H_

#include "vmx_nested_types.h"

struct vmx_nested_memory;

/* Intel VMX bitmap pages are architectural 4 KiB units, not host pages. */
#define	VMX_NESTED_BITMAP_PAGE_SIZE	4096
#define	VMX_NESTED_MSR_BITMAP_SIZE	VMX_NESTED_BITMAP_PAGE_SIZE
#define	VMX_NESTED_IO_BITMAP_SIZE	(2 * VMX_NESTED_BITMAP_PAGE_SIZE)

int	vmx_nested_io_intercept(uint32_t, uint64_t, uint64_t, uint32_t,
	    uint8_t, const struct vmx_nested_memory *, bool *);
/*
 * Freeze VMCS12's two I/O bitmap pages into one host-owned policy image.
 * The image is used for exit reflection, never installed in VMCS02.  Output
 * is unchanged unless both pages have been read successfully.
 */
int	vmx_nested_io_bitmap_materialize(uint32_t, uint64_t, uint64_t,
	    const struct vmx_nested_memory *,
	    uint8_t [VMX_NESTED_IO_BITMAP_SIZE],
	    uint8_t [VMX_NESTED_IO_BITMAP_SIZE]);
int	vmx_nested_io_policy_intercept(
	    const uint8_t [VMX_NESTED_IO_BITMAP_SIZE], uint32_t, uint8_t,
	    bool *);
int	vmx_nested_msr_intercept(uint32_t, uint64_t, uint32_t, bool,
	    const struct vmx_nested_memory *, bool *);
/*
 * Build the immutable, host-owned MSR bitmap used by VMCS02.
 *
 * An intercept requested by either L0 or L1 remains an intercept.  If L1
 * does not enable VMCS12 MSR bitmaps, Intel VMX intercepts every RDMSR and
 * WRMSR; target is therefore filled with ones.  scratch must be a distinct
 * page so a failed guest-memory read leaves target unchanged.
 */
int	vmx_nested_msr_bitmap_materialize(uint32_t, uint64_t,
	    const struct vmx_nested_memory *,
	    const uint8_t [VMX_NESTED_MSR_BITMAP_SIZE],
	    uint8_t [VMX_NESTED_MSR_BITMAP_SIZE],
	    uint8_t [VMX_NESTED_MSR_BITMAP_SIZE],
	    uint8_t [VMX_NESTED_MSR_BITMAP_SIZE]);
int	vmx_nested_msr_policy_intercept(
	    const uint8_t [VMX_NESTED_MSR_BITMAP_SIZE], uint32_t, bool,
	    bool *);
int	vmx_nested_vmcs_access_intercept(bool, uint64_t, uint64_t,
	    const struct vmx_nested_memory *, bool *);

#endif /* _VMM_INTEL_VMX_NESTED_BITMAP_H_ */
