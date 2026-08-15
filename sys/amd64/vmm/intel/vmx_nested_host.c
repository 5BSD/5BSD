/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/types.h>

#ifndef _KERNEL
#include <stdbool.h>
#include <stdint.h>
#else
#include <sys/systm.h>
#endif

#include "vmx_nested_caps.h"
#include "vmx_nested_host.h"
#include "vmx_nested_validate.h"

#define	NVMX_EXIT_HOST_LMA		(UINT32_C(1) << 9)
#define	NVMX_EXIT_LOAD_PAT		(UINT32_C(1) << 19)
#define	NVMX_EXIT_LOAD_EFER		(UINT32_C(1) << 21)
#define	NVMX_ENTRY_GUEST_LMA		(UINT32_C(1) << 9)

#define	NVMX_CR0_NW			(UINT64_C(1) << 29)
#define	NVMX_CR0_CD			(UINT64_C(1) << 30)
#define	NVMX_CR4_PAE			(UINT64_C(1) << 5)
#define	NVMX_CR4_LA57			(UINT64_C(1) << 12)
#define	NVMX_CR4_PCIDE			(UINT64_C(1) << 17)

#define	NVMX_EFER_SCE			(UINT64_C(1) << 0)
#define	NVMX_EFER_LME			(UINT64_C(1) << 8)
#define	NVMX_EFER_LMA			(UINT64_C(1) << 10)
#define	NVMX_EFER_NXE			(UINT64_C(1) << 11)
#define	NVMX_EFER_VALID			(NVMX_EFER_SCE | NVMX_EFER_LME | \
	    NVMX_EFER_LMA | NVMX_EFER_NXE)

static int
nvmx_host_fail(enum vmx_nested_host_failure failure,
    enum vmx_nested_host_failure *reported)
{

	if (reported != NULL)
		*reported = failure;
	return (EINVAL);
}

int
vmx_nested_host_state_validate(
    const struct vmx_nested_capabilities *capabilities, uint32_t vmexit,
    uint32_t vmentry, const struct vmx_nested_host_state *host,
    enum vmx_nested_host_failure *failure)
{
	uint8_t rip_width;
	bool host_lma;

	if (failure != NULL)
		*failure = VMX_NESTED_HOST_OK;
	if (vmx_nested_capabilities_validate(capabilities) != 0 || host == NULL)
		return (EINVAL);
	if (!vmx_nested_fixed_bits_valid(host->cr0, capabilities->cr0_fixed0,
	    capabilities->cr0_fixed1, NVMX_CR0_NW | NVMX_CR0_CD))
		return (nvmx_host_fail(VMX_NESTED_HOST_CR0, failure));
	if (!vmx_nested_physical_range_valid(capabilities, host->cr3, 1, 1))
		return (nvmx_host_fail(VMX_NESTED_HOST_CR3, failure));
	if (!vmx_nested_fixed_bits_valid(host->cr4, capabilities->cr4_fixed0,
	    capabilities->cr4_fixed1, 0))
		return (nvmx_host_fail(VMX_NESTED_HOST_CR4, failure));
	if (!vmx_nested_canonical_address(host->sysenter_esp,
	    capabilities->linear_address_width) ||
	    !vmx_nested_canonical_address(host->sysenter_eip,
	    capabilities->linear_address_width))
		return (nvmx_host_fail(VMX_NESTED_HOST_SYSENTER, failure));
	if ((vmexit & NVMX_EXIT_LOAD_PAT) != 0 &&
	    !vmx_nested_pat_valid(host->pat))
		return (nvmx_host_fail(VMX_NESTED_HOST_PAT, failure));
	host_lma = (vmexit & NVMX_EXIT_HOST_LMA) != 0;
	rip_width = (host->cr4 & NVMX_CR4_LA57) != 0 ? 57 : 48;
	if ((vmexit & NVMX_EXIT_LOAD_EFER) != 0 &&
	    ((host->efer & ~NVMX_EFER_VALID) != 0 ||
	    ((host->efer & NVMX_EFER_LME) != 0) != host_lma ||
	    ((host->efer & NVMX_EFER_LMA) != 0) != host_lma))
		return (nvmx_host_fail(VMX_NESTED_HOST_EFER, failure));
	if (((host->es_selector | host->cs_selector | host->ss_selector |
	    host->ds_selector | host->fs_selector | host->gs_selector |
	    host->tr_selector) & 7) != 0 ||
	    host->cs_selector == 0 || host->tr_selector == 0 ||
	    (!host_lma && host->ss_selector == 0))
		return (nvmx_host_fail(VMX_NESTED_HOST_SELECTOR, failure));
	if (!vmx_nested_canonical_address(host->fs_base,
	    capabilities->linear_address_width) ||
	    !vmx_nested_canonical_address(host->gs_base,
	    capabilities->linear_address_width) ||
	    !vmx_nested_canonical_address(host->tr_base,
	    capabilities->linear_address_width) ||
	    !vmx_nested_canonical_address(host->gdtr_base,
	    capabilities->linear_address_width) ||
	    !vmx_nested_canonical_address(host->idtr_base,
	    capabilities->linear_address_width))
		return (nvmx_host_fail(VMX_NESTED_HOST_BASE, failure));
	if ((!host->root_ia32e &&
	    ((vmentry & NVMX_ENTRY_GUEST_LMA) != 0 || host_lma)) ||
	    (host->root_ia32e && !host_lma) ||
	    (!host_lma && ((host->cr4 & NVMX_CR4_PCIDE) != 0 ||
	    (host->rip >> 32) != 0)) ||
	    (host_lma && ((host->cr4 & NVMX_CR4_PAE) == 0 ||
	    !vmx_nested_canonical_address(host->rip, rip_width))))
		return (nvmx_host_fail(VMX_NESTED_HOST_ADDRESS_SPACE, failure));
	return (0);
}
