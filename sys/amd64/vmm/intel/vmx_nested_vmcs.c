/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/endian.h>
#include <sys/errno.h>
#include <sys/types.h>

#ifndef _KERNEL
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#else
#include <sys/systm.h>
#endif

#include "vmx_nested_vmcs.h"
#include "vmx_nested_caps.h"

#define	VMX_PIN_POSTED_INTERRUPT	(UINT32_C(1) << 7)
#define	VMX_PIN_PREEMPTION_TIMER	(UINT32_C(1) << 6)
#define	VMX_PRIMARY_TPR_SHADOW		(UINT32_C(1) << 21)
#define	VMX_PRIMARY_SECONDARY		(UINT32_C(1) << 31)
#define	VMX_SECONDARY_APIC_ACCESS	(UINT32_C(1) << 0)
#define	VMX_SECONDARY_EPT		(UINT32_C(1) << 1)
#define	VMX_SECONDARY_VPID		(UINT32_C(1) << 5)
#define	VMX_SECONDARY_VIRTUAL_INTR	(UINT32_C(1) << 9)
#define	VMX_SECONDARY_TSC_SCALING	(UINT32_C(1) << 25)
#define	VMX_EXIT_SAVE_DEBUG		(UINT32_C(1) << 2)
#define	VMX_EXIT_SAVE_PAT		(UINT32_C(1) << 18)
#define	VMX_EXIT_LOAD_PAT		(UINT32_C(1) << 19)
#define	VMX_EXIT_SAVE_EFER		(UINT32_C(1) << 20)
#define	VMX_EXIT_LOAD_EFER		(UINT32_C(1) << 21)
#define	VMX_EXIT_SAVE_PERF		(UINT32_C(1) << 30)
#define	VMX_ENTRY_LOAD_DEBUG		(UINT32_C(1) << 2)
#define	VMX_ENTRY_LOAD_PERF		(UINT32_C(1) << 13)
#define	VMX_ENTRY_LOAD_PAT		(UINT32_C(1) << 14)
#define	VMX_ENTRY_LOAD_EFER		(UINT32_C(1) << 15)

struct vmx_nested_vmcs_range {
	uint16_t first;
	uint16_t last;
};

/*
 * Baseline architectural fields implemented by bhyve.  Ranges are split at
 * every reserved hole; accepting an encoding merely because its width/type
 * bits are well formed would incorrectly create VMCS fields.
 */
static const struct vmx_nested_vmcs_range vmx_nested_vmcs_ranges[] = {
	{ 0x0000, 0x0002 },
	{ 0x0800, 0x0810 },
	{ 0x0c00, 0x0c0c },
	{ 0x2000, 0x200c },
	{ 0x2010, 0x2016 },
	{ 0x201a, 0x2022 },
	{ 0x2032, 0x2032 },
	{ 0x2400, 0x2400 },
	{ 0x2800, 0x2810 },
	{ 0x2c00, 0x2c04 },
	{ 0x4000, 0x4022 },
	{ 0x4400, 0x440e },
	{ 0x4800, 0x482a },
	{ 0x482e, 0x482e },
	{ 0x4c00, 0x4c00 },
	{ 0x6000, 0x600e },
	{ 0x6400, 0x640a },
	{ 0x6800, 0x6826 },
	{ 0x6c00, 0x6c16 },
};

static uint8_t
vmx_nested_vmcs_width(uint32_t encoding)
{
	static const uint8_t widths[] = { 2, 8, 4, 8 };

	return (widths[(encoding >> 13) & 3]);
}

static bool
vmx_nested_vmcs_base_present(uint32_t encoding)
{

	for (size_t i = 0; i < nitems(vmx_nested_vmcs_ranges); i++) {
		if (encoding >= vmx_nested_vmcs_ranges[i].first &&
		    encoding <= vmx_nested_vmcs_ranges[i].last)
			return (true);
	}
	return (false);
}

int
vmx_nested_vmcs_field_info(uint32_t encoding,
    struct vmx_nested_vmcs_field_info *info)
{
	uint32_t base;
	uint8_t width;
	bool high_half;

	if (info == NULL || (encoding & UINT32_C(0xffff8000)) != 0)
		return (EINVAL);
	width = vmx_nested_vmcs_width(encoding);
	high_half = (encoding & 1) != 0;
	/*
	 * Access type "high" (encoding bit 0) is architecturally defined only
	 * for 64-bit fields (width class 1).  Natural-width fields (class 3)
	 * also occupy eight bytes but must be accessed as a single full field,
	 * so gating on the width class rather than the byte width is required
	 * to reject their otherwise well-formed high-half encodings.
	 */
	if (high_half && ((encoding >> 13) & 3) != 1)
		return (ENOENT);
	base = encoding & ~UINT32_C(1);
	if (!vmx_nested_vmcs_base_present(base))
		return (ENOENT);
	info->encoding = base;
	info->width = width;
	info->readonly = ((base >> 10) & 3) == 1;
	info->high_half = high_half;
	return (0);
}

bool
vmx_nested_vmcs_field_available(
    const struct vmx_nested_capabilities *capabilities, uint32_t encoding)
{
	struct vmx_nested_vmcs_field_info info;
	uint32_t entry, exit, pin, primary, secondary;

	if (vmx_nested_capabilities_validate(capabilities) != 0 ||
	    vmx_nested_vmcs_field_info(encoding, &info) != 0)
		return (false);
	pin = (uint32_t)(capabilities->pinbased >> 32);
	primary = (uint32_t)(capabilities->primary >> 32);
	secondary = (uint32_t)(capabilities->secondary >> 32);
	exit = (uint32_t)(capabilities->vmexit >> 32);
	entry = (uint32_t)(capabilities->vmentry >> 32);
	switch (info.encoding) {
	case 0x0000:		/* virtual processor identifier */
		return ((secondary & VMX_SECONDARY_VPID) != 0);
	case 0x0002:		/* posted-interrupt notification vector */
	case 0x2016:		/* posted-interrupt descriptor address */
		return ((pin & VMX_PIN_POSTED_INTERRUPT) != 0);
	case 0x0810:		/* guest interrupt status */
	case 0x201c:
	case 0x201e:
	case 0x2020:
	case 0x2022:		/* EOI-exit bitmaps */
		return ((secondary & VMX_SECONDARY_VIRTUAL_INTR) != 0);
	case 0x2012:		/* virtual-APIC page address */
	case 0x401c:		/* TPR threshold */
		return ((primary & VMX_PRIMARY_TPR_SHADOW) != 0);
	case 0x2014:		/* APIC-access address */
		return ((secondary & VMX_SECONDARY_APIC_ACCESS) != 0);
	case 0x201a:		/* EPT pointer */
	case 0x2400:		/* guest physical address */
		return ((secondary & VMX_SECONDARY_EPT) != 0);
	case 0x2032:		/* TSC multiplier */
		return ((secondary & VMX_SECONDARY_TSC_SCALING) != 0);
	case 0x2802:		/* guest IA32_DEBUGCTL */
		return (((entry & VMX_ENTRY_LOAD_DEBUG) |
		    (exit & VMX_EXIT_SAVE_DEBUG)) != 0);
	case 0x2804:		/* guest IA32_PAT */
		return (((entry & VMX_ENTRY_LOAD_PAT) |
		    (exit & VMX_EXIT_SAVE_PAT)) != 0);
	case 0x2806:		/* guest IA32_EFER */
		return (((entry & VMX_ENTRY_LOAD_EFER) |
		    (exit & VMX_EXIT_SAVE_EFER)) != 0);
	case 0x2808:		/* guest IA32_PERF_GLOBAL_CTRL */
		return (((entry & VMX_ENTRY_LOAD_PERF) |
		    (exit & VMX_EXIT_SAVE_PERF)) != 0);
	case 0x2c00:		/* host IA32_PAT */
		return ((exit & VMX_EXIT_LOAD_PAT) != 0);
	case 0x2c02:		/* host IA32_EFER */
		return ((exit & VMX_EXIT_LOAD_EFER) != 0);
	case 0x2c04:		/* host IA32_PERF_GLOBAL_CTRL */
		return ((exit & (UINT32_C(1) << 12)) != 0);
	case 0x401e:		/* secondary processor controls */
		return ((primary & VMX_PRIMARY_SECONDARY) != 0);
	case 0x482e:		/* VMX-preemption timer value */
		return ((pin & VMX_PIN_PREEMPTION_TIMER) != 0);
	default:
		return (true);
	}
}

uint64_t
vmx_nested_vmcs_schema_signature(void)
{
	uint8_t bytes[8];
	uint64_t digest;

	digest = UINT64_C(14695981039346656037);
	for (size_t i = 0; i < nitems(vmx_nested_vmcs_ranges); i++) {
		for (uint32_t encoding = vmx_nested_vmcs_ranges[i].first;
		    encoding <= vmx_nested_vmcs_ranges[i].last; encoding += 2) {
			memset(bytes, 0, sizeof(bytes));
			le32enc(bytes, encoding);
			bytes[4] = vmx_nested_vmcs_width(encoding);
			bytes[5] = ((encoding >> 10) & 3) == 1;
			for (size_t j = 0; j < sizeof(bytes); j++) {
				digest ^= bytes[j];
				digest *= UINT64_C(1099511628211);
			}
		}
	}
	return (digest == 0 ? 1 : digest);
}

uint64_t
vmx_nested_vmcs_enum(void)
{
	uint32_t encoding, max_index;

	max_index = 0;
	for (size_t i = 0; i < nitems(vmx_nested_vmcs_ranges); i++) {
		for (encoding = vmx_nested_vmcs_ranges[i].first;
		    encoding <= vmx_nested_vmcs_ranges[i].last; encoding += 2) {
			if (((encoding >> 1) & 0x1ff) > max_index)
				max_index = (encoding >> 1) & 0x1ff;
		}
	}
	return ((uint64_t)max_index << 1);
}
