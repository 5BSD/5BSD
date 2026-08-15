/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/errno.h>
#include <sys/param.h>
#include <sys/types.h>

#ifdef _KERNEL
#include <sys/systm.h>
#else
#include <stdint.h>
#endif

struct seg_desc;

#include "vmcs.h"
#include "vmx_nested_vmcs_fields.h"

int
vmx_nested_vmcs_segment_encoding(enum vmx_nested_guest_segment_id segment,
    enum vmx_nested_segment_field field, uint32_t *encoding)
{
	static const uint32_t fields[][VMX_NESTED_GUEST_SEGMENT_COUNT] = {
		[VMX_NESTED_SEGMENT_SELECTOR] = {
			VMCS_GUEST_ES_SELECTOR, VMCS_GUEST_CS_SELECTOR,
			VMCS_GUEST_SS_SELECTOR, VMCS_GUEST_DS_SELECTOR,
			VMCS_GUEST_FS_SELECTOR, VMCS_GUEST_GS_SELECTOR,
			VMCS_GUEST_TR_SELECTOR, VMCS_GUEST_LDTR_SELECTOR,
		},
		[VMX_NESTED_SEGMENT_LIMIT] = {
			VMCS_GUEST_ES_LIMIT, VMCS_GUEST_CS_LIMIT,
			VMCS_GUEST_SS_LIMIT, VMCS_GUEST_DS_LIMIT,
			VMCS_GUEST_FS_LIMIT, VMCS_GUEST_GS_LIMIT,
			VMCS_GUEST_TR_LIMIT, VMCS_GUEST_LDTR_LIMIT,
		},
		[VMX_NESTED_SEGMENT_ACCESS] = {
			VMCS_GUEST_ES_ACCESS_RIGHTS,
			VMCS_GUEST_CS_ACCESS_RIGHTS,
			VMCS_GUEST_SS_ACCESS_RIGHTS,
			VMCS_GUEST_DS_ACCESS_RIGHTS,
			VMCS_GUEST_FS_ACCESS_RIGHTS,
			VMCS_GUEST_GS_ACCESS_RIGHTS,
			VMCS_GUEST_TR_ACCESS_RIGHTS,
			VMCS_GUEST_LDTR_ACCESS_RIGHTS,
		},
		[VMX_NESTED_SEGMENT_BASE] = {
			VMCS_GUEST_ES_BASE, VMCS_GUEST_CS_BASE,
			VMCS_GUEST_SS_BASE, VMCS_GUEST_DS_BASE,
			VMCS_GUEST_FS_BASE, VMCS_GUEST_GS_BASE,
			VMCS_GUEST_TR_BASE, VMCS_GUEST_LDTR_BASE,
		},
	};

	_Static_assert(nitems(fields[0]) ==
	    VMX_NESTED_GUEST_SEGMENT_COUNT, "segment field map");
	if (encoding == NULL || segment < VMX_NESTED_GUEST_ES ||
	    segment >= VMX_NESTED_GUEST_SEGMENT_COUNT ||
	    field < VMX_NESTED_SEGMENT_SELECTOR ||
	    field > VMX_NESTED_SEGMENT_BASE)
		return (EINVAL);
	*encoding = fields[field][segment];
	return (0);
}
