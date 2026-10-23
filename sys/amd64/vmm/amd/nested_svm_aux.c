/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>

#ifdef _KERNEL
#include <sys/systm.h>
#include <machine/segments.h>
#include <machine/vmm.h>
#else
#include <stdint.h>
#include <string.h>
#endif

#include "vmcb.h"
#include "nested_svm_aux.h"

#ifdef _KERNEL
CTASSERT(offsetof(struct vmcb, state.fs) == VMCB_OFF_STATE(0x40));
CTASSERT(offsetof(struct vmcb, state.gs) == VMCB_OFF_STATE(0x50));
CTASSERT(offsetof(struct vmcb, state.ldt) == VMCB_OFF_STATE(0x70));
CTASSERT(offsetof(struct vmcb, state.tr) == VMCB_OFF_STATE(0x90));
CTASSERT(offsetof(struct vmcb, state.star) == VMCB_OFF_STAR);
CTASSERT(offsetof(struct vmcb, state.sysenter_eip) ==
    VMCB_OFF_SYSENTER_EIP);
#endif

void
svm_nested_vmcb_aux_copy(void *destination, const void *source)
{
	uint8_t *to;
	const uint8_t *from;

	to = destination;
	from = source;
#ifdef _KERNEL
	KASSERT(to != NULL && from != NULL, ("%s: null VMCB", __func__));
#else
	if (to == NULL || from == NULL)
		return;
#endif
	/* FS, GS; LDTR; TR; STAR through SYSENTER_EIP. */
	memmove(to + VMCB_OFF_STATE(0x40),
	    from + VMCB_OFF_STATE(0x40), 0x20);
	memmove(to + VMCB_OFF_STATE(0x70),
	    from + VMCB_OFF_STATE(0x70), 0x10);
	memmove(to + VMCB_OFF_STATE(0x90),
	    from + VMCB_OFF_STATE(0x90), 0x10);
	memmove(to + VMCB_OFF_STAR, from + VMCB_OFF_STAR, 0x40);
}
