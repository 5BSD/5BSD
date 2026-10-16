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
#include "nested_svm_policy.h"
#include "nested_svm_reflect.h"

#define SVM_COPY_BYTES(off, len) \
	memmove(to + (off), from + (off), (len))

void
svm_nested_vmcb_exit_copy(void *destination, const void *source,
    bool l1_lbr_enabled, bool l1_npt_enabled)
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
	/* EXITCODE through EXITINTINFO, then event injection and decode assist. */
	SVM_COPY_BYTES(VMCB_OFF_EXIT_REASON, 0x20);
	SVM_COPY_BYTES(VMCB_OFF_CTRL(0xa8), 8);
	SVM_COPY_BYTES(VMCB_OFF_CTRL(0xc8), 0x18);
	/* V_TPR, V_IRQ and interrupt shadow are hardware-updated control bits. */
	to[VMCB_OFF_VIRQ] = from[VMCB_OFF_VIRQ];
	to[VMCB_OFF_VIRQ + 1] = (to[VMCB_OFF_VIRQ + 1] & ~1U) |
	    (from[VMCB_OFF_VIRQ + 1] & 1U);
	to[VMCB_OFF_CTRL(0x68)] = (to[VMCB_OFF_CTRL(0x68)] & ~1U) |
	    (from[VMCB_OFF_CTRL(0x68)] & 1U);

	/* VMRUN/#VMEXIT state.  VMLOAD/VMSAVE fields remain L1-owned. */
	SVM_COPY_BYTES(VMCB_OFF_STATE(0x00), 0x40); /* ES, CS, SS, DS */
	SVM_COPY_BYTES(VMCB_OFF_STATE(0x60), 0x10); /* GDTR */
	SVM_COPY_BYTES(VMCB_OFF_STATE(0x80), 0x10); /* IDTR */
	SVM_COPY_BYTES(VMCB_OFF_STATE(0xcb), 1);    /* CPL */
	SVM_COPY_BYTES(VMCB_OFF_STATE(0xd0), 8);    /* EFER */
	SVM_COPY_BYTES(VMCB_OFF_STATE(0x148), 0x38); /* CR4..RIP */
	SVM_COPY_BYTES(VMCB_OFF_STATE(0x1d8), 8); /* RSP */
	SVM_COPY_BYTES(VMCB_OFF_STATE(0x1f8), 8); /* RAX */
	SVM_COPY_BYTES(VMCB_OFF_STATE(0x240), 8); /* CR2 */
	if (l1_npt_enabled)
		SVM_COPY_BYTES(VMCB_OFF_GUEST_PAT, 8);
	if (l1_lbr_enabled)
		SVM_COPY_BYTES(VMCB_OFF_DBGCTL, 0x28);
}

void
svm_nested_vmcb_shutdown_copy(void *destination)
{
	uint8_t *to;
	uint64_t code;

	to = destination;
#ifdef _KERNEL
	KASSERT(to != NULL, ("%s: null VMCB", __func__));
#else
	if (to == NULL)
		return;
#endif
	/* After SHUTDOWN, VMCB02 saved state is undefined.  Keep L1's copy. */
	code = VMCB_EXIT_SHUTDOWN;
	memmove(to + VMCB_OFF_EXIT_REASON, &code, sizeof(code));
	memset(to + VMCB_OFF_EXITINFO1, 0, 0x18);
	memset(to + VMCB_OFF_CTRL(0xa8), 0, 8);
	memset(to + VMCB_OFF_CTRL(0xc8), 0, 0x18);
}

/* Portable active-L2 image: copy guest-owned controls, then live L2 state. */
void
svm_nested_vmcb_checkpoint_copy(void *destination, const void *vmcb12,
    const void *vmcb02, bool l1_lbr_enabled, bool l1_npt_enabled)
{
	uint8_t *to;
	const uint8_t *from;

	to = destination;
	from = vmcb02;
#ifdef _KERNEL
	KASSERT(to != NULL && vmcb12 != NULL && from != NULL,
	    ("%s: null VMCB", __func__));
#else
	if (to == NULL || vmcb12 == NULL || from == NULL)
		return;
#endif
	memmove(to, vmcb12, SVM_NESTED_PAGE_SIZE);
	svm_nested_vmcb_exit_copy(to, from, l1_lbr_enabled,
	    l1_npt_enabled);
	svm_nested_vmcb_aux_copy(to, from);
	/* Preserve live LBR state whether or not L1 virtualized it. */
	memmove(to + VMCB_OFF_DBGCTL, from + VMCB_OFF_DBGCTL, 0x28);
}

#undef SVM_COPY_BYTES
