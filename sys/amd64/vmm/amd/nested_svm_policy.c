/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/types.h>

#ifdef _KERNEL
#include <sys/systm.h>
#else
#include <stdbool.h>
#include <stdint.h>
#endif

#ifdef _KERNEL
#include <machine/segments.h>
#include <machine/vmm.h>
#endif
#include <machine/specialreg.h>

#include "vmcb.h"
#include "nested_svm_l2_msr.h"
#include "nested_svm_policy.h"

#define SVM_NESTED_EFER_MBZ_BITS 0xFFFFFFFFFFFF0200ULL

/* L0 runs L2 with interrupt masking enabled to keep physical IRQs local. */
uint32_t
svm_nested_cr8_intercept_mask(bool l1_intr_masking)
{

	return (l1_intr_masking ? 0 : BIT(8) | BIT(24));
}

/* AMD APM 15.8.1: DecodeAssists identifies the MOV CRx GPR operand. */
bool
svm_nested_cr8_operand(uint64_t exitinfo1, bool write, uint8_t *reg)
{

	if (reg == NULL ||
	    (exitinfo1 & ~(BIT(63) | 0xfULL)) != 0 ||
	    ((exitinfo1 & BIT(63)) != 0) != write)
		return (false);
	*reg = exitinfo1 & 0xf;
	return (true);
}

/* AMD APM volume 2, guest physical bounds used for VMRUN admission. */
bool
svm_nested_guest_physical_range_valid(uint64_t gpa, uint64_t length,
    uint8_t width)
{
	uint64_t limit;

	if (width < 32 || width >= 64 || length == 0)
		return (false);
	limit = 1ULL << width;
	return (gpa < limit && length <= limit - gpa);
}

/* Apply the same SVM entry-state checks to VMRUN and checkpoint restore. */
bool
svm_nested_state_mode_valid(uint64_t efer, uint64_t cr0, uint64_t cr4)
{
	bool long_mode;

	if ((cr0 & ~0xffffffffULL) != 0 ||
	    ((cr0 & CR0_NW) != 0 && (cr0 & CR0_CD) == 0))
		return (false);
	/* SVM permits PG=1, PE=0 unless long mode is also requested. */
	long_mode = (efer & EFER_LME) != 0 && (cr0 & CR0_PG) != 0;
	/* Hardware does not cross-check LMA against LME and PG on VMRUN. */
	if (long_mode && ((cr4 & CR4_PAE) == 0 ||
	    (cr0 & CR0_PE) == 0))
		return (false);
	return (true);
}

static bool
svm_nested_page_range_valid(uint64_t gpa, uint64_t pages, uint8_t width)
{

	return ((gpa & (SVM_NESTED_PAGE_SIZE - 1)) == 0 &&
	    svm_nested_guest_physical_range_valid(gpa,
	    pages * SVM_NESTED_PAGE_SIZE,
	    width));
}

static bool
svm_nested_exception_vector_valid(uint8_t vector)
{

	switch (vector) {
	case 0: case 1: case 3: case 4: case 5: case 6: case 7:
	case 8: case 10: case 11: case 12: case 13: case 14:
	case 16: case 17: case 18: case 19: case 28: case 30:
		return (true);
	default:
		return (false);
	}
}

bool
svm_nested_eventinj_valid(uint64_t eventinj)
{
	uint64_t type;

	if ((eventinj & VMCB_EVENTINJ_VALID) == 0)
		return (true);
	type = (eventinj >> 8) & 7;
	return ((eventinj & 0x7ffff000ULL) == 0 &&
	    (type != VMCB_EVENTINJ_TYPE_EXCEPTION ||
	    svm_nested_exception_vector_valid(eventinj & 0xff)) &&
	    (type == VMCB_EVENTINJ_TYPE_INTR ||
	    type == VMCB_EVENTINJ_TYPE_NMI ||
	    type == VMCB_EVENTINJ_TYPE_EXCEPTION ||
	    type == VMCB_EVENTINJ_TYPE_INTn));
}

int
svm_nested_l2_event_replay(uint64_t eventinj, uint64_t exitintinfo,
    uint64_t *next_eventinj)
{

	if (next_eventinj == NULL)
		return (EINVAL);
	if ((exitintinfo & VMCB_EVENTINJ_VALID) == 0) {
		*next_eventinj = eventinj;
		return (0);
	}
	if ((eventinj & VMCB_EVENTINJ_VALID) != 0 ||
	    !svm_nested_eventinj_valid(exitintinfo))
		return (EPROTO);
	*next_eventinj = exitintinfo;
	return (0);
}

/* Reinjection for L0's exception tracing when L1 did not intercept the fault. */
int
svm_nested_l2_fault_injection(uint8_t vector, uint64_t info1,
    uint64_t eventinj, uint64_t exitintinfo, uint64_t *next_eventinj)
{
	uint64_t injection;

	if (next_eventinj == NULL)
		return (EINVAL);
	if (!svm_nested_exception_vector_valid(vector) ||
	    vector == 3 || vector == 18 ||
	    vector == 28 || vector == 30)
		return (EOPNOTSUPP);
	if (((eventinj | exitintinfo) & VMCB_EVENTINJ_VALID) != 0)
		return (EAGAIN);
	injection = VMCB_EVENTINJ_VALID |
	    ((uint64_t)VMCB_EVENTINJ_TYPE_EXCEPTION << 8) | vector;
	/* #DF has a fixed zero error code.  #TS/#NP/#SS/#GP/#PF/#AC do not. */
	if (vector == 8 || (vector >= 10 && vector <= 14) || vector == 17) {
		injection |= VMCB_EVENTINJ_EC_VALID;
		if (vector != 8)
			injection |= (uint64_t)(uint32_t)info1 << 32;
	}
	*next_eventinj = injection;
	return (0);
}

/* Select an L1-requested exit for an L0 event pending at an L2 boundary. */
uint64_t
svm_nested_pending_event_exit(const struct svm_nested_pending_event *event)
{
	uint64_t rflags;

	if (event == NULL || event->mask_hwintr ||
	    ((event->eventinj | event->exitintinfo) &
	    VMCB_EVENTINJ_VALID) != 0)
		return (0);
	/* An NMI has priority even when L1 does not intercept it. */
	if (event->nmi_pending && !event->nmi_blocked)
		return ((event->l1_intercepts & VMCB_INTCPT_NMI) != 0 ?
		    VMCB_EXIT_NMI : 0);
	rflags = event->l1_intr_masking ? event->l1_rflags :
	    event->l2_rflags;
	/* An L1-requested interrupt exit is not blocked by L2's shadow. */
	if (event->irq_pending && (rflags & BIT(9)) != 0 &&
	    (event->l1_intercepts & VMCB_INTCPT_INTR) != 0)
		return (VMCB_EXIT_INTR);
	return (0);
}

int
svm_nested_portio_decode(uint64_t info1, uint64_t rip, uint64_t nrip,
    struct svm_nested_portio *portio)
{
	uint8_t bytes;

	if (portio == NULL || (info1 & BIT(2)) != 0 ||
	    nrip <= rip || nrip - rip > 15)
		return (EINVAL);
	/* A REP prefix has no repeat count to emulate on plain IN/OUT. */
	bytes = (info1 >> 4) & 7;
	if (bytes != 1 && bytes != 2 && bytes != 4)
		return (EINVAL);
	portio->next_rip = nrip;
	portio->port = (uint16_t)(info1 >> 16);
	portio->bytes = bytes;
	portio->in = (info1 & BIT(0)) != 0;
	return (0);
}

bool
svm_nested_vmcb12_view_valid(const struct svm_nested_vmcb12_view *view,
    uint8_t width, bool nested_npt_available)
{

	/* Hardware uses the page base and ignores IOPM/MSRPM bits 11:0. */
	if (view == NULL || width < 32 || width >= 64 ||
	    !svm_nested_page_range_valid(view->vmcb_gpa, 1, width) ||
	    !svm_nested_page_range_valid(view->hsave_gpa, 1, width) ||
	    !svm_nested_page_range_valid(view->iopm_gpa &
	    ~(uint64_t)(SVM_NESTED_PAGE_SIZE - 1), 3, width) ||
	    !svm_nested_page_range_valid(view->msrpm_gpa &
	    ~(uint64_t)(SVM_NESTED_PAGE_SIZE - 1), 2, width) ||
	    (view->intercept[VMCB_CTRL2_INTCPT] & VMCB_INTCPT_VMRUN) == 0 ||
	    view->asid == 0 || view->v_tpr > 15 ||
	    view->vnmi_controls != 0 ||
	    (view->tlb_ctrl != 0 && view->tlb_ctrl != 1 &&
	    view->tlb_ctrl != 3 && view->tlb_ctrl != 7) ||
	    (view->npt_control & ~1ULL) != 0 ||
	    (view->efer & EFER_SVM) == 0 ||
	    (view->efer & SVM_NESTED_EFER_MBZ_BITS) != 0 ||
	    !svm_nested_guest_physical_range_valid(view->cr3, 1, width) ||
	    ((view->dr6 | view->dr7) & ~0xffffffffULL) != 0 ||
	    ((view->npt_control & 1) != 0 &&
	    !svm_nested_l2_pat_valid(view->g_pat)) ||
	    !svm_nested_state_mode_valid(view->efer, view->cr0,
	    view->cr4))
		return (false);

	if ((view->npt_control & 1) != 0 &&
	    (!nested_npt_available ||
	    !svm_nested_page_range_valid(view->npt_root_gpa, 1, width)))
		return (false);

	if ((view->efer & EFER_LME) != 0 && (view->cr0 & CR0_PG) != 0) {
		if ((view->cr0 & CR0_PE) == 0 ||
		    (view->cr4 & CR4_PAE) == 0 ||
		    (view->cs_attrib &
		    (VMCB_CS_ATTRIB_L | VMCB_CS_ATTRIB_D)) ==
		    (VMCB_CS_ATTRIB_L | VMCB_CS_ATTRIB_D))
			return (false);
	}

	return (svm_nested_eventinj_valid(view->eventinj));
}

#ifdef _KERNEL
bool
svm_nested_vmcb12_view_from_vmcb(struct svm_nested_vmcb12_view *view,
    const struct vmcb *vmcb12, uint64_t vmcb_gpa, uint64_t hsave_gpa)
{
	const struct vmcb_ctrl *ctrl;
	const struct vmcb_state *state;
	int i;

	if (view == NULL || vmcb12 == NULL)
		return (false);
	ctrl = &vmcb12->ctrl;
	state = &vmcb12->state;
	bzero(view, sizeof(*view));
	view->vmcb_gpa = vmcb_gpa;
	view->hsave_gpa = hsave_gpa;
	view->iopm_gpa = ctrl->iopm_base_pa;
	view->msrpm_gpa = ctrl->msrpm_base_pa;
	view->npt_root_gpa = ctrl->n_cr3;
	bcopy((const uint8_t *)ctrl + VMCB_OFF_NP_ENABLE,
	    &view->npt_control, sizeof(view->npt_control));
	view->eventinj = ctrl->eventinj;
	view->efer = state->efer;
	view->g_pat = state->g_pat;
	view->cr0 = state->cr0;
	view->cr3 = state->cr3;
	view->cr4 = state->cr4;
	view->dr6 = state->dr6;
	view->dr7 = state->dr7;
	for (i = 0; i < nitems(ctrl->intercept); i++)
		view->intercept[i] = ctrl->intercept[i];
	view->asid = ctrl->asid;
	view->v_tpr = ctrl->v_tpr;
	view->tlb_ctrl = ctrl->tlb_ctrl;
	/* L1 does not see VNMI in CPUID; these controls belong to L0. */
	view->vnmi_controls = ctrl->v_nmi_enable |
	    ctrl->v_nmi_pending | ctrl->v_nmi_blocking;
	view->cs_attrib = state->cs.attrib;
	return (true);
}
#endif
