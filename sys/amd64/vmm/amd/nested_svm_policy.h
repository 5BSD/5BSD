/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_AMD_NESTED_SVM_POLICY_H_
#define	_VMM_AMD_NESTED_SVM_POLICY_H_

#include <sys/types.h>

#ifndef _KERNEL
#include <stdbool.h>
#include <stdint.h>
#endif

#define	SVM_NESTED_PAGE_SIZE	4096U
/* The private NPT02 vmspace ends at VM_MAXUSER_ADDRESS_LA48 (2^47). */
#define	SVM_NESTED_GPA_WIDTH	47U

static inline uint8_t
svm_nested_physical_width(uint8_t host_width)
{

	return (host_width < SVM_NESTED_GPA_WIDTH ? host_width :
	    SVM_NESTED_GPA_WIDTH);
}

/*
 * A private, copied view of the L1 VMCB.  The frozen VMRUN adapter reads
 * VMCB12 from guest memory into stable storage; none of its addresses are
 * host physical addresses.  The view check covers initial admission only.
 */
struct svm_nested_vmcb12_view {
	uint64_t vmcb_gpa;
	uint64_t hsave_gpa;
	uint64_t iopm_gpa;
	uint64_t msrpm_gpa;
	uint64_t npt_root_gpa;
	uint64_t npt_control;
	uint64_t eventinj;
	uint64_t efer;
	uint64_t g_pat;
	uint64_t cr0;
	uint64_t cr3;
	uint64_t cr4;
	uint64_t dr6;
	uint64_t dr7;
	uint32_t intercept[5];
	uint32_t asid;
	uint16_t cs_attrib;
	uint8_t v_tpr;
	uint8_t tlb_ctrl;
	uint8_t vnmi_controls;
};

struct svm_nested_portio {
	uint64_t next_rip;
	uint16_t port;
	uint8_t bytes;
	bool in;
};

struct svm_nested_pending_event {
	uint32_t l1_intercepts;
	uint64_t l1_rflags;
	uint64_t l2_rflags;
	uint64_t eventinj;
	uint64_t exitintinfo;
	bool l1_intr_masking;
	bool nmi_pending;
	bool nmi_blocked;
	bool irq_pending;
	bool mask_hwintr;
};

bool	svm_nested_guest_physical_range_valid(uint64_t, uint64_t, uint8_t);
bool	svm_nested_state_mode_valid(uint64_t, uint64_t, uint64_t);
bool	svm_nested_vmcb12_view_valid(const struct svm_nested_vmcb12_view *,
	    uint8_t, bool);
bool	svm_nested_eventinj_valid(uint64_t);
int	svm_nested_l2_event_replay(uint64_t, uint64_t, uint64_t *);
int	svm_nested_l2_fault_injection(uint8_t, uint64_t, uint64_t,
	    uint64_t, uint64_t *);
uint64_t svm_nested_pending_event_exit(
	    const struct svm_nested_pending_event *);
int	svm_nested_portio_decode(uint64_t, uint64_t, uint64_t,
	    struct svm_nested_portio *);
uint32_t svm_nested_cr8_intercept_mask(bool);
bool	svm_nested_cr8_operand(uint64_t, bool, uint8_t *);
#ifdef _KERNEL
struct vmcb;
bool	svm_nested_vmcb12_view_from_vmcb(struct svm_nested_vmcb12_view *,
	    const struct vmcb *, uint64_t, uint64_t);
#endif

#endif /* _VMM_AMD_NESTED_SVM_POLICY_H_ */
