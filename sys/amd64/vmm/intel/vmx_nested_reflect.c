/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/types.h>

#ifndef _KERNEL
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#else
#include <sys/systm.h>
#endif

#include "vmx_nested_bitmap.h"
#include "vmx_nested_entry.h"
#include "vmx_nested_reflect.h"
#include "vmx_nested_state_range.h"

/*
 * Intel SDM Appendix C basic exit-reason values.  Keep these names local:
 * tests deliberately use an independent numeric specification fixture.
 */
enum vmx_nested_basic_exit_reason {
	EXIT_REASON_EXCEPTION = 0,
	EXIT_REASON_EXT_INTR = 1,
	EXIT_REASON_TRIPLE_FAULT = 2,
	EXIT_REASON_INIT = 3,
	EXIT_REASON_SIPI = 4,
	EXIT_REASON_IO_SMI = 5,
	EXIT_REASON_SMI = 6,
	EXIT_REASON_INTR_WINDOW = 7,
	EXIT_REASON_NMI_WINDOW = 8,
	EXIT_REASON_TASK_SWITCH = 9,
	EXIT_REASON_CPUID = 10,
	EXIT_REASON_GETSEC = 11,
	EXIT_REASON_HLT = 12,
	EXIT_REASON_INVD = 13,
	EXIT_REASON_INVLPG = 14,
	EXIT_REASON_RDPMC = 15,
	EXIT_REASON_RDTSC = 16,
	EXIT_REASON_RSM = 17,
	EXIT_REASON_VMCALL = 18,
	EXIT_REASON_VMCLEAR = 19,
	EXIT_REASON_VMLAUNCH = 20,
	EXIT_REASON_VMPTRLD = 21,
	EXIT_REASON_VMPTRST = 22,
	EXIT_REASON_VMREAD = 23,
	EXIT_REASON_VMRESUME = 24,
	EXIT_REASON_VMWRITE = 25,
	EXIT_REASON_VMXOFF = 26,
	EXIT_REASON_VMXON = 27,
	EXIT_REASON_CR_ACCESS = 28,
	EXIT_REASON_DR_ACCESS = 29,
	EXIT_REASON_INOUT = 30,
	EXIT_REASON_RDMSR = 31,
	EXIT_REASON_WRMSR = 32,
	EXIT_REASON_INVAL_VMCS = 33,
	EXIT_REASON_MSR_LOAD_FAILURE = 34,
	EXIT_REASON_MWAIT = 36,
	EXIT_REASON_MTF = 37,
	EXIT_REASON_MONITOR = 39,
	EXIT_REASON_PAUSE = 40,
	EXIT_REASON_MCE_DURING_ENTRY = 41,
	EXIT_REASON_TPR = 43,
	EXIT_REASON_APIC_ACCESS = 44,
	EXIT_REASON_VIRTUALIZED_EOI = 45,
	EXIT_REASON_GDTR_IDTR = 46,
	EXIT_REASON_LDTR_TR = 47,
	EXIT_REASON_EPT_FAULT = 48,
	EXIT_REASON_EPT_MISCONFIG = 49,
	EXIT_REASON_INVEPT = 50,
	EXIT_REASON_RDTSCP = 51,
	EXIT_REASON_VMX_PREEMPT = 52,
	EXIT_REASON_INVVPID = 53,
	EXIT_REASON_WBINVD = 54,
	EXIT_REASON_XSETBV = 55,
	EXIT_REASON_APIC_WRITE = 56,
	EXIT_REASON_RDRAND = 57,
	EXIT_REASON_INVPCID = 58,
	EXIT_REASON_VMFUNC = 59,
	EXIT_REASON_ENCLS = 60,
	EXIT_REASON_RDSEED = 61,
	EXIT_REASON_PM_LOG_FULL = 62,
	EXIT_REASON_XSAVES = 63,
	EXIT_REASON_XRSTORS = 64,
	EXIT_REASON_PCONFIG = 65,
	EXIT_REASON_SPP_EVENT = 66,
	EXIT_REASON_UMWAIT = 67,
	EXIT_REASON_TPAUSE = 68,
	EXIT_REASON_LOADIWKEY = 69,
	EXIT_REASON_ENQCMD_PASID = 72,
	EXIT_REASON_ENQCMDS_PASID = 73,
	EXIT_REASON_BUS_LOCK = 74,
	EXIT_REASON_INSTRUCTION_TIMEOUT = 75,
	EXIT_REASON_SEAMCALL = 76,
	EXIT_REASON_TDCALL = 77,
	EXIT_REASON_RDMSRLIST = 78,
	EXIT_REASON_WRMSRLIST = 79,
	EXIT_REASON_URDMSR = 80,
	EXIT_REASON_UWRMSR = 81,
	EXIT_REASON_RDMSR_IMM = 84,
	EXIT_REASON_WRMSR_IMM = 85,
};

#define	PRI_INTR_WINDOW_EXITING		(1U << 2)
#define	PRI_HLT_EXITING			(1U << 7)
#define	PRI_INVLPG_EXITING		(1U << 9)
#define	PRI_MWAIT_EXITING		(1U << 10)
#define	PRI_RDPMC_EXITING		(1U << 11)
#define	PRI_RDTSC_EXITING		(1U << 12)
#define	PRI_CR3_LOAD_EXITING		(1U << 15)
#define	PRI_CR3_STORE_EXITING		(1U << 16)
#define	PRI_CR8_LOAD_EXITING		(1U << 19)
#define	PRI_CR8_STORE_EXITING		(1U << 20)
#define	PRI_TPR_SHADOW			(1U << 21)
#define	PRI_NMI_WINDOW_EXITING		(1U << 22)
#define	PRI_MOV_DR_EXITING		(1U << 23)
#define	PRI_MTF				(1U << 27)
#define	PRI_MONITOR_EXITING		(1U << 29)
#define	PRI_PAUSE_EXITING		(1U << 30)
#define	PRI_SECONDARY_CONTROLS		(1U << 31)

#define	SEC_DESC_TABLE_EXITING		(1U << 2)
#define	SEC_WBINVD_EXITING		(1U << 6)
#define	SEC_PAUSE_LOOP_EXITING		(1U << 10)
#define	SEC_RDRAND_EXITING		(1U << 11)
#define	SEC_ENABLE_INVPCID		(1U << 12)
#define	SEC_RDSEED_EXITING		(1U << 16)
#define	SEC_USER_WAIT_PAUSE		(1U << 26)

#define	EXIT_REASON_BASIC_MASK		0x0000ffffU
#define	EXIT_REASON_RESERVED		0x71ff0000U
#define	EXIT_REASON_UNEXPOSED		0x0a000000U
#define	EXIT_REASON_BUS_LOCK_DETECTED	(1U << 26)
#define	EXIT_REASON_ENTRY_FAILURE	(1U << 31)
#define	INT_INFO_VECTOR_MASK		0x000000ffU
#define	INT_INFO_TYPE_MASK		0x00000700U
#define	INT_INFO_ERROR_VALID		(1U << 11)
#define	INT_INFO_NMI_UNBLOCKING		(1U << 12)
#define	INT_INFO_VALID			(1U << 31)
#define	ENTRY_INFO_OTHER_EVENT		(INT_INFO_VALID | (7U << 8))

static bool
vmx_nested_exception_has_error_code(uint32_t vector)
{

	switch (vector) {
	case 8:		/* #DF */
	case 10:	/* #TS */
	case 11:	/* #NP */
	case 12:	/* #SS */
	case 13:	/* #GP */
	case 14:	/* #PF */
	case 17:	/* #AC */
		return (true);
	default:
		return (false);
	}
}

static int
vmx_nested_event_info_validate(uint32_t info, bool exiting)
{
	uint32_t allowed, type, vector;

	if ((info & INT_INFO_VALID) == 0)
		return (0);
	allowed = INT_INFO_VECTOR_MASK | INT_INFO_TYPE_MASK |
	    INT_INFO_ERROR_VALID | INT_INFO_VALID;
	if (exiting)
		allowed |= INT_INFO_NMI_UNBLOCKING;
	if ((info & ~allowed) != 0)
		return (EINVAL);
	type = (info & INT_INFO_TYPE_MASK) >> 8;
	vector = info & INT_INFO_VECTOR_MASK;
	if (type == 1 || type == 7 || (exiting && type == 4) ||
	    (type == 2 && vector != 2) ||
	    (type == 3 && vector >= 32) ||
	    (type == 5 && vector != 1) ||
	    (type == 6 && vector != 3 && vector != 4) ||
	    (((info & INT_INFO_ERROR_VALID) != 0) !=
	    (type == 3 && vmx_nested_exception_has_error_code(vector))))
		return (EINVAL);
	return (0);
}

int
vmx_nested_exit_information_prepare(
    const struct vmx_nested_exit_information *current,
    const struct vmx_nested_exit_information *hardware,
    struct vmx_nested_exit_information *next)
{
	struct vmx_nested_exit_information candidate;
	uint32_t basic, interruption_type;
	bool failed;

	if (current == NULL || hardware == NULL || next == NULL)
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(next, sizeof(*next), current,
	    sizeof(*current)) ||
	    vmx_nested_state_ranges_overlap(next, sizeof(*next), hardware,
	    sizeof(*hardware)))
		return (EINVAL);
	failed = (hardware->exit_reason & EXIT_REASON_ENTRY_FAILURE) != 0;
	basic = hardware->exit_reason & EXIT_REASON_BASIC_MASK;
	if ((hardware->exit_reason &
	    (EXIT_REASON_RESERVED | EXIT_REASON_UNEXPOSED)) != 0)
		return (EINVAL);
	if (failed) {
		if (hardware->exit_reason !=
		    (EXIT_REASON_ENTRY_FAILURE | basic) ||
		    (basic != 33 && basic != 34 && basic != 41))
			return (EINVAL);
		candidate = *current;
		candidate.exit_reason = hardware->exit_reason;
		candidate.exit_qualification = hardware->exit_qualification;
	} else {
		if (hardware->exit_instruction_length > 15 ||
		    vmx_nested_event_info_validate(
		    hardware->exit_interruption_info, true) != 0 ||
		    vmx_nested_event_info_validate(
		    hardware->idt_vectoring_info, false) != 0)
			return (EINVAL);
		interruption_type = (hardware->exit_interruption_info &
		    INT_INFO_TYPE_MASK) >> 8;
		if (basic == EXIT_REASON_EXCEPTION) {
			if ((hardware->exit_interruption_info &
			    INT_INFO_VALID) == 0 || interruption_type == 0 ||
			    interruption_type == 4)
				return (EINVAL);
		} else if (basic == EXIT_REASON_EXT_INTR) {
			if ((hardware->exit_interruption_info &
			    INT_INFO_VALID) != 0 && interruption_type != 0)
				return (EINVAL);
		} else if ((hardware->exit_interruption_info &
		    INT_INFO_VALID) != 0)
			return (EINVAL);
		candidate = *hardware;
		if ((candidate.exit_interruption_info &
		    INT_INFO_VALID) == 0) {
			candidate.exit_interruption_info = 0;
			candidate.exit_interruption_error = 0;
		}
		if ((candidate.idt_vectoring_info & INT_INFO_VALID) == 0) {
			candidate.idt_vectoring_info = 0;
			candidate.idt_vectoring_error = 0;
		}
		candidate.entry_interruption_info &= ~INT_INFO_VALID;
		candidate.launched = true;
	}
	*next = candidate;
	return (0);
}

static bool
secondary_has(const struct vmx_nested_exit_context *context, uint32_t bit)
{

	return ((context->primary & PRI_SECONDARY_CONTROLS) != 0 &&
	    (context->secondary & bit) != 0);
}

int
vmx_nested_exit_provenance_prepare(
    const struct vmx_nested_exit_information *hardware,
    const struct vmx_nested_exit_provenance *outer,
    struct vmx_nested_exit_provenance *provenance)
{
	struct vmx_nested_exit_provenance candidate;
	uint32_t basic, info, type;

	if (hardware == NULL || outer == NULL || provenance == NULL ||
	    (unsigned int)outer->event_source > VMX_NESTED_EVENT_L1 ||
	    (unsigned int)outer->ept_fault_source > VMX_NESTED_EPT_FAULT_L1 ||
	    (unsigned int)outer->ept_misconfiguration_source >
	    VMX_NESTED_EPT_FAULT_L1 ||
	    (hardware->exit_reason &
	    (EXIT_REASON_RESERVED | EXIT_REASON_UNEXPOSED)) != 0)
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(provenance, sizeof(*provenance),
	    hardware, sizeof(*hardware)) ||
	    vmx_nested_state_ranges_overlap(provenance, sizeof(*provenance),
	    outer, sizeof(*outer)))
		return (EINVAL);

	basic = hardware->exit_reason & EXIT_REASON_BASIC_MASK;
	candidate = *outer;
	if ((hardware->exit_reason & EXIT_REASON_BUS_LOCK_DETECTED) != 0)
		candidate.l0_must_handle = true;

	/*
	 * Raw external interrupts and NMIs are physical L0 events.  An
	 * L1-visible virtual interrupt/NMI exit is synthesized before VMCS02
	 * entry and therefore cannot arrive here as hardware provenance.
	 */
	if (basic == EXIT_REASON_EXT_INTR) {
		if (outer->event_source == VMX_NESTED_EVENT_L1)
			return (EINVAL);
		candidate.event_source = VMX_NESTED_EVENT_L0;
	} else if (basic == EXIT_REASON_EXCEPTION) {
		info = hardware->exit_interruption_info;
		type = (info & INT_INFO_TYPE_MASK) >> 8;
		if ((info & INT_INFO_VALID) != 0 && type == 2) {
			if ((info & INT_INFO_VECTOR_MASK) != 2 ||
			    outer->event_source == VMX_NESTED_EVENT_L1)
				return (EINVAL);
			candidate.event_source = VMX_NESTED_EVENT_L0;
		} else if (outer->event_source != VMX_NESTED_EVENT_NONE) {
			return (EINVAL);
		}
	} else if (outer->event_source != VMX_NESTED_EVENT_NONE) {
		return (EINVAL);
	}

	/*
	 * A hardware EPT exit from the composed shadow does not by itself
	 * identify which translation level failed.  Require the nested walk
	 * or L0 pmap owner to classify it before routing, and reject stale
	 * classifications attached to unrelated exit reasons.
	 */
	if (basic == EXIT_REASON_EPT_FAULT) {
		if (outer->ept_fault_source == VMX_NESTED_EPT_FAULT_NONE ||
		    outer->ept_misconfiguration_source !=
		    VMX_NESTED_EPT_FAULT_NONE)
			return (EINVAL);
	} else if (outer->ept_fault_source !=
	    VMX_NESTED_EPT_FAULT_NONE) {
		return (EINVAL);
	}
	if (basic == EXIT_REASON_EPT_MISCONFIG) {
		if (outer->ept_misconfiguration_source ==
		    VMX_NESTED_EPT_FAULT_NONE ||
		    outer->ept_fault_source !=
		    VMX_NESTED_EPT_FAULT_NONE)
			return (EINVAL);
	} else if (outer->ept_misconfiguration_source !=
	    VMX_NESTED_EPT_FAULT_NONE) {
		return (EINVAL);
	}
	if (basic != EXIT_REASON_VMX_PREEMPT &&
	    outer->l1_timer_expired)
		return (EINVAL);

	/*
	 * These exits are unconditionally owned by L0.  Encode that fact
	 * here so a production caller cannot accidentally omit it while
	 * constructing provenance.
	 */
	switch (basic) {
	case EXIT_REASON_INIT:
	case EXIT_REASON_SIPI:
	case EXIT_REASON_IO_SMI:
	case EXIT_REASON_SMI:
	case EXIT_REASON_MCE_DURING_ENTRY:
	case EXIT_REASON_VMFUNC:
	case EXIT_REASON_PM_LOG_FULL:
	case EXIT_REASON_PCONFIG:
	case EXIT_REASON_SPP_EVENT:
	case EXIT_REASON_LOADIWKEY:
	case EXIT_REASON_ENQCMD_PASID:
	case EXIT_REASON_ENQCMDS_PASID:
	case EXIT_REASON_BUS_LOCK:
	case EXIT_REASON_INSTRUCTION_TIMEOUT:
	case EXIT_REASON_SEAMCALL:
	case EXIT_REASON_TDCALL:
	case EXIT_REASON_RDMSRLIST:
	case EXIT_REASON_WRMSRLIST:
	case EXIT_REASON_URDMSR:
	case EXIT_REASON_UWRMSR:
	case EXIT_REASON_RDMSR_IMM:
	case EXIT_REASON_WRMSR_IMM:
		candidate.l0_must_handle = true;
		break;
	default:
		break;
	}

	*provenance = candidate;
	return (0);
}

int
vmx_nested_outer_exit_prepare(
    const struct vmx_nested_exit_information *hardware,
    const struct vmx_nested_outer_exit_facts *facts,
    enum vmx_nested_outer_exit_dispatch *dispatch,
    struct vmx_nested_exit_provenance *provenance)
{
	struct vmx_nested_exit_provenance candidate, normalized;
	enum vmx_nested_outer_exit_dispatch dispatch_candidate;
	uint32_t basic;
	int error;

	if (hardware == NULL || facts == NULL || dispatch == NULL ||
	    provenance == NULL ||
	    (hardware->exit_reason &
	    (EXIT_REASON_RESERVED | EXIT_REASON_UNEXPOSED)) != 0)
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(dispatch, sizeof(*dispatch),
	    provenance, sizeof(*provenance)) ||
	    vmx_nested_state_ranges_overlap(dispatch, sizeof(*dispatch),
	    hardware, sizeof(*hardware)) ||
	    vmx_nested_state_ranges_overlap(dispatch, sizeof(*dispatch), facts,
	    sizeof(*facts)) ||
	    vmx_nested_state_ranges_overlap(provenance, sizeof(*provenance),
	    hardware, sizeof(*hardware)) ||
	    vmx_nested_state_ranges_overlap(provenance, sizeof(*provenance),
	    facts, sizeof(*facts)))
		return (EINVAL);
	basic = hardware->exit_reason & EXIT_REASON_BASIC_MASK;
	memset(&candidate, 0, sizeof(candidate));
	candidate.l0_must_handle = facts->l0_must_handle;
	dispatch_candidate = VMX_NESTED_OUTER_EXIT_ROUTE;

	switch (basic) {
	case EXIT_REASON_EPT_FAULT:
		if (facts->l1_ept_enabled) {
			/*
			 * The composed root only tells hardware that some
			 * translation is absent.  The frozen EPT transaction
			 * determines whether to populate L0's shadow or reflect
			 * an L1 violation/misconfiguration.
			 */
			dispatch_candidate = VMX_NESTED_OUTER_EXIT_EPT_WALK;
			break;
		}
		candidate.ept_fault_source = VMX_NESTED_EPT_FAULT_L0;
		break;
	case EXIT_REASON_EPT_MISCONFIG:
		/*
		 * L1 entries are interpreted by the software walk before
		 * entering the composed root.  A hardware misconfiguration
		 * therefore belongs to L0's generated root.
		 */
		candidate.ept_misconfiguration_source =
		    VMX_NESTED_EPT_FAULT_L0;
		break;
	case EXIT_REASON_VMX_PREEMPT:
		if (facts->l1_preemption_timer_armed)
			candidate.l1_timer_expired = true;
		else
			candidate.l0_must_handle = true;
		break;
	default:
		break;
	}

	if (dispatch_candidate == VMX_NESTED_OUTER_EXIT_ROUTE) {
		error = vmx_nested_exit_provenance_prepare(hardware,
		    &candidate, &normalized);
		if (error != 0)
			return (error);
		candidate = normalized;
	}
	*dispatch = dispatch_candidate;
	*provenance = candidate;
	return (0);
}

int
vmx_nested_exit_policy_prepare(
    const struct vmx_nested_entry_controls *controls,
    const struct vmx_nested_execution_state *execution,
    const struct vmx_nested_exit_provenance *provenance,
    struct vmx_nested_exit_policy *policy)
{
	struct vmx_nested_exit_policy candidate;

	if (controls == NULL || execution == NULL || provenance == NULL ||
	    policy == NULL ||
	    (unsigned int)provenance->event_source > VMX_NESTED_EVENT_L1 ||
	    (unsigned int)provenance->ept_fault_source >
	    VMX_NESTED_EPT_FAULT_L1 ||
	    (unsigned int)provenance->ept_misconfiguration_source >
	    VMX_NESTED_EPT_FAULT_L1)
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(policy, sizeof(*policy), controls,
	    sizeof(*controls)) ||
	    vmx_nested_state_ranges_overlap(policy, sizeof(*policy), execution,
	    sizeof(*execution)) ||
	    vmx_nested_state_ranges_overlap(policy, sizeof(*policy), provenance,
	    sizeof(*provenance)))
		return (EINVAL);

	memset(&candidate, 0, sizeof(candidate));
	candidate.l0_must_handle = provenance->l0_must_handle;
	/*
	 * Intel requires an MTF exit after VM entry that injects the
	 * vector-zero "other event", irrespective of the MTF execution
	 * control.  This is frozen VMCS12 policy, not caller provenance.
	 */
	candidate.vmcs12_other_event =
	    controls->entry_intr_info == ENTRY_INFO_OTHER_EVENT;
	candidate.l1_timer_expired = provenance->l1_timer_expired;
	candidate.pinbased = controls->pinbased;
	candidate.primary = controls->primary;
	candidate.secondary = controls->secondary;
	candidate.exception_bitmap = execution->exception_bitmap;
	candidate.page_fault_mask = execution->pf_error_mask;
	candidate.page_fault_match = execution->pf_error_match;
	candidate.event_source = provenance->event_source;
	candidate.ept_fault_source = provenance->ept_fault_source;
	candidate.ept_misconfiguration_source =
	    provenance->ept_misconfiguration_source;
	*policy = candidate;
	return (0);
}

int
vmx_nested_exit_context_prepare(
    const struct vmx_nested_exit_information *hardware,
    const struct vmx_nested_exit_policy *policy,
    struct vmx_nested_exit_context *context)
{
	struct vmx_nested_exit_context candidate;
	uint32_t basic, info, type;
	bool failed;

	if (hardware == NULL || policy == NULL || context == NULL ||
	    (unsigned int)policy->event_source > VMX_NESTED_EVENT_L1 ||
	    (unsigned int)policy->ept_fault_source > VMX_NESTED_EPT_FAULT_L1 ||
	    (unsigned int)policy->ept_misconfiguration_source >
	    VMX_NESTED_EPT_FAULT_L1)
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(context, sizeof(*context), hardware,
	    sizeof(*hardware)) ||
	    vmx_nested_state_ranges_overlap(context, sizeof(*context), policy,
	    sizeof(*policy)))
		return (EINVAL);
	if ((hardware->exit_reason &
	    (EXIT_REASON_RESERVED | EXIT_REASON_UNEXPOSED)) != 0)
		return (EINVAL);
	basic = hardware->exit_reason & EXIT_REASON_BASIC_MASK;
	failed = (hardware->exit_reason & EXIT_REASON_ENTRY_FAILURE) != 0;
	if (failed && (hardware->exit_reason !=
	    (EXIT_REASON_ENTRY_FAILURE | basic) ||
	    (basic != EXIT_REASON_INVAL_VMCS &&
	    basic != EXIT_REASON_MSR_LOAD_FAILURE &&
	    basic != EXIT_REASON_MCE_DURING_ENTRY)))
		return (EINVAL);
	if (!failed && (hardware->exit_instruction_length > 15 ||
	    vmx_nested_event_info_validate(hardware->exit_interruption_info,
	    true) != 0 ||
	    vmx_nested_event_info_validate(hardware->idt_vectoring_info,
	    false) != 0))
		return (EINVAL);

	memset(&candidate, 0, sizeof(candidate));
	candidate.reason = basic;
	candidate.entry_failure = failed;
	candidate.l0_must_handle = policy->l0_must_handle;

	if (!failed) {
		candidate.dynamic_l1_intercept =
		    policy->dynamic_l1_intercept;
		candidate.vmcs12_other_event =
		    policy->vmcs12_other_event;
		candidate.l1_timer_expired = policy->l1_timer_expired;
		candidate.pinbased = policy->pinbased;
		candidate.primary = policy->primary;
		candidate.secondary = policy->secondary;
		candidate.exception_bitmap = policy->exception_bitmap;
		candidate.page_fault_mask = policy->page_fault_mask;
		candidate.page_fault_match = policy->page_fault_match;
		candidate.event_source = policy->event_source;
		candidate.ept_fault_source = policy->ept_fault_source;
		candidate.ept_misconfiguration_source =
		    policy->ept_misconfiguration_source;
		info = hardware->exit_interruption_info;
		candidate.interruption_valid = (info & INT_INFO_VALID) != 0;
		candidate.vector = info & INT_INFO_VECTOR_MASK;
		type = (info & INT_INFO_TYPE_MASK) >> 8;
		candidate.interruption_is_nmi = type == 2;
		candidate.page_fault_error =
		    hardware->exit_interruption_error;
		if (basic == EXIT_REASON_EXCEPTION) {
			if (!candidate.interruption_valid || type == 0 ||
			    type == 4)
				return (EINVAL);
		} else if (basic == EXIT_REASON_EXT_INTR) {
			if (candidate.interruption_valid && type != 0)
				return (EINVAL);
		} else if (candidate.interruption_valid) {
			return (EINVAL);
		}
	}
	*context = candidate;
	return (0);
}

int
vmx_nested_dynamic_intercept_prepare(
    const struct vmx_nested_dynamic_exit *exit, bool *intercept)
{
	struct vmx_nested_cr_context cr;
	uint32_t encoding, port;
	uint8_t size;
	bool candidate;
	int error;

	if (exit == NULL || intercept == NULL || exit->controls == NULL ||
	    exit->execution == NULL || exit->io_policy == NULL ||
	    exit->msr_policy == NULL)
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(intercept, sizeof(*intercept), exit,
	    sizeof(*exit)))
		return (EINVAL);
	switch (exit->reason) {
	case EXIT_REASON_CR_ACCESS:
		memset(&cr, 0, sizeof(cr));
		cr.qualification = exit->qualification;
		cr.gpr_value = exit->gpr_value;
		cr.cr0_mask = exit->execution->cr0_mask;
		cr.cr0_shadow = exit->execution->cr0_shadow;
		cr.cr4_mask = exit->execution->cr4_mask;
		cr.cr4_shadow = exit->execution->cr4_shadow;
		memcpy(cr.cr3_target, exit->execution->cr3_target,
		    sizeof(cr.cr3_target));
		cr.primary = exit->controls->primary;
		cr.cr3_target_count = exit->controls->cr3_target_count;
		error = vmx_nested_cr_intercept(&cr, &candidate);
		break;
	case EXIT_REASON_INOUT:
		encoding = exit->qualification & 7;
		if (encoding == 0)
			size = 1;
		else if (encoding == 1)
			size = 2;
		else if (encoding == 3)
			size = 4;
		else
			return (EINVAL);
		port = (exit->qualification >> 16) & 0xffff;
		error = vmx_nested_io_policy_intercept(exit->io_policy, port,
		    size, &candidate);
		break;
	case EXIT_REASON_RDMSR:
	case EXIT_REASON_WRMSR:
		error = vmx_nested_msr_policy_intercept(exit->msr_policy,
		    exit->msr_index, exit->reason == EXIT_REASON_WRMSR,
		    &candidate);
		break;
	case EXIT_REASON_VMREAD:
	case EXIT_REASON_VMWRITE:
		/*
		 * Shadow VMCS controls and their access bitmaps are not
		 * exposed.  These instructions therefore exit to L1
		 * unconditionally whenever L2 executes them.
		 */
		candidate = true;
		error = 0;
		break;
	case EXIT_REASON_APIC_ACCESS:
	case EXIT_REASON_VIRTUALIZED_EOI:
	case EXIT_REASON_APIC_WRITE:
		/*
		 * The corresponding VMCS02 controls and resources are
		 * exclusively derived from VMCS12.  A resulting exit belongs
		 * to L1.
		 */
		candidate = true;
		error = 0;
		break;
	case EXIT_REASON_ENCLS:
	case EXIT_REASON_XSAVES:
	case EXIT_REASON_XRSTORS:
		/* Their optional L1 controls are currently unadvertised. */
		candidate = false;
		error = 0;
		break;
	default:
		return (ENOTSUP);
	}
	if (error != 0)
		return (error);
	*intercept = candidate;
	return (0);
}

bool
vmx_nested_exit_reason_is_dynamic(uint32_t reason)
{

	switch (reason) {
	case EXIT_REASON_CR_ACCESS:
	case EXIT_REASON_INOUT:
	case EXIT_REASON_RDMSR:
	case EXIT_REASON_WRMSR:
	case EXIT_REASON_VMREAD:
	case EXIT_REASON_VMWRITE:
	case EXIT_REASON_APIC_ACCESS:
	case EXIT_REASON_VIRTUALIZED_EOI:
	case EXIT_REASON_APIC_WRITE:
	case EXIT_REASON_ENCLS:
	case EXIT_REASON_XSAVES:
	case EXIT_REASON_XRSTORS:
		return (true);
	default:
		return (false);
	}
}

int
vmx_nested_exit_dispatch_prepare(
    const struct vmx_nested_exit_information *hardware,
    const struct vmx_nested_exit_policy *policy,
    const struct vmx_nested_dynamic_exit *dynamic,
    struct vmx_nested_exit_context *context,
    enum vmx_nested_exit_action *action)
{
	struct vmx_nested_exit_context context_candidate;
	struct vmx_nested_exit_policy policy_candidate;
	enum vmx_nested_exit_action action_candidate;
	bool dynamic_intercept, needs_dynamic;
	int error;

	if (hardware == NULL || policy == NULL || context == NULL ||
	    action == NULL || policy->dynamic_l1_intercept)
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(context, sizeof(*context), action,
	    sizeof(*action)) ||
	    vmx_nested_state_ranges_overlap(context, sizeof(*context), hardware,
	    sizeof(*hardware)) ||
	    vmx_nested_state_ranges_overlap(context, sizeof(*context), policy,
	    sizeof(*policy)) ||
	    vmx_nested_state_ranges_overlap(context, sizeof(*context), dynamic,
	    dynamic == NULL ? 0 : sizeof(*dynamic)) ||
	    vmx_nested_state_ranges_overlap(action, sizeof(*action), hardware,
	    sizeof(*hardware)) ||
	    vmx_nested_state_ranges_overlap(action, sizeof(*action), policy,
	    sizeof(*policy)) ||
	    vmx_nested_state_ranges_overlap(action, sizeof(*action), dynamic,
	    dynamic == NULL ? 0 : sizeof(*dynamic)))
		return (EINVAL);
	policy_candidate = *policy;
	error = vmx_nested_exit_context_prepare(hardware, &policy_candidate,
	    &context_candidate);
	if (error != 0)
		return (error);
	needs_dynamic =
	    vmx_nested_exit_reason_is_dynamic(context_candidate.reason);
	if (needs_dynamic) {
		if (dynamic == NULL ||
		    dynamic->reason != context_candidate.reason ||
		    dynamic->qualification !=
		    hardware->exit_qualification)
			return (EINVAL);
		error = vmx_nested_dynamic_intercept_prepare(dynamic,
		    &dynamic_intercept);
		if (error != 0)
			return (error);
		policy_candidate.dynamic_l1_intercept = dynamic_intercept;
		error = vmx_nested_exit_context_prepare(hardware,
		    &policy_candidate, &context_candidate);
		if (error != 0)
			return (error);
	} else if (dynamic != NULL) {
		return (EINVAL);
	}
	error = vmx_nested_exit_route(&context_candidate, &action_candidate);
	if (error != 0)
		return (error);
	*context = context_candidate;
	*action = action_candidate;
	return (0);
}

int
vmx_nested_cr_intercept(const struct vmx_nested_cr_context *context,
    bool *intercept)
{
	uint64_t value;
	uint32_t access, cr;
	bool candidate;

	if (context == NULL || intercept == NULL ||
	    context->cr3_target_count > 4)
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(intercept, sizeof(*intercept),
	    context, sizeof(*context)))
		return (EINVAL);
	cr = context->qualification & 0xf;
	access = (context->qualification >> 4) & 3;
	candidate = false;
	switch (access) {
	case 0:		/* MOV to CR */
		switch (cr) {
		case 0:
			candidate = (context->cr0_mask &
			    (context->gpr_value ^ context->cr0_shadow)) != 0;
			break;
		case 3:
			if ((context->primary & PRI_CR3_LOAD_EXITING) != 0) {
				candidate = true;
				for (uint32_t i = 0;
				    i < context->cr3_target_count; i++) {
					if (context->gpr_value ==
					    context->cr3_target[i]) {
						candidate = false;
						break;
					}
				}
			}
			break;
		case 4:
			candidate = (context->cr4_mask &
			    (context->gpr_value ^ context->cr4_shadow)) != 0;
			break;
		case 8:
			candidate = (context->primary &
			    PRI_CR8_LOAD_EXITING) != 0;
			break;
		}
		break;
	case 1:		/* MOV from CR */
		if (cr == 3)
			candidate = (context->primary &
			    PRI_CR3_STORE_EXITING) != 0;
		else if (cr == 8)
			candidate = (context->primary &
			    PRI_CR8_STORE_EXITING) != 0;
		break;
	case 2:		/* CLTS */
		if (cr != 0)
			return (EINVAL);
		candidate = (context->cr0_mask & context->cr0_shadow &
		    (1U << 3)) != 0;
		break;
	case 3:		/* LMSW */
		if (cr != 0)
			return (EINVAL);
		value = (context->qualification >> 16) & 0xf;
		candidate = (context->cr0_mask & 0xe &
		    (value ^ context->cr0_shadow)) != 0;
		if ((context->cr0_mask & 1) != 0 &&
		    (context->cr0_shadow & 1) == 0 && (value & 1) != 0)
			candidate = true;
		break;
	}
	*intercept = candidate;
	return (0);
}

int
vmx_nested_exit_route(const struct vmx_nested_exit_context *context,
    enum vmx_nested_exit_action *action)
{
	enum vmx_nested_exit_action candidate;
	bool reflect;

	if (context == NULL || action == NULL ||
	    (unsigned int)context->event_source > VMX_NESTED_EVENT_L1 ||
	    (unsigned int)context->ept_fault_source >
	    VMX_NESTED_EPT_FAULT_L1 ||
	    (unsigned int)context->ept_misconfiguration_source >
	    VMX_NESTED_EPT_FAULT_L1)
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(action, sizeof(*action), context,
	    sizeof(*context)))
		return (EINVAL);
	if (context->entry_failure !=
	    (context->reason == EXIT_REASON_INVAL_VMCS ||
	    context->reason == EXIT_REASON_MSR_LOAD_FAILURE ||
	    context->reason == EXIT_REASON_MCE_DURING_ENTRY))
		return (EINVAL);
	if (context->l0_must_handle) {
		*action = VMX_NESTED_EXIT_HANDLE_L0;
		return (0);
	}

	reflect = false;
	switch (context->reason) {
	case EXIT_REASON_EXCEPTION:
		if (!context->interruption_valid || context->vector >= 32)
			return (EINVAL);
		if (context->interruption_is_nmi) {
			if (context->vector != 2 ||
			    context->event_source != VMX_NESTED_EVENT_L0)
				return (EINVAL);
			/*
			 * A hardware NMI exit is owned by L0.  An L1-visible
			 * NMI exit is synthesized from pending virtual-NMI
			 * state before entry by vmx_nested_event_plan().
			 */
			candidate = VMX_NESTED_EXIT_HANDLE_L0;
			goto done;
		}
		reflect = (context->exception_bitmap &
		    (1U << context->vector)) != 0;
		if (context->vector == 14 &&
		    (context->page_fault_error & context->page_fault_mask) !=
		    context->page_fault_match)
			reflect = !reflect;
		break;
	case EXIT_REASON_EXT_INTR:
		if (context->event_source != VMX_NESTED_EVENT_L0)
			return (EINVAL);
		/*
		 * Raw host interrupts always run L0 handling first.  L1-visible
		 * external-interrupt exits are synthesized from virtual IRQ
		 * state (including acknowledge-on-exit) before entering L2.
		 */
		candidate = VMX_NESTED_EXIT_HANDLE_L0;
		goto done;
	case EXIT_REASON_INIT:
	case EXIT_REASON_SIPI:
	case EXIT_REASON_IO_SMI:
	case EXIT_REASON_SMI:
	case EXIT_REASON_MCE_DURING_ENTRY:
	case EXIT_REASON_VMFUNC:	/* software-emulated by L0 */
	case EXIT_REASON_PM_LOG_FULL: /* software-emulated by L0 */
	case EXIT_REASON_PCONFIG:	/* control not exposed to L1 */
	case EXIT_REASON_SPP_EVENT:	/* control not exposed to L1 */
	case EXIT_REASON_LOADIWKEY:	/* control not exposed to L1 */
	case EXIT_REASON_ENQCMD_PASID:	/* PASID translation is L0-owned */
	case EXIT_REASON_ENQCMDS_PASID:
	case EXIT_REASON_BUS_LOCK:	/* not exposed to L1 */
	case EXIT_REASON_INSTRUCTION_TIMEOUT: /* not exposed to L1 */
	case EXIT_REASON_SEAMCALL:	/* TDX is not exposed to L1 */
	case EXIT_REASON_TDCALL:
	case EXIT_REASON_RDMSRLIST:	/* instruction control unexposed */
	case EXIT_REASON_WRMSRLIST:
	case EXIT_REASON_URDMSR:	/* user-interrupt state unexposed */
	case EXIT_REASON_UWRMSR:
	case EXIT_REASON_RDMSR_IMM:	/* MSR_IMM is not exposed to L1 */
	case EXIT_REASON_WRMSR_IMM:
		candidate = VMX_NESTED_EXIT_HANDLE_L0;
		goto done;
	case EXIT_REASON_TRIPLE_FAULT:
	case EXIT_REASON_TASK_SWITCH:
	case EXIT_REASON_CPUID:
	case EXIT_REASON_GETSEC:
	case EXIT_REASON_INVD:
	case EXIT_REASON_RSM:
	case EXIT_REASON_VMCALL:
	case EXIT_REASON_VMCLEAR:
	case EXIT_REASON_VMLAUNCH:
	case EXIT_REASON_VMPTRLD:
	case EXIT_REASON_VMPTRST:
	case EXIT_REASON_VMRESUME:
	case EXIT_REASON_VMXOFF:
	case EXIT_REASON_VMXON:
	case EXIT_REASON_INVAL_VMCS:
	case EXIT_REASON_MSR_LOAD_FAILURE:
	case EXIT_REASON_INVEPT:
	case EXIT_REASON_INVVPID:
	case EXIT_REASON_XSETBV:
		reflect = true;
		break;
	case EXIT_REASON_INTR_WINDOW:
		reflect = (context->primary & PRI_INTR_WINDOW_EXITING) != 0;
		break;
	case EXIT_REASON_NMI_WINDOW:
		reflect = (context->primary & PRI_NMI_WINDOW_EXITING) != 0;
		break;
	case EXIT_REASON_HLT:
		reflect = (context->primary & PRI_HLT_EXITING) != 0;
		break;
	case EXIT_REASON_INVLPG:
		reflect = (context->primary & PRI_INVLPG_EXITING) != 0;
		break;
	case EXIT_REASON_RDPMC:
		reflect = (context->primary & PRI_RDPMC_EXITING) != 0;
		break;
	case EXIT_REASON_RDTSC:
	case EXIT_REASON_RDTSCP:
		reflect = (context->primary & PRI_RDTSC_EXITING) != 0;
		break;
	case EXIT_REASON_CR_ACCESS:
	case EXIT_REASON_INOUT:
	case EXIT_REASON_RDMSR:
	case EXIT_REASON_WRMSR:
	case EXIT_REASON_VMREAD:
	case EXIT_REASON_VMWRITE:
	case EXIT_REASON_APIC_ACCESS:
	case EXIT_REASON_VIRTUALIZED_EOI:
	case EXIT_REASON_APIC_WRITE:
	case EXIT_REASON_ENCLS:
	case EXIT_REASON_XSAVES:
	case EXIT_REASON_XRSTORS:
		reflect = context->dynamic_l1_intercept;
		break;
	case EXIT_REASON_DR_ACCESS:
		reflect = (context->primary & PRI_MOV_DR_EXITING) != 0;
		break;
	case EXIT_REASON_MWAIT:
		reflect = (context->primary & PRI_MWAIT_EXITING) != 0;
		break;
	case EXIT_REASON_MTF:
		reflect = (context->primary & PRI_MTF) != 0 ||
		    context->vmcs12_other_event;
		break;
	case EXIT_REASON_MONITOR:
		reflect = (context->primary & PRI_MONITOR_EXITING) != 0;
		break;
	case EXIT_REASON_PAUSE:
		reflect = (context->primary & PRI_PAUSE_EXITING) != 0 ||
		    secondary_has(context, SEC_PAUSE_LOOP_EXITING);
		break;
	case EXIT_REASON_TPR:
		reflect = (context->primary & PRI_TPR_SHADOW) != 0;
		break;
	case EXIT_REASON_GDTR_IDTR:
	case EXIT_REASON_LDTR_TR:
		reflect = secondary_has(context, SEC_DESC_TABLE_EXITING);
		break;
	case EXIT_REASON_EPT_FAULT:
		if (context->ept_fault_source == VMX_NESTED_EPT_FAULT_NONE)
			return (EINVAL);
		reflect = context->ept_fault_source ==
		    VMX_NESTED_EPT_FAULT_L1;
		break;
	case EXIT_REASON_EPT_MISCONFIG:
		if (context->ept_misconfiguration_source ==
		    VMX_NESTED_EPT_FAULT_NONE)
			return (EINVAL);
		reflect = context->ept_misconfiguration_source ==
		    VMX_NESTED_EPT_FAULT_L1;
		break;
	case EXIT_REASON_VMX_PREEMPT:
		candidate = context->l1_timer_expired ?
		    VMX_NESTED_EXIT_HANDLE_L0_THEN_REFLECT_L1 :
		    VMX_NESTED_EXIT_HANDLE_L0;
		goto done;
	case EXIT_REASON_WBINVD:
		reflect = secondary_has(context, SEC_WBINVD_EXITING);
		break;
	case EXIT_REASON_RDRAND:
		reflect = secondary_has(context, SEC_RDRAND_EXITING);
		break;
	case EXIT_REASON_INVPCID:
		reflect = secondary_has(context, SEC_ENABLE_INVPCID) &&
		    (context->primary & PRI_INVLPG_EXITING) != 0;
		break;
	case EXIT_REASON_RDSEED:
		reflect = secondary_has(context, SEC_RDSEED_EXITING);
		break;
	case EXIT_REASON_UMWAIT:
	case EXIT_REASON_TPAUSE:
		/*
		 * Intel defines these exit reasons only when both controls are
		 * active.  Keep the conjunction explicit: treating the secondary
		 * control alone as sufficient would expose an exit to L1 that its
		 * VMCS12 did not request.
		 */
		reflect = secondary_has(context, SEC_USER_WAIT_PAUSE) &&
		    (context->primary & PRI_RDTSC_EXITING) != 0;
		break;
	default:
		/*
		 * Intel reserves the remaining 16-bit basic-reason space for
		 * future processors.  An unknown true exit must stay with L0;
		 * reflecting it would expose a facility absent from VMCS12, while
		 * failing this router would prevent the ordinary VMM exit path from
		 * applying its own forward-compatibility policy.
		 */
		candidate = VMX_NESTED_EXIT_HANDLE_L0;
		goto done;
	}
	candidate = reflect ? VMX_NESTED_EXIT_REFLECT_L1 :
	    VMX_NESTED_EXIT_HANDLE_L0;
done:
	*action = candidate;
	return (0);
}
