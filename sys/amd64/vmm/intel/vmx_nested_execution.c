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

#include "vmx_nested_execution.h"
#include "vmx_nested_state_range.h"

#define	NVMX_EXCEPTION_PAGE_FAULT	(UINT32_C(1) << 14)

static bool
nvmx_cr3_target_present(const uint64_t *target, uint32_t count,
    uint64_t value)
{

	for (uint32_t i = 0; i < count; i++) {
		if (target[i] == value)
			return (true);
	}
	return (false);
}

static void
nvmx_cr3_target_add(struct vmx_nested_execution_plan *plan, uint64_t value)
{

	if (nvmx_cr3_target_present(plan->state.cr3_target,
	    plan->cr3_target_count, value))
		return;
	plan->state.cr3_target[plan->cr3_target_count++] = value;
}

int
vmx_nested_execution_compose(
    const struct vmx_nested_execution_compose_input *input,
    struct vmx_nested_execution_plan *plan)
{
	struct vmx_nested_execution_plan candidate;
	const struct vmx_nested_execution_state *l0, *l1;
	bool l0_pf, l1_pf;

	if (input == NULL || plan == NULL || input->l0 == NULL ||
	    input->l1 == NULL || input->l0_cr3_target_count > 4 ||
	    input->l1_cr3_target_count > 4)
		return (EINVAL);
	if (vmx_nested_state_ranges_overlap(plan, sizeof(*plan), input,
	    sizeof(*input)) ||
	    vmx_nested_state_ranges_overlap(plan, sizeof(*plan), input->l0,
	    sizeof(*input->l0)) ||
	    vmx_nested_state_ranges_overlap(plan, sizeof(*plan), input->l1,
	    sizeof(*input->l1)))
		return (EINVAL);
	l0 = input->l0;
	l1 = input->l1;
	memset(&candidate, 0, sizeof(candidate));
	candidate.l0 = *l0;
	candidate.l1 = *l1;
	candidate.l0_cr3_target_count = input->l0_cr3_target_count;
	candidate.l1_cr3_target_count = input->l1_cr3_target_count;
	candidate.l0_cr3_load_exiting = input->l0_cr3_load_exiting;
	candidate.l1_cr3_load_exiting = input->l1_cr3_load_exiting;
	candidate.l0_ple_enabled = input->l0_ple_enabled;
	candidate.l1_ple_enabled = input->l1_ple_enabled;

	candidate.state.exception_bitmap =
	    l0->exception_bitmap | l1->exception_bitmap;
	l0_pf = (l0->exception_bitmap & NVMX_EXCEPTION_PAGE_FAULT) != 0;
	l1_pf = (l1->exception_bitmap & NVMX_EXCEPTION_PAGE_FAULT) != 0;
	if (l0_pf && l1_pf &&
	    (l0->pf_error_mask != l1->pf_error_mask ||
	    l0->pf_error_match != l1->pf_error_match)) {
		/*
		 * One hardware mask/match pair cannot generally represent the
		 * union of two predicates.  Exit on every #PF and evaluate
		 * both original predicates in the L0 exit router.
		 */
		candidate.state.pf_error_mask = 0;
		candidate.state.pf_error_match = 0;
		candidate.page_fault_software_filter = true;
	} else if (l1_pf) {
		candidate.state.pf_error_mask = l1->pf_error_mask;
		candidate.state.pf_error_match = l1->pf_error_match;
	} else if (l0_pf) {
		candidate.state.pf_error_mask = l0->pf_error_mask;
		candidate.state.pf_error_match = l0->pf_error_match;
	}

	candidate.state.cr0_mask = l0->cr0_mask | l1->cr0_mask;
	/*
	 * L0 masks only bits that hardware must force to its VMX fixed-bit
	 * policy.  On an overlapping bit, L1's shadow is the architectural
	 * value visible to L2 and therefore controls whether L1 requested an
	 * exit.  VMCS02's guest CR value independently retains L0's forced
	 * hardware value.  A write that differs from L1's shadow exits and is
	 * routed using the preserved per-level policy below.
	 */
	candidate.state.cr0_shadow =
	    (l0->cr0_shadow & (l0->cr0_mask & ~l1->cr0_mask)) |
	    (l1->cr0_shadow & l1->cr0_mask);
	candidate.state.cr4_mask = l0->cr4_mask | l1->cr4_mask;
	candidate.state.cr4_shadow =
	    (l0->cr4_shadow & (l0->cr4_mask & ~l1->cr4_mask)) |
	    (l1->cr4_shadow & l1->cr4_mask);

	if (input->l0_cr3_load_exiting && input->l1_cr3_load_exiting) {
		for (uint32_t i = 0; i < input->l1_cr3_target_count; i++) {
			if (nvmx_cr3_target_present(l0->cr3_target,
			    input->l0_cr3_target_count, l1->cr3_target[i]))
				nvmx_cr3_target_add(&candidate,
				    l1->cr3_target[i]);
		}
	} else if (input->l0_cr3_load_exiting) {
		for (uint32_t i = 0; i < input->l0_cr3_target_count; i++)
			nvmx_cr3_target_add(&candidate, l0->cr3_target[i]);
	} else if (input->l1_cr3_load_exiting) {
		for (uint32_t i = 0; i < input->l1_cr3_target_count; i++)
			nvmx_cr3_target_add(&candidate, l1->cr3_target[i]);
	}

	for (unsigned int i = 0; i < nitems(candidate.state.eoi_exit_bitmap);
	    i++)
		candidate.state.eoi_exit_bitmap[i] =
		    l0->eoi_exit_bitmap[i] | l1->eoi_exit_bitmap[i];
	candidate.state.guest_intr_status = l1->guest_intr_status;
	if (input->l0_ple_enabled && input->l1_ple_enabled) {
		if (l0->ple_gap != l1->ple_gap ||
		    l0->ple_window != l1->ple_window)
			return (ENOTSUP);
		candidate.state.ple_gap = l1->ple_gap;
		candidate.state.ple_window = l1->ple_window;
	} else if (input->l0_ple_enabled) {
		candidate.state.ple_gap = l0->ple_gap;
		candidate.state.ple_window = l0->ple_window;
	} else if (input->l1_ple_enabled) {
		candidate.state.ple_gap = l1->ple_gap;
		candidate.state.ple_window = l1->ple_window;
	}
	*plan = candidate;
	return (0);
}
