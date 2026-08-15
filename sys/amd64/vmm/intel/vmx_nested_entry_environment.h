/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_ENTRY_ENVIRONMENT_H_
#define	_VMM_INTEL_VMX_NESTED_ENTRY_ENVIRONMENT_H_

#include "vmx_nested_types.h"

#include "vmx_nested_compose.h"
#include "vmx_nested_entry.h"
#include "vmx_nested_invalidate.h"
#include "vmx_nested_runtime.h"
#include "vmx_nested_tsc.h"
#include "vmx_nested_vmcs12.h"
#include "vmx_nested_vmcs02.h"

/*
 * A coherent, value-only capture of the L0/L1 environment used to compose
 * one VMCS02 entry.  It is runtime state, not a checkpoint format.  In
 * particular, it contains no VMCS pointer, host virtual address, callback,
 * or externally owned storage.
 */
struct vmx_nested_entry_environment_input {
	struct vmx_nested_vmcs02_id id;
	const struct vmx_nested_vmcs02_capabilities *virtual_controls;
	const struct vmx_nested_vmcs02_capabilities *hardware_controls;
	const struct vmx_nested_vmcs02_policy *control_policy;
	const struct vmx_nested_vmcs02_controls *l0_controls;
	const struct vmx_nested_execution_state *l0_execution;
	const struct vmx_nested_host_state *l0_host;
	const struct vmx_nested_l1_runtime_state *l1_runtime;
	const struct vmx_nested_tsc_scale_input *tsc;
	const struct vmx_nested_vpid_transition *vpid;
	uint64_t capability_signature;
	uint64_t l1_virtual_tsc;
	uint32_t preemption_timer_value;
	uint32_t l0_cr3_target_count;
	uint8_t preemption_timer_rate;
	bool preemption_timer_enabled;
};

struct vmx_nested_entry_environment {
	struct vmx_nested_vmcs02_id id;
	struct vmx_nested_vmcs02_capabilities virtual_controls;
	struct vmx_nested_vmcs02_capabilities hardware_controls;
	struct vmx_nested_vmcs02_policy control_policy;
	struct vmx_nested_vmcs02_controls l0_controls;
	struct vmx_nested_execution_state l0_execution;
	struct vmx_nested_host_state l0_host;
	struct vmx_nested_l1_runtime_state l1_runtime;
	struct vmx_nested_tsc_scale_input tsc;
	struct vmx_nested_vpid_transition vpid;
	uint64_t capability_signature;
	uint64_t l1_virtual_tsc;
	uint32_t preemption_timer_value;
	uint32_t l0_cr3_target_count;
	uint8_t preemption_timer_rate;
	bool preemption_timer_enabled;
};

/*
 * Semantic capture fields.  Architecture-specific adapters map these to
 * hardware VMCS encodings or to software-owned state as appropriate.
 */
enum vmx_nested_entry_environment_field {
	VMX_NESTED_ENV_PINBASED = 0,
	VMX_NESTED_ENV_PRIMARY,
	VMX_NESTED_ENV_SECONDARY,
	VMX_NESTED_ENV_VMEXIT,
	VMX_NESTED_ENV_VMENTRY,
	VMX_NESTED_ENV_EXCEPTION_BITMAP,
	VMX_NESTED_ENV_PF_ERROR_MASK,
	VMX_NESTED_ENV_PF_ERROR_MATCH,
	VMX_NESTED_ENV_CR0_MASK,
	VMX_NESTED_ENV_CR0_SHADOW,
	VMX_NESTED_ENV_CR4_MASK,
	VMX_NESTED_ENV_CR4_SHADOW,
	VMX_NESTED_ENV_CR3_TARGET_COUNT,
	VMX_NESTED_ENV_CR3_TARGET0,
	VMX_NESTED_ENV_CR3_TARGET1,
	VMX_NESTED_ENV_CR3_TARGET2,
	VMX_NESTED_ENV_CR3_TARGET3,
	VMX_NESTED_ENV_EOI_EXIT0,
	VMX_NESTED_ENV_EOI_EXIT1,
	VMX_NESTED_ENV_EOI_EXIT2,
	VMX_NESTED_ENV_EOI_EXIT3,
	VMX_NESTED_ENV_PLE_GAP,
	VMX_NESTED_ENV_PLE_WINDOW,
	VMX_NESTED_ENV_GUEST_INTR_STATUS,
	VMX_NESTED_ENV_L1_DR7,
	VMX_NESTED_ENV_L1_DEBUGCTL,
	VMX_NESTED_ENV_L1_PAT,
	VMX_NESTED_ENV_L1_EFER,
	VMX_NESTED_ENV_L0_HOST_CR0,
	VMX_NESTED_ENV_L0_HOST_CR3,
	VMX_NESTED_ENV_L0_HOST_CR4,
	VMX_NESTED_ENV_L0_HOST_FS_BASE,
	VMX_NESTED_ENV_L0_HOST_GS_BASE,
	VMX_NESTED_ENV_L0_HOST_TR_BASE,
	VMX_NESTED_ENV_L0_HOST_GDTR_BASE,
	VMX_NESTED_ENV_L0_HOST_IDTR_BASE,
	VMX_NESTED_ENV_L0_HOST_SYSENTER_CS,
	VMX_NESTED_ENV_L0_HOST_SYSENTER_ESP,
	VMX_NESTED_ENV_L0_HOST_SYSENTER_EIP,
	VMX_NESTED_ENV_L0_HOST_RSP,
	VMX_NESTED_ENV_L0_HOST_RIP,
	VMX_NESTED_ENV_L0_HOST_PAT,
	VMX_NESTED_ENV_L0_HOST_EFER,
	VMX_NESTED_ENV_L0_HOST_ES_SELECTOR,
	VMX_NESTED_ENV_L0_HOST_CS_SELECTOR,
	VMX_NESTED_ENV_L0_HOST_SS_SELECTOR,
	VMX_NESTED_ENV_L0_HOST_DS_SELECTOR,
	VMX_NESTED_ENV_L0_HOST_FS_SELECTOR,
	VMX_NESTED_ENV_L0_HOST_GS_SELECTOR,
	VMX_NESTED_ENV_L0_HOST_TR_SELECTOR,
	VMX_NESTED_ENV_L0_TSC_OFFSET,
	VMX_NESTED_ENV_L0_TSC_MULTIPLIER,
	VMX_NESTED_ENV_HOST_TSC,
	VMX_NESTED_ENV_FIELD_COUNT
};

struct vmx_nested_entry_environment_capture_ops {
	int (*read)(void *, enum vmx_nested_entry_environment_field,
	    uint64_t *);
};

struct vmx_nested_entry_environment_capture {
	struct vmx_nested_vmcs02_id id;
	struct vmx_nested_vmcs02_capabilities virtual_controls;
	struct vmx_nested_vmcs02_capabilities hardware_controls;
	struct vmx_nested_vmcs02_policy control_policy;
	struct vmx_nested_tsc_scale_input tsc;
	struct vmx_nested_vpid_transition vpid;
	uint64_t capability_signature;
	uint32_t preemption_timer_value;
	uint8_t preemption_timer_rate;
	bool preemption_timer_enabled;
};

int	vmx_nested_entry_environment_prepare(
	    const struct vmx_nested_entry_environment_input *,
	    struct vmx_nested_entry_environment *);
int	vmx_nested_entry_environment_capture_validate(
	    const struct vmx_nested_entry_environment_capture *);
int	vmx_nested_entry_environment_from_vmcs12(
	    const struct vmx_nested_vmcs12_snapshot *,
	    const struct vmx_nested_vmcs02_id *,
	    const struct vmx_nested_vmcs02_capabilities *, uint16_t, uint16_t,
	    bool, struct vmx_nested_entry_environment_capture *);
int	vmx_nested_entry_environment_capture(
	    const struct vmx_nested_entry_environment_capture *,
	    const struct vmx_nested_entry_environment_capture_ops *, void *,
	    struct vmx_nested_entry_environment *);
int	vmx_nested_entry_environment_validate(
	    const struct vmx_nested_entry_environment *);
/*
 * The returned pointer-bearing input is a synchronous view.  It remains
 * valid only while environment and vmentry remain alive and unmodified.
 */
int	vmx_nested_entry_environment_bind(
	    const struct vmx_nested_entry_environment *,
	    const struct vmx_nested_vmcs02_id *,
	    const struct vmx_nested_capabilities *,
	    const struct vmx_nested_vmentry_input *,
	    struct vmx_nested_vmcs02_input *);

#endif /* _VMM_INTEL_VMX_NESTED_ENTRY_ENVIRONMENT_H_ */
