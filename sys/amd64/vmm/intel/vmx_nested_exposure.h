/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_EXPOSURE_H_
#define	_VMM_INTEL_VMX_NESTED_EXPOSURE_H_

#include "vmx_nested_types.h"

#define	VMX_NESTED_STAGE_CAPABILITY_POLICY	(1U << 0)
#define	VMX_NESTED_STAGE_VMCS_STORE		(1U << 1)
#define	VMX_NESTED_STAGE_INSTRUCTION_RESULTS	(1U << 2)
#define	VMX_NESTED_STAGE_INSTRUCTION_DECODE	(1U << 3)
#define	VMX_NESTED_STAGE_ENTRY_CONTROLS		(1U << 4)
#define	VMX_NESTED_STAGE_HOST_STATE		(1U << 5)
#define	VMX_NESTED_STAGE_GUEST_STATE		(1U << 6)
#define	VMX_NESTED_STAGE_VMCS02			(1U << 7)
#define	VMX_NESTED_STAGE_EXIT_REFLECTION	(1U << 8)
#define	VMX_NESTED_STAGE_EPT_INVEPT		(1U << 9)
#define	VMX_NESTED_STAGE_INTERRUPTS		(1U << 10)
#define	VMX_NESTED_STAGE_CHECKPOINT		(1U << 11)
/*
 * VMCS02 construction is not by itself enough to expose VMX.  Architectural
 * exposure also requires one complete run-loop transaction that settles a
 * deferred common startup owner only after the matching cold, resumed, or
 * hot VMCS02 inverse has made CPU-local residency safe.
 */
#define	VMX_NESTED_STAGE_ENTRY_TRANSACTION	(1U << 12)

#define	VMX_NESTED_EXPOSURE_REQUIRED		\
	(VMX_NESTED_STAGE_CAPABILITY_POLICY |	\
	 VMX_NESTED_STAGE_VMCS_STORE |		\
	 VMX_NESTED_STAGE_INSTRUCTION_RESULTS |	\
	 VMX_NESTED_STAGE_INSTRUCTION_DECODE |	\
	 VMX_NESTED_STAGE_ENTRY_CONTROLS |	\
	 VMX_NESTED_STAGE_HOST_STATE |		\
	 VMX_NESTED_STAGE_GUEST_STATE |		\
	 VMX_NESTED_STAGE_VMCS02 |		\
	 VMX_NESTED_STAGE_EXIT_REFLECTION |	\
	 VMX_NESTED_STAGE_EPT_INVEPT |		\
	 VMX_NESTED_STAGE_INTERRUPTS |		\
	 VMX_NESTED_STAGE_CHECKPOINT |		\
	 VMX_NESTED_STAGE_ENTRY_TRANSACTION)

#define	VMX_NESTED_EXPOSURE_ENABLED		0x1U
#define	VMX_NESTED_EXPOSURE_LOCKED		0x2U
#define	VMX_NESTED_EXPOSURE_STATE_MASK		\
	(VMX_NESTED_EXPOSURE_ENABLED | VMX_NESTED_EXPOSURE_LOCKED)

#define	VMX_NESTED_EXPOSURE_SNAPSHOT_HEADER_SIZE	16U

struct vmx_nested_capabilities;
struct vmx_nested_state_view;

uint32_t vmx_nested_implementation_stages(void);
int	vmx_nested_exposure_snapshot_header_decode(const uint8_t *, size_t,
	    bool *);
int	vmx_nested_exposure_snapshot_header_encode(bool, uint8_t *, size_t);
int	vmx_nested_exposure_configure(uint32_t, bool, uint32_t *);
int	vmx_nested_exposure_lock(uint32_t, uint32_t *);
int	vmx_nested_exposure_validate(
	    const struct vmx_nested_capabilities *);
int	vmx_nested_exposure_policy_validate(
	    const struct vmx_nested_capabilities *, bool);
int	vmx_nested_exposure_restore_validate(
	    const struct vmx_nested_capabilities *,
	    const struct vmx_nested_state_view *, bool);
int	vmx_nested_exposure_snapshot_validate(
	    const struct vmx_nested_capabilities *, bool, bool, bool);
int	vmx_nested_exposure_registry_validate(bool, uint32_t);

#endif /* _VMM_INTEL_VMX_NESTED_EXPOSURE_H_ */
