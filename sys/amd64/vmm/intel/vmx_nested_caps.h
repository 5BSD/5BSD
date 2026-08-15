/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_CAPS_H_
#define	_VMM_INTEL_VMX_NESTED_CAPS_H_

#include "vmx_nested_types.h"

#define	VMX_NESTED_CAP_F_TRUE_CONTROLS	0x0001U
#define	VMX_NESTED_CAP_F_REGION_32BIT	0x0002U
#define	VMX_NESTED_CAP_F_GUEST_RTM	0x0004U
#define	VMX_NESTED_CAPABILITIES_WIRE_SIZE	128U

/*
 * Intel VMXON and VMCS regions are architectural 4 KiB objects.  This is a
 * guest-visible VMX capability, not a host VM-page property.
 */
#define	VMX_NESTED_VMCS_REGION_SHIFT	12U
#define	VMX_NESTED_VMCS_REGION_SIZE	(1U << VMX_NESTED_VMCS_REGION_SHIFT)

_Static_assert((1U << VMX_NESTED_VMCS_REGION_SHIFT) ==
    VMX_NESTED_VMCS_REGION_SIZE,
    "nested VMCS region must remain an architectural 4 KiB unit");

/* Non-VMX guest feature policy which affects architectural VMCS checks. */
#define	VMX_NESTED_GUEST_F_RTM		0x00000001U
#define	VMX_NESTED_GUEST_F_ALL		VMX_NESTED_GUEST_F_RTM

/* Host policy inputs which deliberately extend the nested guest ABI. */
#define	VMX_NESTED_POLICY_F_QUALIFY_VPID	0x00000001U
#define	VMX_NESTED_POLICY_F_ALL		VMX_NESTED_POLICY_F_QUALIFY_VPID

/*
 * This revision identifies bhyve's software VMCS12 schema, not the current
 * processor's hardware VMCS revision.  Keeping the two identities separate
 * is required for migration between compatible Intel processors.
 */
#define	VMX_NESTED_VIRTUAL_REVISION_ID	0x42564859U

/*
 * Guest-visible VMX capability policy.  These are virtual architectural
 * capabilities, not a copy of the host MSRs.  Each control capability uses
 * the Intel MSR form: required-one bits in the low word and allowed-one bits
 * in the high word.
 */
struct vmx_nested_capabilities {
	uint32_t revision_id;
	uint32_t vmcs_region_size;
	uint8_t physical_address_width;
	uint8_t vmcs_memory_type;
	uint16_t flags;
	uint8_t linear_address_width;
	uint64_t pinbased;
	uint64_t primary;
	uint64_t secondary;
	uint64_t vmexit;
	uint64_t vmentry;
	uint64_t cr0_fixed0;
	uint64_t cr0_fixed1;
	uint64_t cr4_fixed0;
	uint64_t cr4_fixed1;
	uint64_t ept_vpid;
	uint64_t misc;
	uint64_t vmcs_enum;
	uint64_t vmfunc;
	uint64_t debugctl_allowed;
};

struct vmx_nested_capability_policy_input {
	uint8_t physical_address_width;
	uint8_t linear_address_width;
	uint32_t policy_flags;
	uint32_t guest_features;
	uint64_t pinbased;
	uint64_t primary;
	uint64_t secondary;
	uint64_t vmexit;
	uint64_t vmentry;
	uint64_t cr0_fixed0;
	uint64_t cr0_fixed1;
	uint64_t cr4_fixed0;
	uint64_t cr4_fixed1;
	uint64_t ept_vpid;
	uint64_t misc;
	uint64_t debugctl_allowed;
};

int	vmx_nested_capabilities_validate(
	    const struct vmx_nested_capabilities *);
int	vmx_nested_capabilities_build(
	    const struct vmx_nested_capability_policy_input *,
	    struct vmx_nested_capabilities *);
int	vmx_nested_capabilities_limit_physical_width(uint8_t, uint64_t,
	    uint8_t *);
bool	vmx_nested_capabilities_equal(
	    const struct vmx_nested_capabilities *,
	    const struct vmx_nested_capabilities *);
bool	vmx_nested_control_valid(uint32_t, uint64_t);
uint32_t vmx_nested_control_adjust(uint32_t, uint64_t);
bool	vmx_nested_region_gpa_valid(
	    const struct vmx_nested_capabilities *, uint64_t);
bool	vmx_nested_revision_valid(
	    const struct vmx_nested_capabilities *, uint32_t, bool);
int	vmx_nested_capabilities_signature(
	    const struct vmx_nested_capabilities *, uint64_t *);
int	vmx_nested_capabilities_wire_encode(
	    const struct vmx_nested_capabilities *, void *, size_t);
int	vmx_nested_capabilities_wire_decode(
	    const void *, size_t, struct vmx_nested_capabilities *);
int	vmx_nested_capability_read_msr(
	    const struct vmx_nested_capabilities *, uint32_t, uint64_t *);

#endif /* _VMM_INTEL_VMX_NESTED_CAPS_H_ */
