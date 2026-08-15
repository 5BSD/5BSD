/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/endian.h>
#include <sys/errno.h>
#include <sys/types.h>

#ifndef _KERNEL
#include <stdint.h>
#include <string.h>
#else
#include <sys/systm.h>
#endif

#include "vmx_nested_caps.h"
#include "vmx_nested_state_range.h"
#include "vmx_nested_vmcs.h"

#define	VMX_PRIMARY_ACTIVATE_SECONDARY	(UINT32_C(1) << 31)
#define	VMX_PRIMARY_ACTIVATE_TERTIARY	(UINT32_C(1) << 17)
#define	VMX_PRIMARY_MONITOR_TRAP_FLAG	(UINT32_C(1) << 27)
#define	VMX_SECONDARY_ENABLE_EPT	(UINT32_C(1) << 1)
#define	VMX_SECONDARY_ENABLE_VPID	(UINT32_C(1) << 5)
#define	VMX_SECONDARY_UNRESTRICTED_GUEST	(UINT32_C(1) << 7)
#define	VMX_SECONDARY_ENABLE_VMFUNC	(UINT32_C(1) << 13)
#define	VMX_SECONDARY_ENABLE_MBEC	(UINT32_C(1) << 22)
#define	NVMX_CR4_LA57			(UINT64_C(1) << 12)

int
vmx_nested_capabilities_limit_physical_width(uint8_t hardware_width,
    uint64_t address_space_end, uint8_t *result)
{
	uint64_t highest;
	uint8_t address_width;

	if (result == NULL || hardware_width < 32 || hardware_width > 52 ||
	    address_space_end == 0)
		return (EINVAL);
	highest = address_space_end - 1;
	address_width = 0;
	do {
		address_width++;
		highest >>= 1;
	} while (highest != 0);
	if (address_width < 32)
		return (ERANGE);
	*result = MIN(hardware_width, address_width);
	return (0);
}

/*
 * These are implementation allowlists, not merely copies of the current
 * processor's capability MSRs.  An allowed-1 bit is part of the nested-VMX
 * guest ABI: L1 must be able to validate it, compose it into VMCS02, route
 * every resulting exit, preserve its state, and restore it.  Keep a control
 * out of these masks until that complete path exists.
 *
 * The legacy default-1 bits are included so the legacy control MSRs can be
 * derived from the same virtual policy.  They do not represent additional
 * optional behavior.
 */
#define	VMX_PINBASED_IMPLEMENTED	UINT32_C(0x0000007f)
#define	VMX_PRIMARY_IMPLEMENTED		\
	((UINT32_C(0xfbfb9e8c) | UINT32_C(0x0401e172)) &	\
	 ~((UINT32_C(1) << 21) |	/* L0/L1 virtual-APIC composition */ \
	 VMX_PRIMARY_MONITOR_TRAP_FLAG)) /* pending MTF after L0 emulation */
#define	VMX_SECONDARY_IMPLEMENTED	\
	((UINT32_C(1) << 1) |	/* EPT */			\
	 (UINT32_C(1) << 2) |	/* descriptor-table exiting */	\
	 (UINT32_C(1) << 3) |	/* RDTSCP */			\
	 (UINT32_C(1) << 6) |	/* WBINVD exiting */		\
	 (UINT32_C(1) << 7) |	/* unrestricted guest */	\
	 (UINT32_C(1) << 11) |	/* RDRAND exiting */		\
	 (UINT32_C(1) << 12) |	/* INVPCID */			\
	 (UINT32_C(1) << 16) |	/* RDSEED exiting */		\
	 (UINT32_C(1) << 25) |	/* TSC scaling */		\
	 (UINT32_C(1) << 26))	/* user-wait/pause */
#define	VMX_EXIT_IMPLEMENTED		\
	(UINT32_C(0x00036dff) |	/* legacy default-1 */		\
	 (UINT32_C(1) << 2) |	/* save debug controls */	\
	 (UINT32_C(1) << 9) |	/* host address-space size */	\
	 (UINT32_C(1) << 15) |	/* acknowledge interrupt */	\
	 (UINT32_C(1) << 18) |	/* save PAT */			\
	 (UINT32_C(1) << 19) |	/* load PAT */			\
	 (UINT32_C(1) << 20) |	/* save EFER */			\
	 (UINT32_C(1) << 21) |	/* load EFER */			\
	 (UINT32_C(1) << 22))	/* save preemption timer */
#define	VMX_ENTRY_IMPLEMENTED		\
	(UINT32_C(0x000011ff) |	/* legacy default-1 */		\
	 (UINT32_C(1) << 2) |	/* load debug controls */	\
	 (UINT32_C(1) << 9) |	/* IA-32e guest */		\
	 (UINT32_C(1) << 14) |	/* load PAT */			\
	 (UINT32_C(1) << 15))	/* load EFER */

/*
 * The generic model validator also accepts controls represented by the
 * schema and pure-model tests but not yet selected by the production
 * allowlist (for example, VPID and APICv).  It must still reject controls
 * whose associated architectural state has no representation at all.
 */
#define	VMX_SECONDARY_UNREPRESENTED	\
	((UINT32_C(1) << 13) | (UINT32_C(1) << 14) |		\
	 (UINT32_C(1) << 15) | (UINT32_C(1) << 17) |		\
	 (UINT32_C(1) << 18) | (UINT32_C(1) << 19) |		\
	 (UINT32_C(1) << 20) | (UINT32_C(1) << 21) |		\
	 (UINT32_C(1) << 23) | (UINT32_C(1) << 24) |		\
	 (UINT32_C(1) << 27) | (UINT32_C(1) << 30) |		\
	 (UINT32_C(1) << 31))
#define	VMX_EXIT_UNREPRESENTED		\
	((UINT32_C(1) << 12) | UINT32_C(0xff800000))
#define	VMX_ENTRY_UNREPRESENTED		\
	((UINT32_C(1) << 13) | UINT32_C(0x03ff0000))

/*
 * CR4 features whose nested architectural companions are not represented.
 * Raw IA32_VMX_CR4_FIXED1 is a hardware ceiling, not permission to expose a
 * partial virtual CPU contract.  In particular CET, PKS, UINTR and FRED have
 * VMCS/MSR state which must be composed and migrated with CR4, while LASS and
 * LAM require matching CPUID and MSR policy.  Keep all of them unavailable
 * until those complete contracts are implemented.
 */
#define	NVMX_CR4_CET		(UINT64_C(1) << 23)
#define	NVMX_CR4_PKS		(UINT64_C(1) << 24)
#define	NVMX_CR4_UINTR		(UINT64_C(1) << 25)
#define	NVMX_CR4_LASS		(UINT64_C(1) << 27)
#define	NVMX_CR4_LAM_SUP	(UINT64_C(1) << 28)
#define	NVMX_CR4_FRED		(UINT64_C(1) << 32)
#define	NVMX_CR4_UNREPRESENTED	(NVMX_CR4_CET | NVMX_CR4_PKS | \
	NVMX_CR4_UINTR | NVMX_CR4_LASS | NVMX_CR4_LAM_SUP | NVMX_CR4_FRED)

#define	VMX_EPT_CAP_WALK_4		(UINT64_C(1) << 6)
#define	VMX_EPT_CAP_WALK_5		(UINT64_C(1) << 7)
#define	VMX_EPT_CAP_MEMORY_UC		(UINT64_C(1) << 8)
#define	VMX_EPT_CAP_MEMORY_WB		(UINT64_C(1) << 14)
#define	VMX_EPT_CAP_ADVANCED_EXIT_INFO	(UINT64_C(1) << 22)
/*
 * Walk-5 (bit 7) is deliberately absent: the production EPT02 root is
 * composed by ept.c with a hardcoded 4-level walk (EPT_PWLEVELS == 4), so a
 * 5-level EPT12 with >48-bit L2 guest-physical addresses could not be
 * represented.  Advertising a capability whose composition path does not
 * exist is a capability lie; withhold it even on 5-level-EPT hosts until a
 * 5-level EPT02 build exists.
 */
#define	VMX_EPT_CAP_ALLOWED		\
	((UINT64_C(1) << 0) | (UINT64_C(1) << 6) |	\
	 (UINT64_C(1) << 8) |				\
	 (UINT64_C(1) << 14) | (UINT64_C(1) << 16) |	\
	 (UINT64_C(1) << 17) | (UINT64_C(1) << 20) |	\
	 (UINT64_C(1) << 21) | (UINT64_C(1) << 22) |	\
	 (UINT64_C(1) << 25) | (UINT64_C(1) << 26))
#define	VMX_VPID_CAP_ALLOWED		\
	((UINT64_C(1) << 32) | (UINT64_C(1) << 40) |	\
	 (UINT64_C(1) << 41) | (UINT64_C(1) << 42) |	\
	 (UINT64_C(1) << 43))
#define	VMX_VPID_CAP_INVVPID		(UINT64_C(1) << 32)
#define	VMX_VPID_CAP_SINGLE_CONTEXT	(UINT64_C(1) << 41)
#define	VMX_DEBUGCTL_DEFINED		UINT64_C(0xdfc7)
#define	VMX_MISC_UNRESTRICTED_LMA	(UINT64_C(1) << 5)
#define	VMX_MISC_ALLOWED		\
	(UINT64_C(0x000000004fff01ff))
#define	VMX_PINBASED_DEFINED		UINT32_C(0x000000e9)
#define	VMX_PRIMARY_DEFINED		UINT32_C(0xfbfb9e8c)
#define	VMX_SECONDARY_DEFINED		UINT32_C(0xcfffffff)
#define	VMX_EXIT_DEFINED		UINT32_C(0xfffc9204)
#define	VMX_ENTRY_DEFINED		UINT32_C(0x03ffee04)
#define	VMX_PINBASED_DEFAULT1		UINT32_C(0x00000016)
#define	VMX_PRIMARY_DEFAULT1		UINT32_C(0x0401e172)
#define	VMX_EXIT_DEFAULT1		UINT32_C(0x00036dff)
#define	VMX_ENTRY_DEFAULT1		UINT32_C(0x000011ff)

#define	VMX_MSR_BASIC			0x480U
#define	VMX_MSR_PINBASED_CTLS		0x481U
#define	VMX_MSR_PROCBASED_CTLS		0x482U
#define	VMX_MSR_EXIT_CTLS		0x483U
#define	VMX_MSR_ENTRY_CTLS		0x484U
#define	VMX_MSR_MISC			0x485U
#define	VMX_MSR_CR0_FIXED0		0x486U
#define	VMX_MSR_CR0_FIXED1		0x487U
#define	VMX_MSR_CR4_FIXED0		0x488U
#define	VMX_MSR_CR4_FIXED1		0x489U
#define	VMX_MSR_VMCS_ENUM		0x48aU
#define	VMX_MSR_PROCBASED_CTLS2		0x48bU
#define	VMX_MSR_EPT_VPID_CAP		0x48cU
#define	VMX_MSR_TRUE_PINBASED_CTLS	0x48dU
#define	VMX_MSR_TRUE_PROCBASED_CTLS	0x48eU
#define	VMX_MSR_TRUE_EXIT_CTLS		0x48fU
#define	VMX_MSR_TRUE_ENTRY_CTLS		0x490U
#define	VMX_MSR_VMFUNC			0x491U

static bool
vmx_nested_control_cap_valid(uint64_t capability)
{
	uint32_t allowed_one, required_one;

	required_one = (uint32_t)capability;
	allowed_one = (uint32_t)(capability >> 32);
	return ((required_one & ~allowed_one) == 0);
}

static uint64_t
nvmx_virtual_control(uint64_t hardware, uint32_t defined, uint32_t removed)
{
	uint32_t allowed;

	allowed = (uint32_t)(hardware >> 32);
	allowed &= defined;
	allowed &= ~removed;
	return ((uint64_t)allowed << 32);
}

int
vmx_nested_capabilities_build(
    const struct vmx_nested_capability_policy_input *input,
    struct vmx_nested_capabilities *capabilities)
{
	struct vmx_nested_capabilities candidate;
	uint32_t primary_allowed, secondary_allowed;

	if (input == NULL || capabilities == NULL ||
	    vmx_nested_state_ranges_overlap(capabilities,
	    sizeof(*capabilities), input, sizeof(*input)) ||
	    input->physical_address_width < 32 ||
	    input->physical_address_width > 52 ||
	    (input->linear_address_width != 48 &&
	    input->linear_address_width != 57) ||
	    (input->policy_flags & ~VMX_NESTED_POLICY_F_ALL) != 0 ||
	    (input->guest_features & ~VMX_NESTED_GUEST_F_ALL) != 0)
		return (EINVAL);

	memset(&candidate, 0, sizeof(candidate));
	candidate.revision_id = VMX_NESTED_VIRTUAL_REVISION_ID;
	candidate.vmcs_region_size = VMX_NESTED_VMCS_REGION_SIZE;
	candidate.physical_address_width = input->physical_address_width;
	candidate.vmcs_memory_type = 6;
	candidate.flags = VMX_NESTED_CAP_F_TRUE_CONTROLS;
	if ((input->guest_features & VMX_NESTED_GUEST_F_RTM) != 0)
		candidate.flags |= VMX_NESTED_CAP_F_GUEST_RTM;
	candidate.linear_address_width = input->linear_address_width;
	candidate.pinbased = nvmx_virtual_control(input->pinbased,
	    VMX_PINBASED_IMPLEMENTED, 0);
	candidate.primary = nvmx_virtual_control(input->primary,
	    VMX_PRIMARY_IMPLEMENTED,
	    VMX_PRIMARY_ACTIVATE_TERTIARY);
	candidate.secondary = nvmx_virtual_control(input->secondary,
	    VMX_SECONDARY_IMPLEMENTED |
	    ((input->policy_flags & VMX_NESTED_POLICY_F_QUALIFY_VPID) != 0 ?
	    VMX_SECONDARY_ENABLE_VPID : 0), 0);
	candidate.vmexit = nvmx_virtual_control(input->vmexit,
	    VMX_EXIT_IMPLEMENTED, 0);
	candidate.vmentry = nvmx_virtual_control(input->vmentry,
	    VMX_ENTRY_IMPLEMENTED, 0);

	/*
	 * A secondary-control capability is meaningless unless L1 can
	 * activate the secondary-control word.  Likewise, unrestricted guest
	 * depends on its companion capability bit.  MBEC is deliberately
	 * absent from the production allowlist until EPT user-execute has a
	 * pmap representation which cannot alias PG_MANAGED.
	 */
	primary_allowed = (uint32_t)(candidate.primary >> 32);
	secondary_allowed = (uint32_t)(candidate.secondary >> 32);
	if ((primary_allowed & VMX_PRIMARY_ACTIVATE_SECONDARY) == 0)
		secondary_allowed = 0;
	if ((input->policy_flags & VMX_NESTED_POLICY_F_QUALIFY_VPID) != 0 &&
	    (secondary_allowed & VMX_SECONDARY_ENABLE_VPID) == 0)
		return (ENOTSUP);
	candidate.misc = input->misc & VMX_MISC_ALLOWED;
	if ((candidate.misc & VMX_MISC_UNRESTRICTED_LMA) == 0)
		secondary_allowed &= ~VMX_SECONDARY_UNRESTRICTED_GUEST;
	candidate.secondary = (uint64_t)secondary_allowed << 32;

	/*
	 * EPT invalidation is implemented.  VPID remains a separate, explicit
	 * qualification policy: do not leak it merely because the hardware has
	 * it.  The model conservatively implements every architectural L1
	 * INVVPID type by invalidating its one destination-local VPID02 context,
	 * so the host needs only the VPID execution control and the INVVPID
	 * single-context primitive which production actually executes.
	 */
	if ((secondary_allowed & VMX_SECONDARY_ENABLE_EPT) != 0)
		candidate.ept_vpid = input->ept_vpid & VMX_EPT_CAP_ALLOWED;
	if ((secondary_allowed & VMX_SECONDARY_ENABLE_VPID) != 0) {
		if ((input->ept_vpid & (VMX_VPID_CAP_INVVPID |
		    VMX_VPID_CAP_SINGLE_CONTEXT)) !=
		    (VMX_VPID_CAP_INVVPID | VMX_VPID_CAP_SINGLE_CONTEXT))
			return (ENOTSUP);
		candidate.ept_vpid |= VMX_VPID_CAP_ALLOWED;
	}
	candidate.cr0_fixed0 = input->cr0_fixed0;
	candidate.cr0_fixed1 = input->cr0_fixed1;
	if ((secondary_allowed & VMX_SECONDARY_UNRESTRICTED_GUEST) != 0)
		candidate.cr0_fixed0 &=
		    ~((UINT64_C(1) << 0) | (UINT64_C(1) << 31));
	candidate.cr4_fixed0 = input->cr4_fixed0;
	candidate.cr4_fixed1 = input->cr4_fixed1;
	if ((candidate.cr4_fixed0 & NVMX_CR4_UNREPRESENTED) != 0)
		return (ENOTSUP);
	candidate.cr4_fixed1 &= ~NVMX_CR4_UNREPRESENTED;
	/*
	 * The virtual CR4 fixed-bit contract must describe the same linear
	 * address mode as virtual CPUID.  A host may implement LA57 without
	 * exposing it to L1, but it cannot require LA57 in that case.
	 */
	if (candidate.linear_address_width == 48) {
		if ((candidate.cr4_fixed0 & NVMX_CR4_LA57) != 0)
			return (ENOTSUP);
		candidate.cr4_fixed1 &= ~NVMX_CR4_LA57;
	}
	candidate.vmcs_enum = vmx_nested_vmcs_enum();
	candidate.vmfunc = 0;
	candidate.debugctl_allowed =
	    input->debugctl_allowed & VMX_DEBUGCTL_DEFINED;

	if (vmx_nested_capabilities_validate(&candidate) != 0)
		return (ENOTSUP);
	*capabilities = candidate;
	return (0);
}

bool
vmx_nested_control_valid(uint32_t controls, uint64_t capability)
{
	uint32_t allowed_one, required_one;

	required_one = (uint32_t)capability;
	allowed_one = (uint32_t)(capability >> 32);
	return ((controls & required_one) == required_one &&
	    (controls & ~allowed_one) == 0);
}

uint32_t
vmx_nested_control_adjust(uint32_t controls, uint64_t capability)
{
	uint32_t allowed_one, required_one;

	required_one = (uint32_t)capability;
	allowed_one = (uint32_t)(capability >> 32);
	return ((controls | required_one) & allowed_one);
}

bool
vmx_nested_region_gpa_valid(
    const struct vmx_nested_capabilities *capabilities, uint64_t gpa)
{
	uint64_t address_limit;

	if (vmx_nested_capabilities_validate(capabilities) != 0 ||
	    (gpa & (UINT64_C(4096) - 1)) != 0)
		return (false);
	address_limit = UINT64_C(1) <<
	    capabilities->physical_address_width;
	if (gpa > address_limit - capabilities->vmcs_region_size)
		return (false);
	if ((capabilities->flags & VMX_NESTED_CAP_F_REGION_32BIT) != 0 &&
	    gpa > UINT64_C(0x100000000) - capabilities->vmcs_region_size)
		return (false);
	return (true);
}

bool
vmx_nested_revision_valid(
    const struct vmx_nested_capabilities *capabilities, uint32_t revision,
    bool shadow)
{
	uint32_t expected;

	if (vmx_nested_capabilities_validate(capabilities) != 0)
		return (false);
	expected = capabilities->revision_id;
	if (shadow)
		expected |= UINT32_C(1) << 31;
	return (revision == expected);
}

int
vmx_nested_capabilities_validate(
    const struct vmx_nested_capabilities *capabilities)
{
	uint64_t controls[5];
	const uint32_t defined[5] = {
		VMX_PINBASED_DEFINED | VMX_PINBASED_DEFAULT1,
		VMX_PRIMARY_DEFINED | VMX_PRIMARY_DEFAULT1,
		VMX_SECONDARY_DEFINED,
		VMX_EXIT_DEFINED | VMX_EXIT_DEFAULT1,
		VMX_ENTRY_DEFINED | VMX_ENTRY_DEFAULT1,
	};
	uint32_t cr3_targets, entry_allowed, exit_allowed, primary_allowed;
	uint32_t secondary_allowed;

	if (capabilities == NULL)
		return (EINVAL);
	controls[0] = capabilities->pinbased;
	controls[1] = capabilities->primary;
	controls[2] = capabilities->secondary;
	controls[3] = capabilities->vmexit;
	controls[4] = capabilities->vmentry;
	if (capabilities->revision_id > INT32_MAX ||
	    capabilities->vmcs_region_size != VMX_NESTED_VMCS_REGION_SIZE ||
	    capabilities->physical_address_width < 32 ||
	    capabilities->physical_address_width > 52 ||
	    (capabilities->linear_address_width != 48 &&
	    capabilities->linear_address_width != 57) ||
	    capabilities->vmcs_memory_type != 6 ||
	    (capabilities->flags & VMX_NESTED_CAP_F_TRUE_CONTROLS) == 0 ||
	    (capabilities->flags & ~(VMX_NESTED_CAP_F_TRUE_CONTROLS |
	    VMX_NESTED_CAP_F_REGION_32BIT |
	    VMX_NESTED_CAP_F_GUEST_RTM)) != 0 ||
	    (capabilities->cr0_fixed0 & ~capabilities->cr0_fixed1) != 0 ||
	    (capabilities->cr4_fixed0 & ~capabilities->cr4_fixed1) != 0 ||
	    (capabilities->cr4_fixed1 & NVMX_CR4_UNREPRESENTED) != 0)
		return (EINVAL);
	for (size_t i = 0; i < nitems(controls); i++) {
		if (!vmx_nested_control_cap_valid(controls[i]) ||
		    (((uint32_t)controls[i] |
		    (uint32_t)(controls[i] >> 32)) & ~defined[i]) != 0)
			return (EINVAL);
	}
	primary_allowed = (uint32_t)(capabilities->primary >> 32);
	secondary_allowed = (uint32_t)(capabilities->secondary >> 32);
	exit_allowed = (uint32_t)(capabilities->vmexit >> 32);
	entry_allowed = (uint32_t)(capabilities->vmentry >> 32);
	cr3_targets = (capabilities->misc >> 16) & 0x1ff;
	if ((((uint32_t)(capabilities->pinbased >> 32) &
	    VMX_PINBASED_DEFAULT1) != VMX_PINBASED_DEFAULT1) ||
	    ((primary_allowed & VMX_PRIMARY_DEFAULT1) !=
	    VMX_PRIMARY_DEFAULT1) ||
	    ((exit_allowed & VMX_EXIT_DEFAULT1) != VMX_EXIT_DEFAULT1) ||
	    ((entry_allowed & VMX_ENTRY_DEFAULT1) != VMX_ENTRY_DEFAULT1))
		return (EINVAL);
	if (capabilities->secondary != 0 &&
	    (primary_allowed & VMX_PRIMARY_ACTIVATE_SECONDARY) == 0)
		return (EINVAL);
	if ((primary_allowed & VMX_PRIMARY_ACTIVATE_TERTIARY) != 0 ||
	    (secondary_allowed & VMX_SECONDARY_UNREPRESENTED) != 0 ||
	    (exit_allowed & VMX_EXIT_UNREPRESENTED) != 0 ||
	    (entry_allowed & VMX_ENTRY_UNREPRESENTED) != 0 ||
	    (capabilities->misc & ~VMX_MISC_ALLOWED) != 0 ||
	    /*
	     * The implemented VMCS12 schema contains the four architectural
	     * CR3-target fields defined by this SDM revision.  Do not advertise
	     * a future larger count until its field encodings and runtime image
	     * are represented.
	     */
	    cr3_targets > 4 ||
	    ((secondary_allowed & (UINT32_C(1) << 7)) != 0 &&
	    (capabilities->misc & VMX_MISC_UNRESTRICTED_LMA) == 0) ||
	    capabilities->vmcs_enum != vmx_nested_vmcs_enum())
		return (EINVAL);
	if ((capabilities->ept_vpid &
	    ~(VMX_EPT_CAP_ALLOWED | VMX_VPID_CAP_ALLOWED)) != 0 ||
	    ((secondary_allowed & VMX_SECONDARY_ENABLE_EPT) == 0 &&
	    (capabilities->ept_vpid & VMX_EPT_CAP_ALLOWED) != 0) ||
	    ((secondary_allowed & VMX_SECONDARY_ENABLE_VPID) == 0 &&
	    (capabilities->ept_vpid & VMX_VPID_CAP_ALLOWED) != 0) ||
	    ((secondary_allowed & VMX_SECONDARY_ENABLE_MBEC) != 0 &&
	    (capabilities->ept_vpid &
	    VMX_EPT_CAP_ADVANCED_EXIT_INFO) == 0) ||
	    ((secondary_allowed & VMX_SECONDARY_ENABLE_EPT) != 0 &&
	    (((capabilities->ept_vpid &
	    (VMX_EPT_CAP_WALK_4 | VMX_EPT_CAP_WALK_5)) == 0) ||
	    (capabilities->ept_vpid &
	    (VMX_EPT_CAP_MEMORY_UC | VMX_EPT_CAP_MEMORY_WB)) == 0)))
		return (EINVAL);
	/*
	 * EPTP switching also requires the EPTP-list VMCS field, execution
	 * semantics, and invalidation handling.  None is complete yet, so do
	 * not accept a virtual policy which could advertise VMFUNC merely
	 * because the host can execute it.
	 */
	if (capabilities->vmfunc != 0 ||
	    (capabilities->debugctl_allowed & ~VMX_DEBUGCTL_DEFINED) != 0)
		return (EINVAL);
	return (0);
}

int
vmx_nested_capabilities_wire_encode(
    const struct vmx_nested_capabilities *capabilities, void *buffer,
    size_t length)
{
	uint8_t bytes[128];
	int error;

	if (buffer == NULL || length != sizeof(bytes) ||
	    vmx_nested_state_ranges_overlap(buffer, length, capabilities,
	    sizeof(*capabilities)))
		return (EINVAL);
	error = vmx_nested_capabilities_validate(capabilities);
	if (error != 0)
		return (error);
	memset(bytes, 0, sizeof(bytes));
	le32enc(bytes, capabilities->revision_id);
	le32enc(bytes + 4, capabilities->vmcs_region_size);
	bytes[8] = capabilities->physical_address_width;
	bytes[9] = capabilities->vmcs_memory_type;
	le16enc(bytes + 10, capabilities->flags);
	bytes[12] = capabilities->linear_address_width;
	le64enc(bytes + 16, capabilities->pinbased);
	le64enc(bytes + 24, capabilities->primary);
	le64enc(bytes + 32, capabilities->secondary);
	le64enc(bytes + 40, capabilities->vmexit);
	le64enc(bytes + 48, capabilities->vmentry);
	le64enc(bytes + 56, capabilities->cr0_fixed0);
	le64enc(bytes + 64, capabilities->cr0_fixed1);
	le64enc(bytes + 72, capabilities->cr4_fixed0);
	le64enc(bytes + 80, capabilities->cr4_fixed1);
	le64enc(bytes + 88, capabilities->ept_vpid);
	le64enc(bytes + 96, capabilities->misc);
	le64enc(bytes + 104, capabilities->vmcs_enum);
	le64enc(bytes + 112, capabilities->vmfunc);
	le64enc(bytes + 120, capabilities->debugctl_allowed);
	memcpy(buffer, bytes, sizeof(bytes));
	return (0);
}

int
vmx_nested_capabilities_wire_decode(const void *buffer, size_t length,
    struct vmx_nested_capabilities *capabilities)
{
	struct vmx_nested_capabilities candidate;
	const uint8_t *bytes;
	int error;

	if (buffer == NULL || capabilities == NULL ||
	    vmx_nested_state_ranges_overlap(capabilities,
	    sizeof(*capabilities), buffer, length) ||
	    length != VMX_NESTED_CAPABILITIES_WIRE_SIZE)
		return (EINVAL);
	bytes = buffer;
	if (bytes[13] != 0 || bytes[14] != 0 || bytes[15] != 0)
		return (EPROTO);
	memset(&candidate, 0, sizeof(candidate));
	candidate.revision_id = le32dec(bytes);
	candidate.vmcs_region_size = le32dec(bytes + 4);
	candidate.physical_address_width = bytes[8];
	candidate.vmcs_memory_type = bytes[9];
	candidate.flags = le16dec(bytes + 10);
	candidate.linear_address_width = bytes[12];
	candidate.pinbased = le64dec(bytes + 16);
	candidate.primary = le64dec(bytes + 24);
	candidate.secondary = le64dec(bytes + 32);
	candidate.vmexit = le64dec(bytes + 40);
	candidate.vmentry = le64dec(bytes + 48);
	candidate.cr0_fixed0 = le64dec(bytes + 56);
	candidate.cr0_fixed1 = le64dec(bytes + 64);
	candidate.cr4_fixed0 = le64dec(bytes + 72);
	candidate.cr4_fixed1 = le64dec(bytes + 80);
	candidate.ept_vpid = le64dec(bytes + 88);
	candidate.misc = le64dec(bytes + 96);
	candidate.vmcs_enum = le64dec(bytes + 104);
	candidate.vmfunc = le64dec(bytes + 112);
	candidate.debugctl_allowed = le64dec(bytes + 120);
	error = vmx_nested_capabilities_validate(&candidate);
	if (error != 0)
		return (EPROTO);
	*capabilities = candidate;
	return (0);
}

int
vmx_nested_capabilities_signature(
    const struct vmx_nested_capabilities *capabilities, uint64_t *signature)
{
	uint8_t bytes[VMX_NESTED_CAPABILITIES_WIRE_SIZE];
	uint64_t digest;
	int error;

	if (signature == NULL ||
	    vmx_nested_state_ranges_overlap(signature, sizeof(*signature),
	    capabilities, sizeof(*capabilities)))
		return (EINVAL);
	error = vmx_nested_capabilities_wire_encode(capabilities, bytes,
	    sizeof(bytes));
	if (error != 0)
		return (error);
	digest = UINT64_C(14695981039346656037);
	for (size_t i = 0; i < sizeof(bytes); i++) {
		digest ^= bytes[i];
		digest *= UINT64_C(1099511628211);
	}
	if (digest == 0)
		digest = 1;
	*signature = digest;
	return (0);
}

bool
vmx_nested_capabilities_equal(
    const struct vmx_nested_capabilities *left,
    const struct vmx_nested_capabilities *right)
{

	if (vmx_nested_capabilities_validate(left) != 0 ||
	    vmx_nested_capabilities_validate(right) != 0)
		return (false);
	return (left->revision_id == right->revision_id &&
	    left->vmcs_region_size == right->vmcs_region_size &&
	    left->physical_address_width == right->physical_address_width &&
	    left->vmcs_memory_type == right->vmcs_memory_type &&
	    left->flags == right->flags &&
	    left->linear_address_width == right->linear_address_width &&
	    left->pinbased == right->pinbased &&
	    left->primary == right->primary &&
	    left->secondary == right->secondary &&
	    left->vmexit == right->vmexit &&
	    left->vmentry == right->vmentry &&
	    left->cr0_fixed0 == right->cr0_fixed0 &&
	    left->cr0_fixed1 == right->cr0_fixed1 &&
	    left->cr4_fixed0 == right->cr4_fixed0 &&
	    left->cr4_fixed1 == right->cr4_fixed1 &&
	    left->ept_vpid == right->ept_vpid &&
	    left->misc == right->misc &&
	    left->vmcs_enum == right->vmcs_enum &&
	    left->vmfunc == right->vmfunc &&
	    left->debugctl_allowed == right->debugctl_allowed);
}

int
vmx_nested_capability_read_msr(
    const struct vmx_nested_capabilities *capabilities, uint32_t msr,
    uint64_t *value)
{
	uint64_t basic;
	int error;

	if (value == NULL ||
	    vmx_nested_state_ranges_overlap(value, sizeof(*value), capabilities,
	    sizeof(*capabilities)))
		return (EINVAL);
	error = vmx_nested_capabilities_validate(capabilities);
	if (error != 0)
		return (error);
	switch (msr) {
	case VMX_MSR_BASIC:
		basic = capabilities->revision_id |
		    ((uint64_t)capabilities->vmcs_region_size << 32) |
		    ((uint64_t)capabilities->vmcs_memory_type << 50) |
		    (UINT64_C(1) << 55);
		if ((capabilities->flags &
		    VMX_NESTED_CAP_F_REGION_32BIT) != 0)
			basic |= UINT64_C(1) << 48;
		*value = basic;
		break;
	case VMX_MSR_PINBASED_CTLS:
		*value = capabilities->pinbased | VMX_PINBASED_DEFAULT1;
		break;
	case VMX_MSR_TRUE_PINBASED_CTLS:
		*value = capabilities->pinbased;
		break;
	case VMX_MSR_PROCBASED_CTLS:
		*value = capabilities->primary | VMX_PRIMARY_DEFAULT1;
		break;
	case VMX_MSR_TRUE_PROCBASED_CTLS:
		*value = capabilities->primary;
		break;
	case VMX_MSR_EXIT_CTLS:
		*value = capabilities->vmexit | VMX_EXIT_DEFAULT1;
		break;
	case VMX_MSR_TRUE_EXIT_CTLS:
		*value = capabilities->vmexit;
		break;
	case VMX_MSR_ENTRY_CTLS:
		*value = capabilities->vmentry | VMX_ENTRY_DEFAULT1;
		break;
	case VMX_MSR_TRUE_ENTRY_CTLS:
		*value = capabilities->vmentry;
		break;
	case VMX_MSR_MISC:
		*value = capabilities->misc;
		break;
	case VMX_MSR_CR0_FIXED0:
		*value = capabilities->cr0_fixed0;
		break;
	case VMX_MSR_CR0_FIXED1:
		*value = capabilities->cr0_fixed1;
		break;
	case VMX_MSR_CR4_FIXED0:
		*value = capabilities->cr4_fixed0;
		break;
	case VMX_MSR_CR4_FIXED1:
		*value = capabilities->cr4_fixed1;
		break;
	case VMX_MSR_VMCS_ENUM:
		*value = capabilities->vmcs_enum;
		break;
	case VMX_MSR_PROCBASED_CTLS2:
		*value = capabilities->secondary;
		break;
	case VMX_MSR_EPT_VPID_CAP:
		*value = capabilities->ept_vpid;
		break;
	case VMX_MSR_VMFUNC:
		*value = capabilities->vmfunc;
		break;
	default:
		return (ENOENT);
	}
	return (0);
}
