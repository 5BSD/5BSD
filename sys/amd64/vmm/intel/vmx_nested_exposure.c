/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/endian.h>
#include <sys/errno.h>
#include <sys/types.h>

#ifdef _KERNEL
#include <sys/systm.h>
#else
#include <stdint.h>
#include <string.h>
#endif

#include "vmx_nested_caps.h"
#include "vmx_nested_exposure.h"
#include "vmx_nested_state.h"
#include "vmx_nested_vmcs.h"

/*
 * Only stages with a complete, independently tested implementation belong
 * here.  Adding source files, or a value-only model of a later transaction,
 * is not sufficient reason to set a stage bit.  ENTRY_TRANSACTION is present
 * because vmx_run_nested() now composes every selected cold, resumed, and hot
 * unwind with common startup-owner settlement before a result can escape.
 */
#define	NVMX_IMPLEMENTED_STAGES					\
	(VMX_NESTED_STAGE_CAPABILITY_POLICY |			\
	 VMX_NESTED_STAGE_VMCS_STORE |				\
	 VMX_NESTED_STAGE_INSTRUCTION_RESULTS |			\
	 VMX_NESTED_STAGE_INSTRUCTION_DECODE |			\
	 VMX_NESTED_STAGE_ENTRY_CONTROLS |			\
	 VMX_NESTED_STAGE_HOST_STATE |				\
	 VMX_NESTED_STAGE_GUEST_STATE |				\
	 VMX_NESTED_STAGE_VMCS02 |				\
	 VMX_NESTED_STAGE_EXIT_REFLECTION |			\
	 VMX_NESTED_STAGE_EPT_INVEPT |				\
	 VMX_NESTED_STAGE_INTERRUPTS |				\
	 VMX_NESTED_STAGE_CHECKPOINT |				\
	 VMX_NESTED_STAGE_ENTRY_TRANSACTION)

#define	VMX_NESTED_EXPOSURE_SNAPSHOT_MAGIC	0x31534d56U
#define	VMX_NESTED_EXPOSURE_SNAPSHOT_VERSION	2U
#define	VMX_NESTED_EXPOSURE_SNAPSHOT_F_ENABLED	0x1U
#define	VMX_NESTED_EXPOSURE_SNAPSHOT_F_MASK	\
	VMX_NESTED_EXPOSURE_SNAPSHOT_F_ENABLED

uint32_t
vmx_nested_implementation_stages(void)
{

	return (NVMX_IMPLEMENTED_STAGES);
}

int
vmx_nested_exposure_snapshot_header_encode(bool enabled, uint8_t *header,
    size_t length)
{

	if (header == NULL ||
	    length != VMX_NESTED_EXPOSURE_SNAPSHOT_HEADER_SIZE)
		return (EINVAL);
	memset(header, 0, length);
	le32enc(header, VMX_NESTED_EXPOSURE_SNAPSHOT_MAGIC);
	le16enc(header + 4, VMX_NESTED_EXPOSURE_SNAPSHOT_VERSION);
	le16enc(header + 6, VMX_NESTED_EXPOSURE_SNAPSHOT_HEADER_SIZE);
	le32enc(header + 8, enabled ?
	    VMX_NESTED_EXPOSURE_SNAPSHOT_F_ENABLED : 0);
	return (0);
}

int
vmx_nested_exposure_snapshot_header_decode(const uint8_t *header,
    size_t length, bool *enabled)
{
	uint32_t flags;
	uint16_t version;
	bool candidate;

	if (header == NULL || enabled == NULL ||
	    length != VMX_NESTED_EXPOSURE_SNAPSHOT_HEADER_SIZE)
		return (EINVAL);
	version = le16dec(header + 4);
	flags = le32dec(header + 8);
	if (le32dec(header) != VMX_NESTED_EXPOSURE_SNAPSHOT_MAGIC ||
	    le16dec(header + 6) !=
	    VMX_NESTED_EXPOSURE_SNAPSHOT_HEADER_SIZE ||
	    version != VMX_NESTED_EXPOSURE_SNAPSHOT_VERSION ||
	    le32dec(header + 12) != 0 ||
	    (flags & ~VMX_NESTED_EXPOSURE_SNAPSHOT_F_MASK) != 0)
		return (ENOTSUP);
	candidate =
	    (flags & VMX_NESTED_EXPOSURE_SNAPSHOT_F_ENABLED) != 0;
	*enabled = candidate;
	return (0);
}

int
vmx_nested_exposure_configure(uint32_t current, bool enabled,
    uint32_t *next)
{

	if (next == NULL ||
	    (current & ~VMX_NESTED_EXPOSURE_STATE_MASK) != 0)
		return (EINVAL);
	if ((current & VMX_NESTED_EXPOSURE_LOCKED) != 0 &&
	    (((current & VMX_NESTED_EXPOSURE_ENABLED) != 0) != enabled))
		return (EBUSY);
	*next = (current & VMX_NESTED_EXPOSURE_LOCKED) |
	    (enabled ? VMX_NESTED_EXPOSURE_ENABLED : 0);
	return (0);
}

int
vmx_nested_exposure_lock(uint32_t current, uint32_t *next)
{

	if (next == NULL ||
	    (current & ~VMX_NESTED_EXPOSURE_STATE_MASK) != 0)
		return (EINVAL);
	*next = current | VMX_NESTED_EXPOSURE_LOCKED;
	return (0);
}

int
vmx_nested_exposure_validate(
    const struct vmx_nested_capabilities *capabilities)
{

	/* Preserve the API's input-error contract independent of readiness. */
	if (vmx_nested_capabilities_validate(capabilities) != 0 ||
	    capabilities->vmcs_enum != vmx_nested_vmcs_enum())
		return (EINVAL);
	if ((NVMX_IMPLEMENTED_STAGES & VMX_NESTED_EXPOSURE_REQUIRED) !=
	    VMX_NESTED_EXPOSURE_REQUIRED)
		return (ENOTSUP);
	return (0);
}

int
vmx_nested_exposure_policy_validate(
    const struct vmx_nested_capabilities *capabilities, bool enabled)
{

	if (vmx_nested_capabilities_validate(capabilities) != 0 ||
	    capabilities->vmcs_enum != vmx_nested_vmcs_enum())
		return (EINVAL);
	if (!enabled)
		return (ENOTSUP);
	return (vmx_nested_exposure_validate(capabilities));
}

/*
 * A checkpoint is another guest-ABI entry point.  In particular, restoring
 * a VMXON or active-L2 image must not bypass the same implementation-stage
 * gate that keeps CPUID, VMX MSRs, and VMX instructions hidden.
 *
 * Canonical inactive state remains portable while exposure is disabled.  It
 * contains no VMX architectural ownership and is what an ordinary guest
 * checkpoint produced by this kernel carries.
 */
int
vmx_nested_exposure_restore_validate(
    const struct vmx_nested_capabilities *capabilities,
    const struct vmx_nested_state_view *view, bool enabled)
{
	int error;

	error = vmx_nested_state_destination_validate(view, capabilities);
	if (error != 0)
		return (error);
	if ((view->flags & VMX_NESTED_STATE_F_VMXON) == 0)
		return (0);
	return (vmx_nested_exposure_policy_validate(capabilities, enabled));
}

/*
 * Exposure is part of the VM-wide CPU model even when no vCPU has entered
 * VMX operation.  An inactive per-vCPU record therefore cannot authorize a
 * source/destination exposure change.  The VM-level snapshot owner calls this
 * before staging any registry or vCPU state.
 */
int
vmx_nested_exposure_snapshot_validate(
    const struct vmx_nested_capabilities *capabilities, bool source_enabled,
    bool destination_enabled, bool host_enabled)
{

	if (vmx_nested_capabilities_validate(capabilities) != 0 ||
	    capabilities->vmcs_enum != vmx_nested_vmcs_enum())
		return (EINVAL);
	if (source_enabled != destination_enabled)
		return (ENOTSUP);
	if (!source_enabled)
		return (0);
	return (vmx_nested_exposure_policy_validate(capabilities,
	    host_enabled));
}

/*
 * A disabled exposure envelope is the legacy, no-nested-VMX CPU model.  It
 * cannot legitimately own even an inactive private VMCS registry: without
 * VMX exposure the source guest could not have created those entries.  Keep
 * this cross-record rule at the VM-level staging boundary so a syntactically
 * valid private registry cannot hide behind a disabled exposure header.
 */
int
vmx_nested_exposure_registry_validate(bool enabled, uint32_t count)
{

	if (!enabled && count != 0)
		return (EPROTO);
	return (0);
}
