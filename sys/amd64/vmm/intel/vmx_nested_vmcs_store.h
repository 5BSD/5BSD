/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_VMCS_STORE_H_
#define	_VMM_INTEL_VMX_NESTED_VMCS_STORE_H_

#include "vmx_nested_types.h"

struct vmx_nested_capabilities;
struct vmx_nested_exit_information;
struct vmx_nested_field;
struct vmx_nested_vmexit_state_input;
struct vmx_nested_vmentry_result;

int	vmx_nested_vmcs_region_init(void *, size_t,
	    const struct vmx_nested_capabilities *, bool);
int	vmx_nested_vmcs_region_prepare(void *, size_t,
	    const struct vmx_nested_capabilities *, bool);
int	vmx_nested_vmcs_region_validate(const void *, size_t,
	    const struct vmx_nested_capabilities *, bool);
int	vmx_nested_vmcs_region_read(const void *, size_t,
	    const struct vmx_nested_capabilities *, bool, uint32_t, uint64_t *);
int	vmx_nested_vmcs_region_write(void *, size_t,
	    const struct vmx_nested_capabilities *, bool, uint32_t, uint64_t);
int	vmx_nested_vmcs_region_set_instruction_error(void *, size_t,
	    const struct vmx_nested_capabilities *, bool, uint32_t);
int	vmx_nested_vmcs_region_clear(void *, size_t,
	    const struct vmx_nested_capabilities *, bool);
int	vmx_nested_vmcs_region_set_launched(void *, size_t,
	    const struct vmx_nested_capabilities *, bool, bool, uint64_t);
int	vmx_nested_vmcs_region_launched(const void *, size_t,
	    const struct vmx_nested_capabilities *, bool, bool *, uint64_t *);
int	vmx_nested_vmcs_region_set_abort_indicator(void *, size_t,
	    const struct vmx_nested_capabilities *, bool, uint32_t);
int	vmx_nested_vmcs_region_abort_indicator(const void *, size_t,
	    const struct vmx_nested_capabilities *, bool, uint32_t *);
int	vmx_nested_vmcs_region_field_count(const void *, size_t,
	    const struct vmx_nested_capabilities *, bool, uint32_t *);
int	vmx_nested_vmcs_region_field(const void *, size_t,
	    const struct vmx_nested_capabilities *, bool, uint32_t,
	    struct vmx_nested_field *);
int	vmx_nested_vmcs_region_import(void *, size_t,
	    const struct vmx_nested_capabilities *, bool,
	    const struct vmx_nested_field *, uint32_t, bool, uint64_t);
int	vmx_nested_vmcs_region_commit_ept_exit_information(void *, size_t,
	    const struct vmx_nested_capabilities *, bool,
	    const struct vmx_nested_exit_information *, uint64_t,
	    void *, size_t);
int	vmx_nested_vmcs_region_commit_vmexit(void *, size_t,
	    const struct vmx_nested_capabilities *, bool,
	    const struct vmx_nested_vmexit_state_input *,
	    const struct vmx_nested_exit_information *, uint64_t,
	    void *, size_t);
int	vmx_nested_vmcs_region_prepare_vmexit(const void *, size_t,
	    const struct vmx_nested_capabilities *, bool,
	    const struct vmx_nested_vmexit_state_input *,
	    const struct vmx_nested_exit_information *, uint64_t,
	    void *, size_t);
int	vmx_nested_vmcs_region_commit_vmentry_failure(void *, size_t,
	    const struct vmx_nested_capabilities *, bool,
	    const struct vmx_nested_vmentry_result *, void *, size_t);

#endif /* _VMM_INTEL_VMX_NESTED_VMCS_STORE_H_ */
