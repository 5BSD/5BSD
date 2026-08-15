/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_EPT_H_
#define	_VMM_INTEL_VMX_NESTED_EPT_H_

#include "vmx_nested_types.h"

struct vmx_nested_capabilities;
struct vmx_nested_ept_memory;

#define	VMX_NESTED_EPT_ACCESS_READ	0x01U
#define	VMX_NESTED_EPT_ACCESS_WRITE	0x02U
#define	VMX_NESTED_EPT_ACCESS_EXECUTE	0x04U
/*
 * Internal cumulative permission for MBEC bit 10.  It is not a distinct
 * access type: an instruction fetch is still reported as execute in exit
 * qualification bits 2:0.
 */
#define	VMX_NESTED_EPT_PERMISSION_USER_EXECUTE	0x08U

enum vmx_nested_ept_outcome {
	VMX_NESTED_EPT_TRANSLATED = 0,
	VMX_NESTED_EPT_VIOLATION,
	VMX_NESTED_EPT_MISCONFIGURATION,
};

struct vmx_nested_ept_walk {
	const struct vmx_nested_capabilities	*capabilities;
	const struct vmx_nested_ept_memory	*memory;
	uint64_t	eptp;
	uint64_t	guest_physical_address;
	uint8_t		access;
	bool		mode_based_execute;
	bool		user_mode;
	bool		guest_paging_structure_access;
};

struct vmx_nested_ept_result {
	enum vmx_nested_ept_outcome	outcome;
	uint64_t	translated_address;
	uint64_t	entry_address;
	uint64_t	entry;
	uint8_t		permissions;
	uint8_t		access;
	uint8_t		level;
	uint8_t		page_shift;
};

struct vmx_nested_ept_exit_provenance {
	bool		linear_address_valid;
	bool		final_translation;
	bool		nmi_unblocking_due_to_iret;
	bool		advanced_information;
	bool		user_mode;
	bool		guest_page_writable;
	bool		guest_page_execute_disable;
};

int	vmx_nested_ept_walk(const struct vmx_nested_ept_walk *,
	    struct vmx_nested_ept_result *);
int	vmx_nested_ept_exit_qualification(
	    const struct vmx_nested_ept_result *,
	    const struct vmx_nested_ept_exit_provenance *, uint64_t *);

#endif /* _VMM_INTEL_VMX_NESTED_EPT_H_ */
