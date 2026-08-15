/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_DECODE_H_
#define	_VMM_INTEL_VMX_NESTED_DECODE_H_

#include "vmx_nested_types.h"

struct vmx_nested_operand {
	uint8_t scale;
	uint8_t address_size;
	uint8_t segment;
	uint8_t index_register;
	uint8_t base_register;
	uint8_t register1;
	uint8_t register2;
	bool index_valid;
	bool base_valid;
	bool register_operand;
};

struct vmx_nested_address_segment {
	uint32_t limit;
	uint8_t type;
	uint64_t base;
	bool unusable;
	bool default_big;
};

enum vmx_nested_decode_failure {
	VMX_NESTED_DECODE_OK = 0,
	VMX_NESTED_DECODE_FORM,
	VMX_NESTED_DECODE_ADDRESS_SIZE,
	VMX_NESTED_DECODE_SEGMENT,
};

enum vmx_nested_address_failure {
	VMX_NESTED_ADDRESS_OK = 0,
	VMX_NESTED_ADDRESS_FORM,
	VMX_NESTED_ADDRESS_NONCANONICAL,
	VMX_NESTED_ADDRESS_SEGMENT_TYPE,
	VMX_NESTED_ADDRESS_SEGMENT_UNUSABLE,
	VMX_NESTED_ADDRESS_SEGMENT_LIMIT,
};

int	vmx_nested_operand_decode(uint32_t, bool, bool, bool,
	    struct vmx_nested_operand *, enum vmx_nested_decode_failure *);
int	vmx_nested_operand_address(const struct vmx_nested_operand *,
	    uint64_t, const uint64_t [16],
	    const struct vmx_nested_address_segment [6], bool, bool,
	    size_t, uint8_t, uint64_t *,
	    enum vmx_nested_address_failure *);

#endif /* _VMM_INTEL_VMX_NESTED_DECODE_H_ */
