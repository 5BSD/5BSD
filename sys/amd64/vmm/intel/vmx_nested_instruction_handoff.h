/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_INSTRUCTION_HANDOFF_H_
#define	_VMM_INTEL_VMX_NESTED_INSTRUCTION_HANDOFF_H_

#include "vmx_nested_types.h"

#include "vmx_nested_caps.h"
#include "vmx_nested_invalidate.h"
#include "vmx_nested_instruction.h"

enum vmx_nested_instruction_handoff_state {
	VMX_NESTED_INSTRUCTION_HANDOFF_IDLE = 0,
	VMX_NESTED_INSTRUCTION_HANDOFF_PENDING,
	VMX_NESTED_INSTRUCTION_HANDOFF_HANDLING,
	VMX_NESTED_INSTRUCTION_HANDOFF_RESOLVED,
};

enum vmx_nested_instruction_operation {
	VMX_NESTED_INSTRUCTION_VMXON = 1,
	VMX_NESTED_INSTRUCTION_VMXOFF,
	VMX_NESTED_INSTRUCTION_VMCLEAR,
	VMX_NESTED_INSTRUCTION_VMPTRLD,
	VMX_NESTED_INSTRUCTION_VMPTRST,
	VMX_NESTED_INSTRUCTION_VMREAD,
	VMX_NESTED_INSTRUCTION_VMWRITE,
	VMX_NESTED_INSTRUCTION_INVEPT,
	VMX_NESTED_INSTRUCTION_VMLAUNCH,
	VMX_NESTED_INSTRUCTION_VMRESUME,
	/*
	 * Append new operations so in-flight internal state retains stable
	 * numeric values across kernel upgrades and checkpoint inspection.
	 */
	VMX_NESTED_INSTRUCTION_INVVPID,
};

enum vmx_nested_instruction_access {
	VMX_NESTED_INSTRUCTION_ACCESS_OK = 0,
	VMX_NESTED_INSTRUCTION_ACCESS_GUEST_FAULT,
	VMX_NESTED_INSTRUCTION_ACCESS_INVALID_REGION,
	VMX_NESTED_INSTRUCTION_ACCESS_RETRY,
	VMX_NESTED_INSTRUCTION_ACCESS_FATAL,
};

struct vmx_nested_instruction_handoff_id {
	uint64_t state_generation;
	uint64_t execution_epoch;
};

/*
 * The runtime supplies the architectural exception created by a failed
 * linear-memory access.  No host pointer or callback is retained.
 */
struct vmx_nested_instruction_fault {
	uint64_t linear_address;
	uint32_t error_code;
	uint8_t vector;
	bool error_code_valid;
	/*
	 * Set only by the production frozen-vCPU adapter after it has queued
	 * this exception in the L1 architectural interrupt state.  The pure
	 * handoff engine may describe an uninjected fault for unit testing,
	 * but the context owner will not consume one.
	 */
	bool injected;
};

struct vmx_nested_instruction_access_result {
	enum vmx_nested_instruction_access kind;
	int error;
	struct vmx_nested_instruction_fault fault;
};

struct vmx_nested_instruction_handoff_request {
	struct vmx_nested_instruction_handoff_id id;
	struct vmx_nested_capabilities capabilities;
	struct vmx_nested_machine machine;
	enum vmx_nested_instruction_operation operation;
	uint64_t linear_address;
	uint64_t register_value;
	uint64_t rflags;
	uint64_t field_encoding;
	uint8_t operand_size;
	uint8_t instruction_length;
	uint8_t register_index;
	bool value_in_register;
	bool movss_blocked;
};

enum vmx_nested_instruction_disposition {
	VMX_NESTED_INSTRUCTION_COMPLETE = 0,
	VMX_NESTED_INSTRUCTION_GUEST_FAULT,
	VMX_NESTED_INSTRUCTION_HOST_ERROR,
	/*
	 * Architectural checks that precede full VM-entry succeeded.  The L1
	 * instruction must not advance RIP or publish success flags; ownership
	 * transfers to the separate frozen entry transaction.
	 */
	VMX_NESTED_INSTRUCTION_ENTRY_READY,
};

struct vmx_nested_instruction_handoff_result {
	struct vmx_nested_instruction_handoff_id id;
	struct vmx_nested_machine machine;
	struct vmx_nested_result instruction;
	struct vmx_nested_instruction_fault fault;
	uint64_t output_value;
	uint64_t rflags;
	int host_error;
	enum vmx_nested_instruction_disposition disposition;
	uint8_t output_size;
	uint8_t output_register_index;
	uint8_t rip_advance;
	bool output_register;
};

/*
 * All callbacks run with the vCPU frozen.  Linear writes and VMCS mutations
 * must be all-or-nothing.  check_region() checks Intel's architectural
 * VMX-region metadata.  The vmcs_* callbacks operate on the virtual
 * processor's decoded VMCS object keyed by GPA.  An implementation-defined
 * representation may be backed by the L1 VMCS region (as real processors
 * are permitted to do), but it is not the portable checkpoint ABI and must
 * not contain host pointers, file descriptors, or hardware-VMCS state.
 * handle() snapshots this table before the first callback.  A callback may
 * not retain arguments or mutate the handoff; changing the caller's table
 * cannot redirect a later callback in the same instruction transaction.
 */
struct vmx_nested_instruction_handoff_ops {
	struct vmx_nested_instruction_access_result (*linear_read)(void *,
	    uint64_t, void *, size_t);
	struct vmx_nested_instruction_access_result (*linear_write)(void *,
	    uint64_t, const void *, size_t);
	struct vmx_nested_instruction_access_result (*check_region)(void *,
	    uint64_t, bool);
	struct vmx_nested_instruction_access_result (*vmxoff_release)(void *);
	struct vmx_nested_instruction_access_result (*vmcs_clear)(void *,
	    uint64_t);
	struct vmx_nested_instruction_access_result (*vmcs_read)(void *,
	    uint64_t, uint32_t, uint64_t *);
	struct vmx_nested_instruction_access_result (*vmcs_write)(void *,
	    uint64_t, uint32_t, uint64_t);
	struct vmx_nested_instruction_access_result (*vmcs_launch_state)(void *,
	    uint64_t, bool *, uint64_t *);
	struct vmx_nested_instruction_access_result (*vmcs_set_error)(void *,
	    uint64_t, uint32_t);
	struct vmx_nested_instruction_access_result (*invept)(void *,
	    const struct vmx_nested_invalidation *);
	struct vmx_nested_instruction_access_result (*invvpid)(void *,
	    const struct vmx_nested_invalidation *);
};

struct vmx_nested_instruction_handoff {
	enum vmx_nested_instruction_handoff_state state;
	struct vmx_nested_instruction_handoff_request request;
	struct vmx_nested_instruction_handoff_result result;
};

void	vmx_nested_instruction_handoff_init(
	    struct vmx_nested_instruction_handoff *);
int	vmx_nested_instruction_handoff_publish(
	    struct vmx_nested_instruction_handoff *,
	    const struct vmx_nested_instruction_handoff_request *);
int	vmx_nested_instruction_handoff_handle(
	    struct vmx_nested_instruction_handoff *,
	    const struct vmx_nested_instruction_handoff_id *,
	    const struct vmx_nested_instruction_handoff_ops *, void *);
int	vmx_nested_instruction_handoff_take(
	    struct vmx_nested_instruction_handoff *,
	    const struct vmx_nested_instruction_handoff_id *,
	    struct vmx_nested_instruction_handoff_result *);
int	vmx_nested_instruction_handoff_cancel(
	    struct vmx_nested_instruction_handoff *,
	    const struct vmx_nested_instruction_handoff_id *);

#endif /* _VMM_INTEL_VMX_NESTED_INSTRUCTION_HANDOFF_H_ */
