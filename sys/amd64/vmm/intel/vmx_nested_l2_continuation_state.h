/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_L2_CONTINUATION_STATE_H_
#define	_VMM_INTEL_VMX_NESTED_L2_CONTINUATION_STATE_H_

#include "vmx_nested_types.h"

#include "vmx_nested_continuation.h"
#include "vmx_nested_l2_state.h"

#define	VMX_NESTED_L2_CONT_STATE_HEADER_SIZE	64U
#define	VMX_NESTED_L2_CONT_STATE_RECORD_SIZE	44U
#define	VMX_NESTED_L2_CONT_STATE_SIZE			\
	(VMX_NESTED_L2_CONT_STATE_HEADER_SIZE +		\
	 VMX_NESTED_L2_CONT_STATE_RECORD_SIZE +		\
	 VMX_NESTED_L2_STATE_SIZE)
#define	VMX_NESTED_L2_CONT_STATE_MAX_SIZE		\
	VMX_NESTED_L2_CONT_STATE_SIZE

struct vmx_nested_l2_continuation_state {
	struct vmx_nested_l0_continuation_record continuation;
	struct vmx_nested_l2_portable_state portable;
};

struct vmx_nested_capabilities;
struct vmx_nested_entry_runtime;

int	vmx_nested_l2_continuation_state_encode(
	    const struct vmx_nested_l0_continuation *,
	    const struct vmx_nested_l2_portable_state *, void *, size_t,
	    size_t *);
int	vmx_nested_l2_continuation_state_decode(const void *, size_t,
	    struct vmx_nested_l2_continuation_state *);
/*
 * Decode and publish only the resource-free cold ownership stage.  This
 * does not rebuild a VMCS02, acquire an EPT root or VPID, install MSRs, or
 * make L2 runnable.  All three outputs are committed together.
 */
int	vmx_nested_l2_continuation_state_restore_cold(
	    struct vmx_nested_l0_continuation *,
	    struct vmx_nested_entry_runtime *,
	    struct vmx_nested_l2_portable_state *,
	    const struct vmx_nested_capabilities *, const void *, size_t, bool);

#endif /* _VMM_INTEL_VMX_NESTED_L2_CONTINUATION_STATE_H_ */
