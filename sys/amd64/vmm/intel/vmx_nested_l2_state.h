/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_L2_STATE_H_
#define	_VMM_INTEL_VMX_NESTED_L2_STATE_H_

#include <sys/types.h>

#include "vmx_nested_l2_portable.h"

/*
 * Fixed-layout, little-endian encoding of an L0-owned cold L2 continuation.
 * The format deliberately does not depend on compiler structure layout,
 * host word size, or host byte order.
 */
#define	VMX_NESTED_L2_STATE_HEADER_SIZE	64U
#define	VMX_NESTED_L2_STATE_BODY_SIZE	494U
#define	VMX_NESTED_L2_STATE_SIZE		\
	(VMX_NESTED_L2_STATE_HEADER_SIZE + VMX_NESTED_L2_STATE_BODY_SIZE)
#define	VMX_NESTED_L2_STATE_MAX_SIZE	VMX_NESTED_L2_STATE_SIZE

int	vmx_nested_l2_state_encode(
	    const struct vmx_nested_l2_portable_state *, void *, size_t,
	    size_t *);
int	vmx_nested_l2_state_decode(const void *, size_t,
	    struct vmx_nested_l2_portable_state *);

#endif /* _VMM_INTEL_VMX_NESTED_L2_STATE_H_ */
