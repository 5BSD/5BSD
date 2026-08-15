/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_MEMORY_H_
#define	_VMM_INTEL_VMX_NESTED_MEMORY_H_

#include <sys/types.h>

/*
 * Guest-physical access required by architectural VM-entry and VM-exit
 * processing.  The caller owns translation, pinning, freezing, and fault
 * handling; the common layer never retains a supplied buffer, callback, or
 * argument.
 *
 * A failed write must leave the requested byte range unchanged.  Earlier
 * successful writes in an architecturally ordered operation may remain
 * visible, as for Intel VM-exit MSR-store processing before a VMX abort.
 */
struct vmx_nested_memory {
	int	(*read)(void *, uint64_t, void *, size_t);
	void	*arg;
	int	(*write)(void *, uint64_t, const void *, size_t);
};

#endif /* _VMM_INTEL_VMX_NESTED_MEMORY_H_ */
