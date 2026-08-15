/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_INTEL_VMX_NESTED_TYPES_H_
#define	_VMM_INTEL_VMX_NESTED_TYPES_H_

/*
 * Public nested-VMX model headers are built both in the kernel and by
 * standalone architectural tests.  sys/types.h provides the fixed-width
 * types in both environments; bool is a C library type outside the kernel.
 */
#include <sys/types.h>

#ifndef _KERNEL
#include <stddef.h>
#include <stdbool.h>
#endif

#endif /* _VMM_INTEL_VMX_NESTED_TYPES_H_ */
