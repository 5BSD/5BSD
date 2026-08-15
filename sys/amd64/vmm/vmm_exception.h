/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _AMD64_VMM_VMM_EXCEPTION_H_
#define	_AMD64_VMM_VMM_EXCEPTION_H_

#include <sys/types.h>

#include <machine/vmm.h>

/*
 * Classify an architecturally delivered #DB from its current cause bits and
 * DR7.  Pass current-event cause bits rather than an accumulated DR6 image
 * when the virtualization transport exposes them separately.
 */
enum vm_exception_class vm_debug_exception_class(uint64_t cause,
    uint64_t dr7);

#endif /* _AMD64_VMM_VMM_EXCEPTION_H_ */
