/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_AMD_NESTED_SVM_REFLECT_H_
#define _VMM_AMD_NESTED_SVM_REFLECT_H_

#include <sys/types.h>

#ifndef _KERNEL
#include <stdbool.h>
#endif

/* Copy only hardware #VMEXIT writeback fields from VMCB02 to VMCB12. */
void svm_nested_vmcb_exit_copy(void *, const void *, bool, bool);
void svm_nested_vmcb_shutdown_copy(void *);
void svm_nested_vmcb_checkpoint_copy(void *, const void *, const void *,
    bool, bool);

#endif /* _VMM_AMD_NESTED_SVM_REFLECT_H_ */
