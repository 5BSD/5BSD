/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#ifndef _VMM_AMD_NESTED_SVM_AUX_H_
#define	_VMM_AMD_NESTED_SVM_AUX_H_

/* AMD APM 15.5.2, additional state moved by VMLOAD and VMSAVE. */
void	svm_nested_vmcb_aux_copy(void *, const void *);

#endif /* _VMM_AMD_NESTED_SVM_AUX_H_ */
