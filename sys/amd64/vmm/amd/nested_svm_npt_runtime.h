/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_AMD_NESTED_SVM_NPT_RUNTIME_H_
#define	_VMM_AMD_NESTED_SVM_NPT_RUNTIME_H_

#include "nested_svm_npt.h"

struct vcpu;

struct svm_nested_npt_runtime {
	struct vcpu *vcpu;
	struct svm_nested_npt_memory memory;
};

int	svm_nested_npt_runtime_init(struct svm_nested_npt_runtime *,
	    struct vcpu *);

#endif /* _VMM_AMD_NESTED_SVM_NPT_RUNTIME_H_ */
