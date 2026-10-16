/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_AMD_NESTED_SVM_L2_MSR_H_
#define _VMM_AMD_NESTED_SVM_L2_MSR_H_

#include <sys/types.h>

#ifndef _KERNEL
#include <stdbool.h>
#include <stdint.h>
#endif

/* Read only MSRs whose live L2 values reside in the saved VMCB02 image. */
bool svm_nested_l2_vmcb_msr_read(const void *vmcb02, uint32_t msr,
    uint64_t host_tsc, uint64_t *value);
bool svm_nested_l2_pat_valid(uint64_t value);
enum svm_nested_l2_msr_write_result {
	SVM_NESTED_L2_MSR_UNSUPPORTED,
	SVM_NESTED_L2_MSR_APPLIED,
	SVM_NESTED_L2_MSR_GP,
};
enum svm_nested_l2_msr_write_result svm_nested_l2_vmcb_msr_write(
    void *vmcb02, uint32_t msr, uint64_t value);
enum svm_nested_l2_msr_write_result svm_nested_l2_efer_write(
    void *vmcb02, uint64_t value, bool nx, bool ffxsr, bool tce);

#endif /* _VMM_AMD_NESTED_SVM_L2_MSR_H_ */
