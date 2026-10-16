/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_AMD_NESTED_SVM_EXIT_POLICY_H_
#define _VMM_AMD_NESTED_SVM_EXIT_POLICY_H_

#include <sys/types.h>

#ifndef _KERNEL
#include <stdbool.h>
#include <stdint.h>
#endif

struct svm_nested_bitmap_reader;
struct svm_nested_vmcb12_view;

enum svm_nested_l2_l0_action {
	SVM_NESTED_L2_ROUTE,
	SVM_NESTED_L2_RESUME,
	SVM_NESTED_L2_REPORT_L0,
	SVM_NESTED_L2_MACHINE_CHECK,
	SVM_NESTED_L2_FAIL_L0,
};

enum svm_nested_l2_l0_action svm_nested_l2_l0_exit_action(uint64_t);
void svm_nested_l2_l0_exit_info(uint64_t, uint64_t *, uint64_t *);

enum svm_nested_l0_debug_action {
	SVM_NESTED_L0_DEBUG_NONE,
	SVM_NESTED_L0_DEBUG_STEP,
	SVM_NESTED_L0_DEBUG_PUSHF,
	SVM_NESTED_L0_DEBUG_POPF,
};

enum svm_nested_l0_debug_action svm_nested_l0_debug_exit(uint64_t,
    uint32_t, uint32_t, bool, bool);

enum svm_nested_synthetic_action {
	SVM_NESTED_SYNTHETIC_REPLAY,
	SVM_NESTED_SYNTHETIC_INJECT,
	SVM_NESTED_SYNTHETIC_REFLECT,
};

struct svm_nested_synthetic_exception {
	enum svm_nested_synthetic_action action;
	uint64_t eventinj;
	uint64_t exitcode;
	uint64_t exitinfo1;
};

int svm_nested_synthetic_exception_prepare(uint32_t, uint64_t, uint64_t,
    uint8_t, bool, uint32_t, struct svm_nested_synthetic_exception *);

/* Report only intercepts requested by L1; L0 may have forced others. */
int svm_nested_exit_intercepted(const struct svm_nested_vmcb12_view *,
    const struct svm_nested_bitmap_reader *, uint64_t, uint64_t,
    uint32_t, bool *);

#endif /* _VMM_AMD_NESTED_SVM_EXIT_POLICY_H_ */
