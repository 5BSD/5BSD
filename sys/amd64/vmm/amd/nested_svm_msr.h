/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_AMD_NESTED_SVM_MSR_H_
#define	_VMM_AMD_NESTED_SVM_MSR_H_

#include <sys/types.h>

#ifndef _KERNEL
#include <stdbool.h>
#include <stdint.h>
#endif

/* Per-vCPU guest-visible SVM state; physical EFER.SVME stays set for L0. */
struct svm_nested_msr_state {
	uint64_t hsave_gpa;
	uint64_t vm_cr;
	bool	 exposed;
	bool	 svme;
};

void	svm_nested_msr_state_init(struct svm_nested_msr_state *);
void	svm_nested_msr_init_signal(struct svm_nested_msr_state *);
int	svm_nested_msr_exposure_set(struct svm_nested_msr_state *, int,
	    bool);
bool	svm_nested_msr_state_valid(const struct svm_nested_msr_state *,
	    uint8_t);
uint64_t svm_nested_msr_efer_read(const struct svm_nested_msr_state *,
	    uint64_t);
bool	svm_nested_msr_efer_write_allowed(const struct svm_nested_msr_state *,
	    uint64_t);
void	svm_nested_msr_efer_import(struct svm_nested_msr_state *, uint64_t);
bool	svm_nested_msr_hsave_write(struct svm_nested_msr_state *, uint64_t,
	    uint8_t);
bool	svm_nested_msr_vmcr_write(struct svm_nested_msr_state *, uint64_t);

#endif /* _VMM_AMD_NESTED_SVM_MSR_H_ */
