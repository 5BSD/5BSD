/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_AMD_NESTED_SVM_MEMORY_H_
#define	_VMM_AMD_NESTED_SVM_MEMORY_H_

#include <sys/types.h>

struct vcpu;
struct vmcb;
struct svm_nested_bitmap_reader;

int	svm_nested_vmcb12_read(struct vcpu *, uint64_t, uint8_t,
	    struct vmcb *);
int	svm_nested_vmcb12_aux_save(struct vcpu *, uint64_t, uint8_t,
	    const struct vmcb *);
int	svm_nested_vmcb12_invalid_exit(struct vcpu *, uint64_t, uint8_t);
int	svm_nested_vmcb12_exit_write(struct vcpu *, uint64_t, uint8_t,
	    const struct vmcb *, bool, bool);
int	svm_nested_vmcb12_shutdown_write(struct vcpu *, uint64_t, uint8_t);
int	svm_nested_bitmap_reader_init(struct vcpu *,
	    struct svm_nested_bitmap_reader *);

#endif /* _VMM_AMD_NESTED_SVM_MEMORY_H_ */
