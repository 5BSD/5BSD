/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_AMD_NESTED_SVM_OPERAND_H_
#define _VMM_AMD_NESTED_SVM_OPERAND_H_

#include <sys/types.h>

#ifndef _KERNEL
#include <stdint.h>
#endif

/* Opcode suffix: VMRUN D8, VMLOAD DA, VMSAVE DB (0F 01 xx). */
int svm_nested_operand_gpa(const uint8_t *, size_t, uint8_t, uint8_t,
    uint64_t, uint64_t *);

#endif /* _VMM_AMD_NESTED_SVM_OPERAND_H_ */
