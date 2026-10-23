/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_AMD_NESTED_SVM_BITMAP_H_
#define _VMM_AMD_NESTED_SVM_BITMAP_H_

#include <sys/types.h>

#ifndef _KERNEL
#include <stdbool.h>
#include <stdint.h>
#endif

/* The callback reads one byte at an L1 guest physical address. */
struct svm_nested_bitmap_reader {
	int (*read8)(void *, uint64_t, uint8_t *);
	void *arg;
};

int svm_nested_iopm_intercepts(const struct svm_nested_bitmap_reader *,
    uint64_t, uint16_t, uint8_t, bool *);
int svm_nested_msrpm_intercepts(const struct svm_nested_bitmap_reader *,
    uint64_t, uint32_t, bool, bool *);

#endif /* _VMM_AMD_NESTED_SVM_BITMAP_H_ */
