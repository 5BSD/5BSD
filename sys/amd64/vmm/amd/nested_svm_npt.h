/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_AMD_NESTED_SVM_NPT_H_
#define	_VMM_AMD_NESTED_SVM_NPT_H_

#include <sys/types.h>

#ifndef _KERNEL
#include <stdbool.h>
#include <stdint.h>
#endif

#define	SVM_NESTED_NPT_READ	0x01U
#define	SVM_NESTED_NPT_WRITE	0x02U
#define	SVM_NESTED_NPT_EXECUTE	0x04U

enum svm_nested_npt_outcome {
	SVM_NESTED_NPT_TRANSLATED,
	SVM_NESTED_NPT_VIOLATION,
	SVM_NESTED_NPT_RESERVED,
};

struct svm_nested_npt_memory {
	int (*read64)(void *, uint64_t, uint64_t *);
	int (*compare_exchange64)(void *, uint64_t, uint64_t,
	    uint64_t, uint64_t *);
	void *arg;
};

struct svm_nested_npt_walk {
	uint64_t root_gpa;
	uint64_t l2_gpa;
	uint8_t physical_width;
	uint8_t access;
	bool allow_1g_pages;
};

struct svm_nested_npt_result {
	enum svm_nested_npt_outcome outcome;
	uint64_t l1_gpa;
	uint64_t entry_gpa[4];
	uint64_t entry[4];
	uint64_t ad_desired[4];
	uint8_t count;
	uint8_t level;
	uint8_t page_shift;
	uint8_t permissions;
};

int	svm_nested_npt_software_access(bool, bool, bool, bool,
	    uint8_t *, uint64_t *);
int	svm_nested_npt_walk(const struct svm_nested_npt_walk *,
	    const struct svm_nested_npt_memory *, struct svm_nested_npt_result *);
int	svm_nested_npt_commit_ad(const struct svm_nested_npt_result *,
	    const struct svm_nested_npt_memory *);
int	svm_nested_npt_reflect_info1(const struct svm_nested_npt_result *,
	    uint64_t, uint64_t *);

#endif /* _VMM_AMD_NESTED_SVM_NPT_H_ */
