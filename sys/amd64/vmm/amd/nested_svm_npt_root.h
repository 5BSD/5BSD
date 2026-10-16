/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VMM_AMD_NESTED_SVM_NPT_ROOT_H_
#define	_VMM_AMD_NESTED_SVM_NPT_ROOT_H_

#include <sys/types.h>

struct svm_nested_npt_root;
struct svm_nested_npt_result;
struct vcpu;
struct pmap;

int	svm_nested_npt_root_create(uint64_t, struct svm_nested_npt_root **);
void	svm_nested_npt_root_destroy(struct svm_nested_npt_root *);
int	svm_nested_npt_root_clear(struct svm_nested_npt_root *);
int	svm_nested_npt_root_populate(struct svm_nested_npt_root *,
	    struct vcpu *, uint64_t, uint64_t, uint8_t, uint8_t);
uint64_t svm_nested_npt_root_pa(const struct svm_nested_npt_root *);
struct pmap *svm_nested_npt_root_pmap(struct svm_nested_npt_root *);
int	svm_nested_npt_root_translate(struct svm_nested_npt_root *,
	    struct vcpu *, uint64_t, uint64_t, uint8_t, uint8_t, bool, bool,
	    struct svm_nested_npt_result *);
int	svm_nested_npt_root_resolve(struct svm_nested_npt_root *,
	    struct vcpu *, uint64_t, uint64_t, uint8_t, uint8_t, bool,
	    struct svm_nested_npt_result *);

#endif /* _VMM_AMD_NESTED_SVM_NPT_ROOT_H_ */
