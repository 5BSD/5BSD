/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/errno.h>

#ifdef _KERNEL
#include <sys/systm.h>
#else
#include <stdint.h>
#include <string.h>
#endif

#include "nested_svm_npt.h"
#include "nested_svm_policy.h"

#define NPF_P       (1ULL << 0)
#define NPF_W       (1ULL << 1)
#define NPF_U       (1ULL << 2)
#define NPF_RSV     (1ULL << 3)
#define NPF_ID      (1ULL << 4)
#define NPF_GPA     (1ULL << 32)
#define NPF_GPT     (1ULL << 33)

#define	NPT_P		(1ULL << 0)
#define	NPT_RW		(1ULL << 1)
#define	NPT_US		(1ULL << 2)
#define	NPT_A		(1ULL << 5)
#define	NPT_D		(1ULL << 6)
#define	NPT_PS		(1ULL << 7)
#define	NPT_NX		(1ULL << 63)
#define	NPT_ADDRESS_MASK 0x000ffffffffff000ULL

/* Build the access and NPF flags used by a software L2 address walk. */
int
svm_nested_npt_software_access(bool guest_page_table, bool usermode,
    bool write, bool execute, uint8_t *access, uint64_t *info1)
{

	if (access == NULL || info1 == NULL || (write && execute))
		return (EINVAL);
	*access = guest_page_table || write ? SVM_NESTED_NPT_WRITE :
	    execute ? SVM_NESTED_NPT_EXECUTE : SVM_NESTED_NPT_READ;
	*info1 = guest_page_table ? NPF_GPT : NPF_GPA;
	if (guest_page_table || usermode)
		*info1 |= NPF_U;
	if (*access == SVM_NESTED_NPT_WRITE)
		*info1 |= NPF_W;
	if (*access == SVM_NESTED_NPT_EXECUTE)
		*info1 |= NPF_ID;
	return (0);
}

/*
 * Walk L1-owned NPT12 using L1 guest physical addresses.  This is read-only:
 * the frozen runtime must commit A/D bits and populate its own NPT02 leaf
 * before L2 can resume.  No L1 entry is ever installed in hardware directly.
 */
int
svm_nested_npt_walk(const struct svm_nested_npt_walk *walk,
    const struct svm_nested_npt_memory *memory,
    struct svm_nested_npt_result *result)
{
	struct svm_nested_npt_result candidate;
	uint64_t address, base, entry, entry_gpa, index, mask, table;
	uint8_t permissions, shift;
	int error, level;
	bool huge;

	if (walk == NULL || memory == NULL || memory->read64 == NULL ||
	    result == NULL || walk->physical_width < 32 ||
	    walk->physical_width > 52 ||
	    (walk->access != SVM_NESTED_NPT_READ &&
	    walk->access != SVM_NESTED_NPT_WRITE &&
	    walk->access != SVM_NESTED_NPT_EXECUTE) ||
	    (walk->root_gpa & 0xfff) != 0 ||
	    /* Four levels consume exactly 48 bits of the L2 address. */
	    walk->l2_gpa >= (1ULL << 48) ||
	    !svm_nested_guest_physical_range_valid(walk->root_gpa,
	    4096, walk->physical_width) ||
	    !svm_nested_guest_physical_range_valid(walk->l2_gpa,
	    1, walk->physical_width))
		return (EINVAL);

	memset(&candidate, 0, sizeof(candidate));
	table = walk->root_gpa;
	permissions = SVM_NESTED_NPT_READ | SVM_NESTED_NPT_WRITE |
	    SVM_NESTED_NPT_EXECUTE;
	for (level = 4; level >= 1; level--) {
		shift = 12 + (level - 1) * 9;
		index = (walk->l2_gpa >> shift) & 0x1ff;
		entry_gpa = table + index * sizeof(entry);
		if (!svm_nested_guest_physical_range_valid(entry_gpa,
		    sizeof(entry), walk->physical_width))
			return (EFAULT);
		error = memory->read64(memory->arg, entry_gpa, &entry);
		if (error != 0)
			return (error);
		candidate.entry_gpa[candidate.count] = entry_gpa;
		candidate.entry[candidate.count++] = entry;
		candidate.level = level;
		if ((entry & NPT_P) == 0) {
			candidate.outcome = SVM_NESTED_NPT_VIOLATION;
			*result = candidate;
			return (0);
		}
		address = entry & NPT_ADDRESS_MASK;
		mask = ((1ULL << walk->physical_width) - 1) &
		    NPT_ADDRESS_MASK;
		huge = (entry & NPT_PS) != 0 && level != 1;
		if ((address & ~mask) != 0 || (level == 4 && huge) ||
		    (level == 3 && huge && !walk->allow_1g_pages)) {
			candidate.outcome = SVM_NESTED_NPT_RESERVED;
			*result = candidate;
			return (0);
		}
		if (huge) {
			/* Huge-page PAT is bit 12; 13..shift-1 are MBZ. */
			mask = ((1ULL << shift) - 1) & ~0x1fffULL;
			if ((address & mask) != 0) {
				candidate.outcome = SVM_NESTED_NPT_RESERVED;
				*result = candidate;
				return (0);
			}
		}
		if ((entry & NPT_RW) == 0)
			permissions &= ~SVM_NESTED_NPT_WRITE;
		if ((entry & NPT_NX) != 0)
			permissions &= ~SVM_NESTED_NPT_EXECUTE;
		if ((entry & NPT_US) == 0)
			permissions = 0;
		candidate.permissions = permissions;
		if ((permissions & walk->access) == 0) {
			candidate.outcome = SVM_NESTED_NPT_VIOLATION;
			*result = candidate;
			return (0);
		}
		if (huge || level == 1) {
			shift = huge ? shift : 12;
			base = address & ~((1ULL << shift) - 1);
			candidate.l1_gpa = base |
			    (walk->l2_gpa & ((1ULL << shift) - 1));
			for (uint8_t i = 0; i < candidate.count; i++)
				candidate.ad_desired[i] =
				    candidate.entry[i] | NPT_A;
			if (walk->access == SVM_NESTED_NPT_WRITE)
				candidate.ad_desired[candidate.count - 1] |= NPT_D;
			candidate.page_shift = shift;
			candidate.outcome = SVM_NESTED_NPT_TRANSLATED;
			*result = candidate;
			return (0);
		}
		if (!svm_nested_guest_physical_range_valid(address, 4096,
		    walk->physical_width)) {
			candidate.outcome = SVM_NESTED_NPT_RESERVED;
			*result = candidate;
			return (0);
		}
		table = address;
	}
	return (EPROTO);
}

/*
 * Commit monotonic A/D updates before publishing the NPT02 alias.  If L1
 * changed any entry after the walk, leave the partial A/D bits in place and
 * ask the caller to walk again; no stale translation is returned as usable.
 */
int
svm_nested_npt_commit_ad(const struct svm_nested_npt_result *result,
    const struct svm_nested_npt_memory *memory)
{
	uint64_t observed;
	uint8_t i;
	int error;

	if (result == NULL || memory == NULL ||
	    memory->compare_exchange64 == NULL ||
	    result->outcome != SVM_NESTED_NPT_TRANSLATED ||
	    result->count == 0 || result->count > 4)
		return (EINVAL);
	for (i = 0; i < result->count; i++) {
		/* A no-op CAS still detects an L1 edit to a previously set A/D entry. */
		error = memory->compare_exchange64(memory->arg,
		    result->entry_gpa[i], result->entry[i],
		    result->ad_desired[i], &observed);
		if (error != 0)
			return (error);
		if (observed != result->entry[i])
			return (EAGAIN);
	}
	return (0);
}

/* Convert an NPT12 denial into the architectural L1 NPF error code. */
int
svm_nested_npt_reflect_info1(const struct svm_nested_npt_result *result,
    uint64_t hardware_info1, uint64_t *l1_info1)
{
	uint64_t info1;

	if (result == NULL || l1_info1 == NULL || result->count == 0 ||
	    result->count > 4 ||
	    (result->outcome != SVM_NESTED_NPT_VIOLATION &&
	    result->outcome != SVM_NESTED_NPT_RESERVED))
		return (EINVAL);
	info1 = hardware_info1 & (NPF_W | NPF_U | NPF_ID | NPF_GPA | NPF_GPT);
	if ((result->entry[result->count - 1] & NPT_P) != 0)
		info1 |= NPF_P;
	if (result->outcome == SVM_NESTED_NPT_RESERVED)
		info1 |= NPF_RSV;
	*l1_info1 = info1;
	return (0);
}
