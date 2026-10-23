/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/errno.h>

#ifndef _KERNEL
#include <stdint.h>
#endif

#include "nested_svm_bitmap.h"

#define SVM_NESTED_IOPM_BYTES  (3 * 4096U)
#define SVM_NESTED_MSRPM_BYTES (2 * 4096U)
#define SVM_NESTED_MSR_REGION_SIZE 0x2000U

static int
svm_nested_bitmap_read(const struct svm_nested_bitmap_reader *reader,
    uint64_t base, uint32_t offset, uint32_t length, uint8_t *value)
{

	if (reader == NULL || reader->read8 == NULL || value == NULL ||
	    offset >= length || base > ~(uint64_t)0 - offset)
		return (EINVAL);
	return (reader->read8(reader->arg, base + offset, value));
}

/* The 64K+3-bit IOPM also covers bytes crossing beyond port 0xffff. */
int
svm_nested_iopm_intercepts(const struct svm_nested_bitmap_reader *reader,
    uint64_t base, uint16_t port, uint8_t bytes, bool *intercept)
{
	uint32_t bit;
	uint8_t value;
	int error;

	if (intercept == NULL || (base & 0xfff) != 0 ||
	    (bytes != 1 && bytes != 2 && bytes != 4))
		return (EINVAL);
	*intercept = false;
	for (uint8_t i = 0; i < bytes; i++) {
		bit = (uint32_t)port + i;
		error = svm_nested_bitmap_read(reader, base, bit >> 3,
		    SVM_NESTED_IOPM_BYTES, &value);
		if (error != 0)
			return (error);
		if ((value & (1U << (bit & 7))) != 0) {
			*intercept = true;
			return (0);
		}
	}
	return (0);
}

/* MSRPM has three 2 KiB regions, with separate read and write bits. */
int
svm_nested_msrpm_intercepts(const struct svm_nested_bitmap_reader *reader,
    uint64_t base, uint32_t msr, bool write, bool *intercept)
{
	uint32_t index, offset;
	uint8_t value;
	int error;

	if (intercept == NULL || (base & 0xfff) != 0)
		return (EINVAL);
	if (msr < SVM_NESTED_MSR_REGION_SIZE) {
		index = msr;
	} else if (msr >= 0xc0000000U && msr < 0xc0002000U) {
		index = SVM_NESTED_MSR_REGION_SIZE +
		    (msr - 0xc0000000U);
	} else if (msr >= 0xc0010000U && msr < 0xc0012000U) {
		index = 2 * SVM_NESTED_MSR_REGION_SIZE +
		    (msr - 0xc0010000U);
	} else {
		/* Out-of-range MSRs always intercept independently of MSRPM. */
		*intercept = true;
		return (0);
	}
	offset = index >> 2;
	error = svm_nested_bitmap_read(reader, base, offset,
	    SVM_NESTED_MSRPM_BYTES, &value);
	if (error != 0)
		return (error);
	*intercept = (value & (1U << (2 * (index & 3) + (write ? 1 : 0))))
	    != 0;
	return (0);
}
