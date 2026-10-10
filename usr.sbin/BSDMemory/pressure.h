/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _BSDMEMORY_PRESSURE_H_
#define _BSDMEMORY_PRESSURE_H_
#include <stdint.h>
#include <stdbool.h>
struct pressure_filter {
	unsigned level, recovery, effective;
	bool have_sample;
};
unsigned pressure_update(struct pressure_filter *, int, uint32_t, uint32_t,
    uint32_t);
#endif
