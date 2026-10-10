/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _BSDPRESSURE_H_
#define _BSDPRESSURE_H_
#include <stdint.h>
struct pressure_filter {
	unsigned level, recovery;
};
unsigned pressure_update(struct pressure_filter *, int, uint32_t, uint32_t,
    uint32_t);
#endif
