/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>

#include <time.h>

#include <lwip/sys.h>

uint32_t
sys_now(void)
{
	struct timespec now;
	uint64_t milliseconds;

	if (clock_gettime(CLOCK_MONOTONIC_FAST, &now) == -1)
		abort();
	milliseconds = (uint64_t)now.tv_sec * 1000 +
	    (uint64_t)now.tv_nsec / 1000000;
	return ((uint32_t)milliseconds);
}

uint32_t
sys_jiffies(void)
{

	return (sys_now());
}
