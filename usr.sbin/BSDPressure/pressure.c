/* SPDX-License-Identifier: BSD-2-Clause */
#include <notify_pressure.h>

#include "pressure.h"
unsigned
pressure_update(struct pressure_filter *filter, int error, uint32_t free_pages,
    uint32_t minimum, uint32_t target)
{
	unsigned next;
	if (error != 0 || minimum == 0 || target < minimum) {
		filter->recovery = 0;
		return (filter->level = NOTIFY_PRESSURE_UNKNOWN);
	}
	next = free_pages <= minimum ? NOTIFY_PRESSURE_CRITICAL :
	    free_pages <= target     ? NOTIFY_PRESSURE_WARNING :
				       NOTIFY_PRESSURE_NORMAL;
	if (filter->level == NOTIFY_PRESSURE_UNKNOWN || next >= filter->level) {
		filter->recovery = 0;
		filter->level = next;
	} else if (++filter->recovery == 3) {
		filter->recovery = 0;
		filter->level = next;
	}
	return (filter->level);
}
