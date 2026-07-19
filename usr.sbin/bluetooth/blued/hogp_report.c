/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "hogp_report.h"

uint16_t
hogp_find_report_handle(const struct hogp_report *reports, int nreports,
    uint8_t report_id, uint8_t report_type)
{
	int i, limit;

	if (reports == NULL || nreports <= 0)
		return (0);
	limit = nreports < HOGP_MAX_REPORTS ? nreports : HOGP_MAX_REPORTS;
	for (i = 0; i < limit; i++) {
		if (reports[i].report_type == report_type &&
		    reports[i].report_id == report_id)
			return (reports[i].value_handle);
	}
	return (0);
}
