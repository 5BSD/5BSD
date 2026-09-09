/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "hogp_report.h"

/*
 * Report Type disposal.  HIDS 1.1 §2.5.3.2 Table 2.7 assigns 0x01/0x02/0x03
 * and marks 0x00 Prohibited, 0x04-0xFF RFU.  A Report characteristic whose
 * Report Reference descriptor could not be read, or carries a value outside
 * the assigned range, cannot be classified and must not be retained: it would
 * sit in the table matching no branch, subscribed to nothing.
 */
bool
hogp_report_type_is_valid(uint8_t report_type)
{

	return (report_type == HID_REPORT_TYPE_INPUT ||
	    report_type == HID_REPORT_TYPE_OUTPUT ||
	    report_type == HID_REPORT_TYPE_FEATURE);
}

/*
 * Count the Input Reports that can actually deliver data: HIDS Table 2.4
 * makes Notify mandatory for an Input Report, and HOGP §4.8 has the Report
 * Host enable notifications through the Client Characteristic Configuration
 * descriptor, so an Input Report with no CCCD is unreachable.
 */
int
hogp_count_usable_input_reports(const struct hogp_report *reports, int nreports)
{
	int i, limit, n = 0;

	if (reports == NULL || nreports <= 0)
		return (0);
	limit = nreports < HOGP_MAX_REPORTS ? nreports : HOGP_MAX_REPORTS;
	for (i = 0; i < limit; i++) {
		if (reports[i].report_type == HID_REPORT_TYPE_INPUT &&
		    reports[i].cccd_handle != 0)
			n++;
	}
	return (n);
}

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

/*
 * Instance-scoped lookup.  The unscoped form above is only unambiguous
 * because hogp_instance_conflicts() refuses to admit a second HID Service
 * instance that reuses a (Report Type, Report ID) pair; where the caller
 * knows the instance it should say so.
 */
uint16_t
hogp_find_report_handle_instance(const struct hogp_report *reports,
    int nreports, uint8_t report_id, uint8_t report_type, uint8_t instance)
{
	int i, limit;

	if (reports == NULL || nreports <= 0)
		return (0);
	limit = nreports < HOGP_MAX_REPORTS ? nreports : HOGP_MAX_REPORTS;
	for (i = 0; i < limit; i++) {
		if (reports[i].instance == instance &&
		    reports[i].report_type == report_type &&
		    reports[i].report_id == report_id)
			return (reports[i].value_handle);
	}
	return (0);
}

/*
 * Decide whether a candidate HID Service instance's report table can share
 * one virtual HID device with the instances already admitted.
 *
 * Two conditions make sharing unsafe, and both are legal on a conformant
 * non-HID-ISO composite device (HOGP §2.5 sanctions multiple HID Service
 * instances; §3.1.6 requires device-wide Report ID uniqueness only for the
 * HID ISO feature):
 *
 *   1. A (Report Type, Report ID) pair that both instances use.  Outbound
 *      routing resolves by Report ID, so the LED write for one instance's
 *      keyboard would reach the other instance's Output Report.
 *   2. Disagreement about whether Report IDs are in use at all.  The
 *      inbound prepend / outbound strip of the ID octet (HOGP §4.8.1) is a
 *      per-HID-device property, so mixing a numbered instance with an
 *      unnumbered one mis-frames one of the two.
 */
bool
hogp_instance_conflicts(const struct hogp_report *accepted, int naccepted,
    const struct hogp_report *cand, int ncand)
{
	int i, j;
	bool accepted_numbered = false, cand_numbered = false;

	if (accepted == NULL || naccepted <= 0 || cand == NULL || ncand <= 0)
		return (false);

	for (i = 0; i < naccepted; i++) {
		if (accepted[i].report_id != 0)
			accepted_numbered = true;
		for (j = 0; j < ncand; j++) {
			if (accepted[i].report_type == cand[j].report_type &&
			    accepted[i].report_id == cand[j].report_id)
				return (true);
		}
	}
	for (j = 0; j < ncand; j++)
		if (cand[j].report_id != 0)
			cand_numbered = true;

	return (accepted_numbered != cand_numbered);
}
