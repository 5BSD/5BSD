/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef _BLUED_HOGP_REPORT_H_
#define _BLUED_HOGP_REPORT_H_

#include <stddef.h>
#include <stdint.h>

/* HOGP 1.1.1 §4.6 Report Reference descriptor Report Type values. */
#define HID_REPORT_TYPE_INPUT		0x01
#define HID_REPORT_TYPE_OUTPUT		0x02
#define HID_REPORT_TYPE_FEATURE		0x03

struct hogp_report {
	uint16_t	value_handle;
	uint16_t	cccd_handle;
	uint8_t		report_id;
	uint8_t		report_type;
};

#define HOGP_MAX_REPORTS	16

uint16_t hogp_find_report_handle(const struct hogp_report *, int, uint8_t,
    uint8_t);

#endif /* _BLUED_HOGP_REPORT_H_ */
