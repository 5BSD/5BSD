/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef _BLUED_HOGP_REPORT_H_
#define _BLUED_HOGP_REPORT_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Report Type values of the Report Reference characteristic descriptor.
 *
 * HID Service 1.1 §2.5.3.2, Table 2.7.  (The values are owned by HIDS, not
 * by HOGP: HOGP §4.6 only requires the descriptor to be discovered.  Neither
 * is the GATT Specification Supplement a source here — it defines none of the
 * HID characteristics or descriptors.)  Table 2.7 marks 0x00 Prohibited and
 * 0x04-0xFF Reserved for Future Use, so HID_REPORT_TYPE_INPUT is the lowest
 * legal value and HID_REPORT_TYPE_FEATURE the highest.
 */
#define HID_REPORT_TYPE_INPUT		0x01
#define HID_REPORT_TYPE_OUTPUT		0x02
#define HID_REPORT_TYPE_FEATURE		0x03

/*
 * One Report characteristic of one HID Service instance.
 *
 * `instance' is the index of the HID Service instance (in primary-service
 * discovery order) that this Report characteristic belongs to.  HIDS §2.5.3.2
 * scopes Report ID uniqueness to a single HID Service; device-wide uniqueness
 * across instances is required only of HID-ISO devices (HOGP §3.1.6).  A
 * conformant composite device may therefore reuse a (Report Type, Report ID)
 * pair in a second instance, and routing that ignores `instance' would deliver
 * an outbound report to the wrong characteristic.
 */
struct hogp_report {
	uint16_t	value_handle;
	uint16_t	cccd_handle;
	uint8_t		report_id;
	uint8_t		report_type;
	uint8_t		instance;
};

#define HOGP_MAX_REPORTS	16

/*
 * Battery Service, Bluetooth SIG Assigned Numbers (16-bit UUID for members).
 * Spelled here so this unit does not depend on the daemon's private header.
 */
#define HOGP_UUID_BATTERY_SERVICE	0x180F

/* Upper bound on HID Service instances handled on one device. */
#define HOGP_MAX_HID_INSTANCES	4

uint16_t hogp_find_report_handle(const struct hogp_report *, int, uint8_t,
    uint8_t);
uint16_t hogp_find_report_handle_instance(const struct hogp_report *, int,
    uint8_t, uint8_t, uint8_t);
bool	hogp_report_type_is_valid(uint8_t);
int	hogp_count_usable_input_reports(const struct hogp_report *, int);
bool	hogp_instance_conflicts(const struct hogp_report *, int,
	    const struct hogp_report *, int);

/*
 * blued_central.c, declared here rather than kept file-static so the
 * daemon-wiring test harness can drive the two decisions that are only
 * observable at this level: whether a HID Service instance is admitted (and
 * with which reports), and whether subscription succeeds.
 */
struct att_conn;
struct gatt_discovery;
struct hogp_device;

int	hogp_process_service(struct hogp_device *, struct gatt_discovery *,
	    int);
int	hogp_subscribe(struct hogp_device *);

/*
 * HOGP §4.5.3 relationship discovery: run the GATT Find Included Services
 * sub-procedure over one HID Service and report the first included Battery
 * Service.  Returns 1 and fills *bas when one is found, 0 when the HID
 * Service includes none, and -1 on a discovery error.
 */
struct gatt_service;

int	hogp_find_included_battery(struct att_conn *,
	    const struct gatt_service *, struct gatt_service *);

#endif /* _BLUED_HOGP_REPORT_H_ */
