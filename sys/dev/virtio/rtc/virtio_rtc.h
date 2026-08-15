/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _VIRTIO_RTC_H_
#define	_VIRTIO_RTC_H_

#include <sys/types.h>

#define	VIRTIO_RTC_F_ALARM			(1ULL << 0)

#define	VIRTIO_RTC_REQ_READ			0x0001
#define	VIRTIO_RTC_REQ_READ_CROSS		0x0002
#define	VIRTIO_RTC_REQ_CFG			0x1000
#define	VIRTIO_RTC_REQ_CLOCK_CAP		0x1001
#define	VIRTIO_RTC_REQ_CROSS_CAP		0x1002
#define	VIRTIO_RTC_REQ_READ_ALARM		0x1003
#define	VIRTIO_RTC_REQ_SET_ALARM		0x1004
#define	VIRTIO_RTC_REQ_SET_ALARM_ENABLED	0x1005

#define	VIRTIO_RTC_S_OK			0
#define	VIRTIO_RTC_S_EOPNOTSUPP		2
#define	VIRTIO_RTC_S_ENODEV		3
#define	VIRTIO_RTC_S_EINVAL		4
#define	VIRTIO_RTC_S_EIO		5

#define	VIRTIO_RTC_CLOCK_UTC			0
#define	VIRTIO_RTC_CLOCK_TAI			1
#define	VIRTIO_RTC_CLOCK_MONOTONIC		2
#define	VIRTIO_RTC_CLOCK_UTC_SMEARED		3
#define	VIRTIO_RTC_CLOCK_UTC_MAYBE_SMEARED	4

#define	VIRTIO_RTC_SMEAR_UNSPECIFIED		0

#define	VIRTIO_RTC_COUNTER_ARM_VCT		0
#define	VIRTIO_RTC_COUNTER_X86_TSC		1
#define	VIRTIO_RTC_COUNTER_INVALID		0xff

#define	VIRTIO_RTC_FLAG_ALARM_CAP		(1U << 0)
#define	VIRTIO_RTC_FLAG_ALARM_ENABLED		(1U << 0)
#define	VIRTIO_RTC_FLAG_CROSS_CAP		(1U << 0)
#define	VIRTIO_RTC_NOTIF_ALARM			0x2000

struct virtio_rtc_req_head {
	uint16_t msg_type;
	uint8_t reserved[6];
} __packed;

struct virtio_rtc_resp_head {
	uint8_t status;
	uint8_t reserved[7];
} __packed;

struct virtio_rtc_req_read {
	struct virtio_rtc_req_head head;
	uint16_t clock_id;
	uint8_t reserved[6];
} __packed;

struct virtio_rtc_resp_read {
	struct virtio_rtc_resp_head head;
	uint64_t clock_reading;
} __packed;

struct virtio_rtc_req_read_cross {
	struct virtio_rtc_req_head head;
	uint16_t clock_id;
	uint8_t hw_counter;
	uint8_t reserved[5];
} __packed;

struct virtio_rtc_resp_read_cross {
	struct virtio_rtc_resp_head head;
	uint64_t clock_reading;
	uint64_t counter_cycles;
} __packed;

struct virtio_rtc_req_cfg {
	struct virtio_rtc_req_head head;
} __packed;

struct virtio_rtc_resp_cfg {
	struct virtio_rtc_resp_head head;
	uint16_t num_clocks;
	uint8_t reserved[6];
} __packed;

struct virtio_rtc_req_clock_cap {
	struct virtio_rtc_req_head head;
	uint16_t clock_id;
	uint8_t reserved[6];
} __packed;

struct virtio_rtc_resp_clock_cap {
	struct virtio_rtc_resp_head head;
	uint8_t type;
	uint8_t leap_second_smearing;
	uint8_t flags;
	uint8_t reserved[5];
} __packed;

struct virtio_rtc_req_cross_cap {
	struct virtio_rtc_req_head head;
	uint16_t clock_id;
	uint8_t hw_counter;
	uint8_t reserved[5];
} __packed;

struct virtio_rtc_resp_cross_cap {
	struct virtio_rtc_resp_head head;
	uint8_t flags;
	uint8_t reserved[7];
} __packed;

struct virtio_rtc_req_read_alarm {
	struct virtio_rtc_req_head head;
	uint16_t clock_id;
	uint8_t reserved[6];
} __packed;

struct virtio_rtc_resp_read_alarm {
	struct virtio_rtc_resp_head head;
	uint64_t alarm_time;
	uint8_t flags;
	uint8_t reserved[7];
} __packed;

struct virtio_rtc_req_set_alarm {
	struct virtio_rtc_req_head head;
	uint64_t alarm_time;
	uint16_t clock_id;
	uint8_t flags;
	uint8_t reserved[5];
} __packed;

struct virtio_rtc_req_set_alarm_enabled {
	struct virtio_rtc_req_head head;
	uint16_t clock_id;
	uint8_t flags;
	uint8_t reserved[5];
} __packed;

struct virtio_rtc_notif_head {
	uint16_t msg_type;
	uint8_t reserved[6];
} __packed;

struct virtio_rtc_notif_alarm {
	struct virtio_rtc_notif_head head;
	uint16_t clock_id;
	uint8_t reserved[6];
} __packed;

#endif /* _VIRTIO_RTC_H_ */
