/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _DEV_VIRTIO_INPUT_VIRTIO_INPUT_H_
#define	_DEV_VIRTIO_INPUT_VIRTIO_INPUT_H_

#include <sys/types.h>

#define	VIRTIO_INPUT_CFG_UNSET		0x00
#define	VIRTIO_INPUT_CFG_ID_NAME	0x01
#define	VIRTIO_INPUT_CFG_ID_SERIAL	0x02
#define	VIRTIO_INPUT_CFG_ID_DEVIDS	0x03
#define	VIRTIO_INPUT_CFG_PROP_BITS	0x10
#define	VIRTIO_INPUT_CFG_EV_BITS	0x11
#define	VIRTIO_INPUT_CFG_ABS_INFO	0x12

struct virtio_input_absinfo {
	uint32_t min;
	uint32_t max;
	uint32_t fuzz;
	uint32_t flat;
	uint32_t res;
} __packed;

struct virtio_input_devids {
	uint16_t bustype;
	uint16_t vendor;
	uint16_t product;
	uint16_t version;
} __packed;

struct virtio_input_config {
	uint8_t select;
	uint8_t subsel;
	uint8_t size;
	uint8_t reserved[5];
	union {
		char string[128];
		uint8_t bitmap[128];
		struct virtio_input_absinfo abs;
		struct virtio_input_devids ids;
	} u;
} __packed;

struct virtio_input_event {
	uint16_t type;
	uint16_t code;
	uint32_t value;
} __packed;

#endif /* _DEV_VIRTIO_INPUT_VIRTIO_INPUT_H_ */
