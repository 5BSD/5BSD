/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef BLUED_CONTROLLER_PROTOCOL_H
#define BLUED_CONTROLLER_PROTOCOL_H
#include <stdint.h>
#define BLUED_CONTROLLER_SERVICE "system.Bluetooth.Controller"
#define BLUED_CONTROLLER_MAGIC UINT32_C(0x35424331)
#define BLUED_CONTROLLER_OPEN UINT64_C(1)
struct blued_controller_request {
	uint32_t magic;
	uint32_t reserved;
	char adapter[32];
};
struct blued_controller_reply {
	uint32_t magic;
	int32_t error;
};
#endif
