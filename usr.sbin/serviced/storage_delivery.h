/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#ifndef SERVICED_STORAGE_DELIVERY_H
#define SERVICED_STORAGE_DELIVERY_H

#include <sys/types.h>
#include <sys/zfshandle.h>

#include <stdbool.h>
#include <stdint.h>

enum storage_delivery_kind {
	STORAGE_DELIVERY_PRIVATE = 0,
	STORAGE_DELIVERY_DIRECTORY,
	STORAGE_DELIVERY_ZFSHANDLE
};

static inline enum storage_delivery_kind
storage_delivery_select(uint64_t rights, bool descriptor_backing)
{

	if (descriptor_backing)
		return (STORAGE_DELIVERY_PRIVATE);
	if (rights == ZH_MOUNT)
		return (STORAGE_DELIVERY_DIRECTORY);
	return (STORAGE_DELIVERY_ZFSHANDLE);
}

#endif
