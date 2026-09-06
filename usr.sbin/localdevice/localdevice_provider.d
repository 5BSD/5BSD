/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * USDT probes for localdevice(8), the system.Device capability provider.
 */

provider localdevice {
	/*
	 * An OPEN was resolved for a client label: the requested /dev leaf, the
	 * rights actually granted (request intersected with policy; 0 on denial),
	 * and the errno (0 on success).
	 */
	probe open(const char *label, const char *device, uint32_t granted,
	    int error);
	/*
	 * A LIST page was produced for a client label: the requested cursor, the
	 * number of entries filled, and the errno (0 on success).
	 */
	probe list(const char *label, uint32_t cursor, uint32_t count,
	    int error);
};
