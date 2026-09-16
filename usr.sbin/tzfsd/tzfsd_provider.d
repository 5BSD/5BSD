/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

provider tzfsd {
	/* A request message arrived: wire length, fd count. */
	probe request__msg(uint64_t, int);
	/* Storage request validated: op, deliver, rights, lifetime, ok(1)/reject(0). */
	probe request__validate(uint16_t, uint8_t, uint32_t, uint16_t, int);
	/* grant() returned: op, deliver, resulting handle fd, errno. */
	probe request__grant(uint16_t, uint8_t, int, int);
	/* About to reply: op, final status, delivered handle fd. */
	probe request__reply(uint16_t, int, int);
};
