/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * USDT provider for BSDTime(8), the system.Time capability provider.
 */
provider bsdtime {
	/* One request from `client`: opcode, and the reply status (0 or errno). */
	probe request(const char *client, int opcode, int status);
	/* A successful clock step (clock_settime) -- audit-worthy. */
	probe clock__set(const char *client, int64_t sec, int nsec);
	/* A successful clock slew (adjtime), delta in nanoseconds. */
	probe clock__adjust(const char *client, int64_t nsec);
};
