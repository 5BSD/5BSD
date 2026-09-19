/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * USDT provider for BSDPower(8), the system.Power capability provider.
 */
provider bsdpower {
	/* One request from `client`: opcode, and the reply status (0 or errno). */
	probe request(const char *client, int opcode, int status);
	/* A successful suspend request to sleep state SN -- audit-worthy. */
	probe suspend(const char *client, int state);
};
