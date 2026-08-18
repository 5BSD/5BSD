/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/*
 * USDT provider for the Casper cap_netdb service.  cap_netdb imposes no
 * per-command allow/deny limits, so its observability point is the command
 * dispatch itself: the command probe records which netdb operation a
 * sandboxed process invoked and its result (error == 0 -> success).
 */
provider cap_netdb {
	/* Final result of a dispatched command (error == 0 -> success). */
	probe command(const char *cmd, int error);
};
