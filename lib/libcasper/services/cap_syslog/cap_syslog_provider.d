/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/*
 * USDT provider for the Casper cap_syslog service.  cap_syslog imposes no
 * per-command allow/deny limits, so its observability point is the command
 * dispatch itself: the command probe records which syslog operation a
 * sandboxed process invoked and its result (error == 0 -> handled).
 */
provider cap_syslog {
	/* Final result of a dispatched command (error == 0 -> handled). */
	probe command(const char *cmd, int error);
};
