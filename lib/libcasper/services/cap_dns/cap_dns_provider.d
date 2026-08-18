/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/*
 * USDT provider for the Casper cap_dns service.  Each probe exposes a
 * capability-mediated decision: whether a requested resolver operation type
 * or address family matched the channel's allow-list (allow-*), which
 * types/families a channel narrowed its limits to (limit-*), and the final
 * result of a dispatched command (command; error == 0 -> success).
 */
provider cap_dns {
	/* Resolver-type allow-list check: type, allow/deny (1/0). */
	probe allow__type(const char *type, int allowed);
	/* Address-family allow-list check: family, allow/deny (1/0). */
	probe allow__family(int family, int allowed);
	/* A channel narrowed the set of allowed resolver types. */
	probe limit__type(const char *type);
	/* A channel narrowed the set of allowed address families. */
	probe limit__family(int family);
	/* Final result of a dispatched command (error == 0 -> success). */
	probe command(const char *cmd, int error);
};
