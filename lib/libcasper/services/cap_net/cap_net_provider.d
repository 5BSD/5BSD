/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/*
 * USDT provider for the Casper cap_net service.  Each allow-* probe exposes a
 * capability-mediated network decision made on behalf of a sandboxed process:
 * whether a requested mode, address family, host/service, or raw socket
 * address matched the channel's limits.  The stage-* probes expose entries
 * added to a cap_net_limit builder before cap_net_limit() submits it.
 */
provider cap_net {
	/* Mode-permission check: requested mode bits, allow/deny (1/0). */
	probe allow__mode(uint64_t mode, int allowed);
	/* Address-family check: family, allow/deny (1/0). */
	probe allow__family(int family, int allowed);
	/* Host/service allow-list check: host, service, allow/deny (1/0). */
	probe allow__host(const char *host, const char *serv, int allowed);
	/* Raw sockaddr allow-list check: sockaddr length, allow/deny (1/0). */
	probe allow__addr(int saddrsize, int allowed);
	/* A builder staged an allowed capability mode. */
	probe stage__mode(uint64_t mode);
	/* A builder staged an allowed host/service entry. */
	probe stage__host(const char *host, const char *serv);
};
