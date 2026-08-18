/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/*
 * USDT provider for the Casper cap_sysctl service.  Each probe exposes a
 * capability-mediated decision: whether a requested sysctl (by name or MIB)
 * matched the channel's allow-list (allow), and which sysctl names/MIBs were
 * staged in a limit builder before cap_sysctl_limit() submits it (stage-*).
 */
provider cap_sysctl {
	/* Name allow-list check: sysctl name ("<mib>" if MIB-only), allow/deny. */
	probe allow(const char *name, int allowed);
	/* A builder staged a named sysctl (operation = flags). */
	probe stage__name(const char *name, int operation);
	/* A builder staged a sysctl MIB (miblen, operation flags). */
	probe stage__mib(int miblen, int operation);
};
