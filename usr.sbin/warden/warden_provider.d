/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

provider warden {
	/*
	 * A retired consumer label's persistent jail was reclaimed
	 * (docs/capability-lifecycle-cleanup.md): the retired label, whether a
	 * jail was actually removed (1) or the label was already clean (0), and
	 * the trigger ("push" == the serviced control-channel notification,
	 * "sweep" == the periodic reconciliation backstop).
	 */
	probe reclaim(const char *label, int reclaimed, const char *reason);
};
