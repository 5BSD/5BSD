/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * USDT provider for warden(8), the Namespace (jail) capability provider.
 */
provider warden {
	/*
	 * One ENTER_JAIL request from `client`: jid is the jail id when warden
	 * created it here (-1 when a persistent jail was reused, or on failure),
	 * result is the reply status (0 = success, else errno).
	 */
	probe enter(const char *client, int jid, int result);
	/* One reconcile pass (when: 0 boot, 1 timer); counts as libcapreclaim. */
	probe reclaim_pass(int when, uint32_t live, uint32_t owned,
	    uint32_t orphans, uint32_t destroyed, uint32_t failed);
};
