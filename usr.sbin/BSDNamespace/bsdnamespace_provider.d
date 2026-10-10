/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * USDT provider for bsdnamespace(8), the Namespace (jail) capability provider.
 */
provider bsdnamespace {
	/* Scalar wire operation/result and reply transport errno; no payloads. */
	probe request__done(uint32_t opcode, int status, int transport_error);
	/*
	 * One ENTER_JAIL request from `client`: jid is the jail id when bsdnamespace
	 * created it here (-1 when a persistent jail was reused, or on failure),
	 * result is the reply status (0 = success, else errno).
	 */
	probe enter(const char *client, int jid, int result);
	/* One reconcile pass (when: 0 boot, 1 timer); counts as libcapreclaim. */
	probe reclaim_pass(int when, uint32_t live, uint32_t owned,
	    uint32_t orphans, uint32_t destroyed, uint32_t failed);
};
