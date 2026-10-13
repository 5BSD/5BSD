/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

provider bsdsysctl {
	/* Request arrival: client label and opcode (UINT16_MAX if unavailable). */
	probe request__start(const char *client, uint16_t opcode);
	/*
	 * Completed request: client, opcode, value bytes read/written, semantic
	 * errno-style status, and channel transport errno.
	 */
	probe request__done(const char *client, uint16_t opcode, uint32_t bytes,
	    int status, int transport_error);
	probe session__limit(int a0, uint64_t a1);
	probe session__open__failure(int a0, int a1);
	probe session__close__reason(int a0, int a1);
};
