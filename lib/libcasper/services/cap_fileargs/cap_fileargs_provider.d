/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/*
 * USDT provider for the Casper cap_fileargs service.  The service mediates
 * pre-declared filesystem paths on behalf of a sandboxed process.  The allow
 * probe exposes each path-permission check (which path, which operation
 * FA_OPEN/FA_LSTAT/FA_REALPATH, and allow/deny); the limit probe exposes the
 * operation/flag mask a channel was narrowed to.
 */
provider cap_fileargs {
	/* Path-permission check: path, operation mask, allow/deny (1/0). */
	probe allow(const char *path, int operation, int allowed);
	/* A channel installed its file-arg limits (operations, open flags). */
	probe limit(int operations, int flags);
};
