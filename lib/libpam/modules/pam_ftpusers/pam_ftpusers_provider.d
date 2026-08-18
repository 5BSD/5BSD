/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

provider pam_ftpusers {
	probe sm__acct_mgmt(const char *user, int result);
};
