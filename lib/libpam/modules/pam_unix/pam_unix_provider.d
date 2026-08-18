/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

provider pam_unix {
	probe sm__authenticate(const char *user, int result);
	probe sm__setcred(const char *user, int flags, int result);
	probe sm__acct_mgmt(const char *user, int result);
	probe sm__chauthtok(const char *user, int result);
};
